import csv
import datetime
import json
import logging
import os
import re
import smtplib
import time
import urllib.error
import urllib.request

import paramiko
from email.message import EmailMessage

from config import (
    HELPDESK_BASE_URL,
    HELPDESK_TOKEN,
    EXPECTED_DNS,
    SMTP_SERVER,
    SMTP_PORT,
    FROM_EMAIL,
    TO_EMAIL,
)
from enumerate_devices import enumerate_devices

# ============================================================
# PATHS / CONSTANTS
# ============================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")
TICKET_URL = f"{HELPDESK_BASE_URL.rstrip('/')}/api/tickets"
LOG_FILE = os.path.join(SCRIPT_DIR, "dns_remediation.log")
SSH_TIMEOUT = 10

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("dns-remediation")


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_dns(values):
    """Return a clean list of unique IPv4 DNS addresses."""
    if isinstance(values, str):
        values = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", values)
    result = []
    for value in values:
        value = str(value).strip()
        if value and value not in result:
            result.append(value)
    return result


def dns_is_correct(current_dns):
    """Compare current DNS to expected (order does not matter)."""
    return set(normalize_dns(current_dns)) == set(normalize_dns(EXPECTED_DNS))


# ============================================================
# DEVICE SELECTION
# ============================================================
def get_devices():
    """Load devices and keep only those that can be SSH-monitored."""
    devices = enumerate_devices(CSV_FILE)
    monitored = []

    for device in devices:
        name = device["Device Name"].strip()
        address = device["Device Address"].strip()
        os_type = device["OS"].strip().lower()
        username = device["Username"].strip()
        password = device["Password"].strip()

        if os_type in {"openvswitch", "ovs"}:
            continue
        if not address or address.upper() in {"DHCP", "NONE"}:
            continue
        if not username or username.lower() == "none":
            continue
        if not password or password.lower() == "none":
            continue

        monitored.append(device)

    return monitored


# ============================================================
# SSH HELPERS
# ============================================================
def connect(device):
    """
    SSH to the device on port 22 using Device Address.
    Access Port is console/telnet — do not use it for Paramiko.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    host = device["Device Address"].strip()
    port = 22

    # Optional: ROUTER1 via same settings as enumerate_devices
    os_type = device["OS"].strip().lower()
    name = device["Device Name"].strip().upper()
    if os_type == "vyos" or name == "ROUTER1":
        from config import VYOS_SSH_HOST, VYOS_SSH_PORT
        host = VYOS_SSH_HOST
        port = int(VYOS_SSH_PORT)

    client.connect(
        hostname=host,
        port=port,
        username=device["Username"],
        password=device["Password"],
        timeout=SSH_TIMEOUT,
        auth_timeout=SSH_TIMEOUT,
        banner_timeout=SSH_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    return client

    
def run_command(client, command):
    stdin, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT)
    output = stdout.read().decode("utf-8", errors="replace").strip()
    error = stderr.read().decode("utf-8", errors="replace").strip()
    exit_code = stdout.channel.recv_exit_status()
    return exit_code, output, error


# ============================================================
# DNS - LINUX / UBUNTU
# ============================================================
def get_linux_dns(client):
    code, output, error = run_command(client, "cat /etc/resolv.conf")
    if code != 0:
        raise RuntimeError(error or "Unable to read /etc/resolv.conf")

    dns_servers = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                dns_servers.append(parts[1])
    return normalize_dns(dns_servers)


def set_linux_dns(client, password):
    dns_content = "\n".join(f"nameserver {dns}" for dns in EXPECTED_DNS) + "\n"
    command = "sudo -S -p '' tee /etc/resolv.conf > /dev/null"

    stdin, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT)
    stdin.write(password + "\n")
    stdin.write(dns_content)
    stdin.flush()
    stdin.channel.shutdown_write()

    exit_code = stdout.channel.recv_exit_status()
    error = stderr.read().decode("utf-8", errors="replace").strip()
    if exit_code != 0:
        raise RuntimeError(error or "Failed to update DNS configuration")


# ============================================================
# DNS - VYOS
# ============================================================
def get_vyos_dns(client):
    command = "show configuration commands | match 'system name-server'"
    code, output, error = run_command(client, command)
    if code != 0:
        raise RuntimeError(error or "Unable to read VyOS DNS configuration")

    dns_servers = []
    for line in output.splitlines():
        match = re.search(
            r"system name-server\s+((?:\d{1,3}\.){3}\d{1,3})",
            line,
        )
        if match:
            dns_servers.append(match.group(1))
    return normalize_dns(dns_servers)


def set_vyos_dns(client):
    shell = client.invoke_shell()
    shell.settimeout(SSH_TIMEOUT)

    def send(cmd, wait=1.5):
        shell.send(cmd + "\n")
        time.sleep(wait)
        output = ""
        while shell.recv_ready():
            output += shell.recv(65535).decode("utf-8", errors="replace")
        return output

    try:
        send("configure")
        send("delete system name-server")
        for dns in EXPECTED_DNS:
            send(f"set system name-server {dns}")
        commit_out = send("commit")
        if "error" in commit_out.lower():
            raise RuntimeError(f"VyOS commit failed: {commit_out}")
        save_out = send("save")
        if "error" in save_out.lower():
            raise RuntimeError(f"VyOS save failed: {save_out}")
        send("exit")
    finally:
        shell.close()


# ============================================================
# DNS DISPATCH
# ============================================================
def get_dns(device, client):
    os_type = device["OS"].strip().lower()
    if os_type in {"ubuntu", "linux", "debian"}:
        return get_linux_dns(client)
    if os_type == "vyos":
        return get_vyos_dns(client)
    raise RuntimeError(f"Unsupported OS: {device['OS']}")


def correct_dns(device, client):
    os_type = device["OS"].strip().lower()
    if os_type in {"ubuntu", "linux", "debian"}:
        set_linux_dns(client, device["Password"])
        return
    if os_type == "vyos":
        set_vyos_dns(client)
        return
    raise RuntimeError(f"Unsupported OS: {device['OS']}")


# ============================================================
# EMAIL (C4 - DNS Setting Altered Notification)
# ============================================================
def send_dns_alert(device, current_dns):
    """
    Send DNS Setting Altered Notification.
    Adjust subject/body to match Task 2 Email Templates.docx exactly.
    """
    name = device["Device Name"]
    ip = device["Device Address"]
    current_text = ", ".join(current_dns) if current_dns else "None detected"
    expected_text = ", ".join(EXPECTED_DNS)
    detected_time = now()

    subject = f"DNS Setting Altered Notification - {name} ({ip})"
    body = f"""Dear Network Administrator,

This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:

Device Name: {name}
IP Address: {ip}
Detected DNS Setting: {current_text}
Expected DNS Setting: {expected_text}
Time Detected: {detected_time}

The system will attempt to automatically correct this configuration.

Best regards,
Network Monitoring System
"""

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = FROM_EMAIL
    message["To"] = TO_EMAIL
    message.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as smtp:
            smtp.send_message(message)
        print(f"    [EMAIL] Sent DNS alert to {TO_EMAIL}")
        logger.info("DNS ALERT EMAIL SENT | %s | %s", name, ip)
        return True
    except Exception as exc:
        print(f"    [EMAIL] Failed: {type(exc).__name__}: {exc}")
        logger.error("DNS ALERT EMAIL FAILED | %s | %s | %s", name, ip, exc)
        return False


# ============================================================
# HELPDESK API
# ============================================================
def api_request(method, url, payload=None):
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {HELPDESK_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, {"message": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": raw.strip()}
        return exc.code, body
    except urllib.error.URLError as exc:
        return None, {"error": str(exc.reason)}


def create_dns_ticket(device, current_dns):
    """Create a ticket for an altered DNS setting."""
    name = device["Device Name"]
    ip = device["Device Address"]
    current_text = ", ".join(current_dns) if current_dns else "None detected"
    expected_text = ", ".join(EXPECTED_DNS)

    payload = {
        "title": f"DNS Configuration Altered - {name}",
        "description": (
            f"Unauthorized or incorrect DNS configuration detected.\n"
            f"Device: {name}\n"
            f"IP Address: {ip}\n"
            f"Detected DNS: {current_text}\n"
            f"Expected DNS: {expected_text}\n"
            f"Time: {now()}"
        ),
        "status": "open",
    }

    status, response = api_request("POST", TICKET_URL, payload)
    if status not in {200, 201}:
        raise RuntimeError(f"Unable to create ticket: HTTP {status} - {response}")

    ticket_id = None
    if isinstance(response, dict):
        ticket_id = response.get("id") or response.get("ticket_id")

    print(f"    [TICKET] Created #{ticket_id}")
    logger.info("TICKET CREATED | #%s | %s | %s", ticket_id, name, ip)
    return response if isinstance(response, dict) else {"id": ticket_id}


def resolve_ticket(ticket, device):
    """Mark the DNS ticket as resolved after successful remediation."""
    ticket_id = ticket.get("id")
    if ticket_id is None:
        raise RuntimeError("DNS ticket has no ID")

    payload = {
        "status": "resolved",
        "resolution": (
            f"DNS configuration automatically corrected to "
            f"{', '.join(EXPECTED_DNS)}."
        ),
    }

    url = f"{TICKET_URL}/{ticket_id}"
    status, response = api_request("PATCH", url, payload)
    if status not in {200, 204}:
        raise RuntimeError(
            f"Unable to resolve ticket #{ticket_id}: HTTP {status} - {response}"
        )

    print(f"    [TICKET] #{ticket_id} resolved")
    logger.info(
        "TICKET RESOLVED | #%s | %s | %s",
        ticket_id,
        device["Device Name"],
        device["Device Address"],
    )


# ============================================================
# HEALTHY DNS LOG (also supports C5)
# ============================================================
def log_dns_ok(device, current_dns):
    msg = (
        f"DNS service functioning correctly - "
        f"Device: {device['Device Name']} - "
        f"Date/Time: {now()} - "
        f"DNS: {','.join(current_dns)}"
    )
    logger.info(msg)
    print(f"    [LOG] {msg}")


# ============================================================
# PROCESS ONE DEVICE (C4 core)
# ============================================================
def process_device(device):
    name = device["Device Name"]
    ip = device["Device Address"]

    print()
    print(f"[CHECK] {name:<8} | {ip:<15} | {device['OS']}")

    client = None
    try:
        client = connect(device)
        current_dns = get_dns(device, client)
        current_text = ", ".join(current_dns) if current_dns else "None detected"
        expected_text = ", ".join(EXPECTED_DNS)

        # ----- DNS is correct -----
        if dns_is_correct(current_dns):
            print("    [DNS] OK")
            print(f"          Current : {current_text}")
            print(f"          Expected: {expected_text}")
            log_dns_ok(device, current_dns)
            return True

        # ----- DNS is altered (C4 path) -----
        print("    [DNS] ALTERED")
        print(f"          Current : {current_text}")
        print(f"          Expected: {expected_text}")
        logger.warning(
            "DNS ALTERED | %s | %s | Current=%s | Expected=%s",
            name,
            ip,
            current_text,
            expected_text,
        )

        # 1. Email stakeholders
        send_dns_alert(device, current_dns)

        # 2. Create ticket
        ticket = create_dns_ticket(device, current_dns)

        # 3. Correct DNS
        print("    [REMEDIATE] Correcting DNS...")
        correct_dns(device, client)
        print("    [REMEDIATE] DNS configuration updated")

        # 4. Verify
        print("    [VERIFY] Checking DNS again...")
        verified_dns = get_dns(device, client)
        verified_text = ", ".join(verified_dns) if verified_dns else "None detected"
        print(f"    [VERIFY] Current: {verified_text}")

        if not dns_is_correct(verified_dns):
            print("    [VERIFY] FAILED - DNS still incorrect")
            logger.error(
                "DNS VERIFICATION FAILED | %s | %s | Actual=%s",
                name,
                ip,
                verified_text,
            )
            return False

        print("    [VERIFY] SUCCESS - DNS restored")
        logger.info("DNS RESTORED | %s | %s | DNS=%s", name, ip, verified_text)

        # 5. Update ticket to resolved
        resolve_ticket(ticket, device)
        return True

    except Exception as exc:
        print(f"    [ERROR] {type(exc).__name__}: {exc}")
        logger.error("DEVICE PROCESSING FAILED | %s | %s | %s", name, ip, exc)
        return False
    finally:
        if client:
            client.close()


# ============================================================
# MAIN
# ============================================================
def main():
    print()
    print("=" * 70)
    print("AUTOMATED DNS REMEDIATION (C4)")
    print("=" * 70)
    print(f"Expected DNS : {', '.join(EXPECTED_DNS)}")
    print(f"Helpdesk API : {TICKET_URL}")
    print(f"SMTP Server  : {SMTP_SERVER}:{SMTP_PORT}")
    print("=" * 70)

    devices = get_devices()
    print(f"\n[+] Devices selected: {len(devices)}")

    successful = 0
    failed = 0

    for device in devices:
        if process_device(device):
            successful += 1
        else:
            failed += 1

    print()
    print("=" * 70)
    print("DNS REMEDIATION SUMMARY")
    print("=" * 70)
    print(f"Devices checked : {len(devices)}")
    print(f"Successful      : {successful}")
    print(f"Failed          : {failed}")
    print(f"Log file        : {LOG_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()