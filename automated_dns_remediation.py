import json
import os
import re
import shutil
import smtplib
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import (
    HELPDESK_BASE_URL,
    HELPDESK_TOKEN,
    SMTP_SERVER,
    SMTP_PORT,
    FROM_EMAIL,
    TO_EMAIL,
    SEND_EMAIL,
    VYOS_SSH_PORT,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enumerate_devices import enumerate_devices
from monitor_device_availability import has_static_ip, ping_device


# ============================================================
# Configuration
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")
TICKET_URL = f"{HELPDESK_BASE_URL}/api/tickets"

EXPECTED_DNS = [
    "10.10.10.10",
    "10.10.10.20",
]

ISSUE_TYPE = "DNS Compromise"


# ============================================================
# Device selection
# ============================================================

def get_monitored_devices():
    devices = enumerate_devices(CSV_FILE)
    monitored = []

    for device in devices:
        address = device.get("Device Address", "").strip()
        os_type = device.get("OS", "").strip().lower()
        username = device.get("Username", "").strip().lower()

        if not has_static_ip(address):
            continue
        if os_type in ("openvswitch", "switch"):
            continue
        if username in ("", "none"):
            continue

        monitored.append(device)

    return monitored


# ============================================================
# SSH
# ============================================================

def run_ssh(host, port, username, password, command, timeout=10):
    try:
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=host,
                port=int(port),
                username=username,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )

            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")

            if out.strip():
                return True, out
            if err.strip():
                return False, err
            return True, ""

        finally:
            client.close()

    except ImportError:
        pass
    except Exception as exc:
        if not shutil.which("sshpass"):
            return False, str(exc)

    if shutil.which("sshpass") and password:
        command_args = [
            "sshpass",
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            f"ConnectTimeout={timeout}",
            "-p",
            str(port),
            f"{username}@{host}",
            command,
        ]

        try:
            result = subprocess.run(
                command_args,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
            output = result.stdout if result.stdout.strip() else result.stderr
            return (result.returncode == 0, output)
        except Exception as exc:
            return False, str(exc)

    return False, "Neither paramiko nor sshpass is available for SSH."


# ============================================================
# DNS Detection
# ============================================================

def detect_altered_dns(device):
    name = device["Device Name"]
    ip = device["Device Address"]
    os_type = device.get("OS", "").strip()
    username = device.get("Username", "").strip()
    password = device.get("Password", "")

    port = VYOS_SSH_PORT if os_type.lower() == "vyos" else 22

    print(f"\n  Checking DNS configuration on {name} ({ip}) [OS: {os_type}]...")

    if not ping_device(ip):
        print(f"  [SKIP] {name} ({ip}) is offline.")
        return None

    if os_type.lower() == "vyos":
        command = "/bin/vbash -ic 'show configuration commands | match \"system name-server\"'"
    else:
        command = "cat /etc/resolv.conf"

    success, output = run_ssh(ip, port, username, password, command)

    if not success:
        print(f"  [WARN] Could not retrieve DNS configuration from {name}:")
        print(f"         {output.strip()}")
        return None

    detected = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)
    detected = list(dict.fromkeys(detected))
    active = [dns for dns in detected if not dns.startswith("127.")]

    print(f"  Current DNS : {', '.join(active) if active else 'None detected'}")
    print(f"  Expected DNS: {', '.join(EXPECTED_DNS)}")

    if set(active) == set(EXPECTED_DNS):
        print(f"  [OK] DNS configuration on {name} is correct.")
        return None

    current_dns = ", ".join(active) if active else "None detected"
    print(f"  [ALERT] DNS configuration altered on {name}: {current_dns}")
    return current_dns


# ============================================================
# Email Notification
# ============================================================

def build_altered_email(device, current_dns, expected_dns, timestamp):
    name = device["Device Name"]
    ip = device["Device Address"]
    subject = f"DNS Configuration Alert: {name} ({ip})"
    body = f"""Dear Network Administrator,

This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:

Device Name: {name}
IP Address: {ip}
Detected DNS Setting: {current_dns}
Expected DNS Setting: {expected_dns}
Time Detected: {timestamp}

The system will attempt to automatically correct this configuration.

Best regards,
Network Monitoring System"""

    return subject, body


def send_email(subject, body):
    message = MIMEMultipart()
    message["From"] = FROM_EMAIL
    message["To"] = TO_EMAIL
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    print("\n" + "=" * 70)
    print("DNS SETTING ALTERED NOTIFICATION EMAIL")
    print("=" * 70)
    print(f"From    : {FROM_EMAIL}")
    print(f"To      : {TO_EMAIL}")
    print(f"Subject : {subject}")
    print("-" * 70)
    print(body)
    print("=" * 70)

    if not SEND_EMAIL or not SMTP_SERVER:
        print("\n[DRY RUN] Email displayed. SMTP disabled or not configured.")
        return True

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.send_message(message)
        print("\n[OK] Alert email sent successfully.")
        return True
    except Exception as exc:
        print(f"\n[WARN] Failed to send email: {exc}")
        return False


# ============================================================
# Helpdesk API
# ============================================================

def get_tickets():
    headers = {"Accept": "application/json"}
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"

    request = urllib.request.Request(TICKET_URL, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("tickets") or data.get("data") or []
            return []
    except Exception as exc:
        print(f"\n  [WARN] Ticket service query failed ({TICKET_URL}): {exc}")
        return []


def find_dns_ticket(tickets, device):
    """
    Search tickets by looking at title, description, or dedicated attributes.
    """
    name = device["Device Name"].strip().lower()
    ip = device["Device Address"].strip()

    for ticket in tickets:
        status = str(ticket.get("status", "")).strip().lower()
        if status == "resolved":
            continue

        title = str(ticket.get("title", "")).lower()
        desc = str(ticket.get("description", "")).lower()

        # Must be a DNS-related ticket
        if "dns" not in title and "dns" not in desc:
            continue

        # Must match either device name or device IP
        if name in title or name in desc or ip in desc:
            return ticket

    return None


def create_dns_ticket(device, detected_dns):
    name = device["Device Name"]
    ip = device["Device Address"]

    payload = json.dumps({
        "title": f"DNS Setting Altered - {name}",
        "description": (
            f"DNS configuration altered on {name} ({ip}). "
            f"Detected DNS: {detected_dns}. "
            f"Expected DNS: {', '.join(EXPECTED_DNS)}."
        ),
        "priority": "medium",
        "status": "open",
    }).encode()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"

    request = urllib.request.Request(TICKET_URL, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8", errors="replace")
            ticket = json.loads(raw)
            print("  [OK] DNS ticket created.")
            return ticket
    except Exception as exc:
        print(f"  [WARN] DNS ticket creation failed: {exc}")
        return None


def resolve_ticket(ticket_id, device, timestamp):
    url = f"{TICKET_URL}/{ticket_id}"
    payload = json.dumps({
        "status": "resolved",
        "resolution": f"DNS settings restored to {', '.join(EXPECTED_DNS)}",
        "updated_at": timestamp,
    }).encode()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"

    for method in ("PATCH", "PUT"):
        request = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                print(f"  [OK] Ticket #{ticket_id} updated -> status: resolved")
                return True
        except urllib.error.HTTPError as exc:
            if exc.code == 405 and method == "PATCH":
                continue
            print(f"  [WARN] Ticket #{ticket_id} update failed: HTTP {exc.code}")
            return False
        except Exception as exc:
            print(f"  [WARN] Ticket #{ticket_id} update failed: {exc}")
            return False

    return False


# ============================================================
# DNS Remediation
# ============================================================

def correct_dns(device):
    name = device["Device Name"]
    ip = device["Device Address"]
    os_type = device.get("OS", "").strip()
    username = device.get("Username", "").strip()
    password = device.get("Password", "")

    port = VYOS_SSH_PORT if os_type.lower() == "vyos" else 22

    print(f"\n  --- Correcting DNS Configuration on {name} ({ip}) ---")

    if os_type.lower() == "vyos":
        command = f"""/bin/vbash -ic '
configure
delete system name-server
set system name-server {EXPECTED_DNS[0]}
set system name-server {EXPECTED_DNS[1]}
commit
save
exit
'"""
        verify_command = "/bin/vbash -ic 'show configuration commands | match \"system name-server\"'"
    else:
        # Non-blocking, clean root rewrite avoiding sudo shell sub-quoting issues
        resolv_lines = "".join(f"nameserver {dns}\\n" for dns in EXPECTED_DNS)
        command = f"echo '{password}' | sudo -S -p '' bash -c 'printf \"{resolv_lines}\" > /etc/resolv.conf'"
        verify_command = "cat /etc/resolv.conf"

    success, output = run_ssh(ip, port, username, password, command, timeout=10)

    if not success:
        print(f"  [FAIL] Failed to modify DNS configuration on {name}.")
        print(f"         {output.strip()}")
        return False

    print(f"  [OK] {os_type} DNS configuration command completed.")

    # Verification step
    verify_success, verify_output = run_ssh(ip, port, username, password, verify_command, timeout=10)

    if not verify_success:
        print(f"  [FAIL] DNS verification failed on {name}.")
        return False

    verified_dns = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", verify_output)
    verified_dns = list(dict.fromkeys(verified_dns))
    verified_dns = [dns for dns in verified_dns if not dns.startswith("127.")]

    if set(verified_dns) == set(EXPECTED_DNS):
        print(f"  [SUCCESS] {name} DNS restored to {', '.join(EXPECTED_DNS)}")
        return True

    print("  [FAIL] DNS verification does not match expected configuration.")
    print(f"  Expected: {', '.join(EXPECTED_DNS)}")
    print(f"  Detected: {', '.join(verified_dns) if verified_dns else 'None'}")
    return False


# ============================================================
# Display Tickets (Formatted for Submission Screenshot)
# ============================================================

def show_ticket_entries(tickets):
    print("\n" + "=" * 100)
    print("WEB SERVICE TICKETS")
    print("=" * 100)

    header = f"{'ID':<6} {'Title':<30} {'Status':<12} {'Description':<50}"
    print(header)
    print("-" * len(header))

    if not tickets:
        print("No tickets found.")
    else:
        for ticket in tickets:
            t_id = ticket.get("id") or ticket.get("ticket_id") or "?"
            title = ticket.get("title", "")[:28]
            status = ticket.get("status", "")[:10]
            desc = ticket.get("description", "")[:48]
            print(f"{str(t_id):<6} {title:<30} {status:<12} {desc:<50}")

    print("=" * 100)


# ============================================================
# Main
# ============================================================

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices = get_monitored_devices()

    print("=" * 70)
    print("AUTOMATED DNS CONFIGURATION MONITORING & REMEDIATION")
    print(f"Helpdesk API : {TICKET_URL}")
    print(f"Expected DNS : {', '.join(EXPECTED_DNS)}")
    print(f"Devices to scan: {len(devices)}")
    print("=" * 70)

    tickets = get_tickets()
    altered_count = 0
    remediated_count = 0
    failed_count = 0

    for device in devices:
        name = device["Device Name"]
        ip = device["Device Address"]

        current_dns = detect_altered_dns(device)
        if current_dns is None:
            continue

        altered_count += 1
        print("\n" + "=" * 70)
        print(f"REMEDIATING: {name} ({ip})")
        print("=" * 70)

        # 1. Alert email
        subject, body = build_altered_email(device, current_dns, ", ".join(EXPECTED_DNS), timestamp)
        send_email(subject, body)

        # 2. Check or create ticket
        ticket = find_dns_ticket(tickets, device)
        ticket_id = None

        if ticket:
            ticket_id = ticket.get("id") or ticket.get("ticket_id")
            print(f"\n  [OK] Existing DNS ticket found: #{ticket_id}")
        else:
            print("\n  No open DNS ticket found. Creating a new DNS ticket...")
            created_ticket = create_dns_ticket(device, current_dns)
            if created_ticket:
                ticket_id = created_ticket.get("id") or created_ticket.get("ticket_id")
                if ticket_id:
                    print(f"  [OK] Using new DNS ticket #{ticket_id}")
                    tickets.append(created_ticket)

        # 3. Correct DNS
        remediated = correct_dns(device)

        if not remediated:
            failed_count += 1
            print(f"\n  [FAIL] DNS remediation failed for {name}. Ticket #{ticket_id} remains open.")
            continue

        remediated_count += 1

        # 4. Resolve ticket
        if ticket_id:
            print("\n  --- Updating DNS Ticket in Web Service ---")
            resolve_ticket(ticket_id, device, timestamp)

    print("\n" + "=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)
    print(f"DNS altered devices : {altered_count}")
    print(f"Successfully fixed  : {remediated_count}")
    print(f"Failed remediation  : {failed_count}")
    print("=" * 70)

    # Show refreshed tickets table for screenshot evidence
    updated_tickets = get_tickets()
    if updated_tickets:
        show_ticket_entries(updated_tickets)


if __name__ == "__main__":
    main()