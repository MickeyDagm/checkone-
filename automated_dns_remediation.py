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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")
TICKET_URL = f"{HELPDESK_BASE_URL}/api/tickets"

EXPECTED_DNS = ["10.10.10.10", "10.10.10.20"]


def get_monitored_devices():
    devices = enumerate_devices(CSV_FILE)
    monitored = []
    for d in devices:
        addr = d.get("Device Address", "").strip()
        os_type = d.get("OS", "").strip().lower()
        user = d.get("Username", "").strip().lower()
        if not has_static_ip(addr) or "switch" in os_type or user in ("", "none"):
            continue
        monitored.append(d)
    return monitored


def run_ssh(host, port, username, password, command, timeout=8):
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host, port=int(port), username=username, password=password,
                timeout=timeout, allow_agent=False, look_for_keys=False
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
    except Exception as exc:
        pass

    if shutil.which("sshpass") and password:
        command_args = [
            "sshpass", "-p", password, "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={timeout}",
            "-p", str(port), f"{username}@{host}", command
        ]
        try:
            res = subprocess.run(command_args, capture_output=True, text=True, timeout=timeout + 4)
            out = res.stdout if res.stdout.strip() else res.stderr
            return (res.returncode == 0, out.strip())
        except Exception as exc:
            return False, str(exc)

    return False, "Auth/Connection timed out"


def get_tickets():
    headers = {"Accept": "application/json"}
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"
    try:
        req = urllib.request.Request(TICKET_URL, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            return data if isinstance(data, list) else data.get("tickets", data.get("data", []))
    except Exception:
        return []


def find_dns_ticket(tickets, device):
    name = device["Device Name"].strip().lower()
    ip = device["Device Address"].strip()
    for t in tickets:
        if str(t.get("status", "")).lower() == "resolved":
            continue
        title = str(t.get("title", "")).lower()
        desc = str(t.get("description", "")).lower()
        if "dns" in title or "dns" in desc:
            if name in title or name in desc or ip in desc:
                return t
    return None


def resolve_ticket(ticket_id, timestamp):
    url = f"{TICKET_URL}/{ticket_id}"
    payload = json.dumps({
        "status": "resolved",
        "resolution": f"DNS settings confirmed/restored to {', '.join(EXPECTED_DNS)}",
        "updated_at": timestamp
    }).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"

    for method in ("PATCH", "PUT"):
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=5):
                return True
        except urllib.error.HTTPError as exc:
            if exc.code == 405 and method == "PATCH":
                continue
            return False
        except Exception:
            return False
    return False


def send_alert_email(device, current_dns, timestamp):
    name, ip = device["Device Name"], device["Device Address"]
    body = (
        f"Dear Network Administrator,\n\n"
        f"This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:\n\n"
        f"Device Name: {name}\n"
        f"IP Address: {ip}\n"
        f"Detected DNS Setting: {current_dns}\n"
        f"Expected DNS Setting: {', '.join(EXPECTED_DNS)}\n"
        f"Time Detected: {timestamp}\n\n"
        f"The system will attempt to automatically correct this configuration.\n\n"
        f"Best regards,\nNetwork Monitoring System"
    )
    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg["Subject"] = f"DNS Configuration Alert: {name} ({ip})"
    msg.attach(MIMEText(body, "plain"))

    if not SEND_EMAIL or not SMTP_SERVER:
        print(f"    --> [EMAIL] Dry run logged for {name}")
        return True
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as s:
            s.send_message(msg)
        print(f"    --> [EMAIL] Alert sent to {TO_EMAIL}")
        return True
    except Exception as exc:
        print(f"    --> [EMAIL] Failed: {exc}")
        return False


def correct_dns(device):
    name, ip = device["Device Name"], device["Device Address"]
    os_type = device.get("OS", "").strip().lower()
    user, pw = device.get("Username", "").strip(), device.get("Password", "")
    port = VYOS_SSH_PORT if "vyos" in os_type else 22

    if "vyos" in os_type:
        cmd = f"""/bin/vbash -ic 'configure
delete system name-server
set system name-server {EXPECTED_DNS[0]}
set system name-server {EXPECTED_DNS[1]}
commit; save; exit'"""
        verify_cmd = "/bin/vbash -ic 'show configuration commands | match \"system name-server\"'"
    else:
        lines = "".join(f"nameserver {dns}\\n" for dns in EXPECTED_DNS)
        cmd = f"echo '{pw}' | sudo -S -p '' bash -c 'printf \"{lines}\" > /etc/resolv.conf'"
        verify_cmd = "cat /etc/resolv.conf"

    success, _ = run_ssh(ip, port, user, pw, cmd)
    if not success:
        return False

    v_success, v_out = run_ssh(ip, port, user, pw, verify_cmd)
    if not v_success:
        return False

    verified = [dns for dns in list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", v_out))) if not dns.startswith("127.")]
    return set(verified) == set(EXPECTED_DNS)


def show_ticket_entries(tickets):
    print("\n" + "=" * 90)
    print(f"{'ID':<6} {'Status':<12} {'Title':<30} {'Description':<40}")
    print("-" * 90)
    for t in tickets:
        t_id = t.get("id") or t.get("ticket_id") or "?"
        status = str(t.get("status", ""))[:10]
        title = str(t.get("title", ""))[:28]
        desc = str(t.get("description", ""))[:38]
        print(f"{str(t_id):<6} {status:<12} {title:<30} {desc:<40}")
    print("=" * 90)


def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices = get_monitored_devices()
    tickets = get_tickets()

    print("=" * 60)
    print(f"DNS MONITORING & REMEDIATION SCAN ({len(devices)} Devices)")
    print("=" * 60)

    for device in devices:
        name = device["Device Name"]
        ip = device["Device Address"]
        os_type = device.get("OS", "").strip().lower()
        user = device.get("Username", "").strip()
        pw = device.get("Password", "")
        port = VYOS_SSH_PORT if "vyos" in os_type or "router" in name.lower() else 22

        if not ping_device(ip):
            print(f"[-] {name:<8} ({ip:<15}) : OFFLINE (Skipped)")
            continue

        cmd = "/bin/vbash -ic 'show configuration commands | match \"system name-server\"'" if "vyos" in os_type or "router" in name.lower() else "cat /etc/resolv.conf"
        success, output = run_ssh(ip, port, user, pw, cmd)

        if not success:
            print(f"[!] {name:<8} ({ip:<15}) : SSH Failed ({output if output else 'connection refused/timeout'})")
            continue

        detected = [dns for dns in list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output))) if not dns.startswith("127.")]

        # If DNS is already correct
        if set(detected) == set(EXPECTED_DNS):
            print(f"[+] {name:<8} ({ip:<15}) : OK ({', '.join(detected)})")
            
            # Auto-resolve any leftover open ticket for this device
            open_ticket = find_dns_ticket(tickets, device)
            if open_ticket:
                t_id = open_ticket.get("id") or open_ticket.get("ticket_id")
                if resolve_ticket(t_id, timestamp):
                    print(f"    --> [TICKET] Closed stale ticket #{t_id} as RESOLVED")
            continue

        # DNS is altered
        current_dns = ", ".join(detected) if detected else "None detected"
        print(f"[!] {name:<8} ({ip:<15}) : ALTERED ({current_dns})")
        send_alert_email(device, current_dns, timestamp)

        open_ticket = find_dns_ticket(tickets, device)
        ticket_id = open_ticket.get("id") or open_ticket.get("ticket_id") if open_ticket else None

        print(f"    --> [REMEDIATE] Restoring /etc/resolv.conf...", end=" ", flush=True)
        if correct_dns(device):
            print("SUCCESS")
            if ticket_id and resolve_ticket(ticket_id, timestamp):
                print(f"    --> [TICKET] #{ticket_id} updated to RESOLVED")
        else:
            print("FAILED")

    print("\nRefreshing ticket summary for submission evidence...")
    show_ticket_entries(get_tickets())


if __name__ == "__main__":
    main()