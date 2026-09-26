from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import os
import re
import smtplib
import sys
import time
import urllib.error
import urllib.request
import paramiko

from config import (
    EXPECTED_DNS,
    FROM_EMAIL,
    HELPDESK_BASE_URL,
    HELPDESK_TOKEN,
    SEND_EMAIL,
    SMTP_PORT,
    SMTP_SERVER,
    TO_EMAIL,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enumerate_devices import enumerate_devices

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")
TICKET_URL = f"{HELPDESK_BASE_URL.rstrip('/')}/api/tickets"

IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def build_altered_dns_email(device_name, ip_address, detected_dns, timestamp):
    detected_str = (
        ", ".join(detected_dns) if detected_dns else "None (Missing/Empty)"
    )
    expected_str = ", ".join(EXPECTED_DNS)

    subject = f"DNS Configuration Alert: {device_name} ({ip_address})"
    body = f"""Dear Network Administrator,

This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:

Device Name: {device_name}
IP Address: {ip_address}
Detected DNS Setting: {detected_str}
Expected DNS Setting: {expected_str}
Time Detected: {timestamp}

The system will attempt to automatically correct this configuration.

Best regards,
Network Monitoring System"""
    return subject, body


def send_email(subject, body):
    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    if not SEND_EMAIL or not SMTP_SERVER:
        print(
            "\n[DRY RUN] Email displayed (startup SMTP not configured / SEND_EMAIL unset)."
        )
        return

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.send_message(msg)
        print("\nNotification email sent successfully.")
    except Exception as e:
        print(f"\nFailed to send email: {e}")


def get_device_dns(ssh_client):
    cmd = "resolvectl dns 2>/dev/null; grep '^nameserver' /etc/resolv.conf 2>/dev/null"
    _, stdout, _ = ssh_client.exec_command(cmd, timeout=5)
    output = stdout.read().decode("utf-8", errors="replace").strip()

    detected_dns = []
    for line in output.splitlines():
        if "Link" in line or "nameserver" in line:
            parts = line.replace("nameserver", "").split(":")[-1].strip().split()
            for part in parts:
                if (
                    IP_PATTERN.match(part)
                    and not part.startswith("127.")
                    and part not in detected_dns
                ):
                    detected_dns.append(part)
    return detected_dns


def remediate_dns(ssh_client, interface="ens3"):
    expected_str = " ".join(EXPECTED_DNS)
    cmd = (
        f"sudo resolvectl dns {interface} {expected_str} && "
        f"sudo resolvectl flush-caches"
    )
    _, stdout, stderr = ssh_client.exec_command(cmd, timeout=10)
    stdout.channel.recv_exit_status()

    time.sleep(1)

    verify_cmd = (
        f"resolvectl status {interface} | grep -E 'DNS Servers|Current DNS'"
    )
    _, v_out, _ = ssh_client.exec_command(verify_cmd, timeout=5)
    res = v_out.read().decode("utf-8", errors="replace").strip()

    if not res:
        _, v_out2, _ = ssh_client.exec_command("resolvectl dns", timeout=5)
        res = v_out2.read().decode("utf-8", errors="replace").strip()

    return res


def update_ticket_system(device_name, ip_address):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {HELPDESK_TOKEN.strip()}",
    }

    # 1. Create ticket
    payload_create = json.dumps({
        "title": f"DNS Configuration Altered - {device_name}",
        "description": f"DNS configuration altered on {device_name} ({ip_address}). Expected: {', '.join(EXPECTED_DNS)}.",
        "status": "open",
        "priority": "medium",
    }).encode("utf-8")

    req_create = urllib.request.Request(
        TICKET_URL, data=payload_create, headers=headers, method="POST"
    )

    ticket_id = None
    try:
        with urllib.request.urlopen(req_create, timeout=5) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            resp_data = json.loads(raw)
            ticket_id = resp_data.get("id") or resp_data.get("ticket_id")
            print(f"[TICKET] Created ticket #{ticket_id} at {TICKET_URL} for {device_name}")
    except Exception as exc:
        print(f"[WARN] Failed to create ticket at {TICKET_URL}: {exc}", file=sys.stderr)

    # 2. Update to resolved
    if ticket_id:
        patch_url = f"{TICKET_URL}/{ticket_id}"
        payload_patch = json.dumps({"status": "resolved"}).encode("utf-8")

        req_patch = urllib.request.Request(
            patch_url, data=payload_patch, headers=headers, method="PATCH"
        )
        try:
            with urllib.request.urlopen(req_patch, timeout=5) as resp:
                print(
                    f"[TICKET] Updated ticket #{ticket_id} to status 'resolved' (HTTP {resp.status})"
                )
        except Exception as exc:
            print(f"[WARN] Failed to resolve ticket #{ticket_id}: {exc}", file=sys.stderr)


def main():
    print("=" * 70)
    print("DNS CONFIGURATION MONITOR AND REMEDIATION")
    print(f"Ticket Endpoint: {TICKET_URL}")
    print(f"Expected DNS   : {', '.join(EXPECTED_DNS)}")
    print("=" * 70)

    devices = enumerate_devices(CSV_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for dev in devices:
        name = dev["Device Name"].strip()
        ip = dev["Device Address"].strip()
        os_type = dev.get("OS", "").strip().lower()
        user = dev.get("Username", "ubuntu").strip()
        password = dev.get("Password", "ubuntu").strip()

        if os_type != "ubuntu" or not IP_PATTERN.match(ip):
            continue
        if name.upper() in ["DNS1", "DNS2", "SMTP"]:
            continue

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(
                ip,
                port=22,
                username=user,
                password=password,
                timeout=4,
                allow_agent=False,
                look_for_keys=False,
            )

            current_dns = get_device_dns(ssh)
            is_compliant = all(srv in current_dns for srv in EXPECTED_DNS)

            if not is_compliant:
                print(f"\n[!] ALERT: DNS configuration altered on {name} ({ip})!")
                print(f"    Detected : {current_dns}")
                print(f"    Expected : {EXPECTED_DNS}")

                # 1. Send / Display Email Template
                subject, body = build_altered_dns_email(
                    name, ip, current_dns, timestamp
                )
                send_email(subject, body)

                # 2. Correct DNS Settings
                print(f"\n[*] Correcting DNS settings on {name}...")
                verification = remediate_dns(ssh)
                print(f"    Remediated status:\n    {verification}\n")

                # 3. Create & Resolve Ticket
                update_ticket_system(name, ip)
                print("-" * 70)
            else:
                print(f"[OK] {name:<8} | {ip:<16} | DNS is compliant.")

        except Exception as err:
            print(f"[-] Could not connect to {name} ({ip}): {err}")
        finally:
            ssh.close()


if __name__ == "__main__":
    main()