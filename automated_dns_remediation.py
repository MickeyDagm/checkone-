from datetime import datetime
import email.utils
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
from enumerate_devices import CSV_FILE, enumerate_devices

# Dynamically construct the ticket endpoint from the base URL
TICKET_URL = f"{HELPDESK_BASE_URL.rstrip('/')}/api/tickets"
IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def send_email_alert(device_name, ip_address, detected_dns):
    """Sends or displays the DNS Setting Altered Notification."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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

    if not SEND_EMAIL or not SMTP_SERVER:
        print("\n" + "=" * 20 + " EMAIL NOTIFICATION GENERATED " + "=" * 20)
        print(f"To: {TO_EMAIL}\nFrom: {FROM_EMAIL}\nSubject: {subject}\n\n{body}")
        print("=" * 66 + "\n")
        return

    msg = f"From: {FROM_EMAIL}\r\nTo: {TO_EMAIL}\r\nSubject: {subject}\r\nDate: {email.utils.formatdate(localtime=True)}\r\n\r\n{body}"
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=5) as server:
            server.sendmail(FROM_EMAIL, [TO_EMAIL], msg)
        print(f"[EMAIL] Alert sent successfully: {subject}")
    except Exception as exc:
        print(f"[WARN] Failed to send email alert: {exc}", file=sys.stderr)


def get_device_dns(ssh_client):
    """Checks DNS settings from both resolvectl and resolv.conf."""
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
    """Corrects DNS settings via sudo resolvectl."""
    expected_str = " ".join(EXPECTED_DNS)
    cmd = (
        f"sudo resolvectl dns {interface} {expected_str} && "
        f"sudo resolvectl flush-caches"
    )
    _, stdout, stderr = ssh_client.exec_command(cmd, timeout=10)
    stdout.channel.recv_exit_status()

    time.sleep(1)

    # Verify remediation
    verify_cmd = f"resolvectl dns {interface}"
    _, v_out, _ = ssh_client.exec_command(verify_cmd, timeout=5)
    res = v_out.read().decode("utf-8", errors="replace").strip()
    return res


def create_and_resolve_ticket(device_name, ip_address):
    """Creates a ticket for the altered DNS, then updates it to resolved."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {HELPDESK_TOKEN.strip()}",
    }

    # 1. Create Ticket
    create_payload = json.dumps({
        "title": f"DNS Configuration Altered - {device_name}",
        "description": f"DNS configuration altered on {device_name} ({ip_address}). Expected: {', '.join(EXPECTED_DNS)}.",
        "status": "open",
        "priority": "medium",
    }).encode("utf-8")

    req = urllib.request.Request(
        TICKET_URL, data=create_payload, headers=headers, method="POST"
    )

    ticket_id = None
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            ticket_id = resp_data.get("id") or resp_data.get("ticket_id")
            print(f"[TICKET] Created ticket #{ticket_id} at {TICKET_URL} for {device_name}")
    except Exception as exc:
        print(f"[WARN] Failed to create ticket at {TICKET_URL}: {exc}", file=sys.stderr)

    # 2. Resolve Ticket
    if ticket_id:
        patch_url = f"{TICKET_URL}/{ticket_id}"
        patch_payload = json.dumps({"status": "resolved"}).encode("utf-8")

        patch_req = urllib.request.Request(
            patch_url, data=patch_payload, headers=headers, method="PATCH"
        )
        try:
            with urllib.request.urlopen(patch_req, timeout=5) as resp:
                print(
                    f"[TICKET] Updated ticket #{ticket_id} to status 'resolved' (HTTP {resp.status})"
                )
        except Exception as exc:
            print(f"[WARN] Failed to resolve ticket #{ticket_id}: {exc}", file=sys.stderr)


def main():
    print(f"[*] Helpdesk ticketing endpoint: {TICKET_URL}")
    print("[*] Enumerating devices from CSV...")
    devices = enumerate_devices(CSV_FILE)

    for dev in devices:
        name = dev["Device Name"].strip()
        ip = dev["Device Address"].strip()
        os_type = dev.get("OS", "").strip().lower()
        user = dev.get("Username", "ubuntu").strip()
        password = dev.get("Password", "ubuntu").strip()

        # Audit only valid Ubuntu clients/servers, skip authoritatives & SMTP
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
                print(
                    f"\n[!] ALERT: DNS configuration altered on {name} ({ip})!"
                )
                print(f"    Current : {current_dns}")
                print(f"    Expected: {EXPECTED_DNS}")

                # 1. Email notification
                send_email_alert(name, ip, current_dns)

                # 2. Remediate DNS
                print(f"[*] Correcting DNS on {name}...")
                status = remediate_dns(ssh)
                print(f"    Remediated status: {status}")

                # 3. Update Web Ticket Service
                create_and_resolve_ticket(name, ip)
                print("-" * 50)
            else:
                print(f"[OK] {name} ({ip}) DNS is compliant.")

        except Exception as err:
            print(f"[-] Could not connect to {name} ({ip}): {err}")
        finally:
            ssh.close()


if __name__ == "__main__":
    main()