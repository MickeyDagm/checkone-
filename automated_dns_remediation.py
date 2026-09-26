from datetime import datetime
import email.utils
import os
import re
import smtplib
import sys
import paramiko
import requests

from config import (
    EXPECTED_DNS,
    FROM_EMAIL,
    HELPDESK_BASE_URL,
    HELPDESK_TOKEN,
    SEND_EMAIL,
    SMTP_PORT,
    SMTP_SERVER,
    TICKET_URL,
    TO_EMAIL,
)
from enumerate_devices import CSV_FILE, enumerate_devices

IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def send_email(subject, body):
    """Sends an email notification if SEND_EMAIL is enabled, otherwise prints to console."""
    if not SEND_EMAIL or not SMTP_SERVER:
        print("\n" + "=" * 20 + " EMAIL NOTIFICATION (DRY RUN) " + "=" * 20)
        print(f"To: {TO_EMAIL}\nFrom: {FROM_EMAIL}\nSubject: {subject}\n\n{body}")
        print("=" * 60 + "\n")
        return

    msg = f"From: {FROM_EMAIL}\r\nTo: {TO_EMAIL}\r\nSubject: {subject}\r\nDate: {email.utils.formatdate(localtime=True)}\r\n\r\n{body}"
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.sendmail(FROM_EMAIL, [TO_EMAIL], msg)
        print(f"[EMAIL] Alert sent successfully: {subject}")
    except Exception as exc:
        print(f"[WARN] Failed to send email alert: {exc}", file=sys.stderr)


def send_altered_dns_alert(device_name, ip_address, detected_dns):
    """Formats and sends the 'DNS Setting Altered Notification' email."""
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

    send_email(subject, body)


def get_device_dns(ssh_client):
    """Retrieves configured DNS servers using resolvectl."""
    stdin, stdout, stderr = ssh_client.exec_command(
        "resolvectl dns 2>/dev/null", timeout=5
    )
    output = stdout.read().decode("utf-8", errors="replace").strip()

    detected_dns = []
    for line in output.splitlines():
        if "Link" in line:
            parts = line.split(":")[-1].strip().split()
            for part in parts:
                if IP_PATTERN.match(part) and part not in detected_dns:
                    detected_dns.append(part)
    return detected_dns


def remediate_dns(ssh_client, interface="ens3"):
    """Corrects the DNS settings on the remote node using resolvectl."""
    expected_str = " ".join(EXPECTED_DNS)
    cmd = (
        f"sudo resolvectl dns {interface} {expected_str} && "
        f"sudo resolvectl flush-caches"
    )
    stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=10)
    stdout.channel.recv_exit_status()  # Wait for command completion

    # Verify remediation
    verify_stdin, verify_stdout, _ = ssh_client.exec_command(
        f"resolvectl dns {interface}", timeout=5
    )
    res = verify_stdout.read().decode("utf-8", errors="replace").strip()
    return res


def update_ticket_system(device_name, ip_address):
    """Searches for an open ticket for the device or creates/resolves it in Helpdesk."""
    headers = {"Content-Type": "application/json"}
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"

    resolution_note = (
        f"Resolved: DNS configuration restored to {', '.join(EXPECTED_DNS)} "
        f"on {device_name} ({ip_address}) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."
    )

    try:
        # Check existing tickets
        resp = requests.get(TICKET_URL, headers=headers, timeout=5)
        ticket_id = None

        if resp.status_code == 200:
            tickets = resp.json()
            # Handle if tickets are enclosed in a list or dict
            ticket_list = (
                tickets if isinstance(tickets, list) else tickets.get("data", [])
            )
            for t in ticket_list:
                title = t.get("title", "") or t.get("description", "")
                if (
                    device_name.lower() in title.lower()
                    or ip_address in title.lower()
                ):
                    if t.get("status", "").lower() != "resolved":
                        ticket_id = t.get("id")
                        break

        # Update existing ticket or post resolution update
        if ticket_id:
            patch_url = f"{TICKET_URL}/{ticket_id}"
            payload = {
                "status": "Resolved",
                "notes": resolution_note,
                "resolution": resolution_note,
            }
            p_resp = requests.patch(
                patch_url, json=payload, headers=headers, timeout=5
            )
            print(
                f"[TICKET] Updated ticket #{ticket_id} for {device_name} to 'Resolved' (HTTP {p_resp.status_code})"
            )
        else:
            # If no open ticket was found, create a resolved ticket log entry
            payload = {
                "title": f"DNS Issue Resolved: {device_name}",
                "description": resolution_note,
                "device": device_name,
                "status": "Resolved",
            }
            c_resp = requests.post(
                TICKET_URL, json=payload, headers=headers, timeout=5
            )
            print(
                f"[TICKET] Created resolution ticket for {device_name} (HTTP {c_resp.status_code})"
            )

    except Exception as exc:
        print(f"[WARN] Helpdesk ticketing update failed: {exc}", file=sys.stderr)


def main():
    print("[*] Enumerating network devices...")
    devices = enumerate_devices(CSV_FILE)

    for dev in devices:
        name = dev["Device Name"].strip()
        ip = dev["Device Address"].strip()
        os_type = dev.get("OS", "").strip().lower()
        user = dev.get("Username", "ubuntu").strip()
        password = dev.get("Password", "ubuntu").strip()

        # Only audit Ubuntu client/server nodes (skip routers, switches, and authoritatives)
        if os_type != "ubuntu" or not IP_PATTERN.match(ip):
            continue
        if name.upper() in ["DNS1", "DNS2", "SMTP"]:
            continue

        print(f"[*] Auditing {name} ({ip})...")
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

            # Check if all EXPECTED_DNS servers are present
            is_compliant = all(srv in current_dns for srv in EXPECTED_DNS)

            if not is_compliant:
                print(
                    f"\n[!] ALERT: DNS configuration altered on {name} ({ip})!"
                )
                print(f"    Current : {current_dns}")
                print(f"    Expected: {EXPECTED_DNS}")

                # 1. Send Task 2 Email Template alert
                send_altered_dns_alert(name, ip, current_dns)

                # 2. Correct DNS configuration
                print(f"[*] Correcting DNS on {name}...")
                verified = remediate_dns(ssh)
                print(f"    Remediated status: {verified}")

                # 3. Update Helpdesk Ticket
                update_ticket_system(name, ip)
                print("-" * 50)
            else:
                print(f"[OK] {name} DNS configuration is compliant.\n")

        except Exception as err:
            print(f"[-] Could not connect or audit {name} ({ip}): {err}\n")
        finally:
            ssh.close()


if __name__ == "__main__":
    main()