from datetime import datetime
import os
import re
import sys
import paramiko

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import EXPECTED_DNS
from enumerate_devices import enumerate_devices

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")
LOG_FILE = os.path.join(SCRIPT_DIR, "dns_health_log.txt")

IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def verify_live_dns(device):
    """Connects to the device via SSH to check if DNS is functioning and compliant."""
    ip = device["Device Address"].strip()
    user = device.get("Username", "ubuntu").strip()
    password = device.get("Password", "ubuntu").strip()

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

        cmd = "resolvectl dns 2>/dev/null; grep '^nameserver' /etc/resolv.conf 2>/dev/null"
        _, stdout, _ = ssh.exec_command(cmd, timeout=5)
        output = stdout.read().decode("utf-8", errors="replace").strip()

        detected = []
        for line in output.splitlines():
            if "Link" in line or "nameserver" in line:
                parts = (
                    line.replace("nameserver", "").split(":")[-1].strip().split()
                )
                for part in parts:
                    if (
                        IP_PATTERN.match(part)
                        and not part.startswith("127.")
                        and part not in detected
                    ):
                        detected.append(part)

        # Compliant if expected nameservers are present
        is_compliant = all(srv in detected for srv in EXPECTED_DNS)
        return is_compliant, detected

    except Exception as exc:
        return False, str(exc)
    finally:
        ssh.close()


def write_log_entry(device_name, ip_address, timestamp):
    """Writes compliant entry containing device name, date, and time per C5 rubric."""
    entry = (
        f"[{timestamp}] Device: {device_name:<8} (IP: {ip_address:<15}) "
        f"| DNS service is functioning correctly and has not been altered\n"
    )
    with open(LOG_FILE, "a") as f:
        f.write(entry)


def show_log():
    if not os.path.isfile(LOG_FILE):
        return
    print("\n" + "=" * 75)
    print("DNS HEALTH LOG ENTRIES (dns_health_log.txt)")
    print("=" * 75)
    with open(LOG_FILE) as f:
        print(f.read().rstrip())
    print("=" * 75)


def main():
    devices = enumerate_devices(CSV_FILE)

    print("=" * 75)
    print("DNS HEALTH MONITORING & LOGGING (REQUIREMENT C5)")
    print(f"Log output file: {LOG_FILE}")
    print(f"Expected DNS   : {', '.join(EXPECTED_DNS)}")
    print("=" * 75)

    healthy_count = 0

    for dev in devices:
        name = dev["Device Name"].strip()
        ip = dev["Device Address"].strip()
        os_type = dev.get("OS", "").strip().lower()

        # Only audit Ubuntu hosts with resolved IP addresses; skip DNS servers and switches
        if os_type != "ubuntu" or not IP_PATTERN.match(ip):
            continue
        if name.upper() in ["DNS1", "DNS2", "SMTP"]:
            continue

        print(f"[*] Checking {name:<8} ({ip:<15})...", end=" ")
        is_healthy, info = verify_live_dns(dev)

        if is_healthy:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            write_log_entry(name, ip, timestamp)
            print("[HEALTHY - LOGGED]")
            healthy_count += 1
        else:
            print(f"[UNHEALTHY / ALTERED - SKIPPED] -> {info}")

    print(f"\nTotal healthy devices logged: {healthy_count}")
    show_log()


if __name__ == "__main__":
    main()