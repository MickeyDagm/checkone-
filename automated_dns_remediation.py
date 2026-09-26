import datetime
import ipaddress
import json
import logging
import os
import re
import shlex
import smtplib
import socket
import urllib.error
import urllib.request

import paramiko
from email.message import EmailMessage
from config import (
    HELPDESK_BASE_URL, HELPDESK_TOKEN, EXPECTED_DNS, SMTP_SERVER,
    SMTP_PORT, FROM_EMAIL, TO_EMAIL,
)
from enumerate_devices import enumerate_devices

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")
TICKET_URL = f"{HELPDESK_BASE_URL.rstrip('/')}/api/tickets"
LOG_FILE = os.path.join(SCRIPT_DIR, "dns_remediation.log")
SSH_TIMEOUT = 10
LAB_PASSWORD = "ubuntu"
LINUX_OS = {"ubuntu", "linux", "debian"}

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("dns-remediation")


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_dns(values):
    """Validate addresses before comparison or inclusion in remote commands."""
    if isinstance(values, str):
        values = values.replace(",", " ").split()
    result = []
    for value in values:
        value = str(ipaddress.ip_address(str(value).strip()))
        if value not in result:
            result.append(value)
    return result


EXPECTED_DNS = normalize_dns(EXPECTED_DNS)
if not EXPECTED_DNS:
    raise ValueError("config.EXPECTED_DNS must contain the lab DNS servers")


def dns_is_correct(current):
    # Compare each scope separately: combining subnets can hide missing servers.
    if isinstance(current, dict):
        return bool(current) and all(dns_is_correct(v) for v in current.values())
    return set(normalize_dns(current)) == set(EXPECTED_DNS)


def dns_text(current):
    if isinstance(current, dict):
        return "; ".join(f"{k}: {', '.join(v) or 'None'}" for k, v in current.items())
    return ", ".join(current) if current else "None detected"


def is_vyos(device):
    return (device["OS"].lower() == "vyos"
            or device["Device Name"].upper() == "ROUTER1")


def get_devices():
    devices = []
    for original in enumerate_devices(CSV_FILE):
        device = dict(original)
        for key in ("Device Name", "Device Address", "OS"):
            device[key] = str(device.get(key) or "").strip()
        name, address = device["Device Name"], device["Device Address"]
        if device["OS"].lower() in {"openvswitch", "ovs"}:
            print(f"[SKIP] {name}: unmanaged switch")
            continue
        try:
            ipaddress.ip_address(address)
        except ValueError:
            print(f"[SKIP] {name}: enumerate_devices returned no usable IP ({address!r})")
            continue
        if not is_vyos(device) and device["OS"].lower() not in LINUX_OS:
            print(f"[SKIP] {name}: unsupported OS {device['OS']}")
            continue
        # Credentials confirmed for this lab, regardless of stale CSV values.
        device["Username"] = "vyos" if is_vyos(device) else "ubuntu"
        device["Password"] = LAB_PASSWORD
        devices.append(device)
    return devices


def connect(device):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=device["Device Address"], port=22,
                       username=device["Username"], password=device["Password"],
                       timeout=SSH_TIMEOUT, auth_timeout=SSH_TIMEOUT,
                       banner_timeout=SSH_TIMEOUT, look_for_keys=False,
                       allow_agent=False)
    except Exception:
        client.close()
        raise
    return client


def run_command(client, command, input_text=None, timeout=SSH_TIMEOUT):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    if input_text is not None:
        stdin.write(input_text)
        stdin.flush()
    stdin.channel.shutdown_write()
    output = stdout.read().decode("utf-8", errors="replace").strip()
    error = stderr.read().decode("utf-8", errors="replace").strip()
    return stdout.channel.recv_exit_status(), output, error


def checked(client, command, input_text=None, timeout=SSH_TIMEOUT):
    code, output, error = run_command(client, command, input_text, timeout)
    if code != 0:
        raise RuntimeError(error or output or f"Remote command failed (exit {code})")
    return output


def sudo(client, script, password):
    # Only the password is sent on stdin; it cannot become resolver-file content.
    return checked(client, "sudo -S -p '' sh -c " + shlex.quote(script),
                   password + "\n", timeout=30)


def parse_resolv_conf(output):
    return normalize_dns([line.split()[1] for line in output.splitlines()
                          if re.match(r"^\s*nameserver\s+\S+", line)])


def parse_resolvectl(output):
    groups = {}
    for line in output.splitlines():
        match = re.match(r"^Global:\s*(.*)$", line.strip())
        if match:
            groups["Global"] = normalize_dns(match.group(1))
            continue
        match = re.match(r"^Link\s+\d+\s+\(([^)]+)\):\s*(.*)$", line.strip())
        if match:
            groups["Link " + match.group(1)] = normalize_dns(match.group(2))
    if not groups:
        raise RuntimeError("Unrecognized resolvectl dns output; DNS was not checked")
    return groups


def linux_state(client):
    conf = checked(client, "cat /etc/resolv.conf")
    file_dns = parse_resolv_conf(conf)
    target = checked(client, "readlink -f /etc/resolv.conf")
    managed = (target.startswith("/run/systemd/resolve/")
               or "managed by man:systemd-resolved" in conf)
    code, output, error = run_command(client, "LC_ALL=C resolvectl dns")
    groups = {}
    if code == 0:
        raw = parse_resolvectl(output)
        groups = {k: v for k, v in raw.items() if v}
        # Empty default-route links must also be checked. Empty unused links
        # (e.g. bridges) should not be assigned DNS arbitrarily.
        routes = json.loads(checked(client, "ip -j route show default"))
        for route in routes:
            interface = route.get("dev")
            if interface and interface != "lo":
                key = "Link " + interface
                if key not in raw:
                    raise RuntimeError(f"Default interface {interface} absent from resolvectl")
                groups[key] = raw[key]
        if not groups:
            raise RuntimeError("No DNS-bearing or default-route interface found")
    elif managed or any(ipaddress.ip_address(v).is_loopback for v in file_dns):
        raise RuntimeError("Cannot read upstream DNS: resolvectl failed: " + (error or output))
    # A regular resolver file may override systemd-resolved for applications.
    # Check it too; do not mistake the managed 127.0.0.53 stub for bad DNS.
    if not managed:
        groups["resolv.conf"] = file_dns
    return groups, target, managed


def get_linux_dns(client):
    return linux_state(client)[0]


def set_linux_dns(client, password):
    groups, target, managed = linux_state(client)
    servers = " ".join(shlex.quote(v) for v in EXPECTED_DNS)
    for scope, values in groups.items():
        if dns_is_correct(values):
            continue
        if scope.startswith("Link "):
            sudo(client, f"resolvectl dns {shlex.quote(scope[5:])} {servers}", password)
            print("    [NOTE] Ubuntu link DNS corrected at runtime; DHCP/reboot can replace it.")
        elif scope == "Global":
            # Setting link DNS does not remove incorrect global servers.
            # Do not claim success when an unsupported global override remains.
            raise RuntimeError("Unexpected global DNS override: correct DNS= in the "
                               "systemd-resolved configuration, then rerun")
        elif scope == "resolv.conf":
            if managed or target != "/etc/resolv.conf":
                raise RuntimeError("Resolver file is managed by another service; "
                                   "correct that service's DNS configuration")
            previous = checked(client, "cat /etc/resolv.conf")
            retained = [line for line in previous.splitlines()
                        if not re.match(r"^\s*nameserver\b", line)]
            content = "\n".join(retained + [f"nameserver {v}" for v in EXPECTED_DNS]) + "\n"
            script = ("set -e\ncp -p /etc/resolv.conf /etc/resolv.conf.dns-remediation.bak\n"
                      "printf '%s' " + shlex.quote(content) + " > /etc/resolv.conf")
            sudo(client, script, password)


def parse_vyos_config(output):
    """Discover all DHCP subnets, including ones with missing DNS options."""
    scopes = {}
    system = []
    for line in output.splitlines():
        tokens = shlex.split(line)
        if tokens[:3] == ["set", "system", "name-server"]:
            system.extend(normalize_dns(tokens[3:]))
        if (len(tokens) < 7 or tokens[:4] !=
                ["set", "service", "dhcp-server", "shared-network-name"]
                or tokens[5] != "subnet"):
            continue
        prefix = tuple(tokens[1:7])
        record = scopes.setdefault(prefix, {"option": ("option", "name-server"), "dns": []})
        tail = tokens[7:]
        if tail[:2] == ["option", "name-server"]:
            record["dns"].extend(normalize_dns(tail[2:]))
        elif tail[:1] == ["dns-server"]:
            record["option"] = ("dns-server",)
            record["dns"].extend(normalize_dns(tail[1:]))
    if not scopes:
        raise RuntimeError("No VyOS DHCP subnets found; cannot check DHCP DNS")
    # Empty router system DNS is valid for this lab; it is distinct from DHCP.
    return scopes, system


def vyos_state(client):
    output = checked(client, "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands")
    return parse_vyos_config(output)


def get_vyos_dns(client):
    scopes, system = vyos_state(client)
    groups = {f"DHCP {p[3]} {p[5]}": r["dns"] for p, r in scopes.items()}
    if system:
        groups["system name-server"] = system
    return groups


def set_vyos_dns(client):
    scopes, system = vyos_state(client)
    changes = []
    for prefix, record in scopes.items():
        if dns_is_correct(record["dns"]):
            continue
        path = shlex.join(prefix + record["option"])
        if record["dns"]:
            changes.append(f"delete {path} || exit 1")
        changes.extend(f"set {path} {shlex.quote(v)} || exit 1" for v in EXPECTED_DNS)
    if system and not dns_is_correct(system):
        changes.append("delete system name-server || exit 1")
        changes.extend(f"set system name-server {shlex.quote(v)} || exit 1" for v in EXPECTED_DNS)
    if not changes:
        return
    script = "\n".join([
        "source /opt/vyatta/etc/functions/script-template || exit 1",
        "configure || exit 1",
        "trap 'exit discard >/dev/null 2>&1' EXIT",
        *changes,
        "commit || exit 1", "save || exit 1", "exit || exit 1", "trap - EXIT",
    ])
    # Run under the VyOS configuration group, never as root via sudo.
    command = "sg vyattacfg -c " + shlex.quote("/bin/vbash -c " + shlex.quote(script))
    checked(client, command, timeout=60)


def get_dns(device, client):
    return get_vyos_dns(client) if is_vyos(device) else get_linux_dns(client)


def correct_dns(device, client):
    if is_vyos(device):
        set_vyos_dns(client)
    else:
        set_linux_dns(client, device["Password"])


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
    current_text = dns_text(current_dns)
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
    current_text = dns_text(current_dns)
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
    ticket_id = ticket.get("id") or ticket.get("ticket_id")
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
        f"DNS configuration matches expected settings - "
        f"Device: {device['Device Name']} - "
        f"Date/Time: {now()} - "
        f"DNS: {dns_text(current_dns)}"
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
        current_text = dns_text(current_dns)
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
        ticket = None
        try:
            ticket = create_dns_ticket(device, current_dns)
        except Exception as exc:
            print(f"    [TICKET] Failed; continuing DNS correction: {exc}")
            logger.error("TICKET CREATE FAILED | %s | %s", name, exc)

        # 3. Correct DNS
        print("    [REMEDIATE] Correcting DNS...")
        correct_dns(device, client)
        print("    [REMEDIATE] DNS configuration updated")

        # 4. Verify
        print("    [VERIFY] Checking DNS again...")
        verified_dns = get_dns(device, client)
        verified_text = dns_text(verified_dns)
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
        if ticket is not None:
            resolve_ticket(ticket, device)
        return True

    except (paramiko.ssh_exception.NoValidConnectionsError,
            paramiko.AuthenticationException, paramiko.SSHException,
            socket.timeout, OSError) as exc:
        print(f"    [UNVERIFIED] SSH/connection error: {exc}")
        print("    DNS could not be checked or corrected. This does not prove the host is offline.")
        logger.error("DNS UNVERIFIED | %s | %s | %s", name, ip, exc)
        return False
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
    print(f"Devices attempted: {len(devices)}")
    print(f"Successful      : {successful}")
    print(f"Failed/unverified: {failed}")
    print(f"Log file        : {LOG_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()