#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LVO Security (lvosec) Linux agent — Ubuntu/Debian, systemd hosts.

The Windows PowerShell agent is the full-featured fleet client; this one is the
VPS/server companion. It speaks the same wire protocol (register, heartbeat,
pending actions, action completion) so an Ubuntu/Contabo-style VPS shows up in
the Blue Team "Machines · VPS" view with its network status and is controllable
through the same locks:

  - firewall: ufw enable/disable (with an SSH-safe guard on enable)
  - USB: block/allow removable storage via a udev rule
  - lock/unlock: loginctl session locks
  - restart/shutdown: systemd shutdown with a grace period
  - send_message: wall broadcast to all logged-in terminals
  - wake: WoL magic-packet relay for offline machines
  - server_url_rotate: switch deployments without a reinstall

Blue Team VPS protection feeds this same agent, on an hourly telemetry
channel separate from the heartbeat:

  - services: the running/enabled systemd unit list (see them in Admin →
    Blue Team, with start/stop/restart/enable/disable controls)
  - packages: the dpkg inventory, compared against a known-vulnerable list
  - authFailures: sshd "Failed password" counts for the last ~24 hours
  - fim: sha-256 baseline of /etc/ssh/sshd_config, /etc/passwd, /etc/shadow,
    /etc/sudoers, /etc/crontab, unit/agent files and common web-server/ufw
    configs; drift is reported as a posture finding
  - sshRateLimited: reported with the heartbeat when ufw rate-limits SSH
  - fw_limit_ssh / fw_unlimit_ssh: ufw `limit 22/tcp` toggle (~6 new
    connections per 30 seconds per source) without touching iptables by hand

Runs as a systemd service (root), one check-in per heartbeat interval, and
self-updates by downloading the bundled script from the server.

Install (Ubuntu / Debian VPS, Administrator shell):

    curl -fsSL "https://YOUR-APP.onrender.com/api/agent/download-linux" \\
      -o /tmp/lab-agent-linux.py
    sudo python3 /tmp/lab-agent-linux.py --install \\
      --server-url "https://YOUR-APP.onrender.com"

Uninstall:

    sudo python3 /usr/local/lib/lvosec/lab-agent-linux.py --uninstall
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

LVOSEC_AGENT_VERSION = "1.24.0"

CONFIG_DIR = "/etc/lvosec"
CONFIG_PATH = "/etc/lvosec/agent.conf"
BIN_PATH = "/usr/local/lib/lvosec/lab-agent-linux.py"
UNIT_PATH = "/etc/systemd/system/lvosec-agent.service"
UNIT_NAME = "lvosec-agent"
LOG_PATH = "/var/log/lvosec-agent.log"
USB_RULE_PATH = "/etc/udev/rules.d/90-lvosec-block-usb.rules"

# The Blue Team "VPS protection" telemetry channel: systemd services, package
# inventory, sshd login failures and config-integrity (FIM) hashes are sent on
# a slow timer so the 10-second heartbeat stays small.
TELEMETRY_INTERVAL_SECONDS = 3600
FIM_CONFIG_PATH = "/etc/lvosec/fim.json"

USB_BLOCK_RULE = """# lvosec: block removable USB mass-storage, leave HID (keyboard/mouse) alone
ACTION=="add", SUBSYSTEM=="usb", DRIVER=="usb-storage", ATTR{authorized}="0"
"""

UNIT_TEMPLATE = """[Unit]
Description=lvosec agent (Linux) — security telemetry & remote management
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {bin} --foreground
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Nice=5

[Install]
WantedBy=multi-user.target
"""


def log(msg):
    line = "[lvosec-agent] %s" % msg
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except OSError:
        pass


def run(cmd, timeout=15):
    """Run a command, return (returncode, stdout). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        out = proc.stdout.decode("utf-8", "replace").strip()
        return proc.returncode, out
    except Exception as exc:  # noqa: BLE001
        return 127, str(exc)


def read_conf():
    conf = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                conf[key.strip()] = value.strip()
    except OSError:
        pass
    return conf


def write_conf(conf):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            for key, value in conf.items():
                fh.write("%s=%s\n" % (key, value))
    except OSError as exc:
        log("could not write config: %s" % exc)
        raise


# --------------------------------------------------------------------------
# Machine info
# --------------------------------------------------------------------------

def os_label():
    name = version = "Linux"
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for raw in fh:
                m = re.match(r'^(NAME|VERSION)="?([^"]*)"?$', raw.strip())
                if m:
                    if m.group(1) == "NAME":
                        name = m.group(2)
                    else:
                        version = m.group(2)
    except OSError:
        pass
    rc, kernel = run(["uname", "-r"])
    tail = " (%s)" % kernel if rc == 0 and kernel else ""
    return "%s %s%s" % (name, version, tail)


def hostname():
    rc, out = run(["hostname"])
    name = out.strip() if rc == 0 and out else "vps"
    return name[:100]


def mac_address():
    rc, out = run(["ip", "link", "show"])
    if rc == 0:
        m = re.search(r"ether\s+([0-9a-fA-F:]{17})", out)
        if m:
            return m.group(1)
    rc, out = run(["cat", "/sys/class/net/eth0/address"])
    if rc == 0 and re.match(r"^[0-9a-f:]+$", out):
        return out
    return None


def local_ip():
    """Interface IP via a connectionless UDP probe (no egress traffic)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and ip != "0.0.0.0":
            return ip
    except OSError:
        pass
    rc, out = run(["hostname", "-I"])
    if rc == 0 and out:
        return out.split()[0]
    return None


def hardware():
    info = {}
    rc, out = run(["lscpu"])
    m = re.search(r"Model name[:\s]+(.+)", out or "")
    if m:
        info["cpuName"] = m.group(1).strip()[:128]
    rc, cores = run(["nproc"])
    if rc == 0 and cores:
        try:
            info["cpuCores"] = int(cores)
        except ValueError:
            pass
    rc, mem = run(["free", "-b"])
    if rc == 0:
        line = next((ln for ln in mem.splitlines() if ln.startswith("Mem:")), None)
        if line:
            try:
                info["totalRAM"] = int(line.split()[1]) // (1024 * 1024)
            except (ValueError, IndexError):
                pass
    try:
        st = os.statvfs("/")
        info["diskTotal"] = st.f_frsize * st.f_blocks
        info["diskFree"] = st.f_frsize * st.f_bavail
    except OSError:
        pass
    return info


def ufw_active():
    rc, out = run(["ufw", "status"], timeout=8)
    if rc != 0:
        return None
    return "status: active" in out.lower()


def clam_av():
    for unit in ("clamav-daemon", "clamd"):
        rc, _ = run(["systemctl", "is-active", unit])
        if rc == 0:
            return True
    if shutil.which("clamd"):
        return True
    return None


# --------------------------------------------------------------------------
# Wire protocol
# --------------------------------------------------------------------------

def api(url, path, body, timeout=10):
    """POST JSON, return (status, parsed json or raw text)."""
    request = urllib.request.Request(
        url.rstrip("/") + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


def probe_health(url, timeout=6):
    """GET /api/healthz and require an explicit 'ok' (matches the Windows agent)."""
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/healthz", timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            return resp.status == 200 and data.get("status") == "ok"
    except Exception:  # noqa: BLE001
        return False


def ssh_rate_limited():
    """True when ufw carries a limit rule for SSH (ufw `limit 22/tcp` or
    `limit OpenSSH`), False when ufw is active without it, None when ufw is
    not usable at all. Only reported as a signal when ufw answered."""
    if not shutil.which("ufw"):
        return None
    rc, status = run(["ufw", "status"])
    if rc != 0:
        return None
    limited = bool(
        re.search(r"\b(?:22/tcp|OpenSSH)\b\s+LIMIT", status or "", re.IGNORECASE)
        or re.search(r"\bLIMIT\b\s+.*\b(?:22/tcp|OpenSSH)\b", status or "", re.IGNORECASE)
    )
    return limited


def compute_heartbeat(conf):
    hw = hardware()
    av = clam_av()
    fw = ufw_active()
    rl = ssh_rate_limited()
    body = {
        "token": conf.get("TOKEN", ""),
        "os": os_label(),
        "agentVersion": LVOSEC_AGENT_VERSION,
        "firewallProfiles": "ufw" if fw is not None else None,
    }
    if fw is not None:
        body["firewallEnabled"] = fw
    if av is not None:
        body["avEnabled"] = av
    mac = mac_address()
    if mac:
        body["macAddress"] = mac
    ip = local_ip()
    if ip:
        body["ipAddress"] = ip
    for key, value in hw.items():
        body[key] = value
    security = {}
    if fw is not None:
        security["firewallAllProfiles"] = bool(fw)
    if av is not None:
        security["avRealtimeProtection"] = bool(av)
    if rl is not None:
        security["sshRateLimited"] = bool(rl)
    # posture: absent keys = not reported -> unknown, never a fabricated pass
    if security:
        body["security"] = security
    return body


# ---------------------------------------------------------------------------
# VPS telemetry collectors — the hourly Blue Team channel. Everything here is
# best-effort: a failing collection returns None and the server stores what it
# got, never fabricating data.
# ---------------------------------------------------------------------------

SERVICE_FILE_STATES = ("enabled", "disabled", "static", "masked", "generated", "indirect")


def collect_services():
    """systemd service units with their runtime state and boot enablement."""
    rc, out = run(
        ["systemctl", "list-unit-files", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"],
        timeout=30,
    )
    if rc != 0:
        return None
    units = {}
    for line in (out or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        state = parts[-1] if len(parts) > 1 and parts[-1] in SERVICE_FILE_STATES else None
        units[name] = {"name": name, "enabled": state}
    rc2, out2 = run(
        ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"],
        timeout=30,
    )
    if rc2 == 0:
        for line in (out2 or "").splitlines():
            parts = line.split(None, 3)
            if len(parts) < 2:
                continue
            entry = units.setdefault(parts[0], {"name": parts[0], "enabled": None})
            entry["active"] = parts[1]
            if len(parts) > 2:
                entry["sub"] = parts[2]
    result = [
        {"name": u["name"], "active": u.get("active", "unknown"), "sub": u.get("sub"), "enabled": u.get("enabled")}
        for u in units.values()
    ]

    def sort_key(item):
        running = item["active"] == "active"
        enabled = item.get("enabled") == "enabled"
        return (0 if running or enabled else 1, item["name"])

    result.sort(key=sort_key)
    return result[:400]


def collect_packages():
    """dpkg package inventory (name + version). None when dpkg is unavailable."""
    if not shutil.which("dpkg-query"):
        return None
    rc, out = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=60)
    if rc != 0:
        return None
    packages = []
    for line in (out or "").splitlines():
        if "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        if name and version:
            packages.append({"name": name, "version": version})
    packages.sort(key=lambda p: p["name"])
    return packages[:3000]


AUTH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]


def collect_authfail():
    """sshd 'Failed password' lines in the current auth log. auth.log rotates
    daily on Ubuntu/Debian, so this is approximately the last 24 hours, plus
    the top source IPs. Falls back to journalctl when no auth log exists."""
    count = 0
    ip_counts = {}
    found = False
    for log_path in AUTH_LOG_PATHS:
        if not os.path.exists(log_path):
            continue
        found = True
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if "Failed password" not in line:
                        continue
                    count += 1
                    match = re.search(r"\bfrom\s+([0-9a-fA-F.:]+)\b", line)
                    if match:
                        ip = match.group(1)
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        except OSError:
            continue
    if not found:
        rc, out = run(
            ["journalctl", "-u", "ssh", "--since", "24 hours ago", "--no-pager"],
            timeout=20,
        )
        if rc == 0:
            for line in (out or "").splitlines():
                if "Failed password" not in line:
                    continue
                count += 1
                match = re.search(r"\bfrom\s+([0-9a-fA-F.:]+)\b", line)
                if match:
                    ip = match.group(1)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top = sorted(ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return {
        "count24h": count,
        "topSources": [{"ip": ip, "count": c} for ip, c in top],
    }


# Config files whose hash changes are a plausible-compromise signal. The first
# run snapshots them as the baseline; every later run compares against it.
FIM_PATHS = [
    "/etc/ssh/sshd_config",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hostname",
    "/etc/crontab",
    BIN_PATH,
    UNIT_PATH,
]
FIM_OPTIONAL_PATHS = [
    "/etc/nginx/nginx.conf",
    "/etc/apache2/apache2.conf",
    "/etc/ufw/user.rules",
    "/etc/iptables/rules.v4",
]


def sha256_file(file_path):
    try:
        digest = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def collect_fim():
    """Hashes the protected file set and compares it to the stored baseline.

    Returns {"status": "clean"|"drift", "changed": [...]}. The first run
    writes the baseline and reports clean instead of crying wolf."""
    watched = list(FIM_PATHS)
    for optional in FIM_OPTIONAL_PATHS:
        if optional and os.path.exists(optional):
            watched.append(optional)
    current = {}
    for file_path in sorted(set(watched)):
        digest = sha256_file(file_path)
        if digest:
            current[file_path] = digest
    baseline = {}
    try:
        with open(FIM_CONFIG_PATH, "r", encoding="utf-8") as fh:
            parsed = json.loads(fh.read() or "{}")
        if isinstance(parsed, dict):
            baseline = parsed
    except (OSError, ValueError):
        baseline = {}
    if not baseline:
        try:
            with open(FIM_CONFIG_PATH, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(current, indent=2))
        except OSError:
            pass
        return {"status": "clean", "changed": []}
    changed = [
        {"path": file_path, "hash": digest}
        for file_path, digest in sorted(current.items())
        if baseline.get(file_path) != digest
    ]
    return {"status": "drift" if changed else "clean", "changed": changed[:40]}


def maybe_send_telemetry(server_url, conf):
    """Hourly push of the VPS telemetry channel. Never retries immediately; the
    next cycle simply tries again after the interval."""
    now = time.time()
    last = 0
    try:
        last = float(conf.get("LAST_TELEMETRY") or 0)
    except (TypeError, ValueError):
        last = 0
    if now - last < TELEMETRY_INTERVAL_SECONDS:
        return
    payload = {
        "token": conf.get("TOKEN", ""),
        "services": collect_services(),
        "packages": collect_packages(),
        "authFailures": collect_authfail(),
        "fim": collect_fim(),
    }
    status, _ = api(server_url, "/api/agent/telemetry", payload)
    if status == 200:
        conf["LAST_TELEMETRY"] = str(int(now))
        write_conf(conf)
    else:
        log("telemetry push failed (%s) — will retry next interval" % status)


def ensure_registered(server_url, conf, name_override, room_override):
    token = conf.get("TOKEN")
    if token:
        return True, conf
    hw = hardware()
    body = {
        "name": (name_override or hostname())[:100],
        "os": os_label(),
        "agentVersion": LVOSEC_AGENT_VERSION,
        "macAddress": mac_address(),
        "ipAddress": local_ip(),
    }
    for key, value in hw.items():
        if key in ("totalRAM", "cpuName", "cpuCores"):
            body[key] = value
    status, data = api(server_url, "/api/agent/register", body)
    if status == 200 and isinstance(data, dict) and data.get("token"):
        conf["TOKEN"] = data["token"]
        conf["COMPUTER_ID"] = str(data.get("computerId", ""))
        conf["COMPUTER_NAME"] = str(data.get("name", ""))
        if room_override:
            conf["ROOM"] = room_override
        write_conf(conf)
        log("registered as %r (computerId=%s)" % (data.get("name"), data.get("computerId")))
        return True, conf
    log("register failed (%s): %s" % (status, data))
    return False, conf


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------

def action_lock():
    rc, _ = run(["loginctl", "lock-sessions"])
    return rc == 0, "Interactive sessions locked (or none present)"


def action_unlock():
    rc, _ = run(["loginctl", "unlock-sessions"])
    return rc == 0, "Session lock released"


def action_restart():
    rc, _ = run(["shutdown", "-r", "+1", "lvosec: restart requested by operator"])
    return rc == 0, "Restart scheduled in 60 seconds"


def action_shutdown():
    rc, _ = run(["shutdown", "-h", "+1", "lvosec: shutdown requested by operator"])
    return rc == 0, "Shutdown scheduled in 60 seconds"


def action_message(text):
    if not text:
        return False, "No message text supplied"
    rc, _ = run(["/usr/bin/wall", text], timeout=10)
    detail = "Broadcast to all logged-in terminals"
    if rc != 0 or not shutil.which("wall"):
        banner = "/tmp/lvosec-message.txt"
        try:
            with open(banner, "w", encoding="utf-8") as fh:
                fh.write(text)
            detail = "Written to %s (no wall available)" % banner
            return True, detail
        except OSError:
            return False, "wall not available and banner write failed"
    return True, detail


def action_fw_enable():
    if not shutil.which("ufw"):
        return False, "ufw is not installed — install it with: sudo apt install ufw"
    rc, status = run(["ufw", "status"])
    if rc == 0 and "status: active" in status.lower():
        return True, "Firewall already active"
    # SSH-safe guard: never flip ufw on without allowing port 22 first.
    has_ssh = bool(re.search(r"\b(22/tcp|OpenSSH)\b", status or ""))
    if not has_ssh and shutil.which("ufw"):
        run(["ufw", "allow", "22/tcp"], timeout=20)
    rc, out = run(["ufw", "--force", "enable"], timeout=30)
    if rc == 0 or "status: active" in out.lower():
        return True, "ufw enabled (SSH port 22 allowed as a safety guard)"
    return False, "ufw enable failed: %s" % out[:200]


def action_fw_disable():
    if not shutil.which("ufw"):
        return False, "ufw is not installed"
    proc = subprocess.run(
        ["ufw", "disable"],
        input=b"y\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    out = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode != 0 and "status: inactive" not in out.lower():
        return False, "ufw disable failed: %s" % out[:200]
    return True, "ufw disabled — machine exposed to the internet"


SERVICE_ACTION_COMMANDS = {
    "service_start": ["systemctl", "start"],
    "service_stop": ["systemctl", "stop"],
    "service_restart": ["systemctl", "restart"],
    "service_enable": ["systemctl", "enable"],
    "service_disable": ["systemctl", "disable"],
}
SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.@+-]+$")


def action_service(service, operation):
    if not service:
        return False, "No service name supplied in the action payload"
    if not SERVICE_NAME_RE.match(service):
        return False, "Invalid service name: %r" % service
    cmd = SERVICE_ACTION_COMMANDS.get(operation)
    if not cmd:
        return False, "Unsupported service operation: %s" % operation
    rc, _ = run(cmd + [service], timeout=30)
    verb = operation.replace("service_", "")
    if rc == 0:
        return True, "systemctl %s %s" % (verb, service)
    return False, "systemctl %s %s failed (exit %s)" % (verb, service, rc)


def action_fw_rate_limit_ssh():
    """ufw `limit` caps SSH at ~6 new connections per 30 seconds per source —
    the basic brute-force damper without touching iptables directly."""
    if not shutil.which("ufw"):
        return False, "ufw is not installed — install it with: sudo apt install ufw"
    rc, status = run(["ufw", "status"])
    if rc != 0:
        return False, "ufw status failed — is the firewall active?"
    if re.search(r"\b(?:22/tcp|OpenSSH)\b\s+LIMIT", status or "", re.IGNORECASE):
        return True, "SSH is already rate-limited (ufw limit rule present)"
    rc, _ = run(["ufw", "limit", "OpenSSH"])
    if rc != 0:
        rc, _ = run(["ufw", "limit", "22/tcp"])
    if rc != 0:
        return False, "Could not add the ufw limit rule for SSH"
    return True, "SSH rate limiting applied — ufw limit 22/tcp (max ~6 new connections/30s per source)"


def action_fw_unrate_limit_ssh():
    """Removes the SSH limit rule and re-adds a plain allow so SSH stays up."""
    if not shutil.which("ufw"):
        return False, "ufw is not installed — install it with: sudo apt install ufw"
    removed = False
    rc, _ = run(["ufw", "delete", "limit", "22/tcp"])
    if rc != 0:
        rc, _ = run(["ufw", "delete", "limit", "OpenSSH"])
    removed = rc == 0
    rc2, _ = run(["ufw", "allow", "22/tcp"])
    if rc2 != 0:
        run(["ufw", "allow", "OpenSSH"])
    if removed:
        return True, "SSH rate limiting removed; SSH remains reachable by its plain allow rule"
    return True, "No SSH limit rule was present (plain allow ensured)"


def usb_unmount_removables():
    for base in ("/media", "/run/media", "/mnt"):
        if not os.path.isdir(base):
            continue
        for entry in os.listdir(base):
            path = os.path.join(base, entry)
            if os.path.ismount(path):
                run(["umount", path], timeout=20)


def action_block_usb():
    try:
        os.makedirs("/etc/udev/rules.d", exist_ok=True)
        with open(USB_RULE_PATH, "w", encoding="utf-8") as fh:
            fh.write(USB_BLOCK_RULE)
        run(["udevadm", "control", "--reload-rules"], timeout=15)
        run(["udevadm", "trigger", "--subsystem-match=usb", "--action=add"], timeout=30)
        usb_unmount_removables()
        return True, "Removable USB storage blocked by udev rule; drives unmounted"
    except OSError as exc:
        return False, "Could not write udev rule: %s" % exc


def action_allow_usb():
    try:
        if os.path.exists(USB_RULE_PATH):
            os.remove(USB_RULE_PATH)
        run(["udevadm", "control", "--reload-rules"], timeout=15)
        run(["udevadm", "trigger", "--subsystem-match=usb", "--action=add"], timeout=30)
        return True, "USB storage allowed again (udev rule removed)"
    except OSError as exc:
        return False, "Could not remove udev rule: %s" % exc


def action_wake(payload):
    mac = (payload or {}).get("mac")
    if not mac:
        return False, "No target MAC supplied for wake"
    mac = mac.replace(":", "").replace("-", "").lower()
    if len(mac) != 12:
        return False, "Invalid MAC address"
    magic = bytes.fromhex("ff" * 6 + mac * 16)
    port = int((payload or {}).get("port") or 9)
    target = (payload or {}).get("ip") or "255.255.255.255"
    sent = False
    for family in (socket.AF_INET,):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic, (target, port))
            sock.close()
            sent = True
        except OSError:
            continue
    return sent, "Wake-on-LAN magic packet sent to %s:%s" % (target, port)


def action_rotate(server_url, payload):
    new_url = (payload or {}).get("url") or ""
    candidate = new_url.strip().rstrip("/")
    if not candidate.startswith("https://"):
        return False, "Server URL must use https."
    if "@" in candidate.split("://", 1)[1]:
        return False, "Server URL must not contain credentials."
    if not probe_health(candidate):
        return False, "New server did not answer /api/healthz (must report status ok)"
    conf = read_conf()
    conf["SERVER_URL"] = candidate
    write_conf(conf)
    return True, "Server URL rotated to %s" % candidate


def handle_actions(server_url, token, pending):
    results = []
    for item in pending or []:
        action_id = item.get("id")
        action_name = item.get("action")
        message = item.get("message")
        payload = {}
        raw = item.get("payload")
        if raw:
            try:
                payload = json.loads(raw)
            except (ValueError, TypeError):
                payload = {}
        success, detail = False, "Unsupported action on Linux agent: %s" % action_name

        if action_name == "lock":
            success, detail = action_lock()
        elif action_name == "unlock":
            success, detail = action_unlock()
        elif action_name == "restart":
            success, detail = action_restart()
        elif action_name == "shutdown":
            success, detail = action_shutdown()
        elif action_name == "send_message":
            success, detail = action_message(message or payload.get("message"))
        elif action_name == "fw_enable":
            success, detail = action_fw_enable()
        elif action_name == "fw_disable":
            success, detail = action_fw_disable()
        elif action_name == "block_usb":
            success, detail = action_block_usb()
        elif action_name == "allow_usb":
            success, detail = action_allow_usb()
        elif action_name in ("wake", "wol_relay"):
            success, detail = action_wake(payload)
        elif action_name == "server_url_rotate":
            success, detail = action_rotate(server_url, payload)
        elif action_name == "fw_limit_ssh":
            success, detail = action_fw_rate_limit_ssh()
        elif action_name == "fw_unlimit_ssh":
            success, detail = action_fw_unrate_limit_ssh()
        elif action_name in SERVICE_ACTION_COMMANDS:
            success, detail = action_service(payload.get("service"), action_name)
        # remote_view / remote_input / remote_control / disable_rdp / av_* /
        # push_file / delete_file / list_files / sleep are Windows concerns and
        # are honestly reported as failed rather than silently ignored.

        if action_id is not None:
            body = {"token": token, "success": bool(success)}
            if detail:
                body["detail"] = detail[:400]
            status, resp = api(
                server_url, "/api/agent/actions/%s/complete" % action_id, body
            )
            if status != 200:
                log("action %s: server rejected completion (%s)" % (action_id, status))
        log("action %s -> %s: %s" % (action_id, action_name, detail))
        results.append((action_name, success, detail))
    return results


# --------------------------------------------------------------------------
# Self update
# --------------------------------------------------------------------------

def self_update(server_url, force=False):
    """Download the bundled script; swap it in place and restart the service."""
    url = server_url.rstrip("/") + "/api/agent/download-linux"
    tmp = "/tmp/lab-agent-linux-new.py"
    try:
        urllib.request.urlretrieve(url, tmp, )
        with open(tmp, "r", encoding="utf-8") as fh:
            head = fh.read(400)
        m = re.search(r"LVOSEC_AGENT_VERSION\s*=\s*['\"]([^'\"]+)", head)
        if not m or not head.startswith("#!"):
            log("self-update: downloaded script did not look like the agent")
            return False
        if m.group(1) == LVOSEC_AGENT_VERSION and not force:
            log("self-update: already at %s" % LVOSEC_AGENT_VERSION)
            return False
        rc, out = run([sys.executable, "-m", "py_compile", tmp])
        if rc != 0:
            log("self-update: downloaded script failed to compile: %s" % out[:200])
            return False
        os.chmod(tmp, 0o755)
        os.makedirs(os.path.dirname(BIN_PATH), exist_ok=True)
        os.replace(tmp, BIN_PATH)
        log("self-update: installed %s (was %s)" % (m.group(1), LVOSEC_AGENT_VERSION))
    except Exception as exc:  # noqa: BLE001
        log("self-update failed: %s" % exc)
        return False

    if os.getenv("INVOCATION_ID") or os.path.exists("/run/systemd/system"):
        run(["systemctl", "restart", UNIT_NAME], timeout=30)
        return True
    os.execv(sys.executable, [sys.executable, BIN_PATH, "--foreground"])
    return True


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------

def cycle(conf, name_override):
    server_url = (conf.get("SERVER_URL") or "").rstrip("/")
    if not server_url.startswith("http"):
        log("no server URL configured; run --install --server-url https://...")
        return conf, 60
    ok, conf = ensure_registered(server_url, conf, name_override, None)
    if not ok:
        return conf, 30
    body = compute_heartbeat(conf)
    status, data = api(server_url, "/api/agent/heartbeat", body)
    if status == 401:
        conf.pop("TOKEN", None)
        write_conf(conf)
        log("heartbeat rejected (%s) — re-registering" % data)
        return conf, 10
    if status != 200:
        log("heartbeat failed (%s)" % status)
        return conf, 30

    latest = data.get("latestAgentVersion") if isinstance(data, dict) else None
    if isinstance(data, dict) and data.get("agentUpdateRequested") and latest:
        if latest != LVOSEC_AGENT_VERSION:
            self_update(server_url)
            return conf, 120
    if isinstance(data, dict) and data.get("pendingActions"):
        handle_actions(server_url, conf.get("TOKEN", ""), data["pendingActions"])
    # Hourly VPS telemetry channel — services, packages, login failures, FIM.
    maybe_send_telemetry(server_url, conf)
    return conf, int(conf.get("HEARTBEAT_SECONDS") or 10)


def install(server_url, name_override, room_override):
    if not server_url:
        print("--server-url https://... is required for --install")
        return 1
    os.makedirs(os.path.dirname(BIN_PATH), exist_ok=True)
    shutil.copy2(sys.argv[0], BIN_PATH)
    os.chmod(BIN_PATH, 0o755)
    unit = UNIT_TEMPLATE.format(bin=BIN_PATH)
    with open(UNIT_PATH, "w", encoding="utf-8") as fh:
        fh.write(unit)
    run(["systemctl", "daemon-reload"], timeout=20)
    run(["systemctl", "enable", UNIT_NAME], timeout=20)
    run(["systemctl", "start", UNIT_NAME], timeout=20)
    write_conf({"SERVER_URL": server_url.rstrip("/")})
    if room_override:
        conf = read_conf()
        conf["ROOM"] = room_override
        write_conf(conf)
    print("lvosec agent installed as systemd service '%s'" % UNIT_NAME)
    print("config: %s" % CONFIG_PATH)
    print("log: journalctl -u %s -f  (or %s)" % (UNIT_NAME, LOG_PATH))
    print("The VPS will register under its hostname within a minute.")
    return 0


def uninstall():
    run(["systemctl", "stop", UNIT_NAME], timeout=20)
    run(["systemctl", "disable", UNIT_NAME], timeout=20)
    for path in (UNIT_PATH,):
        try:
            os.remove(path)
        except OSError:
            pass
    run(["systemctl", "daemon-reload"], timeout=20)
    try:
        os.remove(CONFIG_PATH)
    except OSError:
        pass
    print("lvosec agent stopped and removed (binary kept at %s)" % BIN_PATH)
    print("To remove the binary and logs too: sudo rm -rf %s /var/log/lvosec-agent.log /etc/lvosec" % os.path.dirname(BIN_PATH))
    return 0


def main():
    parser = argparse.ArgumentParser(description="lvosec Linux agent")
    parser.add_argument("--server-url", dest="server_url", default="", help="lvosec server URL, e.g. https://lvosec.onrender.com")
    parser.add_argument("--install", action="store_true", help="install as a systemd service and start it")
    parser.add_argument("--uninstall", action="store_true", help="stop and remove the service")
    parser.add_argument("--foreground", action="store_true", help="run the agent loop in this process (service mode)")
    parser.add_argument("--name", default="", help="override the computer name")
    parser.add_argument("--room", default="", help="set the room label at registration")
    parser.add_argument("--once", action="store_true", help="run a single heartbeat cycle then exit (diagnostics)")
    args = parser.parse_args()

    if args.install:
        sys.exit(install(args.server_url.strip(), args.name.strip(), args.room.strip()))
    if args.uninstall:
        sys.exit(uninstall())

    if not args.server_url:
        conf = read_conf()
        args.server_url = conf.get("SERVER_URL", "")

    if args.server_url:
        conf = read_conf()
        conf["SERVER_URL"] = args.server_url.rstrip("/")
        write_conf(conf)

    if args.once:
        conf = read_conf()
        ok, conf = ensure_registered(args.server_url, conf, args.name, args.room)
        if not ok:
            return 1
        body = compute_heartbeat(conf)
        status, data = api(args.server_url, "/api/agent/heartbeat", body)
        print("heartbeat status=%s" % status)
        if isinstance(data, dict) and data.get("pendingActions"):
            print("pending actions: %s" % json.dumps(data["pendingActions"]))
        return 0 if status == 200 else 1

    log("lvosec Linux agent %s starting (server=%s)" % (LVOSEC_AGENT_VERSION, args.server_url or "(from config)"))
    conf = read_conf()
    while True:
        try:
            conf, delay = cycle(conf, args.name)
        except Exception as exc:  # noqa: BLE001
            log("cycle error: %s" % exc)
            delay = 30
        time.sleep(delay)


if __name__ == "__main__":
    main()