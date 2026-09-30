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

LVOSEC_AGENT_VERSION = "1.23.0"

CONFIG_DIR = "/etc/lvosec"
CONFIG_PATH = "/etc/lvosec/agent.conf"
BIN_PATH = "/usr/local/lib/lvosec/lab-agent-linux.py"
UNIT_PATH = "/etc/systemd/system/lvosec-agent.service"
UNIT_NAME = "lvosec-agent"
LOG_PATH = "/var/log/lvosec-agent.log"
USB_RULE_PATH = "/etc/udev/rules.d/90-lvosec-block-usb.rules"

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


def compute_heartbeat(conf):
    hw = hardware()
    av = clam_av()
    fw = ufw_active()
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
    # posture: absent keys = not reported -> unknown, never a fabricated pass
    if security:
        body["security"] = security
    return body


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