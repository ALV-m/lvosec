# Protecting a Windows VPS with the lvosec agent

The **Blue Team dashboard** (`/t/:slug/blue-team`) is the seat for protecting
your machines and VPSes through lvosec. Install an agent on a VPS and it
registers under your account, then firewall, USB, lock, restart and operator
message controls work from the Blue Team page (and the Computers page).

Two agents speak the same protocol and appear in the same view:

- **Windows** — the PowerShell agent every lab PC runs (`lab-agent.ps1`).
- **Linux** — a Python 3 companion for Ubuntu/Debian VPSes (Contabo-style)
  covering the same controls (`lab-agent-linux.py`, see below).

## Install on the VPS

Open an **Administrator PowerShell** on the Windows VPS and paste:

```powershell
$s='https://<your-render-host>'; iwr "$s/api/agent/download" -OutFile "$env:TEMP\lab-agent.ps1"; powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\lab-agent.ps1" -ServerUrl $s -Install; Remove-Item "$env:TEMP\lab-agent.ps1"
```

On the Blue Team dashboard you don't have to type any of this — **Machines ·
VPS → Add machine** prints the exact command (with your server URL) and a Copy
button.

What the install does:

- Installs the agent as a **SYSTEM boot task** (survives reboots, no login
  required) and starts the foreground check-in immediately.
- Phones home with the host name, **public IP + MAC**, Windows Firewall state
  (domain/private/public profiles), AV status, hardware fingerprint and OS
  version.
- The machine appears in **Blue Team → Machines · VPS** within a minute,
  named after the host.

## One-time reuse

Run once manually in front of the same agent script on future controls from
the dashboard:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\lab-agent.ps1" -ServerUrl $s
```

## Controls available from Blue Team

| Control | What it does on the VPS |
| --- | --- |
| Firewall toggle | `fw_enable` / `fw_disable` — switches the VPS's own Windows Firewall. **Disabling opens the VPS to the internet; only do it deliberately.** |
| USB block / allow | `block_usb` / `allow_usb` — blocks storage-class devices from the VPS (useful on dedicated servers hosting untrusted media). |
| Lock / Unlock | `lock` / `unlock` — locks the interactive session and gates check-ins. Headless VPSes that never have an interactive session are better handled with restart or message. |
| Restart | `restart` — reboots after a 30-second grace, with an on-screen reason. Good for applying a firewall toggle that needs a clean boot. |
| Send message | `send_message` — shows an operator banner on the machine's screen. |

Every control goes through the same `queueMachineAction` pipeline as the lab:
queued → sent → acknowledged, with each action appended to that account's
`lab_events` audit trail.

## Linux servers & VPSes (Ubuntu / Debian — Contabo-style)

The PowerShell agent is Windows-only. For Linux VPSes (Ubuntu 20.04/22.04/24.04,
Debian 11/12, most Contabo and Hetzner images) there is a Python 3 companion
agent that speaks the same protocol and appears in the same **Blue Team →
Machines · VPS** table with the same controls.

### Install on the VPS

Open a root administrator shell on the VPS and paste:

```bash
curl -fsSL "https://<your-render-host>/api/agent/download-linux" -o /tmp/lab-agent-linux.py && sudo python3 /tmp/lab-agent-linux.py --install --server-url "https://<your-render-host>"
```

Blue Team → **Machines · VPS → Add machine** shows this exact command (already
filled with your server URL) with a Copy button.

What the install does:

- Installs a **systemd service** (`lvosec-agent`) running as root, with
  `Restart=always`.
- Registers under the **host name** within a minute and starts heartbeating
  public IP + MAC + OS + ufw firewall state.
- Supports `--name NAME` / `--room ROOM` to override the label, and
  `--uninstall` to remove the service:
  `sudo python3 /usr/local/lib/lvosec/lab-agent-linux.py --uninstall`.

### Linux controls

| Control | What it does on the VPS |
| --- | --- |
| Firewall toggle | `fw_enable` / `fw_disable` via **ufw**. Enabling is SSH-safe: the agent allows port 22 first if no SSH rule exists, so a fresh VPS cannot lock itself out. **Disabling opens the VPS to the internet.** |
| USB block / allow | Writes/removes a udev rule that sets `authorized=0` on new USB-mass-storage devices only (keyboard/mouse HIDs are left alone), unmounts any currently mounted removable drives, and reloads the rules. |
| Lock / Unlock | `loginctl lock-sessions` / `unlock-sessions` for interactive sessions. Headless VPSes have none, so use restart or message instead. |
| Restart / Shutdown | `shutdown -r +1` / `shutdown -h +1` — a 60-second grace with a reason broadcast to terminals. |
| Send message | Broadcast with **wall** to every logged-in terminal (falls back to a banner file if `wall` is unavailable). |
| Wake | WoL magic-packet relay for offline machines (broadcast UDP port 9). |
| Server URL rotate | Validates `https://` + probes `/api/healthz` before committing, then persists the new URL — no reinstall. |

Actions unsupported on Linux (remote view/input, AV scan, file push, RDP etc.)
are **reported as failed with the reason** rather than silently ignored, so the
dashboard never shows a fake success.

### Notes

- Requires **Python 3** (preinstalled on Ubuntu) and systemd.
- Software inventory (the 1-hour channel) is Windows-only today — Linux assets
  show up under posture/firewall/USB but not yet in the installed-software
  list.
- post a Linux machine and the posture engine only marks checks **unknown**
  when a Windows-specific signal is missing — it never invents a failure.

## Requirements & notes

- **Windows 10/11 or Windows Server 2016+** with PowerShell 5.1+ — nothing else
  to install.
- The VPS must reach your Render host on **HTTPS** — the agent refuses
  non-HTTPS server URLs when rotating between deployments
  (`server_url_rotate`), so install with an `https://` URL from the start.
- Firewall state shows as **?** until the first heartbeat carries
  `security_signals` (agent ≥ 1.23.0).
- One lvosec account handles **every machine/VPS it protects**; the platform
  Super Admin additionally gets a platform-wide fleet view (all accounts) in
  Admin → Machines — see `docs/PLATFORM-MACHINES.md`.