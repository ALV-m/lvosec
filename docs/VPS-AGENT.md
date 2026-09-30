# Protecting a VPS with the lvosec agent (Windows or Linux)

The **Blue Team** seat lives in the **Platform Admin dashboard** — it is the
platform-level place for protecting machines and VPSes through lvosec. Install
an agent on a VPS and it registers under a tenant, then firewall, USB, lock,
restart and operator message controls run from **Platform Admin → Blue Team →
Cloud VPS protection** (platform-wide across every tenant).

Two agents speak the same protocol and appear in the same view:

- **Windows** — the PowerShell agent every lab PC runs (`lab-agent.ps1`).
- **Linux** — a Python 3 companion for Ubuntu/Debian VPSes (Contabo-style)
  covering the same controls (`lab-agent-linux.py`, see below).

## Install on the VPS (Windows)

Open an **Administrator PowerShell** on the Windows VPS and paste (using the
tenant slug your machine should enroll into, e.g. `my-lab`):

```powershell
$s='https://<your-render-host>/t/my-lab'; iwr "$s/api/agent/download" -OutFile "$env:TEMP\lab-agent.ps1"; powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\lab-agent.ps1" -ServerUrl $s -Install; Remove-Item "$env:TEMP\lab-agent.ps1"
```

In Platform Admin **Blue Team → Cloud VPS protection → Add VPS** you don't have
to type any of this — pick the target tenant and the dialog prints the exact
command (with your server URL) and a Copy button.

What the install does:

- Installs the agent as a **SYSTEM boot task** (survives reboots, no login
  required) and starts the foreground check-in immediately.
- Phones home with the host name, **public IP + MAC**, Windows Firewall state
  (domain/private/public profiles), AV status, hardware fingerprint and OS
  version.
- The machine appears in **Blue Team → Cloud VPS protection** within a minute,
  named after the host.

## Install on the VPS (Linux)

Open a root administrator shell on the VPS and paste (again, tenant-scoped):

```bash
curl -fsSL "https://<your-render-host>/t/my-lab/api/agent/download-linux" -o /tmp/lab-agent-linux.py && sudo python3 /tmp/lab-agent-linux.py --install --server-url "https://<your-render-host>/t/my-lab"
```

Blue Team → **Cloud VPS protection → Add VPS** shows this exact command (already
filled with your server URL) with a Copy button.

What the install does:

- Installs a **systemd service** (`lvosec-agent`) running as root, with
  `Restart=always`.
- Registers under the **host name** within a minute and starts heartbeating
  public IP + MAC + OS + ufw firewall state.
- Supports `--name NAME` / `--room ROOM` to override the label, and
  `--uninstall` to remove the service:
  `sudo python3 /usr/local/lib/lvosec/lab-agent-linux.py --uninstall`.

## Controls available from Blue Team

| Control | What it does on the VPS |
| --- | --- |
| Firewall toggle | `fw_enable` / `fw_disable` — switches the VPS's own firewall: **Windows Firewall** on Windows, **ufw** on Linux. Linux enabling is SSH-safe: the agent allows port 22 first if no SSH rule exists, so a fresh VPS cannot lock itself out. **Disabling opens the VPS to the internet; only do it deliberately.** |
| USB block / allow | `block_usb` / `allow_usb` — blocks storage-class devices. Linux uses a udev rule (`authorized=0`) on USB-mass-storage only, unmounts mounted drives, and leaves keyboard/mouse HIDs alone. |
| Lock / Unlock | `lock` / `unlock` — locks interactive sessions (`loginctl lock-sessions` on Linux). Headless VPSes that never have an interactive session are better handled with restart or message. |
| Restart | `restart` — reboots after a grace period with an on-screen reason (60s via `shutdown -r +1` on Linux). |
| Send message | `send_message` — shows an operator banner on the machine's screen (broadcast with **wall** on Linux). |
| Wake | WoL magic-packet relay for offline machines (broadcast UDP port 9). |

Every control goes through the same `queueMachineAction` pipeline as the lab:
queued → sent → acknowledged, with each action appended to that account's
`lab_events` audit trail.

Actions unsupported on Linux (remote view/input, AV scan, file push, RDP etc.)
are **reported as failed with the reason** rather than silently ignored, so the
dashboard never shows a fake success.

## One-time reuse (Windows)

Run once manually in front of the same agent script on future controls from
the dashboard:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\lab-agent.ps1" -ServerUrl $s
```

## Notes

- Requires **Python 3** (preinstalled on Ubuntu) on Linux; Windows needs
  **Windows 10/11 or Windows Server 2016+** with PowerShell 5.1+.
- The VPS must reach your Render host on **HTTPS** — the agent refuses
  non-HTTPS server URLs when rotating between deployments
  (`server_url_rotate`), so install with an `https://` URL from the start.
- Firewall state shows as **?** until the first heartbeat carries
  `security_signals` (agent ≥ 1.23.0).
- Software inventory (the 1-hour channel) is Windows-only today — Linux assets
  show up under posture/firewall/USB but not yet in the installed-software
  list.
- On a Linux machine the posture engine only marks checks **unknown** when a
  Windows-specific signal is missing — it never invents a failure.
- VPS vs computer classification is derived from the reported OS
  (`classifyMachineKind`) and is surfaced as two separate services in Admin →
  Machines (`docs/PLATFORM-MACHINES.md`).