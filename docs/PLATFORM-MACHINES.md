# Platform Machines (Platform Admin)

The **Machines** section of the Platform Admin dashboard (`/admin`) is the
platform-wide fleet view: every tenant's machines under one Platform Admin
dashboard, with live network status and the same operator controls each lab
already has.

It reuses the exact agent action pipeline as the per-lab dashboard
(`queueMachineAction`), so behavior is identical whether a command is issued
from a tenant's Lab page or from here. No new agent work was required.

## Two services, one view

Platform Admin protects two different kinds of service, shown as **tabs**:

| Tab | What it lists | Agent |
| --- | --- | --- |
| **Computers** | Windows lab machines | `lab-agent.ps1` (PowerShell) |
| **Cloud VPS** | Linux cloud servers — Ubuntu/Debian VPSes (Contabo-style) | `lab-agent-linux.py` (lvosec Linux agent) |

Classification is derived from the `os` string the agent reports on each
heartbeat (`classifyMachineKind`): Linux-family OS → **Cloud VPS**, everything
else → **Computers**. No schema change needed — installing the Linux agent on a
server makes it show up under Cloud VPS automatically.

Both tabs share the same table columns and the same protective controls; a
VPS row is tagged with a **VPS** badge.

## What you see per machine

Live network and endpoint status, read straight from each tenant's computer
row (last heartbeat + agent-reported signals):

| Column | Meaning |
| --- | --- |
| Machine | Name (+ **VPS** badge for Linux servers) + OS / signed-in user + agent version |
| Tenant | Which lab account owns the machine |
| Room | Assigned room |
| IP | Agent-reported public/primary IP (`ipAddress`) |
| Status | `online` / `locked` / `offline` / other |
| Last seen | Time of the last agent heartbeat |
| Firewall | Agent-reported `firewallEnabled` — On / Off / ? (not reported) |
| USB | Current usb policy — `allowed` / `blocked` |

Summary chips across the whole fleet: total machines, computers, cloud VPS,
online, locked, and a red flag for any machine whose firewall is reported
**Off**.

## Controls (shared with the lab dashboard)

| Action | What it does |
| --- | --- |
| Lock / Unlock | Sessions lock/unlock on the machine (`lock` / `unlock`) |
| Restart | Reboots the machine (confirmation dialog) |
| USB block / allow | Sets the machine's USB policy (`block_usb` / `allow_usb`) |
| Firewall toggle | `fw_enable` / `fw_disable` based on reported state |
| Send message | Operator message popup on the machine's screen |

Every action is recorded in that tenant's `lab_events` audit trail with
**actor = "Platform administrator"** so cross-tenant actions are attributable.

## Endpoints

`/api/admin/*`, gated by `requirePlatformAuth` (same cookie as the whole
Admin dashboard).

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/admin/machines` | Flatten every tenant's computers into one list (tenants are scanned via the shared pool + `SET search_path`; a tenant with a missing schema is skipped, never fails the fleet view) |
| POST | `/admin/machines/:tenantId/:computerId/actions` | Queue an action on one machine (`action` in `lock/unlock/restart/wake/send_message/block_usb/allow_usb/fw_enable/fw_disable`, optional `message`) |

The action route refuses to run against **suspended** tenants (403), keeping
drives from reaching decommissioned accounts.

## Scope limits (deliberate)

- No remote desktop / `remote_view` / `remote_input` from the Platform Admin view —
  those stay tenant-internal.
- No per-port firewall *rules* editing — only the on/off switch (ufw on VPSes,
  Windows firewall on computers).
- No agent push / server URL rotation / file push from here.
- Attaching a new VPS is done from the Platform Admin **Blue Team → Cloud VPS
  protection → Add VPS** (pick the target tenant, then run the agent one-liner
  on the server); it then appears under Cloud VPS here.