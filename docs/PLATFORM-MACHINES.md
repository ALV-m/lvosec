# Platform Machines (Super Admin)

The **Machines** section of the Platform Admin dashboard (`/admin`) is the
platform-wide "manage VPS networking in server" view: every tenant's
computers and servers — lab PCs, VPSes, what have you — under one Super Admin
dashboard, with live network status and the same operator controls each lab
already has.

It reuses the exact agent action pipeline as the per-lab dashboard
(`queueMachineAction`), so behavior is identical whether a command is issued
from a tenant's Lab page or from here. No new agent work was required.

## What you see per machine

Live network and endpoint status, read straight from each tenant's computer
row (last heartbeat + agent-reported signals):

| Column | Meaning |
| --- | --- |
| Machine | Name + signed-in user + agent version |
| Tenant | Which lab account owns the machine |
| Room | Assigned room |
| IP | Agent-reported public/primary IP (`ipAddress`) |
| Status | `online` / `locked` / `offline` / other |
| Last seen | Time of the last agent heartbeat |
| Firewall | Agent-reported `firewallEnabled` — On / Off / ? (not reported) |
| USB | Current usb policy — `allowed` / `blocked` |

Summary chips across the whole fleet: total machines, online, locked, and a
red flag for any machine whose firewall is reported **Off**.

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

- No remote desktop / `remote_view` / `remote_input` from the Super Admin view —
  those stay tenant-internal.
- No per-port firewall *rules* editing — only the on/off switch.
- No agent push / server URL rotation / file push from here.