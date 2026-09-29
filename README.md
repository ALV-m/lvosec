# LVO Security

A multi-tenant computer-lab management platform. Organizations self-register at `/register` and each gets its own isolated workspace at `/t/<slug>` with a full management dashboard: track computers, run operator actions (lock, unlock, restart, send messages, push files), monitor alerts, control USB policies with scan-before-use approval, and record student attendance and violations — all behind one Express API that also serves the React frontend. Each lab PC runs a zero-dependency PowerShell agent (`lab-agent.ps1`) that phones home to the server.

## Features

- **Multi-tenant** — every organization that registers gets its own Postgres schema (`t<id>`), its own super admin account, and its own sign-in URL (`/t/<slug>/login`). Labs are fully isolated from each other.
- **Platform admin** — the platform owner signs in at `/admin` to see all tenants, their computer/admin counts, and to suspend, re-activate, reset passwords, or permanently delete a tenant.
- **Dashboard** — live lab summary, status distribution chart, recent alerts.
- **Computers** — searchable/filterable list with per-machine actions (lock, unlock, restart, wake, send message, remote control, remote view, block/allow USB, push file, delete file, security controls). New machines register automatically when the agent first runs.
- **Alerts** — acknowledge and resolve alerts raised across the lab.
- **Check-ins** — a mandatory full-screen login form appears when a session starts and after every admin lock, with user-type buttons for **Student**, **Teacher**, **Visitor**, and **Administrator**. Students, teachers, and visitors enter their own details (students: name, phone, admission number, optional email + photo; teachers and visitors: name, phone, optional ID/email/photo); administrators sign in with a username + passphrase. Submissions are recorded on the Check-ins page with a Student/Teacher/Visitor/Admin role badge. Choose the lab's sign-in method on the Agent page: per-student Windows passwords plus the form, or "login form instead of password" where every PC boots into one local account straight to the form (no Windows password page) — the server auto-generates a random non-admin account if you don't supply one, and the agent applies the Windows Hello fix so auto-login works on password-protected PCs.
- **USB policy** — set removable-media policy to allowed/blocked/review for all or selected computers; in review/quarantine mode newly inserted flash drives and phones are disabled at the device level (unusable and unchargeable) and Defender-scanned until you approve them.
- **Peripherals** — the agent inventories keyboards, mice, and monitors on first run; if one is removed, the PC shows a full-screen warning overlay to return it and an alert + event (with the current user) is recorded for the administrator. Live status on the Peripherals page.
- **Security** — an **Antivirus** and **Firewall** submenu: run quick/full scans or definition updates on all PCs (or a selected set), see live per-PC protection health, and browse a persisted scan-history report with per-computer results (JSON/CSV/print). Firewall enable/disable is broadcast the same way.
- **Password monitoring** — the agent watches the Windows Security log (events 4723/4724) and alerts on password changes/resets; it also clears the Winlogon auto-login setting at boot unless the "login form instead of password" method is configured, in which case it sets up auto-login so the form is the first screen.
- **Idle logout** — set an inactivity threshold (minutes); the agent logs the user out automatically when keyboard/mouse idle exceeds it.
- **Reports** — attendance, violations, peripheral event, and security-scan reports with JSON + CSV export and a print button on every report and log.
- **Agent** — download `lab-agent.ps1` and install it on each lab PC; it reports heartbeat/status, tracks logins, shows the login gate (Student/Administrator), scans and quarantines USB devices, watches peripherals, monitors password changes, applies the lab's sign-in method (auto-login on/off), and executes queued actions (lock/unlock, WoL relay, remote-view screenshots, and more). Installed agents run at boot as SYSTEM so they cover every user.
- **Events** — an audit log of operator actions, logins, USB events, password changes, auto-login changes, and peripheral connects/disconnects (printable).
- **Deployment** — a `render.yaml` blueprint for the web service with schema bootstrap and seed data.

## Tech stack

| Layer      | Stack                                                        |
| ---------- | ------------------------------------------------------------ |
| Frontend   | React 19, TypeScript, Vite 7, Tailwind CSS 4, shadcn/ui, wouter, TanStack Query, recharts, sonner |
| API        | Express 5, Zod 3 (v4 API), pino logging, esbuild bundling    |
| Database   | PostgreSQL, Drizzle ORM, `node-postgres`                     |
| Tooling    | pnpm workspaces with a shared version catalog                |

## Repository layout

```
lvosec/                    # formerly lab-command-center
├── artifacts/
│   ├── api-server/          # Express API, serves the built frontend too
│   └── lab-control/         # React dashboard (Vite)
├── lib/
│   ├── api-zod/             # Zod schemas shared by the server and client
│   ├── api-client-react/    # Typed fetch client + React Query hooks
│   └── db/                  # Drizzle schema, pool, and idempotent ensureSchema()
├── scripts/                 # DB bootstrap + seed scripts
├── render.yaml              # Render blueprint (web service)
├── pnpm-workspace.yaml      # Workspace + version catalog
└── tsconfig.base.json
```

## Prerequisites

- Node.js >= 20 (tested on 22)
- pnpm >= 11 (`corepack enable` if needed)
- A PostgreSQL database (local or hosted)

## Running locally

1. **Install dependencies**

   ```sh
   pnpm install
   ```

2. **Configure environment** — copy the example file and fill in real values:

   ```sh
   cp .env.example .env
   ```

   Required variables:

   - `DATABASE_URL` — PostgreSQL connection string.
   - `PORT` — port for the API (default 3000).
   - `BASE_PATH` — base path for the frontend build (keep `/`).
   - `PLATFORM_ADMIN_USERNAME` / `PLATFORM_ADMIN_PASSWORD` — the platform owner's
     account, upserted on every server start. Sign in at `/admin`. (Optional but
     recommended; the same form is used for tenants at `/t/<slug>/login`.)

3. **Create and seed the schema**

   ```sh
   pnpm run db:setup
   ```

   This runs `db:bootstrap` (idempotent `CREATE TABLE IF NOT EXISTS`) followed by
   `db:seed`, which creates a demo tenant (`demo-lab`) with a super admin
   (`admin` / `admin123`) and 3 sample computers, then seeds alerts, sessions and
   events into that tenant's schema. Seeding is skipped if the demo tenant
   already exists.

4. **Build**

   ```sh
   pnpm run build
   ```

   The Vite config requires `PORT` and `BASE_PATH` to be set in the environment (as above).

5. **Run**

   ```sh
   pnpm start
   ```

   The server listens on `PORT` (e.g. `http://localhost:3000`). It serves:

   - the public registration page at `/register`,
   - the platform admin console at `/admin`,
   - each tenant's dashboard at `/t/<slug>/login`,
   - the API under `/api` (platform) and `/t/<slug>/api` (tenant).

   For development with hot reload:

   ```sh
   pnpm --filter @workspace/lab-control run dev   # Vite dev server on PORT
   pnpm --filter @workspace/api-server run dev    # bundled API on PORT
   ```

## API

All tenant endpoints live under `/t/<slug>/api/...` and are scoped to that
tenant's schema. Platform endpoints live under `/api/...`.

| Method | Path                              | Description                              |
| ------ | --------------------------------- | ---------------------------------------- |
| GET    | `/api/healthz`                    | Health check                            |
| POST   | `/api/tenant/register`            | Self-service tenant registration         |
| POST   | `/api/admin/login`                | Platform admin login                     |
| POST   | `/api/admin/logout`               | Platform admin logout                    |
| GET    | `/api/admin/me`                   | Current platform admin                   |
| GET    | `/api/admin/tenants`              | List tenants (with computer/admin counts)|
| GET    | `/api/admin/stats`                | Platform-wide stats                      |
| PATCH  | `/api/admin/tenants/:id`          | Suspend / re-activate a tenant           |
| POST   | `/api/admin/tenants/:id/reset-password` | Reset a tenant's super admin password |
| DELETE | `/api/admin/tenants/:id`          | Delete a tenant and all of its data      |

The following tenant endpoints are mounted under the tenant router, so the real
paths are `/t/<slug>/api/...` (the slug is the tenant's address from
registration).

| Method | Path (`/t/<slug>/api` prefix)       | Description                              |
| ------ | --------------------------------- | ---------------------------------------- |
| POST   | `/auth/login`                     | Tenant admin login                       |
| POST   | `/auth/logout`                    | Tenant admin logout                      |
| GET    | `/auth/me`                        | Current tenant admin                     |
| GET    | `/users`                          | Manage tenant admins                     |
| GET    | `/agent/download`                 | Download `lab-agent.ps1`                |
| POST   | `/agent/register`                 | Register/re-key an agent + computer     |
| POST   | `/agent/heartbeat`                | Agent heartbeat; polls for actions      |
| POST   | `/agent/actions/:id/complete`     | Mark an action complete/failed          |
| POST   | `/agent/events`                   | Agent-reported events (login, USB, ...) |
| POST   | `/agent/peripherals`              | Agent peripheral inventory snapshot     |
| GET    | `/agent/files/download/:id`       | Download a file queued for a computer   |
| GET    | `/lab/summary`                    | Dashboard summary counters              |
| GET    | `/lab/computers`                  | List computers                          |
| POST   | `/lab/computers/:id/actions`      | Queue an action for a computer          |
| GET    | `/lab/alerts`                     | List alerts                             |
| PATCH  | `/lab/alerts/:id`                 | Update alert status                     |
| GET    | `/lab/usb-policies`               | List USB policies                       |
| PATCH  | `/lab/usb-policies`               | Update the lab USB policy               |
| GET    | `/lab/usb-devices`                | List USB devices (pending/decided)      |
| POST   | `/lab/usb-devices/:id/decide`     | Approve/deny a pending USB device       |
| GET    | `/lab/peripherals`                | List tracked peripherals per computer   |
| GET    | `/lab/settings`                   | Read lab settings (idle logout, sign-in method, admin passphrase) |
| PATCH  | `/lab/settings`                   | Update lab settings                     |
| GET    | `/lab/student-sessions`           | List student sessions                   |
| POST   | `/lab/student-sessions`           | Start a session (sign a student in)     |
| GET    | `/lab/events`                     | List recent audit events                |
| GET    | `/reports/attendance`             | Attendance report (JSON)                |
| GET    | `/reports/attendance.csv`         | Attendance report (CSV)                 |
| GET    | `/reports/violations`             | Violations report (JSON)                |
| GET    | `/reports/violations.csv`         | Violations report (CSV)                 |
| GET    | `/reports/peripherals`            | Peripheral events report (JSON)         |
| GET    | `/reports/peripherals.csv`        | Peripheral events report (CSV)          |
| GET    | `/reports/scans`                  | Security scan runs + per-PC results     |
| GET    | `/reports/scans.csv`              | Security scan results (CSV)             |
| POST   | `/security/broadcast`             | Broadcast scans/updates/firewall actions |
| GET    | `/security/health.csv`            | Per-PC AV/firewall health (CSV)         |
| POST   | `/lab/files/broadcast`            | Send one file to all/selected PCs       |
| POST   | `/lab/files/delete-broadcast`     | Delete a file/folder on all/selected PCs |
| GET    | `/lab/computers/:id/files/browse` | Browse a PC's folder listing            |
| POST   | `/agent/files/list`               | Agent: report a directory listing        |

Computer actions: `lock`, `unlock`, `restart`, `wake`, `send_message`, `remote_view`, `remote_control`, `block_usb`, `allow_usb`, `push_file`, `delete_file`, `av_scan`, `av_update`, `av_toggle`, `fw_enable`, `fw_disable`.

All request/response bodies are validated with the Zod schemas in `lib/api-zod`.

## Installing the client agent

Every agent is bound to one tenant by the URL it is given. Use your lab's URL
so all traffic carries the tenant prefix automatically:

1. After registering your lab, download the agent script using your lab address:

   ```sh
   curl -o lab-agent.ps1 https://<your-app>.onrender.com/t/<your-slug>/api/agent/download
   ```

2. On each lab PC (Windows PowerShell 5.1+), run once to test:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File lab-agent.ps1 -ServerUrl https://<your-app>.onrender.com/t/<your-slug>
   ```

3. To install it so it starts at **boot as SYSTEM** (covers every user on the PC):

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File lab-agent.ps1 -Install -ServerUrl https://<your-app>.onrender.com/t/<your-slug>
   ```

The agent registers the PC (its name becomes the computer name in the dashboard), heartbeats every 30 seconds, reports USB device connections (scanning them with Windows Defender first), inventories keyboards/mice/monitors (showing a full-screen warning overlay on the PC when a baseline device is disconnected), tracks student login/logout, watches the Security log for password changes/resets, clears the Windows auto-login setting at boot, and executes queued actions. `-ServerUrl` can be an `http://<ip>:<port>/t/<slug>` address for a LAN deployment.

To enable automatic logout after inactivity, open the **Agent** page and set **Idle minutes** (0 disables it). Agents read the threshold from their heartbeat and log the user off when keyboard/mouse input has been idle for that long.

### Agent upgrades and the LvOsSec rename

Agents update themselves. The server reports its bundled agent version on every
heartbeat; an agent whose version is older downloads the new script,
syntax-checks it, swaps it in and hands off to a fresh process. **No reinstall
and no PC-side action is needed** — pushing a new agent version reaches the whole
fleet within one heartbeat interval.

Agent **1.20.0** renames the on-disk identity to match the product:

| | before | after |
|---|---|---|
| Storage | `C:\ProgramData\LabCommandCenter` | `C:\ProgramData\LvOsSec` |
| Boot task | `LabCommandCenter Agent` | `LVOSEC Agent` |
| Logon task | `LabCommandCenter Logon` | `LVOSEC Logon` |
| Env var | `LCC_SERVER_URL` | `LVOSEC_SERVER_URL` (old still read) |

The agent carries its own state across on first run after the update: it copies
`config.json` (which holds the token that authenticates the PC) to the new
directory, re-registers the boot task against the new path, retires the old task
names, and renames the old directory to `LabCommandCenter.migrated` — it is
renamed, not deleted.

If any part of that fails, the agent logs the reason and **continues using the
old directory and old task names**, so the worst case is "the rename did not
happen", never "the PC dropped off the dashboard". A machine is only considered
migrated once the new `config.json` is readable *and* carries a token, so a
truncated copy cannot orphan a PC.

Nothing here needs a reinstall. To confirm a PC moved over, check that
`C:\ProgramData\LvOsSec\config.json` exists on it.

## Deploying to Render

The `render.yaml` blueprint defines the **web service** (free tier). It deliberately does **not** provision a database — the app connects to a database you already run, so it plays nicely with your other projects on a shared Postgres.

Why it's safe to share a database:

- Every tenant's data lives in its own Postgres schema (`t<id>`), created on registration. Tenant tables never collide with each other or with your other apps' tables (platform tables use the `tenants`, `platform_users`, and `auth_sessions_platform` names).
- Schema bootstrap is idempotent (`CREATE TABLE IF NOT EXISTS`).
- The seed script only creates the `demo-lab` tenant the first time, so it never re-seeds or overwrites anything.

To deploy:

1. Render dashboard → **New → Blueprint** and connect the repository. The service is named `lvosec` (subdomain `lvosec.onrender.com`).

   > **About renames.** The Render service name determines the subdomain, and
   > every lab PC's boot task holds an absolute URL to it. This is exactly why
   > the agent (≥ 1.23.0) can be moved with the `server_url_rotate` action
   > instead of a reinstall. If you ever need to move the fleet to a new
   > deployment, follow `docs/RENDER-RENAME.md` — never rename the service and
   > hope the machines follow.
2. Pick the repo; Render creates the web service (no database resource).
3. Open the service → **Environment** and set:
   - `DATABASE_URL` to the connection string of the database you want to share:
     - If it's another **Render Postgres**, use its **Internal Database URL** and connect that database to this service from the database's dashboard (Render manages the network access automatically).
     - If it's an **external** database (e.g. Neon, Supabase, a VM), use its connection string and add the web service's IP range to the database's allowlist.
   - `PLATFORM_ADMIN_USERNAME` / `PLATFORM_ADMIN_PASSWORD` for your platform owner account (sign in at `/admin`).
4. First deploy runs `pnpm install && pnpm run db:setup && pnpm run build`, then starts the server. Health check `/api/healthz` marks it live.
5. Future pushes to `main` auto-deploy.

Note: the shared database must be reachable from Render — Render-managed databases and standard managed Postgres (Neon/Supabase) work out of the box.

## Verification

```sh
pnpm run typecheck     # typechecks libs (tsc --build) + all packages
pnpm run build         # bundles the API and builds the dashboard
pnpm --filter @workspace/scripts test:agent   # agent storage migration + file-op confinement
```

The agent tests run on any platform with `pwsh`. They load the real functions
out of the shipped `lab-agent.ps1` and assert the two things that would damage a
lab if they broke: that a PC keeps its token and identity through the LvOsSec
storage migration, and that `delete_file` cannot point outside the allowed write
roots. Both paths are covered, including the failure path where the migration
cannot complete and the agent has to stay on the legacy directory.

## License

MIT
