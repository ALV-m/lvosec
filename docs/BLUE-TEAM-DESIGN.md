# LVO Security — Blue Team Design

> **Implementation status (2026-09-29)**
>
> | Phase | Status |
> |---|---|
> | §1a WS tunnel auth + §8 hardening | ✅ shipped in PR #1 (`security/server-protection`) |
> | §4 rename + storage migration | ✅ shipped in PR #2 (`rename/lvosec`), agent 1.20.0 |
> | §5 posture engine (computed, not persisted) | ✅ shipped in PR #3 (`feat/blue-team`), agent 1.21.0 |
> | §7 correlation rules (waves + compounding) + IOC record search | ✅ shipped in PR #3 |
> | WAF-lite + software inventory + Cloudflare edge rules | ✅ shipped in PR #4 (`feat/waf-inventory`), agent 1.22.0 |
> | Render service rename (agent `server_url_rotate`) | ✅ shipped in PR #5 (`infra/render-rename`), agent 1.23.0 — runbook: `docs/RENDER-RENAME.md` |
> | §6 FIM / defence-evasion | ⏳ next — see §6 |
>
> Where this doc says "new table" for findings (§5.1), the shipped engine
> computes posture **on the fly** from `lab_computers.security_signals` +
> tenant settings and stores nothing — findings stay purely derived and
> reproduce identically on any redeploy. The dashboard renders `unknown`
> coverage honestly instead of persisting stale pass/fail.

Status: **shipping, phased — see the table above**
Target repo: `ALV-m/lvosec` (renamed from `ALV-m/lab-command-center`)

---

## 1. Naming

| Context | Value |
|---|---|
| Full name (prose, README, release notes) | `LVO Security` |
| Short form (UI headings, page titles, toast text) | `LVOSEC` |
| Slug (repo, `package.json`, domain) | `lvosec` |
| Agent `ProgramData` dir | `C:\ProgramData\LvOsSec` |
| Scheduled task names | `LVOSEC Agent`, `LVOSEC Logon` |

Flag: the casing above is my reading of "lvo security real name short form for
heading domain and naming". Say the word if you want `LvOsSec` in headings too.

---

---

## 1a. CRITICAL — unauthenticated remote control of every lab PC

**This is live right now. It should be fixed before any other work in this document.**

`/ws/tunnel` is attached to the raw `http.Server` (`index.ts:39-40`), so
WebSocket upgrade requests **never pass through Express middleware**. The
`resolveSession` / auth layer in `lib/auth.ts` is on the HTTP path only. Nothing
guards the socket.

### The chain — no credentials required

**1. Connect as a dashboard with no token at all** (`tunnel.ts:96-109`)

```ts
const role = url.searchParams.get("role");
const token = url.searchParams.get("token") ?? "";
...
} else if (role === "dashboard") {
  const computerId = Number(computerIdParam);
  if (!Number.isFinite(computerId) || computerId <= 0) { ...reject... }
  handleDashboardConnection(ws, computerId);   // :109 — no token parameter exists
}
```

`handleDashboardConnection(ws: WebSocket, computerId: number)` (`:207`) has no
token argument to check. So this is a valid, fully-working connection:

```
wss://<your-app>.onrender.com/ws/tunnel?role=dashboard&computerId=1
```

**2. Watch the live screen** — send `{"type":"start_view"}` (`:235-243`). The
agent starts streaming JPEG/H.264 and `broadcastFrame` (`:58`) forwards it to
you. That is a live feed of a school PC's screen.

**3. Control the machine** — send `{"type":"input","payload":{...}}` (`:257`).
Forwarded verbatim to the agent, which injects keyboard and mouse. Full remote
control, no validation, no auth.

**4. Run destructive actions** — `{"type":"action","action":"..."}` (`:264`).
There *is* an allowlist (`:267-271`) — credit where due — but it is enforced on
an **unauthenticated** connection. Reachable: `lock`, `unlock`, `restart`,
`push_file`, `delete_file`, `block_usb`, `disable_rdp`, `av_toggle`,
`fw_disable`. `disable_rdp` is notable: silencing RDP is textbook defence
evasion.

**5. Arbitrary file read and delete on the PC.** `delete_file` (`:2684`) →
`Remove-TargetFile`, which is:

```powershell
Remove-Item -LiteralPath $target -Force -Recurse -ErrorAction Stop
```

No allowlist, no root confinement, operator-supplied path verbatim. `list_files`
(`:2688`) likewise. Combined with `push_file` for arbitrary write, or `input` to
open Run and type a command, this is **remote code execution on every lab PC in
the fleet**.

**6. The agent side is equally unauthenticated.** `handleAgentConnection(ws,
_token)` (`:119`) — the underscore prefix says it: the token is accepted and
discarded. So `{"type":"hello","computerId":1}` (`:141`) registers the caller as
PC #1 and **evicts the real agent** (`:144-146`, `prev.ws.close(4010,
"Replaced")`). An attacker can walk the fleet kicking every genuine agent
offline — a one-message-per-machine denial of service. A rogue connection can
also forge `action_result` frames (`:162-179`) to write arbitrary status into
the `lab_actions` audit trail.

**7. No tenant check anywhere in the socket path.** `computerId` is a raw
integer with no scoping, so this is not "any user of one school" — it is
**anyone on the internet**, and IDs span all tenants. Your multi-tenant
isolation, which is the strongest thing in this codebase, is bypassed entirely
by using the WebSocket instead of the API.

**8. Tokens are in the query string** (`:97`) even where they would be checked.
Query strings land in access logs, proxy logs, and browser history.

**9. No attributable audit trail.** Actions inserted at `:279` carry no actor,
because there is no authenticated actor. The operator event log cannot help
forensics here.

### Impact

Unauthenticated surveillance, remote control, and RCE-equivalent access to every
deployed lab PC, across every tenant, with no audit trail. For a school this is
the most serious class of bug there is, and it is remotely reachable on the
public internet.

### Fix

| Change | Where |
|---|---|
| Reject the upgrade unless the request carries a valid session cookie **or** a valid agent token, before `wss.on("connection")` runs | `index.ts:39-40`, `tunnel.ts:91-114` |
| Pass the session token into `handleDashboardConnection` and verify it; check the caller is authorised for that `computerId` **and that tenant** | `tunnel.ts:109`, `:207` |
| Actually verify the agent token in `handleAgentConnection` — drop the `_` prefix and check it | `tunnel.ts:119` |
| Move tokens out of the query string; use a header or a short-lived ticket | `tunnel.ts:97` |
| Record the authenticated actor on dispatched actions | `tunnel.ts:279` |
| Confinement: refuse paths outside an allowlisted root in `Remove-TargetFile` / `Get-DirListing` / `Receive-PushedFile` | `lab-agent.ps1` |
| Reject `input` unless an active `start_view` exists for that conn | `tunnel.ts:257` |

Fix the server side first. Agent-side confinement is what limits blast radius
if a token is ever stolen, so it ships in the same change.

**Interim mitigation, today, without a deploy:** put Cloudflare in front of the
host and block `/ws/tunnel` at the edge. That is the only thing that closes this
before the code fix lands.

---

## 2. Honest starting position

This is not a SOC with a lab module bolted on. It is a lab management tool with
**more blue-team capability than its UI currently reveals.** The agent already
does real defensive work that this document promotes into first-class features.

| Already implemented | Location | Blueprint layer |
|---|---|---|
| AV enable/disable, quick+full scan, signature update, scan history | `routes/security.ts`, `scanRuns/results` tables | 5 — endpoint protection |
| Firewall enable/disable + profile reporting | `routes/security.ts`, `computers.firewallEnabled` | 5 — network control |
| USB block/review/quarantine, scan-before-use approval | `usb-devices.ts`, `usbPolicies` | 5 — application control |
| Software Restriction Policy blocking executables | `lab-agent.ps1:1889` | 5 — application control |
| Peripheral inventory + tamper alert + on-screen warning | `lab-agent.ps1` (inventory fns) | Physical security |
| Password change/reset monitoring (Security 4723/4724) | agent Security log watcher | Credential monitoring |
| Idle auto-logout | `settings.idle_logout_minutes` | Session control |
| Remote lock / restart / message / file push / file delete | `routes/agent.ts` action queue | 2 — incident response |
| Full operator + system event audit log | `lab_events` | Audit trail |
| Named-session identity at check-in | `lab_checkins` | User attribution |
| **Agent self-update with rollback** | `lab-agent.ps1` `Update-Self` | — (see §5) |
| Multi-tenant isolation, per-tenant schema | `lib/tenant.ts` | Multi-site |

The gap is **not** raw capability. It is that these signals are scattered across
separate pages with no aggregate view, no severity model, and no baseline to
compare against. Phases 2–4 close that gap.

---

## 3. Out of scope — and why

I am not going to add these. Each would be theatre: a module that looks like
coverage while defending nothing, which is worse than an honest gap because it
stops anyone from asking the real question.

| Blueprint item | Why not |
|---|---|
| **Deep Packet Inspection** | Needs raw sockets and a SPAN/tap port. A Node process on Render has no layer-2 access. Not an architecture choice — physically unreachable. |
| **TLS/SSL decryption & inspection** | Requires a MITM proxy holding a CA private key installed on every lab PC. A school-wide interception proxy is a catastrophic blast radius if that key leaks, and it breaks under TLS 1.3. If this is genuinely required it needs a commercial product and a principal-level decision — not a feature added on request. |
| **Inline IDS/IPS** | Requires network position. An Express app is not inline. |
| **Impossible travel** | No geolocation is collected, and adding location tracking to school check-ins is a privacy problem, not a feature. |
| **PAM, DLP, DAM, data masking** | Enterprise data-platform concerns. Wrong product. |
| **Air-gapped immutable backups** | Infrastructure/ops work, not application code. |
| **Hand-rolled WAF / UA blocklist** | Regex blocklists in front of Express are trivially bypassed and create false confidence. Render already provides real edge DDoS protection. If you want a WAF, front it with Cloudflare — that is config, not code. |
| **`.htaccess` / iptables snippets** | Not applicable. Not running Apache; not managing the host firewall. |

`nmap`/`nikto` UA blocking is also theatre specifically: every real scanner sets
whatever UA it likes, and the one UA that matters — your own monitoring — you
would be banning too.

---

## 4. Phase 1 — Rename to `lvosec` + agent storage migration

### 4.1 Why this is the delicate part

The agent persists state at paths derived from:

```powershell
$ConfigDir     = Join-Path $env:ProgramData 'LabCommandCenter'   # :54
$TaskName      = 'LabCommandCenter Agent'                        # :59
$LogonTaskName = 'LabCommandCenter Logon'                        # :60
$LauncherPath  = Join-Path $ConfigDir 'LabCC-LaunchHidden.vbs'   # :368
```

`$ConfigDir` holds `config.json`, which holds **the agent token**
(`Read-Token`, `:758`). Renaming naively means every deployed PC looks for its
token in an empty directory, cannot authenticate, and silently drops off the
dashboard. The registered boot task additionally stores a **literal** path
(`C:\ProgramData\LabCommandCenter\lab-agent.ps1`), so deleting the old
directory breaks the next boot even if the token survived.

### 4.2 The saving grace: the agent already self-updates

`Update-Self` (`:1690`+) downloads `/api/agent/download`, syntax-checks the
result, verifies the version marker, backs up, replaces, restores on failure,
posts an `agent_update` event, then hands off to a fresh process and exits.

**So the migration ships to the entire fleet automatically.** Bumping
`$script:AgentVersion` from `1.18.0` to `1.19.0` is all that triggers rollout.
No manual reinstall, no site visit. This satisfies your "it should auto update"
requirement with machinery that already exists.

### 4.3 `Invoke-StorageMigration`

New function, called at the very top of the script — **before** the single-
instance lock check at `:2847` and before any `Read-Token` call. This ordering
matters: the lock file lives in `$ConfigDir`, so checking it before migrating
would let a second instance start alongside a still-running old one.

```
legacy : C:\ProgramData\LabCommandCenter
current: C:\ProgramData\LvOsSec
```

| Step | Behaviour |
|---|---|
| 1 | If `current\config.json` exists and parses → already migrated. Ensure tasks are correct, return. |
| 2 | If legacy dir absent → fresh install, return (no-op). |
| 3 | Create `current`. Copy `config.json` **and** `pending\checkins.json` — a queued check-in must not be silently dropped. |
| 4 | **Verify**: new `config.json` parses AND has a non-empty `token`. If not, roll back (remove partial `current`, keep legacy) and return. |
| 5 | Re-register boot + logon scheduled tasks using new names and the **new** agent path, same principal/triggers as `Install` does at `:245-250`. |
| 6 | Unregister legacy task names. Failure here is non-fatal — logged, retried next start. |
| 7 | Rename legacy dir to `LabCommandCenter.migrated` rather than deleting. Reversible; safe manual cleanup later. |
| 8 | Post an `agent_migrated` event so the dashboard shows the transition. |

Guarantees:

- **Idempotent** — safe to run on every agent start, forever.
- **Token-safe** — step 4 is a hard gate; a failed copy never destroys working
  credentials.
- **Reversible** — nothing is deleted, only renamed with a suffix.
- **Non-fatal** — any failure logs and continues on the legacy path, which
  still works. A failed migration degrades to "not yet renamed", never to
  "PC offline".

One subtlety worth naming: `Update-Self` hands off by launching the new script
from the **old** path. That process has already parsed the file into memory, so
moving the directory out from under it is harmless. What the migration must
guarantee is that the *next boot* resolves to the new path — which is exactly
what step 5 does.

### 4.4 Safe display-string renames

Tier 1 — change freely:

| File | Lines | What |
|---|---|---|
| `README.md` | 1, 35, 226 | H1, layout tree, Render service name |
| `package.json` | 2 | `"name": "lvosec"` |
| `.env.example` | 1 | header comment |
| `render.yaml` | 1, 13 | `name: lvosec` — **changes the Render subdomain**, see §9 |
| `index.html` | 7, 8 | `<title>`, meta description |
| `pages/login.tsx` | 92 | heading |
| `pages/root-login.tsx` | 54 | heading |
| `pages/register.tsx` | 71 | heading |
| `pages/admin/login.tsx` | 59 | heading |
| `pages/admin/dashboard.tsx` | 321 | heading |
| `App.tsx` | 127 | sidebar brand |
| `api-server/src/app.ts` | 66 | startup message |
| `lab-agent.ps1` | 2 | header comment |
| `lab-agent.ps1` | 394, 436, 925, 935, 1926, 2629, 3193 | window title, toast, MessageBox titles, SRP rule description, restart comment, idle-logoff message |

Tier 2 — **never** change: `:54`, `:59`, `:60`, `:368`.

---

## 5. Phase 2 — Security posture engine *(recommended first feature)*

### 5.1 New table

```ts
export const securityFindingsTable = pgTable("lab_security_findings", {
  id: serial("id").primaryKey(),
  computerId: integer("computer_id").notNull(),
  computerName: text("computer_name").notNull(),
  check: text("check").notNull(),          // stable slug, e.g. "antivirus_disabled"
  title: text("title").notNull(),
  severity: text("severity").notNull(),    // critical|high|medium|low|info
  status: text("status").notNull(),        // fail|warn|pass|unknown
  detail: text("detail"),
  remediation: text("remediation"),        // operator instruction, e.g. "Run a full scan"
  observedAt: timestamp("observed_at", { withTimezone: true }).notNull().defaultNow(),
});
```

Unique on `(computerId, check)` so re-evaluation upserts rather than duplicates.
Purely derived data — safe to truncate and recompute at any time.

### 5.2 Checks, each grounded in a column that exists today

| Check | Source | Severity | Remediation |
|---|---|---|---|
| `antivirus_disabled` | `computers.avEnabled === false` | high | enable Defender |
| `av_signature_stale` | parse `computers.avSignature` age | medium | push def update |
| `no_recent_scan` | `computers.avLastScanAt` older than N days | medium | run quick scan |
| `firewall_disabled` | `computers.firewallEnabled === false` | high | enable firewall |
| `usb_policy_violation` | `computers.usbState` vs `usbPolicies.mode` | high | review USB policy |
| `peripheral_missing` | any `peripherals.present === false` | high | recover device |
| `autologin_while_password_required` | agent-reported `autoLoginEnabled` vs `settings.signin_method` | **critical** | disable auto-login |
| `no_idle_timeout` | `settings.idle_logout_minutes` null | medium | set threshold |
| `agent_offline` | `computers.lastSeen` | high | check machine |
| `agent_version_stale` | `computers.agentVersion` < min | medium | push update |
| `disk_pressure` | `diskFree / diskTotal < 10%` | medium | free space |
| `unknown_hardware` | `computers.serialNumber` null | low | re-inventory |

`autologin_while_password_required` is the one worth surfacing loudest: if an
admin configured "students must face the Windows password page" but auto-login
is on, the lab is silently unenforced. Today nothing detects that.

### 5.3 Scoring

Weighted, 0–100. `critical` ×10, `high` ×5, `medium` ×2, `low` ×1, normalised
against computers reporting in. Lab score = mean of PC scores. A single
`critical` finding caps the lab at `at_risk` regardless of total.

### 5.4 Agent additions

Three new heartbeat fields, all cheap:

| Field | Source |
|---|---|
| `autoLoginEnabled` | read Winlogon `AutoAdminLogon` — makes the check an observation, not a guess |
| `osBuild` + `lastBootAt` | `Win32_OperatingSystem` |
| `pendingReboot` | pending-reboot registry keys |

**Software inventory does not go in the heartbeat.** The loop is 10 seconds;
enumerating installed software takes seconds itself. Separate endpoint
`POST /api/agent/software`, agent-driven on a daily timer or on-demand from the
UI, into a new `lab_software_inventory` table. Same pattern as the existing
`/api/agent/files/list` — heavy data on demand, not on the fast path.

This closes blueprint item 4 (asset inventory) and gives item 5's patch
management a data source to prioritise against.

### 5.5 New page

`artifacts/lab-control/src/pages/security-posture.tsx` — lab score gauge, PC
table sorted by severity, filter by check/severity, CSV export, print view
(matching the existing reports pattern), and a remediation action per finding
that queues an existing agent action where one exists.

---

## 6. Phase 3 — File Integrity Monitoring

Real gap, and the agent is well placed to close it.

| Table | Purpose |
|---|---|
| `lab_fim_baselines` | `computerId`, `path`, `sha256`, `size`, `capturedAt` |
| `lab_fim_changes` | `computerId`, `path`, `changeType` (added/modified/deleted), `oldHash`, `newHash`, `detectedAt` |

Baseline: SHA-256 over a curated set — `sethc.exe`, `lsass.exe`,
`winlogon.exe`, `taskhostw.exe`, `svchost.exe`, plus the SRP registry keys at
`:1889` and the Winlogon keys at `:2432`. Cadence **every 5 minutes**, not every
10 seconds — hashing cost is trivial but not free, and 5 minutes is a defensible
detection window for lab PCs.

Any divergence raises an alert and an event. Blueprint item 5, FIM, done
honestly.

---

## 7. Phase 4 — Correlation rules

Turn the existing `lab_events` stream into higher-severity findings.

| Table | Purpose |
|---|---|
| `lab_detect_rules` | `name`, `severity`, `enabled`, `windowMinutes`, `threshold`, `matchType`, `field`, `value` |

Evaluated on event insert. Candidate rules:

- ≥3 peripheral removals lab-wide in 15 min → **bulk theft**
- same `phone` across ≥N distinct computers in a day → attendance anomaly
- ≥N password changes on one PC in 15 min → possible credential attack
- agent version below minimum on >X% of fleet → broken rollout
- one PC flapping online/offline → hardware or network fault

Rules are data, not code, so a new detection ships without a deploy.

Blueprint item 2, correlation engine — the achievable subset. UEBA baselines
and historical threat hunting are larger and would follow, not precede, this.

---

## 8. Cross-cutting hardening

Real but **lower severity than §1a** — and I overstated the CORS issue on first
pass, so here is the accurate picture:

```
artifacts/api-server/src/app.ts:32   app.use(cors());   // no origin allowlist
                                     // no helmet
                                     // no rate limiting anywhere
lib/auth.ts:51-56                    sessionCookieOptions — no `secure` flag
```

| Fix | Severity | Detail |
|---|---|---|
| **Session cookie `secure: true`** | medium | `sessionCookieOptions` sets `httpOnly` and `sameSite: "lax"` correctly, but omits `secure`, so the session token is transmitted over plaintext HTTP. Set it, and gate it on an env flag for local dev. |
| **Rate limiting** | medium | None anywhere. `/api/auth/*`, `/api/login`, `/api/agent/register` are directly brute-forceable. Apply `express-rate-limit` strictly to those; keep agent heartbeats generous (10s cadence × fleet size would trip a naive global limit). |
| **CORS allowlist** | low | `cors()` reflects any `Origin`. To be accurate: it does **not** set `Access-Control-Allow-Credentials`, so browsers block credentialed cross-origin reads, and `sameSite: "lax"` blocks cookie sending on cross-site POSTs. So this is **not** a live account-takeover path — it is a hygiene and defence-in-depth issue, and it leaks which API endpoints exist to any origin. Still worth an allowlist from `ALLOWED_ORIGINS`. |
| **Security headers** | low | Add `helmet`. |
| **Login attempt cap** | medium | Per username+IP, backed by existing `app_users`. Blueprint item 1's brute-force protection, and it genuinely belongs here. |
| **Body size limit** | low | `express.json()` (`:34`) is already bounded at body-parser's 100kb default, so this is not the unbounded-DoS I first suspected. Set an explicit limit anyway so the value is intentional rather than inherited. |

Password handling needs no work — `scrypt` with per-password salt and
`timingSafeEqual` comparison (`lib/passwords.ts`) is correct as written.

**CSRF:** no token, but `sameSite: "lax"` is doing the work. If you ever need
`sameSite: "none"` for a cross-site deployment, you must add real CSRF tokens
at the same time. Worth a comment in the code so nobody flips it casually.

---

## 9. Rollout and risk

| Risk | Mitigation |
|---|---|
| Migration loses an agent token | Hard verification gate (§4.3 step 4) + legacy dir renamed not deleted |
| Migration runs twice / mid-flight | Idempotent; re-entrant; legacy path still works if it fails |
| Two agents run at once | Migration precedes the lock check at `:2847` |
| Render service rename breaks the live URL | Solved, not mitigated: agent ≥ 1.23.0 handles a `server_url_rotate` action (validates https + probes healthz before committing), and machine identity survives because tenants share one Postgres. Execute per `docs/RENDER-RENAME.md` — rotate the fleet **before** retiring the old service. |
| GitHub repo rename | GitHub redirects old clones, but any hardcoded URL or CI reference needs updating. |
| Posture checks fire noisily on first run | Seed `status` as `unknown` and only escalate after two consecutive observations. |

---

## 10. What I cannot verify

I have no Postgres and no lab PC available. My confidence comes from
`pnpm typecheck` passing and from reading the code — **not** from running it.
Phase 1's migration in particular needs testing on one real machine before it
reaches the fleet, and because self-update ships automatically, a broken
migration would propagate everywhere. Suggest: bump the version, watch one
machine, confirm its dashboard heartbeat stays green and a new `agent_migrated`
event appears, then let it roll.

---

## 11. Suggested order

0. **§1a — fix the unauthenticated WebSocket tunnel.** Unauthenticated RCE on
   the fleet. Nothing else matters until this is closed. Edge-block
   `/ws/tunnel` today; ship the code fix before anything else deploys.
1. §8 hardening — small, standalone, fixes live issues
2. §4 rename + migration — one machine test, then fleet
3. §5 posture engine
4. §7 correlation rules (+ IOC record search)
5. WAF-lite + software inventory + Cloudflare edge rules
6. Render service rename — safe now: agent `server_url_rotate` moves the fleet
   without a reinstall (`docs/RENDER-RENAME.md`)
7. §6 FIM — now that posture/correlation/search are live, FIM closes the
   endpoint layer: agent self-hash + autorun/task enumeration vs baseline
