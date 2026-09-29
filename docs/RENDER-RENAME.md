# Render service rename — runbook

The Render service name is the public subdomain (`https://<name>.onrender.com`),
and every lab PC's boot task stores an **absolute URL** in its config. This
document is how the rename happens without reinstalling the fleet.

## Why this works

- **Identity survives.** `DATABASE_URL` is user-managed and untouched by the
  rename. `lab_computers.agent_token` rows persist, so a machine's heartbeat
  against the **new** deployment finds the same computer row — no re-register,
  no new machine entries, remote view and history intact.
- **The agent moves itself.** Agent ≥ 1.23.0 handles a `server_url_rotate`
  action: it validates the new URL (https, no credentials), probes the new
  server's `/api/healthz`, persists the URL in its config, and starts
  reporting there. The WebSocket listener follows via the shared `WsState`
  table on its next reconnect. If the token were ever invalid on the new
  server (separate database), the existing 401 → re-register path takes over
  with the same hardware fingerprint.
- **Machines never discover the new URL — they are told.** That is why there
  is an action rather than "just rename it": the old server must still be
  reachable to deliver the instruction.

## Preconditions

1. **Fleet is on agent ≥ 1.23.0.** Deploy this code to the current service
   first. Machines self-update via `Update-Self` on heartbeat. Confirm from
   the dashboard: Computers page shows agent version ≥ 1.23.0 fleet-wide
   (or wait — old agents keep working, they just cannot rotate).
2. **Know each machine's computer id** (Computers page) or script the
   rotation from the API.
3. **Decide the transition shape** (below). Free plan has one web service, so
   the two-service overlap only works on a paid plan; the single-shot variant
   accepts a short outage for machines you cannot reach beforehand.

## Option A — two-service overlap (no outage, needs paid plan)

1. In `render.yaml`, temporarily add a **second** web service with the new
   name while keeping the old one:
   ```yaml
   services:
     - type: web
       name: computermanagementsystem   # old — still live
       ...
     - type: web
       name: lvosec                     # new — same code, same DATABASE_URL
       ...
   ```
   Render deploys both against the shared database.
2. Queue `server_url_rotate` for every machine, one by one:
   ```
   curl -X POST https://computermanagementsystem.onrender.com/t/<slug>/api/lab/computers/<id>/actions \
     -H 'Cookie: <dashboard session>' \
     -H 'Content-Type: application/json' \
     -d '{"action":"server_url_rotate","payload":"{\"url\":\"https://lvosec.onrender.com\"}"}'
   ```
   The server validates the payload; the agent re-validates and probes before
   committing.
3. Watch `lvosec.onrender.com` — heartbeats and WS `hello` begin landing
   there within one interval (10s × fleet size). Nothing went offline.
4. Keep the old service for a grace period (e.g. a week). When no machine has
   hit it (check its logs for `/api/agent/heartbeat`), remove it from
   `render.yaml` and redeploy.
5. Stray machine that was powered off the whole time: when it boots it
   receives the pending action and rotates then — **but only if the old
   service is still alive to deliver it.** Keep the old service until you are
   certain every machine has rotated, or accept that a machine that was off
   the whole grace period needs a manual re-point (`-Install -ServerUrl` or
   editing `agent-config.json` per Option B).

## Option B — single shot (free plan)

1. Deploy agent ≥ 1.23.0 to the fleet (step 1 of preconditions).
2. Rotate every machine to the **new URL** *before* the new URL exists is not
   possible — an agent only commits after its probe succeeds. So the order is:
   a. Rename the service in the Render dashboard (`Services → <name> →
      Settings → Name`). The new subdomain is live immediately. Whether the
      old one keeps serving is Render's behavior and can change over time —
      **assume it stops**, and confirm before Option B that machines cannot
      reach it (that is exactly why Option A exists).
   b. Machines still point at the old URL → fleet shows offline. This is the
      accepted outage window of Option B.
   c. Re-point each machine manually, in any order (they do not need the old
      server for this):
      ```
      powershell -NoProfile -ExecutionPolicy Bypass -Command
        "$c=Get-Content C:\ProgramData\LvOsSec\agent-config.json -Raw|ConvertFrom-Json;
         $c.serverUrl='https://lvosec.onrender.com';
         $c|ConvertTo-Json -Compress|Set-Content C:\ProgramData\LvOsSec\agent-config.json
         -Encoding UTF8"
      ```
      or, if the machine is already running agent ≥ 1.23.0, queue the rotate
      action **from the new UI** — but a machine cannot receive it while
      pointed at a dead URL, so this only helps machines that are still reachable
      (they are not). Manual re-point is the honest Option B path.
3. This is why Option A exists. Use it if the fleet matters during the rename.

## Verification

- Dashboard Computers page: machines return to `online` on the new subdomain;
  agent versions still ≥ 1.23.0; no duplicate computer entries (the token was
  preserved).
- Remote view: open one machine — the WS tunnel must connect via the new URL
  (`/t/:slug/ws/tunnel`). Screenshots continue to stream.
- Events: a `server_url_rotate` action row per machine, completed with
  success, in the lab's action history.
- Old service logs (Option A): heartbeat traffic drains to zero during the
  grace period.

## Rollback

Before the old service is retired, rotate machines **back** to the old URL
with the same action. The agent's probe validates the old service is alive,
then commits. After retirement, rollback means re-provisioning the hand full
of offline machines — another reason to keep the overlap until the drain is
observed.

## Rules of thumb for future renames

- Never rename a Render service that a fleet points at without either the
  rotate action (fleet ≥ 1.23.0) or a manual re-point plan.
- Prefer a pause DNS-visible name (`lvosec`) that you will not change again.
- The action is restricted to `https`, credential-free URLs, and the agent
  independently probes before committing — a typo is caught at queue time and
  again at execution time.