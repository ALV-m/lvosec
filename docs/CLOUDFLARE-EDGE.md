# Cloudflare edge rules (perimeter layer)

The app-level WAF (`/api` middleware) only sees requests Express accepts. For
the defences that belong *in front* of the app — TLS termination, bot scoring,
true rate limits that survive redeploys — put the site on the free Cloudflare
plan and apply these rules. Every rule has a **why**, because a rule justified
only by a technology name gets removed by the first admin who does not
understand it.

The Cloudflare DNS record must be set to **DNS only** (grey cloud) while the
`CF-IPCountry` geofence is off, and **Proxied** (orange cloud) once you turn it
on — the app only trusts the country header when Cloudflare is provably in
front (see `artifacts/api-server/src/lib/waf.ts`).

## Rules, in order

Cloudflare evaluate rules top-down and stop at the first match, so order
matters. This order blocks the worst traffic first and keeps the lab working
even when things go sideways.

| # | Rule | Action | Why |
|---|------|--------|-----|
| 1 | `http.request.uri.path contains "/ws/tunnel"` and `cf.worker` unset is **not** used here — see note below | — | The tunnel upgrade path is now authenticated at upgrade time; the edge cannot validate cookies, so do **not** block this path at the edge. Documented so nobody re-adds the old blanket block. |
| 2 | `http.request.headers["user-agent"] contains "wget"` or `"python-requests"` or `"curl"` and `not cf.worker` (do not match the server's own probes) | Block | The known attack tooling on this lab used python-requests-style clients. The server-side agent uses `WindowsPowerShell`, which is deliberately **not** in this list. |
| 3 | `http.request.uri.path` matches `/(^|/)\.(env|git|svn|hg)(/|$)|wp-admin|xmlrpc\.php|server-status` | Block | Same never-legitimate set as the app WAF; blocking at the edge spares the app entirely. |
| 4 | `cf.bot_management.score lt 30` | Managed Challenge | Free plan Bot Fight Mode may be off; `cf.bot_management.score` is available on pro+. If unavailable, skip this rule. |
| 5 | `http.request.uri.path` matches `^/api/(login|auth/login)` or `http.request.uri.path contains "/api/auth/login"` | Rate limit — `anon` burst 10 / 60s | Login brute force. The app also rate-limits; two cheap fences are fine, the app one is the reliable one across redeploys. |
| 6 | `ip.geoip.country not in {list}` | Block (only **after** the geofence env `WAF_ALLOW_COUNTRIES` is set in Render) | The lab lives in one country. Enabling this while the env var is unset locks everyone out, because the app has no header to trust. |

## WAF env vars on Render

| Env | What it does | Set it when |
|-----|--------------|-------------|
| `WAF_ALLOW_COUNTRIES` | Comma-separated ISO codes (`KE,US,GB`). Enables the app-level country allowlist. | Cloudflare DNS is **Proxied** and the lab's country is known. |
| `WAF_ENFORCE=off` | Observe mode: WAF decisions are logged with `reason` but not enforced. | First rollout, to confirm no false positives before the fence bites. |

## Order of operations for enabling the geofence

1. Turn on **Proxied** DNS in Cloudflare and confirm the site still loads.
2. On Render, set `WAF_ENFORCE=off`, set `WAF_ALLOW_COUNTRIES` to the lab's
   country, redeploy.
3. Wait a day. Read the logs for `waf:request-blocked` entries — countries you
   actually serve, or the agent's own heartbeats, must not appear.
4. Remove `WAF_ENFORCE=off` and redeploy.

If a country appears in the logs that you do serve, either the header is not
trusted (Cloudflare not proxying) or the country list is wrong. Both are
visible in the log line (`country: null` means the header was not trusted).

## What the edge cannot fix

- The authenticated WebSocket tunnel path: edge rules cannot inspect cookies
  or tokens, so tunnel auth lives in the app (PR #1). Do not block `/ws/tunnel`
  at the edge — you would cut off every agent's remote view.
- TLS inspection / content-level DPI: Cloudflare free tier decrypts in front
  of the origin but the lab owns no certificate authority, so MITM inspection
  of student traffic is out of scope.
- The origin's own logs: those still land on Render, not in Cloudflare. The
  app logs its own redacted request stream regardless.