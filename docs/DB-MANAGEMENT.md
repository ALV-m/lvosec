# DB Management (Super Admin)

The **DB Management** section of the Platform Admin dashboard (`/admin`) keeps
all database server URLs in one place: you input each database's connection
URL, the dashboard manages them under a single view, health-checks them, and
**provides the URL for the database you set to use** so your other sites can
consume it.

Data movement is **manual, per target** — nothing is mirrored automatically.
For any registered database you can push a one-off snapshot of the platform.

## Flow

1. **Input** — "Add connection" registers a Postgres URL with a friendly name
   and an optional note (e.g. "main site", "archiving", "lab 3 reports").
2. **Manage under one dashboard** — the registry lists every connection with
   its host, health status, and last check.
3. **Provide the URL to use** — each row shows its full connection URL with a
   one-click copy. Marking a connection **Set active** badges it "In use":
   that is the database you have designated as the current one for your sites.
4. **Manual per-target data** — the **Snapshot** action on a row pushes a JSON
   snapshot of the platform (tenant list with computer/admin counts) written
   into that specific database.

## Endpoints

All endpoints sit under `/api/admin/*` and are gated by `requirePlatformAuth`
(same cookie as the Platform Admin dashboard).

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/admin/databases` | List registered connections |
| POST | `/admin/databases` | Register a connection (name, url, note?) |
| PATCH | `/admin/databases/:id` | Update name/url/note; `isActive: true` marks it as the in-use database (clears the others) |
| DELETE | `/admin/databases/:id` | Remove from the dashboard (nothing is deleted on the target DB) |
| POST | `/admin/databases/:id/test` | Connect, `SELECT 1`, record status + latency |
| POST | `/admin/databases/:id/push-snapshot` | Manual snapshot push to that target |

## Where data lives

- **Registry** — `platform_db_connections` (public schema of the platform DB):
  `name`, `url`, `note`, `is_active`, `status` (`unknown`/`ok`/`error`),
  `last_checked_at`, `last_error`.
- **Snapshots on each target** — pushing to a database creates a
  `lvosec_platform_snapshots` table there (`id`, `taken_at`, `payload jsonb`),
  so snapshots are queryable with plain SQL.

## Security notes

- Registered URLs are stored exactly as entered; they contain credentials, so
  this area is Super Admin only.
- URL input is validated to accept only `postgres://` or `postgresql://`
  connection strings.
- Outbound test/snapshot connections time out after 8 seconds so a dead host
  never hangs the dashboard.