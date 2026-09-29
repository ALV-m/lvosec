import pg from "pg";

// ---------------------------------------------------------------------------
// Outbound database connections for the Super Admin "DB Management" dashboard.
// These talk to Postgres URLs the platform admin has registered (external
// URLs, e.g. Neon/Supabase/RDS), independent of the platform's own DATABASE_URL.
// ---------------------------------------------------------------------------

const { Client } = pg;

export interface DbConnectionTestResult {
  ok: boolean;
  latencyMs: number | null;
  error: string | null;
}

export interface DbSnapshotWriteResult {
  ok: boolean;
  rows: number;
  error: string | null;
}

// Give slow external hosts a bounded window; fail instead of hanging the admin
// request (admin routes are not tenant-scoped, but we still want fast feedback).
const OUTBOUND_CONNECT_TIMEOUT_MS = 8000;

export async function testDbConnection(
  url: string,
): Promise<DbConnectionTestResult> {
  const client = new Client({
    connectionString: url,
    connectionTimeoutMillis: OUTBOUND_CONNECT_TIMEOUT_MS,
  });
  const startedAt = performance.now();
  try {
    await client.connect();
    await client.query("SELECT 1");
    return {
      ok: true,
      latencyMs: Math.round(performance.now() - startedAt),
      error: null,
    };
  } catch (err) {
    return {
      ok: false,
      latencyMs: null,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    await client.end().catch(() => {});
  }
}

// Snapshots land in a dedicated table on the target database so the admin can
// query them with standard SQL (id serial, taken_at, payload jsonb).
const SNAPSHOT_DDL = `
CREATE TABLE IF NOT EXISTS lvosec_platform_snapshots (
  id serial PRIMARY KEY,
  taken_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL
);
`;

export async function writePlatformSnapshot(
  url: string,
  payload: unknown,
): Promise<DbSnapshotWriteResult> {
  const client = new Client({
    connectionString: url,
    connectionTimeoutMillis: OUTBOUND_CONNECT_TIMEOUT_MS,
  });
  try {
    await client.connect();
    await client.query(SNAPSHOT_DDL);
    await client.query(
      `INSERT INTO lvosec_platform_snapshots (taken_at, payload)
       VALUES (now(), $1::jsonb)`,
      [JSON.stringify(payload)],
    );
    return { ok: true, rows: 1, error: null };
  } catch (err) {
    return {
      ok: false,
      rows: 0,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    await client.end().catch(() => {});
  }
}