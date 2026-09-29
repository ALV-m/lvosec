import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { AsyncLocalStorage } from "node:async_hooks";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ---------------------------------------------------------------------------
// Tenant-scoped database access
// ---------------------------------------------------------------------------
// The whole platform is multi-tenant: each tenant owns a dedicated Postgres
// schema (e.g. `t7`) holding its own copy of the lab tables. A request is
// routed into a tenant by `runInTenant()`, and the exported `db` below is a
// Proxy that transparently talks to the active tenant's schema (or the public
// schema when no tenant context is active, e.g. for platform/registration
// code). Existing route handlers keep using `db` unchanged.
// ---------------------------------------------------------------------------

export interface TenantDbContext {
  db: NodePgDatabase<typeof schema>;
  tenantId: number;
}

export const tenantContext = new AsyncLocalStorage<TenantDbContext>();

export function createTenantDb(
  client: pg.PoolClient,
): NodePgDatabase<typeof schema> {
  return drizzle(client, { schema });
}

export function runInTenant<T>(
  ctx: TenantDbContext,
  fn: () => Promise<T> | T,
): T {
  return tenantContext.run(ctx, fn) as T;
}

const publicDb = drizzle(pool, { schema });

export const db = new Proxy(publicDb, {
  get(_target, prop) {
    const ctx = tenantContext.getStore();
    const base = ctx ? ctx.db : publicDb;
    const value = (base as unknown as Record<PropertyKey, unknown>)[prop];
    return typeof value === "function" ? value.bind(base) : value;
  },
}) as NodePgDatabase<typeof schema>;

export * from "./schema";

// ---------------------------------------------------------------------------
// Schema bootstrap
// ---------------------------------------------------------------------------
// DDL is kept in sync with the Drizzle tables declared in ./schema/lab.ts.
// `ensureSchema()` is idempotent (CREATE TABLE IF NOT EXISTS) and is used by
// the deployment scripts and at server startup so a fresh database always has
// the expected tables.
//
// Multi-tenant layout:
//  * the PUBLIC schema holds only platform tables (`tenants`,
//    `platform_users`, `auth_sessions_platform`);
//  * every tenant owns a dedicated Postgres schema (created by
//    `ensureTenantSchema()`) that mirrors the lab tables below.
// ---------------------------------------------------------------------------

const PUBLIC_DDL_STATEMENTS = [
  `
  CREATE TABLE IF NOT EXISTS tenants (
    id serial PRIMARY KEY,
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    contact_name text NOT NULL,
    contact_email text,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS platform_users (
    id serial PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS auth_sessions_platform (
    id text PRIMARY KEY,
    user_id integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
  );
  CREATE INDEX IF NOT EXISTS auth_sessions_platform_user_idx
    ON auth_sessions_platform (user_id);
  `,
  `
  ALTER TABLE tenants ADD COLUMN IF NOT EXISTS login_token text;
  ALTER TABLE tenants ADD COLUMN IF NOT EXISTS login_token_expires_at timestamptz;
  `,
  `
  CREATE TABLE IF NOT EXISTS platform_db_connections (
    id serial PRIMARY KEY,
    name text NOT NULL,
    url text NOT NULL,
    note text,
    is_active boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'unknown',
    last_checked_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  `,
];

export function schemaNameFor(tenantId: number): string {
  return `t${tenantId}`;
}

const TENANT_DDL_STATEMENTS = [
  `
  CREATE TABLE IF NOT EXISTS lab_computers (
    id serial PRIMARY KEY,
    name text NOT NULL,
    room text NOT NULL,
    status text NOT NULL DEFAULT 'offline',
    user_name text,
    last_seen timestamptz NOT NULL DEFAULT now(),
    os text NOT NULL DEFAULT 'Windows 11 Pro',
    usb_state text NOT NULL DEFAULT 'blocked',
    keyboard boolean NOT NULL DEFAULT true,
    mouse boolean NOT NULL DEFAULT true,
    agent_token text,
    agent_version text,
    av_enabled boolean,
    av_signature text,
    av_last_scan_at timestamptz,
    disk_total bigint,
    disk_free bigint
  );
  `,
  `
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS agent_token text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS agent_version text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS av_enabled boolean;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS av_signature text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS av_last_scan_at timestamptz;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS av_scan_state text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS firewall_enabled boolean;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS firewall_profiles text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS mac_address text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS ip_address text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS checkin_required boolean NOT NULL DEFAULT false;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS remote_view_until timestamptz;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS manufacturer text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS model text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS serial_number text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS bios_serial text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS system_uuid text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS total_ram bigint;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS cpu_name text;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS cpu_cores integer;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS disk_total bigint;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS disk_free bigint;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS security_signals jsonb;
  ALTER TABLE lab_computers ADD COLUMN IF NOT EXISTS installed_software jsonb;
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_actions (
    id serial PRIMARY KEY,
    computer_id integer NOT NULL,
    action text NOT NULL,
    status text NOT NULL DEFAULT 'queued',
    message text,
    payload text,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  `,
  `
  ALTER TABLE lab_actions ADD COLUMN IF NOT EXISTS payload text;
  `,
  `
  ALTER TABLE lab_actions ADD COLUMN IF NOT EXISTS detail text;
  `,
  `
  ALTER TABLE lab_actions ADD COLUMN IF NOT EXISTS actor text;
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_alerts (
    id serial PRIMARY KEY,
    severity text NOT NULL,
    title text NOT NULL,
    detail text NOT NULL,
    computer_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'open'
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_usb_policies (
    id serial PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL,
    mode text NOT NULL DEFAULT 'approval_required',
    scope text NOT NULL DEFAULT 'all',
    computer_ids integer[],
    updated_at timestamptz NOT NULL DEFAULT now()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_student_sessions (
    id serial PRIMARY KEY,
    student_name text NOT NULL,
    student_id text NOT NULL,
    computer_id integer NOT NULL,
    computer_name text NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    status text NOT NULL DEFAULT 'active'
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_events (
    id serial PRIMARY KEY,
    type text NOT NULL,
    message text NOT NULL,
    actor text NOT NULL,
    computer_name text,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  `,
  `
  ALTER TABLE lab_events ADD COLUMN IF NOT EXISTS computer_name text;
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_usb_devices (
    id serial PRIMARY KEY,
    computer_id integer NOT NULL,
    computer_name text NOT NULL,
    device_id text,
    drive_letter text,
    label text,
    status text NOT NULL DEFAULT 'pending',
    scan_result text,
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz
  );
  ALTER TABLE lab_usb_devices ADD COLUMN IF NOT EXISTS instance_id text;
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_peripherals (
    id serial PRIMARY KEY,
    computer_id integer NOT NULL,
    computer_name text NOT NULL,
    kind text NOT NULL,
    name text NOT NULL,
    instance_id text NOT NULL,
    present boolean NOT NULL DEFAULT true,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_changed_at timestamptz NOT NULL DEFAULT now()
  );
  `,
  `
  ALTER TABLE lab_peripherals ADD COLUMN IF NOT EXISTS last_changed_at timestamptz;
  ALTER TABLE lab_peripherals ADD COLUMN IF NOT EXISTS serial text;
  CREATE UNIQUE INDEX IF NOT EXISTS lab_peripherals_computer_instance_idx
    ON lab_peripherals (computer_id, instance_id);
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_settings (
    key text PRIMARY KEY,
    value text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_scan_runs (
    id serial PRIMARY KEY,
    action text NOT NULL,
    initiated_by text NOT NULL,
    status text NOT NULL DEFAULT 'queued',
    requested_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
  );
  CREATE TABLE IF NOT EXISTS lab_scan_results (
    id serial PRIMARY KEY,
    run_id integer NOT NULL,
    computer_id integer NOT NULL,
    computer_name text NOT NULL,
    status text NOT NULL DEFAULT 'queued',
    detail text,
    finished_at timestamptz
  );
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_file_entries (
    id serial PRIMARY KEY,
    computer_id integer NOT NULL,
    path text NOT NULL,
    name text NOT NULL,
    is_dir boolean NOT NULL DEFAULT false,
    size bigint NOT NULL DEFAULT 0,
    modified_at text,
    listed_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS lab_file_entries_computer_path_idx
    ON lab_file_entries (computer_id, path);
  `,
  `
  ALTER TABLE lab_file_entries ADD COLUMN IF NOT EXISTS label text;
  ALTER TABLE lab_file_entries ADD COLUMN IF NOT EXISTS capacity bigint;
  ALTER TABLE lab_file_entries ADD COLUMN IF NOT EXISTS free_space bigint;
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_checkins (
    id serial PRIMARY KEY,
    computer_id integer NOT NULL,
    computer_name text NOT NULL,
    user_name text,
    student_name text NOT NULL,
    phone text,
    admission_no text,
    course text,
    class text,
    reason text,
    email text,
    photo_file_id text,
    submitted_at timestamptz NOT NULL DEFAULT now()
  );
  ALTER TABLE lab_checkins ALTER COLUMN phone DROP NOT NULL;
  ALTER TABLE lab_checkins ALTER COLUMN admission_no DROP NOT NULL;
  ALTER TABLE lab_checkins ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'student';
  ALTER TABLE lab_checkins ADD COLUMN IF NOT EXISTS course text;
  ALTER TABLE lab_checkins ADD COLUMN IF NOT EXISTS class text;
  ALTER TABLE lab_checkins ADD COLUMN IF NOT EXISTS reason text;
  CREATE INDEX IF NOT EXISTS lab_checkins_computer_idx
    ON lab_checkins (computer_id, submitted_at);
  `,
  `
  CREATE TABLE IF NOT EXISTS lab_screenshots (
    id serial PRIMARY KEY,
    computer_id integer NOT NULL,
    file_id text NOT NULL,
    taken_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS lab_screenshots_computer_idx
    ON lab_screenshots (computer_id, taken_at);
  `,
  `
  CREATE TABLE IF NOT EXISTS app_users (
    id serial PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'admin',
    submenu_access jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS auth_sessions (
    id text PRIMARY KEY,
    user_id integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
  );
  CREATE INDEX IF NOT EXISTS auth_sessions_user_idx
    ON auth_sessions (user_id);
  `,
];

export async function ensureSchema(): Promise<void> {
  for (const statement of PUBLIC_DDL_STATEMENTS) {
    await pool.query(statement);
  }
}

export async function ensureTenantSchema(tenantId: number): Promise<void> {
  const schemaName = schemaNameFor(tenantId);
  const client = await pool.connect();
  try {
    await client.query(`CREATE SCHEMA IF NOT EXISTS "${schemaName}"`);
    await client.query(`SET search_path TO "${schemaName}"`);
    for (const statement of TENANT_DDL_STATEMENTS) {
      await client.query(statement);
    }
  } finally {
    await client.query("SET search_path TO public").catch(() => {});
    client.release();
  }
}

export async function ensureAllTenantSchemas(tenantIds: number[]): Promise<void> {
  for (const tenantId of tenantIds) {
    await ensureTenantSchema(tenantId);
  }
}

export async function dropTenantSchema(tenantId: number): Promise<void> {
  await pool.query(`DROP SCHEMA IF EXISTS "${schemaNameFor(tenantId)}" CASCADE`);
}

export * from "./db-connections";
