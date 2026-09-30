import { Router, type IRouter } from "express";
import { asc, eq } from "drizzle-orm";
import {
  computersTable,
  createTenantDb,
  db,
  platformDbConnectionsTable,
  platformUsersTable,
  pool,
  schemaNameFor,
  tenantsTable,
  testDbConnection,
  writePlatformSnapshot,
} from "@workspace/db";
import {
  AdminAccount,
  AdminLoginBody,
  AdminLoginResponse,
  AdminMeResponse,
  AdminLogoutResponse,
  AdminOpenLabResponse,
  DbConnectionCreateBody,
  DbConnectionIdParams,
  DbConnectionSnapshotResponse,
  DbConnectionTestResponse,
  DbConnectionUpdateBody,
  DbConnectionsListResponse,
  PlatformMachineActionBody,
  PlatformMachineActionParams,
  PlatformMachineActionResponse,
  PlatformMachinesListResponse,
  PlatformStatsResponse,
  TenantAdminPasswordBody,
  TenantIdParams,
  TenantsListResponse,
  TenantStatusUpdateBody,
  type DbConnectionStatus,
  type PlatformDbConnection,
  type PlatformMachine,
  type TenantListItem,
} from "@workspace/api-zod";
import {
  createPlatformSession,
  deletePlatformSession,
  generateSessionToken,
  PLATFORM_COOKIE,
  platformSessionCookieOptions,
  requirePlatformAuth,
  SESSION_COOKIE,
  sessionCookieOptions,
} from "../lib/auth";
import { hashPassword, verifyPassword } from "../lib/passwords";
import {
  consumeTenantLoginLink,
  countTenantAdmins,
  countTenantComputers,
  createTenantLoginLink,
  createTenantSuperAdminSession,
  deleteTenant,
  getTenantSuperAdminUsername,
  resetTenantSuperAdmin,
} from "../lib/tenant";
import { queueMachineAction } from "../lib/machine-actions";
import { classifyMachineKind } from "../lib/machine-kind";
import { logger } from "../lib/logger";
import adminBlueTeamRouter from "./admin-blue-team";

const router: IRouter = Router();

const mapAdmin = (row: typeof platformUsersTable.$inferSelect): AdminAccount => ({
  id: row.id,
  username: row.username,
  createdAt: row.createdAt instanceof Date
    ? row.createdAt.toISOString()
    : String(row.createdAt),
});

async function findPlatformUser(username: string) {
  const [row] = await db
    .select()
    .from(platformUsersTable)
    .where(eq(platformUsersTable.username, username))
    .limit(1);
  return row ?? null;
}

router.post("/admin/login", async (req, res): Promise<void> => {
  const body = AdminLoginBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: "Invalid username or password" });
    return;
  }

  const user = await findPlatformUser(body.data.username);
  if (!user || !verifyPassword(body.data.password, user.passwordHash)) {
    res.status(401).json({ error: "Invalid username or password" });
    return;
  }

  const token = generateSessionToken();
  await createPlatformSession(user.id, token);
  res.cookie(PLATFORM_COOKIE, token, platformSessionCookieOptions);

  res.json(AdminLoginResponse.parse({ user: mapAdmin(user) }));
});

router.post("/admin/logout", async (req, res): Promise<void> => {
  const token = typeof req.cookies?.[PLATFORM_COOKIE] === "string"
    ? req.cookies[PLATFORM_COOKIE]
    : "";
  if (token) {
    await deletePlatformSession(token);
  }
  res.clearCookie(PLATFORM_COOKIE, { path: "/" });
  res.json(AdminLogoutResponse.parse({ ok: true }));
});

router.use("/admin", requirePlatformAuth);

// Platform-wide Blue Team (SOC seat, moved out of the tenant comp lab). Mounted
// after requirePlatformAuth, so every request below is platform-admin-gated.
router.use(adminBlueTeamRouter);

router.get("/admin/me", async (req, res): Promise<void> => {
  const admin = req.platformAdmin!;
  const [row] = await db
    .select()
    .from(platformUsersTable)
    .where(eq(platformUsersTable.id, admin.id))
    .limit(1);
  if (!row) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  res.json(AdminMeResponse.parse({ user: mapAdmin(row) }));
});

router.get("/admin/tenants", async (_req, res): Promise<void> => {
  const rows = await db.select().from(tenantsTable).orderBy(tenantsTable.id);

  const items: TenantListItem[] = await Promise.all(
    rows.map(async (row) => ({
      id: row.id,
      name: row.name,
      slug: row.slug,
      contactName: row.contactName,
      contactEmail: row.contactEmail,
      status: row.status as TenantListItem["status"],
      createdAt: row.createdAt instanceof Date
        ? row.createdAt.toISOString()
        : String(row.createdAt),
      computers: await countTenantComputers(row.id),
      admins: await countTenantAdmins(row.id),
      superAdminUsername: await getTenantSuperAdminUsername(row.id),
    })),
  );

  res.json(TenantsListResponse.parse({ tenants: items }));
});

router.get("/admin/stats", async (_req, res): Promise<void> => {
  const rows = await db.select().from(tenantsTable);
  const active = rows.filter((row) => row.status === "active").length;
  const suspended = rows.length - active;

  let totalComputers = 0;
  let totalAdmins = 0;
  for (const row of rows) {
    totalComputers += await countTenantComputers(row.id);
    totalAdmins += await countTenantAdmins(row.id);
  }

  res.json(
    PlatformStatsResponse.parse({
      totalTenants: rows.length,
      activeTenants: active,
      suspendedTenants: suspended,
      totalComputers,
      totalAdmins,
    }),
  );
});

router.patch("/admin/tenants/:tenantId", async (req, res): Promise<void> => {
  const params = TenantIdParams.safeParse(req.params);
  const body = TenantStatusUpdateBody.safeParse(req.body);
  if (!params.success || !body.success) {
    res.status(400).json({ error: "Invalid tenant update" });
    return;
  }

  const [existing] = await db
    .select()
    .from(tenantsTable)
    .where(eq(tenantsTable.id, params.data.tenantId))
    .limit(1);
  if (!existing) {
    res.status(404).json({ error: "Tenant not found" });
    return;
  }

  const [updated] = await db
    .update(tenantsTable)
    .set({ status: body.data.status })
    .where(eq(tenantsTable.id, existing.id))
    .returning();

  logger.info(
    { tenantId: existing.id, status: body.data.status },
    "Tenant status updated",
  );
  res.json({
    id: updated.id,
    name: updated.name,
    slug: updated.slug,
    contactName: updated.contactName,
    contactEmail: updated.contactEmail,
    status: updated.status,
    createdAt: updated.createdAt instanceof Date
      ? updated.createdAt.toISOString()
      : String(updated.createdAt),
  });
});

router.post("/admin/tenants/:tenantId/reset-password", async (req, res): Promise<void> => {
  const params = TenantIdParams.safeParse(req.params);
  const body = TenantAdminPasswordBody.safeParse(req.body);
  if (!params.success || !body.success) {
    res.status(400).json({ error: "Invalid password" });
    return;
  }

  const tenant = await db
    .select()
    .from(tenantsTable)
    .where(eq(tenantsTable.id, params.data.tenantId))
    .limit(1);
  if (tenant.length === 0) {
    res.status(404).json({ error: "Tenant not found" });
    return;
  }

  await resetTenantSuperAdmin(params.data.tenantId, body.data.password);
  res.json({ ok: true });
});

router.post("/admin/tenants/:tenantId/login-link", async (req, res): Promise<void> => {
  const params = TenantIdParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: "Invalid tenant id" });
    return;
  }

  const [tenant] = await db
    .select()
    .from(tenantsTable)
    .where(eq(tenantsTable.id, params.data.tenantId))
    .limit(1);
  if (!tenant) {
    res.status(404).json({ error: "Tenant not found" });
    return;
  }

  const { token } = await createTenantLoginLink(params.data.tenantId);
  res.json({ url: `/t/${tenant.slug}/login?link=${token}` });
});

router.post("/admin/tenants/:tenantId/open-lab", async (req, res): Promise<void> => {
  const params = TenantIdParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: "Invalid tenant id" });
    return;
  }

  const [tenant] = await db
    .select()
    .from(tenantsTable)
    .where(eq(tenantsTable.id, params.data.tenantId))
    .limit(1);
  if (!tenant) {
    res.status(404).json({ error: "Tenant not found" });
    return;
  }
  if (tenant.status !== "active") {
    res.status(403).json({ error: "This lab account is suspended" });
    return;
  }

  const session = await createTenantSuperAdminSession(tenant.id);
  if (!session) {
    res.status(404).json({ error: "This lab has no super admin account" });
    return;
  }

  res.cookie(SESSION_COOKIE, session.sessionToken, sessionCookieOptions);
  res.json(AdminOpenLabResponse.parse({ path: `/t/${tenant.slug}` }));
});

router.delete("/admin/tenants/:tenantId", async (req, res): Promise<void> => {
  const params = TenantIdParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: "Invalid tenant id" });
    return;
  }

  const [existing] = await db
    .select()
    .from(tenantsTable)
    .where(eq(tenantsTable.id, params.data.tenantId))
    .limit(1);
  if (!existing) {
    res.status(404).json({ error: "Tenant not found" });
    return;
  }

  await deleteTenant(existing.id);
  logger.info({ tenantId: existing.id }, "Tenant deleted");
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// DB Management — registry of Postgres URLs the admin inputs and manages under
// one dashboard. The admin marks one connection as active (the DB their sites
// should use — the dashboard provides the URL to copy), health-checks any
// connection, and pushes a manual platform snapshot to a chosen target.
// ---------------------------------------------------------------------------

const mapDbConnection = (
  row: typeof platformDbConnectionsTable.$inferSelect,
): PlatformDbConnection => ({
  id: row.id,
  name: row.name,
  url: row.url,
  note: row.note,
  isActive: row.isActive,
  status: row.status as DbConnectionStatus,
  lastCheckedAt: row.lastCheckedAt
    ? new Date(row.lastCheckedAt).toISOString()
    : null,
  lastError: row.lastError,
  createdAt: new Date(row.createdAt).toISOString(),
});

router.get("/admin/databases", async (_req, res): Promise<void> => {
  const rows = await db
    .select()
    .from(platformDbConnectionsTable)
    .orderBy(asc(platformDbConnectionsTable.id));
  res.json(
    DbConnectionsListResponse.parse({ connections: rows.map(mapDbConnection) }),
  );
});

router.post("/admin/databases", async (req, res): Promise<void> => {
  const body = DbConnectionCreateBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: "Invalid connection details" });
    return;
  }
  const [row] = await db
    .insert(platformDbConnectionsTable)
    .values({
      name: body.data.name,
      url: body.data.url,
      note: body.data.note ?? null,
    })
    .returning();
  res.status(201).json(mapDbConnection(row));
});

router.patch("/admin/databases/:id", async (req, res): Promise<void> => {
  const params = DbConnectionIdParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: "Invalid connection id" });
    return;
  }
  const body = DbConnectionUpdateBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: "Invalid connection update" });
    return;
  }

  const [existing] = await db
    .select()
    .from(platformDbConnectionsTable)
    .where(eq(platformDbConnectionsTable.id, params.data.id))
    .limit(1);
  if (!existing) {
    res.status(404).json({ error: "Connection not found" });
    return;
  }

  // Only one connection can be the active (in-use) database at a time.
  if (body.data.isActive === true) {
    await db
      .update(platformDbConnectionsTable)
      .set({ isActive: false })
      .where(eq(platformDbConnectionsTable.isActive, true));
  }

  const set: Partial<typeof platformDbConnectionsTable.$inferInsert> = {};
  if (body.data.name !== undefined) set.name = body.data.name;
  if (body.data.url !== undefined) set.url = body.data.url;
  if (body.data.note !== undefined) set.note = body.data.note;
  if (body.data.isActive !== undefined) set.isActive = body.data.isActive;
  if (Object.keys(set).length > 0) {
    await db
      .update(platformDbConnectionsTable)
      .set(set)
      .where(eq(platformDbConnectionsTable.id, existing.id));
  }

  const [updated] = await db
    .select()
    .from(platformDbConnectionsTable)
    .where(eq(platformDbConnectionsTable.id, existing.id))
    .limit(1);
  res.json(mapDbConnection(updated));
});

router.delete("/admin/databases/:id", async (req, res): Promise<void> => {
  const params = DbConnectionIdParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: "Invalid connection id" });
    return;
  }
  const [existing] = await db
    .select()
    .from(platformDbConnectionsTable)
    .where(eq(platformDbConnectionsTable.id, params.data.id))
    .limit(1);
  if (!existing) {
    res.status(404).json({ error: "Connection not found" });
    return;
  }
  await db
    .delete(platformDbConnectionsTable)
    .where(eq(platformDbConnectionsTable.id, existing.id));
  res.json({ ok: true });
});

router.post("/admin/databases/:id/test", async (req, res): Promise<void> => {
  const params = DbConnectionIdParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: "Invalid connection id" });
    return;
  }
  const [existing] = await db
    .select()
    .from(platformDbConnectionsTable)
    .where(eq(platformDbConnectionsTable.id, params.data.id))
    .limit(1);
  if (!existing) {
    res.status(404).json({ error: "Connection not found" });
    return;
  }

  const result = await testDbConnection(existing.url);
  await db
    .update(platformDbConnectionsTable)
    .set({
      status: result.ok ? "ok" : "error",
      lastCheckedAt: new Date(),
      lastError: result.error,
    })
    .where(eq(platformDbConnectionsTable.id, existing.id));

  res.json(
    DbConnectionTestResponse.parse({
      ok: result.ok,
      latencyMs: result.latencyMs,
      error: result.error,
    }),
  );
});

async function buildPlatformSnapshot(takenAt: string) {
  const tenants = await db
    .select()
    .from(tenantsTable)
    .orderBy(asc(tenantsTable.id));
  const tenantRows = [];
  for (const tenant of tenants) {
    const [computers, admins] = await Promise.all([
      countTenantComputers(tenant.id),
      countTenantAdmins(tenant.id),
    ]);
    tenantRows.push({
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      status: tenant.status,
      computers,
      admins,
    });
  }
  const stats = tenants.reduce(
    (acc, t) => {
      acc.total += 1;
      if (t.status === "active") acc.active += 1;
      if (t.status === "suspended") acc.suspended += 1;
      return acc;
    },
    { total: 0, active: 0, suspended: 0 },
  );
  return {
    takenAt,
    source: "lvosec",
    platform: {
      totalTenants: stats.total,
      activeTenants: stats.active,
      suspendedTenants: stats.suspended,
      totalComputers: tenantRows.reduce((n, t) => n + t.computers, 0),
      totalAdmins: tenantRows.reduce((n, t) => n + t.admins, 0),
    },
    tenants: tenantRows,
  };
}

router.post(
  "/admin/databases/:id/push-snapshot",
  async (req, res): Promise<void> => {
    const params = DbConnectionIdParams.safeParse(req.params);
    if (!params.success) {
      res.status(400).json({ error: "Invalid connection id" });
      return;
    }
    const [existing] = await db
      .select()
      .from(platformDbConnectionsTable)
      .where(eq(platformDbConnectionsTable.id, params.data.id))
      .limit(1);
    if (!existing) {
      res.status(404).json({ error: "Connection not found" });
      return;
    }

    const takenAt = new Date().toISOString();
    const payload = await buildPlatformSnapshot(takenAt);
    const result = await writePlatformSnapshot(existing.url, payload);

    await db
      .update(platformDbConnectionsTable)
      .set({
        status: result.ok ? "ok" : "error",
        lastCheckedAt: new Date(),
        lastError: result.error,
      })
      .where(eq(platformDbConnectionsTable.id, existing.id));

    if (!result.ok) {
      res.status(502).json({ error: result.error ?? "Snapshot push failed" });
      return;
    }
    res.json(
      DbConnectionSnapshotResponse.parse({ ok: true, rows: result.rows, takenAt }),
    );
  },
);

// ---------------------------------------------------------------------------
// Platform-wide Machines — every tenant's computers/servers under one Super
// Admin dashboard. Network status (IP, MAC, firewall on/off, last seen) plus
// the same operator controls the tenant lab uses (firewall, USB, lock,
// restart, message), forwards through the shared queueMachineAction() so
// behavior is identical to the per-lab dashboard.
// ---------------------------------------------------------------------------

const mapPlatformMachine = (
  tenant: { id: number; name: string; slug: string; status: string },
  computer: typeof computersTable.$inferSelect,
): PlatformMachine => ({
  tenantId: tenant.id,
  tenantName: tenant.name,
  tenantSlug: tenant.slug,
  tenantStatus: tenant.status,
  id: computer.id,
  name: computer.name,
  room: computer.room,
  status: computer.status,
  userName: computer.userName,
  lastSeen:
    computer.lastSeen instanceof Date
      ? computer.lastSeen.toISOString()
      : String(computer.lastSeen),
  os: computer.os,
  // Determines which Platform Admin "service" the machine belongs to:
  // a Windows lab computer or a Linux cloud VPS.
  kind: classifyMachineKind(computer.os),
  agentVersion: computer.agentVersion,
  usbState: computer.usbState,
  avEnabled: computer.avEnabled,
  firewallEnabled: computer.firewallEnabled,
  firewallProfiles: computer.firewallProfiles,
  ipAddress: computer.ipAddress,
  macAddress: computer.macAddress,
  // VPS telemetry from the hourly channel (services, packages, login
  // failures, FIM). JSONB columns come back as unknown; the zod parse on the
  // response shape re-validates them.
  services: computer.services as PlatformMachine["services"] | null,
  packages: computer.packages as PlatformMachine["packages"] | null,
  authFailures: computer.authFailures as PlatformMachine["authFailures"] | null,
  fimState: computer.fimState as PlatformMachine["fimState"] | null,
  // Surfaces the Linux agent's sshRateLimited heartbeat signal so Blue Team
  // can toggle the ufw limit rule with visible state.
  sshRateLimited:
    (computer.securitySignals as { sshRateLimited?: boolean } | null)?.sshRateLimited ?? null,
});

router.get("/admin/machines", async (_req, res): Promise<void> => {
  const tenants = await db
    .select()
    .from(tenantsTable)
    .orderBy(asc(tenantsTable.id));
  const client = await pool.connect();
  const machines: PlatformMachine[] = [];
  try {
    for (const tenant of tenants) {
      try {
        await client.query(`SET search_path TO "${schemaNameFor(tenant.id)}"`);
        const tenantDb = createTenantDb(client);
        const computers = await tenantDb
          .select()
          .from(computersTable)
          .orderBy(asc(computersTable.name));
        machines.push(...computers.map((c) => mapPlatformMachine(tenant, c)));
      } catch (err) {
        // Tenant schemas are provisioned lazily at startup; skip missing ones
        // so one broken tenant never fails the whole platform view.
        logger.warn(
          { tenantId: tenant.id, err },
          "Skipping machine scan for tenant",
        );
      }
    }
  } finally {
    // Never hand a connection back to the pool with a tenant search_path.
    await client.query("SET search_path TO public").catch(() => {});
    client.release();
  }
  res.json(PlatformMachinesListResponse.parse({ machines }));
});

router.post(
  "/admin/machines/:tenantId/:computerId/actions",
  async (req, res): Promise<void> => {
    const params = PlatformMachineActionParams.safeParse(req.params);
    const body = PlatformMachineActionBody.safeParse(req.body);
    if (!params.success || !body.success) {
      res.status(400).json({ error: "Invalid machine action" });
      return;
    }

    const [tenant] = await db
      .select()
      .from(tenantsTable)
      .where(eq(tenantsTable.id, params.data.tenantId))
      .limit(1);
    if (!tenant) {
      res.status(404).json({ error: "Tenant not found" });
      return;
    }
    if (tenant.status !== "active") {
      res.status(403).json({ error: "This lab account is suspended" });
      return;
    }

    const client = await pool.connect();
    try {
      await client.query(`SET search_path TO "${schemaNameFor(tenant.id)}"`);
      const tenantDb = createTenantDb(client);
      const [computer] = await tenantDb
        .select()
        .from(computersTable)
        .where(eq(computersTable.id, params.data.computerId))
        .limit(1);
      if (!computer) {
        res.status(404).json({ error: "Computer not found" });
        return;
      }

      const outcome = await queueMachineAction(tenantDb, computer, {
        action: body.data.action,
        message: body.data.message ?? null,
        payload: body.data.payload ?? null,
        actor: "Platform administrator",
      });
      if (!outcome.ok || !outcome.queued) {
        res
          .status(outcome.httpStatus)
          .json({ error: outcome.error ?? "Action failed" });
        return;
      }
      res
        .status(outcome.httpStatus)
        .json(PlatformMachineActionResponse.parse(outcome.queued));
    } finally {
      await client.query("SET search_path TO public").catch(() => {});
      client.release();
    }
  },
);

export default router;
