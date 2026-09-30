// ---------------------------------------------------------------------------
// Platform-wide Blue Team — the SOC seat moved from each tenant's comp lab to
// the Platform Admin dashboard. Every endpoint aggregates across ALL tenant
// schemas (machines, posture, software inventory, record search) so the
// platform admin sees the whole deployment, not one lab.
//
// Defense Stack states are derived from the same posture engine the tenant
// version used; blueprint layers that are deliberately out of scope are still
// reported as "na" so the dashboard stays honest about coverage.
// ---------------------------------------------------------------------------

import { Router, type IRouter } from "express";
import { asc, desc, ilike, or } from "drizzle-orm";
import {
  actionsTable,
  alertsTable,
  checkinsTable,
  computersTable,
  createTenantDb,
  db,
  eventsTable,
  pool,
  schemaNameFor,
  settingsTable,
  tenantsTable,
} from "@workspace/db";
import {
  correlateLab,
  evaluatePosture,
  summariseLab,
  type LabFinding,
  type PostureCategory,
  type PostureSummary,
  type SecuritySignals,
} from "../lib/blue-team/posture";
import { DefenseStackResponse } from "@workspace/api-zod";
import { bundledAgentVersion } from "../lib/agent-version";
import { logger } from "../lib/logger";

const router: IRouter = Router();

// Highest version advertised by any bundled agent (Windows PS or Linux Python).
const latestAgentVersion = bundledAgentVersion();

type TenantComputer = typeof computersTable.$inferSelect;
type TenantDb = ReturnType<typeof createTenantDb>;
type LabSummary = ReturnType<typeof summariseLab>;

/**
 * Rebuilds the SecuritySignals the posture engine reads from what the agent has
 * actually reported. Old rows predate the security_signals column and the
 * heartbeat still fills the legacy flat fields, so both are folded together.
 */
function signalsFor(computer: {
  securitySignals?: unknown;
  avEnabled?: boolean | null;
  firewallEnabled?: boolean | null;
}): SecuritySignals {
  const reported = (computer.securitySignals ?? {}) as SecuritySignals;
  return {
    avEnabled: reported.avEnabled ?? computer.avEnabled,
    firewallEnabled: reported.firewallEnabled ?? computer.firewallEnabled,
    ...reported,
  };
}

function settingsMapFor(
  rows: Array<{ key: string; value: string | null }>,
): Record<string, string | null> {
  const map: Record<string, string | null> = {};
  for (const s of rows) map[s.key] = s.value;
  return map;
}

function evaluateComputer(
  computer: TenantComputer,
  settings: Record<string, string | null>,
): PostureSummary {
  return evaluatePosture({
    computer: {
      id: computer.id,
      name: computer.name,
      room: computer.room,
      status: computer.status,
      os: computer.os,
      lastSeen: computer.lastSeen,
      agentVersion: computer.agentVersion,
      avEnabled: computer.avEnabled,
      avSignature: computer.avSignature,
      avLastScanAt: computer.avLastScanAt,
      firewallEnabled: computer.firewallEnabled,
      diskFree: computer.diskFree,
      diskTotal: computer.diskTotal,
    },
    settings,
    security: signalsFor(computer),
    bundledAgentVersion: latestAgentVersion,
    now: new Date(),
  });
}

function emptyPostureByCategory(): Record<
  PostureCategory,
  { passing: number; failing: number; unknown: number }
> {
  return {
    detection: { passing: 0, failing: 0, unknown: 0 },
    endpoint: { passing: 0, failing: 0, unknown: 0 },
    network: { passing: 0, failing: 0, unknown: 0 },
    access_control: { passing: 0, failing: 0, unknown: 0 },
    data_protection: { passing: 0, failing: 0, unknown: 0 },
    configuration: { passing: 0, failing: 0, unknown: 0 },
  };
}

/** Sums per-lab posture aggregates into a platform-wide lab summary. */
function mergeLabs(labs: LabSummary[]): LabSummary {
  const merged: LabSummary = {
    computers: 0,
    withFailures: 0,
    checks: 0,
    passing: 0,
    failing: 0,
    unknown: 0,
    byCategory: emptyPostureByCategory(),
    criticalMachines: [],
  };
  for (const lab of labs) {
    merged.computers += lab.computers;
    merged.withFailures += lab.withFailures;
    merged.checks += lab.checks;
    merged.passing += lab.passing;
    merged.failing += lab.failing;
    merged.unknown += lab.unknown;
    for (const key of Object.keys(merged.byCategory) as PostureCategory[]) {
      merged.byCategory[key].passing += lab.byCategory[key].passing;
      merged.byCategory[key].failing += lab.byCategory[key].failing;
      merged.byCategory[key].unknown += lab.byCategory[key].unknown;
    }
    merged.criticalMachines.push(...lab.criticalMachines);
  }
  return merged;
}

/**
 * Runs a callback against every tenant's schema. Tenant schemas are provisioned
 * lazily at startup, so a missing/broken one is skipped — it never fails the
 * whole platform view.
 */
async function scanTenants(
  visit: (
    tenant: { id: number; name: string; slug: string; status: string },
    tenantDb: TenantDb,
  ) => Promise<void>,
): Promise<void> {
  const tenants = await db.select().from(tenantsTable).orderBy(asc(tenantsTable.id));
  const client = await pool.connect();
  try {
    for (const tenant of tenants) {
      try {
        await client.query(`SET search_path TO "${schemaNameFor(tenant.id)}"`);
        await visit(tenant, createTenantDb(client));
      } catch (err) {
        logger.warn({ tenantId: tenant.id, err }, "Skipping Blue Team scan for tenant");
      }
    }
  } finally {
    // Never hand a connection back to the pool with a tenant search_path.
    await client.query("SET search_path TO public").catch(() => {});
    client.release();
  }
}

interface PlatformPostureComputerRow {
  tenantId: number;
  tenantName: string;
  tenantSlug: string;
  computerId: number;
  computerName: string;
  room: string;
  status: string;
  os: string | null;
  summary: PostureSummary;
}

router.get("/admin/blue-team/posture", async (_req, res): Promise<void> => {
  const labs: LabSummary[] = [];
  const findings: LabFinding[] = [];
  const computers: PlatformPostureComputerRow[] = [];

  await scanTenants(async (tenant, tenantDb) => {
    const [rows, settingsRows] = await Promise.all([
      tenantDb.select().from(computersTable),
      tenantDb
        .select({ key: settingsTable.key, value: settingsTable.value })
        .from(settingsTable),
    ]);
    const settings = settingsMapFor(settingsRows);
    const summaries: Array<{
      computerId: number;
      computerName: string;
      room: string;
      summary: PostureSummary;
    }> = [];
    for (const computer of rows) {
      const summary = evaluateComputer(computer, settings);
      summaries.push({
        computerId: computer.id,
        computerName: computer.name,
        room: computer.room,
        summary,
      });
      computers.push({
        tenantId: tenant.id,
        tenantName: tenant.name,
        tenantSlug: tenant.slug,
        computerId: computer.id,
        computerName: computer.name,
        room: computer.room,
        status: computer.status,
        os: computer.os,
        summary,
      });
    }
    labs.push(summariseLab(summaries));
    // Finding ids are namespaced per tenant so the merged list stays unique.
    for (const finding of correlateLab(summaries)) {
      findings.push({ ...finding, id: `t${tenant.id}:${finding.id}` });
    }
  });

  res.json({ lab: mergeLabs(labs), findings, computers });
});

/**
 * Software inventory across every machine in every tenant that has reported
 * one. Empty list when nothing has reported yet (agents below 1.22.0 do not
 * send inventories).
 */
router.get("/admin/blue-team/software", async (_req, res): Promise<void> => {
  const inventories: Array<{
    tenantId: number;
    tenantName: string;
    computerId: number;
    computerName: string;
    room: string;
    software: Array<{ name: string; version?: string | null; publisher?: string | null }>;
  }> = [];
  let totalEntries = 0;

  await scanTenants(async (tenant, tenantDb) => {
    const rows = await tenantDb
      .select({
        id: computersTable.id,
        name: computersTable.name,
        room: computersTable.room,
        installedSoftware: computersTable.installedSoftware,
      })
      .from(computersTable);
    for (const c of rows) {
      const software = Array.isArray(c.installedSoftware) ? c.installedSoftware : [];
      if (software.length === 0) continue;
      inventories.push({
        tenantId: tenant.id,
        tenantName: tenant.name,
        computerId: c.id,
        computerName: c.name,
        room: c.room,
        software,
      });
      totalEntries += software.length;
    }
  });

  res.json({ machines: inventories.length, totalEntries, inventories });
});

/**
 * Defense Stack — the live status of every defensive layer the platform covers,
 * mapped 1:1 to the SOC blueprint (perimeter/WAF, detection, assets, hosts,
 * databases, data). Counts are aggregated across all tenants; states are
 * computed from the same data the other blue-team endpoints use. Blueprint
 * layers that are deliberately out of scope are reported as "na" so the
 * dashboard shows honest coverage.
 */
router.get("/admin/blue-team/defense-stack", async (_req, res): Promise<void> => {
  const labs: LabSummary[] = [];
  let findingCount = 0;
  let inventoryMachines = 0;
  let inventoryEntries = 0;

  await scanTenants(async (_tenant, tenantDb) => {
    const [rows, settingsRows] = await Promise.all([
      tenantDb.select().from(computersTable),
      tenantDb
        .select({ key: settingsTable.key, value: settingsTable.value })
        .from(settingsTable),
    ]);
    const settings = settingsMapFor(settingsRows);
    const summaries: Array<{
      computerId: number;
      computerName: string;
      room: string;
      summary: PostureSummary;
    }> = [];
    for (const computer of rows) {
      summaries.push({
        computerId: computer.id,
        computerName: computer.name,
        room: computer.room,
        summary: evaluateComputer(computer, settings),
      });
      const software = Array.isArray(computer.installedSoftware)
        ? computer.installedSoftware
        : [];
      if (software.length > 0) {
        inventoryMachines += 1;
        inventoryEntries += software.length;
      }
    }
    labs.push(summariseLab(summaries));
    findingCount += correlateLab(summaries).length;
  });

  const lab = mergeLabs(labs);

  let dbTotal = 0;
  let dbOk = 0;
  try {
    const registry = await pool.query(
      `SELECT count(*) AS total,
              count(*) FILTER (WHERE status = 'ok') AS ok
       FROM platform_db_connections`,
    );
    dbTotal = Number(registry.rows[0]?.total ?? 0);
    dbOk = Number(registry.rows[0]?.ok ?? 0);
  } catch {
    // Fresh deployments may not have created the registry table yet.
  }

  const allowCountries = (process.env.WAF_ALLOW_COUNTRIES ?? "")
    .split(",")
    .map((c) => c.trim().toUpperCase())
    .filter(Boolean);
  const wafEnforce = process.env.WAF_ENFORCE !== "off";

  const layers = [
    {
      id: "perimeter",
      label: "Perimeter · WAF",
      state: allowCountries.length > 0 ? (wafEnforce ? "active" : "warning") : "off",
      detail:
        allowCountries.length > 0
          ? wafEnforce
            ? `Geo-allowlist enforced (${allowCountries.length} countries), abusive-method & scanner-rule blocking on`
            : `Geo-allowlist configured but observe-only (${allowCountries.length} countries)`
          : "No country allowlist configured",
      count: allowCountries.length,
    },
    {
      id: "detection",
      label: "Detection · Correlation",
      state: findingCount > 0 ? "warning" : "active",
      detail:
        findingCount > 0
          ? `${findingCount} open correlation finding${findingCount === 1 ? "" : "s"} across the platform`
          : "No open correlation findings",
      count: findingCount,
    },
    {
      id: "hosts",
      label: "Hosts · Hardening",
      state: lab.failing > 0 ? "warning" : lab.computers > 0 ? "active" : "off",
      detail:
        lab.computers === 0
          ? "No machines reported yet"
          : `${lab.computers} machines, ${lab.failing} failing posture checks`,
      count: lab.computers,
    },
    {
      id: "assets",
      label: "Assets · Inventory",
      state: inventoryMachines > 0 ? "active" : "off",
      detail:
        inventoryMachines > 0
          ? `${inventoryMachines} machines inventoried, ${inventoryEntries} software entries`
          : "No software inventory yet (reported on the hourly channel)",
      count: inventoryEntries,
    },
    {
      id: "databases",
      label: "Databases · Registry",
      state: dbTotal > 0 ? (dbOk > 0 ? "active" : "warning") : "off",
      detail:
        dbTotal > 0
          ? `${dbTotal} connection${dbTotal === 1 ? "" : "s"} registered, ${dbOk} healthy`
          : "No Postgres connections registered in Admin → Databases",
      count: dbTotal,
    },
    {
      id: "data",
      label: "Data · Protection",
      state: dbOk > 0 ? "active" : "na",
      detail:
        dbOk > 0
          ? "Manual snapshots available to push to healthy targets"
          : "DLP/PAM/data masking deliberately out of scope; snapshots need a healthy DB target",
      count: null,
    },
  ];

  res.json(
    DefenseStackResponse.parse({
      layers,
      lab: { computers: lab.computers, failing: lab.failing },
      findings: findingCount,
    }),
  );
});

/**
 * IOC / record search across everything every tenant has logged. The honest
 * platform SOC search: it looks at the events, actions, alerts and check-ins
 * that already exist in each tenant's schema, because that is what this server
 * can actually see. Not pretending to be a fleet-wide SIEM.
 */
router.get("/admin/blue-team/search", async (req, res): Promise<void> => {
  const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
  if (!q) {
    res.json({ query: "", results: [] });
    return;
  }
  const limit = Math.min(100, Number(req.query.limit) || 50);
  const term = `%${q.replace(/[%_\\]/g, (c) => `\\${c}`)}%`;
  const like = (col: Parameters<typeof ilike>[0]) => ilike(col, term);

  const results: Array<{
    kind: "event" | "action" | "alert" | "checkin";
    id: number | string;
    title: string;
    detail: string;
    severity: string | null;
    computerName: string | null;
    createdAt: Date | string;
    tenantName: string;
  }> = [];

  await scanTenants(async (tenant, tenantDb) => {
    const [events, actions, alerts, checkins] = await Promise.all([
      tenantDb
        .select({
          id: eventsTable.id,
          type: eventsTable.type,
          message: eventsTable.message,
          actor: eventsTable.actor,
          computerName: eventsTable.computerName,
          createdAt: eventsTable.createdAt,
        })
        .from(eventsTable)
        .where(or(like(eventsTable.message), like(eventsTable.actor), like(eventsTable.type)))
        .orderBy(desc(eventsTable.createdAt))
        .limit(limit),
      tenantDb
        .select({
          id: actionsTable.id,
          action: actionsTable.action,
          message: actionsTable.message,
          actor: actionsTable.actor,
          status: actionsTable.status,
          createdAt: actionsTable.createdAt,
        })
        .from(actionsTable)
        .where(
          or(
            like(actionsTable.action),
            like(actionsTable.message),
            like(actionsTable.actor),
            like(actionsTable.payload),
          ),
        )
        .orderBy(desc(actionsTable.createdAt))
        .limit(limit),
      tenantDb
        .select({
          id: alertsTable.id,
          severity: alertsTable.severity,
          title: alertsTable.title,
          detail: alertsTable.detail,
          computerName: alertsTable.computerName,
          status: alertsTable.status,
          createdAt: alertsTable.createdAt,
        })
        .from(alertsTable)
        .where(or(like(alertsTable.title), like(alertsTable.detail), like(alertsTable.computerName)))
        .orderBy(desc(alertsTable.createdAt))
        .limit(limit),
      tenantDb
        .select({
          id: checkinsTable.id,
          studentName: checkinsTable.studentName,
          computerName: checkinsTable.computerName,
          role: checkinsTable.role,
          course: checkinsTable.course,
          reason: checkinsTable.reason,
          submittedAt: checkinsTable.submittedAt,
        })
        .from(checkinsTable)
        .where(
          or(
            like(checkinsTable.studentName),
            like(checkinsTable.computerName),
            like(checkinsTable.course),
            like(checkinsTable.reason),
            like(checkinsTable.admissionNo),
          ),
        )
        .orderBy(desc(checkinsTable.submittedAt))
        .limit(limit),
    ]);

    // Hit ids are namespaced per tenant so merged results keep unique keys.
    for (const r of events) {
      results.push({
        kind: "event",
        id: `t${tenant.id}:${r.id}`,
        title: r.message,
        detail: `actor: ${r.actor}` + (r.computerName ? ` · ${r.computerName}` : ""),
        severity: null,
        computerName: r.computerName ?? null,
        createdAt: r.createdAt,
        tenantName: tenant.name,
      });
    }
    for (const r of actions) {
      results.push({
        kind: "action",
        id: `t${tenant.id}:${r.id}`,
        title: r.action,
        detail: (r.message ?? "") + (r.actor ? ` · by ${r.actor}` : ""),
        severity: null,
        computerName: null,
        createdAt: r.createdAt,
        tenantName: tenant.name,
      });
    }
    for (const r of alerts) {
      results.push({
        kind: "alert",
        id: `t${tenant.id}:${r.id}`,
        title: r.title,
        detail: r.detail,
        severity: r.severity,
        computerName: r.computerName,
        createdAt: r.createdAt,
        tenantName: tenant.name,
      });
    }
    for (const r of checkins) {
      results.push({
        kind: "checkin",
        id: `t${tenant.id}:${r.id}`,
        title: `${r.role} check-in: ${r.studentName}`,
        detail: `${r.course ?? "no course"} · ${r.reason ?? "no reason"}`,
        severity: null,
        computerName: r.computerName,
        createdAt: r.submittedAt,
        tenantName: tenant.name,
      });
    }
  });

  results.sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );
  res.json({ query: q, count: results.length, results: results.slice(0, limit) });
});

export default router;