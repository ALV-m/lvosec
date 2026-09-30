import { Router, type IRouter } from "express";
import { eq, ilike, or, desc } from "drizzle-orm";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { db, pool } from "@workspace/db";
import {
  actionsTable,
  alertsTable,
  checkinsTable,
  computersTable,
  eventsTable,
  settingsTable,
} from "@workspace/db";
import {
  correlateLab,
  evaluatePosture,
  summariseLab,
  type PostureSummary,
  type SecuritySignals,
} from "../lib/blue-team/posture";
import { DefenseStackResponse } from "@workspace/api-zod";
import { bundledAgentVersion } from "../lib/agent-version";

const router: IRouter = Router();

// Highest version advertised by any bundled agent (Windows PS or Linux Python).
const latestAgentVersion = bundledAgentVersion();

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

router.get("/blue-team/posture", async (_req, res) => {
  const [computers, settings] = await Promise.all([
    db.select().from(computersTable),
    db.select({ key: settingsTable.key, value: settingsTable.value }).from(settingsTable),
  ]);

  const settingsMap: Record<string, string | null> = {};
  for (const s of settings) settingsMap[s.key] = s.value;

  const perComputer: Array<{
    computerId: number;
    computerName: string;
    room: string;
    status: string;
    os: string | null;
    summary: PostureSummary;
  }> = [];
  const summaries: Array<{
    computerId: number;
    computerName: string;
    room: string;
    summary: PostureSummary;
  }> = [];

  for (const computer of computers) {
    const summary = evaluatePosture({
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
      settings: settingsMap,
      security: signalsFor(computer),
bundledAgentVersion: latestAgentVersion,
      now: new Date(),
    });
    perComputer.push({
      computerId: computer.id,
      computerName: computer.name,
      room: computer.room,
      status: computer.status,
      os: computer.os,
      summary,
    });
    summaries.push({ computerId: computer.id, computerName: computer.name, room: computer.room, summary });
  }

  const lab = summariseLab(summaries);
  const findings = correlateLab(summaries);

  res.json({ lab, findings, computers: perComputer });
});

router.get("/blue-team/posture/:computerId", async (req, res) => {
  const computerId = Number(req.params.computerId);
  if (!Number.isInteger(computerId) || computerId < 1) {
    res.status(400).json({ error: "Invalid computer id" });
    return;
  }
  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.id, computerId))
    .limit(1);

  if (!computer) {
    res.status(404).json({ error: "Computer not found" });
    return;
  }

  const settings = await db
    .select({ key: settingsTable.key, value: settingsTable.value })
    .from(settingsTable);
  const settingsMap: Record<string, string | null> = {};
  for (const s of settings) settingsMap[s.key] = s.value;

  const summary = evaluatePosture({
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
    settings: settingsMap,
    security: signalsFor(computer),
bundledAgentVersion: latestAgentVersion,
    now: new Date(),
  });

  res.json({
    computer: {
      id: computer.id,
      name: computer.name,
      room: computer.room,
      status: computer.status,
      os: computer.os,
    },
    summary,
  });
});

/**
 * Software inventory across every machine that has reported one. The client
 * does the searching; the server just hands over what it has. Empty list when
 * nothing has reported yet (agents below 1.22.0 do not send inventories).
 */
router.get("/blue-team/software", async (_req, res) => {
  const computers = await db
    .select({ id: computersTable.id, name: computersTable.name, room: computersTable.room, installedSoftware: computersTable.installedSoftware })
    .from(computersTable);

  const inventories: Array<{
    computerId: number;
    computerName: string;
    room: string;
    software: Array<{ name: string; version?: string | null; publisher?: string | null }>;
  }> = [];
  let totalEntries = 0;

  for (const c of computers) {
    const software = Array.isArray(c.installedSoftware) ? c.installedSoftware : [];
    if (software.length === 0) continue;
    inventories.push({ computerId: c.id, computerName: c.name, room: c.room, software });
    totalEntries += software.length;
  }

  res.json({ machines: inventories.length, totalEntries, inventories });
});

/**
 * Defense Stack — the live status of every defensive layer this deployment
 * covers, mapped 1:1 to the SOC blueprint (perimeter/WAF, detection,
 * assets, hosts, databases, data). States are computed from the same data
 * the other blue-team endpoints use; blueprint layers that are deliberately
 * out of scope are reported as "na" so the dashboard shows honest coverage.
 */
router.get("/blue-team/defense-stack", async (_req, res) => {
  const [computers, settingsRows] = await Promise.all([
    db.select().from(computersTable),
    db.select({ key: settingsTable.key, value: settingsTable.value }).from(settingsTable),
  ]);

  const settingsMap: Record<string, string | null> = {};
  for (const s of settingsRows) settingsMap[s.key] = s.value;

  const summaries: Array<{ computerId: number; computerName: string; room: string; summary: PostureSummary }> = [];
  for (const computer of computers) {
    summaries.push({
      computerId: computer.id,
      computerName: computer.name,
      room: computer.room,
      summary: evaluatePosture({
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
        settings: settingsMap,
        security: signalsFor(computer),
bundledAgentVersion: latestAgentVersion,
        now: new Date(),
      }),
    });
  }

  const lab = summariseLab(summaries);
  const findings = correlateLab(summaries);

  let inventoryMachines = 0;
  let inventoryEntries = 0;
  for (const c of computers) {
    const software = Array.isArray(c.installedSoftware) ? c.installedSoftware : [];
    if (software.length > 0) {
      inventoryMachines += 1;
      inventoryEntries += software.length;
    }
  }

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
      state: findings.length > 0 ? "warning" : "active",
      detail:
        findings.length > 0
          ? `${findings.length} open correlation finding${findings.length === 1 ? "" : "s"} across the lab`
          : "No open correlation findings",
      count: findings.length,
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
      findings: findings.length,
    }),
  );
});

/**
 * IOC / record search across everything the lab has logged. This is the honest
 * local SOC search: it looks at the events, actions, alerts and check-ins that
 * already exist in this tenant's schema, because that is what this server can
 * actually see. It is not pretending to be a fleet-wide SIEM.
 */
router.get("/blue-team/search", async (req, res) => {
  const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
  if (!q) {
    res.json({ query: "", results: [] });
    return;
  }
  const limit = Math.min(100, Number(req.query.limit) || 50);
  const term = `%${q.replace(/[%_\\]/g, (c) => `\\${c}`)}%`;
  const like = (col: Parameters<typeof ilike>[0]) => ilike(col, term);

  const [events, actions, alerts, checkins] = await Promise.all([
    db
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
    db
      .select({
        id: actionsTable.id,
        action: actionsTable.action,
        message: actionsTable.message,
        actor: actionsTable.actor,
        status: actionsTable.status,
        createdAt: actionsTable.createdAt,
      })
      .from(actionsTable)
      .where(or(like(actionsTable.action), like(actionsTable.message), like(actionsTable.actor), like(actionsTable.payload)))
      .orderBy(desc(actionsTable.createdAt))
      .limit(limit),
    db
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
    db
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

  const results = [
    ...events.map((r) => ({
      kind: "event" as const,
      id: r.id as number | string,
      title: r.message,
      detail: `actor: ${r.actor}` + (r.computerName ? ` · ${r.computerName}` : ""),
      severity: null,
      computerName: r.computerName ?? null,
      createdAt: r.createdAt,
    })),
    ...actions.map((r) => ({
      kind: "action" as const,
      id: r.id as number | string,
      title: r.action,
      detail: (r.message ?? "") + (r.actor ? ` · by ${r.actor}` : ""),
      severity: null,
      computerName: null,
      createdAt: r.createdAt,
    })),
    ...alerts.map((r) => ({
      kind: "alert" as const,
      id: r.id as number | string,
      title: r.title,
      detail: r.detail,
      severity: r.severity,
      computerName: r.computerName,
      createdAt: r.createdAt,
    })),
    ...checkins.map((r) => ({
      kind: "checkin" as const,
      id: r.id as number | string,
      title: `${r.role} check-in: ${r.studentName}`,
      detail: `${r.course ?? "no course"} · ${r.reason ?? "no reason"}`,
      severity: null,
      computerName: r.computerName,
      createdAt: r.submittedAt,
    })),
  ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  res.json({ query: q, count: results.length, results: results.slice(0, limit) });
});

export default router;