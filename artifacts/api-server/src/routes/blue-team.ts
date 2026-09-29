import { Router, type IRouter } from "express";
import { eq, ilike, or, desc } from "drizzle-orm";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { db } from "@workspace/db";
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

const router: IRouter = Router();

const DIST_DIR = path.dirname(fileURLToPath(import.meta.url));
const AGENT_SCRIPT_PATH = path.join(DIST_DIR, "lab-agent.ps1");

// Same lookup the agent router uses. Split out so posture reports \"agent is
// behind\" consistently with what the heartbeat advertises.
const bundledAgentVersion = (() => {
  try {
    const source = readFileSync(AGENT_SCRIPT_PATH, "utf8");
    const match = source.match(/\$script:AgentVersion\s*=\s*'([^']+)'/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
})();

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
      bundledAgentVersion,
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
    bundledAgentVersion,
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
      detail: r.message ?? "" + (r.actor ? ` · by ${r.actor}` : ""),
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