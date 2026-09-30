import { Router, type IRouter } from "express";
import express from "express";
import { and, eq, sql } from "drizzle-orm";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { db } from "@workspace/db";
import {
  actionsTable,
  alertsTable,
  checkinsTable,
  computersTable,
  eventsTable,
  fileEntriesTable,
  scanResultsTable,
  scanRunsTable,
  screenshotsTable,
  settingsTable,
  studentSessionsTable,
  usbDevicesTable,
  usbPoliciesTable,
} from "@workspace/db";
import {
  AgentActionCompleteBody,
  AgentActionCompleteParams,
  AgentActionCompleteResponse,
  AgentCheckinBody,
  AgentCheckinResponse,
  AgentEventBody,
  AgentEventResponse,
  AgentHeartbeatBody,
  AgentHeartbeatResponse,
  AgentRegisterBody,
  AgentRegisterResponse,
  AgentScreenshotResponse,
  AgentSoftwareBody,
  AgentSoftwareResponse,
  AgentUploadResponse,
  ReportFileListingBody,
} from "@workspace/api-zod";
import { broadcastFrame } from "../lib/tunnel";
import { bundledAgentVersion } from "../lib/agent-version";

const router: IRouter = Router();

const DIST_DIR = path.dirname(fileURLToPath(import.meta.url));
const UPLOADS_DIR = path.join(DIST_DIR, "data", "uploads");
const AGENT_SCRIPT_PATH = path.join(DIST_DIR, "lab-agent.ps1");
const AGENT_LINUX_SCRIPT_PATH = path.join(DIST_DIR, "lab-agent-linux.py");

await mkdir(UPLOADS_DIR, { recursive: true });

const safeUser = (value: string | null | undefined): string | null => {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
};

const approveByDefault = (
  computer: { usbState: string },
  globalMode: string,
): boolean => globalMode === "allowed" || computer.usbState === "allowed";

async function endActiveSessions(computerId: number): Promise<void> {
  await db
    .update(studentSessionsTable)
    .set({ status: "ended", endedAt: new Date() })
    .where(
      and(
        eq(studentSessionsTable.computerId, computerId),
        eq(studentSessionsTable.status, "active"),
      ),
    );
}

async function hasActiveSession(computerId: number): Promise<boolean> {
  const [row] = await db
    .select({ id: studentSessionsTable.id })
    .from(studentSessionsTable)
    .where(
      and(
        eq(studentSessionsTable.computerId, computerId),
        eq(studentSessionsTable.status, "active"),
      ),
    )
    .limit(1);
  return Boolean(row);
}

async function startSession(
  computerId: number,
  computerName: string,
  userName: string,
): Promise<void> {
  await db.insert(studentSessionsTable).values({
    studentName: userName,
    studentId: `agent:${userName.toLowerCase()}`,
    computerId,
    computerName,
    status: "active",
  });
}

router.post("/agent/register", async (req, res): Promise<void> => {
  const body = AgentRegisterBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const name = body.data.name.trim();
  const [existing] = await db
    .select()
    .from(computersTable)
    .where(sql`lower(${computersTable.name}) = ${name.toLowerCase()}`)
    .limit(1);

  let computer;
  let token = existing?.agentToken ?? null;

  if (existing) {
    if (!token) {
      token = randomBytes(24).toString("hex");
    }
    const [updated] = await db
      .update(computersTable)
      .set({
        agentToken: token,
        agentVersion: body.data.agentVersion ?? existing.agentVersion,
        os: body.data.os ?? existing.os,
        macAddress: body.data.macAddress ?? existing.macAddress,
        ipAddress: body.data.ipAddress ?? existing.ipAddress,
        manufacturer: body.data.manufacturer ?? existing.manufacturer,
        model: body.data.model ?? existing.model,
        serialNumber: body.data.serialNumber ?? existing.serialNumber,
        biosSerial: body.data.biosSerial ?? existing.biosSerial,
        systemUUID: body.data.systemUUID ?? existing.systemUUID,
        totalRAM: body.data.totalRAM ?? existing.totalRAM,
        cpuName: body.data.cpuName ?? existing.cpuName,
        cpuCores: body.data.cpuCores ?? existing.cpuCores,
      })
      .where(eq(computersTable.id, existing.id))
      .returning();
    computer = updated;
  } else {
    token = randomBytes(24).toString("hex");
    const [inserted] = await db
      .insert(computersTable)
      .values({
        name,
        room: "Unassigned",
        status: "offline",
        os: body.data.os ?? "Windows",
        agentToken: token,
        agentVersion: body.data.agentVersion ?? null,
        macAddress: body.data.macAddress ?? null,
        ipAddress: body.data.ipAddress ?? null,
        manufacturer: body.data.manufacturer ?? null,
        model: body.data.model ?? null,
        serialNumber: body.data.serialNumber ?? null,
        biosSerial: body.data.biosSerial ?? null,
        systemUUID: body.data.systemUUID ?? null,
        totalRAM: body.data.totalRAM ?? null,
        cpuName: body.data.cpuName ?? null,
        cpuCores: body.data.cpuCores ?? null,
      })
      .returning();
    computer = inserted;
  }

  res.json(
    AgentRegisterResponse.parse({
      computerId: computer.id,
      token: token!,
      name: computer.name,
      usbState: computer.usbState,
      serverTime: new Date().toISOString(),
    }),
  );
});

router.post("/agent/heartbeat", async (req, res): Promise<void> => {
  const body = AgentHeartbeatBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.agentToken, body.data.token))
    .limit(1);
  if (!computer) {
    res.status(401).json({ error: "Invalid agent token" });
    return;
  }

  const reportedUser = safeUser(body.data.userName);
  const previousUser = safeUser(computer.userName);
  const sessionEvents: Array<{ type: string; message: string; actor: string }> = [];

  if (reportedUser !== previousUser) {
    if (previousUser) {
      await endActiveSessions(computer.id);
      sessionEvents.push({
        type: "student_logout",
        message: `${previousUser} signed out of ${computer.name}`,
        actor: previousUser,
      });
    }
    if (reportedUser && !(await hasActiveSession(computer.id))) {
      await startSession(computer.id, computer.name, reportedUser);
      sessionEvents.push({
        type: "student_login",
        message: `${reportedUser} signed in on ${computer.name}`,
        actor: reportedUser,
      });
    }
  }

  await db
    .update(computersTable)
    .set({
      status: "online",
      lastSeen: new Date(),
      userName: reportedUser,
      os: body.data.os ? body.data.os : computer.os,
      agentVersion: body.data.agentVersion ? body.data.agentVersion : computer.agentVersion,
      avEnabled: body.data.avEnabled ?? computer.avEnabled,
      avSignature: body.data.avSignature ?? computer.avSignature,
      avLastScanAt: body.data.avLastScanAt
        ? new Date(body.data.avLastScanAt)
        : computer.avLastScanAt,
      avScanState: body.data.avScanState ?? computer.avScanState,
      firewallEnabled: body.data.firewallEnabled ?? computer.firewallEnabled,
      firewallProfiles: body.data.firewallProfiles ?? computer.firewallProfiles,
      macAddress: body.data.macAddress ?? computer.macAddress,
      ipAddress: body.data.ipAddress ?? computer.ipAddress,
      manufacturer: body.data.manufacturer ?? computer.manufacturer,
      model: body.data.model ?? computer.model,
      serialNumber: body.data.serialNumber ?? computer.serialNumber,
      biosSerial: body.data.biosSerial ?? computer.biosSerial,
      systemUUID: body.data.systemUUID ?? computer.systemUUID,
      totalRAM: body.data.totalRAM ?? computer.totalRAM,
      cpuName: body.data.cpuName ?? computer.cpuName,
      cpuCores: body.data.cpuCores ?? computer.cpuCores,
      diskTotal: body.data.diskTotal ?? computer.diskTotal,
      diskFree: body.data.diskFree ?? computer.diskFree,
      // The agent sends its full security snapshot with every heartbeat, so
      // store it wholesale. Old agents never send it and leave the last value
      // in place, which is the correct stale-but-known outcome.
      securitySignals: body.data.security ?? computer.securitySignals,
    })
    .where(eq(computersTable.id, computer.id));

  if (body.data.avScanState === "scanning") {
    const started = await db
      .update(scanResultsTable)
      .set({ status: "running" })
      .where(
        and(
          eq(scanResultsTable.computerId, computer.id),
          eq(scanResultsTable.status, "queued"),
        ),
      )
      .returning({ runId: scanResultsTable.runId });

    const runIds = Array.from(new Set(started.map((row) => row.runId)));
    for (const runId of runIds) {
      await db
        .update(scanRunsTable)
        .set({ status: "running" })
        .where(and(eq(scanRunsTable.id, runId), eq(scanRunsTable.status, "queued")));
    }
  }

  for (const event of sessionEvents) {
    await db
      .insert(eventsTable)
      .values({ ...event, computerName: computer.name });
  }

  const [policy] = await db
    .select()
    .from(usbPoliciesTable)
    .orderBy(usbPoliciesTable.id)
    .limit(1);
  const policyMode = policy?.mode ?? "approval_required";

  const approvedDevices =
    approveByDefault(computer, policyMode)
      ? []
      : await db
          .select()
          .from(usbDevicesTable)
          .where(
            and(
              eq(usbDevicesTable.computerId, computer.id),
              eq(usbDevicesTable.status, "approved"),
            ),
          );
  const allowedUsb = approvedDevices
    .map((device) => device.driveLetter)
    .filter((letter): letter is string => Boolean(letter));

  const allowedDeviceIds = approvedDevices
    .map((device) => device.instanceId)
    .filter((instanceId): instanceId is string => Boolean(instanceId));

  const pending = await db
    .select()
    .from(actionsTable)
    .where(
      and(
        eq(actionsTable.computerId, computer.id),
        eq(actionsTable.status, "queued"),
      ),
    )
    .orderBy(actionsTable.id)
    .limit(20);

  const [idleSetting] = await db
    .select()
    .from(settingsTable)
    .where(eq(settingsTable.key, "idle_logout_minutes"))
    .limit(1);
  const idleParsed = idleSetting ? Number(idleSetting.value) : NaN;
  const idleLogoutMinutes =
    idleSetting && Number.isFinite(idleParsed) && idleParsed > 0
      ? Math.min(600, Math.floor(idleParsed))
      : null;

  const settingValue = async (key: string): Promise<string | null> => {
    const [row] = await db
      .select({ value: settingsTable.value })
      .from(settingsTable)
      .where(eq(settingsTable.key, key))
      .limit(1);
    return row?.value ?? null;
  };
  const [signinSetting, sharedUserSetting, sharedPassSetting, adminWindowsUserSetting, blockDownloadsSetting] =
    await Promise.all([
      settingValue("signin_method"),
      settingValue("shared_account_user"),
      settingValue("shared_account_password"),
      settingValue("admin_windows_user"),
      settingValue("block_downloads"),
    ]);
  const signinMethod =
    signinSetting === "shared_account"
      ? ("shared_account" as const)
      : signinSetting === "password"
        ? ("password" as const)
        : null;

  // When the lab uses the "login form instead of password" method with no
  // account configured, generate one automatically so agents can create the
  // local account and set up auto-login without the administrator typing
  // anything.
  let autoShared: { user: string; password: string } | null = null;
  if (signinMethod === "shared_account" && !(sharedUserSetting && sharedPassSetting)) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const bytes = randomBytes(18);
    let password = "";
    for (let i = 0; i < bytes.length; i++) password += chars[bytes[i] % chars.length];
    const user = "lab.student";
    await db
      .insert(settingsTable)
      .values({ key: "shared_account_user", value: user })
      .onConflictDoUpdate({ target: settingsTable.key, set: { value: user } });
    await db
      .insert(settingsTable)
      .values({ key: "shared_account_password", value: password })
      .onConflictDoUpdate({ target: settingsTable.key, set: { value: password } });
    autoShared = { user, password };
  }

  const latest = bundledAgentVersion();

  res.json(
    AgentHeartbeatResponse.parse({
      serverTime: new Date().toISOString(),
      latestAgentVersion: latest,
      agentUpdateRequested:
        latest !== null && latest !== (computer.agentVersion ?? null),
      computer: {
        id: computer.id,
        name: computer.name,
        status: "online",
        usbState: computer.usbState,
        firewallEnabled: computer.firewallEnabled,
        firewallProfiles: computer.firewallProfiles,
        checkinRequired: computer.checkinRequired,
        signinMethod,
        sharedAccountUser: signinMethod === "shared_account" ? autoShared?.user ?? sharedUserSetting : null,
        sharedAccountPassword:
          signinMethod === "shared_account" ? autoShared?.password ?? sharedPassSetting : null,
        adminWindowsUser: adminWindowsUserSetting,
        blockDownloads: blockDownloadsSetting === "true",
        remoteViewActive: Boolean(computer.remoteViewUntil && computer.remoteViewUntil.getTime() > Date.now()),
      },
      allowedUsb,
      allowedDeviceIds,
      pendingActions: pending.map((action) => ({
        id: action.id,
        action: action.action as never,
        message: action.message,
        payload: action.payload,
      })),
      idleLogoutMinutes,
    }),
  );
});

router.post("/agent/actions/:actionId/complete", async (req, res): Promise<void> => {
  const params = AgentActionCompleteParams.safeParse(req.params);
  const body = AgentActionCompleteBody.safeParse(req.body);
  if (!params.success || !body.success) {
    res.status(400).json({ error: "Invalid request" });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.agentToken, body.data.token))
    .limit(1);
  if (!computer) {
    res.status(401).json({ error: "Invalid agent token" });
    return;
  }

  const [action] = await db
    .select()
    .from(actionsTable)
    .where(eq(actionsTable.id, params.data.actionId))
    .limit(1);
  if (!action || action.computerId !== computer.id) {
    res.status(404).json({ error: "Action not found" });
    return;
  }

  await db
    .update(actionsTable)
    .set({ status: body.data.success ? "acknowledged" : "failed" })
    .where(eq(actionsTable.id, action.id));

  const scanMeta = (() => {
    try {
      const parsed = JSON.parse(action.payload ?? "{}") as Record<string, unknown>;
      const runId = Number(parsed.scanRunId);
      const resultId = Number(parsed.scanResultId);
      return Number.isFinite(runId) && Number.isFinite(resultId)
        ? { runId, resultId }
        : null;
    } catch {
      return null;
    }
  })();

  if (scanMeta) {
    const [result] = await db
      .update(scanResultsTable)
      .set({
        status: body.data.success ? "completed" : "failed",
        detail: body.data.detail?.trim() ?? null,
        finishedAt: new Date(),
      })
      .where(eq(scanResultsTable.id, scanMeta.resultId))
      .returning();

    if (result) {
      const [pending] = await db
        .select({ id: scanResultsTable.id })
        .from(scanResultsTable)
        .where(
          and(
            eq(scanResultsTable.runId, scanMeta.runId),
            sql`${scanResultsTable.status} NOT IN ('completed', 'failed')`,
          ),
        )
        .limit(1);

      if (!pending) {
        const allResults = await db
          .select({ status: scanResultsTable.status })
          .from(scanResultsTable)
          .where(eq(scanResultsTable.runId, scanMeta.runId));
        const hasFailure = allResults.some((row) => row.status === "failed");
        await db
          .update(scanRunsTable)
          .set({ status: hasFailure ? "completed_with_errors" : "completed", finishedAt: new Date() })
          .where(eq(scanRunsTable.id, scanMeta.runId));
      }
    }
  }

  const detail = body.data.detail?.trim();
  await db.insert(eventsTable).values({
    type: "operator_action",
    message: `${action.action.replaceAll("_", " ")} ${body.data.success ? "executed" : "failed"} on ${computer.name}${
      detail ? ` â€” ${detail}` : ""
    }`,
    actor: "Agent",
    computerName: computer.name,
  });

  res.json(AgentActionCompleteResponse.parse({ ok: true }));
});

router.post("/agent/files/list", async (req, res): Promise<void> => {
  const body = ReportFileListingBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.agentToken, body.data.token))
    .limit(1);
  if (!computer) {
    res.status(401).json({ error: "Invalid agent token" });
    return;
  }

  const pathKey = body.data.path.replaceAll("\\", "/").replace(/\/+$/, "") || "/";
  await db
    .delete(fileEntriesTable)
    .where(
      and(
        eq(fileEntriesTable.computerId, computer.id),
        eq(fileEntriesTable.path, pathKey),
      ),
    );

  if (body.data.entries.length > 0) {
    await db.insert(fileEntriesTable).values(
      body.data.entries.map((entry) => ({
        computerId: computer.id,
        path: pathKey,
        name: entry.name,
        isDir: entry.isDir,
        size: entry.size,
        modifiedAt: entry.modifiedAt,
        label: entry.label,
        capacity: entry.capacity,
        freeSpace: entry.freeSpace,
      })),
    );
  }

  res.json(AgentActionCompleteResponse.parse({ ok: true }));
});

router.post("/agent/events", async (req, res): Promise<void> => {
  const body = AgentEventBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.agentToken, body.data.token))
    .limit(1);
  if (!computer) {
    res.status(401).json({ error: "Invalid agent token" });
    return;
  }

  const detail = body.data.detail?.trim();
  const message = body.data.message?.trim();

  switch (body.data.type) {
    case "student_login": {
      const user = safeUser(message ?? detail);
      if (user && !(await hasActiveSession(computer.id))) {
        await startSession(computer.id, computer.name, user);
        await db.insert(eventsTable).values({
          type: "student_login",
          message: `${user} signed in on ${computer.name}`,
          actor: user,
          computerName: computer.name,
        });
      }
      break;
    }
    case "student_logout": {
      const user = safeUser(message ?? detail);
      if (user) {
        await endActiveSessions(computer.id);
        await db.insert(eventsTable).values({
          type: "student_logout",
          message: `${user} signed out of ${computer.name}`,
          actor: user,
          computerName: computer.name,
        });
      }
      break;
    }
    case "usb_connected": {
      const [policy] = await db
        .select()
        .from(usbPoliciesTable)
        .orderBy(usbPoliciesTable.id)
        .limit(1);
      const policyMode = policy?.mode ?? "approval_required";

      const driveMatch = detail?.match(/\b([A-Za-z]):\b/);
      const driveLetter = driveMatch ? driveMatch[1].toUpperCase() : null;
      const serialMatch = detail?.match(/serial=([\w-]+)/i);
      const deviceId = serialMatch ? serialMatch[1].toLowerCase() : null;
      const instanceMatch = detail?.match(/instanceId=([^\s;()]+)/);
      const instanceId = instanceMatch ? instanceMatch[1] : null;
      const label = detail ? detail.slice(0, 120) : "Removable device";
      const status = approveByDefault(computer, policyMode) ? "approved" : "pending";

      const existing = deviceId
        ? await db
            .select()
            .from(usbDevicesTable)
            .where(
              and(
                eq(usbDevicesTable.computerId, computer.id),
                eq(usbDevicesTable.deviceId, deviceId),
              ),
            )
            .limit(1)
        : [];

      if (existing.length === 0) {
        await db.insert(usbDevicesTable).values({
          computerId: computer.id,
          computerName: computer.name,
          deviceId,
          instanceId,
          driveLetter,
          label,
          status,
          scanResult: message ?? null,
        });

        if (status === "pending") {
          await db.insert(alertsTable).values({
            severity: "warning",
            title: "USB device awaiting approval",
            detail: `Removable device connected on ${computer.name}${
              driveLetter ? ` (drive ${driveLetter}:)` : ""
            } â€” review and approve to allow use.`,
            computerName: computer.name,
            status: "open",
          });
        }

        await db.insert(eventsTable).values({
          type: status === "approved" ? "usb_connected" : "usb_blocked",
          message: `Removable device on ${computer.name}${
            driveLetter ? ` (drive ${driveLetter}:)` : ""
          }${status === "pending" ? " awaiting approval" : ""}`,
          actor: "Agent",
          computerName: computer.name,
        });
      }
      break;
    }
    case "login_failure": {
      await db.insert(alertsTable).values({
        severity: "warning",
        title: "Failed login",
        detail: detail ?? message ?? "Failed login attempt",
        computerName: computer.name,
        status: "open",
      });
      await db.insert(eventsTable).values({
        type: "login_failure",
        message: detail ?? message ?? "Failed login attempt",
        actor: "unknown",
        computerName: computer.name,
      });
      break;
    }
    case "password_change":
    case "password_reset": {
      const isReset = body.data.type === "password_reset";
      const actorMatch = detail?.match(/actor=([^\s;]+)/);
      const targetMatch = detail?.match(/target=([^\s;]+)/);
      const actor = actorMatch ? actorMatch[1] : "unknown";
      const target = targetMatch ? targetMatch[1] : null;
      const who = safeUser(message ?? null);
      await db.insert(alertsTable).values({
        severity: "warning",
        title: isReset ? "Password reset" : "Password changed",
        detail: `Account "${target ?? "?"}" ${
          isReset ? "password was reset" : "changed its own password"
        } on ${computer.name}${actor !== "unknown" ? ` by ${actor}` : ""}${
          who ? ` â€” user on the PC at the time: ${who}` : ""
        }`,
        computerName: computer.name,
        status: "open",
      });
      await db.insert(eventsTable).values({
        type: body.data.type,
        message:
          message ??
          detail ??
          `${isReset ? "Password reset" : "Password change"} on ${computer.name}`,
        actor,
        computerName: computer.name,
      });
      break;
    }
    case "autologon": {
      await db.insert(eventsTable).values({
        type: "autologon",
        message:
          message ??
          detail ??
          `Auto-login disabled at boot on ${computer.name}`,
        actor: "Agent",
        computerName: computer.name,
      });
      break;
    }
    default: {
      await db.insert(eventsTable).values({
        type: body.data.type,
        message: message ?? detail ?? body.data.type,
        actor: "Agent",
        computerName: computer.name,
      });
    }
  }

  res.json(AgentEventResponse.parse({ ok: true }));
});

/**
 * Installed-software snapshot. Separate from the heartbeat on purpose: the
 * heartbeat runs every 10 seconds and must stay small; software changes about
 * once a session at most, so the agent should send it on a slow timer.
 */
router.post("/agent/software", async (req, res): Promise<void> => {
  const body = AgentSoftwareBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.agentToken, body.data.token))
    .limit(1);
  if (!computer) {
    res.status(401).json({ error: "Invalid agent token" });
    return;
  }

  await db
    .update(computersTable)
    .set({ installedSoftware: body.data.software })
    .where(eq(computersTable.id, computer.id));

  res.json(AgentSoftwareResponse.parse({ ok: true }));
});

router.post(
  "/agent/upload",
  express.raw({ type: () => true, limit: "16mb" }),
  async (req, res): Promise<void> => {
    const token = typeof req.query.token === "string" ? req.query.token : "";
    const [computer] = await db
      .select()
      .from(computersTable)
      .where(eq(computersTable.agentToken, token))
      .limit(1);
    if (!computer) {
      res.status(401).json({ error: "Invalid agent token" });
      return;
    }
    if (!Buffer.isBuffer(req.body) || req.body.byteLength === 0) {
      res.status(400).json({ error: "Empty upload" });
      return;
    }
    const fileId = randomBytes(16).toString("hex");
    await writeFile(path.join(UPLOADS_DIR, fileId), req.body);
    res.status(201).json(AgentUploadResponse.parse({ fileId }));
  },
);

router.post(
  "/agent/screenshot",
  express.raw({ type: () => true, limit: "16mb" }),
  async (req, res): Promise<void> => {
    const token = typeof req.query.token === "string" ? req.query.token : "";
    const [computer] = await db
      .select()
      .from(computersTable)
      .where(eq(computersTable.agentToken, token))
      .limit(1);
    if (!computer) {
      res.status(401).json({ error: "Invalid agent token" });
      return;
    }
    if (!Buffer.isBuffer(req.body) || req.body.byteLength === 0) {
      res.status(400).json({ error: "Empty screenshot" });
      return;
    }

    const fileId = randomBytes(16).toString("hex");
    await writeFile(path.join(UPLOADS_DIR, fileId), req.body);

    await db
      .delete(screenshotsTable)
      .where(eq(screenshotsTable.computerId, computer.id));

    await db.insert(screenshotsTable).values({
      computerId: computer.id,
      fileId,
    });

    // Forward frame to any connected dashboards via WebSocket
    broadcastFrame(computer.id, req.body.toString("base64"));

    res.status(201).json(AgentScreenshotResponse.parse({ fileId, takenAt: new Date().toISOString() }));
  },
);

router.post("/agent/checkin", async (req, res): Promise<void> => {
  const body = AgentCheckinBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.agentToken, body.data.token))
    .limit(1);
  if (!computer) {
    res.status(401).json({ error: "Invalid agent token" });
    return;
  }

  const role = body.data.role ?? "student";

  if (role === "admin") {
    const [adminUserRow] = await db
      .select({ value: settingsTable.value })
      .from(settingsTable)
      .where(eq(settingsTable.key, "admin_windows_user"))
      .limit(1);
    const adminWindowsUser = adminUserRow?.value?.trim() ?? "";
    const suppliedName = (body.data.studentName ?? "").trim();
    if (adminWindowsUser) {
      // The agent reports the account that is actually signed in on the PC.
      // Accept it when it matches the configured Windows administrator
      // account (with or without the DOMAIN\ prefix).
      const matches =
        suppliedName.toLowerCase() === adminWindowsUser.toLowerCase() ||
        suppliedName.toLowerCase().endsWith(`\\${adminWindowsUser.toLowerCase()}`);
      if (!matches || !suppliedName) {
        res.json(
          AgentCheckinResponse.parse({
            ok: false,
            error: "This account is not the configured Windows administrator",
          }),
        );
        return;
      }
    } else {
      const [secretRow] = await db
        .select({ value: settingsTable.value })
        .from(settingsTable)
        .where(eq(settingsTable.key, "admin_gate_secret"))
        .limit(1);
      const expected = secretRow?.value ?? "";
      if (!expected) {
        res.json(AgentCheckinResponse.parse({ ok: false, error: "No administrator is configured for sign-in" }));
        return;
      }
      const supplied = body.data.adminPass ?? "";
      const suppliedUser = (body.data.adminUser ?? "").trim();
      if (!supplied || supplied !== expected) {
        res.json(AgentCheckinResponse.parse({ ok: false, error: "Invalid administrator passphrase" }));
        return;
      }
      if (!suppliedUser) {
        res.json(AgentCheckinResponse.parse({ ok: false, error: "Enter your administrator username" }));
        return;
      }
    }
  }

  const [checkin] = await db
    .insert(checkinsTable)
    .values({
      computerId: computer.id,
      computerName: computer.name,
      userName: body.data.userName ?? null,
      role,
      studentName: body.data.studentName,
      phone: body.data.phone ?? null,
      admissionNo: body.data.admissionNo ?? null,
      course: body.data.course ?? null,
      className: body.data.class ?? null,
      reason: body.data.reason ?? null,
      email: body.data.email ?? null,
      photoFileId: body.data.photoFileId ?? null,
    })
    .returning();

  await db
    .update(computersTable)
    .set({ checkinRequired: false, status: "online" })
    .where(eq(computersTable.id, computer.id));

  const roleLabel: Record<string, string> = {
    student: "checked in",
    teacher: "(teacher) signed in",
    visitor: "(visitor) signed in",
    admin: "signed in as administrator",
  };
  const verb = roleLabel[role] ?? "checked in";
  const suffix = role === "student" ? ` (${body.data.admissionNo ?? "—"})` : "";
  await db.insert(eventsTable).values({
    type: role === "admin" ? "admin_checkin" : "checkin",
    message: `${body.data.studentName} ${verb} on ${computer.name}${suffix}`,
    actor: body.data.studentName,
    computerName: computer.name,
  });

  res.json(AgentCheckinResponse.parse({ ok: true, checkinId: checkin.id }));
});

router.get("/agent/files/download/:fileId", async (req, res): Promise<void> => {
  const fileId = req.params.fileId;
  const token = typeof req.query.token === "string" ? req.query.token : "";
  if (!token) {
    res.status(401).json({ error: "Missing agent token" });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.agentToken, token))
    .limit(1);
  if (!computer) {
    res.status(401).json({ error: "Invalid agent token" });
    return;
  }

  const queued = await db
    .select()
    .from(actionsTable)
    .where(
      and(
        eq(actionsTable.computerId, computer.id),
        eq(actionsTable.status, "queued"),
      ),
    );

  let fileName = "file";
  let matched = false;
  for (const action of queued) {
    try {
      const payload = JSON.parse(action.payload ?? "{}") as Record<string, unknown>;
      if (payload.fileId === fileId) {
        matched = true;
        if (typeof payload.fileName === "string") fileName = payload.fileName;
        break;
      }
    } catch {
      // ignore malformed payloads
    }
  }
  if (!matched) {
    res.status(404).json({ error: "File not found" });
    return;
  }

  const filePath = path.join(UPLOADS_DIR, fileId);
  if (!existsSync(filePath)) {
    res.status(404).json({ error: "File no longer available" });
    return;
  }

  res.download(filePath, fileName);
});

router.get("/agent/download", (_req, res): void => {
  if (!existsSync(AGENT_SCRIPT_PATH)) {
    res.status(404).json({ error: "Agent script is not bundled with this build" });
    return;
  }
  res.download(AGENT_SCRIPT_PATH, "lab-agent.ps1");
});

// Linux agent (Ubuntu/Debian VPSes — Contabo & co) — same protocol, same
// dashboard. Served so a VPS can install with a one-liner.
router.get("/agent/download-linux", (_req, res): void => {
  if (!existsSync(AGENT_LINUX_SCRIPT_PATH)) {
    res.status(404).json({ error: "Linux agent is not bundled with this build" });
    return;
  }
  res.download(AGENT_LINUX_SCRIPT_PATH, "lab-agent-linux.py");
});

export default router;
