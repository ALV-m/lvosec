import { Router, type IRouter } from "express";
import { and, desc, eq, sql } from "drizzle-orm";
import express from "express";
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { db } from "@workspace/db";
import {
  actionsTable,
  alertsTable,
  computersTable,
  eventsTable,
  studentSessionsTable,
  usbPoliciesTable,
} from "@workspace/db";
import {
  CreateComputerActionBody,
  CreateComputerActionParams,
  CreateComputerActionResponse,
  CreateStudentSessionBody,
  CreateStudentSessionResponse,
  GetComputersResponse,
  GetLabAlertsResponse,
  GetLabEventsResponse,
  GetLabSummaryResponse,
  GetStudentSessionsResponse,
  GetUsbPoliciesResponse,
  PushFileParams,
  PushFileResponse,
  SetComputerUsbModeBody,
  SetComputerUsbModeParams,
  SetComputerUsbModeResponse,
  UpdateLabAlertBody,
  UpdateLabAlertParams,
  UpdateLabAlertResponse,
  UpdateUsbPolicyBody,
  UpdateUsbPolicyResponse,
} from "@workspace/api-zod";

const router: IRouter = Router();

const REMOTE_VIEW_TTL_MS = 45_000;

const UPLOADS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "data",
  "uploads",
);

await mkdir(UPLOADS_DIR, { recursive: true });

const iso = (value: Date | string | null | undefined) =>
  value instanceof Date ? value.toISOString() : value ?? null;

const mapComputer = (computer: typeof computersTable.$inferSelect) => ({
  id: computer.id,
  name: computer.name,
  room: computer.room,
  status: computer.status,
  userName: computer.userName,
  lastSeen: iso(computer.lastSeen) as string,
  os: computer.os,
  agentVersion: computer.agentVersion,
  usbState: computer.usbState,
  peripherals: { keyboard: computer.keyboard, mouse: computer.mouse },
  avEnabled: computer.avEnabled,
  avSignature: computer.avSignature,
  avLastScanAt: iso(computer.avLastScanAt),
  avScanState: computer.avScanState,
  firewallEnabled: computer.firewallEnabled,
  firewallProfiles: computer.firewallProfiles,
  manufacturer: computer.manufacturer,
  model: computer.model,
  serialNumber: computer.serialNumber,
  biosSerial: computer.biosSerial,
  systemUUID: computer.systemUUID,
  totalRAM: computer.totalRAM,
  cpuName: computer.cpuName,
  cpuCores: computer.cpuCores,
  ipAddress: computer.ipAddress,
  macAddress: computer.macAddress,
});

const mapAlert = (alert: typeof alertsTable.$inferSelect) => ({
  ...alert,
  createdAt: iso(alert.createdAt) as string,
});

router.get("/lab/summary", async (_req, res): Promise<void> => {
  const [computers, sessions, alerts, events] = await Promise.all([
    db.select().from(computersTable),
    db.select().from(studentSessionsTable),
    db.select().from(alertsTable),
    db.select().from(eventsTable),
  ]);

  res.json(
    GetLabSummaryResponse.parse({
      totalComputers: computers.length,
      onlineComputers: computers.filter((computer) => computer.status === "online").length,
      activeSessions: sessions.filter((session) => session.status === "active").length,
      openAlerts: alerts.filter((alert) => alert.status === "open").length,
      blockedUsbEvents: events.filter((event) => event.type === "usb_blocked").length,
      lastSyncAt: new Date().toISOString(),
    }),
  );
});

router.get("/lab/computers", async (_req, res): Promise<void> => {
  const computers = await db.select().from(computersTable).orderBy(computersTable.name);
  res.json(GetComputersResponse.parse(computers.map(mapComputer)));
});

router.post("/lab/computers/:computerId/actions", async (req, res): Promise<void> => {
  const params = CreateComputerActionParams.safeParse(req.params);
  const body = CreateComputerActionBody.safeParse(req.body);
  if (!params.success || !body.success) {
    res.status(400).json({ error: "Invalid computer action" });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.id, params.data.computerId))
    .limit(1);
  if (!computer) {
    res.status(404).json({ error: "Computer not found" });
    return;
  }

  // server_url_rotate points the agent at a different deployment of this same
  // app. It is the mechanism behind the Render service rename (see
  // docs/RENDER-RENAME.md) and must be belt-and-braces validated: an https URL
  // without credentials, nothing else. The agent independently probes the new
  // server's health endpoint before committing, so a typo here is caught
  // twice — once at queue time, once at execution.
  if (body.data.action === "server_url_rotate") {
    let payload: { url?: unknown } | null = null;
    try {
      payload = body.data.payload ? (JSON.parse(body.data.payload) as { url?: unknown }) : null;
    } catch {
      res.status(400).json({ error: "server_url_rotate requires a { \"url\": \"https://…\" } JSON payload" });
      return;
    }
    const candidate = typeof payload?.url === "string" ? payload.url : null;
    if (!candidate) {
      res.status(400).json({ error: "server_url_rotate requires a { \"url\": \"https://…\" } JSON payload" });
      return;
    }
    try {
      const target = new URL(candidate);
      if (target.protocol !== "https:") {
        res.status(400).json({ error: "server_url_rotate only accepts https URLs" });
        return;
      }
      if (target.username || target.password) {
        res.status(400).json({ error: "server_url_rotate URLs must not contain credentials" });
        return;
      }
    } catch {
      res.status(400).json({ error: "server_url_rotate requires a valid absolute URL" });
      return;
    }
  }

  if (body.data.action === "wake") {
    if (!computer.macAddress) {
      res.status(400).json({
        error: `${computer.name} has not reported a MAC address yet, so Wake-on-LAN cannot be sent.`,
      });
      return;
    }
    const relayPool = await db
      .select()
      .from(computersTable)
      .where(sql`${computersTable.status} = 'online' AND ${computersTable.lastSeen} > now() - interval '90 seconds' AND ${computersTable.id} <> ${computer.id}`)
      .orderBy(sql`${computersTable.room} = ${computer.room} DESC`);
    const relay = relayPool[0];
    if (!relay) {
      res.status(400).json({
        error: "No online computer on the same network is available to relay the wake packet.",
      });
      return;
    }
    const [relayAction] = await db
      .insert(actionsTable)
      .values({
        computerId: relay.id,
        action: "wol_relay",
        message: `Wake ${computer.name} via ${relay.name}`,
        payload: JSON.stringify({
          targetMac: computer.macAddress,
          targetComputerId: computer.id,
          targetName: computer.name,
        }),
        status: "queued",
      })
      .returning();

    await db.insert(eventsTable).values({
      type: "operator_action",
      message: `Wake-on-LAN requested for ${computer.name} and relayed through ${relay.name}`,
      actor: "Lab administrator",
      computerName: computer.name,
    });

    res.status(201).json(
      CreateComputerActionResponse.parse({
        id: relayAction.id,
        computerId: computer.id,
        action: "wake",
        status: "queued",
        message: `Wake-on-LAN relayed via ${relay.name}`,
        createdAt: iso(relayAction.createdAt),
      }),
    );
    return;
  }

  const [action] = await db
    .insert(actionsTable)
    .values({
      computerId: params.data.computerId,
      action: body.data.action,
      message: body.data.message ?? null,
      payload: body.data.payload ?? null,
      status: "queued",
    })
    .returning();

  // Keep a remote view/control session alive so the agent keeps streaming
  // screenshots and polls fast while the operator is looking at / controlling
  // the PC. It expires on its own shortly after the last remote action.
  if (body.data.action === "remote_view" || body.data.action === "remote_input") {
    await db
      .update(computersTable)
      .set({ remoteViewUntil: new Date(Date.now() + REMOTE_VIEW_TTL_MS) })
      .where(eq(computersTable.id, params.data.computerId));
  }

  if (body.data.action === "lock") {
    await db.update(computersTable).set({ status: "locked", checkinRequired: true }).where(eq(computersTable.id, params.data.computerId));
  } else if (body.data.action === "unlock") {
    await db.update(computersTable).set({ status: "online", checkinRequired: false }).where(eq(computersTable.id, params.data.computerId));
  } else if (body.data.action === "block_usb") {
    await db.update(computersTable).set({ usbState: "blocked" }).where(eq(computersTable.id, params.data.computerId));
  } else if (body.data.action === "allow_usb") {
    await db.update(computersTable).set({ usbState: "allowed" }).where(eq(computersTable.id, params.data.computerId));
  }

  await db.insert(eventsTable).values({
    type: "operator_action",
    message: `${body.data.action.replaceAll("_", " ")} queued for ${computer.name}`,
    actor: "Lab administrator",
    computerName: computer.name,
  });

  res.status(201).json(
    CreateComputerActionResponse.parse({
      ...action,
      createdAt: iso(action.createdAt),
    }),
  );
});

router.post(
  "/lab/computers/:computerId/files",
  express.raw({ type: () => true, limit: "64mb" }),
  async (req, res): Promise<void> => {
    const params = PushFileParams.safeParse(req.params);
    if (!params.success || !Buffer.isBuffer(req.body)) {
      res.status(400).json({ error: "Invalid upload" });
      return;
    }

    const [computer] = await db
      .select()
      .from(computersTable)
      .where(eq(computersTable.id, params.data.computerId))
      .limit(1);
    if (!computer) {
      res.status(404).json({ error: "Computer not found" });
      return;
    }

    const rawName = typeof req.headers["x-file-name"] === "string" ? req.headers["x-file-name"] : "";
    let fileName = "file.bin";
    try {
      const decoded = decodeURIComponent(rawName).trim();
      if (decoded) fileName = decoded;
    } catch {
      // fall back to the default name
    }
    const safeName = path.basename(fileName);

    const fileId = randomUUID();
    await writeFile(path.join(UPLOADS_DIR, fileId), req.body);
    const size = req.body.byteLength;

    const [action] = await db
      .insert(actionsTable)
      .values({
        computerId: computer.id,
        action: "push_file",
        message: `Push file "${safeName}" to ${computer.name}`,
        payload: JSON.stringify({ fileId, fileName: safeName, size }),
        status: "queued",
      })
      .returning();

    await db.insert(eventsTable).values({
      type: "operator_action",
      message: `File "${safeName}" (${size} bytes) queued for ${computer.name}`,
      actor: "Lab administrator",
      computerName: computer.name,
    });

    res.status(201).json(
      PushFileResponse.parse({ actionId: action.id, fileName: safeName, size }),
    );
  },
);

router.get("/lab/alerts", async (_req, res): Promise<void> => {
  const alerts = await db.select().from(alertsTable).orderBy(desc(alertsTable.createdAt));
  res.json(GetLabAlertsResponse.parse(alerts.map(mapAlert)));
});

router.patch("/lab/alerts/:alertId", async (req, res): Promise<void> => {
  const params = UpdateLabAlertParams.safeParse(req.params);
  const body = UpdateLabAlertBody.safeParse(req.body);
  if (!params.success || !body.success) {
    res.status(400).json({ error: "Invalid alert update" });
    return;
  }

  const [alert] = await db
    .update(alertsTable)
    .set({ status: body.data.status })
    .where(eq(alertsTable.id, params.data.alertId))
    .returning();
  if (!alert) {
    res.status(404).json({ error: "Alert not found" });
    return;
  }
  res.json(UpdateLabAlertResponse.parse(mapAlert(alert)));
});

router.get("/lab/usb-policies", async (_req, res): Promise<void> => {
  const policies = await db.select().from(usbPoliciesTable).orderBy(desc(usbPoliciesTable.updatedAt));
  res.json(
    GetUsbPoliciesResponse.parse(
      policies.map((policy) => ({
        ...policy,
        computerIds: policy.computerIds ?? undefined,
        updatedAt: iso(policy.updatedAt) as string,
      })),
    ),
  );
});

router.patch("/lab/usb-policies", async (req, res): Promise<void> => {
  const body = UpdateUsbPolicyBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: "Invalid USB policy" });
    return;
  }

  const [current] = await db.select().from(usbPoliciesTable).orderBy(usbPoliciesTable.id).limit(1);
  const [policy] = current
    ? await db
        .update(usbPoliciesTable)
        .set({
          mode: body.data.mode,
          scope: body.data.scope,
          computerIds: body.data.computerIds ?? null,
          updatedAt: new Date(),
        })
        .where(eq(usbPoliciesTable.id, current.id))
        .returning()
    : await db
        .insert(usbPoliciesTable)
        .values({
          name: "Default removable media policy",
          description: "Controls flash drives, phones, and other removable storage in the lab.",
          mode: body.data.mode,
          scope: body.data.scope,
          computerIds: body.data.computerIds ?? null,
        })
        .returning();

  if (body.data.scope === "all") {
    await db.update(computersTable).set({ usbState: body.data.mode === "allowed" ? "allowed" : "blocked" });
  }

  await db.insert(eventsTable).values({
    type: "usb_policy_change",
    message: `USB policy set to ${body.data.mode} for ${body.data.scope === "all" ? "all computers" : "selected computers"}`,
    actor: "Lab administrator",
  });

  res.json(
    UpdateUsbPolicyResponse.parse({
      ...policy,
      computerIds: policy.computerIds ?? undefined,
      updatedAt: iso(policy.updatedAt),
    }),
  );
});

router.get("/lab/student-sessions", async (_req, res): Promise<void> => {
  const sessions = await db.select().from(studentSessionsTable).orderBy(desc(studentSessionsTable.startedAt));
  res.json(
    GetStudentSessionsResponse.parse(
      sessions.map((session) => ({
        ...session,
        startedAt: iso(session.startedAt),
        endedAt: iso(session.endedAt),
      })),
    ),
  );
});

router.post("/lab/student-sessions", async (req, res): Promise<void> => {
  const body = CreateStudentSessionBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }
  const [computer] = await db.select().from(computersTable).where(eq(computersTable.id, body.data.computerId));
  if (!computer) {
    res.status(404).json({ error: "Computer not found" });
    return;
  }
  const [session] = await db
    .insert(studentSessionsTable)
    .values({
      studentName: body.data.studentName,
      studentId: body.data.studentId,
      computerId: computer.id,
      computerName: computer.name,
      status: "active",
    })
    .returning();
  await db
    .update(computersTable)
    .set({ userName: body.data.studentName })
    .where(eq(computersTable.id, computer.id));
  await db.insert(eventsTable).values({
    type: "student_login",
    message: `${body.data.studentName} signed in on ${computer.name}`,
    actor: body.data.studentName,
  });
  res.status(201).json(
    CreateStudentSessionResponse.parse({
      ...session,
      startedAt: iso(session.startedAt),
      endedAt: iso(session.endedAt),
    }),
  );
});

router.get("/lab/events", async (_req, res): Promise<void> => {
  const events = await db.select().from(eventsTable).orderBy(desc(eventsTable.createdAt)).limit(50);
  res.json(
    GetLabEventsResponse.parse(
      events.map((event) => ({ ...event, createdAt: iso(event.createdAt) as string })),
    ),
  );
});

router.put("/lab/computers/:computerId/usb-mode", async (req, res): Promise<void> => {
  const params = SetComputerUsbModeParams.safeParse(req.params);
  const body = SetComputerUsbModeBody.safeParse(req.body);
  if (!params.success || !body.success) {
    res.status(400).json({ error: "Invalid USB mode" });
    return;
  }

  const [computer] = await db
    .select()
    .from(computersTable)
    .where(eq(computersTable.id, params.data.computerId))
    .limit(1);
  if (!computer) {
    res.status(404).json({ error: "Computer not found" });
    return;
  }

  const [updated] = await db
    .update(computersTable)
    .set({ usbState: body.data.mode })
    .where(eq(computersTable.id, computer.id))
    .returning();

  await db.insert(eventsTable).values({
    type: "usb_policy_change",
    message: `USB mode for ${computer.name} set to ${body.data.mode}`,
    actor: "Lab administrator",
    computerName: computer.name,
  });

  res.json(
    SetComputerUsbModeResponse.parse({
      computerId: updated.id,
      usbState: updated.usbState,
    }),
  );
});

router.get("/lab/computers/:computerId/rdp", async (req, res): Promise<void> => {
  const computerId = Number(req.params.computerId);
  if (!Number.isFinite(computerId) || computerId <= 0) {
    res.status(400).json({ error: "Invalid computer ID" });
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

  const ip = computer.ipAddress;
  if (!ip) {
    res.status(400).json({ error: "Computer IP address unknown; agent must connect first." });
    return;
  }

  const rdpContent = [
    "screen mode id:i:2",
    "use multimon:i:0",
    "desktopwidth:i:1920",
    "desktopheight:i:1080",
    "session bpp:i:32",
    "winposv:i:0,1,0,0,1920,1080",
    "compression:i:1",
    "keyboardhook:i:2",
    "audiocapturemode:i:0",
    "videoplaybackmode:i:1",
    "connection type:i:7",
    "networkautodetect:i:1",
    "bandwidthautodetect:i:1",
    `displayconnectionbar:i:1`,
    `full address:s:${ip}:3389`,
    `alternate full address:s:${ip}:3389`,
    `username:s:${computer.userName ?? ""}`,
    "prompt for credentials:i:1",
    "negotiate security layer:i:1",
    "autoreconnection enabled:i:1",
    "authentication level:i:2",
    "prompt for credentials on client:i:1",
    "servername:s:",
    "gatewayhostname:s:",
    "gatewayusagemethod:i:4",
    "gatewaycredentialssource:i:4",
    "gatewayprofileusagemethod:i:0",
    "use redirection server name:i:0",
    "rdgiskdcproxy:i:0",
    "kdcproxyname:s:",
    `drivestoredirect:s:`,
    "drivestoredirect:s:",
  ].join("\r\n");

  res.setHeader("Content-Type", "application/x-rdp");
  res.setHeader("Content-Disposition", `attachment; filename="${computer.name}.rdp"`);
  res.send(rdpContent);
});

export default router;
