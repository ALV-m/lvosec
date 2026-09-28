import { WebSocketServer, WebSocket } from "ws";
import { STATUS_CODES, type IncomingMessage, type Server } from "node:http";
import type { Duplex } from "node:stream";
import type { RawData } from "ws";
import { and, eq } from "drizzle-orm";
import {
  actionsTable,
  computersTable,
  createTenantDb,
  db,
  eventsTable,
  pool,
  runInTenant,
  schemaNameFor,
  tenantContext,
} from "@workspace/db";
import {
  hasSubmenuAccess,
  resolveSessionFromCookieHeader,
  type AuthUser,
} from "./auth";
import { getTenantBySlugPublic } from "./tenant";
import { logger } from "./logger";

// ---------------------------------------------------------------------------
// WebSocket tunnel — bridges dashboard ↔ agent for real-time remote view.
//
// SECURITY: this endpoint drives remote keyboard/mouse control and destructive
// actions (restart, file delete, RDP disable) on lab PCs, so it is an
// authentication boundary. It is attached to the raw http.Server, which means
// upgrade requests never pass through Express middleware — the session checks
// below are the ONLY thing guarding it. Every connection must authenticate
// before it can send or receive anything.
//
// Endpoint: /t/:slug/ws/tunnel?role=...&computerId=...
//   The tenant slug is part of the path (matching the agent's own ServerUrl and
//   the HTTP /t/:slug/api layout) so the socket can be scoped to one tenant's
//   Postgres schema. A bare /ws/tunnel is rejected outright.
//
// Protocol (JSON messages over WS):
//
//   Dashboard → Server:
//     { type: "start_view" }
//     { type: "stop_view" }
//     { type: "input", payload: object }
//     { type: "set_mode", mode: "jpeg" | "h264" }
//
//   Server → Dashboard:
//     { type: "frame", data: string }         // base64 JPEG
//     { type: "status", connected: boolean }
//     { type: "input_ack", ok: boolean, detail: string }
//     { type: "error", message: string }
//
//   Binary messages: forwarded as-is (MPEG-TS chunks from agent)
// ---------------------------------------------------------------------------

/** Tenant-scoped path. The slug is required so every query can be confined. */
const WS_PATH_RE = /^\/t\/([^/]+)\/ws\/tunnel$/;

/** HTTP statuses used to refuse an upgrade. Authenticating during the upgrade
 *  means a rejected client never gets a WebSocket at all, rather than being
 *  accepted and then closed. */
const REFUSE = {
  notFound: 404,
  forbidden: 403,
  unauthenticated: 401,
  badRequest: 400,
  tooManyRequests: 429,
} as const;

/** Close codes in the private-use range (4000-4999) for cases where the socket
 *  is already established and has to be torn down. */
const CLOSE = {
  badRequest: 4000,
  badRole: 4002,
  suspended: 4003,
  notFound: 4004,
  unauthenticated: 4401,
  forbidden: 4403,
  rateLimited: 4429,
  internal: 4500,
} as const;

/** Result of authenticating an upgrade request, carried on the request object
 *  into the connection handler so credentials are never re-resolved. */
interface WsAuth {
  tenantId: number;
  role: "agent" | "dashboard";
  user?: AuthUser;
}

const WS_AUTH = Symbol.for("lvosec.wsAuth");

type AuthedRequest = IncomingMessage & { [WS_AUTH]?: WsAuth };

/** Actions a single dashboard connection may dispatch per window. Stops a
 *  compromised or looping client from flooding the agent with commands. */
const ACTION_BUDGET = 30;
const ACTION_WINDOW_MS = 10_000;

interface AgentConn {
  ws: WebSocket;
  computerId: number;
  tenantId: number;
}

interface DashboardConn {
  ws: WebSocket;
  computerId: number;
  tenantId: number;
  streaming: boolean;
  mode: "jpeg" | "h264";
  actor: string;
  actions: { count: number; resetAt: number };
}

// Keyed by tenant AND computer: computer ids restart at 1 in every tenant
// schema, so keying on computerId alone let one lab evict or hijack another
// lab's agent connection.
const agents = new Map<string, AgentConn>();
const dashboardByComputer = new Map<string, Set<DashboardConn>>();

function connKey(tenantId: number, computerId: number): string {
  return `${tenantId}:${computerId}`;
}

function sendJson(ws: WebSocket, obj: Record<string, unknown>): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function reject(ws: WebSocket, code: number, reason: string): void {
  sendJson(ws, { type: "error", message: reason });
  ws.close(code, reason);
}

/** Runs `fn` against the tenant's Postgres schema on a dedicated pooled
 *  connection, mirroring `tenantContextMiddleware` but scoped to one message
 *  instead of one HTTP request. The connection is always returned with a clean
 *  search_path so a tenant context can never leak to the next borrower. */
async function withTenant<T>(tenantId: number, fn: () => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query(`SET search_path TO "${schemaNameFor(tenantId)}"`);
    return await runInTenant({ db: createTenantDb(client), tenantId }, fn);
  } finally {
    await client.query("SET search_path TO public").catch(() => {});
    client.release();
  }
}

function sendToAgent(tenantId: number, computerId: number, obj: Record<string, unknown>): void {
  const agent = agents.get(connKey(tenantId, computerId));
  if (agent) sendJson(agent.ws, obj);
}

function broadcastToDashboards(
  tenantId: number,
  computerId: number,
  obj: Record<string, unknown>,
): void {
  const set = dashboardByComputer.get(connKey(tenantId, computerId));
  if (!set) return;
  for (const d of set) {
    sendJson(d.ws, obj);
  }
}

export function broadcastFrame(computerId: number, base64Data: string): void {
  // Called from the agent upload route, which always runs inside a tenant
  // request context. Refuse rather than guess if that ever stops being true.
  const tenantId = tenantContext.getStore()?.tenantId;
  if (tenantId == null) {
    logger.warn({ computerId }, "broadcastFrame called without a tenant context; dropping frame");
    return;
  }
  const set = dashboardByComputer.get(connKey(tenantId, computerId));
  if (!set || set.size === 0) return;
  const msg = JSON.stringify({ type: "frame", data: base64Data });
  for (const d of set) {
    if (d.ws.readyState === WebSocket.OPEN && d.streaming && d.mode === "jpeg") {
      d.ws.send(msg);
    }
  }
}

function broadcastBinary(tenantId: number, computerId: number, data: Buffer): void {
  const set = dashboardByComputer.get(connKey(tenantId, computerId));
  if (!set || set.size === 0) return;
  for (const d of set) {
    if (d.ws.readyState === WebSocket.OPEN && d.streaming && d.mode === "h264") {
      d.ws.send(data);
    }
  }
}

function notifyDashboardsStatus(tenantId: number, computerId: number): void {
  const connected = agents.has(connKey(tenantId, computerId));
  const set = dashboardByComputer.get(connKey(tenantId, computerId));
  if (!set) return;
  for (const d of set) {
    sendJson(d.ws, { type: "status", connected });
  }
}

/** Writes a minimal HTTP error response and tears the socket down, so a failed
 *  authentication never results in an established WebSocket. */
function refuseUpgrade(socket: Duplex, status: number, message: string): void {
  const body = JSON.stringify({ error: message });
  try {
    socket.write(
      `HTTP/1.1 ${status} ${STATUS_CODES[status] ?? "Error"}\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${Buffer.byteLength(body)}\r\n` +
        `Connection: close\r\n` +
        `\r\n${body}`,
    );
  } catch {
    // Socket already gone; nothing to do.
  }
  socket.destroy();
}

export function attachWebSocket(server: Server): void {
  // noServer + a manual `upgrade` listener (rather than the `path` option)
  // because authentication is async and has to happen before the handshake.
  // `path` also matched exactly, which silently rejected every agent (it
  // connects to /t/:slug/ws/tunnel, not /ws/tunnel).
  const wss = new WebSocketServer({ noServer: true });

  server.on("upgrade", (req, socket, head) => {
    const pathname = (req.url ?? "/").split("?")[0];
    if (!WS_PATH_RE.test(pathname)) return; // not ours; leave it alone

    void authenticateUpgrade(req as AuthedRequest)
      .then((auth) => {
        if (!auth.ok) {
          logger.warn(
            { url: pathname, reason: auth.message },
            "Refused WebSocket upgrade",
          );
          refuseUpgrade(socket, auth.status, auth.message);
          return;
        }
        wss.handleUpgrade(req, socket, head, (ws) => {
          wss.emit("connection", ws, req, auth.value);
        });
      })
      .catch((err) => {
        logger.error({ err }, "WebSocket upgrade authentication failed");
        refuseUpgrade(socket, REFUSE.unauthenticated, "Authentication failed");
      });
  });

  wss.on("connection", (ws: WebSocket, req: AuthedRequest, auth: WsAuth) => {
    if (auth.role === "dashboard") {
      void handleDashboardConnection(ws, req, auth).catch((err) => {
        logger.error({ err }, "Dashboard WebSocket setup failed");
        reject(ws, CLOSE.internal, "Internal error");
      });
      return;
    }
    handleAgentConnection(ws, req, auth);
  });

  wss.on("error", (err) => {
    logger.warn({ err }, "WebSocket server error");
  });

  logger.info("WebSocket tunnel attached at /t/:slug/ws/tunnel (authenticated)");
}

type UpgradeDecision =
  | { ok: true; value: WsAuth }
  | { ok: false; status: number; message: string };

/** Validates the upgrade request: tenant exists and is active, the role is
 *  known, and the caller presented valid credentials for that tenant. */
async function authenticateUpgrade(req: AuthedRequest): Promise<UpgradeDecision> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const slug = WS_PATH_RE.exec(url.pathname)?.[1];
  if (!slug) {
    return { ok: false, status: REFUSE.badRequest, message: "Unknown tunnel path" };
  }

  // The session and agent token both live in the tenant schema, so the tenant
  // has to be resolved before anything can be verified.
  const tenant = await getTenantBySlugPublic(slug);
  if (!tenant) {
    return { ok: false, status: REFUSE.notFound, message: "Unknown lab" };
  }
  if (tenant.status !== "active") {
    return { ok: false, status: REFUSE.forbidden, message: "This lab account is suspended" };
  }

  const role = url.searchParams.get("role");
  if (role !== "agent" && role !== "dashboard") {
    return { ok: false, status: REFUSE.badRequest, message: "Unknown role" };
  }

  if (role === "dashboard") {
    const computerId = Number(url.searchParams.get("computerId"));
    if (!Number.isInteger(computerId) || computerId <= 0) {
      return { ok: false, status: REFUSE.badRequest, message: "Missing or invalid computerId" };
    }
    const user = await withTenant(tenant.id, () =>
      resolveSessionFromCookieHeader(req.headers.cookie),
    );
    if (!user) {
      return { ok: false, status: REFUSE.unauthenticated, message: "Authentication required" };
    }
    // Remote control lives under the "computers" submenu, so honour the same
    // per-submenu grants the HTTP routes enforce.
    if (!hasSubmenuAccess(user, "computers")) {
      return {
        ok: false,
        status: REFUSE.forbidden,
        message: "You do not have access to computer control",
      };
    }
    // The computer must exist in THIS tenant's schema. Combined with the
    // slug-derived tenant, this is what stops one lab watching another's PCs.
    const exists = await withTenant(tenant.id, async () => {
      const [row] = await db
        .select({ id: computersTable.id })
        .from(computersTable)
        .where(eq(computersTable.id, computerId))
        .limit(1);
      return Boolean(row);
    });
    if (!exists) {
      return { ok: false, status: REFUSE.notFound, message: "Unknown computer" };
    }
    return { ok: true, value: { tenantId: tenant.id, role, user } };
  }

  // Agent: reject an unknown token before the handshake. The computerId is not
  // known yet (the agent sends it in the first `hello` frame), so this only
  // proves the token belongs to some machine in this tenant; the exact pairing
  // is re-checked at hello time.
  const token = agentTokenFrom(req);
  if (!token) {
    return { ok: false, status: REFUSE.unauthenticated, message: "Agent token required" };
  }
  const known = await withTenant(tenant.id, async () => {
    const [row] = await db
      .select({ id: computersTable.id })
      .from(computersTable)
      .where(eq(computersTable.agentToken, token))
      .limit(1);
    return Boolean(row);
  });
  if (!known) {
    return { ok: false, status: REFUSE.unauthenticated, message: "Invalid agent token" };
  }
  return { ok: true, value: { tenantId: tenant.id, role } };
}

/** Header is preferred (keeps the secret out of URLs, access logs and proxy
 *  logs); the query parameter stays supported for existing agents. */
function agentTokenFrom(req: IncomingMessage): string {
  const header = req.headers["x-agent-token"];
  if (typeof header === "string" && header) return header;
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  return url.searchParams.get("token") ?? "";
}

/** Confirms `token` is the registered agent token for `computerId` inside the
 *  given tenant's schema. Returns false for unknown computers, missing tokens
 *  and mismatches alike so the caller cannot distinguish them. */
async function verifyAgentToken(
  tenantId: number,
  computerId: number,
  token: string,
): Promise<boolean> {
  if (!token) return false;
  return withTenant(tenantId, async () => {
    const [row] = await db
      .select({ id: computersTable.id })
      .from(computersTable)
      .where(
        and(
          eq(computersTable.id, computerId),
          eq(computersTable.agentToken, token),
        ),
      )
      .limit(1);
    return Boolean(row);
  });
}

function handleAgentConnection(ws: WebSocket, req: AuthedRequest, auth: WsAuth): void {
  const tenantId = auth.tenantId;
  const token = agentTokenFrom(req);

  // -1 means "not authenticated yet". Every handler below is gated on this, so
  // nothing an unauthenticated socket sends has any effect.
  let computerId = -1;

  ws.on("message", (raw: RawData, isBinary: boolean) => {
    // Binary frames = MPEG-TS chunks → forward to dashboards watching this PC.
    if (isBinary) {
      if (computerId > 0) {
        const buf = Buffer.isBuffer(raw)
          ? raw
          : Buffer.from(raw instanceof ArrayBuffer ? new Uint8Array(raw) : String(raw));
        broadcastBinary(tenantId, computerId, buf);
      }
      return;
    }

    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(String(raw));
    } catch {
      return;
    }

    if (msg.type === "hello" && typeof msg.computerId === "number") {
      if (computerId > 0) return; // already bound; ignore rebinds
      void (async () => {
        const authorised = await verifyAgentToken(tenantId, msg.computerId as number, token);
        if (!authorised) {
          logger.warn(
            { tenantId, computerId: msg.computerId },
            "Rejected WebSocket agent connection: invalid token",
          );
          reject(ws, CLOSE.unauthenticated, "Invalid agent token");
          return;
        }
        computerId = msg.computerId as number;
        const k = connKey(tenantId, computerId);
        const prev = agents.get(k);
        if (prev && prev.ws !== ws) {
          prev.ws.close(4010, "Replaced");
        }
        agents.set(k, { ws, computerId, tenantId });
        sendJson(ws, { type: "hello_ok" });
        notifyDashboardsStatus(tenantId, computerId);
        logger.info({ tenantId, computerId }, "Agent WebSocket connected");
      })().catch((err) => {
        logger.error({ err }, "Agent WebSocket handshake failed");
        reject(ws, CLOSE.internal, "Internal error");
      });
      return;
    }

    // Everything below requires a completed handshake.
    if (computerId <= 0) return;

    if (msg.type === "input_ack") {
      broadcastToDashboards(tenantId, computerId, {
        type: "input_ack",
        ok: msg.ok,
        detail: msg.detail,
      });
    }

    if (msg.type === "action_result" && typeof msg.actionId === "number") {
      const actionId = msg.actionId;
      const success = Boolean(msg.success);
      const detail = typeof msg.detail === "string" ? msg.detail : undefined;
      // Scoped to this agent's own computer so a rogue connection cannot mark
      // another machine's actions complete.
      void withTenant(tenantId, async () => {
        await db
          .update(actionsTable)
          .set({ status: success ? "completed" : "failed", detail })
          .where(
            and(
              eq(actionsTable.id, actionId),
              eq(actionsTable.computerId, computerId),
            ),
          );
        await db.insert(eventsTable).values({
          type: "action_result",
          message: success
            ? `Action ${actionId} completed on ${computerId}`
            : `Action ${actionId} failed on ${computerId}`,
          actor: `agent:${computerId}`,
          computerName: String(computerId),
        });
      })
        .then(() => {
          broadcastToDashboards(tenantId, computerId, {
            type: "action_result",
            actionId,
            action: msg.action,
            success,
            detail,
          });
        })
        .catch((err) => {
          logger.warn({ err, actionId }, "Failed to record WS action result");
        });
      logger.info(
        { tenantId, computerId, actionId, success },
        "WS action result received",
      );
    }
  });

  ws.on("close", () => {
    if (computerId > 0) {
      const k = connKey(tenantId, computerId);
      // Only drop the registration if it is still ours; a reconnect may have
      // already replaced it.
      if (agents.get(k)?.ws === ws) {
        agents.delete(k);
        notifyDashboardsStatus(tenantId, computerId);
        logger.info({ tenantId, computerId }, "Agent WebSocket disconnected");
      }
    }
  });

  ws.on("error", (err) => {
    logger.warn({ err, tenantId }, "Agent WebSocket error");
  });
}

async function handleDashboardConnection(
  ws: WebSocket,
  _req: AuthedRequest,
  auth: WsAuth,
): Promise<void> {
  // Authentication, submenu authorisation and tenant scoping all happened
  // during the upgrade (see `authenticateUpgrade`); nothing is re-checked here.
  const tenantId = auth.tenantId;
  const user = auth.user;
  if (!user) {
    reject(ws, CLOSE.unauthenticated, "Authentication required");
    return;
  }
  const computerId = Number(
    new URL(_req.url ?? "/", "http://localhost").searchParams.get("computerId"),
  );

  const conn: DashboardConn = {
    ws,
    computerId,
    tenantId,
    streaming: false,
    mode: "jpeg",
    actor: user.username,
    actions: { count: 0, resetAt: Date.now() + ACTION_WINDOW_MS },
  };

  const k = connKey(tenantId, computerId);
  let set = dashboardByComputer.get(k);
  if (!set) {
    set = new Set();
    dashboardByComputer.set(k, set);
  }
  set.add(conn);

  sendJson(ws, { type: "status", connected: agents.has(k) });
  logger.info({ tenantId, computerId, actor: user.username }, "Dashboard WebSocket connected");

  function clearRemoteView(): void {
    const anyStreaming = set ? [...set].some((d) => d.streaming) : false;
    if (anyStreaming) return;
    void withTenant(tenantId, async () => {
      await db
        .update(computersTable)
        .set({ remoteViewUntil: null })
        .where(eq(computersTable.id, computerId));
    }).catch((err) => {
      logger.warn({ err, computerId }, "Failed to clear remoteViewUntil");
    });
    sendToAgent(tenantId, computerId, { type: "stop_view" });
  }

  function allowAction(): boolean {
    const now = Date.now();
    if (now >= conn.actions.resetAt) {
      conn.actions = { count: 0, resetAt: now + ACTION_WINDOW_MS };
    }
    if (conn.actions.count >= ACTION_BUDGET) return false;
    conn.actions.count += 1;
    return true;
  }

  ws.on("message", (raw: RawData, isBinary: boolean) => {
    if (isBinary) return; // dashboards don't send binary
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(String(raw));
    } catch {
      return;
    }

    switch (msg.type) {
      case "set_mode": {
        if (msg.mode === "h264" || msg.mode === "jpeg") {
          conn.mode = msg.mode;
        }
        break;
      }

      case "start_view": {
        conn.streaming = true;
        const until = new Date(Date.now() + 120_000);
        void withTenant(tenantId, async () => {
          await db
            .update(computersTable)
            .set({ remoteViewUntil: until })
            .where(eq(computersTable.id, computerId));
        }).catch((err) => {
          logger.warn({ err, computerId }, "Failed to set remoteViewUntil");
        });
        sendToAgent(tenantId, computerId, { type: "start_view" });
        break;
      }

      case "stop_view": {
        conn.streaming = false;
        clearRemoteView();
        break;
      }

      case "input": {
        // Keyboard/mouse injection is only meaningful during an active view.
        // Without this gate a client could drive the machine blind.
        if (!conn.streaming) {
          sendJson(ws, {
            type: "error",
            message: "Start the remote view before sending input",
          });
          return;
        }
        if (!allowAction()) {
          sendJson(ws, { type: "error", message: "Too many commands; slow down" });
          ws.close(CLOSE.rateLimited, "Rate limited");
          return;
        }
        sendToAgent(tenantId, computerId, { type: "input", payload: msg.payload });
        break;
      }

      case "action": {
        const action = String(msg.action ?? "");
        if (!action) break;
        const allowedActions = new Set([
          "lock", "unlock", "restart", "send_message", "remote_view", "remote_control",
          "remote_input", "block_usb", "allow_usb", "push_file", "delete_file", "list_files",
          "av_scan", "av_update", "av_toggle", "fw_enable", "fw_disable", "disable_rdp",
        ]);
        if (!allowedActions.has(action)) {
          sendJson(ws, {
            type: "action_result",
            action: false,
            detail: `Unknown action: ${action}`,
          });
          return;
        }
        if (!allowAction()) {
          sendJson(ws, { type: "error", message: "Too many actions; slow down" });
          ws.close(CLOSE.rateLimited, "Rate limited");
          return;
        }

        const message = String(msg.message ?? `${action} requested`);
        const payload = msg.payload != null ? String(msg.payload) : null;

        void withTenant(tenantId, async () => {
          const [inserted] = await db
            .insert(actionsTable)
            .values({
              computerId,
              action: action as never,
              message,
              payload,
              status: "dispatched",
              actor: user.username,
            })
            .returning();
          // Audit trail: the socket is now the only path that can dispatch
          // actions without an HTTP row, so record it here too.
          await db.insert(eventsTable).values({
            type: "action",
            message: `${action} on ${computerId}: ${message}`,
            actor: user.username,
          });
          sendToAgent(tenantId, computerId, {
            type: "action",
            actionId: inserted.id,
            action,
            message,
            payload,
          });
          logger.info(
            { tenantId, computerId, action, actionId: inserted.id, actor: user.username },
            "WS instant action dispatched",
          );
        }).catch((err) => {
          logger.warn({ err, action }, "Failed to create instant action");
          sendJson(ws, {
            type: "action_result",
            action: false,
            detail: "Failed to queue action",
          });
        });
        break;
      }
    }
  });

  ws.on("close", () => {
    conn.streaming = false;
    set?.delete(conn);
    if (set && set.size === 0) {
      dashboardByComputer.delete(k);
    }
    if (set && set.size === 0) {
      void withTenant(tenantId, async () => {
        await db
          .update(computersTable)
          .set({ remoteViewUntil: null })
          .where(eq(computersTable.id, computerId));
      }).catch(() => {});
      sendToAgent(tenantId, computerId, { type: "stop_view" });
    }
  });

  ws.on("error", (err) => {
    logger.warn({ err, tenantId }, "Dashboard WebSocket error");
  });
}
