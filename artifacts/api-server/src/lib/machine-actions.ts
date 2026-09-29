import { sql } from "drizzle-orm";
import {
  actionsTable,
  computersTable,
  eventsTable,
  type TenantDbShape,
} from "@workspace/db";

// ---------------------------------------------------------------------------
// Shared operator-action pipeline for lab computers.
//
// Both the tenant lab routes (/t/:slug/api/lab/computers/:id/actions) and the
// Super Admin platform-wide machine routes (/api/admin/machines/...) funnel
// through queueMachineAction() so locking, wake-relay, USB toggles and the
// audit event write behave identically regardless of which dashboard
// initiated them.
// ---------------------------------------------------------------------------

const REMOTE_VIEW_TTL_MS = 45_000;

const iso = (value: Date | string | null | undefined) =>
  value instanceof Date ? value.toISOString() : value ?? null;

export interface QueueMachineActionArgs {
  action: string;
  message?: string | null;
  payload?: string | null;
  actor: string;
}

export interface QueuedAction {
  id: number;
  computerId: number;
  action: string;
  status: "queued" | "sent" | "acknowledged" | "failed";
  message: string | null;
  createdAt: string;
}

export interface MachineActionOutcome {
  ok: boolean;
  httpStatus: number;
  error?: string;
  queued?: QueuedAction;
}

const rotatePayloadError =
  'server_url_rotate requires a { "url": "https://…" } JSON payload';

export async function queueMachineAction(
  // The tenant-scoped drizzle instance the computer lives in (a schema with
  // lab_computers / actions / events).
  tenantDb: TenantDbShape,
  computer: {
    id: number;
    name: string;
    room: string;
    status: string;
    macAddress: string | null;
  },
  args: QueueMachineActionArgs,
): Promise<MachineActionOutcome> {
  const { action, message, payload, actor } = args;

  // server_url_rotate points the agent at a different deployment of this same
  // app (see docs/RENDER-RENAME.md). Only reachable from the tenant path —
  // the platform-wide admin route restricts its own action set.
  if (action === "server_url_rotate") {
    let parsed: { url?: unknown } | null = null;
    try {
      parsed = payload ? (JSON.parse(payload) as { url?: unknown }) : null;
    } catch {
      return { ok: false, httpStatus: 400, error: rotatePayloadError };
    }
    const candidate = typeof parsed?.url === "string" ? parsed.url : null;
    if (!candidate) {
      return { ok: false, httpStatus: 400, error: rotatePayloadError };
    }
    try {
      const target = new URL(candidate);
      if (target.protocol !== "https:") {
        return {
          ok: false,
          httpStatus: 400,
          error: "server_url_rotate only accepts https URLs",
        };
      }
      if (target.username || target.password) {
        return {
          ok: false,
          httpStatus: 400,
          error: "server_url_rotate URLs must not contain credentials",
        };
      }
    } catch {
      return {
        ok: false,
        httpStatus: 400,
        error: "server_url_rotate requires a valid absolute URL",
      };
    }
  }

  if (action === "wake") {
    if (!computer.macAddress) {
      return {
        ok: false,
        httpStatus: 400,
        error: `${computer.name} has not reported a MAC address yet, so Wake-on-LAN cannot be sent.`,
      };
    }
    const relayPool = await tenantDb
      .select()
      .from(computersTable)
      .where(
        sql`${computersTable.status} = 'online' AND ${computersTable.lastSeen} > now() - interval '90 seconds' AND ${computersTable.id} <> ${computer.id}`,
      )
      .orderBy(sql`${computersTable.room} = ${computer.room} DESC`);
    const relay = relayPool[0];
    if (!relay) {
      return {
        ok: false,
        httpStatus: 400,
        error:
          "No online computer on the same network is available to relay the wake packet.",
      };
    }
    const [relayAction] = await tenantDb
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

    await tenantDb.insert(eventsTable).values({
      type: "operator_action",
      message: `Wake-on-LAN requested for ${computer.name} and relayed through ${relay.name}`,
      actor,
      computerName: computer.name,
    });

    return {
      ok: true,
      httpStatus: 201,
      queued: {
        id: relayAction.id,
        computerId: computer.id,
        action: "wake",
        status: relayAction.status as QueuedAction["status"],
        message: `Wake-on-LAN relayed via ${relay.name}`,
        createdAt: iso(relayAction.createdAt) as string,
      },
    };
  }

  const [queued] = await tenantDb
    .insert(actionsTable)
    .values({
      computerId: computer.id,
      action,
      message: message ?? null,
      payload: payload ?? null,
      status: "queued",
    })
    .returning();

  // Keep a remote view/control session alive while the operator watches or
  // controls the PC. It expires on its own shortly after the last remote
  // action.
  if (action === "remote_view" || action === "remote_input") {
    await tenantDb
      .update(computersTable)
      .set({ remoteViewUntil: new Date(Date.now() + REMOTE_VIEW_TTL_MS) })
      .where(sql`${computersTable.id} = ${computer.id}`);
  }

  if (action === "lock") {
    await tenantDb
      .update(computersTable)
      .set({ status: "locked", checkinRequired: true })
      .where(sql`${computersTable.id} = ${computer.id}`);
  } else if (action === "unlock") {
    await tenantDb
      .update(computersTable)
      .set({ status: "online", checkinRequired: false })
      .where(sql`${computersTable.id} = ${computer.id}`);
  } else if (action === "block_usb") {
    await tenantDb
      .update(computersTable)
      .set({ usbState: "blocked" })
      .where(sql`${computersTable.id} = ${computer.id}`);
  } else if (action === "allow_usb") {
    await tenantDb
      .update(computersTable)
      .set({ usbState: "allowed" })
      .where(sql`${computersTable.id} = ${computer.id}`);
  }

  await tenantDb.insert(eventsTable).values({
    type: "operator_action",
    message: `${action.replaceAll("_", " ")} queued for ${computer.name}`,
    actor,
    computerName: computer.name,
  });

  return {
    ok: true,
    httpStatus: 201,
    queued: {
      id: queued.id,
      computerId: computer.id,
      action,
      status: queued.status as QueuedAction["status"],
      message: queued.message ?? null,
      createdAt: iso(queued.createdAt) as string,
    },
  };
}