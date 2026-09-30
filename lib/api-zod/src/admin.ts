import * as zod from "zod";
import { CreateComputerActionResponse } from "./generated/api";
import { TenantAccount, TenantStatus } from "./tenant";

export const AdminAccount = zod.object({
  id: zod.number(),
  username: zod.string(),
  createdAt: zod.string(),
});
export type AdminAccount = zod.infer<typeof AdminAccount>;

export const AdminLoginBody = zod.object({
  username: zod.string().trim().min(1).max(100),
  password: zod.string().min(1).max(200),
});

export const AdminLoginResponse = zod.object({
  user: AdminAccount,
});

export const AdminMeResponse = zod.object({
  user: AdminAccount,
});

export const AdminLogoutResponse = zod.object({
  ok: zod.boolean(),
});

export const TenantListItem = TenantAccount.extend({
  computers: zod.number(),
  admins: zod.number(),
  superAdminUsername: zod.string().nullable(),
});
export type TenantListItem = zod.infer<typeof TenantListItem>;

export const TenantsListResponse = zod.object({
  tenants: zod.array(TenantListItem),
});

export const TenantStatusUpdateBody = zod.object({
  status: TenantStatus,
});

export const TenantAdminPasswordBody = zod.object({
  password: zod.string().min(6).max(200),
});

export const AdminOpenLabResponse = zod.object({
  path: zod.string(),
});

export const PlatformStatsResponse = zod.object({
  totalTenants: zod.number(),
  activeTenants: zod.number(),
  suspendedTenants: zod.number(),
  totalComputers: zod.number(),
  totalAdmins: zod.number(),
});

export const TenantIdParams = zod.object({
  tenantId: zod.coerce.number().int().positive(),
});

// ---------------------------------------------------------------------------
// DB Management (Super Admin): registry of Postgres connection URLs the admin
// inputs and manages under one dashboard, plus health checks and manual
// per-target snapshot pushes.
// ---------------------------------------------------------------------------

export const DbConnectionStatus = zod.enum(["unknown", "ok", "error"]);
export type DbConnectionStatus = zod.infer<typeof DbConnectionStatus>;

export const PlatformDbConnection = zod.object({
  id: zod.number(),
  name: zod.string(),
  url: zod.string(),
  note: zod.string().nullable(),
  isActive: zod.boolean(),
  status: DbConnectionStatus,
  lastCheckedAt: zod.string().nullable(),
  lastError: zod.string().nullable(),
  createdAt: zod.string(),
});
export type PlatformDbConnection = zod.infer<typeof PlatformDbConnection>;

export const DbConnectionsListResponse = zod.object({
  connections: zod.array(PlatformDbConnection),
});
export type DbConnectionsListResponse = zod.infer<typeof DbConnectionsListResponse>;

export const DbConnectionUrl = zod
  .string()
  .trim()
  .min(1)
  .max(1000)
  .refine(
    (value) => /^(postgres|postgresql):\/\//i.test(value),
    "URL must start with postgres:// or postgresql://",
  );
export type DbConnectionUrl = zod.infer<typeof DbConnectionUrl>;

export const DbConnectionCreateBody = zod.object({
  name: zod.string().trim().min(1).max(100),
  url: DbConnectionUrl,
  note: zod.string().trim().max(500).optional(),
});
export type DbConnectionCreateBody = zod.infer<typeof DbConnectionCreateBody>;
export type DbConnectionCreateInput = DbConnectionCreateBody;

export const DbConnectionUpdateBody = zod.object({
  name: zod.string().trim().min(1).max(100).optional(),
  url: DbConnectionUrl.optional(),
  note: zod.string().trim().max(500).nullable().optional(),
  isActive: zod.boolean().optional(),
});
export type DbConnectionUpdateBody = zod.infer<typeof DbConnectionUpdateBody>;

export const DbConnectionTestResponse = zod.object({
  ok: zod.boolean(),
  latencyMs: zod.number().nullable(),
  error: zod.string().nullable(),
});
export type DbConnectionTestResponse = zod.infer<typeof DbConnectionTestResponse>;

export const DbConnectionSnapshotResponse = zod.object({
  ok: zod.boolean(),
  rows: zod.number(),
  takenAt: zod.string(),
});
export type DbConnectionSnapshotResponse = zod.infer<typeof DbConnectionSnapshotResponse>;

export const DbConnectionIdParams = zod.object({
  id: zod.coerce.number().int().positive(),
});

// ---------------------------------------------------------------------------
// Platform-wide Machines (Super Admin): every tenant's computers/servers with
// network status (IP, MAC, firewall on/off, last seen) and management actions.
// ---------------------------------------------------------------------------

export const PlatformMachineKind = zod.enum(["computer", "vps"]);
export type PlatformMachineKind = zod.infer<typeof PlatformMachineKind>;

export const PlatformMachine = zod.object({
  tenantId: zod.number(),
  tenantName: zod.string(),
  tenantSlug: zod.string(),
  tenantStatus: zod.string(),
  id: zod.number(),
  name: zod.string(),
  room: zod.string(),
  status: zod.string(),
  userName: zod.string().nullable(),
  lastSeen: zod.string(),
  os: zod.string().nullable(),
  // "computer" = Windows lab machine · "vps" = Linux cloud server (lvosec
  // Linux agent). The Platform Admin dashboard protects them as separate
  // services.
  kind: PlatformMachineKind,
  agentVersion: zod.string().nullable(),
  usbState: zod.string(),
  avEnabled: zod.boolean().nullable(),
  firewallEnabled: zod.boolean().nullable(),
  firewallProfiles: zod.string().nullable(),
  ipAddress: zod.string().nullable(),
  macAddress: zod.string().nullable(),
});
export type PlatformMachine = zod.infer<typeof PlatformMachine>;

export const PlatformMachinesListResponse = zod.object({
  machines: zod.array(PlatformMachine),
});
export type PlatformMachinesListResponse = zod.infer<typeof PlatformMachinesListResponse>;

export const PlatformMachineAction = zod.enum([
  "lock",
  "unlock",
  "restart",
  "wake",
  "send_message",
  "block_usb",
  "allow_usb",
  "fw_enable",
  "fw_disable",
]);
export type PlatformMachineAction = zod.infer<typeof PlatformMachineAction>;

export const PlatformMachineActionParams = zod.object({
  tenantId: zod.coerce.number().int().positive(),
  computerId: zod.coerce.number().int().positive(),
});
export type PlatformMachineActionParams = zod.infer<typeof PlatformMachineActionParams>;

export const PlatformMachineActionBody = zod.object({
  action: PlatformMachineAction,
  message: zod.string().trim().max(500).nullish(),
  payload: zod.string().nullish(),
});
export type PlatformMachineActionBody = zod.infer<typeof PlatformMachineActionBody>;

export const PlatformMachineActionResponse = CreateComputerActionResponse;
