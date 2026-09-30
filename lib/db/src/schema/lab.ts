import { createInsertSchema } from "drizzle-zod";
import {
  bigint,
  boolean,
  integer,
  jsonb,
  pgTable,
  serial,
  text,
  timestamp,
} from "drizzle-orm/pg-core";
import { z } from "zod/v4";

export const computersTable = pgTable("lab_computers", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  room: text("room").notNull(),
  status: text("status").notNull().default("offline"),
  userName: text("user_name"),
  lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  os: text("os").notNull().default("Windows 11 Pro"),
  usbState: text("usb_state").notNull().default("blocked"),
  keyboard: boolean("keyboard").notNull().default(true),
  mouse: boolean("mouse").notNull().default(true),
  agentToken: text("agent_token"),
  agentVersion: text("agent_version"),
  avEnabled: boolean("av_enabled"),
  avSignature: text("av_signature"),
  avLastScanAt: timestamp("av_last_scan_at", { withTimezone: true }),
  avScanState: text("av_scan_state"),
  firewallEnabled: boolean("firewall_enabled"),
  firewallProfiles: text("firewall_profiles"),
  macAddress: text("mac_address"),
  ipAddress: text("ip_address"),
  checkinRequired: boolean("checkin_required").notNull().default(false),
  remoteViewUntil: timestamp("remote_view_until", { withTimezone: true }),
  manufacturer: text("manufacturer"),
  model: text("model"),
  serialNumber: text("serial_number"),
  biosSerial: text("bios_serial"),
  systemUUID: text("system_uuid"),
  totalRAM: bigint("total_ram", { mode: "number" }),
  cpuName: text("cpu_name"),
  cpuCores: integer("cpu_cores"),
  diskTotal: bigint("disk_total", { mode: "number" }),
  diskFree: bigint("disk_free", { mode: "number" }),
  // Ad-hoc security signals reported by the agent and consumed by the posture
  // engine (lib/blue-team/posture.ts). Tri-state in spirit: a missing key means
  // "not reported yet", which the engine returns as `unknown`, never `pass`.
  securitySignals: jsonb("security_signals"),
  /**
   * VPS (Linux lvosec agent) telemetry. Reported hourly on the dedicated
   * /api/agent/telemetry channel so the heartbeat stays small:
   *   - services: systemd unit list [{name, active, sub, enabled}]
   *   - packages: dpkg inventory [{name, version}]
   *   - authFailures: sshd failed-login counter {count24h, topSources}
   *   - fimState: config-integrity report {status: clean|drift, changed}
   */
  services: jsonb("services"),
  packages: jsonb("packages"),
  authFailures: jsonb("auth_failures"),
  fimState: jsonb("fim_state"),
  // Installed-software snapshot, reported by the agent on a slow timer (not on
  // every heartbeat). Shape matches SoftwareEntry (name, version, publisher).
  installedSoftware: jsonb("installed_software"),
});

export const actionsTable = pgTable("lab_actions", {
  id: serial("id").primaryKey(),
  computerId: integer("computer_id").notNull(),
  action: text("action").notNull(),
  status: text("status").notNull().default("queued"),
  message: text("message"),
  payload: text("payload"),
  detail: text("detail"),
  // Authenticated operator (or "agent:<computerId>") responsible for the action.
  // Null on rows created before audit attribution shipped.
  actor: text("actor"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const alertsTable = pgTable("lab_alerts", {
  id: serial("id").primaryKey(),
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  detail: text("detail").notNull(),
  computerName: text("computer_name").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  status: text("status").notNull().default("open"),
});

export const usbPoliciesTable = pgTable("lab_usb_policies", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  mode: text("mode").notNull().default("approval_required"),
  scope: text("scope").notNull().default("all"),
  computerIds: integer("computer_ids").array(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const studentSessionsTable = pgTable("lab_student_sessions", {
  id: serial("id").primaryKey(),
  studentName: text("student_name").notNull(),
  studentId: text("student_id").notNull(),
  computerId: integer("computer_id").notNull(),
  computerName: text("computer_name").notNull(),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  endedAt: timestamp("ended_at", { withTimezone: true }),
  status: text("status").notNull().default("active"),
});

export const eventsTable = pgTable("lab_events", {
  id: serial("id").primaryKey(),
  type: text("type").notNull(),
  message: text("message").notNull(),
  actor: text("actor").notNull(),
  computerName: text("computer_name"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const usbDevicesTable = pgTable("lab_usb_devices", {
  id: serial("id").primaryKey(),
  computerId: integer("computer_id").notNull(),
  computerName: text("computer_name").notNull(),
  deviceId: text("device_id"),
  instanceId: text("instance_id"),
  driveLetter: text("drive_letter"),
  label: text("label"),
  status: text("status").notNull().default("pending"),
  scanResult: text("scan_result"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  decidedAt: timestamp("decided_at", { withTimezone: true }),
});

export const peripheralsTable = pgTable("lab_peripherals", {
  id: serial("id").primaryKey(),
  computerId: integer("computer_id").notNull(),
  computerName: text("computer_name").notNull(),
  kind: text("kind").notNull(),
  name: text("name").notNull(),
  instanceId: text("instance_id").notNull(),
  serial: text("serial"),
  present: boolean("present").notNull().default(true),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastChangedAt: timestamp("last_changed_at", { withTimezone: true }).notNull().defaultNow(),
});

export const settingsTable = pgTable("lab_settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const scanRunsTable = pgTable("lab_scan_runs", {
  id: serial("id").primaryKey(),
  action: text("action").notNull(),
  initiatedBy: text("initiated_by").notNull(),
  status: text("status").notNull().default("queued"),
  requestedAt: timestamp("requested_at", { withTimezone: true }).notNull().defaultNow(),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
});

export const scanResultsTable = pgTable("lab_scan_results", {
  id: serial("id").primaryKey(),
  runId: integer("run_id").notNull(),
  computerId: integer("computer_id").notNull(),
  computerName: text("computer_name").notNull(),
  status: text("status").notNull().default("queued"),
  detail: text("detail"),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
});

export const fileEntriesTable = pgTable("lab_file_entries", {
  id: serial("id").primaryKey(),
  computerId: integer("computer_id").notNull(),
  path: text("path").notNull(),
  name: text("name").notNull(),
  isDir: boolean("is_dir").notNull().default(false),
  size: bigint("size", { mode: "number" }).notNull().default(0),
  modifiedAt: text("modified_at"),
  label: text("label"),
  capacity: bigint("capacity", { mode: "number" }),
  freeSpace: bigint("free_space", { mode: "number" }),
  listedAt: timestamp("listed_at", { withTimezone: true }).notNull().defaultNow(),
});

export const checkinsTable = pgTable("lab_checkins", {
  id: serial("id").primaryKey(),
  computerId: integer("computer_id").notNull(),
  computerName: text("computer_name").notNull(),
  userName: text("user_name"),
  role: text("role").notNull().default("student"),
  studentName: text("student_name").notNull(),
  phone: text("phone"),
  admissionNo: text("admission_no"),
  course: text("course"),
  className: text("class"),
  reason: text("reason"),
  email: text("email"),
  photoFileId: text("photo_file_id"),
  submittedAt: timestamp("submitted_at", { withTimezone: true }).notNull().defaultNow(),
});

export const screenshotsTable = pgTable("lab_screenshots", {
  id: serial("id").primaryKey(),
  computerId: integer("computer_id").notNull(),
  fileId: text("file_id").notNull(),
  takenAt: timestamp("taken_at", { withTimezone: true }).notNull().defaultNow(),
});

export const appUsersTable = pgTable("app_users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  role: text("role").notNull().default("admin"),
  submenuAccess: jsonb("submenu_access").notNull().default([]),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const authSessionsTable = pgTable("auth_sessions", {
  id: text("id").primaryKey(),
  userId: integer("user_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});

// ---------------------------------------------------------------------------
// Platform tables (live in the public schema, outside any tenant schema)
// ---------------------------------------------------------------------------

export const tenantsTable = pgTable("tenants", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  contactName: text("contact_name").notNull(),
  contactEmail: text("contact_email"),
  status: text("status").notNull().default("active"),
  loginToken: text("login_token"),
  loginTokenExpiresAt: timestamp("login_token_expires_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const platformUsersTable = pgTable("platform_users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const authSessionsPlatformTable = pgTable("auth_sessions_platform", {
  id: text("id").primaryKey(),
  userId: integer("user_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});

export const insertComputerSchema = createInsertSchema(computersTable).omit({ id: true });
export const insertActionSchema = createInsertSchema(actionsTable).omit({ id: true, createdAt: true });
export const insertAlertSchema = createInsertSchema(alertsTable).omit({ id: true, createdAt: true });
export const insertUsbPolicySchema = createInsertSchema(usbPoliciesTable).omit({ id: true, updatedAt: true });
export const insertStudentSessionSchema = createInsertSchema(studentSessionsTable).omit({ id: true, startedAt: true });
export const insertEventSchema = createInsertSchema(eventsTable).omit({ id: true, createdAt: true });

export type Computer = typeof computersTable.$inferSelect;
export type Action = typeof actionsTable.$inferSelect;
export type Alert = typeof alertsTable.$inferSelect;
export type UsbPolicy = typeof usbPoliciesTable.$inferSelect;
export type StudentSession = typeof studentSessionsTable.$inferSelect;
export type LabEvent = typeof eventsTable.$inferSelect;
export type Peripheral = typeof peripheralsTable.$inferSelect;
export type ScanRun = typeof scanRunsTable.$inferSelect;
export type ScanResult = typeof scanResultsTable.$inferSelect;
export type InsertComputer = z.infer<typeof insertComputerSchema>;
export type AppUser = typeof appUsersTable.$inferSelect;
export type AuthSession = typeof authSessionsTable.$inferSelect;
export type Tenant = typeof tenantsTable.$inferSelect;
export type PlatformUser = typeof platformUsersTable.$inferSelect;
export type AuthSessionPlatform = typeof authSessionsPlatformTable.$inferSelect;
