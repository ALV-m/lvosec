import * as zod from "zod";

export const AgentComputerAction = zod.enum([
  "lock",
  "unlock",
  "restart",
  "wake",
  "send_message",
  "remote_view",
  "remote_control",
  "remote_input",
  "block_usb",
  "allow_usb",
  "push_file",
  "delete_file",
  "list_files",
  "av_scan",
  "av_update",
  "av_toggle",
  "fw_enable",
  "fw_disable",
  "wol_relay",
  "disable_rdp",
  "shutdown",
  "sleep",
]);

export const AgentRegisterBody = zod.object({
  name: zod.string().min(1).max(100),
  os: zod.string().max(200).optional(),
  agentVersion: zod.string().max(50).optional(),
  macAddress: zod.string().max(64).nullish(),
  ipAddress: zod.string().max(64).nullish(),
  manufacturer: zod.string().max(128).nullish(),
  model: zod.string().max(128).nullish(),
  serialNumber: zod.string().max(128).nullish(),
  biosSerial: zod.string().max(128).nullish(),
  systemUUID: zod.string().max(128).nullish(),
  totalRAM: zod.number().nullish(),
  cpuName: zod.string().max(128).nullish(),
  cpuCores: zod.number().nullish(),
});

export const AgentRegisterResponse = zod.object({
  computerId: zod.number(),
  token: zod.string(),
  name: zod.string(),
  usbState: zod.enum(["blocked", "allowed", "review"]),
  serverTime: zod.string(),
});

export const AgentHeartbeatBody = zod.object({
  token: zod.string().min(1),
  userName: zod.string().nullish(),
  os: zod.string().nullish(),
  agentVersion: zod.string().nullish(),
  avEnabled: zod.boolean().nullish(),
  avSignature: zod.string().nullish(),
  avLastScanAt: zod.string().nullish(),
  avScanState: zod.string().nullish(),
  firewallEnabled: zod.boolean().nullish(),
  firewallProfiles: zod.string().nullish(),
  macAddress: zod.string().max(64).nullish(),
  ipAddress: zod.string().max(64).nullish(),
  manufacturer: zod.string().max(128).nullish(),
  model: zod.string().max(128).nullish(),
  serialNumber: zod.string().max(128).nullish(),
  biosSerial: zod.string().max(128).nullish(),
  systemUUID: zod.string().max(128).nullish(),
  totalRAM: zod.number().nullish(),
  cpuName: zod.string().max(128).nullish(),
  cpuCores: zod.number().nullish(),
  diskTotal: zod.number().nullish(),
  diskFree: zod.number().nullish(),
  /**
   * Security posture signals consumed by the posture engine. Tri-state: a
   * missing member means \"not reported\", which the engine reports as
   * `unknown` rather than `pass`. The agent sends its full cached snapshot
   * with every heartbeat; the server stores it wholesale in
   * lab_computers.security_signals.
   */
  security: zod
    .object({
      avRealtimeProtection: zod.boolean().nullish(),
      avTamperProtection: zod.boolean().nullish(),
      /** Count of paths excluded from AV scanning. */
      avExclusionCount: zod.number().nullish(),
      avSignatureAgeDays: zod.number().nullish(),
      avDisabledByPolicy: zod.boolean().nullish(),
      firewallAllProfiles: zod.boolean().nullish(),
      smb1Enabled: zod.boolean().nullish(),
      smbSigningRequired: zod.boolean().nullish(),
      rdpEnabled: zod.boolean().nullish(),
      bitlockerEnabled: zod.boolean().nullish(),
      tpmPresent: zod.boolean().nullish(),
      secureBootEnabled: zod.boolean().nullish(),
      uacEnabled: zod.boolean().nullish(),
      guestAccountEnabled: zod.boolean().nullish(),
      screenLockEnabled: zod.boolean().nullish(),
      autorunEnabled: zod.boolean().nullish(),
      windowsUpdateDisabled: zod.boolean().nullish(),
      localAdminCount: zod.number().nullish(),
      /** Winlogon AutoAdminLogon state, compared against the sign-in method. */
      autoLogonEnabled: zod.boolean().nullish(),
    })
    .nullish(),
});

export const AgentPendingAction = zod.object({
  id: zod.number(),
  action: AgentComputerAction,
  message: zod.string().nullish(),
  payload: zod.string().nullish(),
});

export const AgentHeartbeatResponse = zod.object({
  serverTime: zod.string(),
  latestAgentVersion: zod.string().nullish(),
  agentUpdateRequested: zod.boolean().default(false),
  computer: zod.object({
    id: zod.number(),
    name: zod.string(),
    status: zod.enum(["online", "offline", "warning", "locked"]),
    usbState: zod.enum(["blocked", "allowed", "review"]),
    firewallEnabled: zod.boolean().nullish(),
    firewallProfiles: zod.string().nullish(),
    checkinRequired: zod.boolean().nullish(),
    signinMethod: zod.enum(["password", "shared_account"]).nullish(),
    sharedAccountUser: zod.string().max(64).nullish(),
    sharedAccountPassword: zod.string().max(128).nullish(),
    adminWindowsUser: zod.string().max(100).nullish(),
    blockDownloads: zod.boolean().nullish(),
    remoteViewActive: zod.boolean().nullish(),
  }),
  allowedUsb: zod.array(zod.string()),
  allowedDeviceIds: zod.array(zod.string()).default([]),
  pendingActions: zod.array(AgentPendingAction),
  idleLogoutMinutes: zod.number().int().nonnegative().nullish(),
});

export const AgentActionCompleteParams = zod.object({
  actionId: zod.coerce.number(),
});

export const AgentActionCompleteBody = zod.object({
  token: zod.string().min(1),
  success: zod.boolean(),
  detail: zod.string().nullish(),
});

export const AgentActionCompleteResponse = zod.object({
  ok: zod.boolean(),
});

export const AgentEventBody = zod.object({
  token: zod.string().min(1),
  type: zod.enum([
    "student_login",
    "student_logout",
    "usb_connected",
    "usb_removed",
    "login_failure",
    "password_change",
    "password_reset",
    "autologon",
    "gate",
    "agent_update",
  ]),
  message: zod.string().max(500).optional(),
  detail: zod.string().max(500).optional(),
});

export const AgentEventResponse = zod.object({
  ok: zod.boolean(),
});

export const SoftwareEntry = zod.object({
  name: zod.string().min(1).max(256),
  version: zod.string().max(128).nullish(),
  publisher: zod.string().max(256).nullish(),
});

export const AgentSoftwareBody = zod.object({
  token: zod.string().min(1),
  /** Full installed-software snapshot, deduplicated, sorted. */
  software: zod.array(SoftwareEntry).max(600),
});

export const AgentCheckinRole = zod.enum(["student", "teacher", "visitor", "admin"]);

export const AgentCheckinBody = zod
  .object({
    token: zod.string().min(1),
    userName: zod.string().max(200).nullish(),
    role: AgentCheckinRole.nullish(),
    studentName: zod.string().min(1).max(200),
    phone: zod.string().max(50).nullish(),
    admissionNo: zod.string().max(100).nullish(),
    course: zod.string().max(200).nullish(),
    class: zod.string().max(100).nullish(),
    reason: zod.string().max(500).nullish(),
    email: zod.string().max(200).nullish(),
    photoFileId: zod.string().max(200).nullish(),
    adminUser: zod.string().max(100).nullish(),
    adminPass: zod.string().max(128).nullish(),
  })
  .superRefine((value, ctx) => {
    const role = value.role ?? "student";
    const text = (input: string | null | undefined) => input?.trim() ?? "";
    if (role === "student") {
      if (!text(value.course)) ctx.addIssue({ code: "custom", path: ["course"], message: "Course is required for students" });
      if (!text(value.class)) ctx.addIssue({ code: "custom", path: ["class"], message: "Class is required for students" });
      if (!text(value.reason)) ctx.addIssue({ code: "custom", path: ["reason"], message: "Reason for use is required" });
    } else if (role === "teacher") {
      if (!text(value.admissionNo)) ctx.addIssue({ code: "custom", path: ["admissionNo"], message: "Staff / employee ID is required for teachers" });
      if (!text(value.reason)) ctx.addIssue({ code: "custom", path: ["reason"], message: "Reason for use is required" });
    } else if (role === "visitor") {
      if (!text(value.reason)) ctx.addIssue({ code: "custom", path: ["reason"], message: "Reason for use is required" });
    }
  });

export const AgentCheckinResponse = zod.object({
  ok: zod.boolean(),
  checkinId: zod.number().nullish(),
  error: zod.string().max(300).nullish(),
});

export const AgentUploadResponse = zod.object({
  fileId: zod.string(),
});

export const AgentScreenshotResponse = zod.object({
  fileId: zod.string(),
  takenAt: zod.string(),
});

export const AgentSoftwareResponse = zod.object({
  ok: zod.boolean(),
});
