/**
 * Security posture engine.
 *
 * A pure, side-effect-free evaluator: it takes a machine's reported state and
 * the tenant's settings, and returns a list of findings. No database, no clock
 * beyond the one it is handed, no I/O. That is what makes it testable and what
 * makes it safe to run on every heartbeat.
 *
 * Two rules shape everything here:
 *
 * 1. **Absent data is `unknown`, never `pass`.** A check that cannot be
 *    evaluated says so. Reporting "fine" for something we did not look at is
 *    how a dashboard convinces an admin they are safe when they are not, so
 *    the summary reports coverage alongside results.
 *
 * 2. **Configuration is compared against intent.** The finding that matters
 *    most is not "auto-login is on" but "auto-login is on *while a password is
 *    required*" -- the lab is silently unenforced and nothing else notices.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PostureSeverity = "critical" | "high" | "medium" | "low" | "info";

export type PostureState = "pass" | "fail" | "unknown";

/**
 * Groups findings by the defensive layer they belong to, so the dashboard can
 * show coverage of the whole picture rather than a flat list.
 */
export type PostureCategory =
  | "detection"
  | "endpoint"
  | "network"
  | "access_control"
  | "data_protection"
  | "configuration";

/**
 * Everything the agent can tell us about a machine's security state. Every
 * field is tri-state: `true`, `false`, or absent/null for "not reported".
 * A field is null when the agent is older than the check that reads it, or when
 * the check could not run on that machine.
 */
export interface SecuritySignals {
  // Defence evasion / detection
  /** Windows Defender antivirus enabled. */
  avEnabled?: boolean | null;
  /** Defender real-time protection. */
  avRealtimeProtection?: boolean | null;
  /** Defender behavioural/tamper protection. */
  avTamperProtection?: boolean | null;
  /** How many paths are excluded from scanning. Any nonzero count is suspect. */
  avExclusionCount?: number | null;
  /** Age of AV definitions in days. */
  avSignatureAgeDays?: number | null;
  /** Defender managed via policy with real-time protection forced off. */
  avDisabledByPolicy?: boolean | null;

  // Network
  /** Host firewall enabled. */
  firewallEnabled?: boolean | null;
  /** Firewall on for domain, private and public profiles. */
  firewallAllProfiles?: boolean | null;
  /** SMBv1 (the WannaCry-era protocol). */
  smb1Enabled?: boolean | null;
  /** SMB signing required. */
  smbSigningRequired?: boolean | null;
  /** Remote Desktop accepting connections. */
  rdpEnabled?: boolean | null;
  /** VPS only: ufw rate-limits SSH (`limit 22/tcp`, ~6 conn/30s). */
  sshRateLimited?: boolean | null;

  // Data protection
  /** OS volume encrypted with BitLocker. */
  bitlockerEnabled?: boolean | null;
  /** A TPM is present. */
  tpmPresent?: boolean | null;

  // Configuration / access control
  secureBootEnabled?: boolean | null;
  uacEnabled?: boolean | null;
  guestAccountEnabled?: boolean | null;
  screenLockEnabled?: boolean | null;
  autorunEnabled?: boolean | null;
  windowsUpdateDisabled?: boolean | null;
  /** Count of local accounts in the Administrators group. */
  localAdminCount?: number | null;
  /**
   * Whether Windows auto-logs a user in without asking for a password
   * (Winlogon\AutoAdminLogon). Compared against the tenant's configured
   * sign-in method, which is where the dangerous combinations come from.
   */
  autoLogonEnabled?: boolean | null;
}

export interface PostureComputer {
  id: number;
  name: string;
  room: string;
  status: string;
  os?: string | null;
  lastSeen?: Date | string | null;
  agentVersion?: string | null;
  avEnabled?: boolean | null;
  avSignature?: string | null;
  avLastScanAt?: Date | string | null;
  firewallEnabled?: boolean | null;
  diskFree?: number | null;
  diskTotal?: number | null;
  /**
   * VPS (Linux agent) telemetry from the hourly channel. Absent on Windows lab
   * machines; on a Linux host an absent field is `unknown`, never a pass.
   */
  services?: Array<{
    name: string;
    active?: string | null;
    sub?: string | null;
    enabled?: string | null;
  }> | null;
  packages?: Array<{ name: string; version?: string | null }> | null;
  authFailures?: {
    count24h?: number | null;
    topSources?: Array<{ ip?: string; count?: number }> | null;
  } | null;
  fimState?: {
    status?: "clean" | "drift" | null;
    changed?: Array<{ path?: string; hash?: string }> | null;
  } | null;
}

export interface PostureContext {
  computer: PostureComputer;
  /** Tenant settings, keyed as stored in lab_settings. */
  settings: Record<string, string | null>;
  security: SecuritySignals;
  /** Agent version the server ships, or null if it could not be determined. */
  bundledAgentVersion?: string | null;
  now: Date;
}

export interface PostureFinding {
  /** Stable identifier, safe to use as a key or in a URL. */
  id: string;
  title: string;
  severity: PostureSeverity;
  state: PostureState;
  /** Why this finding fired, or why it could not be evaluated. */
  detail: string;
  /** What an operator should actually do about it. */
  remediation: string;
  category: PostureCategory;
}

export interface PostureSummary {
  findings: PostureFinding[];
  /** How many checks ran, out of how many exist. */
  evaluated: number;
  total: number;
  bySeverity: Record<PostureSeverity, number>;
  /** Checks that failed, worst first. */
  failing: number;
  /** The single most important thing to fix, or null when nothing failed. */
  headline: PostureFinding | null;
}

/**
 * A finding that only exists because of what *other* machines reported, or
 * because of how several independent failures combine on one machine. This is
 * the thin slice of SOC that runs locally: single-machine checks above, and
 * compounding + fleet-wide patterns here.
 */
export interface LabFinding {
  id: string;
  title: string;
  severity: PostureSeverity;
  detail: string;
  remediation: string;
  category: PostureCategory;
  /** How many machines are implicated. */
  affected: number;
  /** Total machines evaluated (for fraction-based rules). */
  total: number;
  computerIds: number[];
}

const SEVERITY_ORDER: Record<PostureSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const CATEGORY_ORDER: PostureCategory[] = [
  "detection",
  "endpoint",
  "network",
  "access_control",
  "data_protection",
  "configuration",
];

/** Signature age past which we consider AV definitions stale. */
const STALE_SIGNATURE_DAYS = 7;

/** How long a computer may go unheard before the agent counts as missing. */
const AGENT_SILENT_MINUTES = 10;

/** Auto-login left on for this long after the last agent contact is a smell. */
const NOISE_LEVEL = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function finding(
  id: string,
  state: PostureState,
  severity: PostureSeverity,
  category: PostureCategory,
  title: string,
  detail: string,
  remediation: string,
): PostureFinding {
  return { id, title, severity, state, detail, remediation, category };
}

/**
 * Turns a tri-state into a finding, or null when the data is absent.
 *
 * The single place that decides "unknown" behaviour, so the rule cannot drift
 * between checks.
 */
function triState(
  id: string,
  value: boolean | number | null | undefined,
  opts: {
    category: PostureCategory;
    title: string;
    pass: string;
    fail: (observed: string) => string;
    remediation: string;
    severity: PostureSeverity;
    /**
     * The boolean value that counts as healthy. Signals are named for the
     * dangerous state ("smb1_enabled", "guest_account_on"), so most checks want
     * `"false"`. Defaults to `"true"`.
     */
    passOn?: "true" | "false";
    /** Numeric values above this count as a failure (e.g. exclusions). */
    threshold?: number;
  },
): PostureFinding | null {
  if (value === null || value === undefined) {
    return finding(
      id,
      "unknown",
      "info",
      opts.category,
      opts.title,
      "The agent has not reported this yet. Update the agent to cover this check.",
      opts.remediation,
    );
  }
  const passOn = opts.passOn ?? "true";
  let failed: boolean;
  if (opts.threshold !== undefined) {
    failed = Number(value) > opts.threshold;
  } else {
    const bool = value as boolean;
    failed = passOn === "true" ? bool === false : bool === true;
  }
  return finding(
    id,
    failed ? "fail" : "pass",
    opts.severity,
    opts.category,
    opts.title,
    failed ? opts.fail(String(value)) : opts.pass,
    opts.remediation,
  );
}

function ageInDays(from: Date | string | null | undefined, now: Date): number | null {
  if (!from) return null;
  const t = typeof from === "string" ? new Date(from) : from;
  if (Number.isNaN(t.getTime())) return null;
  return Math.floor((now.getTime() - t.getTime()) / 86_400_000);
}

// ---------------------------------------------------------------------------
// VPS patch risk — curated end-of-life markers
//
// Not a CVE feed and not a promise of completeness: only unambiguous markers
// (whole series that are upstream-end-of-life and routinely exploited) count,
// so "0 known-vulnerable packages" stays a meaningful statement.
// ---------------------------------------------------------------------------

export const VPS_AUTHFAIL_THRESHOLD = 10;

const KNOWN_VULNERABLE_PREFIXES: Array<{ name: string; prefixes: string[] }> = [
  { name: "openssl", prefixes: ["1.1.1"] }, // 1.1.1 EOL since Sept 2023
  { name: "bash", prefixes: ["4."] }, // 4.x EOL since 2019; 5.x is current
  { name: "php", prefixes: ["7.", "8.0.", "8.1."] }, // 8.1 EOL Nov 2024
  { name: "python3", prefixes: ["3.6", "3.7", "3.8"] }, // 3.8 EOL Oct 2024
];

export interface VulnerablePackage {
  name: string;
  version: string;
}

export function findVulnerablePackages(
  packages: Array<{ name: string; version?: string | null }> | null | undefined,
): VulnerablePackage[] {
  if (!packages || packages.length === 0) return [];
  const byName = new Map(packages.map((p) => [p.name.toLowerCase(), p]));
  const found: VulnerablePackage[] = [];
  for (const rule of KNOWN_VULNERABLE_PREFIXES) {
    const pkg = byName.get(rule.name.toLowerCase());
    if (!pkg?.version) continue;
    const version = pkg.version.toLowerCase();
    if (rule.prefixes.some((prefix) => version === prefix || version.startsWith(prefix))) {
      found.push({ name: pkg.name, version: pkg.version });
    }
  }
  return found;
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

/**
 * Evaluates one machine. Returns every check, including the ones that pass, so
 * the dashboard can show what was actually looked at.
 */
export function evaluatePosture(ctx: PostureContext): PostureSummary {
  const { computer, settings, security, now } = ctx;
  const findings: PostureFinding[] = [];
  const push = (f: PostureFinding | null) => {
    if (f) findings.push(f);
  };

  // --- Detection: is anything actually watching this machine? --------------
  push(
    triState("av_disabled", security.avEnabled, {
      category: "detection",
      severity: "critical",
      title: "Antivirus is disabled",
      pass: "Antivirus is enabled.",
      fail: () => "Windows Defender reports itself as disabled.",
      remediation: "Re-enable antivirus on the machine, or push the policy from the dashboard.",
    }),
  );

  push(
    triState("av_realtime_off", security.avRealtimeProtection, {
      category: "detection",
      severity: "critical",
      title: "Real-time protection is off",
      pass: "Real-time scanning is on.",
      fail: () => "Real-time protection is disabled, so files are only scanned on demand.",
      remediation: "Turn real-time protection back on. A student can install malware before anything scans it.",
    }),
  );

  push(
    triState("av_tamper_off", security.avTamperProtection, {
      category: "detection",
      severity: "high",
      title: "Tamper protection is off",
      pass: "Tamper protection is on, so malware cannot switch Defender off.",
      fail: () => "Tamper protection is disabled, so anything running as admin can turn Defender off.",
      remediation: "Re-enable tamper protection so the agent cannot itself be neutralised.",
    }),
  );

  push(
    triState("av_policy_disabled", security.avDisabledByPolicy, {
      category: "detection",
      severity: "critical",
      title: "Antivirus disabled by group policy",
      pass: "No policy is disabling antivirus.",
      fail: () => "A group policy has disabled antivirus on this machine.",
      remediation: "Find and remove the policy. A lab PC with no AV and a known policy is a deliberate gap.",
      passOn: "false",
    }),
  );

  push(
    triState("av_exclusions", security.avExclusionCount, {
      category: "detection",
      severity: "high",
      title: "Antivirus scan exclusions are set",
      pass: "No scan exclusions are configured.",
      fail: (n) => `${n} path(s) are excluded from scanning. Malware can live there unscanned.`,
      remediation: "Remove the exclusions unless you set one deliberately and know why.",
      threshold: 0,
    }),
  );

  push(
    triState("av_signature_stale", security.avSignatureAgeDays, {
      category: "detection",
      severity: "medium",
      title: "Antivirus definitions are out of date",
      pass: "Antivirus definitions are current.",
      fail: (n) => `Definitions are ${n} day(s) old. New malware will not be caught.`,
      remediation: "Trigger an AV signature update from the dashboard.",
      threshold: STALE_SIGNATURE_DAYS,
    }),
  );

  // --- Network -------------------------------------------------------------
  push(
    triState("firewall_off", security.firewallEnabled, {
      category: "network",
      severity: "high",
      title: "Host firewall is disabled",
      pass: "The host firewall is on.",
      fail: () => "The Windows firewall is disabled, so every listening port is exposed to the lab network.",
      remediation: "Re-enable the firewall on all profiles.",
    }),
  );

  push(
    triState("firewall_partial", security.firewallAllProfiles, {
      category: "network",
      severity: "medium",
      title: "Firewall is not on for every network profile",
      pass: "The firewall is on for domain, private and public profiles.",
      fail: () => "The firewall is on for some profiles only, so the machine is exposed on the others.",
      remediation: "Enable the firewall for all three profiles, including public.",
    }),
  );

  push(
    triState("smb1_enabled", security.smb1Enabled, {
      category: "network",
      severity: "high",
      title: "SMBv1 is enabled",
      pass: "SMBv1 is disabled.",
      fail: () => "SMBv1 is enabled. This is the protocol behind WannaCry and a standard ransomware entry point.",
      remediation: "Disable SMBv1. Modern Windows does not need it.",
      passOn: "false",
    }),
  );

  push(
    triState("smb_signing_off", security.smbSigningRequired, {
      category: "network",
      severity: "medium",
      title: "SMB signing is not required",
      pass: "SMB signing is required.",
      fail: () => "SMB signing is not required, so file traffic on the lab network can be tampered with.",
      remediation: "Require SMB signing so a machine cannot impersonate another on the network.",
    }),
  );

  push(
    triState("rdp_enabled", security.rdpEnabled, {
      category: "network",
      severity: "low",
      title: "Remote Desktop is enabled",
      pass: "Remote Desktop is disabled.",
      fail: () => "Remote Desktop accepts connections, giving anything that reaches the machine a login prompt.",
      remediation:
        "Disable RDP on student machines unless this lab is deliberately used for remote access.",
      passOn: "false",
    }),
  );

  // --- Data protection -----------------------------------------------------
  push(
    triState("bitlocker_off", security.bitlockerEnabled, {
      category: "data_protection",
      severity: "high",
      title: "Disk is not encrypted",
      pass: "The OS volume is encrypted with BitLocker.",
      fail: () => "The OS volume is not encrypted, so a stolen machine exposes its contents offline.",
      remediation: "Enable BitLocker. A lab PC that can be stolen is a data-loss event waiting to happen.",
    }),
  );

  push(
    triState("tpm_absent", security.tpmPresent, {
      category: "data_protection",
      severity: "info",
      title: "No TPM present",
      pass: "A TPM is present, so BitLocker and Credential Guard can bind keys to hardware.",
      fail: () => "No TPM, so encryption keys cannot be bound to hardware and BitLocker is weaker.",
      remediation: "Usually expected on lab hardware. Only worth fixing if these machines leave the building.",
    }),
  );

  // --- Access control ------------------------------------------------------
  push(
    triState("guest_account_on", security.guestAccountEnabled, {
      category: "access_control",
      severity: "medium",
      title: "Built-in guest account is active",
      pass: "The guest account is disabled.",
      fail: () => "The built-in guest account is enabled, giving anyone at the machine a way in without a password.",
      remediation: "Disable the guest account.",
      passOn: "false",
    }),
  );

  push(
    triState("screen_lock_off", security.screenLockEnabled, {
      category: "access_control",
      severity: "medium",
      title: "Screen lock is disabled",
      pass: "The screen locks after the idle timeout.",
      fail: () => "The screen never locks, so any walk-up can use an unattended machine.",
      remediation: "Set an idle screen lock timeout on the machine.",
    }),
  );

  push(
    triState("too_many_admins", security.localAdminCount, {
      category: "access_control",
      severity: "medium",
      title: "Multiple local administrators",
      pass: "One local administrator account.",
      fail: (n) => `${n} local accounts are administrators. A compromised student account is then an admin compromise.`,
      remediation: "Keep a single administrator account and give students standard accounts.",
      threshold: 1,
    }),
  );

  // --- Configuration -------------------------------------------------------
  push(
    triState("secure_boot_off", security.secureBootEnabled, {
      category: "configuration",
      severity: "high",
      title: "Secure Boot is disabled",
      pass: "Secure Boot is on, so the bootloader only loads signed components.",
      fail: () => "Secure Boot is disabled, so the machine can be made to boot code that never went through signing.",
      remediation: "Re-enable Secure Boot unless the lab hardware cannot support it.",
    }),
  );

  push(
    triState("uac_off", security.uacEnabled, {
      category: "configuration",
      severity: "medium",
      title: "User Account Control is disabled",
      pass: "User Account Control is on.",
      fail: () => "UAC is off, so every program runs with full administrator rights without a prompt.",
      remediation: "Re-enable UAC. Lab machines do not need it turned off to work.",
    }),
  );

  push(
    triState("autorun_on", security.autorunEnabled, {
      category: "configuration",
      severity: "medium",
      title: "AutoPlay / AutoRun is enabled",
      pass: "AutoPlay is off.",
      fail: () => "AutoPlay is on, so plugging in a USB drive can run what is on it without a prompt.",
      remediation: "Disable AutoPlay. This is the main way removable media gets malware onto a lab PC.",
      passOn: "false",
    }),
  );

  push(
    triState("windows_update_off", security.windowsUpdateDisabled, {
      category: "configuration",
      severity: "high",
      title: "Windows Update is disabled",
      pass: "Windows Update is enabled.",
      fail: () => "Windows Update is off, so known-vulnerable builds never get their fixes.",
      remediation: "Re-enable Windows Update, or patch through whatever mechanism the lab uses.",
      passOn: "false",
    }),
  );

  // --- The check that matters most ----------------------------------------
  // Comparing configuration against intent is the whole point. "Auto-login is
  // on" is a normal lab setup; "auto-login is on while a password is required"
  // means the lab is silently unenforced and nothing else on this page notices.
  const signinMethod = settings.signin_method ?? null;
  if (security.autoLogonEnabled === null || security.autoLogonEnabled === undefined) {
    push(
      finding(
        "signin_gate_unverifiable",
        "unknown",
        "info",
        "access_control",
        "Sign-in gate is not enforced",
        "The agent has not reported the auto-login state, so whether the sign-in gate is actually in force is unknown.",
        "Update the agent. Until it reports this, the dashboard cannot tell you the lab is enforcing its own policy.",
      ),
    );
  } else if (signinMethod === "password" && security.autoLogonEnabled === true) {
    push(
      finding(
        "signin_gate_bypassed",
        "fail",
        "critical",
        "access_control",
        "Sign-in gate is bypassed by auto-login",
        "The lab is set to require a password, but Windows is still configured to log a user in automatically. Students reach a desktop without ever passing the check-in gate.",
        "Clear the Windows auto-login setting. The agent clears it at boot; something is putting it back.",
      ),
    );
  } else if (signinMethod === "shared_account" && security.autoLogonEnabled === false) {
    push(
      finding(
        "signin_gate_missing",
        "fail",
        "high",
        "access_control",
        "Auto-login is off, so students see the Windows password screen",
        "The lab uses a shared auto-login account, but auto-login is disabled, so students stop at the Windows password prompt instead of the check-in gate.",
        "Re-enable auto-login for the shared account.",
      ),
    );
  } else {
    push(
      finding(
        "signin_gate_enforced",
        "pass",
        "info",
        "access_control",
        "Sign-in gate is configured consistently",
        "The auto-login state matches the lab's configured sign-in method.",
        "Nothing to do.",
      ),
    );
  }

  // --- Agent health --------------------------------------------------------
  // A machine nothing is reporting from is a blind spot, not a healthy machine.
  const silentMinutes = computer.lastSeen
    ? Math.floor((now.getTime() - new Date(computer.lastSeen).getTime()) / 60_000)
    : null;
  if (silentMinutes === null) {
    push(
      finding(
        "agent_silent",
        "unknown",
        "info",
        "detection",
        "Agent has never reported",
        "This machine has no agent contact recorded, so none of its security state can be checked.",
        "Deploy the agent to this machine.",
      ),
    );
  } else if (silentMinutes > AGENT_SILENT_MINUTES) {
    push(
      finding(
        "agent_silent",
        "fail",
        "high",
        "detection",
        "Agent is not reporting",
        `No contact for ${silentMinutes} minutes. Every other check on this machine is stale.`,
        "Check that the machine is powered on and can reach the server, then redeploy the agent if needed.",
      ),
    );
  } else {
    push(
      finding(
        "agent_silent",
        "pass",
        "info",
        "detection",
        "Agent is reporting",
        `Last contact ${silentMinutes} minute(s) ago.`,
        "Nothing to do.",
      ),
    );
  }

  if (ctx.bundledAgentVersion && computer.agentVersion) {
    const behind =
      compareVersions(computer.agentVersion, ctx.bundledAgentVersion) < 0;
    push(
      finding(
        "agent_outdated",
        behind ? "fail" : "pass",
        behind ? "medium" : "info",
        "detection",
        "Agent is out of date",
        behind
          ? `Running v${computer.agentVersion}; the server ships v${ctx.bundledAgentVersion}. Newer checks are not running on this machine.`
          : `Running v${computer.agentVersion}, which matches the server.`,
        behind
          ? "Let the agent self-update, or deploy the current script to this machine."
          : "Nothing to do.",
      ),
    );
  }

  const diskFree = computer.diskFree ?? null;
  const diskTotal = computer.diskTotal ?? null;
  if (diskFree !== null && diskTotal !== null && diskTotal > 0) {
    const freePct = Math.round((diskFree / diskTotal) * 100);
    push(
      finding(
        "disk_nearly_full",
        freePct < 10 ? "fail" : "pass",
        freePct < 10 ? "low" : "info",
        "configuration",
        "Disk is nearly full",
        freePct < 10
          ? `${freePct}% free. A full disk stops Windows logging properly, which quietly blinds the audit trail.`
          : `${freePct}% free.`,
        freePct < 10 ? "Free space on this machine." : "Nothing to do.",
      ),
    );
  }

  // --- VPS (Linux agent) telemetry ------------------------------------------
  // The Blue Team protects VPS servers too, so these checks run per-host the
  // same way the Windows checks do — but only against Linux hosts, where the
  // data can exist. A Windows lab machine cannot collect services/packages/
  // auth-logs, so the checks are skipped entirely rather than reported as
  // unknown. On a Linux host, absent telemetry is `unknown`: never a pass.
  const isVps = /linux|ubuntu|debian/i.test(computer.os ?? "");

  if (isVps) {
    const auth = computer.authFailures ?? null;
    const authKnown = auth !== null && (auth.count24h ?? null) !== null;
    if (!authKnown) {
      push(
        finding(
          "vps_authfail",
          "unknown",
          "info",
          "detection",
          "SSH brute-force exposure",
          "This VPS has not reported login-failure data yet. Linux agent 1.24+ sends it on the hourly telemetry channel.",
          "Update the agent; failed-ssh-login counts appear on its next telemetry push.",
        ),
      );
    } else if ((auth?.count24h ?? 0) >= VPS_AUTHFAIL_THRESHOLD) {
      const sources = (auth?.topSources ?? [])
        .slice(0, 3)
        .filter((s) => s.ip)
        .map((s) => `${s.ip} (${s.count ?? 0})`)
        .join(", ");
      push(
        finding(
          "vps_authfail",
          "fail",
          "high",
          "detection",
          "SSH brute-force attack in progress",
          `${auth?.count24h ?? 0} failed ssh logins in the last 24 hours${sources ? ` — top sources: ${sources}` : ""}.`,
          "Confirm the attempts are not your own monitors, rotate any exposed credentials, restrict SSH to known IPs, and enable SSH rate limiting (Blue Team → VPS action → rate limit SSH).",
        ),
      );
    } else {
      push(
        finding(
          "vps_authfail",
          "pass",
          "info",
          "detection",
          "No failed ssh logins",
          `${auth?.count24h ?? 0} failed logins in the last 24 hours — no brute-force noise.`,
          "Nothing to do.",
        ),
      );
    }

    push(
      triState("vps_ssh_rate_limited", security.sshRateLimited, {
        category: "network",
        severity: "medium",
        title: "SSH rate limiting is off",
        pass: "SSH is rate-limited by the host firewall (ufw limit).",
        fail: () =>
          "SSH accepts unlimited connection attempts — brute-force scripts can hammer it freely.",
        remediation:
          "Run “Rate limit SSH” from Blue Team → VPS actions (ufw limit 22/tcp, ~6 new connections per 30 seconds per source).",
      }),
    );

    const fim = computer.fimState ?? null;
    const fimKnown = fim !== null && (fim.status ?? null) !== null;
    if (!fimKnown) {
      push(
        finding(
          "vps_fim_drift",
          "unknown",
          "info",
          "configuration",
          "Config integrity (FIM) not reporting",
          "This VPS has not reported its config-integrity baseline yet. Linux agent 1.24+ snapshots sshd/account/boot configs hourly.",
          "Update the agent; the first telemetry push establishes the hash baseline.",
        ),
      );
    } else if (fim?.status === "drift") {
      const changed = (fim.changed ?? []).slice(0, 5).map((c) => c.path).filter(Boolean).join(", ");
      push(
        finding(
          "vps_fim_drift",
          "fail",
          "high",
          "configuration",
          "Protected files changed",
          `${(fim.changed ?? []).length} protected file(s) no longer match the baseline${changed ? `: ${changed}` : ""}. A config-tampering / rootkit signature — or a legitimate admin edit.`,
          "Review each changed path on the server. Revert edits that were not yours and treat unexplained drift as a potential compromise.",
        ),
      );
    } else {
      push(
        finding(
          "vps_fim_drift",
          "pass",
          "info",
          "configuration",
          "Protected files unchanged",
          "The config-integrity baseline matches — no unexpected changes to sshd, accounts or boot config.",
          "Nothing to do.",
        ),
      );
    }

    const hasPackages = computer.packages !== null && computer.packages !== undefined;
    const vulnerable = findVulnerablePackages(computer.packages);
    if (!hasPackages) {
      push(
        finding(
          "vps_vuln_packages",
          "unknown",
          "info",
          "configuration",
          "Patch risk not reporting",
          "This VPS has not reported its package inventory yet. Linux agent 1.24+ sends the dpkg list hourly.",
          "Update the agent; the hourly telemetry push includes the package inventory.",
        ),
      );
    } else if (vulnerable.length > 0) {
      const names = vulnerable.slice(0, 5).map((v) => `${v.name} ${v.version}`).join(", ");
      push(
        finding(
          "vps_vuln_packages",
          "fail",
          "high",
          "configuration",
          "Known-vulnerable software installed",
          `${vulnerable.length} package(s) in an end-of-life / widely-exploited series: ${names}. Curated marker list, not a full CVE feed.`,
          "Upgrade the flagged packages from the distro repository, or move the server to a supported release.",
        ),
      );
    } else {
      push(
        finding(
          "vps_vuln_packages",
          "pass",
          "info",
          "configuration",
          "No known-vulnerable packages",
          `${computer.packages?.length ?? 0} packages inventoried; none match the curated end-of-life marker list.`,
          "Nothing to do.",
        ),
      );
    }
  }

  return summarise(findings, NOISE_LEVEL);
}

/** Wraps findings into a summary, worst-first within each severity. */
function summarise(findings: PostureFinding[], _noise: number): PostureSummary {
  const bySeverity: Record<PostureSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    if (f.state === "fail") bySeverity[f.severity] += 1;
  }

  const ordered = [...findings].sort((a, b) => {
    if (a.state !== b.state) return a.state === "fail" ? -1 : b.state === "fail" ? 1 : 0;
    return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  });

  const failing = findings.filter((f) => f.state === "fail");

  return {
    findings: ordered,
    evaluated: findings.filter((f) => f.state !== "unknown").length,
    total: findings.length,
    bySeverity,
    failing: failing.length,
    headline: failing.length > 0 ? ordered[0] ?? null : null,
  };
}

/** Compares dotted version strings. Returns <0, 0 or >0. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => Number.parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

/** Aggregate posture across every machine in a lab. */
export function summariseLab(
  summaries: Array<{ computerId: number; computerName: string; room: string; summary: PostureSummary }>,
): {
  computers: number;
  withFailures: number;
  checks: number;
  passing: number;
  failing: number;
  unknown: number;
  byCategory: Record<PostureCategory, { passing: number; failing: number; unknown: number }>;
  criticalMachines: Array<{ computerId: number; computerName: string; room: string; headline: PostureFinding }>;
} {
  const byCategory = Object.fromEntries(
    CATEGORY_ORDER.map((c) => [c, { passing: 0, failing: 0, unknown: 0 }]),
  ) as Record<PostureCategory, { passing: number; failing: number; unknown: number }>;

  let passing = 0;
  let failing = 0;
  let unknown = 0;
  const criticalMachines: Array<{
    computerId: number;
    computerName: string;
    room: string;
    headline: PostureFinding;
  }> = [];

  for (const entry of summaries) {
    for (const f of entry.summary.findings) {
      if (f.state === "fail") failing += 1;
      else if (f.state === "pass") passing += 1;
      else unknown += 1;
      const bucket = f.state === "fail" ? "failing" : f.state === "pass" ? "passing" : "unknown";
      byCategory[f.category][bucket] += 1;
    }
    const critical = entry.summary.findings.find(
      (f) => f.state === "fail" && f.severity === "critical",
    );
    if (critical) {
      criticalMachines.push({
        computerId: entry.computerId,
        computerName: entry.computerName,
        room: entry.room,
        headline: critical,
      });
    }
  }

  criticalMachines.sort(
    (a, b) => SEVERITY_ORDER[a.headline.severity] - SEVERITY_ORDER[b.headline.severity],
  );

  return {
    computers: summaries.length,
    withFailures: summaries.filter((s) => s.summary.failing > 0).length,
    checks: passing + failing + unknown,
    passing,
    failing,
    unknown,
    byCategory,
    criticalMachines,
  };
}

/**
 * Correlates per-machine posture into compound and fleet-wide findings.
 *
 * Three patterns, kept deliberately small because each one has to be plainly
 * explainable to whoever reads the dashboard:
 *
 * 1. **Same-finding wave.** When more than half the evaluated machines fail the
 *    *same* check, singleton failures stop being coincidence — the lab image or
 *    the deployment is systematically wrong. This is the insight an individual
 *    machine list can never show.
 * 2. **Silent and unprotected.** A machine both off the radar *and* with AV off
 *    is an incident, not two open tickets: anything could have happened while
 *    nothing was watching.
 * 3. **Exclusions and silent.** AV exclusions that exist *and* no agent contact
 *    is the evasion signature: something deleted the agent's view while knowing
 *    exactly where not to look.
 */
export function correlateLab(
  summaries: Array<{
    computerId: number;
    computerName: string;
    room: string;
    summary: PostureSummary;
  }>,
): LabFinding[] {
  const findings: LabFinding[] = [];

  // ---- Rule 1: waves -------------------------------------------------------
  const failingByCheck = new Map<
    string,
    { computerId: number; computerName: string; room: string; finding: PostureFinding }[]
  >();
  for (const entry of summaries) {
    for (const f of entry.summary.findings) {
      if (f.state !== "fail") continue;
      const list = failingByCheck.get(f.id) ?? [];
      list.push({
        computerId: entry.computerId,
        computerName: entry.computerName,
        room: entry.room,
        finding: f,
      });
      failingByCheck.set(f.id, list);
    }
  }

  const total = Math.max(1, summaries.length);
  for (const [checkId, members] of failingByCheck) {
    if (members.length < 3 || members.length / total <= 0.5) continue;
    const example = members[0]!.finding;
    const names = members.map((m) => m.computerName).join(", ");
    findings.push({
      id: `wave:${checkId}`,
      title: `Whole-lab failure: ${example.title.toLowerCase()}`,
      severity: example.severity,
      detail: `${members.length} of ${summaries.length} machines fail the same check (${names}). This is a fleet problem — the image or the rollout is wrong — not ${members.length} independent accidents.`,
      remediation:
        "Fix the baseline once: repair the lab image, re-push the agent or reapply the policy, then let the wave clear on the next heartbeat.",
      category: example.category,
      affected: members.length,
      total: summaries.length,
      computerIds: members.map((m) => m.computerId),
    });
  }

  // ---- Rules 2 & 3: compounding on one machine ----------------------------
  for (const entry of summaries) {
    const byId = new Map(entry.summary.findings.map((f) => [f.id, f]));
    const silent = byId.get("agent_silent");
    const active =
      silent && silent.state === "fail" &&
      (byId.get("av_disabled")?.state === "fail" ||
        byId.get("av_realtime_off")?.state === "fail");
    if (active) {
      findings.push({
        id: `silent_unprotected:${entry.computerId}`,
        title: "Machine is both unreachable and unprotected",
        severity: "critical",
        detail: `${entry.computerName} has had no agent contact and its antivirus is off. A machine nobody is watching and nothing is protecting may have been taken off the network deliberately.`,
        remediation:
          "Physically check the machine. An unreachable, unprotected lab PC is the one scenario the dashboard cannot resolve remotely.",
        category: "detection",
        affected: 1,
        total: summaries.length,
        computerIds: [entry.computerId],
      });
    }

    const evasive =
      byId.get("av_exclusions")?.state === "fail" &&
      byId.get("agent_silent")?.state === "fail";
    if (evasive) {
      findings.push({
        id: `evasive:${entry.computerId}`,
        title: "AV exclusions on a machine the agent no longer reaches",
        severity: "high",
        detail: `${entry.computerName} has scan exclusions configured and its agent has gone silent. That exact combination is how malware hides.`,
        remediation:
          "Reach the machine by hand, review the exclusion list, and get the agent reporting again.",
        category: "detection",
        affected: 1,
        total: summaries.length,
        computerIds: [entry.computerId],
      });
    }
  }

  return findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      b.affected - a.affected,
  );
}

// ---------------------------------------------------------------------------
// VPS telemetry correlation — the same "SOC across machines" math, but for
// what the Linux agents report: brute-force spikes, config drift and package
// risk. Called by the platform Blue Team alongside correlateLab.
// ---------------------------------------------------------------------------

export interface VpsTelemetryRow {
  computerId: number;
  computerName: string;
  room: string;
  os?: string | null;
  authFailures?: PostureComputer["authFailures"];
  fimState?: PostureComputer["fimState"];
  packages?: PostureComputer["packages"];
}

export function correlateVpsTelemetry(rows: VpsTelemetryRow[]): LabFinding[] {
  const findings: LabFinding[] = [];
  const total = Math.max(1, rows.length);

  // 1. Brute-force spike — one machine is being hammered, or several are.
  const spiked = rows.filter((row) => (row.authFailures?.count24h ?? 0) >= VPS_AUTHFAIL_THRESHOLD);
  if (spiked.length === 1) {
    const row = spiked[0]!;
    findings.push({
      id: `vps_bruteforce:${row.computerId}`,
      title: "VPS under active ssh brute-force",
      severity: "high",
      detail: `${row.computerName} saw ${row.authFailures?.count24h ?? 0} failed ssh logins in the last 24 hours.`,
      remediation:
        "Rotate exposed credentials, restrict SSH to known IPs, and enable SSH rate limiting from Blue Team → VPS actions.",
      category: "detection",
      affected: 1,
      total,
      computerIds: [row.computerId],
    });
  } else if (spiked.length > 1) {
    const names = spiked.map((s) => s.computerName).join(", ");
    findings.push({
      id: "vps_bruteforce_wave",
      title: "Multiple VPS under ssh brute-force",
      severity: "high",
      detail: `${spiked.length} server(s) logged ${spiked
        .map((s) => `${s.computerName} (${s.authFailures?.count24h ?? 0})`)
        .join(", ")} failed logins in 24 hours. Same-attacker signature.`,
      remediation:
        "Block the common source IPs at the firewall, rotate every exposed credential, and enable SSH rate limiting fleet-wide.",
      category: "detection",
      affected: spiked.length,
      total,
      computerIds: spiked.map((s) => s.computerId),
    });
  }

  // 2. Possible active intrusion — brute-force spike AND config drift on the
  //    same host is what a compromise looks like from a posture engine.
  for (const row of rows) {
    const hammered = (row.authFailures?.count24h ?? 0) >= VPS_AUTHFAIL_THRESHOLD;
    const drifted = row.fimState?.status === "drift";
    if (hammered && drifted) {
      findings.push({
        id: `vps_compromised:${row.computerId}`,
        title: "Possible active intrusion on a VPS",
        severity: "critical",
        detail: `${row.computerName} is under ssh brute-force AND its protected config files changed. Treat as compromised until proven otherwise.`,
        remediation:
          "Disconnect the server, preserve the disk image and review /var/log/auth.log and the changed files. Do not just reboot it.",
        category: "detection",
        affected: 1,
        total,
        computerIds: [row.computerId],
      });
    }
  }

  // 3. Vulnerable fleet — two or more distinct servers carrying EOL packages
  //    is a rollout problem, not independent accidents.
  const withVulns = rows.filter((row) => findVulnerablePackages(row.packages).length > 0);
  if (withVulns.length >= 2) {
    const names = withVulns.map((s) => s.computerName).join(", ");
    findings.push({
      id: "vps_vuln_wave",
      title: "End-of-life software across servers",
      severity: "medium",
      detail: `${withVulns.length} server(s) run packages from end-of-life series (${names}). One lapse is a mistake; several is a base image problem.`,
      remediation:
        "Fix the base image or update policy once, then re-patch every affected server from the distro repo.",
      category: "configuration",
      affected: withVulns.length,
      total,
      computerIds: withVulns.map((s) => s.computerId),
    });
  }

  return findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      b.affected - a.affected,
  );
}
