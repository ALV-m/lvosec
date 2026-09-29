import { describe, expect, it } from "vitest";
import {
  compareVersions,
  correlateLab,
  evaluatePosture,
  summariseLab,
  type PostureContext,
  type PostureSeverity,
  type SecuritySignals,
} from "../src/lib/blue-team/posture";

const NOW = new Date("2026-09-29T12:00:00.000Z");

/** A machine reporting a fully healthy, fully-known state. */
function healthySignals(): SecuritySignals {
  return {
    avEnabled: true,
    avRealtimeProtection: true,
    avTamperProtection: true,
    avDisabledByPolicy: false,
    avExclusionCount: 0,
    avSignatureAgeDays: 0,
    firewallEnabled: true,
    firewallAllProfiles: true,
    smb1Enabled: false,
    smbSigningRequired: true,
    rdpEnabled: false,
    bitlockerEnabled: true,
    tpmPresent: true,
    guestAccountEnabled: false,
    screenLockEnabled: true,
    autorunEnabled: false,
    windowsUpdateDisabled: false,
    secureBootEnabled: true,
    uacEnabled: true,
    localAdminCount: 1,
    autoLogonEnabled: false,
  };
}

function context(overrides: Partial<PostureContext> = {}): PostureContext {
  return {
    computer: {
      id: 1,
      name: "LAB-PC-01",
      room: "Room A",
      status: "online",
      os: "Windows 11 Pro",
      lastSeen: new Date(NOW.getTime() - 30_000),
      agentVersion: "1.20.0",
      diskFree: 100_000_000_000,
      diskTotal: 256_000_000_000,
    },
    settings: { signin_method: "password" },
    security: healthySignals(),
    bundledAgentVersion: "1.20.0",
    now: NOW,
    ...overrides,
  };
}

function failed(summary: ReturnType<typeof evaluatePosture>, id: string) {
  return summary.findings.find((f) => f.id === id);
}

describe("posture engine", () => {
  it("reports every check as passing for a healthy, fully-reported machine", () => {
    const summary = evaluatePosture(context());
    expect(summary.failing).toBe(0);
    expect(summary.bySeverity.critical).toBe(0);
    expect(summary.headline).toBeNull();
    // Nothing may silently drop out of the evaluation.
    expect(summary.evaluated).toBe(summary.total);
  });

  it("treats absent data as unknown, never as pass", () => {
    // An agent that reports nothing must not produce a clean bill of health.
    const summary = evaluatePosture(context({ security: {} }));
    expect(summary.failing).toBe(0);
    expect(summary.evaluated).toBeLessThan(summary.total);
    expect(failed(summary, "av_disabled")?.state).toBe("unknown");
    expect(failed(summary, "firewall_off")?.state).toBe("unknown");
    expect(failed(summary, "av_disabled")?.severity).toBe("info");
    // The whole point: coverage is visible alongside results.
    const unknown = summary.findings.filter((f) => f.state === "unknown");
    expect(unknown.length).toBeGreaterThan(15);
  });

  // The finding this engine exists for.
  describe("sign-in gate consistency", () => {
    it("flags auto-login left on while a password is required as critical", () => {
      const summary = evaluatePosture(
        context({
          settings: { signin_method: "password" },
          security: { ...healthySignals(), autoLogonEnabled: true },
        }),
      );
      const gate = failed(summary, "signin_gate_bypassed");
      expect(gate?.state).toBe("fail");
      expect(gate?.severity).toBe("critical");
      expect(summary.headline?.id).toBe("signin_gate_bypassed");
    });

    it("flags auto-login off when the lab needs it as high", () => {
      const summary = evaluatePosture(
        context({
          settings: { signin_method: "shared_account" },
          security: { ...healthySignals(), autoLogonEnabled: false },
        }),
      );
      const gate = failed(summary, "signin_gate_missing");
      expect(gate?.state).toBe("fail");
      expect(gate?.severity).toBe("high");
    });

    it("passes when the gate matches the configured method", () => {
      // Auto-login on is *correct* for a shared-account lab, not a finding.
      const summary = evaluatePosture(
        context({
          settings: { signin_method: "shared_account" },
          security: { ...healthySignals(), autoLogonEnabled: true },
        }),
      );
      expect(failed(summary, "signin_gate_enforced")?.state).toBe("pass");
      expect(summary.failing).toBe(0);
    });

    it("says so when it cannot verify the gate", () => {
      const summary = evaluatePosture(context({ security: { ...healthySignals(), autoLogonEnabled: null } }));
      expect(failed(summary, "signin_gate_unverifiable")?.state).toBe("unknown");
      expect(summary.failing).toBe(0);
    });
  });

  describe("detection coverage", () => {
    it("treats disabled real-time protection as critical", () => {
      const summary = evaluatePosture(
        context({ security: { ...healthySignals(), avRealtimeProtection: false } }),
      );
      expect(failed(summary, "av_realtime_off")?.severity).toBe("critical");
    });

    it("treats a single AV exclusion as a failure", () => {
      const summary = evaluatePosture(
        context({ security: { ...healthySignals(), avExclusionCount: 1 } }),
      );
      const f = failed(summary, "av_exclusions");
      expect(f?.state).toBe("fail");
      expect(f?.detail).toContain("1 path");
    });

    it("only calls definitions stale past the threshold", () => {
      const fresh = evaluatePosture(
        context({ security: { ...healthySignals(), avSignatureAgeDays: 7 } }),
      );
      expect(failed(fresh, "av_signature_stale")?.state).toBe("pass");

      const stale = evaluatePosture(
        context({ security: { ...healthySignals(), avSignatureAgeDays: 30 } }),
      );
      expect(failed(stale, "av_signature_stale")?.state).toBe("fail");
    });
  });

  describe("agent health", () => {
    it("flags a machine that stopped reporting", () => {
      const summary = evaluatePosture(
        context({
          computer: {
            ...context().computer,
            lastSeen: new Date(NOW.getTime() - 30 * 60_000),
          },
        }),
      );
      const f = failed(summary, "agent_silent");
      expect(f?.state).toBe("fail");
      expect(f?.detail).toContain("30 minutes");
    });

    it("flags an agent behind the shipped version", () => {
      const summary = evaluatePosture(
        context({ computer: { ...context().computer, agentVersion: "1.18.0" } }),
      );
      expect(failed(summary, "agent_outdated")?.state).toBe("fail");
    });

    it("does not flag an agent ahead of the server", () => {
      // A PC can update during a rolling deploy; that is not a fault.
      const summary = evaluatePosture(
        context({ computer: { ...context().computer, agentVersion: "2.0.0" } }),
      );
      expect(failed(summary, "agent_outdated")?.state).toBe("pass");
    });
  });

  describe("ordering and aggregation", () => {
    it("puts the worst failure first", () => {
      const summary = evaluatePosture(
        context({
          settings: { signin_method: "password" },
          security: {
            ...healthySignals(),
            autoLogonEnabled: true,
            firewallEnabled: false,
            uacEnabled: false,
          },
        }),
      );
      expect(summary.findings[0]?.id).toBe("signin_gate_bypassed");
      const severities = summary.findings
        .filter((f) => f.state === "fail")
        .map((f) => f.severity);
      expect(severities[0]).toBe("critical");
    });

    it("aggregates a lab and surfaces the machines that need a human", () => {
      const good = evaluatePosture(context());
      const bad = evaluatePosture(
        context({
          computer: { ...context().computer, id: 2, name: "LAB-PC-02", room: "Room B" },
          settings: { signin_method: "password" },
          security: { ...healthySignals(), autoLogonEnabled: true, avRealtimeProtection: false },
        }),
      );
      const agg = summariseLab([
        { computerId: 1, computerName: "LAB-PC-01", room: "Room A", summary: good },
        { computerId: 2, computerName: "LAB-PC-02", room: "Room B", summary: bad },
      ]);

      expect(agg.computers).toBe(2);
      expect(agg.withFailures).toBe(1);
      expect(agg.criticalMachines).toHaveLength(1);
      expect(agg.criticalMachines[0]?.computerName).toBe("LAB-PC-02");
      // Coverage is reported so a mostly-unknown lab is not read as healthy.
      expect(agg.unknown).toBe(0);
      expect(agg.failing).toBeGreaterThan(0);
    });

    it("counts a lab where nothing is reported as entirely unknown", () => {
      const blind = evaluatePosture(
        context({
          security: {},
          computer: {
            id: 3,
            name: "LAB-PC-03",
            room: "Room C",
            status: "offline",
            os: null,
            lastSeen: null,
            agentVersion: null,
            // A machine the agent never reaches does not report disk either.
            diskFree: null,
            diskTotal: null,
          },
        }),
      );
      const agg = summariseLab([
        { computerId: 3, computerName: "LAB-PC-03", room: "Room C", summary: blind },
      ]);
      expect(agg.failing).toBe(0);
      expect(agg.passing).toBe(0);
      expect(agg.unknown).toBe(agg.checks);
      expect(agg.withFailures).toBe(0);
    });
  });

  describe("compareVersions", () => {
    it("orders correctly, including uneven lengths", () => {
      expect(compareVersions("1.20.0", "1.20.0")).toBe(0);
      expect(compareVersions("1.18.0", "1.20.0")).toBeLessThan(0);
      expect(compareVersions("1.20.0", "1.18.0")).toBeGreaterThan(0);
      expect(compareVersions("1.20", "1.20.0")).toBe(0);
      expect(compareVersions("1.20.1", "1.20")).toBeGreaterThan(0);
      expect(compareVersions("2.0.0", "1.99.99")).toBeGreaterThan(0);
    });
  });

  it("gives every check a remediation, because a finding with no action is noise", () => {
    const summary = evaluatePosture(context());
    const all: PostureSeverity[] = ["critical", "high", "medium", "low", "info"];
    for (const f of summary.findings) {
      expect(f.remediation.length).toBeGreaterThan(0);
      expect(all).toContain(f.severity);
      if (f.state === "pass" || f.state === "unknown") {
        expect(f.title.length).toBeGreaterThan(0);
      }
    }
  });
});

describe("correlation engine", () => {
  function entry(name: string, id: number, summary: ReturnType<typeof evaluatePosture>) {
    return { computerId: id, computerName: name, room: "Room A", summary };
  }

  it("surfaces a whole-lab failure wave as one fleet problem", () => {
    // Three of four machines with the firewall off: a wave, not accidents.
    const entries = [];
    for (let i = 1; i <= 4; i += 1) {
      const unhealthy = i < 4;
      const summary = evaluatePosture(
        context({
          computer: { ...context().computer, id: i, name: `LAB-PC-0${i}` },
          security: unhealthy
            ? { ...healthySignals(), firewallEnabled: false }
            : healthySignals(),
        }),
      );
      entries.push(entry(`LAB-PC-0${i}`, i, summary));
    }
    const findings = correlateLab(entries);
    const wave = findings.find((f) => f.id === "wave:firewall_off");
    expect(wave).toBeDefined();
    expect(wave?.affected).toBe(3);
    expect(wave?.detail).toContain("fleet problem");
    expect(wave?.computerIds).toEqual([1, 2, 3]);
  });

  it("does not raise a wave when a minority fails", () => {
    // Two of four — real machines being individually broken, not a fleet issue.
    const entries = [];
    for (let i = 1; i <= 4; i += 1) {
      const unhealthy = i <= 2;
      const summary = evaluatePosture(
        context({
          computer: { ...context().computer, id: i, name: `LAB-PC-0${i}` },
          security: unhealthy
            ? { ...healthySignals(), firewallEnabled: false }
            : healthySignals(),
        }),
      );
      entries.push(entry(`LAB-PC-0${i}`, i, summary));
    }
    const findings = correlateLab(entries);
    expect(findings.find((f) => f.id === "wave:firewall_off")).toBeUndefined();
  });

  it("never raises a wave below three machines", () => {
    const entries = [];
    for (let i = 1; i <= 2; i += 1) {
      const summary = evaluatePosture(
        context({
          computer: { ...context().computer, id: i, name: `LAB-PC-0${i}` },
          security: { ...healthySignals(), firewallEnabled: false },
        }),
      );
      entries.push(entry(`LAB-PC-0${i}`, i, summary));
    }
    const findings = correlateLab(entries);
    expect(findings.find((f) => f.id === "wave:firewall_off")).toBeUndefined();
  });

  it("compounds a silent machine with antivirus off into a critical incident", () => {
    const summary = evaluatePosture(
      context({
        computer: {
          ...context().computer,
          id: 9,
          name: "LAB-PC-09",
          lastSeen: new Date(NOW.getTime() - 60 * 60_000),
        },
        security: { ...healthySignals(), avRealtimeProtection: false },
      }),
    );
    const findings = correlateLab([entry("LAB-PC-09", 9, summary)]);
    const compound = findings.find((f) => f.id === "silent_unprotected:9");
    expect(compound).toBeDefined();
    expect(compound?.severity).toBe("critical");
    expect(compound?.remediation).toContain("Physically check");
  });

  it("flags scan exclusions on a machine the agent stopped reaching", () => {
    const summary = evaluatePosture(
      context({
        computer: {
          ...context().computer,
          id: 11,
          name: "LAB-PC-11",
          lastSeen: new Date(NOW.getTime() - 3 * 60 * 60_000),
        },
        security: { ...healthySignals(), avExclusionCount: 2 },
      }),
    );
    const findings = correlateLab([entry("LAB-PC-11", 11, summary)]);
    const evasive = findings.find((f) => f.id === "evasive:11");
    expect(evasive).toBeDefined();
    expect(evasive?.severity).toBe("high");
  });

  it("does not compound a silent machine whose AV was last known good", () => {
    // Silence alone is a finding; silence + healthy AV is not an incident.
    const summary = evaluatePosture(
      context({
        computer: {
          ...context().computer,
          id: 12,
          name: "LAB-PC-12",
          lastSeen: new Date(NOW.getTime() - 60 * 60_000),
        },
      }),
    );
    const findings = correlateLab([entry("LAB-PC-12", 12, summary)]);
    expect(findings.find((f) => f.id === "silent_unprotected:12")).toBeUndefined();
  });

  it("orders compound findings by severity then breadth", () => {
    const silentUnprotected = evaluatePosture(
      context({
        computer: { ...context().computer, id: 1, name: "LAB-PC-01", lastSeen: new Date(NOW.getTime() - 60 * 60_000) },
        security: { ...healthySignals(), avRealtimeProtection: false },
      }),
    );
    const withWave = evaluatePosture(
      context({
        computer: { ...context().computer, id: 2, name: "LAB-PC-02" },
        security: { ...healthySignals(), firewallEnabled: false },
      }),
    );
    const entries = [entry("LAB-PC-01", 1, silentUnprotected), entry("LAB-PC-02", 2, withWave)];
    const findings = correlateLab(entries);
    expect(findings[0]?.id).toBe("silent_unprotected:1");
  });
});
