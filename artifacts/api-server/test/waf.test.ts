import { describe, expect, it, vi } from "vitest";
import { evaluateWaf } from "../src/lib/waf";

function req(overrides: Partial<Parameters<typeof evaluateWaf>[0]> = {}) {
  return {
    method: "GET",
    path: "/api/lab/computers",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126 Safari/537.36",
    country: null,
    ...overrides,
  };
}

type WafOptions = NonNullable<Parameters<typeof evaluateWaf>[1]>;

describe("WAF-lite", () => {
  it("allows an ordinary GET from a browser with no country policy", () => {
    expect(evaluateWaf(req())).toEqual({ action: "allow", reason: "-" });
  });

  it("allows the real agent traffic shape (PowerShell UA, POST, heartbeats)", () => {
    const d = evaluateWaf(
      req({ method: "POST", path: "/t/lab/api/agent/heartbeat", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsPowerShell/5.1.22621" }),
    );
    expect(d.action).toBe("allow");
  });

  it("rejects TRACE, TRACK and CONNECT", () => {
    for (const method of ["TRACE", "TRACK", "CONNECT"]) {
      const d = evaluateWaf(req({ method }));
      expect(d.action).toBe("block");
      expect(d.status).toBe(405);
    }
  });

  it("rejects methods added via extraBlockedMethods", () => {
    const d = evaluateWaf(req({ method: "PURGE" }), { extraBlockedMethods: ["PURGE"] });
    expect(d.action).toBe("block");
  });

  it("blocks known scanner user-agents", () => {
    for (const ua of ["sqlmap/1.7.2", "Mozilla Nikto/2.5.0", "nmap script", "zgrab/0.1", "gobuster/3.6"]) {
      const d = evaluateWaf(req({ userAgent: ua }));
      expect(d.action).toBe("block", `expected ${ua} blocked`);
    }
  });

  it("does not block a browser containing an innocent fragment", () => {
    // "map" and "scan" appear in legit UAs; only whole fragment words match.
    const d = evaluateWaf(req({ userAgent: "Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0" }));
    expect(d.action).toBe("allow");
  });

  it("blocks the paths scanners always try first", () => {
    for (const path of [
      "/.env",
      "/.git/config",
      "/t/slug/.env",
      "/wp-admin/install.php",
      "/wp-login.php",
      "/server-status",
      "/phpmyadmin/",
      "/.DS_Store",
      "/t/slug/../register",
    ]) {
      const d = evaluateWaf(req({ path }));
      expect(d.action).toBe("block", `expected ${path} blocked`);
    }
  });

  it("leaves legitimate paths alone, including the ones with lookalike segments", () => {
    for (const path of [
      "/",
      "/register",
      "/t/lab/api/agent/register",
      "/admin/login",
      "/api/healthz",
      "/t/lab/api/lab/computers",
    ]) {
      const d = evaluateWaf(req({ path }));
      expect(d.action).toBe("allow", `expected ${path} allowed`);
    }
  });

  describe("country allowlist", () => {
    it("blocks outside the allowlist", () => {
      const d = evaluateWaf(req({ country: "RU" }), { allowCountries: ["KE", "US", "GB"] });
      expect(d.action).toBe("block");
    });

    it("allows countries on the list, case-insensitively", () => {
      const d = evaluateWaf(req({ country: "us" }), { allowCountries: ["KE", "US", "GB"] });
      expect(d.action).toBe("allow");
    });

    it("blocks when the list is set but no trusted country header exists", () => {
      // Fail closed: a geofence with no header would either let everything
      // through or lock everything out. Block is the safe answer.
      const d = evaluateWaf(req({ country: null }), { allowCountries: ["US"] });
      expect(d.action).toBe("block");
      expect(d.reason).toContain("no trusted country header");
    });

    it("is inert without a configured allowlist", () => {
      const d = evaluateWaf(req({ country: null }));
      expect(d.action).toBe("allow");
    });
  });

  it("logs blocks and can run in observe mode without enforcing", () => {
    const log = vi.fn();
    const options: WafOptions = { enforce: false, logBlock: log };
    const d = evaluateWaf(req({ method: "TRACE" }), options);
    expect(d.action).toBe("allow");
    expect(log).toHaveBeenCalledTimes(1);
    expect(log.mock.calls[0]![0].reason).toContain("TRACE");
  });
});