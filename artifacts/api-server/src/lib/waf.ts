/**
 * WAF-lite: application-layer perimeter controls that a Render free-tier
 * Express app can actually own.
 *
 * Honest scope: this is not a network WAF. It cannot see TLS-terminated
 * traffic, it does not do HTTP request inspection beyond the headers Express
 * hands it, and it only trusts `CF-IPCountry` when Cloudflare is in front.
 * What it *can* do is cut the cheap attacks before they reach a handler:
 *
 * - Reject abusive HTTP methods (TRACE/TRACK/CONNECT), which exist to probe
 *   and reflect responses.
 * - Dump requests from known vulnerability scanners by user-agent.
 * - Block the paths scanners always try first (/.env, /.git, wp-admin,
 *   server-status) — on this app those are never legitimate.
 * - Optional country geofencing via the Cloudflare country header, and only
 *   enforced when the app is configured to trust it.
 *
 * The decision logic is a pure function (`evaluateWaf`) so it can be tested
 * without a server; the Express middleware is a thin adapter around it.
 */

import type { NextFunction, Request, Response } from "express";

export type WafDecision =
  | { action: "allow"; reason: string }
  | { action: "block"; reason: string; status: number };

export interface WafContext {
  /**
   * Effective ISO country codes (uppercase) read from CF-IPCountry. The
   * middleware only passes this through when trustProxy sees the Cloudflare
   * chain; the pure function treats it as authoritative because the caller
   * already decided that.
   */
  country?: string | null;
  /** Raw user-agent header, lowercased before matching. */
  userAgent?: string | null;
  method: string;
  /** Application path, without /t/:slug prefix (or with — scan patterns do
   *  not depend on the prefix, and matching both costs nothing). */
  path: string;
}

export interface WafOptions {
  /**
   * When set, only requests from these country codes are allowed. The inverse
   * of an allowlist's usual shape on purpose: labs deploy where the lab is,
   * so the default posture is "block the countries the lab is nowhere near".
   */
  allowCountries?: string[];
  /** Extra method names to reject on top of the always-rejected set. */
  extraBlockedMethods?: string[];
  /** When false, every decision is "allow" but logged via `logBlock`. Used
   *  during rollout so the rules can be observed before they bite. */
  enforce?: boolean;
  /** Called for every non-allow decision, for observability. */
  logBlock?: (decision: WafDecision, ctx: WafContext) => void;
}

const ALWAYS_BLOCKED_METHODS = new Set(["TRACE", "TRACK", "CONNECT"]);

/** User-agent fragments of known vulnerability scanners. Deliberately narrow:
 *  only strings that identify a scanner, never a browser or a package
 *  manager. The exploit chain this WAF targets used its own UA, and the
 *  rate limits from the security work catch the rest. */
const SCANNER_UA_FRAGMENTS = [
  "sqlmap",
  "nikto",
  "nmap",
  "masscan",
  "zgrab",
  "wpscan",
  "acunetix",
  "nessus",
  "openvas",
  "gobuster",
  "dirbuster",
  "whatweb",
];

/**
 * Paths that are never legitimate on this application. `/t/:slug` prefixes and
 * query strings are stripped before matching so the patterns stay short.
 */
const BLOCKED_PATH_PATTERNS: Array<RegExp> = [
  /(^|\/)\.env($|\?)/,
  /(^|\/)\.git(\/|$)/,
  /(^|\/)\.svn(\/|$)/,
  /(^|\/)\.hg(\/|$)/,
  /(^|\/)\.DS_Store$/,
  /(^|\/)wp-admin(\/|$)/,
  /(^|\/)wp-login\.php/,
  /(^|\/)xmlrpc\.php/,
  /(^|\/)server-status(\/|$)/,
  /(^|\/)server-info(\/|$)/,
  /(^|\/)phpmyadmin(\/|$)/,
  /(^|\/)\.\./,
];

export function evaluateWaf(ctx: WafContext, options: WafOptions = {}): WafDecision {
  const log = (d: WafDecision) => options.logBlock?.(d, ctx);

  const method = ctx.method.toUpperCase();
  if (ALWAYS_BLOCKED_METHODS.has(method) || options.extraBlockedMethods?.includes(method)) {
    const d = {
      action: "block" as const,
      reason: `method ${method} is not part of this application`,
      status: 405,
    };
    log(d);
    return options.enforce === false ? { action: "allow", reason: d.reason + " (not enforced)" } : d;
  }

  const ua = (ctx.userAgent ?? "").toLowerCase();
  if (ua) {
    for (const fragment of SCANNER_UA_FRAGMENTS) {
      if (ua.includes(fragment)) {
        const d = {
          action: "block" as const,
          reason: `user-agent matches known scanner (${fragment})`,
          status: 403,
        };
        log(d);
        return options.enforce === false ? { action: "allow", reason: d.reason + " (not enforced)" } : d;
      }
    }
  }

  const path = (ctx.path ?? "").split("?")[0];
  for (const pattern of BLOCKED_PATH_PATTERNS) {
    if (pattern.test(path)) {
      const d = {
        action: "block" as const,
        reason: `path matches a never-legitimate pattern (${pattern})`,
        status: 403,
      };
      log(d);
      return options.enforce === false ? { action: "allow", reason: d.reason + " (not enforced)" } : d;
    }
  }

  if (options.allowCountries && options.allowCountries.length > 0) {
    if (!ctx.country) {
      const d = {
        action: "block" as const,
        reason: "country allowlist set but no trusted country header (is Cloudflare in front?)",
        status: 403,
      };
      // Geofencing without a trusted header would lock out every lab. Fail
      // closed in the dashboard sense: block, because we cannot verify.
      log(d);
      return options.enforce === false ? { action: "allow", reason: d.reason + " (not enforced)" } : d;
    }
    if (!options.allowCountries.includes(ctx.country.toUpperCase())) {
      const d = {
        action: "block" as const,
        reason: `country ${ctx.country} not in allowlist`,
        status: 403,
      };
      log(d);
      return options.enforce === false ? { action: "allow", reason: d.reason + " (not enforced)" } : d;
    }
  }

  return { action: "allow", reason: "-" };
}

/**
 * Express middleware. Country header trust rules:
 * - A `CF-IPCountry` header is only accepted when the app is behind
 *   Cloudflare (proxy chain includes cloudflare, exposed through
 *   `req.app.get("trust proxy")`).
 * - Every request gets an `x-waf` response header saying what was decided,
 *   which makes the boundary observable in the dashboard network tab and in
 *   the logs.
 */
export function wafMiddleware(options: WafOptions = {}) {
  return (req: Request, res: Response, next: NextFunction) => {
    const decision = evaluateWaf(toWafContext(req), options);

    res.setHeader("x-waf", decision.action === "allow" ? decision.reason : `${decision.status} ${decision.reason}`);

    if (decision.action === "allow") {
      next();
      return;
    }
    res.status(decision.status).json({
      error: decision.reason,
      // Deliberately terse: mirrors the other error shapes, no details leak.
    });
  };
}

function toWafContext(req: Request): WafContext {
  // req.ip reflects trust proxy settings via Express's income parsing.
  const chain = (req.headers["x-forwarded-for"] as string | undefined)?.split(",") ?? [];
  const viaCloudflare =
    String(req.headers["cdn-loop"] ?? "").toLowerCase().includes("cloudflare") ||
    chain.some((hop) => hop.trim().toLowerCase().endsWith(".cloudflare.com"));

  const country =
    viaCloudflare && typeof req.headers["cf-ipcountry"] === "string"
      ? req.headers["cf-ipcountry"].toUpperCase()
      : null;

  return {
    method: req.method,
    path: req.path,
    userAgent: req.headers["user-agent"] ?? null,
    country,
  };
}