import { and, eq, gt } from "drizzle-orm";
import type { NextFunction, Request, Response } from "express";
import { randomBytes } from "node:crypto";
import {
  appUsersTable,
  authSessionsPlatformTable,
  authSessionsTable,
  db,
  platformUsersTable,
} from "@workspace/db";
import {
  SUBMENUS,
  type SubmenuKey,
  type UserRole,
} from "@workspace/api-zod";
import { logger } from "./logger";
import { hashPassword } from "./passwords";

// ---------------------------------------------------------------------------
// Request augmentation
// ---------------------------------------------------------------------------

export interface AuthUser {
  id: number;
  username: string;
  role: UserRole;
  submenuAccess: SubmenuKey[];
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
      platformAdmin?: PlatformAdminUser;
    }
  }
}

export interface PlatformAdminUser {
  id: number;
  username: string;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export const SESSION_COOKIE = "lcc_session";
export const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export const sessionCookieOptions = {
  httpOnly: true,
  sameSite: "lax" as const,
  path: "/",
  maxAge: SESSION_TTL_MS,
  // Send the session token over TLS only. Defaults to on unless explicitly
  // disabled, so a plain-HTTP local dev server still works.
  secure: process.env.COOKIE_SECURE !== "false",
};

export function generateSessionToken(): string {
  return randomBytes(32).toString("hex");
}

export async function createSession(
  userId: number,
  token: string,
): Promise<void> {
  await db.insert(authSessionsTable).values({
    id: token,
    userId,
    expiresAt: new Date(Date.now() + SESSION_TTL_MS),
  });
}

export async function deleteSession(token: string): Promise<void> {
  await db.delete(authSessionsTable).where(eq(authSessionsTable.id, token));
}

// Parses a raw `Cookie:` header. Needed for the WebSocket upgrade request,
// which never passes through `cookie-parser`.
export function parseCookieHeader(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 1) continue;
    const name = part.slice(0, eq).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[name] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

// Resolves a session from a raw cookie header string. Caller must already be
// inside the correct tenant context (`runInTenant`), because `auth_sessions`
// lives in the tenant schema.
export async function resolveSessionFromCookieHeader(
  cookieHeader: string | undefined,
): Promise<AuthUser | null> {
  const token = parseCookieHeader(cookieHeader)[SESSION_COOKIE] ?? "";
  if (!token) return null;

  const [row] = await db
    .select()
    .from(authSessionsTable)
    .innerJoin(appUsersTable, eq(authSessionsTable.userId, appUsersTable.id))
    .where(
      and(
        eq(authSessionsTable.id, token),
        gt(authSessionsTable.expiresAt, new Date()),
      ),
    )
    .limit(1);

  if (!row) return null;

  return {
    id: row.app_users.id,
    username: row.app_users.username,
    role: row.app_users.role as UserRole,
    submenuAccess: row.app_users.submenuAccess as SubmenuKey[],
  };
}

export async function resolveSession(req: Request): Promise<AuthUser | null> {
  const header = req.headers.cookie;
  const fromHeader = await resolveSessionFromCookieHeader(header);
  if (fromHeader) return fromHeader;
  // Fall back to the parsed cookie bag for tests/middleware that populate
  // `req.cookies` directly.
  const token = typeof req.cookies?.[SESSION_COOKIE] === "string"
    ? req.cookies[SESSION_COOKIE]
    : "";
  if (!token) return null;
  return resolveSessionFromCookieHeader(`${SESSION_COOKIE}=${token}`);
}

// ---------------------------------------------------------------------------
// Submenu routing for per-submenu access control
// ---------------------------------------------------------------------------
// Admin users only reach APIs belonging to submenus listed in their
// `submenu_access`. Super admins bypass this entirely. Routes are matched in
// order; a path may map to several submenus (any match grants access). The
// special "*" submenu marks routes every authenticated admin may use (the
// read-only computer/alert lists are needed by many dashboard pages). A path
// that matches nothing is denied for admin users (fail closed).

type SubmenuGrant = SubmenuKey | "*";

const SUBMENU_ROUTES: Array<{ test: (path: string, method: string) => boolean; submenu: SubmenuGrant }> = [
  { test: (p, m) => m === "GET" && p === "/api/lab/computers", submenu: "*" },
  { test: (p, m) => m === "GET" && p === "/api/lab/alerts", submenu: "*" },
  { test: (p) => p === "/api/lab/summary", submenu: "overview" },
  { test: (p) => p.startsWith("/api/lab/computers/") && p.includes("/files/browse"), submenu: "files" },
  { test: (p) => p.startsWith("/api/lab/computers/"), submenu: "computers" },
  { test: (p) => p === "/api/lab/computers", submenu: "computers" },
  { test: (p) => p.startsWith("/api/lab/alerts"), submenu: "alerts" },
  { test: (p) => p.startsWith("/api/lab/usb-policies"), submenu: "usb_policies" },
  { test: (p) => p.startsWith("/api/lab/usb-devices"), submenu: "usb_policies" },
  { test: (p) => p.startsWith("/api/lab/student-sessions"), submenu: "sessions" },
  { test: (p) => p.startsWith("/api/lab/events"), submenu: "events" },
  { test: (p) => p.startsWith("/api/lab/settings"), submenu: "settings" },
  { test: (p) => p.startsWith("/api/lab/checkins"), submenu: "checkins" },
  { test: (p) => p.startsWith("/api/lab/peripherals"), submenu: "peripherals" },
  { test: (p) => p.startsWith("/api/lab/files/screenshots/"), submenu: "checkins" },
  { test: (p) => p.startsWith("/api/lab/files/screenshots/"), submenu: "computers" },
  { test: (p) => p.startsWith("/api/lab/files/"), submenu: "files" },
  { test: (p) => p === "/api/lab/files", submenu: "files" },
  { test: (p) => p.startsWith("/api/reports/"), submenu: "reports" },
  { test: (p) => p === "/api/reports", submenu: "reports" },
  { test: (p) => p.startsWith("/api/security/"), submenu: "antivirus" },
  { test: (p) => p.startsWith("/api/security/"), submenu: "firewall" },
  { test: (p) => p.startsWith("/api/blue-team/"), submenu: "blue_team" },
  { test: (p) => p.startsWith("/api/users"), submenu: "users" },
];

// The tenant API is mounted under `/t/:slug/api`, so `req.originalUrl` carries
// the tenant prefix. Strip it so submenu matching works on the plain API path.
export function apiPath(req: Request): string {
  const url = req.originalUrl ?? req.url;
  const stripped = url.replace(/^\/t\/[^/]+\/api/, "");
  return stripped.split("?")[0];
}

export function submenusForPath(path: string, method: string): SubmenuGrant[] {
  const normalized = path.split("?")[0];
  return SUBMENU_ROUTES
    .filter((entry) => entry.test(normalized, method))
    .map((entry) => entry.submenu);
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const user = await resolveSession(req);
  if (!user) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  req.user = user;
  next();
}

export function requireSubmenuAccess(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const user = req.user;
  if (!user) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  if (user.role === "super_admin") {
    next();
    return;
  }

  const submenus = submenusForPath(apiPath(req), req.method);
  if (submenus.length === 0) {
    res.status(403).json({ error: "Forbidden" });
    return;
  }
  if (
    submenus.includes("*") ||
    submenus.some((submenu) => submenu !== "*" && user.submenuAccess.includes(submenu))
  ) {
    next();
    return;
  }
  res.status(403).json({ error: "You do not have access to this section" });
}

// Whether a user may use a given submenu. Super admins bypass, and "*" is the
// wildcard grant meaning "every authenticated admin". Used by the WebSocket
// tunnel, which cannot rely on path-based matching.
export function hasSubmenuAccess(
  user: AuthUser,
  submenu: SubmenuKey,
): boolean {
  if (user.role === "super_admin") return true;
  if (user.submenuAccess.includes("*" as SubmenuKey)) return true;
  return user.submenuAccess.includes(submenu);
}

export function requireSuperAdmin(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const user = req.user;
  if (!user) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  if (user.role !== "super_admin") {
    res.status(403).json({ error: "Super admin access required" });
    return;
  }
  next();
}

// ---------------------------------------------------------------------------
// Platform admin auth
// ---------------------------------------------------------------------------
// The platform owner is the sole operator of the multi-tenant system. They log
// in through a dedicated endpoint and dashboard, and manage tenants (approval,
// suspension, deletion, password resets). Sessions live in the public schema.

export const PLATFORM_COOKIE = "lcc_platform_session";

export const platformSessionCookieOptions = {
  httpOnly: true,
  sameSite: "lax" as const,
  path: "/",
  maxAge: SESSION_TTL_MS,
  secure: process.env.COOKIE_SECURE !== "false",
};

export async function createPlatformSession(
  userId: number,
  token: string,
): Promise<void> {
  await db.insert(authSessionsPlatformTable).values({
    id: token,
    userId,
    expiresAt: new Date(Date.now() + SESSION_TTL_MS),
  });
}

export async function deletePlatformSession(token: string): Promise<void> {
  await db
    .delete(authSessionsPlatformTable)
    .where(eq(authSessionsPlatformTable.id, token));
}

export async function resolvePlatformSession(
  req: Request,
): Promise<PlatformAdminUser | null> {
  const token = typeof req.cookies?.[PLATFORM_COOKIE] === "string"
    ? req.cookies[PLATFORM_COOKIE]
    : "";
  if (!token) return null;

  const [row] = await db
    .select()
    .from(authSessionsPlatformTable)
    .innerJoin(platformUsersTable, eq(authSessionsPlatformTable.userId, platformUsersTable.id))
    .where(
      and(
        eq(authSessionsPlatformTable.id, token),
        gt(authSessionsPlatformTable.expiresAt, new Date()),
      ),
    )
    .limit(1);

  if (!row) return null;

  return {
    id: row.platform_users.id,
    username: row.platform_users.username,
  };
}

export async function requirePlatformAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const admin = await resolvePlatformSession(req);
  if (!admin) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  req.platformAdmin = admin;
  next();
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

export async function seedPlatformAdmin(): Promise<void> {
  const username = process.env.PLATFORM_ADMIN_USERNAME?.trim();
  const password = process.env.PLATFORM_ADMIN_PASSWORD;
  if (!username || !password) {
    return;
  }
  if (password.length < 6) {
    logger.warn("PLATFORM_ADMIN_PASSWORD is too short; platform admin not synced");
    return;
  }

  try {
    await db
      .insert(platformUsersTable)
      .values({ username, passwordHash: hashPassword(password) })
      .onConflictDoUpdate({
        target: platformUsersTable.username,
        set: { passwordHash: hashPassword(password) },
      });
    logger.info({ username }, "Platform admin synced from environment");
  } catch (err) {
    logger.warn({ err }, "Could not sync platform admin from environment");
  }
}

// Legacy alias kept for backwards compatibility with existing deployments
// that only set SUPER_ADMIN_*; the tenant super admin is provisioned at
// registration instead.
export async function seedSuperAdmin(): Promise<void> {
  await seedPlatformAdmin();
}
