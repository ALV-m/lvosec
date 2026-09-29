import * as zod from "zod";

export const SUBMENUS = [
  "overview",
  "computers",
  "alerts",
  "usb_policies",
  "antivirus",
  "firewall",
  "peripherals",
  "sessions",
  "reports",
  "files",
  "events",
  "checkins",
  "agent",
  "blue_team",
  "settings",
  "users",
] as const;

export const SubmenuKey = zod.enum(SUBMENUS);
export type SubmenuKey = zod.infer<typeof SubmenuKey>;

export const UserRole = zod.enum(["super_admin", "admin"]);
export type UserRole = zod.infer<typeof UserRole>;

export const UserAccount = zod.object({
  id: zod.number(),
  username: zod.string(),
  role: UserRole,
  submenuAccess: zod.array(SubmenuKey),
  createdAt: zod.string(),
});
export type UserAccount = zod.infer<typeof UserAccount>;

export const LoginBody = zod.object({
  username: zod.string().trim().min(1).max(100),
  password: zod.string().min(1).max(200),
});

export const LoginLinkBody = zod.object({
  link: zod.string().trim().min(1).max(256),
});

export const CreateLoginLinkResponse = zod.object({
  url: zod.string(),
});

export const LoginResponse = zod.object({
  token: zod.string(),
  user: UserAccount,
});

export const AuthMeResponse = zod.object({
  user: UserAccount,
});

export const LogoutResponse = zod.object({
  ok: zod.boolean(),
});

// Result of the platform-wide login at `POST /api/login`. The same page signs
// in both the platform admin and lab accounts, so the response discriminates
// on `type` so the client can route to `/admin` or `/t/:slug` respectively.
export const DiscoverLoginResponse = zod.discriminatedUnion("type", [
  zod.object({
    type: zod.literal("platform"),
    user: zod.object({
      id: zod.number(),
      username: zod.string(),
      createdAt: zod.string(),
    }),
  }),
  zod.object({
    type: zod.literal("tenant"),
    tenantSlug: zod.string(),
    tenantName: zod.string(),
    user: UserAccount,
  }),
]);
export type DiscoverLoginResponse = zod.infer<typeof DiscoverLoginResponse>;

export const UserCreateBody = zod.object({
  username: zod.string().trim().min(1).max(100),
  password: zod.string().min(6).max(200),
  role: UserRole,
  submenuAccess: zod.array(SubmenuKey).min(1),
});

export const UserUpdateBody = zod.object({
  password: zod.string().min(6).max(200).optional(),
  role: UserRole.optional(),
  submenuAccess: zod.array(SubmenuKey).min(1).optional(),
});

export const UserIdParams = zod.object({
  userId: zod.coerce.number(),
});

export const UsersListResponse = zod.object({
  users: zod.array(UserAccount),
});
