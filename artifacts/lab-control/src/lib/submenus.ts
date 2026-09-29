import type { SubmenuKey } from "@workspace/api-client-react";

export const SUBMENU_LABELS: Record<SubmenuKey, string> = {
  overview: "Overview",
  computers: "Computers",
  alerts: "Alerts",
  usb_policies: "USB Policy",
  antivirus: "Antivirus",
  firewall: "Firewall",
  peripherals: "Peripherals",
  sessions: "Sessions",
  reports: "Reports",
  files: "File Transfer",
  events: "Events",
  checkins: "Check-ins",
  agent: "Agent",
  blue_team: "Blue Team",
  settings: "Settings",
  users: "Users",
};

export const SUBMENU_HREFS: Record<SubmenuKey, string> = {
  overview: "/",
  computers: "/computers",
  alerts: "/alerts",
  usb_policies: "/usb-policies",
  antivirus: "/antivirus",
  firewall: "/firewall",
  peripherals: "/peripherals",
  sessions: "/sessions",
  reports: "/reports",
  files: "/files",
  events: "/events",
  checkins: "/checkins",
  agent: "/agents",
  blue_team: "/blue-team",
  settings: "/agents",
  users: "/users",
};

export const ALL_SUBMENUS: SubmenuKey[] = [
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
];

export function hasSubmenuAccess(
  submenu: SubmenuKey,
  role: string | null,
  submenuAccess: SubmenuKey[],
): boolean {
  if (role === "super_admin") return true;
  return submenuAccess.includes(submenu);
}

export function defaultPathFor(
  role: string | null,
  submenuAccess: SubmenuKey[],
): string {
  if (role === "super_admin") return "/";
  for (const submenu of ALL_SUBMENUS) {
    if (submenuAccess.includes(submenu)) {
      return SUBMENU_HREFS[submenu];
    }
  }
  return "/";
}
