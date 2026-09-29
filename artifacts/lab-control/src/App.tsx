import { useEffect, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Cable,
  Download,
  FileText,
  FolderUp,
  LayoutDashboard,
  LogOut,
  Menu,
  Monitor,
  Radar,
  Server,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Users,
  X,
} from "lucide-react";
import { Route, Router as WouterRouter, Switch, Link, useLocation, useParams } from "wouter";
import { Toaster } from "sonner";

import { cn } from "@/lib/utils";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Button } from "@/components/ui/button";
import { AuthProvider, GuardedRoute, RequireAuth, useAuth } from "@/lib/auth";
import { AdminAuthProvider, RequireAdmin } from "@/lib/admin-auth";
import { hasSubmenuAccess } from "@/lib/submenus";
import type { SubmenuKey } from "@workspace/api-client-react";
import Agents from "@/pages/agents";
import Alerts from "@/pages/alerts";
import Antivirus from "@/pages/antivirus";
import BlueTeam from "@/pages/blue-team";
import Checkins from "@/pages/checkins";
import Computers from "@/pages/computers";
import Dashboard from "@/pages/dashboard";
import Events from "@/pages/events";
import Files from "@/pages/files";
import Firewall from "@/pages/firewall";
import LoginPage from "@/pages/login";
import NotFound from "@/pages/not-found";
import Peripherals from "@/pages/peripherals";
import RegisterPage from "@/pages/register";
import Reports from "@/pages/reports";
import RootLogin from "@/pages/root-login";
import Sessions from "@/pages/sessions";
import UsbPolicies from "@/pages/usb-policies";
import UsersPage from "@/pages/users";
import AdminLoginPage from "@/pages/admin/login";
import AdminDashboard from "@/pages/admin/dashboard";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

type NavItem = {
  href: string;
  label: string;
  icon: typeof Server;
  submenu: SubmenuKey;
  superAdminOnly?: boolean;
};

const NAV_SECTIONS: Array<{
  label: string | null;
  items: NavItem[];
}> = [
  {
    label: null,
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard, submenu: "overview" },
      { href: "/computers", label: "Computers", icon: Monitor, submenu: "computers" },
      { href: "/alerts", label: "Alerts", icon: AlertTriangle, submenu: "alerts" },
      { href: "/usb-policies", label: "USB Policy", icon: ShieldCheck, submenu: "usb_policies" },
      { href: "/peripherals", label: "Peripherals", icon: Cable, submenu: "peripherals" },
      { href: "/files", label: "File Transfer", icon: FolderUp, submenu: "files" },
      { href: "/checkins", label: "Check-ins", icon: UserCheck, submenu: "checkins" },
      { href: "/sessions", label: "Sessions", icon: Users, submenu: "sessions" },
    ],
  },
  {
    label: "Security",
    items: [
      { href: "/antivirus", label: "Antivirus", icon: ShieldAlert, submenu: "antivirus" },
      { href: "/firewall", label: "Firewall", icon: ShieldCheck, submenu: "firewall" },
      { href: "/blue-team", label: "Blue Team", icon: Radar, submenu: "blue_team" },
    ],
  },
  {
    label: null,
    items: [
      { href: "/reports", label: "Reports", icon: FileText, submenu: "reports" },
      { href: "/events", label: "Events", icon: Activity, submenu: "events" },
      { href: "/agents", label: "Agent", icon: Download, submenu: "agent" },
      { href: "/users", label: "Users", icon: ShieldCheck, submenu: "users", superAdminOnly: true },
    ],
  },
];

function canSeeItem(item: NavItem, role: string | null, submenuAccess: SubmenuKey[]): boolean {
  if (!hasSubmenuAccess(item.submenu, role, submenuAccess)) return false;
  if (item.superAdminOnly && role !== "super_admin") return false;
  return true;
}

function LiveClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1_000);
    return () => clearInterval(id);
  }, []);
  return <p className="tabular-nums">{now.toLocaleString()}</p>;
}

function Brand() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
        <Server className="size-4" />
      </div>
      <div className="leading-tight">
        <p className="text-sm font-bold">LVO Security</p>
        <p className="text-[11px] text-muted-foreground">Computer Manager</p>
      </div>
    </div>
  );
}

function SignOutButton({ className }: { className?: string }) {
  const { signOut } = useAuth();
  return (
    <Button
      variant="ghost"
      size="sm"
      className={className}
      onClick={() => void signOut()}
      aria-label="Sign out"
    >
      <LogOut className="size-4" />
      Sign out
    </Button>
  );
}

function Sidebar() {
  const [location] = useLocation();
  const { user } = useAuth();

  const sections = NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) =>
      canSeeItem(item, user?.role ?? null, user?.submenuAccess ?? []),
    ),
  })).filter((section) => section.items.length > 0);

  return (
    <aside className="no-print sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r bg-card md:flex">
      <div className="flex h-16 items-center border-b px-4">
        <Brand />
      </div>
      <nav className="flex-1 space-y-4 overflow-y-auto p-3">
        {sections.map((section, index) => (
          <div key={index} className="space-y-1">
            {section.label ? (
              <p className="px-3 pt-2 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
                {section.label}
              </p>
            ) : null}
            {section.items.map((item) => {
              const active = location === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                    active
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                  )}
                >
                  <item.icon className="size-4" />
                  {item.label}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="border-t p-4">
        {user ? (
          <div className="mb-3 flex items-center justify-between gap-2">
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{user.username}</p>
              <p className="text-xs text-muted-foreground">
                {user.role === "super_admin" ? "Super Admin" : "Admin"}
              </p>
            </div>
          </div>
        ) : null}
        <div className="flex items-center justify-between gap-2">
          <LiveClock />
          <SignOutButton className="px-2" />
        </div>
      </div>
    </aside>
  );
}

function MobileNav() {
  const [location] = useLocation();
  const { user } = useAuth();
  const [open, setOpen] = useState(false);

  const sections = NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) =>
      canSeeItem(item, user?.role ?? null, user?.submenuAccess ?? []),
    ),
  })).filter((section) => section.items.length > 0);

  return (
    <>
      <div className="no-print sticky top-0 z-40 flex items-center justify-between gap-2 border-b bg-background px-4 py-3 md:hidden">
        <Brand />
        <Button
          variant="outline"
          size="icon"
          className="size-9"
          aria-label="Open navigation menu"
          onClick={() => setOpen(true)}
        >
          <Menu className="size-5" />
        </Button>
      </div>
      {open ? (
        <div className="no-print fixed inset-0 z-50 flex flex-col bg-background md:hidden">
          <div className="flex items-center justify-between gap-2 border-b px-4 py-3">
            <Brand />
            <Button
              variant="outline"
              size="icon"
              className="size-9"
              aria-label="Close navigation menu"
              onClick={() => setOpen(false)}
            >
              <X className="size-5" />
            </Button>
          </div>
          {user ? (
            <div className="flex items-center justify-between gap-2 border-b px-4 py-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{user.username}</p>
                <p className="text-xs text-muted-foreground">
                  {user.role === "super_admin" ? "Super Admin" : "Admin"}
                </p>
              </div>
              <SignOutButton className="px-2" />
            </div>
          ) : null}
          <nav className="flex-1 overflow-y-auto p-4 pb-[max(1rem,env(safe-area-inset-bottom))]">
            {sections.map((section, index) => (
              <div key={index} className="space-y-1">
                {section.label ? (
                  <p className="px-3 pt-3 pb-1 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
                    {section.label}
                  </p>
                ) : null}
                {section.items.map((item) => {
                  const active = location === item.href;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={() => setOpen(false)}
                      className={cn(
                        "flex items-center gap-3 rounded-md px-3 py-3 text-sm font-medium transition-colors",
                        active
                          ? "bg-primary text-primary-foreground"
                          : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                      )}
                    >
                      <item.icon className="size-5" />
                      {item.label}
                    </Link>
                  );
                })}
              </div>
            ))}
          </nav>
        </div>
      ) : null}
    </>
  );
}

function Layout() {
  return (
    <div className="min-h-screen bg-background">
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <MobileNav />
          <main className="flex-1 p-4 md:p-6 lg:p-8">
            <Switch>
              <GuardedRoute path="/" submenu="overview" component={Dashboard} />
              <GuardedRoute path="/computers" submenu="computers" component={Computers} />
              <GuardedRoute path="/alerts" submenu="alerts" component={Alerts} />
              <GuardedRoute path="/usb-policies" submenu="usb_policies" component={UsbPolicies} />
              <GuardedRoute path="/peripherals" submenu="peripherals" component={Peripherals} />
              <GuardedRoute path="/files" submenu="files" component={Files} />
              <GuardedRoute path="/checkins" submenu="checkins" component={Checkins} />
              <GuardedRoute path="/antivirus" submenu="antivirus" component={Antivirus} />
              <GuardedRoute path="/firewall" submenu="firewall" component={Firewall} />
              <GuardedRoute path="/blue-team" submenu="blue_team" component={BlueTeam} />
              <GuardedRoute path="/sessions" submenu="sessions" component={Sessions} />
              <GuardedRoute path="/reports" submenu="reports" component={Reports} />
              <GuardedRoute path="/events" submenu="events" component={Events} />
              <GuardedRoute path="/agents" submenu="agent" component={Agents} />
              <GuardedRoute path="/users" submenu="users" component={UsersPage} superAdminOnly />
              <Route component={NotFound} />
            </Switch>
          </main>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root-level routing: tenant labs under /t/:slug, platform admin under /admin.
// The `nest` flag makes wouter mount a nested router with the matched prefix as
// its base, so the tenant dashboard below works exactly as before.
// ---------------------------------------------------------------------------

function TenantApp() {
  const params = useParams<{ slug: string }>();
  const slug = params.slug;

  return (
    <AuthProvider slug={slug}>
      <Switch>
        <Route path="/login">
          {() => <LoginPage slug={slug} />}
        </Route>
        <Route path="*">
          {() => (
            <RequireAuth>
              <Layout />
            </RequireAuth>
          )}
        </Route>
      </Switch>
    </AuthProvider>
  );
}

function AdminApp() {
  return (
    <AdminAuthProvider>
      <Switch>
        <Route path="/login" component={AdminLoginPage} />
        <Route path="*">
          {() => (
            <RequireAdmin>
              <AdminDashboard />
            </RequireAdmin>
          )}
        </Route>
      </Switch>
    </AdminAuthProvider>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Switch>
            <Route path="/" component={RootLogin} />
            <Route path="/register" component={RegisterPage} />
            <Route path="/admin" nest>
              <AdminApp />
            </Route>
            <Route path="/t/:slug" nest>
              <TenantApp />
            </Route>
            <Route component={NotFound} />
          </Switch>
        </WouterRouter>
        <Toaster position="top-right" richColors />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
