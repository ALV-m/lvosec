import { useState } from "react";
import {
  Database,
  LayoutDashboard,
  LogOut,
  Menu,
  Monitor,
  Radar,
  Server,
  X,
} from "lucide-react";
import { Link, Route, Switch, useLocation } from "wouter";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useAdminAuth } from "@/lib/admin-auth";
import NotFound from "@/pages/not-found";
import TenantsPage from "./dashboard";
import DatabasesPage from "./databases-page";
import MachinesPage from "./machines-page";
import BlueTeamPage from "./blue-team-page";

// ---------------------------------------------------------------------------
// Platform Admin shell: a real sidebar menu instead of one long scroll. The
// old single dashboard was why some controls were a button-click away from
// nowhere to be found; every section is now its own routed page.
// ---------------------------------------------------------------------------

type AdminNavItem = {
  href: string;
  label: string;
  icon: typeof Server;
};

const ADMIN_NAV: AdminNavItem[] = [
  { href: "/", label: "Tenants", icon: LayoutDashboard },
  { href: "/databases", label: "Databases", icon: Database },
  { href: "/machines", label: "Machines", icon: Monitor },
  { href: "/blue-team", label: "Blue Team", icon: Radar },
];

function AdminBrand() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
        <Server className="size-4" />
      </div>
      <div className="leading-tight">
        <p className="text-sm font-bold">Platform Admin</p>
        <p className="text-[11px] text-muted-foreground">LVO Security</p>
      </div>
    </div>
  );
}

function AdminSignOutButton({ className }: { className?: string }) {
  const { signOut } = useAdminAuth();
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

function AdminSidebar() {
  const [location] = useLocation();
  const { admin } = useAdminAuth();

  return (
    <aside className="no-print sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r bg-card md:flex">
      <div className="flex h-16 items-center border-b px-4">
        <AdminBrand />
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {ADMIN_NAV.map((item) => {
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
      </nav>
      <div className="border-t p-4">
        {admin ? (
          <div className="mb-3 min-w-0">
            <p className="truncate text-sm font-medium">{admin.username}</p>
            <p className="text-xs text-muted-foreground">Super Admin</p>
          </div>
        ) : null}
        <AdminSignOutButton className="px-2" />
      </div>
    </aside>
  );
}

function AdminMobileNav() {
  const [location] = useLocation();
  const { admin } = useAdminAuth();
  const [open, setOpen] = useState(false);

  return (
    <>
      <div className="no-print sticky top-0 z-40 flex items-center justify-between gap-2 border-b bg-background px-4 py-3 md:hidden">
        <AdminBrand />
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
            <AdminBrand />
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
          {admin ? (
            <div className="flex items-center justify-between gap-2 border-b px-4 py-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{admin.username}</p>
                <p className="text-xs text-muted-foreground">Super Admin</p>
              </div>
              <AdminSignOutButton className="px-2" />
            </div>
          ) : null}
          <nav className="flex-1 space-y-1 overflow-y-auto p-4 pb-[max(1rem,env(safe-area-inset-bottom))]">
            {ADMIN_NAV.map((item) => {
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
          </nav>
        </div>
      ) : null}
    </>
  );
}

export default function AdminLayout() {
  return (
    <div className="min-h-screen bg-background">
      <div className="flex min-h-screen">
        <AdminSidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <AdminMobileNav />
          <main className="flex-1 p-4 md:p-6 lg:p-8">
            <Switch>
              <Route path="/" component={TenantsPage} />
              <Route path="/databases" component={DatabasesPage} />
              <Route path="/machines" component={MachinesPage} />
              <Route path="/blue-team" component={BlueTeamPage} />
              <Route component={NotFound} />
            </Switch>
          </main>
        </div>
      </div>
    </div>
  );
}