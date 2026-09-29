import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useDeleteTenant,
  useGetAdminStats,
  useListAdminTenants,
  useOpenLab,
  useResetTenantAdminPassword,
  useUpdateTenantStatus,
} from "@workspace/api-client-react";
import type { TenantListItem } from "@workspace/api-client-react";
import {
  Boxes,
  CheckCircle2,
  ExternalLink,
  KeyRound,
  Link as LinkIcon,
  LogOut,
  Monitor,
  Server,
  ShieldCheck,
  Trash2,
  UserCog,
} from "lucide-react";
import { toast } from "sonner";
import { Link } from "wouter";

import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAdminAuth } from "@/lib/admin-auth";
import { DbManagementSection } from "./db-management";

function StatCard({
  icon: Icon,
  label,
  value,
  loading,
}: {
  icon: typeof Server;
  label: string;
  value: number | null;
  loading: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className="flex size-10 items-center justify-center rounded-md bg-primary/10 text-primary">
          <Icon className="size-5" />
        </div>
        <div>
          <p className="text-sm text-muted-foreground">{label}</p>
          {loading ? (
            <Skeleton className="mt-1 h-6 w-14" />
          ) : (
            <p className="text-2xl font-bold tabular-nums">{value ?? 0}</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function TenantActions({
  tenant,
  onReset,
  onOpen,
  onDelete,
  openDisabled,
}: {
  tenant: TenantListItem;
  onReset: (tenant: TenantListItem) => void;
  onOpen: (tenant: TenantListItem) => void;
  onDelete: (tenant: TenantListItem) => void;
  openDisabled?: boolean;
}) {
  const queryClient = useQueryClient();
  const updateStatus = useUpdateTenantStatus({
    mutation: {
      onSuccess: () => {
        void queryClient.invalidateQueries({ queryKey: ["/api/admin/tenants"] });
        void queryClient.invalidateQueries({ queryKey: ["/api/admin/stats"] });
        toast.success(
          tenant.status === "active"
            ? "Tenant suspended — their lab is now offline."
            : "Tenant re-activated — their lab is back online.",
        );
      },
      onError: (error) => toast.error(error.message),
    },
  });

  return (
    <div className="flex flex-wrap items-center justify-end gap-1.5">
      {tenant.status === "active" ? (
        <Button
          variant="outline"
          size="sm"
          onClick={() => updateStatus.mutate({ tenantId: tenant.id, data: { status: "suspended" } })}
          disabled={updateStatus.isPending}
        >
          <CheckCircle2 className="size-4" />
          Suspend
        </Button>
      ) : (
        <Button
          variant="outline"
          size="sm"
          onClick={() => updateStatus.mutate({ tenantId: tenant.id, data: { status: "active" } })}
          disabled={updateStatus.isPending}
        >
          <CheckCircle2 className="size-4" />
          Activate
        </Button>
      )}
      <Button
        variant="outline"
        size="sm"
        onClick={() => onOpen(tenant)}
        disabled={openDisabled}
      >
        <ExternalLink className="size-4" />
        Open lab
      </Button>
      <Button variant="outline" size="sm" onClick={() => onReset(tenant)}>
        <KeyRound className="size-4" />
        Reset password
      </Button>
      <Button
        variant="outline"
        size="sm"
        className="text-destructive hover:text-destructive"
        onClick={() => onDelete(tenant)}
      >
        <Trash2 className="size-4" />
        Delete
      </Button>
    </div>
  );
}

function ResetPasswordDialog({
  tenant,
  onOpenChange,
}: {
  tenant: TenantListItem | null;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [password, setPassword] = useState("");
  const resetMutation = useResetTenantAdminPassword({
    mutation: {
      onSuccess: () => {
        toast.success(`Password reset for ${tenant?.name}.`);
        onOpenChange(false);
      },
      onError: (error) => toast.error(error.message),
    },
  });

  if (!tenant) return null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (password.length < 6) {
      toast.error("Password must be at least 6 characters.");
      return;
    }
    resetMutation.mutate({ tenantId: tenant.id, data: { password } });
    void queryClient.invalidateQueries({ queryKey: ["/api/admin/tenants"] });
  };

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Reset super admin password</DialogTitle>
          <DialogDescription>
            Set a new password for the super admin of {tenant.name} (
            {tenant.slug}).
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="reset-password">New password</Label>
            <Input
              id="reset-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={resetMutation.isPending}>
              {resetMutation.isPending ? <Spinner className="size-4" /> : null}
              Reset password
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteTenantDialog({
  tenant,
  onOpenChange,
}: {
  tenant: TenantListItem | null;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const deleteMutation = useDeleteTenant({
    mutation: {
      onSuccess: () => {
        void queryClient.invalidateQueries({ queryKey: ["/api/admin/tenants"] });
        void queryClient.invalidateQueries({ queryKey: ["/api/admin/stats"] });
        toast.success(`Tenant "${tenant?.name}" deleted.`);
        onOpenChange(false);
      },
      onError: (error) => toast.error(error.message),
    },
  });

  if (!tenant) return null;

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Delete tenant</DialogTitle>
          <DialogDescription>
            This permanently deletes {tenant.name} ({tenant.slug}) and all of
            its data, including computers, users and sessions. This cannot be
            undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={() => deleteMutation.mutate({ tenantId: tenant.id })}
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending ? <Spinner className="size-4" /> : <Trash2 className="size-4" />}
            Delete tenant
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function AdminDashboard() {
  const { admin, signOut } = useAdminAuth();
  const tenantsQuery = useListAdminTenants();
  const statsQuery = useGetAdminStats();
  const [resetTarget, setResetTarget] = useState<TenantListItem | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<TenantListItem | null>(null);

  const openLabMutation = useOpenLab({
    mutation: {
      onSuccess: (data) => {
        window.location.assign(data.path);
      },
      onError: (error) => toast.error(error.message),
    },
  });

  const tenants = useMemo(() => tenantsQuery.data?.tenants ?? [], [tenantsQuery.data]);

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-10 border-b bg-card">
        <div className="flex h-16 items-center justify-between gap-4 px-4 md:px-6">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
              <Server className="size-4" />
            </div>
            <div className="leading-tight">
              <p className="text-sm font-bold">Platform Admin</p>
              <p className="text-[11px] text-muted-foreground">
                LVO Security
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {admin ? (
              <span className="hidden text-sm text-muted-foreground sm:block">
                {admin.username}
              </span>
            ) : null}
            <Button variant="ghost" size="sm" onClick={() => void signOut()}>
              <LogOut className="size-4" />
              Sign out
            </Button>
          </div>
        </div>
      </header>

      <main className="space-y-6 p-4 md:p-6 lg:p-8">
        <div className="flex flex-col gap-1">
          <h1 className="text-2xl font-bold">Tenants</h1>
          <p className="text-sm text-muted-foreground">
            Manage the computer labs running on this platform.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <StatCard icon={Boxes} label="Total tenants" value={statsQuery.data?.totalTenants ?? null} loading={statsQuery.isLoading} />
          <StatCard icon={CheckCircle2} label="Active" value={statsQuery.data?.activeTenants ?? null} loading={statsQuery.isLoading} />
          <StatCard icon={ShieldCheck} label="Suspended" value={statsQuery.data?.suspendedTenants ?? null} loading={statsQuery.isLoading} />
          <StatCard icon={Monitor} label="Computers" value={statsQuery.data?.totalComputers ?? null} loading={statsQuery.isLoading} />
          <StatCard icon={UserCog} label="Admins" value={statsQuery.data?.totalAdmins ?? null} loading={statsQuery.isLoading} />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>All labs</CardTitle>
            <CardDescription>
              Open a lab to manage its computers, or use the actions to suspend,
              reset credentials or remove it.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Lab</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Super admin login</TableHead>
                  <TableHead className="text-right">Computers</TableHead>
                  <TableHead className="text-right">Admins</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tenantsQuery.isLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                      Loading tenants…
                    </TableCell>
                  </TableRow>
                ) : tenants.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                      No tenants yet. Share the registration link to get started.
                    </TableCell>
                  </TableRow>
                ) : (
                  tenants.map((tenant) => (
                    <TableRow key={tenant.id}>
                      <TableCell>
                        <div className="flex flex-col gap-0.5">
                          <span className="font-medium">{tenant.name}</span>
                          <span className="flex items-center gap-1 text-xs text-muted-foreground">
                            <LinkIcon className="size-3" />
                            <Link
                              href={`~/t/${tenant.slug}/login`}
                              className="underline hover:text-foreground"
                            >
                              t/{tenant.slug}/login
                            </Link>
                          </span>
                          {(tenant.contactName || tenant.contactEmail) && (
                            <span className="text-xs text-muted-foreground">
                              {[tenant.contactName, tenant.contactEmail]
                                .filter(Boolean)
                                .join(" · ")}
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={tenant.status === "active" ? "success" : "warning"}
                          className={cn(tenant.status === "suspended" && "capitalize")}
                        >
                          {tenant.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {tenant.superAdminUsername ? (
                          <div className="flex flex-col text-sm">
                            <span className="font-medium">{tenant.superAdminUsername}</span>
                            <span className="text-xs text-muted-foreground">Password can be reset below</span>
                          </div>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{tenant.computers}</TableCell>
                      <TableCell className="text-right tabular-nums">{tenant.admins}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {new Date(tenant.createdAt).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <TenantActions
                          tenant={tenant}
                          onReset={setResetTarget}
                          onOpen={(t) => openLabMutation.mutate({ tenantId: t.id })}
                          onDelete={setDeleteTarget}
                          openDisabled={openLabMutation.isPending}
                        />
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <DbManagementSection />
      </main>

      <ResetPasswordDialog tenant={resetTarget} onOpenChange={(open) => { if (!open) setResetTarget(null); }} />
      <DeleteTenantDialog tenant={deleteTarget} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }} />
    </div>
  );
}

export default AdminDashboard;
