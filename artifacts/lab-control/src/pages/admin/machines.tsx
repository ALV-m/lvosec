import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import {
  useGetAdminMachines,
  useRunAdminMachineAction,
  type PlatformMachine,
  type PlatformMachineAction,
} from "@workspace/api-client-react";
import {
  CheckCircle2,
  Lock,
  LockOpen,
  MessageSquare,
  Monitor,
  Power,
  RefreshCw,
  Server,
  ShieldOff,
  Shield,
  Trash2 as UsbIcon,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";

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

function MachineStatusBadge({ status }: { status: string }) {
  if (status === "online") {
    return (
      <Badge variant="success">
        <CheckCircle2 className="size-3" />
        Online
      </Badge>
    );
  }
  if (status === "locked") {
    return (
      <Badge variant="warning">
        <Lock className="size-3" />
        Locked
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="text-muted-foreground">
      <XCircle className="size-3" />
      {status === "offline" ? "Offline" : status}
    </Badge>
  );
}

const lastSeenLabel = (iso: string) => {
  const delta = Date.now() - new Date(iso).getTime();
  if (delta < 60_000) return "just now";
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h ago`;
  return new Date(iso).toLocaleDateString();
};

export function MachinesSection() {
  const machinesQuery = useGetAdminMachines();
  const actionMutation = useRunAdminMachineAction();

  const machines = machinesQuery.data?.machines ?? [];

  const [filter, setFilter] = useState("");
  const [tenantFilter, setTenantFilter] = useState("all");
  const [kindTab, setKindTab] = useState<"all" | "computer" | "vps">("all");
  const [busy, setBusy] = useState<string | null>(null);
  const [restartTarget, setRestartTarget] = useState<PlatformMachine | null>(null);
  const [messageTarget, setMessageTarget] = useState<PlatformMachine | null>(null);
  const [messageText, setMessageText] = useState("");

  const tenants = useMemo(
    () => [...new Set(machines.map((m) => m.tenantName))].sort(),
    [machines],
  );

  const visible = machines.filter((machine) => {
    if (kindTab !== "all" && machine.kind !== kindTab) return false;
    if (tenantFilter !== "all" && machine.tenantName !== tenantFilter) return false;
    const q = filter.trim().toLowerCase();
    if (!q) return true;
    return [machine.name, machine.room, machine.userName, machine.tenantName, machine.ipAddress]
      .filter(Boolean)
      .some((field) => String(field).toLowerCase().includes(q));
  });

  const counts = useMemo(() => {
    return {
      total: machines.length,
      computers: machines.filter((m) => m.kind === "computer").length,
      vps: machines.filter((m) => m.kind === "vps").length,
      online: machines.filter((m) => m.status === "online").length,
      locked: machines.filter((m) => m.status === "locked").length,
      firewallOff: machines.filter((m) => m.firewallEnabled === false).length,
    };
  }, [machines]);

  const keyOf = (machine: PlatformMachine) => `${machine.tenantId}/${machine.id}`;
  const isBusy = (machine: PlatformMachine) => busy === keyOf(machine);

  const run = async (machine: PlatformMachine, action: PlatformMachineAction) => {
    setBusy(keyOf(machine));
    try {
      const result = await actionMutation.mutateAsync({
        tenantId: machine.tenantId,
        computerId: machine.id,
        data: { action },
      });
      toast.success(
        result.message ?? `${action.replaceAll("_", " ")} queued for ${machine.name}`,
      );
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Action failed");
    } finally {
      setBusy(null);
    }
  };

  const toggleUsb = (machine: PlatformMachine) =>
    run(machine, machine.usbState === "blocked" ? "allow_usb" : "block_usb");

  const toggleFirewall = (machine: PlatformMachine) =>
    run(machine, machine.firewallEnabled === true ? "fw_disable" : "fw_enable");

  const confirmRestart = async () => {
    if (!restartTarget) return;
    await run(restartTarget, "restart");
    setRestartTarget(null);
  };

  const sendMessage = async (event: FormEvent) => {
    event.preventDefault();
    if (!messageTarget) return;
    const text = messageText.trim();
    if (!text) return;
    setBusy(keyOf(messageTarget));
    try {
      await actionMutation.mutateAsync({
        tenantId: messageTarget.tenantId,
        computerId: messageTarget.id,
        data: { action: "send_message", message: text },
      });
      toast.success(`Message sent to ${messageTarget.name}`);
      setMessageTarget(null);
      setMessageText("");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not send message");
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <div className="flex flex-col gap-1">
        <h2 className="text-xl font-bold">Machines</h2>
        <p className="text-sm text-muted-foreground">
          Two services protected from one place — <strong>Computers</strong>{" "}
          (Windows lab machines) and <strong>Cloud VPS</strong> (Linux servers
          via the lvosec Linux agent) — with firewall, USB, lock, restart and
          message controls.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-1 rounded-lg border bg-muted/40 p-1 w-fit">
        <button
          type="button"
          onClick={() => setKindTab("all")}
          aria-pressed={kindTab === "all"}
          className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            kindTab === "all"
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          <Server className="size-4" />
          All ({counts.total})
        </button>
        <button
          type="button"
          onClick={() => setKindTab("computer")}
          aria-pressed={kindTab === "computer"}
          className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            kindTab === "computer"
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          <Monitor className="size-4" />
          Computers ({counts.computers})
        </button>
        <button
          type="button"
          onClick={() => setKindTab("vps")}
          aria-pressed={kindTab === "vps"}
          className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            kindTab === "vps"
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          <Server className="size-4" />
          Cloud VPS ({counts.vps})
        </button>
      </div>

      <Card>
        <CardHeader className="gap-3">
          <div className="flex flex-row items-start justify-between gap-4 space-y-0">
            <div className="space-y-1">
              <CardTitle className="flex items-center gap-2">
                {kindTab === "vps" ? (
                  <Server className="size-4 text-muted-foreground" />
                ) : kindTab === "computer" ? (
                  <Monitor className="size-4 text-muted-foreground" />
                ) : (
                  <Server className="size-4 text-muted-foreground" />
                )}
                {kindTab === "vps"
                  ? "Cloud VPS"
                  : kindTab === "computer"
                    ? "Computers"
                    : "All machines"}
              </CardTitle>
              <CardDescription>
                {kindTab === "vps"
                  ? `${counts.vps} cloud servers · Linux agents (ufw firewall, USB, lock, message)`
                  : kindTab === "computer"
                    ? `${counts.computers} Windows lab machines`
                    : `${counts.total} machines · ${counts.computers} computers · ${counts.vps} cloud VPS`}
                {" · "}
                {counts.online} online
                {counts.locked > 0 ? ` · ${counts.locked} locked` : ""}
                {counts.firewallOff > 0 ? ` · ${counts.firewallOff} firewalls OFF` : ""}
              </CardDescription>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void machinesQuery.refetch()}
              disabled={machinesQuery.isFetching}
            >
              <RefreshCw className={`size-4 ${machinesQuery.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter machines…"
              className="sm:max-w-64"
            />
            <select
              value={tenantFilter}
              onChange={(e) => setTenantFilter(e.target.value)}
              className="h-9 rounded-md border bg-transparent px-3 text-sm"
              aria-label="Filter by tenant"
            >
              <option value="all">All tenants</option>
              {tenants.map((tenant) => (
                <option key={tenant} value={tenant}>
                  {tenant}
                </option>
              ))}
            </select>
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Machine</TableHead>
                <TableHead>Tenant</TableHead>
                <TableHead>Room</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Firewall</TableHead>
                <TableHead>USB</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {machinesQuery.isLoading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell colSpan={9}>
                      <Skeleton className="h-8 w-full" />
                    </TableCell>
                  </TableRow>
                ))
              ) : visible.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={9}
                    className="py-8 text-center text-sm text-muted-foreground"
                  >
                    {kindTab === "vps"
                      ? "No cloud VPS yet — install the lvosec Linux agent on a server (Blue Team → Machines · VPS → Add machine) and it appears here."
                      : kindTab === "computer"
                        ? "No computers yet — connect Windows lab agents and they appear here by tenant."
                        : "No machines match — connect lab agents or install the Linux agent, and they appear here by tenant."}
                  </TableCell>
                </TableRow>
              ) : (
                visible.map((machine) => (
                  <TableRow key={keyOf(machine)}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="flex items-center gap-1.5 font-medium">
                          {machine.name}
                          {machine.kind === "vps" ? (
                            <Badge variant="info" className="px-1.5 py-0 text-[10px]">
                              VPS
                            </Badge>
                          ) : null}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {machine.os ?? machine.userName ?? "—"} · agent{" "}
                          {machine.agentVersion ?? "?"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm">{machine.tenantName}</TableCell>
                    <TableCell className="text-sm">{machine.room}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {machine.ipAddress ?? "—"}
                    </TableCell>
                    <TableCell>
                      <MachineStatusBadge status={machine.status} />
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {lastSeenLabel(machine.lastSeen)}
                    </TableCell>
                    <TableCell>
                      {machine.firewallEnabled === true ? (
                        <Badge variant="success">On</Badge>
                      ) : machine.firewallEnabled === false ? (
                        <Badge variant="destructive">Off</Badge>
                      ) : (
                        <Badge variant="outline">?</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={machine.usbState === "blocked" ? "info" : "warning"}
                      >
                        {machine.usbState}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          title={machine.status === "locked" ? "Unlock" : "Lock"}
                          aria-label={machine.status === "locked" ? "Unlock" : "Lock"}
                          onClick={() =>
                            run(machine, machine.status === "locked" ? "unlock" : "lock")
                          }
                          disabled={isBusy(machine)}
                        >
                          {machine.status === "locked" ? (
                            <LockOpen className="size-4" />
                          ) : (
                            <Lock className="size-4" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          title="Restart"
                          aria-label="Restart"
                          onClick={() => setRestartTarget(machine)}
                          disabled={isBusy(machine)}
                        >
                          <Power className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          title={
                            machine.usbState === "blocked" ? "Allow USB" : "Block USB"
                          }
                          aria-label="Toggle USB"
                          onClick={() => toggleUsb(machine)}
                          disabled={isBusy(machine)}
                        >
                          <UsbIcon className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          title={
                            machine.firewallEnabled === true
                              ? "Disable firewall"
                              : "Enable firewall"
                          }
                          aria-label="Toggle firewall"
                          onClick={() => toggleFirewall(machine)}
                          disabled={isBusy(machine)}
                        >
                          {machine.firewallEnabled === true ? (
                            <ShieldOff className="size-4" />
                          ) : (
                            <Shield className="size-4" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          title="Send message"
                          aria-label="Send message"
                          onClick={() => {
                            setMessageText("");
                            setMessageTarget(machine);
                          }}
                          disabled={isBusy(machine)}
                        >
                          <MessageSquare className="size-4" />
                        </Button>
                        {isBusy(machine) ? <Spinner className="size-4" /> : null}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog
        open={restartTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRestartTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Restart {restartTarget?.name}?</DialogTitle>
            <DialogDescription>
              The machine ({restartTarget?.tenantName} · {restartTarget?.room})
              will reboot. Unsaved work will be lost.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRestartTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => void confirmRestart()}
              disabled={actionMutation.isPending}
            >
              {actionMutation.isPending ? <Spinner className="size-4" /> : null}
              Restart
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={messageTarget !== null}
        onOpenChange={(open) => {
          if (!open) setMessageTarget(null);
        }}
      >
        <DialogContent>
          <form onSubmit={(e) => void sendMessage(e)}>
            <DialogHeader>
              <DialogTitle>Message {messageTarget?.name}</DialogTitle>
              <DialogDescription>
                The operator message pops up on the machine's screen (shown by
                the agent).
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-2 py-4">
              <Label htmlFor="machine-message">Message</Label>
              <Input
                id="machine-message"
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                placeholder="Example: Scheduled maintenance in 10 minutes"
                autoFocus
                required
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setMessageTarget(null)}>
                Cancel
              </Button>
              <Button type="submit" disabled={actionMutation.isPending}>
                {actionMutation.isPending ? <Spinner className="size-4" /> : null}
                Send
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}