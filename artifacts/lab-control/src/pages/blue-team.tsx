import { useState, type FormEvent } from "react";
import {
  type Computer,
  type ComputerActionInputAction,
  type DefenseLayer,
  type DefenseLayerState,
  type LabFinding,
  type PostureFinding,
  type PostureSeverity,
  type PostureState,
  tenantApiPrefix,
  useCreateComputerAction,
  useGetBlueTeamDefenseStack,
  useGetBlueTeamPosture,
  useGetBlueTeamSoftware,
  useGetComputers,
  searchBlueTeamRecords,
} from "@workspace/api-client-react";
import {
  AlertTriangle,
  ChevronRight,
  Copy,
  Crosshair,
  Database,
  Globe,
  Layers,
  Lock,
  LockOpen,
  MessageSquare,
  Plus,
  Power,
  Radar,
  Search,
  Server,
  Shield,
  ShieldCheck,
  ShieldOff,
  ShieldQuestion,
  Usb,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PrintButton } from "@/components/print-button";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";

const SEVERITY_VARIANT: Record<PostureSeverity, string> = {
  critical: "destructive",
  high: "destructive",
  medium: "warning",
  low: "secondary",
  info: "info",
};

const STATE_LABEL: Record<PostureState, string> = {
  pass: "OK",
  fail: "Failing",
  unknown: "Not reported",
};

const CATEGORY_LABEL: Record<string, string> = {
  detection: "Detection",
  endpoint: "Endpoint",
  network: "Network",
  access_control: "Access control",
  data_protection: "Data protection",
  configuration: "Configuration",
};

function SeverityBadge({ severity, state }: { severity: PostureSeverity; state: PostureState }) {
  if (state === "pass") return <Badge variant="success">OK</Badge>;
  if (state === "unknown") return <Badge variant="secondary">Not reported</Badge>;
  return <Badge variant={SEVERITY_VARIANT[severity] as "destructive"}>{severity}</Badge>;
}

function FindingRow({ finding }: { finding: PostureFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border">
      <button
        type="button"
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
        onClick={() => setOpen((v) => !v)}
      >
        <div className="flex min-w-0 items-center gap-3">
          <SeverityBadge severity={finding.severity} state={finding.state} />
          <span className={cn("truncate text-sm font-medium", finding.state === "fail" && "text-foreground")}>
            {finding.title}
          </span>
        </div>
        <ChevronRight className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
      </button>
      {open ? (
        <div className="space-y-2 border-t px-4 py-3">
          <p className="text-sm text-muted-foreground">{finding.detail}</p>
          <p className="text-sm">
            <span className="font-medium">Fix: </span>
            {finding.remediation}
          </p>
        </div>
      ) : null}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  tone,
  icon,
}: {
  label: string;
  value: number;
  tone: "good" | "bad" | "warn" | "neutral";
  icon: React.ReactNode;
}) {
  const toneClass =
    tone === "good" ? "text-emerald-600" : tone === "bad" ? "text-red-600" : tone === "warn" ? "text-amber-600" : "text-foreground";
  return (
    <Card className="gap-2 py-4">
      <CardContent className="flex items-center gap-3 px-5 py-0">
        <div className="text-muted-foreground">{icon}</div>
        <div>
          <p className={cn("text-2xl font-semibold leading-none tabular-nums", toneClass)}>{value}</p>
          <p className="mt-1 text-xs text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function DefenseStackSection() {
  const stack = useGetBlueTeamDefenseStack();
  // Supplementary view — never blocks or breaks the page.
  if (stack.isError || !stack.data) return null;

  const stateBadge: Record<DefenseLayerState, string> = {
    active: "On",
    warning: "Attention",
    off: "Off",
    na: "Not in scope",
  };

  const stateClass: Record<DefenseLayerState, string> = {
    active: "border-emerald-500/40 bg-emerald-500/5",
    warning: "border-amber-500/40 bg-amber-500/5",
    off: "border-border bg-muted/40",
    na: "border-dashed border-border bg-transparent",
  };

  const layerIcon: Record<string, React.ReactNode> = {
    perimeter: <Globe className="size-4 text-muted-foreground" />,
    detection: <Crosshair className="size-4 text-muted-foreground" />,
    hosts: <ShieldCheck className="size-4 text-muted-foreground" />,
    assets: <Database className="size-4 text-muted-foreground" />,
    databases: <Database className="size-4 text-muted-foreground" />,
    data: <Lock className="size-4 text-muted-foreground" />,
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers className="size-4 text-muted-foreground" />
          Defense stack
        </CardTitle>
        <CardDescription>
          Every defensive layer of this deployment mapped to the SOC blueprint —
          live status, not promises. Layers marked “not in scope” are the
          blueprint items this server deliberately does not implement.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 px-6">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {stack.data.layers.map((layer) => (
            <div
              key={layer.id}
              className={cn(
                "flex flex-col gap-1.5 rounded-lg border p-3",
                stateClass[layer.state],
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="flex min-w-0 items-center gap-2 text-sm font-medium">
                  {layerIcon[layer.id] ?? null}
                  <span className="truncate">{layer.label}</span>
                </span>
                <Badge variant="outline" className="shrink-0 capitalize">
                  {stateBadge[layer.state]}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground">{layer.detail}</p>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          Blueprint items deliberately out of scope here: packet IDS/IPS &amp;
          deep packet inspection, TLS inspection, portspoof &amp; port-knocking,
          impossible travel, PAM/DAM, data masking and air-gapped backups.
        </p>
      </CardContent>
    </Card>
  );
}

function MachineStatusBadge({ status }: { status: Computer["status"] }) {
  if (status === "online") {
    return <Badge variant="success">Online</Badge>;
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
      {status}
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

/**
 * Machines · VPS — the tenant's own fleet surface on the Blue Team dashboard.
 * Same endpoints as the Computers page, surfaced here so blue team manages the
 * machines/VPSes it protects from this seat: deploy the lvosec agent on a
 * Windows VPS, and firewall / USB / lock / restart / message controls land on
 * this page through the normal agent action queue.
 */
function BlueTeamMachinesSection() {
  const computersQuery = useGetComputers();
  const actionMutation = useCreateComputerAction();

  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const serverUrl = `${origin}${tenantApiPrefix().replace(/\/api$/, "")}`;
  const installCmd = `$s='${serverUrl}'; iwr "$s/api/agent/download" -OutFile "$env:TEMP\\lab-agent.ps1"; powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\\lab-agent.ps1" -ServerUrl $s -Install; Remove-Item "$env:TEMP\\lab-agent.ps1"`;
  const installCmdLinux = `curl -fsSL "${serverUrl}/api/agent/download-linux" -o /tmp/lab-agent-linux.py && sudo python3 /tmp/lab-agent-linux.py --install --server-url "${serverUrl}"`;

  const computers = computersQuery.data ?? [];
  const [busy, setBusy] = useState<number | null>(null);
  const [restartId, setRestartId] = useState<number | null>(null);
  const [messageId, setMessageId] = useState<number | null>(null);
  const [messageText, setMessageText] = useState("");
  const [showDeploy, setShowDeploy] = useState(false);

  const target = (id: number) => computers.find((c) => c.id === id);

  const run = async (id: number, action: ComputerActionInputAction, message?: string) => {
    setBusy(id);
    try {
      const result = await actionMutation.mutateAsync({
        computerId: id,
        data: message ? { action, message } : { action },
      });
      toast.success(result.message ?? `${action.replaceAll("_", " ")} queued`);
      return true;
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Action failed");
      return false;
    } finally {
      setBusy(null);
    }
  };

  const confirmRestart = async () => {
    if (restartId === null) return;
    const ok = await run(restartId, "restart");
    if (ok) setRestartId(null);
  };

  const sendMessage = async (event: FormEvent) => {
    event.preventDefault();
    if (messageId === null) return;
    const text = messageText.trim();
    if (!text) return;
    const ok = await run(messageId, "send_message", text);
    if (ok) {
      setMessageId(null);
      setMessageText("");
    }
  };

  const copyInstall = async () => {
    try {
      await navigator.clipboard.writeText(installCmd);
      toast.success("Windows command copied");
    } catch {
      toast.error("Could not copy — select the command manually");
    }
  };

  const copyInstallLinux = async () => {
    try {
      await navigator.clipboard.writeText(installCmdLinux);
      toast.success("Linux command copied");
    } catch {
      toast.error("Could not copy — select the command manually");
    }
  };

  const onlineCount = computers.filter((c) => c.status === "online").length;
  const firewallOffCount = computers.filter((c) => c.firewallEnabled === false).length;

  return (
    <>
      <Card>
        <CardHeader className="gap-3">
          <div className="flex flex-row items-start justify-between gap-4 space-y-0">
            <div className="space-y-1">
              <CardTitle className="flex items-center gap-2">
                <Server className="size-4 text-muted-foreground" />
                Machines · VPS
              </CardTitle>
              <CardDescription>
                Manage the machines and VPSes lvosec protects. Install the agent
                on a Windows PC or VPS and it registers here — then firewall,
                USB, lock, restart and operator messages run from this page.
                {computers.length > 0 &&
                  ` ${computers.length} machines · ${onlineCount} online` +
                    (firewallOffCount > 0 ? ` · ${firewallOffCount} firewalls OFF` : "")}
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => setShowDeploy(true)}>
              <Plus className="size-4" /> Add machine
            </Button>
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Machine</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Firewall</TableHead>
                <TableHead>USB</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {computersQuery.isLoading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell colSpan={7}>
                      <Skeleton className="h-8 w-full" />
                    </TableCell>
                  </TableRow>
                ))
              ) : computers.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={7}
                    className="py-8 text-center text-sm text-muted-foreground"
                  >
                    No machines connected yet. Deploy the agent on a Windows PC
                    or VPS and it registers under this account automatically.
                  </TableCell>
                </TableRow>
              ) : (
                computers.map((machine) => (
                  <TableRow key={machine.id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{machine.name}</span>
                        <span className="text-xs text-muted-foreground">
                          {machine.userName ?? "—"} · agent{" "}
                          {machine.agentVersion ?? "?"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {machine.ipAddress ?? "—"}
                    </TableCell>
                    <TableCell>
                      <MachineStatusBadge status={machine.status} />
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
                    <TableCell className="text-sm text-muted-foreground">
                      {lastSeenLabel(machine.lastSeen)}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          title={machine.status === "locked" ? "Unlock" : "Lock"}
                          aria-label={machine.status === "locked" ? "Unlock" : "Lock"}
                          onClick={() =>
                            void run(machine.id, machine.status === "locked" ? "unlock" : "lock")
                          }
                          disabled={busy === machine.id}
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
                          onClick={() => setRestartId(machine.id)}
                          disabled={busy === machine.id}
                        >
                          <Power className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          title={machine.usbState === "blocked" ? "Allow USB" : "Block USB"}
                          aria-label="Toggle USB"
                          onClick={() =>
                            void run(machine.id, machine.usbState === "blocked" ? "allow_usb" : "block_usb")
                          }
                          disabled={busy === machine.id}
                        >
                          <Usb className="size-4" />
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
                          onClick={() =>
                            void run(machine.id, machine.firewallEnabled === true ? "fw_disable" : "fw_enable")
                          }
                          disabled={busy === machine.id}
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
                            setMessageId(machine.id);
                          }}
                          disabled={busy === machine.id}
                        >
                          <MessageSquare className="size-4" />
                        </Button>
                        {busy === machine.id ? <Spinner className="size-4" /> : null}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={showDeploy} onOpenChange={setShowDeploy}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deploy the agent to a new machine</DialogTitle>
            <DialogDescription>
              Pick the platform, paste the command into the machine's shell,
              and it registers itself under this account within a minute. The
              host name becomes the machine name; after that you can toggle
              firewall &amp; USB, lock, restart or message it from this page.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Windows — PowerShell (admin)
              </p>
              <div className="flex items-center justify-between gap-2 rounded-md border bg-muted px-3 py-2">
                <code className="min-w-0 flex-1 truncate font-mono text-xs">
                  {installCmd}
                </code>
                <Button variant="ghost" size="sm" onClick={() => void copyInstall()}>
                  <Copy className="size-4" /> Copy
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Linux — Ubuntu / Debian VPS (Contabo-style)
              </p>
              <div className="flex items-center justify-between gap-2 rounded-md border bg-muted px-3 py-2">
                <code className="min-w-0 flex-1 truncate font-mono text-xs">
                  {installCmdLinux}
                </code>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => void copyInstallLinux()}
                >
                  <Copy className="size-4" /> Copy
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Installs a systemd service with Python 3 (preinstalled on
                Ubuntu). Firewall controls use ufw, USB blocking uses a udev
                rule, messages broadcast with wall.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => setShowDeploy(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={restartId !== null}
        onOpenChange={(open) => {
          if (!open) setRestartId(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Restart {target(restartId ?? -1)?.name ?? ""}?</DialogTitle>
            <DialogDescription>
              The machine will reboot on the agent's next poll. Unsaved work will
              be lost.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRestartId(null)}>
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
        open={messageId !== null}
        onOpenChange={(open) => {
          if (!open) setMessageId(null);
        }}
      >
        <DialogContent>
          <form onSubmit={(e) => void sendMessage(e)}>
            <DialogHeader>
              <DialogTitle>Message {target(messageId ?? -1)?.name ?? ""}</DialogTitle>
              <DialogDescription>
                The operator message pops up on the machine's screen (shown by
                the agent).
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-2 py-4">
              <Label htmlFor="blue-team-machine-message">Message</Label>
              <Input
                id="blue-team-machine-message"
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                placeholder="Example: Scheduled maintenance in 10 minutes"
                autoFocus
                required
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setMessageId(null)}>
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

export default function BlueTeam() {
  const posture = useGetBlueTeamPosture();
  const data = posture.data;

  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [hits, setHits] = useState<Awaited<ReturnType<typeof searchBlueTeamRecords>> | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);

  const runSearch = async () => {
    const q = query.trim();
    if (!q) return;
    setSearching(true);
    setSearchError(null);
    try {
      setHits(await searchBlueTeamRecords(q));
    } catch (err) {
      setSearchError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setSearching(false);
    }
  };

  if (posture.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (posture.isError || !data) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia>💥</EmptyMedia>
          <EmptyTitle>Could not load security posture</EmptyTitle>
          <EmptyDescription>
            The posture engine is part of this deployment. If you are seeing this, the
            server it is running on is older than this dashboard — redeploy and try again.
          </EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <Button variant="outline" onClick={() => posture.refetch()}>
            Retry
          </Button>
        </EmptyContent>
      </Empty>
    );
  }

  const { lab, findings, computers } = data;
  const criticalCount = lab.criticalMachines.length;
  const unknownPct = lab.checks > 0 ? Math.round((lab.unknown / lab.checks) * 100) : 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Blue Team</h1>
          <p className="text-sm text-muted-foreground">
            Security posture, correlation findings and record search — the honest
            slice of a SOC that runs where the lab does.
          </p>
        </div>
        <PrintButton />
      </div>

      {/* Defense stack — SOC blueprint layers, live status */}
      <DefenseStackSection />

      {/* Machines · VPS — the tenant's own fleet, managed through lvosec */}
      <BlueTeamMachinesSection />

      {/* Summary */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <SummaryCard label="Machines evaluated" value={lab.computers} tone="neutral" icon={<Database className="size-5" />} />
        <SummaryCard label="With findings" value={lab.withFailures} tone={lab.withFailures > 0 ? "warn" : "good"} icon={<AlertTriangle className="size-5" />} />
        <SummaryCard label="Critical machines" value={criticalCount} tone={criticalCount > 0 ? "bad" : "good"} icon={<Radar className="size-5" />} />
        <SummaryCard label="Failing checks" value={lab.failing} tone={lab.failing > 0 ? "warn" : "good"} icon={<ShieldQuestion className="size-5" />} />
        <SummaryCard label="Unknown (not reported)" value={lab.unknown} tone={unknownPct > 50 ? "bad" : "neutral"} icon={<ShieldCheck className="size-5" />} />
      </div>

      {/* Correlation findings */}
      <Card>
        <CardHeader>
          <CardTitle>Correlation findings</CardTitle>
          <CardDescription>
            Patterns the individual machine checks cannot show you — whole-fleet
            waves and compounded failures. {findings.length === 0 ? "Nothing compounding right now." : `${findings.length} active.`}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 px-6">
          {findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No correlations triggered. A machine list would have said the same thing — but
              this page also watches for a wave of identical failures and for machines that are
              both silent and unprotected.
            </p>
          ) : (
            findings.map((f: LabFinding) => (
              <div key={f.id} className="rounded-lg border">
                <div className="flex items-center gap-3 px-4 py-3">
                  <SeverityBadge severity={f.severity} state="fail" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{f.title}</p>
                    <p className="text-xs text-muted-foreground">
                      {f.affected} of {f.total} machines · {CATEGORY_LABEL[f.category] ?? f.category}
                    </p>
                  </div>
                </div>
                <div className="space-y-2 border-t px-4 py-3">
                  <p className="text-sm text-muted-foreground">{f.detail}</p>
                  <p className="text-sm">
                    <span className="font-medium">Fix: </span>
                    {f.remediation}
                  </p>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Coverage by category — honest: unknown is shown, not hidden */}
        <Card>
          <CardHeader>
            <CardTitle>Coverage by layer</CardTitle>
            <CardDescription>
              “Not reported” is shown deliberately. A check nobody looked at is not a
              check that passes.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 px-6">
            {Object.entries(lab.byCategory).map(([category, counts]) => (
              <div key={category} className="flex items-center gap-3">
                <span className="w-36 shrink-0 text-sm text-muted-foreground">
                  {CATEGORY_LABEL[category] ?? category}
                </span>
                <div className="flex h-2.5 flex-1 overflow-hidden rounded-full bg-muted">
                  <div
                    className="bg-emerald-500"
                    style={{ width: `${(counts.passing / Math.max(1, lab.checks)) * 100}%` }}
                    title={`${counts.passing} passing`}
                  />
                  <div
                    className="bg-red-500"
                    style={{ width: `${(counts.failing / Math.max(1, lab.checks)) * 100}%` }}
                    title={`${counts.failing} failing`}
                  />
                  <div
                    className="bg-muted-foreground/30"
                    style={{ width: `${(counts.unknown / Math.max(1, lab.checks)) * 100}%` }}
                    title={`${counts.unknown} not reported`}
                  />
                </div>
                <span className="w-20 shrink-0 text-right text-xs tabular-nums text-muted-foreground">
                  {counts.passing} ✓ · {counts.failing} ✗ · {counts.unknown} ?
                </span>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* IOC / record search */}
        <Card>
          <CardHeader>
            <CardTitle>Record search</CardTitle>
            <CardDescription>
              Search events, actions, alerts and check-ins already recorded in this lab.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 px-6">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  className="pl-9"
                  placeholder='e.g. "student name", "delete_file", "USB", a computer name…'
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void runSearch();
                  }}
                />
              </div>
              <Button onClick={() => void runSearch()} disabled={searching || !query.trim()}>
                {searching ? <Spinner className="size-4" /> : <Crosshair className="size-4" />}
                Search
              </Button>
            </div>

            {searchError ? <p className="text-sm text-red-600">{searchError}</p> : null}

            {hits ? (
              hits.results.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No records match “{hits.query}” in this lab.
                </p>
              ) : (
                <div className="max-h-80 space-y-1 overflow-y-auto pr-1">
                  {hits.results.slice(0, 50).map((hit) => (
                    <div key={`${hit.kind}-${hit.id}`} className="rounded-md border px-3 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <p className="truncate text-sm font-medium">{hit.title}</p>
                        <Badge variant="secondary" className="shrink-0">
                          {hit.kind}
                        </Badge>
                      </div>
                      <p className="truncate text-xs text-muted-foreground">{hit.detail}</p>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        {hit.computerName ?? "—"} · {formatDateTime(String(hit.createdAt))}
                      </p>
                    </div>
                  ))}
                </div>
              )
            ) : (
              <p className="text-xs text-muted-foreground">
                Searches only what this server actually stores: lab events, queued actions,
                alerts and check-ins. No claims about the network around it.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Machines */}
      <Card>
        <CardHeader>
          <CardTitle>Machines</CardTitle>
          <CardDescription>
            Every computer, with its posture findings. Expand a machine to see what is
            wrong and what to do about it. Coverage varies — machines running an older agent
            report fewer checks.
          </CardDescription>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Machine</TableHead>
                <TableHead>Room</TableHead>
                <TableHead className="text-right">Failing</TableHead>
                <TableHead className="text-right">Coverage</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {computers.map((computer) => (
                <ComputerRow key={computer.computerId} computer={computer} />
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Software inventory */}
      <SoftwareInventory />
    </div>
  );
}

function SoftwareInventory() {
  const inventory = useGetBlueTeamSoftware();
  const data = inventory.data;
  const [filter, setFilter] = useState("");

  const lower = filter.trim().toLowerCase();
  const matches = !data
    ? []
    : data.inventories.flatMap((machine) =>
        machine.software
          .filter((s) => !lower || s.name.toLowerCase().includes(lower))
          .map((s) => ({ ...s, computerName: machine.computerName, room: machine.room })),
      );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Software inventory</CardTitle>
        <CardDescription>
          What is installed where. Search to answer the question the whole lab
          depends on: <em>which machines have this?</em>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 px-6">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-9"
              placeholder="Filter by software name, e.g. WinRAR, Python, Zoom…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>
        </div>

        {inventory.isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner className="size-4" /> Loading inventory…
          </div>
        ) : !data || data.machines === 0 ? (
          <p className="text-sm text-muted-foreground">
            No machine has reported an inventory yet. Agents older than 1.22.0
            do not send one — they pick it up when they self-update.
          </p>
        ) : (
          <>
            <p className="text-xs text-muted-foreground">
              {data.machines} machine{data.machines === 1 ? "" : "s"} · {data.totalEntries} programs
              {lower ? ` · ${matches.length} match${matches.length === 1 ? "" : "es"} for “${filter.trim()}”` : ""}
            </p>
            {matches.length > 0 ? (
              <div className="max-h-96 overflow-y-auto border rounded-lg">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Software</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Machine</TableHead>
                      <TableHead>Room</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {matches.slice(0, 200).map((m, i) => (
                      <TableRow key={`${m.computerName}-${i}`}>
                        <TableCell className="font-medium">{m.name}</TableCell>
                        <TableCell className="text-muted-foreground">{m.version ?? "—"}</TableCell>
                        <TableCell>{m.computerName}</TableCell>
                        <TableCell className="text-muted-foreground">{m.room}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Nothing matches that filter.</p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function ComputerRow({
  computer,
}: {
  computer: {
    computerId: number;
    computerName: string;
    room: string;
    status: string;
    os: string | null;
    summary: {
      findings: PostureFinding[];
      evaluated: number;
      total: number;
      failing: number;
      headline: PostureFinding | null;
    };
  };
}) {
  const [open, setOpen] = useState(false);
  const summary = computer.summary;
  const critical = summary.findings.filter((f) => f.state === "fail" && f.severity === "critical").length;

  return (
    <>
      <TableRow className="cursor-pointer" onClick={() => setOpen((v) => !v)}>
        <TableCell>
          <div className="flex items-center gap-2">
            <span className={cn("size-2 rounded-full", computer.status === "online" ? "bg-emerald-500" : "bg-muted-foreground/40")} />
            <span className="font-medium">{computer.computerName}</span>
          </div>
          {computer.os ? <p className="text-xs text-muted-foreground">{computer.os}</p> : null}
        </TableCell>
        <TableCell className="text-muted-foreground">{computer.room}</TableCell>
        <TableCell className="text-right">
          {critical > 0 ? (
            <Badge variant="destructive">{critical} critical</Badge>
          ) : summary.failing > 0 ? (
            <Badge variant="warning">{summary.failing}</Badge>
          ) : (
            <Badge variant="success">clean</Badge>
          )}
        </TableCell>
        <TableCell className="text-right text-xs tabular-nums text-muted-foreground">
          {summary.evaluated}/{summary.total}
        </TableCell>
        <TableCell>
          <ChevronRight className={cn("size-4 text-muted-foreground transition-transform", open && "rotate-90")} />
        </TableCell>
      </TableRow>
      {open ? (
        <TableRow>
          <TableCell colSpan={5} className="bg-muted/30 p-4">
            <div className="grid gap-2 lg:grid-cols-2">
              {summary.findings.map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </div>
          </TableCell>
        </TableRow>
      ) : null}
    </>
  );
}