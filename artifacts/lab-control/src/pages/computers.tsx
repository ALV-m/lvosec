import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type WheelEvent as ReactWheelEvent,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ComputerActionInputAction,
  getGetComputersQueryKey,
  getGetLabSummaryQueryKey,
  getLatestScreenshotQueryKey,
  resolveTenantSlug,
  screenshotFileUrl,
  type Computer,
  type UsbMode,
  useCreateComputerAction,
  useGetComputers,
  useGetLatestScreenshot,
  usePushFileToComputer,
  useSetComputerUsbMode,
} from "@workspace/api-client-react";
import {
  Ban,
  Camera,
  ChevronDown,
  Cpu,
  Download,
  FileUp,
  Keyboard,
  Lock,
  Monitor,
  MonitorPlay,
  MoreHorizontal,
  MousePointer2,
  Moon,
  Power,
  Radar,
  RefreshCcw,
  Search,
  Send,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Unlock,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";

// The tunnel endpoint is tenant-scoped (/t/:slug/ws/tunnel) because the server
// authenticates the session inside that tenant's Postgres schema. Returns null
// outside a tenant context rather than falling back to the bare path, which the
// server rejects outright.
function tunnelUrl(computerId: number): string | null {
  if (typeof window === "undefined") return null;
  const slug = resolveTenantSlug();
  if (!slug) return null;
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/t/${slug}/ws/tunnel?role=dashboard&computerId=${computerId}`;
}
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge, UsbBadge } from "@/components/badges";
import { formatBytes, formatDateTime, timeAgo } from "@/lib/format";
import { cn } from "@/lib/utils";

const STATUS_FILTERS = ["all", "online", "offline", "warning", "locked"] as const;

function Computers() {
  const queryClient = useQueryClient();
  const { data: computers, isLoading } = useGetComputers({
    query: { queryKey: getGetComputersQueryKey(), refetchInterval: 10_000 },
  });

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<(typeof STATUS_FILTERS)[number]>("all");
  const [messageTarget, setMessageTarget] = useState<Computer | null>(null);
  const [message, setMessage] = useState("");
  const [fileTarget, setFileTarget] = useState<Computer | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Computer | null>(null);
  const [deletePath, setDeletePath] = useState("");
  const [securityTarget, setSecurityTarget] = useState<Computer | null>(null);
  const [viewTarget, setViewTarget] = useState<Computer | null>(null);
  const [hwTarget, setHwTarget] = useState<Computer | null>(null);

  // Shared WebSocket pool for instant action dispatch (keyed by computerId)
  const wsPoolRef = useRef<Map<number, WebSocket>>(new Map());
  const wsPendingRef = useRef<Map<number, Array<{ resolve: (v: unknown) => void; reject: (e: Error) => void }>>>(new Map());

  const getWs = useCallback((computerId: number): WebSocket | null => {
    const existing = wsPoolRef.current.get(computerId);
    if (existing && (existing.readyState === WebSocket.OPEN || existing.readyState === WebSocket.CONNECTING)) {
      return existing;
    }
    const url = tunnelUrl(computerId);
    if (!url) return null;
    const ws = new WebSocket(url);
    wsPoolRef.current.set(computerId, ws);
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(String(event.data));
        if (msg.type === "action_result") {
          const pending = wsPendingRef.current.get(computerId);
          if (pending && pending.length > 0) {
            const handler = pending.shift()!;
            handler.resolve(msg);
          }
        }
      } catch {}
    };
    ws.onerror = () => {};
    ws.onclose = () => { wsPoolRef.current.delete(computerId); };
    return ws;
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      for (const ws of wsPoolRef.current.values()) {
        try { ws.close(); } catch {}
      }
      wsPoolRef.current.clear();
    };
  }, []);

  const actionMutation = useCreateComputerAction({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getGetComputersQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetLabSummaryQueryKey() });
        toast.success("Action queued");
      },
      onError: (error) => toast.error(error.message),
    },
  });

  const usbModeMutation = useSetComputerUsbMode({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getGetComputersQueryKey() });
        toast.success("USB mode updated");
      },
      onError: (error) => toast.error(error.message),
    },
  });

  const fileMutation = usePushFileToComputer({
    mutation: {
      onSuccess: (result) => {
        setFileTarget(null);
        setSelectedFile(null);
        toast.success(`Queued "${result.fileName}" for delivery`);
      },
      onError: (error) => toast.error(error.message),
    },
  });

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return (computers ?? []).filter((computer) => {
      const matchesStatus = statusFilter === "all" || computer.status === statusFilter;
      const matchesSearch =
        term.length === 0 ||
        computer.name.toLowerCase().includes(term) ||
        computer.room.toLowerCase().includes(term) ||
        (computer.userName ?? "").toLowerCase().includes(term);
      return matchesStatus && matchesSearch;
    });
  }, [computers, search, statusFilter]);

  const runAction = (computer: Computer, action: ComputerActionInputAction, payload?: string) => {
    const ws = getWs(computer.id);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "action", action, payload: payload ?? null }));
      toast.success(`Action "${action}" sent instantly`);
      queryClient.invalidateQueries({ queryKey: getGetComputersQueryKey() });
      return;
    }
    // Fallback: HTTP queue
    actionMutation.mutate({ computerId: computer.id, data: { action, payload } });
  };

  const setUsbMode = (computer: Computer, mode: UsbMode) => {
    usbModeMutation.mutate({ computerId: computer.id, mode });
  };

  const sendMessage = () => {
    if (!messageTarget || message.trim().length === 0) return;
    actionMutation.mutate(
      {
        computerId: messageTarget.id,
        data: { action: ComputerActionInputAction.send_message, message: message.trim() },
      },
      {
        onSuccess: () => {
          setMessageTarget(null);
          setMessage("");
        },
      },
    );
  };

  const sendFile = () => {
    if (!fileTarget || !selectedFile) return;
    fileMutation.mutate({ computerId: fileTarget.id, file: selectedFile });
  };

  const confirmDelete = () => {
    if (!deleteTarget || deletePath.trim().length === 0) return;
    runAction(
      deleteTarget,
      ComputerActionInputAction.delete_file,
      JSON.stringify({ path: deletePath.trim() }),
    );
    setDeleteTarget(null);
    setDeletePath("");
  };

  const securityBusy = actionMutation.isPending;
  const avEnabled = securityTarget?.avEnabled;
  const firewallEnabled = securityTarget?.firewallEnabled;
  const firewallProfiles = securityTarget?.firewallProfiles;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Computers</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {isLoading ? "Loading…" : `${filtered.length} of ${computers?.length ?? 0} computers`}
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative sm:w-72">
          <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by name, room, or user…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={statusFilter} onValueChange={(value) => setStatusFilter(value as (typeof STATUS_FILTERS)[number])}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_FILTERS.map((status) => (
              <SelectItem key={status} value={status} className="capitalize">
                {status}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="rounded-lg border">
        {isLoading ? (
          <div className="space-y-3 p-4">
            {Array.from({ length: 5 }).map((_, index) => (
              <Skeleton key={index} className="h-12 w-full" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyMedia>
                <Monitor className="size-5" />
              </EmptyMedia>
              <EmptyTitle>No computers found</EmptyTitle>
              <EmptyDescription>
                {search || statusFilter !== "all"
                  ? "Try adjusting your search or filters."
                  : "No computers have reported to the lab yet."}
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Computer</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>User</TableHead>
                <TableHead>USB</TableHead>
                <TableHead>Storage</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((computer) => (
                <TableRow key={computer.id}>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div
                        className={cn(
                          "flex size-8 items-center justify-center rounded-md",
                          computer.status === "online" && "bg-emerald-500/10 text-emerald-600",
                          computer.status === "offline" && "bg-muted text-muted-foreground",
                          computer.status === "warning" && "bg-amber-500/10 text-amber-600",
                          computer.status === "locked" && "bg-destructive/10 text-destructive",
                        )}
                      >
                        <Monitor className="size-4" />
                      </div>
                      <div>
                        <p className="font-medium">{computer.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {computer.room}
                          {computer.agentVersion
                            ? ` · agent v${computer.agentVersion}`
                            : ""}
                        </p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={computer.status} />
                  </TableCell>
                  <TableCell>
                    <span className="text-muted-foreground">{computer.userName || "—"}</span>
                  </TableCell>
                  <TableCell>
                    <UsbBadge state={computer.usbState} />
                  </TableCell>
                  <TableCell>
                    {computer.diskTotal && computer.diskTotal > 0 ? (
                      <div className="flex min-w-28 flex-col gap-1">
                        <div className="flex items-baseline justify-between gap-2 text-xs">
                          <span className="font-medium tabular-nums">
                            {formatBytes(computer.diskFree)} free
                          </span>
                          <span className="text-muted-foreground tabular-nums">
                            {formatBytes(computer.diskTotal)}
                          </span>
                        </div>
                        <div
                          className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
                          role="img"
                          aria-label={`${Math.round(
                            ((computer.diskTotal - (computer.diskFree ?? 0)) / computer.diskTotal) * 100,
                          )}% used`}
                        >
                          <div
                            className={cn(
                              "h-full rounded-full",
                              (computer.diskTotal - (computer.diskFree ?? 0)) / computer.diskTotal > 0.9
                                ? "bg-destructive"
                                : "bg-primary",
                            )}
                            style={{
                              width: `${Math.min(
                                100,
                                Math.max(
                                  0,
                                  Math.round(
                                    ((computer.diskTotal - (computer.diskFree ?? 0)) / computer.diskTotal) * 100,
                                  ),
                                ),
                              )}%`,
                            }}
                          />
                        </div>
                      </div>
                    ) : (
                      <span className="text-muted-foreground">-</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <span className="text-muted-foreground tabular-nums">
                      {timeAgo(computer.lastSeen)}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label={`Actions for ${computer.name}`}>
                          <MoreHorizontal className="size-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-48">
                        <DropdownMenuLabel>{computer.name}</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.lock)}
                        >
                          <Lock className="size-4" />
                          Lock
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.unlock)}
                        >
                          <Unlock className="size-4" />
                          Unlock
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.restart)}
                        >
                          <RefreshCcw className="size-4" />
                          Restart
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.shutdown)}
                        >
                          <Power className="size-4" />
                          Shutdown
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.sleep)}
                        >
                          <Moon className="size-4" />
                          Sleep
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.wake)}
                        >
                          <Zap className="size-4" />
                          Wake on LAN
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => setMessageTarget(computer)}
                        >
                          <Send className="size-4" />
                          Send message…
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => setViewTarget(computer)}
                        >
                          <MousePointer2 className="size-4" />
                          Remote view & control
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.remote_control)}
                        >
                          <MonitorPlay className="size-4" />
                          Enable RDP
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.disable_rdp)}
                        >
                          <Ban className="size-4" />
                          Disable RDP
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={!computer.ipAddress}
                          onClick={() => {
                            window.open(`/api/lab/computers/${computer.id}/rdp`, "_blank");
                          }}
                        >
                          <Download className="size-4" />
                          Download RDP file
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => setHwTarget(computer)}>
                          <Cpu className="size-4" />
                          Hardware info…
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.av_scan)}
                        >
                          <Radar className="size-4" />
                          Run antivirus scan
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => setSecurityTarget(computer)}
                        >
                          <ShieldAlert className="size-4" />
                          Security…
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={fileMutation.isPending}
                          onClick={() => setFileTarget(computer)}
                        >
                          <FileUp className="size-4" />
                          Push file…
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => {
                            setDeleteTarget(computer);
                            setDeletePath("");
                          }}
                        >
                          <Trash2 className="size-4" />
                          Delete file…
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          disabled={usbModeMutation.isPending}
                          onClick={() => setUsbMode(computer, "allowed")}
                        >
                          <ShieldCheck className="size-4" />
                          USB: allow devices
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={usbModeMutation.isPending}
                          onClick={() => setUsbMode(computer, "blocked")}
                        >
                          <Ban className="size-4" />
                          USB: block devices
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={usbModeMutation.isPending}
                          onClick={() => setUsbMode(computer, "review")}
                        >
                          <ShieldAlert className="size-4" />
                          USB: review / quarantine
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.block_usb)}
                        >
                          <Ban className="size-4" />
                          Eject removable drives
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={actionMutation.isPending}
                          onClick={() => runAction(computer, ComputerActionInputAction.allow_usb)}
                        >
                          <ShieldCheck className="size-4" />
                          Allow all USB (policy)
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <Dialog open={messageTarget !== null} onOpenChange={(open) => !open && setMessageTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Send message to {messageTarget?.name}</DialogTitle>
            <DialogDescription>
              The message will appear on the target computer's screen.
            </DialogDescription>
          </DialogHeader>
          <Textarea
            placeholder="Type your message…"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            rows={4}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setMessageTarget(null)}>
              Cancel
            </Button>
            <Button onClick={sendMessage} disabled={message.trim().length === 0 || actionMutation.isPending}>
              {actionMutation.isPending ? <Spinner className="size-4" /> : <Send className="size-4" />}
              Send
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={fileTarget !== null} onOpenChange={(open) => !open && setFileTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Push file to {fileTarget?.name}</DialogTitle>
            <DialogDescription>
              The file is uploaded to the server and delivered to the target computer's Downloads
              folder when its agent checks in.
            </DialogDescription>
          </DialogHeader>
          <Input
            type="file"
            onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setFileTarget(null)}>
              Cancel
            </Button>
            <Button onClick={sendFile} disabled={!selectedFile || fileMutation.isPending}>
              {fileMutation.isPending ? <Spinner className="size-4" /> : <FileUp className="size-4" />}
              Queue file
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete file on {deleteTarget?.name}</DialogTitle>
            <DialogDescription>
              Enter the full path of the file or folder on the client PC to remove.
            </DialogDescription>
          </DialogHeader>
          <Input
            placeholder="C:\Users\student\Downloads\example.exe"
            value={deletePath}
            onChange={(event) => setDeletePath(event.target.value)}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDelete} disabled={deletePath.trim().length === 0 || actionMutation.isPending}>
              <Trash2 className="size-4" />
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={securityTarget !== null} onOpenChange={(open) => !open && setSecurityTarget(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Security on {securityTarget?.name}</DialogTitle>
            <DialogDescription>
              Antivirus and firewall status and controls. Actions are delivered to the agent on its
              next check-in.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            <div className="rounded-lg border p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="size-4 text-amber-500" />
                  <p className="font-medium">Windows Defender</p>
                </div>
                <Badge variant={avEnabled === false ? "destructive" : "default"}>
                  {avEnabled == null ? "Unknown" : avEnabled ? "Enabled" : "Disabled"}
                </Badge>
              </div>
              <dl className="mt-3 space-y-1 text-sm text-muted-foreground">
                <div className="flex justify-between">
                  <dt>Definitions</dt>
                  <dd className="tabular-nums">{securityTarget?.avSignature || "—"}</dd>
                </div>
                <div className="flex justify-between">
                  <dt>Last scan</dt>
                  <dd className="tabular-nums">{formatDateTime(securityTarget?.avLastScanAt)}</dd>
                </div>
              </dl>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={securityBusy}
                  onClick={() => securityTarget && runAction(securityTarget, ComputerActionInputAction.av_scan)}
                >
                  <Radar className="size-4" />
                  Quick scan
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={securityBusy}
                  onClick={() =>
                    securityTarget &&
                    runAction(
                      securityTarget,
                      ComputerActionInputAction.av_scan,
                      JSON.stringify({ type: "full" }),
                    )
                  }
                >
                  <Radar className="size-4" />
                  Full scan
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={securityBusy}
                  onClick={() => securityTarget && runAction(securityTarget, ComputerActionInputAction.av_update)}
                >
                  <RefreshCcw className="size-4" />
                  Update definitions
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={securityBusy || avEnabled == null}
                  onClick={() =>
                    securityTarget &&
                    runAction(
                      securityTarget,
                      ComputerActionInputAction.av_toggle,
                      JSON.stringify({ enabled: !avEnabled }),
                    )
                  }
                >
                  {avEnabled ? <Ban className="size-4" /> : <ShieldCheck className="size-4" />}
                  {avEnabled ? "Disable protection" : "Enable protection"}
                </Button>
              </div>
            </div>

            <div className="rounded-lg border p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="size-4 text-emerald-500" />
                  <p className="font-medium">Windows Firewall</p>
                </div>
                <Badge variant={firewallEnabled === false ? "destructive" : "default"}>
                  {firewallEnabled == null ? "Unknown" : firewallEnabled ? "Enabled" : "Disabled"}
                </Badge>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{firewallProfiles || "No profile data reported yet."}</p>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={securityBusy}
                  onClick={() => securityTarget && runAction(securityTarget, ComputerActionInputAction.fw_enable)}
                >
                  <ShieldCheck className="size-4" />
                  Enable firewall
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={securityBusy}
                  onClick={() => securityTarget && runAction(securityTarget, ComputerActionInputAction.fw_disable)}
                >
                  <Ban className="size-4" />
                  Disable firewall
                </Button>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSecurityTarget(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={hwTarget !== null} onOpenChange={(open) => !open && setHwTarget(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Hardware — {hwTarget?.name}</DialogTitle>
            <DialogDescription>
              Physical details reported by the agent on every heartbeat.
            </DialogDescription>
          </DialogHeader>
          {hwTarget && (
            <div className="space-y-3 text-sm">
              <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
                <span className="font-medium text-muted-foreground">Manufacturer</span>
                <span>{hwTarget.manufacturer || "—"}</span>
                <span className="font-medium text-muted-foreground">Model</span>
                <span>{hwTarget.model || "—"}</span>
                <span className="font-medium text-muted-foreground">Serial (System)</span>
                <span className="font-mono">{hwTarget.serialNumber || "—"}</span>
                <span className="font-medium text-muted-foreground">Serial (Board)</span>
                <span className="font-mono">{hwTarget.biosSerial || "—"}</span>
                <span className="font-medium text-muted-foreground">System UUID</span>
                <span className="font-mono text-xs break-all">{hwTarget.systemUUID || "—"}</span>
                <span className="font-medium text-muted-foreground">CPU</span>
                <span>{hwTarget.cpuName || "—"}</span>
                <span className="font-medium text-muted-foreground">Cores (logical)</span>
                <span>{hwTarget.cpuCores ?? "—"}</span>
<span className="font-medium text-muted-foreground">RAM</span>
                <span>{hwTarget.totalRAM != null ? `${hwTarget.totalRAM} GB` : "-"}</span>
                <span className="font-medium text-muted-foreground">Storage</span>
                <span>
                  {hwTarget.diskTotal && hwTarget.diskTotal > 0
                    ? `${formatBytes(hwTarget.diskFree ?? 0)} free of ${formatBytes(hwTarget.diskTotal)}`
                    : "-"}
                </span>
                <span className="font-medium text-muted-foreground">IP Address</span>
                <span className="font-mono">{hwTarget.ipAddress || "—"}</span>
                <span className="font-medium text-muted-foreground">MAC Address</span>
                <span className="font-mono">{hwTarget.macAddress || "—"}</span>
                <span className="font-medium text-muted-foreground">OS</span>
                <span>{hwTarget.os}</span>
                <span className="font-medium text-muted-foreground">Agent Version</span>
                <span>{hwTarget.agentVersion || "—"}</span>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setHwTarget(null)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {viewTarget ? (
        <RemoteViewDialog
          computer={viewTarget}
          open
          onOpenChange={(open) => !open && setViewTarget(null)}
        />
      ) : null}
    </div>
  );
}

type RemoteInputPayload = {
  type: "move" | "click" | "dblclick" | "down" | "up" | "scroll" | "key" | "type";
  x?: number;
  y?: number;
  button?: "left" | "right" | "middle";
  key?: string;
  text?: string;
  mods?: string;
  delta?: number;
};

const SPECIAL_KEYS: Record<string, string> = {
  Enter: "Enter",
  Tab: "Tab",
  Escape: "Esc",
  Backspace: "Backspace",
  Delete: "Delete",
  Home: "Home",
  End: "End",
  PageUp: "PageUp",
  PageDown: "PageDown",
  ArrowUp: "Up",
  ArrowDown: "Down",
  ArrowLeft: "Left",
  ArrowRight: "Right",
};

function RemoteViewDialog({
  computer,
  open,
  onOpenChange,
}: {
  computer: Computer;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [controlEnabled, setControlEnabled] = useState(false);
  const [keyboardEnabled, setKeyboardEnabled] = useState(false);
  const [typeText, setTypeText] = useState("");
  const [cursor, setCursor] = useState<{ x: number; y: number } | null>(null);
  const [wsFrame, setWsFrame] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const imgRef = useRef<HTMLImageElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const lastMoveRef = useRef(0);
  const clickTimerRef = useRef<number | null>(null);
  const dragRef = useRef<{ button: "left" | "right" | "middle"; x: number; y: number } | null>(null);
  const downRef = useRef<{ x: number; y: number; t: number; button: "left" | "right" | "middle" } | null>(null);

  // HTTP fallback for initial screenshot
  const { data } = useGetLatestScreenshot(computer.id, {
    query: {
      queryKey: getLatestScreenshotQueryKey(computer.id),
      refetchInterval: open && !wsConnected ? 1_000 : false,
    },
  });

  const actionMutation = useCreateComputerAction({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getGetComputersQueryKey() });
      },
      onError: (error) => toast.error(error.message),
    },
  });

  const shot = data?.screenshot;

  // WebSocket tunnel for real-time frames
  useEffect(() => {
    if (!open) {
      setWsFrame(null);
      setWsConnected(false);
      return;
    }

    const url = tunnelUrl(computer.id);
    if (!url) {
      console.error("Cannot open remote view: no tenant context for the tunnel URL");
      return;
    }
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "start_view" }));
      // Trigger an initial HTTP screenshot so the agent starts streaming
      actionMutation.mutate(
        { computerId: computer.id, data: { action: ComputerActionInputAction.remote_view } },
        { onError: () => {} },
      );
    };

    ws.onmessage = (event) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(String(event.data));
      } catch {
        return;
      }
      if (msg.type === "frame" && typeof msg.data === "string") {
        setWsFrame(msg.data);
        setWsConnected(true);
      }
      if (msg.type === "status") {
        setWsConnected(Boolean(msg.connected));
      }
    };

    ws.onerror = () => {};
    ws.onclose = () => {
      setWsConnected(false);
    };

    return () => {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.send(JSON.stringify({ type: "stop_view" }));
        ws.close();
      }
      wsRef.current = null;
    };
  }, [open, computer.id, actionMutation]);

  const invalidateShot = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: getLatestScreenshotQueryKey(computer.id) });
  }, [queryClient, computer.id]);

  const requestShot = useCallback(
    (notify = false) => {
      actionMutation.mutate(
        {
          computerId: computer.id,
          data: { action: ComputerActionInputAction.remote_view },
        },
        notify ? undefined : { onError: () => {} },
      );
      window.setTimeout(invalidateShot, 4_000);
    },
    [actionMutation, computer.id, invalidateShot],
  );

  const sendInput = useCallback(
    (payload: RemoteInputPayload) => {
      // Try WebSocket first, fall back to HTTP
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: "input", payload }));
      } else {
        actionMutation.mutate(
          {
            computerId: computer.id,
            data: {
              action: ComputerActionInputAction.remote_input,
              payload: JSON.stringify(payload),
            },
          },
          { onError: () => {} },
        );
      }
    },
    [actionMutation, computer.id],
  );

  useEffect(() => {
    if (!open) {
      setControlEnabled(false);
      setKeyboardEnabled(false);
      setTypeText("");
      setCursor(null);
    }
  }, [open]);

  useEffect(() => {
    return () => {
      if (clickTimerRef.current) window.clearTimeout(clickTimerRef.current);
    };
  }, []);

  useEffect(() => {
    if (keyboardEnabled) contentRef.current?.focus();
  }, [keyboardEnabled]);

  const toRemoteCoords = (event: ReactMouseEvent) => {
    const img = imgRef.current;
    if (!img || !img.naturalWidth || !img.naturalHeight) return null;
    const rect = img.getBoundingClientRect();
    const scale = Math.min(rect.width / img.naturalWidth, rect.height / img.naturalHeight);
    const offsetX = (rect.width - img.naturalWidth * scale) / 2;
    const offsetY = (rect.height - img.naturalHeight * scale) / 2;
    const x = Math.round((event.clientX - rect.left - offsetX) / scale);
    const y = Math.round((event.clientY - rect.top - offsetY) / scale);
    return {
      x: Math.max(0, Math.min(img.naturalWidth, x)),
      y: Math.max(0, Math.min(img.naturalHeight, y)),
    };
  };

  const buttonFor = (button: number): "left" | "right" | "middle" => {
    if (button === 2) return "right";
    if (button === 1) return "middle";
    return "left";
  };

  const handleMouseMove = (event: ReactMouseEvent) => {
    const point = toRemoteCoords(event);
    if (point) setCursor(point);
    if (!controlEnabled || !point) return;
    if (downRef.current && !dragRef.current) {
      const moved = Math.hypot(point.x - downRef.current.x, point.y - downRef.current.y);
      if (moved > 6) {
        dragRef.current = { button: downRef.current.button, x: downRef.current.x, y: downRef.current.y };
        sendInput({
          type: "down",
          x: downRef.current.x,
          y: downRef.current.y,
          button: dragRef.current.button,
        });
      }
    }
    const now = Date.now();
    if (now - lastMoveRef.current < 200) return;
    lastMoveRef.current = now;
    if (dragRef.current) {
      sendInput({ type: "move", x: point.x, y: point.y, button: dragRef.current.button });
    } else {
      sendInput({ type: "move", x: point.x, y: point.y });
    }
  };

  const handleMouseDown = (event: ReactMouseEvent) => {
    if (!controlEnabled) return;
    const point = toRemoteCoords(event);
    if (!point) return;
    event.preventDefault();
    downRef.current = { ...point, t: Date.now(), button: buttonFor(event.button) };
  };

  const handleMouseUp = (event: ReactMouseEvent) => {
    if (!controlEnabled) return;
    const point = toRemoteCoords(event);
    const down = downRef.current;
    downRef.current = null;
    if (!down || !point) return;
    if (dragRef.current) {
      sendInput({ type: "up", x: point.x, y: point.y, button: dragRef.current.button });
      dragRef.current = null;
      return;
    }
    const moved = Math.hypot(point.x - down.x, point.y - down.y);
    if (moved > 6 || Date.now() - down.t > 500) {
      sendInput({ type: "up", x: point.x, y: point.y, button: down.button });
      return;
    }
    if (clickTimerRef.current) window.clearTimeout(clickTimerRef.current);
    const button = down.button;
    clickTimerRef.current = window.setTimeout(() => {
      sendInput({ type: "click", x: point.x, y: point.y, button });
    }, 250);
  };

  const handleDoubleClick = (event: ReactMouseEvent) => {
    if (!controlEnabled) return;
    const point = toRemoteCoords(event);
    if (!point) return;
    event.preventDefault();
    if (clickTimerRef.current) {
      window.clearTimeout(clickTimerRef.current);
      clickTimerRef.current = null;
    }
    sendInput({ type: "dblclick", x: point.x, y: point.y, button: "left" });
  };

  const handleWheel = (event: ReactWheelEvent) => {
    if (!controlEnabled) return;
    sendInput({ type: "scroll", delta: Math.round(event.deltaY) });
  };

  const modsFromEvent = (event: ReactKeyboardEvent) => {
    const mods: string[] = [];
    if (event.ctrlKey) mods.push("ctrl");
    if (event.altKey) mods.push("alt");
    if (event.shiftKey) mods.push("shift");
    if (event.metaKey) mods.push("win");
    return mods;
  };

  const handleKeyDown = (event: ReactKeyboardEvent) => {
    if (!keyboardEnabled || event.repeat) return;
    if ((event.target as HTMLElement).tagName === "INPUT") return;
    if (["Control", "Shift", "Alt", "Meta"].includes(event.key)) return;
    const mods = modsFromEvent(event);
    if (event.key.length === 1) {
      event.preventDefault();
      if (mods.length > 0) {
        sendInput({ type: "key", key: event.key.toUpperCase(), mods: mods.join(",") });
      } else {
        sendInput({ type: "type", text: event.key });
      }
      return;
    }
    const mapped = SPECIAL_KEYS[event.key];
    if (mapped) {
      event.preventDefault();
      sendInput({ type: "key", key: mapped, mods: mods.join(",") });
    }
  };

  const sendKey = (key: string, mods: string[]) => {
    sendInput({ type: "key", key, mods: mods.join(",") });
  };

  const sendTypeText = () => {
    const text = typeText;
    if (!text) return;
    sendInput({ type: "type", text });
    setTypeText("");
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Remote view & control — {computer.name}</DialogTitle>
          <DialogDescription>
            {wsConnected
              ? "Real-time stream via WebSocket. Move your mouse and type to control the remote PC."
              : wsFrame
                ? "Connected. Waiting for continuous stream…"
                : shot
                  ? `HTTP fallback preview from ${formatDateTime(shot.takenAt)}. Waiting for WebSocket connection…`
                  : "Connecting to agent… frames will stream once the agent is reachable."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant={controlEnabled ? "default" : "outline"}
              size="sm"
              onClick={() => setControlEnabled((value) => !value)}
            >
              <MousePointer2 className="size-4" />
              {controlEnabled ? "Remote control on" : "Enable remote control"}
            </Button>
            <Button
              variant={keyboardEnabled ? "default" : "outline"}
              size="sm"
              disabled={!controlEnabled}
              onClick={() => setKeyboardEnabled((value) => !value)}
            >
              <Keyboard className="size-4" />
              {keyboardEnabled ? "Keyboard on" : "Keyboard off"}
            </Button>
            <div className="flex-1" />
            <Button variant="outline" size="sm" disabled={actionMutation.isPending} onClick={() => requestShot(true)}>
              {actionMutation.isPending ? <Spinner className="size-4" /> : <Camera className="size-4" />}
              Capture fresh view
            </Button>
          </div>

          {controlEnabled ? (
            <div className="flex flex-wrap items-center gap-1.5 rounded-md border p-2">
              <Button variant="ghost" size="sm" onClick={() => sendKey("Tab", ["alt"])}>
                Alt+Tab
              </Button>
              <Button variant="ghost" size="sm" onClick={() => sendKey("R", ["win"])}>
                Win+R
              </Button>
              <Button variant="ghost" size="sm" onClick={() => sendKey("D", ["win"])}>
                Win+D
              </Button>
              <Button variant="ghost" size="sm" onClick={() => sendKey("C", ["ctrl"])}>
                Ctrl+C
              </Button>
              <Button variant="ghost" size="sm" onClick={() => sendKey("V", ["ctrl"])}>
                Ctrl+V
              </Button>
              <Button variant="ghost" size="sm" onClick={() => sendKey("Esc", [])}>
                Esc
              </Button>
              <div className="flex min-w-0 flex-1 items-center gap-2">
                <Input
                  className="h-8 w-full"
                  placeholder="Type text on the remote PC…"
                  value={typeText}
                  onChange={(event) => setTypeText(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      sendTypeText();
                    }
                  }}
                />
                <Button variant="ghost" size="icon" onClick={sendTypeText} disabled={!typeText}>
                  <Send className="size-4" />
                </Button>
              </div>
            </div>
          ) : null}

          <div
            ref={contentRef}
            tabIndex={-1}
            onKeyDown={handleKeyDown}
            onMouseMove={handleMouseMove}
            onMouseDown={handleMouseDown}
            onMouseUp={handleMouseUp}
            onDoubleClick={handleDoubleClick}
            onWheel={handleWheel}
            onContextMenu={(event) => controlEnabled && event.preventDefault()}
            className={cn(
              "relative aspect-video w-full overflow-hidden rounded-md border bg-muted outline-none",
              controlEnabled && "cursor-crosshair focus-visible:ring-2 focus-visible:ring-ring",
            )}
          >
            {(wsFrame || shot) ? (
              <img
                ref={imgRef}
                src={wsFrame ? `data:image/jpeg;base64,${wsFrame}` : screenshotFileUrl(shot!.fileId)}
                alt={`Screenshot of ${computer.name}`}
                className="h-full w-full object-contain"
                draggable={false}
              />
            ) : (
              <div className="flex h-full items-center justify-center gap-2 text-sm text-muted-foreground">
                {!wsConnected ? <Spinner className="size-4" /> : <Monitor className="size-4" />}
                {!wsConnected ? "Connecting to agent…" : "No screenshot yet. Request one above."}
              </div>
            )}
            {controlEnabled && (wsFrame || shot) ? (
              <div className="absolute top-2 left-2 flex items-center gap-1.5 rounded-md bg-black/60 px-2 py-1 text-xs text-white">
                <span className="size-1.5 animate-pulse rounded-full bg-red-500" />
                {wsConnected ? "Live — WebSocket" : "Live — HTTP fallback"}
                {cursor ? ` — ${cursor.x}, ${cursor.y}` : null}
              </div>
            ) : null}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default Computers;
