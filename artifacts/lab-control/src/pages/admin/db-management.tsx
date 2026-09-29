import { useState } from "react";
import type { FormEvent } from "react";
import {
  useCreateDbConnection,
  useDeleteDbConnection,
  useGetDbConnections,
  usePushDbSnapshot,
  useTestDbConnection,
  useUpdateDbConnection,
  type PlatformDbConnection,
} from "@workspace/api-client-react";
import {
  CheckCircle2,
  Copy,
  Database,
  Plus,
  PlugZap,
  RefreshCw,
  Send,
  Trash2,
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

function hostFromUrl(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function StatusBadge({ status }: { status: PlatformDbConnection["status"] }) {
  if (status === "ok") {
    return (
      <Badge variant="success">
        <CheckCircle2 className="size-3" />
        Online
      </Badge>
    );
  }
  if (status === "error") {
    return (
      <Badge variant="destructive">
        <XCircle className="size-3" />
        Error
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="text-muted-foreground">
      Unknown
    </Badge>
  );
}

export function DbManagementSection() {
  const connectionsQuery = useGetDbConnections();
  const createMutation = useCreateDbConnection();
  const updateMutation = useUpdateDbConnection();
  const deleteMutation = useDeleteDbConnection();
  const testMutation = useTestDbConnection();
  const pushMutation = usePushDbSnapshot();

  const connections = connectionsQuery.data?.connections ?? [];

  const [addOpen, setAddOpen] = useState(false);
  const [addName, setAddName] = useState("");
  const [addUrl, setAddUrl] = useState("");
  const [addNote, setAddNote] = useState("");
  const [testingIds, setTestingIds] = useState<number[]>([]);
  const [snapshotTarget, setSnapshotTarget] = useState<PlatformDbConnection | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<PlatformDbConnection | null>(null);

  const runTest = async (id: number) => {
    setTestingIds((ids) => [...ids, id]);
    try {
      const result = await testMutation.mutateAsync(id);
      if (result.ok) {
        toast.success(
          result.latencyMs != null ? `Connected in ${result.latencyMs} ms` : "Connected",
        );
      } else {
        toast.error(`Connection failed: ${result.error ?? "unknown error"}`);
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Test failed");
    } finally {
      setTestingIds((ids) => ids.filter((x) => x !== id));
    }
  };

  const runTestAll = async () => {
    if (connections.length === 0) {
      toast.info("No connections registered yet.");
      return;
    }
    for (const connection of connections) {
      await runTest(connection.id);
    }
  };

  const copyUrl = async (connection: PlatformDbConnection) => {
    try {
      await navigator.clipboard.writeText(connection.url);
      toast.success(`Copied URL for ${connection.name}`);
    } catch {
      toast.error("Clipboard unavailable — copy the URL from the cell below.");
    }
  };

  const setActive = (connection: PlatformDbConnection) => {
    updateMutation.mutate(
      { id: connection.id, data: { isActive: true } },
      {
        onSuccess: () =>
          toast.success(`${connection.name} is now the active database.`),
        onError: (error) => toast.error(error.message),
      },
    );
  };

  const submitAdd = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const created = await createMutation.mutateAsync({
        name: addName.trim(),
        url: addUrl.trim(),
        note: addNote.trim() || undefined,
      });
      toast.success(`Registered ${created.name}.`);
      setAddOpen(false);
      setAddName("");
      setAddUrl("");
      setAddNote("");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not register connection");
    }
  };

  const confirmSnapshot = async () => {
    if (!snapshotTarget) return;
    try {
      const result = await pushMutation.mutateAsync(snapshotTarget.id);
      toast.success(
        `Snapshot written to ${snapshotTarget.name} (${result.rows} row inserted).`,
      );
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Snapshot push failed",
      );
    }
    setSnapshotTarget(null);
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    try {
      await deleteMutation.mutateAsync(deleteTarget.id);
      toast.success(`Removed ${deleteTarget.name}.`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not remove connection");
    }
    setDeleteTarget(null);
  };

  return (
    <>
      <div className="flex flex-col gap-1">
        <h2 className="text-xl font-bold">Databases</h2>
        <p className="text-sm text-muted-foreground">
          Register Postgres connection URLs under one dashboard. Mark one as the
          active database for your sites, copy its URL when you need it, and
          push a manual snapshot to any target.
        </p>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2">
              <Database className="size-4 text-muted-foreground" />
              Connection registry
            </CardTitle>
            <CardDescription>
              {connections.length === 0
                ? "No database connections yet — add your first one."
                : `${connections.length} connection${connections.length === 1 ? "" : "s"} registered · ${connections.filter((c) => c.isActive).length} active`}
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void runTestAll()}
              disabled={testingIds.length > 0}
            >
              <RefreshCw className="size-4" />
              Test all
            </Button>
            <Button size="sm" onClick={() => setAddOpen(true)}>
              <Plus className="size-4" />
              Add connection
            </Button>
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Active</TableHead>
                <TableHead>Connection URL</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {connectionsQuery.isLoading ? (
                Array.from({ length: 2 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell colSpan={6}>
                      <Skeleton className="h-8 w-full" />
                    </TableCell>
                  </TableRow>
                ))
              ) : connections.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="py-8 text-center text-sm text-muted-foreground"
                  >
                    No connections registered. Use “Add connection” to input
                    your first database server URL.
                  </TableCell>
                </TableRow>
              ) : (
                connections.map((connection) => (
                  <TableRow key={connection.id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{connection.name}</span>
                        {connection.note ? (
                          <span className="text-xs text-muted-foreground">
                            {connection.note}
                          </span>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {hostFromUrl(connection.url)}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-0.5">
                        <StatusBadge status={connection.status} />
                        {connection.status !== "unknown" && connection.lastCheckedAt ? (
                          <span className="text-xs text-muted-foreground">
                            checked {new Date(connection.lastCheckedAt).toLocaleString()}
                          </span>
                        ) : null}
                        {connection.lastError ? (
                          <span
                            className="max-w-48 truncate text-xs text-destructive"
                            title={connection.lastError}
                          >
                            {connection.lastError}
                          </span>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell>
                      {connection.isActive ? (
                        <Badge variant="info">In use</Badge>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setActive(connection)}
                          disabled={updateMutation.isPending}
                        >
                          Set active
                        </Button>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <code className="max-w-56 truncate rounded bg-muted px-1.5 py-0.5 text-xs">
                          {connection.url}
                        </code>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          aria-label={`Copy URL for ${connection.name}`}
                          onClick={() => void copyUrl(connection)}
                        >
                          <Copy className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => void runTest(connection.id)}
                          disabled={testingIds.includes(connection.id)}
                        >
                          {testingIds.includes(connection.id) ? (
                            <Spinner className="size-4" />
                          ) : (
                            <PlugZap className="size-4" />
                          )}
                          Test
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSnapshotTarget(connection)}
                          disabled={pushMutation.isPending}
                        >
                          <Send className="size-4" />
                          Snapshot
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Delete ${connection.name}`}
                          onClick={() => setDeleteTarget(connection)}
                        >
                          <Trash2 className="size-4 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <form onSubmit={(e) => void submitAdd(e)}>
            <DialogHeader>
              <DialogTitle>Add database connection</DialogTitle>
              <DialogDescription>
                Input a Postgres connection URL (for example a Neon, Supabase or
                RDS external URL). It becomes available here for health checks,
                copying, and snapshots.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="db-name">Name</Label>
                <Input
                  id="db-name"
                  value={addName}
                  onChange={(e) => setAddName(e.target.value)}
                  placeholder="db 1"
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="db-url">Connection URL</Label>
                <Input
                  id="db-url"
                  value={addUrl}
                  onChange={(e) => setAddUrl(e.target.value)}
                  placeholder="postgres://user:password@host:5432/database"
                  required
                  className="font-mono text-xs"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="db-note">Note (optional)</Label>
                <Input
                  id="db-note"
                  value={addNote}
                  onChange={(e) => setAddNote(e.target.value)}
                  placeholder="Which site / purpose this database serves"
                />
              </div>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setAddOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? <Spinner className="size-4" /> : null}
                Register
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={snapshotTarget !== null}
        onOpenChange={(open) => {
          if (!open) setSnapshotTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Push snapshot to {snapshotTarget?.name}?</DialogTitle>
            <DialogDescription>
              This writes a JSON snapshot of the platform (all tenants with
              their computer and admin counts) into the{" "}
              <code className="rounded bg-muted px-1 py-0.5 text-xs">
                lvosec_platform_snapshots
              </code>{" "}
              table on the target database. Data flows manually, per target.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setSnapshotTarget(null)}
            >
              Cancel
            </Button>
            <Button
              onClick={() => void confirmSnapshot()}
              disabled={pushMutation.isPending}
            >
              {pushMutation.isPending ? <Spinner className="size-4" /> : null}
              Push snapshot
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove {deleteTarget?.name}?</DialogTitle>
            <DialogDescription>
              The connection is removed from this dashboard. Nothing is deleted
              on the database itself.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => void confirmDelete()}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? <Spinner className="size-4" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}