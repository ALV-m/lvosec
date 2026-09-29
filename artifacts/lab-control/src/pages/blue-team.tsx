import { useState } from "react";
import {
  type LabFinding,
  type PostureFinding,
  type PostureSeverity,
  type PostureState,
  useGetBlueTeamPosture,
  useGetBlueTeamSoftware,
  searchBlueTeamRecords,
} from "@workspace/api-client-react";
import {
  AlertTriangle,
  ChevronRight,
  Crosshair,
  Database,
  Radar,
  Search,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
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