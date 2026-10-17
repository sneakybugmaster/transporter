import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Activity, KeyRound, Network, Server } from "lucide-react";

import { PageHeader } from "@/components/app-layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api, queryKeys } from "@/lib/api";
import { osLabel, relativeTime } from "@/lib/format";

export function DashboardPage() {
  const stats = useQuery({ queryKey: queryKeys.stats, queryFn: api.stats });
  const nodes = useQuery({ queryKey: queryKeys.nodes, queryFn: api.nodes });
  const settings = useQuery({ queryKey: queryKeys.settings, queryFn: api.settings });
  const version = useQuery({ queryKey: queryKeys.version, queryFn: api.version, refetchInterval: 15_000 });

  const recent = [...(nodes.data ?? [])].sort((a, b) => b.lastSeen.localeCompare(a.lastSeen)).slice(0, 5);

  return (
    <>
      <PageHeader title="Dashboard" description="Overview of your mesh network." />
      <div className="grid grid-cols-3 gap-2 sm:gap-4">
        <StatCard label="Nodes" value={stats.data?.nodes} icon={Server} />
        <StatCard label="Online" value={stats.data?.online} icon={Activity} />
        <StatCard
          label="Offline"
          value={stats.data ? stats.data.nodes - stats.data.online : undefined}
          icon={Network}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recently active nodes</CardTitle>
            <CardDescription>Updates live as devices connect and disconnect.</CardDescription>
          </CardHeader>
          <CardContent>
            {nodes.isPending ? (
              <div className="space-y-2">
                <Skeleton className="h-8" />
                <Skeleton className="h-8" />
              </div>
            ) : recent.length === 0 ? (
              <div className="flex flex-col items-start gap-3 rounded-md border border-dashed p-6">
                <p className="text-sm text-muted-foreground">No devices yet. Create an auth key and run one command on each device.</p>
                <Button asChild>
                  <Link to="/enroll">
                    <KeyRound /> Enroll your first device
                  </Link>
                </Button>
              </div>
            ) : (
              <ul className="divide-y">
                {recent.map((n) => (
                  <li key={n.id} className="flex items-center gap-3 py-2 text-sm">
                    <span
                      className={`size-2 shrink-0 rounded-full ${n.online ? "bg-success" : "bg-muted-foreground/40"}`}
                      aria-label={n.online ? "online" : "offline"}
                    />
                    <span className="font-medium">{n.name}</span>
                    <span className="font-mono text-xs text-muted-foreground">{n.addresses[0]?.split("/")[0]}</span>
                    <span className="hidden text-muted-foreground sm:inline">{osLabel(n.os)}</span>
                    <span className="ml-auto text-xs text-muted-foreground">
                      {n.online ? "online now" : `seen ${relativeTime(n.lastSeen)}`}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Coordinator{" "}
              {version.isError ? (
                <Badge variant="destructive">unreachable</Badge>
              ) : (
                version.isSuccess && <Badge variant="success">healthy</Badge>
              )}
            </CardTitle>
            <CardDescription>Control plane, STUN and relay.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
              <dt className="text-muted-foreground">Version</dt>
              <dd className="truncate font-mono">{version.data?.version ?? "—"}</dd>
              <dt className="text-muted-foreground">Network</dt>
              <dd className="font-mono">{settings.data?.networkPrefix ?? "—"}</dd>
              <dt className="text-muted-foreground">STUN</dt>
              <dd>{settings.data ? (settings.data.stunPort ? `UDP ${settings.data.stunPort}` : "off") : "—"}</dd>
              <dt className="text-muted-foreground">Relay</dt>
              <dd>{settings.data ? (settings.data.relayEnabled ? "on" : "off") : "—"}</dd>
            </dl>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function StatCard({ label, value, icon: Icon }: { label: string; value?: number; icon: typeof Server }) {
  return (
    <Card className="gap-2 py-3 sm:py-4">
      <CardHeader className="flex items-center justify-between px-3 sm:px-4">
        <CardDescription>{label}</CardDescription>
        <Icon className="hidden size-4 text-muted-foreground sm:block" />
      </CardHeader>
      <CardContent className="px-3 sm:px-4">
        {value === undefined ? (
          <Skeleton className="h-8 w-12" />
        ) : (
          <div className="text-2xl font-semibold tabular-nums sm:text-3xl" data-testid={`stat-${label.toLowerCase()}`}>
            {value}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
