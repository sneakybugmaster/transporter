import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { PageHeader } from "@/components/app-layout";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, queryKeys } from "@/lib/api";
import { circleLayout, mergeLinks } from "@/lib/topology";
import { cn } from "@/lib/utils";

// Labels get an outline in the card colour so edges don't run through them.
const labelClass = "stroke-card [paint-order:stroke] [stroke-width:4px] [stroke-linejoin:round]";

/** useNarrow tracks phone-width screens, where the graph gets a smaller canvas. */
function useNarrow() {
  const query = "(max-width: 640px)";
  const [narrow, setNarrow] = useState(() => typeof matchMedia !== "undefined" && matchMedia(query).matches);
  useEffect(() => {
    if (typeof matchMedia === "undefined") return;
    const mq = matchMedia(query);
    const on = () => setNarrow(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return narrow;
}

export function TopologyPage() {
  const nodes = useQuery({ queryKey: queryKeys.nodes, queryFn: api.nodes });
  // Nodes report their paths every 30 seconds.
  const topo = useQuery({ queryKey: queryKeys.topology, queryFn: api.topology, refetchInterval: 30_000 });
  const [hover, setHover] = useState<string | null>(null);
  // Drawing units roughly match CSS pixels, so labels stay readable.
  const narrow = useNarrow();
  const W = narrow ? 340 : 640;
  const H = narrow ? 360 : 440;

  const list = [...(nodes.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  const edges = mergeLinks(topo.data?.links ?? [], list);
  const pos = new Map(list.map((n, i) => [n.id, circleLayout(list.length, W / 2, H / 2, Math.min(W, H) / 2 - 60)[i]!]));
  const name = (id: string) => list.find((n) => n.id === id)?.name ?? id;
  const relayed = edges.filter((e) => e.path === "relay").length;

  return (
    <>
      <PageHeader title="Topology" description="How nodes reach each other right now, as they report it." />
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            Mesh
            <Badge variant="success">{edges.length - relayed} direct</Badge>
            {relayed > 0 && <Badge variant="warning">{relayed} relayed</Badge>}
          </CardTitle>
          <CardDescription>
            Solid lines are direct WireGuard paths; dashed lines go through the coordinator's relay, usually because
            both sides are behind strict NATs. Only pairs that have talked recently and that the policy lets see each
            other are shown.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {nodes.isPending || topo.isPending ? (
            <Skeleton className="h-80 w-full" />
          ) : list.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">No nodes yet.</p>
          ) : (
            <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Mesh topology">
              {edges.map((e) => {
                const p = pos.get(e.a)!;
                const q = pos.get(e.b)!;
                const lit = hover === null || hover === e.a || hover === e.b;
                return (
                  <line
                    key={`${e.a}-${e.b}`}
                    x1={p.x}
                    y1={p.y}
                    x2={q.x}
                    y2={q.y}
                    strokeWidth={2}
                    strokeDasharray={e.path === "relay" ? "6 5" : undefined}
                    className={cn(e.path === "direct" ? "stroke-success" : "stroke-warning", !lit && "opacity-15", "transition-opacity")}
                  >
                    <title>
                      {name(e.a)} ↔ {name(e.b)}: {e.path}
                      {e.latencyMs ? `, ${e.latencyMs.toFixed(1)} ms` : ""}
                    </title>
                  </line>
                );
              })}
              {list.map((n) => {
                const p = pos.get(n.id)!;
                return (
                  <g
                    key={n.id}
                    transform={`translate(${p.x} ${p.y})`}
                    onMouseEnter={() => setHover(n.id)}
                    onMouseLeave={() => setHover(null)}
                    className="cursor-default"
                  >
                    <circle r={18} className={cn("stroke-2", n.online ? "fill-card stroke-primary" : "fill-muted stroke-border")} />
                    <text textAnchor="middle" dy="0.35em" className={cn("text-[11px] font-semibold", n.online ? "fill-primary" : "fill-muted-foreground")}>
                      {n.name.slice(0, 2).toUpperCase()}
                    </text>
                    <text textAnchor="middle" y={34} className={labelClass + " fill-foreground text-[12px]"}>
                      {n.name}
                    </text>
                    <text textAnchor="middle" y={48} className={labelClass + " fill-muted-foreground font-mono text-[10px]"}>
                      {n.addresses[0]?.split("/")[0]}
                    </text>
                    <title>
                      {n.name} ({n.online ? "online" : "offline"})
                    </title>
                  </g>
                );
              })}
            </svg>
          )}
        </CardContent>
      </Card>
      {edges.length > 0 && (
        <Card className="py-4">
          <CardContent className="px-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Between</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead>Latency</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {edges.map((e) => (
                  <TableRow key={`${e.a}-${e.b}`}>
                    <TableCell>
                      {name(e.a)} ↔ {name(e.b)}
                    </TableCell>
                    <TableCell>
                      <Badge variant={e.path === "direct" ? "success" : "warning"}>{e.path}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{e.latencyMs ? `${e.latencyMs.toFixed(1)} ms` : "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </>
  );
}
