import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Waypoints } from "lucide-react";

import { PageHeader } from "@/components/app-layout";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api, queryKeys, type Node } from "@/lib/api";
import { isExit, pendingRoutes } from "@/lib/routes";

import { FormError } from "./auth-shell";
import { RouteApprovals } from "./nodes";

export function RoutesPage() {
  const nodes = useQuery({ queryKey: queryKeys.nodes, queryFn: api.nodes });
  const routers = (nodes.data ?? []).filter((n) => n.advertisedRoutes.length + n.approvedRoutes.length > 0);
  const pending = routers.reduce((sum, n) => sum + pendingRoutes(n).length, 0);

  return (
    <>
      <PageHeader title="Routes" description="Subnet routers and exit nodes, and the routes they may use." />
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Advertised routes {pending > 0 && <Badge variant="warning">{pending} awaiting approval</Badge>}
          </CardTitle>
          <CardDescription>
            Nodes offer routes with <code className="font-mono">--advertise-routes</code> and{" "}
            <code className="font-mono">--advertise-exit-node</code>. A route is used only once approved here, or
            automatically by the policy's <code className="font-mono">autoApprovers</code>. Other nodes use subnet routes
            with <code className="font-mono">--accept-routes</code> and an exit node with{" "}
            <code className="font-mono">--exit-node &lt;name&gt;</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {nodes.isPending ? (
            <Skeleton className="h-24" />
          ) : routers.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">No node advertises routes yet.</p>
          ) : (
            routers.map((n) => <RouterRow key={n.id} node={n} />)
          )}
        </CardContent>
      </Card>
    </>
  );
}

function RouterRow({ node }: { node: Node }) {
  const qc = useQueryClient();
  const approve = useMutation({
    mutationFn: (approved: string[]) => api.updateNode(node.id, { approvedRoutes: approved }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: queryKeys.nodes }),
  });
  return (
    <section className="space-y-2 rounded-lg border p-3" aria-label={`Routes of ${node.name}`}>
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="font-medium">{node.name}</h2>
        <span className="font-mono text-xs text-muted-foreground">{node.addresses[0]?.split("/")[0]}</span>
        <Badge variant={node.online ? "success" : "secondary"}>{node.online ? "online" : "offline"}</Badge>
        {node.advertisedRoutes.some(isExit) && (
          <Badge variant="outline">
            <Globe /> offers exit
          </Badge>
        )}
        {node.advertisedRoutes.some((r) => !isExit(r)) && (
          <Badge variant="outline">
            <Waypoints /> subnet router
          </Badge>
        )}
      </div>
      <RouteApprovals node={node} pending={approve.isPending} onChange={(r) => approve.mutate(r)} />
      <FormError error={approve.error} />
    </section>
  );
}
