import { useInfiniteQuery } from "@tanstack/react-query";

import { PageHeader } from "@/components/app-layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, queryKeys } from "@/lib/api";
import { relativeTime } from "@/lib/format";

const actionLabels: Record<string, string> = {
  "setup.complete": "Completed setup",
  "admin.password": "Changed password",
  "node.rename": "Renamed node",
  "node.tags": "Set node tags",
  "node.routes": "Changed approved routes",
  "node.delete": "Removed node",
  "authkey.create": "Created auth key",
  "authkey.revoke": "Revoked auth key",
  "settings.update": "Changed settings",
  "policy.update": "Updated access policy",
  "dns.update": "Updated DNS settings",
  "routes.approve": "Auto-approved routes",
};

export function AuditPage() {
  const audit = useInfiniteQuery({
    queryKey: queryKeys.audit,
    queryFn: ({ pageParam }) => api.audit(pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.length === 100 ? last[last.length - 1]?.id : undefined),
  });
  const entries = audit.data?.pages.flat() ?? [];

  return (
    <>
      <PageHeader title="Audit log" description="Who changed what, and when." />
      <Card className="py-4">
        <CardContent className="px-4">
          {audit.isPending ? (
            <div className="space-y-2">
              <Skeleton className="h-9" />
              <Skeleton className="h-9" />
            </div>
          ) : entries.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Nothing has changed yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Who</TableHead>
                  <TableHead>What</TableHead>
                  <TableHead className="hidden md:table-cell">Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="whitespace-nowrap text-muted-foreground" title={new Date(e.time).toLocaleString()}>
                      {relativeTime(e.time)}
                    </TableCell>
                    <TableCell>{e.actor}</TableCell>
                    <TableCell>
                      {actionLabels[e.action] ?? e.action}
                      {e.target && <span className="ml-1 font-mono text-xs text-muted-foreground">{e.target}</span>}
                    </TableCell>
                    <TableCell className="hidden max-w-sm truncate text-xs text-muted-foreground md:table-cell" title={e.detail}>
                      {e.detail}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {audit.hasNextPage && (
            <div className="mt-4 flex justify-center">
              <Button variant="outline" size="sm" onClick={() => void audit.fetchNextPage()} disabled={audit.isFetchingNextPage}>
                Load older entries
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </>
  );
}
