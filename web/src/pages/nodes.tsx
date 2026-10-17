import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { KeyRound, Search, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";

import { PageHeader } from "@/components/app-layout";
import { CopyButton } from "@/components/copy-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, queryKeys, type Node } from "@/lib/api";
import { osLabel, relativeTime } from "@/lib/format";

import { FormError } from "./auth-shell";

export function NodesPage() {
  const nodes = useQuery({ queryKey: queryKeys.nodes, queryFn: api.nodes });
  const [filter, setFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const q = filter.trim().toLowerCase();
  const shown = (nodes.data ?? []).filter(
    (n) => !q || [n.name, n.hostname, n.os, ...n.addresses].some((v) => v.toLowerCase().includes(q)),
  );
  const selected = nodes.data?.find((n) => n.id === selectedId);

  return (
    <>
      <PageHeader title="Nodes" description="Every device enrolled in the mesh.">
        <Button asChild variant="outline">
          <Link to="/enroll">
            <KeyRound /> Enroll device
          </Link>
        </Button>
      </PageHeader>
      <Card className="py-4">
        <CardContent className="space-y-4 px-4">
          <div className="relative max-w-sm">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search name, address, OS…"
              aria-label="Search nodes"
              className="pl-8"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>
          {nodes.isPending ? (
            <div className="space-y-2">
              <Skeleton className="h-9" />
              <Skeleton className="h-9" />
              <Skeleton className="h-9" />
            </div>
          ) : shown.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              {nodes.data?.length ? "No nodes match your search." : "No nodes yet."}
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Address</TableHead>
                  <TableHead className="hidden sm:table-cell">OS</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="hidden md:table-cell">Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shown.map((n) => (
                  <TableRow key={n.id} className="cursor-pointer" onClick={() => setSelectedId(n.id)}>
                    <TableCell>
                      <button type="button" className="text-left font-medium hover:underline" onClick={() => setSelectedId(n.id)}>
                        {n.name}
                      </button>
                      {n.hostname !== n.name && <div className="text-xs text-muted-foreground">{n.hostname}</div>}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{n.addresses[0]?.split("/")[0]}</TableCell>
                    <TableCell className="hidden sm:table-cell">{osLabel(n.os)}</TableCell>
                    <TableCell>
                      <Badge variant={n.online ? "success" : "secondary"}>{n.online ? "online" : "offline"}</Badge>
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">
                      {n.online ? "now" : relativeTime(n.lastSeen)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      {selected && <NodeDialog node={selected} onClose={() => setSelectedId(null)} />}
    </>
  );
}

function NodeDialog({ node, onClose }: { node: Node; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(node.name);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: queryKeys.nodes });
    void qc.invalidateQueries({ queryKey: queryKeys.stats });
  };

  const rename = useMutation({
    mutationFn: () => api.renameNode(node.id, name),
    onSuccess: (n) => {
      toast.success(`Renamed to ${n.name}`);
      setName(n.name);
      refresh();
    },
  });
  const remove = useMutation({
    mutationFn: () => api.deleteNode(node.id),
    onSuccess: () => {
      toast.success(`${node.name} removed from the mesh`);
      refresh();
      onClose();
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    rename.mutate();
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {node.name}
            <Badge variant={node.online ? "success" : "secondary"}>{node.online ? "online" : "offline"}</Badge>
          </DialogTitle>
          <DialogDescription>
            {osLabel(node.os)} · enrolled {relativeTime(node.createdAt)}
          </DialogDescription>
        </DialogHeader>

        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Mesh address</dt>
          <dd className="font-mono">{node.addresses.join(", ")}</dd>
          <dt className="text-muted-foreground">Hostname</dt>
          <dd>{node.hostname}</dd>
          <dt className="text-muted-foreground">Last seen</dt>
          <dd>{node.online ? "now" : relativeTime(node.lastSeen)}</dd>
          <dt className="text-muted-foreground">Endpoints</dt>
          <dd className="font-mono text-xs">
            {node.endpoints.length ? node.endpoints.map((e) => <div key={e}>{e}</div>) : "—"}
          </dd>
          <dt className="text-muted-foreground">Public key</dt>
          <dd className="flex min-w-0 items-center gap-2">
            <span className="min-w-0 truncate font-mono text-xs" title={node.publicKey}>
              {node.publicKey}
            </span>
            <CopyButton value={node.publicKey} />
          </dd>
        </dl>

        <form onSubmit={submit} className="space-y-2">
          <Label htmlFor="node-name">Name</Label>
          <div className="flex min-w-0 gap-2">
            <Input id="node-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={63} />
            <Button type="submit" variant="secondary" disabled={rename.isPending || name === node.name}>
              Rename
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">Lowercase letters, digits and hyphens; other characters are replaced.</p>
          <FormError error={rename.error} />
        </form>

        <DialogFooter className="items-center border-t pt-4 sm:justify-between">
          {confirmDelete ? (
            <div className="flex w-full flex-wrap items-center gap-2">
              <span className="text-sm">Remove {node.name}? It disconnects immediately and must re-enroll.</span>
              <div className="ml-auto flex gap-2">
                <Button variant="ghost" onClick={() => setConfirmDelete(false)}>
                  Cancel
                </Button>
                <Button variant="destructive" onClick={() => remove.mutate()} disabled={remove.isPending}>
                  Remove
                </Button>
              </div>
            </div>
          ) : (
            <Button variant="ghost" className="text-destructive" onClick={() => setConfirmDelete(true)}>
              <Trash2 /> Remove from mesh
            </Button>
          )}
        </DialogFooter>
        <FormError error={remove.error} />
      </DialogContent>
    </Dialog>
  );
}
