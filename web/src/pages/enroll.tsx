import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { CircleCheck, KeyRound, TriangleAlert } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";

import { PageHeader } from "@/components/app-layout";
import { CodeBlock, CopyButton } from "@/components/copy-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, queryKeys, type AuthKey, type AuthKeyCreated } from "@/lib/api";
import { installCommands, platforms, type Platform } from "@/lib/commands";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";

import { FormError } from "./auth-shell";

const expiries = [
  { label: "1 hour", seconds: 3600 },
  { label: "1 day", seconds: 86400 },
  { label: "7 days", seconds: 7 * 86400 },
  { label: "30 days", seconds: 30 * 86400 },
  { label: "Never", seconds: 0 },
];

export function EnrollPage() {
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: queryKeys.settings, queryFn: api.settings });
  const keys = useQuery({ queryKey: queryKeys.authKeys, queryFn: api.authKeys });
  const [description, setDescription] = useState("");
  const [reusable, setReusable] = useState(false);
  const [ttl, setTtl] = useState(86400);
  const [created, setCreated] = useState<AuthKeyCreated | null>(null);

  const create = useMutation({
    mutationFn: () => api.createAuthKey({ description, reusable, ttlSeconds: ttl }),
    onSuccess: (k) => {
      setCreated(k);
      setDescription("");
      void qc.invalidateQueries({ queryKey: queryKeys.authKeys });
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate();
  };

  const url = settings.data?.publicURL || window.location.origin;
  const live = created && keys.data?.find((k) => k.id === created.key.id);

  return (
    <>
      <PageHeader title="Enroll device" description="Create an auth key, then run one command on the device." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>New auth key</CardTitle>
            <CardDescription>Keys are secrets: anyone holding one can join the mesh until it expires or is revoked.</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="desc">Description</Label>
                <Input id="desc" placeholder="e.g. office laptops" maxLength={200} value={description} onChange={(e) => setDescription(e.target.value)} />
              </div>
              <div className="flex items-center justify-between gap-4 rounded-md border p-3">
                <div>
                  <Label htmlFor="reusable">Reusable</Label>
                  <p className="text-xs text-muted-foreground">Enroll many devices with the same key.</p>
                </div>
                <Switch id="reusable" checked={reusable} onCheckedChange={setReusable} />
              </div>
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">Expires after</legend>
                <div className="flex flex-wrap gap-2">
                  {expiries.map((x) => (
                    <button
                      key={x.seconds}
                      type="button"
                      aria-pressed={ttl === x.seconds}
                      onClick={() => setTtl(x.seconds)}
                      className={cn(
                        "rounded-md border px-3 py-1.5 text-sm",
                        ttl === x.seconds ? "border-primary bg-primary/10 text-primary" : "hover:bg-accent",
                      )}
                    >
                      {x.label}
                    </button>
                  ))}
                </div>
              </fieldset>
              <FormError error={create.error} />
              <Button type="submit" disabled={create.isPending}>
                <KeyRound /> Create key
              </Button>
            </form>
          </CardContent>
        </Card>

        {created ? (
          <Card className="border-primary/40">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">Run this on the device</CardTitle>
              <CardDescription className="flex items-start gap-2">
                <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-500" />
                The key is shown only now. Copy it before leaving this page.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Auth key</Label>
                <div className="flex items-center gap-2">
                  <code className="min-w-0 flex-1 truncate rounded-md border bg-muted px-2 py-1.5 font-mono text-xs" data-testid="authkey-secret">
                    {created.secret}
                  </code>
                  <CopyButton value={created.secret} />
                </div>
              </div>
              <InstallCommands url={url} secret={created.secret} />
              <p className="flex items-center gap-2 text-sm" role="status" data-testid="enrolled-count">
                {live && live.usedCount > 0 ? (
                  <>
                    <CircleCheck className="size-4 text-success" />
                    {live.usedCount} {live.usedCount === 1 ? "device" : "devices"} enrolled with this key.{" "}
                    <Link to="/nodes" className="text-primary hover:underline">
                      View nodes
                    </Link>
                  </>
                ) : (
                  <span className="text-muted-foreground">Waiting for a device to use this key…</span>
                )}
              </p>
            </CardContent>
          </Card>
        ) : (
          <Card className="justify-center border-dashed">
            <CardContent className="text-sm text-muted-foreground">
              Create a key to get the install commands for Linux, macOS, Windows and Docker.
            </CardContent>
          </Card>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Auth keys</CardTitle>
          <CardDescription>Revoking a key stops new enrollments; devices already enrolled keep working.</CardDescription>
        </CardHeader>
        <CardContent>
          <KeysTable keys={keys.data ?? []} />
        </CardContent>
      </Card>
    </>
  );
}

function InstallCommands({ url, secret }: { url: string; secret: string }) {
  const [tab, setTab] = useState<Platform>("linux");
  const cmds = installCommands(url, secret);
  const note = platforms.find((p) => p.id === tab)?.note;
  return (
    <div className="space-y-3">
      <div role="tablist" className="inline-flex flex-wrap rounded-md border p-0.5 text-sm">
        {platforms.map((p) => (
          <button
            key={p.id}
            role="tab"
            type="button"
            aria-selected={tab === p.id}
            onClick={() => setTab(p.id)}
            className={cn("rounded px-3 py-1", tab === p.id ? "bg-accent font-medium" : "text-muted-foreground")}
          >
            {p.label}
          </button>
        ))}
      </div>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
        <div className="min-w-0 flex-1 space-y-2">
          <CodeBlock value={cmds[tab]} label="Copy command" />
          {note && <p className="text-xs text-muted-foreground">{note}</p>}
        </div>
        <div className="shrink-0 self-start rounded-md border bg-white p-2" title="Scan to copy the command to another device">
          <QRCodeSVG value={cmds[tab]} size={112} aria-label="QR code of the install command" />
        </div>
      </div>
    </div>
  );
}

function keyState(k: AuthKey): { label: string; variant: "success" | "secondary" | "destructive" } {
  if (k.revoked) return { label: "revoked", variant: "destructive" };
  if (!k.valid) return { label: k.reusable ? "expired" : "used", variant: "secondary" };
  return { label: "valid", variant: "success" };
}

function KeysTable({ keys }: { keys: AuthKey[] }) {
  const qc = useQueryClient();
  const revoke = useMutation({
    mutationFn: api.revokeAuthKey,
    onSuccess: () => {
      toast.success("Key revoked");
      void qc.invalidateQueries({ queryKey: queryKeys.authKeys });
    },
    onError: (e) => toast.error(e.message),
  });
  if (keys.length === 0) return <p className="text-sm text-muted-foreground">No keys yet.</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Description</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Used</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="hidden sm:table-cell">Expires</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {keys.map((k) => {
          const st = keyState(k);
          return (
            <TableRow key={k.id}>
              <TableCell>
                {k.description || <span className="text-muted-foreground">—</span>}
                <div className="font-mono text-xs text-muted-foreground">{k.id}</div>
              </TableCell>
              <TableCell>{k.reusable ? "reusable" : "single use"}</TableCell>
              <TableCell className="tabular-nums">{k.usedCount}</TableCell>
              <TableCell>
                <Badge variant={st.variant}>{st.label}</Badge>
              </TableCell>
              <TableCell className="hidden text-muted-foreground sm:table-cell">
                {k.expiresAt ? relativeTime(k.expiresAt) : "never"}
              </TableCell>
              <TableCell className="text-right">
                {!k.revoked && k.valid && (
                  <Button variant="ghost" size="sm" onClick={() => revoke.mutate(k.id)} disabled={revoke.isPending}>
                    Revoke
                  </Button>
                )}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
