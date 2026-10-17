import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, TriangleAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";

import { PageHeader } from "@/components/app-layout";
import { CopyButton } from "@/components/copy-button";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api, queryKeys } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";

import { FormError } from "./auth-shell";

export function SettingsPage() {
  const me = useQuery({ queryKey: queryKeys.me, queryFn: api.me });
  return (
    <>
      <PageHeader title="Settings" description="Coordinator configuration and your account." />
      <div className="grid gap-4 lg:grid-cols-2">
        <CoordinatorSettings />
        <div className="space-y-4">
          <KeyExpiryCard />
          {me.data?.hasPassword !== false && <PasswordForm />}
        </div>
        <div className="lg:col-span-2">
          <APITokens />
        </div>
      </div>
    </>
  );
}

const expiryChoices = [
  { days: 0, label: "Never" },
  { days: 30, label: "30 days" },
  { days: 90, label: "90 days" },
  { days: 180, label: "180 days" },
  { days: 365, label: "1 year" },
];

function KeyExpiryCard() {
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: queryKeys.settings, queryFn: api.settings });
  const save = useMutation({
    mutationFn: (days: number) => api.updateSettings({ keyExpiryDays: days }),
    onSuccess: (s) => {
      qc.setQueryData(queryKeys.settings, s);
      toast.success(s.keyExpiryDays ? `Node keys now last ${s.keyExpiryDays} days` : "Node keys no longer expire");
    },
  });
  const current = settings.data?.keyExpiryDays;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Node key expiry</CardTitle>
        <CardDescription>
          After this long, a node must re-authenticate with an auth key, which limits how long a stolen node identity
          stays useful. Applies from each node's next authentication; individual nodes can be exempted on the Nodes page.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-2" role="group" aria-label="Node key expiry">
          {expiryChoices.map((c) => (
            <button
              key={c.days}
              type="button"
              aria-pressed={current === c.days}
              disabled={save.isPending || current === undefined}
              onClick={() => save.mutate(c.days)}
              className={cn(
                "rounded-md border px-3 py-1.5 text-sm",
                current === c.days ? "border-primary bg-primary/10 text-primary" : "hover:bg-accent",
              )}
            >
              {c.label}
            </button>
          ))}
        </div>
        {current !== undefined && !expiryChoices.some((c) => c.days === current) && (
          <p className="text-sm text-muted-foreground">Currently {current} days.</p>
        )}
        <FormError error={save.error} />
      </CardContent>
    </Card>
  );
}

const tokenLifetimes = [
  { seconds: 30 * 86400, label: "30 days" },
  { seconds: 90 * 86400, label: "90 days" },
  { seconds: 365 * 86400, label: "1 year" },
  { seconds: 0, label: "Never" },
];

function APITokens() {
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: queryKeys.tokens, queryFn: api.tokens });
  const [description, setDescription] = useState("");
  const [ttl, setTtl] = useState(tokenLifetimes[1]!.seconds);
  const [secret, setSecret] = useState<string | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: queryKeys.tokens });
  const create = useMutation({
    mutationFn: () => api.createToken({ description, ttlSeconds: ttl }),
    onSuccess: (t) => {
      setSecret(t.secret);
      setDescription("");
      refresh();
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.deleteToken(id),
    onSuccess: () => {
      toast.success("Token revoked");
      refresh();
    },
    onError: (e) => toast.error(e.message),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate();
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle>API tokens</CardTitle>
        <CardDescription>
          For scripts and CI: send <code className="font-mono">Authorization: Bearer &lt;token&gt;</code> to{" "}
          <code className="font-mono">/api/v1</code>. A token acts as you, except that it cannot manage tokens or
          change passwords.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
          <div className="min-w-48 flex-1 space-y-1">
            <Label htmlFor="token-desc">Description</Label>
            <Input id="token-desc" placeholder="e.g. terraform" maxLength={200} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="token-ttl">Expires after</Label>
            <select
              id="token-ttl"
              value={ttl}
              onChange={(e) => setTtl(Number(e.target.value))}
              className="h-9 rounded-md border bg-transparent px-2 text-sm"
            >
              {tokenLifetimes.map((l) => (
                <option key={l.seconds} value={l.seconds}>
                  {l.label}
                </option>
              ))}
            </select>
          </div>
          <Button type="submit" disabled={create.isPending}>
            <KeyRound /> Create token
          </Button>
        </form>
        <FormError error={create.error} />
        {secret && (
          <div className="space-y-2 rounded-md border border-primary/40 p-3" role="status">
            <p className="flex items-center gap-2 text-sm">
              <TriangleAlert className="size-4 shrink-0 text-warning" /> Copy the token now; it is not shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded-md border bg-muted px-2 py-1.5 font-mono text-xs" data-testid="token-secret">
                {secret}
              </code>
              <CopyButton value={secret} />
            </div>
          </div>
        )}
        {tokens.data && tokens.data.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Description</TableHead>
                <TableHead className="hidden sm:table-cell">Acts as</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="hidden md:table-cell">Last used</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.data.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>
                    {t.description || <span className="text-muted-foreground">—</span>}
                    <div className="font-mono text-xs text-muted-foreground">{t.id}</div>
                  </TableCell>
                  <TableCell className="hidden sm:table-cell">{t.admin}</TableCell>
                  <TableCell className="text-muted-foreground">{t.expiresAt ? relativeTime(t.expiresAt) : "never"}</TableCell>
                  <TableCell className="hidden text-muted-foreground md:table-cell">{t.lastUsed ? relativeTime(t.lastUsed) : "never"}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => revoke.mutate(t.id)} disabled={revoke.isPending}>
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <p className="text-sm text-muted-foreground">No API tokens.</p>
        )}
      </CardContent>
    </Card>
  );
}

function CoordinatorSettings() {
  const settings = useQuery({ queryKey: queryKeys.settings, queryFn: api.settings });
  const s = settings.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Coordinator</CardTitle>
        <CardDescription>Network settings come from the coordinator's flags and environment.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Mounted once loaded so the field starts with the saved value. */}
        {s && <PublicURLForm saved={s.publicURL} />}
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
          <dt className="text-muted-foreground">Mesh network</dt>
          <dd className="font-mono">{s?.networkPrefix ?? "—"}</dd>
          <dt className="text-muted-foreground">STUN server</dt>
          <dd>{s ? (s.stunPort ? `UDP port ${s.stunPort}` : "disabled") : "—"}</dd>
          <dt className="text-muted-foreground">Relay</dt>
          <dd>{s ? (s.relayEnabled ? "enabled" : "disabled") : "—"}</dd>
          <dt className="text-muted-foreground">Version</dt>
          <dd className="font-mono">{s?.version ?? "—"}</dd>
        </dl>
      </CardContent>
    </Card>
  );
}

function PublicURLForm({ saved }: { saved: string }) {
  const qc = useQueryClient();
  const [url, setUrl] = useState(saved);
  const save = useMutation({
    mutationFn: () => api.updateSettings({ publicURL: url }),
    onSuccess: (s) => {
      qc.setQueryData(queryKeys.settings, s);
      toast.success("Settings saved");
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };

  return (
    <form onSubmit={submit} className="space-y-2">
      <Label htmlFor="public-url">Public URL</Label>
      <div className="flex gap-2">
        <Input id="public-url" type="url" placeholder={window.location.origin} value={url} onChange={(e) => setUrl(e.target.value)} />
        <Button type="submit" disabled={save.isPending || url === saved}>
          Save
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">Used in enrollment commands. Leave empty to use this page's address.</p>
      <FormError error={save.error} />
    </form>
  );
}

function PasswordForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [localError, setLocalError] = useState("");
  const change = useMutation({
    mutationFn: () => api.changePassword({ currentPassword: current, newPassword: next }),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      setConfirm("");
      toast.success("Password changed. Other sessions were signed out.");
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setLocalError("");
    if (next !== confirm) return setLocalError("The new passwords don't match.");
    change.mutate();
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
        <CardDescription>Signs out your other sessions.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="current">Current password</Label>
            <Input id="current" type="password" required autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="new">New password</Label>
            <Input id="new" type="password" required minLength={10} autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-new">Confirm new password</Label>
            <Input id="confirm-new" type="password" required autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </div>
          <FormError error={localError || change.error} />
          <Button type="submit" disabled={change.isPending}>
            Change password
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
