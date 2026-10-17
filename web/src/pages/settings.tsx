import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";

import { PageHeader } from "@/components/app-layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, queryKeys } from "@/lib/api";

import { FormError } from "./auth-shell";

export function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" description="Coordinator configuration and your account." />
      <div className="grid gap-4 lg:grid-cols-2">
        <CoordinatorSettings />
        <PasswordForm />
      </div>
    </>
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
