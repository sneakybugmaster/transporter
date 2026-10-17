import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";

import { PageHeader } from "@/components/app-layout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { api, queryKeys, type DNSConfig } from "@/lib/api";

import { FormError } from "./auth-shell";

export function DNSPage() {
  const dns = useQuery({ queryKey: queryKeys.dns, queryFn: api.dns });
  return (
    <>
      <PageHeader title="DNS" description="Names for nodes, and which resolvers answer for private domains." />
      {/* Mounted once loaded so the form starts with the saved values. */}
      {dns.data ? <DNSForm saved={dns.data} /> : <Skeleton className="h-64" />}
    </>
  );
}

type SplitRow = { domain: string; resolvers: string };

function DNSForm({ saved }: { saved: DNSConfig }) {
  const qc = useQueryClient();
  const [magic, setMagic] = useState(saved.magicDNS);
  const [domain, setDomain] = useState(saved.domain);
  const [split, setSplit] = useState<SplitRow[]>(
    saved.split.map((s) => ({ domain: s.domain, resolvers: s.resolvers.join(", ") })),
  );
  const save = useMutation({
    mutationFn: () =>
      api.setDNS({
        magicDNS: magic,
        domain,
        split: split
          .filter((s) => s.domain.trim())
          .map((s) => ({
            domain: s.domain.trim(),
            resolvers: s.resolvers
              .split(/[\s,]+/)
              .map((r) => r.trim())
              .filter(Boolean),
          })),
      }),
    onSuccess: (c) => {
      qc.setQueryData(queryKeys.dns, c);
      setDomain(c.domain);
      setSplit(c.split.map((s) => ({ domain: s.domain, resolvers: s.resolvers.join(", ") })));
      toast.success("DNS settings pushed to all nodes");
    },
  });
  const update = (i: number, patch: Partial<SplitRow>) => setSplit(split.map((s, j) => (j === i ? { ...s, ...patch } : s)));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };

  return (
    <form onSubmit={submit} className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>MagicDNS</CardTitle>
          <CardDescription>
            Every node answers <code className="font-mono">&lt;node&gt;.{domain || "domain"}</code> itself, at{" "}
            <code className="font-mono">100.100.100.100</code>, and points the system resolver there for these names
            (systemd-resolved on Linux, macOS, Windows).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between gap-4 rounded-md border p-3">
            <Label htmlFor="magic">Answer node names</Label>
            <Switch id="magic" checked={magic} onCheckedChange={setMagic} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="domain">Domain</Label>
            <Input id="domain" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="mesh.internal" />
            <p className="text-xs text-muted-foreground">
              Use a name you own or one reserved for private use, like the default{" "}
              <code className="font-mono">mesh.internal</code>.
            </p>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Split DNS</CardTitle>
          <CardDescription>
            Send queries for these domains to their own resolvers, e.g. an office DNS server behind a subnet router.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {split.length === 0 && <p className="text-sm text-muted-foreground">No split DNS domains.</p>}
          {split.map((s, i) => (
            <div key={i} className="grid grid-cols-[1fr_1fr_auto] items-end gap-2">
              <div className="space-y-1">
                <Label htmlFor={`split-domain-${i}`} className="text-xs">
                  Domain
                </Label>
                <Input id={`split-domain-${i}`} value={s.domain} placeholder="corp.example.com" onChange={(e) => update(i, { domain: e.target.value })} />
              </div>
              <div className="space-y-1">
                <Label htmlFor={`split-resolvers-${i}`} className="text-xs">
                  Resolvers
                </Label>
                <Input id={`split-resolvers-${i}`} value={s.resolvers} placeholder="10.0.0.53" onChange={(e) => update(i, { resolvers: e.target.value })} />
              </div>
              <Button type="button" variant="ghost" size="icon" aria-label={`Remove ${s.domain || "domain"}`} onClick={() => setSplit(split.filter((_, j) => j !== i))}>
                <Trash2 />
              </Button>
            </div>
          ))}
          <Button type="button" variant="outline" size="sm" onClick={() => setSplit([...split, { domain: "", resolvers: "" }])}>
            <Plus /> Add domain
          </Button>
        </CardContent>
      </Card>
      <div className="space-y-3 lg:col-span-2">
        <FormError error={save.error} />
        <Button type="submit" disabled={save.isPending}>
          Save DNS settings
        </Button>
      </div>
    </form>
  );
}
