import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, CircleX, RotateCcw, Save } from "lucide-react";
import { useState, type FormEvent, type KeyboardEvent } from "react";
import { toast } from "sonner";

import { PageHeader } from "@/components/app-layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { api, ApiError, queryKeys, type PolicyCheck, type PolicyCheckResult } from "@/lib/api";
import { cn } from "@/lib/utils";

import { FormError } from "./auth-shell";

export function AccessPage() {
  const policy = useQuery({ queryKey: queryKeys.policy, queryFn: api.policy });
  return (
    <>
      <PageHeader title="Access control" description="Which nodes may open connections to which, on which ports." />
      {/* Mounted once loaded so the editor starts with the saved policy. */}
      {policy.data ? <PolicyEditor saved={policy.data.policy} /> : <Skeleton className="h-96" />}
    </>
  );
}

function PolicyEditor({ saved }: { saved: string }) {
  const qc = useQueryClient();
  const [text, setText] = useState(saved);
  const dirty = text !== saved;
  const save = useMutation({
    mutationFn: () => api.setPolicy(text),
    onSuccess: (p) => {
      qc.setQueryData(queryKeys.policy, p);
      void qc.invalidateQueries({ queryKey: queryKeys.audit });
      toast.success("Policy saved and pushed to all nodes");
    },
  });
  const lines = text.split("\n").length;

  // Tab indents instead of leaving the editor (Esc then Tab still moves on).
  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key !== "Tab" || e.shiftKey) return;
    e.preventDefault();
    const el = e.currentTarget;
    const { selectionStart: a, selectionEnd: b } = el;
    const next = text.slice(0, a) + "  " + text.slice(b);
    setText(next);
    requestAnimationFrame(() => el.setSelectionRange(a + 2, a + 2));
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Policy {dirty ? <Badge variant="warning">unsaved changes</Badge> : <Badge variant="secondary">saved</Badge>}
          </CardTitle>
          <CardDescription>
            JSON with comments. Saving checks the syntax and runs the <code className="font-mono">tests</code>; nodes
            get the new rules within seconds.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <textarea
            aria-label="Policy"
            spellCheck={false}
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={onKeyDown}
            rows={Math.min(Math.max(lines + 1, 14), 40)}
            className="w-full resize-y rounded-md border bg-muted/40 p-3 font-mono text-xs leading-5 outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
          />
          {save.error && <PolicyErrors error={save.error} />}
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => save.mutate()} disabled={!dirty || save.isPending}>
              <Save /> Save policy
            </Button>
            <Button variant="ghost" onClick={() => setText(saved)} disabled={!dirty}>
              <RotateCcw /> Discard changes
            </Button>
          </div>
        </CardContent>
      </Card>
      <div className="space-y-4">
        <Simulator draft={dirty ? text : undefined} />
        <Reference />
      </div>
    </div>
  );
}

function PolicyErrors({ error }: { error: unknown }) {
  if (!(error instanceof ApiError) || error.details.length === 0) return <FormError error={error} />;
  return (
    <div role="alert" className="space-y-1 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      <p className="font-medium">The policy was not saved:</p>
      <ul className="list-disc space-y-0.5 pl-5">
        {error.details.map((d) => (
          <li key={d} className="font-mono text-xs">
            {d}
          </li>
        ))}
      </ul>
    </div>
  );
}

const protos = ["tcp", "udp", "icmp"] as const;

function Simulator({ draft }: { draft?: string }) {
  const nodes = useQuery({ queryKey: queryKeys.nodes, queryFn: api.nodes });
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [port, setPort] = useState("22");
  const [proto, setProto] = useState<(typeof protos)[number]>("tcp");
  const check = useMutation({
    mutationFn: (body: PolicyCheck) => api.checkPolicy(body),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    check.mutate({ src, dst, port: Number(port) || 0, proto, ...(draft ? { policy: draft } : {}) });
  };
  const result: PolicyCheckResult | undefined = check.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Test a connection</CardTitle>
        <CardDescription>{draft ? "Against your unsaved changes." : "Against the saved policy."}</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <datalist id="node-names">
            {nodes.data?.map((n) => (
              <option key={n.id} value={n.name} />
            ))}
          </datalist>
          <div className="space-y-1">
            <Label htmlFor="sim-src">From</Label>
            <Input id="sim-src" list="node-names" placeholder="node name or IP" value={src} onChange={(e) => setSrc(e.target.value)} required />
          </div>
          <div className="space-y-1">
            <Label htmlFor="sim-dst">To</Label>
            <Input id="sim-dst" list="node-names" placeholder="node name or IP" value={dst} onChange={(e) => setDst(e.target.value)} required />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor="sim-proto">Protocol</Label>
              <select
                id="sim-proto"
                value={proto}
                onChange={(e) => setProto(e.target.value as (typeof protos)[number])}
                className="h-9 w-full rounded-md border bg-transparent px-2 text-sm"
              >
                {protos.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="sim-port">Port</Label>
              <Input
                id="sim-port"
                type="number"
                min={0}
                max={65535}
                value={port}
                disabled={proto === "icmp"}
                onChange={(e) => setPort(e.target.value)}
              />
            </div>
          </div>
          <Button type="submit" variant="secondary" className="w-full" disabled={check.isPending}>
            Check
          </Button>
          {check.error && <PolicyErrors error={check.error} />}
          {result && (
            <div
              role="status"
              className={cn(
                "flex items-start gap-2 rounded-md border p-3 text-sm",
                result.allowed ? "border-success/40 bg-success/10" : "border-destructive/30 bg-destructive/10",
              )}
            >
              {result.allowed ? (
                <CircleCheck className="mt-0.5 size-4 shrink-0 text-success" />
              ) : (
                <CircleX className="mt-0.5 size-4 shrink-0 text-destructive" />
              )}
              <div>
                <p className="font-medium">{result.allowed ? "Allowed" : "Denied"}</p>
                <p className="text-muted-foreground">{result.reason}</p>
              </div>
            </div>
          )}
        </form>
      </CardContent>
    </Card>
  );
}

const examples: [string, string][] = [
  ["*", "anything"],
  ["tag:web", "nodes tagged web"],
  ["laptop", "the node named laptop"],
  ["office", 'a "hosts" alias'],
  ["10.0.0.0/24", "an address or subnet"],
  ["tag:web:80,443", "destination with ports"],
  ["tag:db:5432-5433", "a port range"],
  ["10.0.0.0/24:*", "every port"],
];

function Reference() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Syntax</CardTitle>
        <CardDescription>
          Each rule in <code className="font-mono">acls</code> accepts traffic from <code className="font-mono">src</code>{" "}
          to <code className="font-mono">dst</code>, optionally for one <code className="font-mono">proto</code>. Replies
          are always allowed; everything else is dropped.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
          {examples.map(([code, what]) => (
            <div key={code} className="contents">
              <dt>
                <code className="font-mono">{code}</code>
              </dt>
              <dd className="text-muted-foreground">{what}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}
