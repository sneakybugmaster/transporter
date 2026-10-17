import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ArrowLeft, ArrowRight, Check } from "lucide-react";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, queryKeys } from "@/lib/api";
import { cn } from "@/lib/utils";

import { AuthShell, FormError } from "./auth-shell";

const steps = ["Setup code", "Admin account", "Public address"] as const;

export function SetupPage() {
  const [step, setStep] = useState(0);
  const [code, setCode] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [publicURL, setPublicURL] = useState(window.location.origin);
  const [localError, setLocalError] = useState("");
  const qc = useQueryClient();
  const navigate = useNavigate();

  const setup = useMutation({
    mutationFn: () => api.completeSetup({ setupCode: code, username, password, publicURL }),
    onSuccess: (me) => {
      qc.setQueryData(queryKeys.me, me);
      qc.setQueryData(queryKeys.setup, { needsSetup: false });
      void navigate({ to: "/enroll" });
    },
  });

  const next = (e: FormEvent) => {
    e.preventDefault();
    setLocalError("");
    if (step === 1) {
      if (password.length < 10) return setLocalError("Use at least 10 characters for the password.");
      if (password !== confirm) return setLocalError("The passwords don't match.");
    }
    if (step < steps.length - 1) setStep(step + 1);
    else setup.mutate();
  };

  return (
    <AuthShell>
      <ol className="flex items-center justify-center gap-2 text-xs" aria-label="Setup progress">
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-2">
            <span
              className={cn(
                "flex size-6 items-center justify-center rounded-full border text-[11px] font-medium",
                i < step && "border-primary bg-primary text-primary-foreground",
                i === step && "border-primary text-primary",
              )}
              aria-current={i === step ? "step" : undefined}
            >
              {i < step ? <Check className="size-3" /> : i + 1}
            </span>
            <span className={cn("hidden sm:inline", i === step ? "font-medium" : "text-muted-foreground")}>{s}</span>
            {i < steps.length - 1 && <span className="h-px w-6 bg-border" />}
          </li>
        ))}
      </ol>
      <Card>
        <form onSubmit={next} className="contents">
          <CardHeader>
            <CardTitle>{["Welcome to Transporter", "Create the admin account", "How nodes reach this coordinator"][step]}</CardTitle>
            <CardDescription>
              {
                [
                  "To prove you run this coordinator, enter the setup code it printed in its log when it started.",
                  "You'll sign in to this console with these credentials.",
                  "Devices use this URL to enroll. Use the address they can reach, e.g. your public hostname.",
                ][step]
              }
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {step === 0 && (
              <div className="space-y-2">
                <Label htmlFor="code">Setup code</Label>
                <Input
                  id="code"
                  autoFocus
                  required
                  autoComplete="off"
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  className="font-mono tracking-wider uppercase"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Find it with <code className="rounded bg-muted px-1">docker logs &lt;container&gt;</code> or in the
                  coordinator's output: look for <code className="rounded bg-muted px-1">setupCode</code>.
                </p>
              </div>
            )}
            {step === 1 && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input id="username" autoFocus required autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input id="password" type="password" required autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="confirm">Confirm password</Label>
                  <Input id="confirm" type="password" required autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
                </div>
              </>
            )}
            {step === 2 && (
              <div className="space-y-2">
                <Label htmlFor="url">Coordinator URL</Label>
                <Input id="url" type="url" autoFocus required value={publicURL} onChange={(e) => setPublicURL(e.target.value)} />
                <p className="text-xs text-muted-foreground">You can change this later in Settings.</p>
              </div>
            )}
            <FormError error={localError || setup.error} />
            <div className="flex justify-between gap-2">
              <Button type="button" variant="ghost" onClick={() => setStep(step - 1)} disabled={step === 0 || setup.isPending}>
                <ArrowLeft /> Back
              </Button>
              <Button type="submit" disabled={setup.isPending}>
                {step < steps.length - 1 ? (
                  <>
                    Next <ArrowRight />
                  </>
                ) : (
                  "Finish setup"
                )}
              </Button>
            </div>
          </CardContent>
        </form>
      </Card>
    </AuthShell>
  );
}
