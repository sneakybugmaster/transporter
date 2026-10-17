import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getRouteApi, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, queryKeys } from "@/lib/api";

import { AuthShell, FormError } from "./auth-shell";

const route = getRouteApi("/login");

export function LoginPage() {
  const { redirect, error: ssoError } = route.useSearch();
  const methods = useQuery({ queryKey: queryKeys.authMethods, queryFn: api.authMethods, staleTime: 60_000 });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const qc = useQueryClient();
  const navigate = useNavigate();

  const login = useMutation({
    mutationFn: () => api.login({ username, password }),
    onSuccess: (me) => {
      qc.setQueryData(queryKeys.me, me);
      void navigate({ to: redirect ?? "/" });
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate();
  };

  return (
    <AuthShell>
      <Card>
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>Manage your mesh network.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {ssoError && <FormError error={ssoError} />}
          {methods.data?.oidc && (
            <>
              <Button asChild variant="outline" className="w-full">
                {/* A full page load: the browser must leave for the identity provider. */}
                <a href="/api/v1/auth/oidc/login">Sign in with {methods.data.oidcName}</a>
              </Button>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="h-px flex-1 bg-border" />
                or with a password
                <span className="h-px flex-1 bg-border" />
              </div>
            </>
          )}
          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input id="username" autoFocus required autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <FormError error={login.error} />
            <Button type="submit" className="w-full" disabled={login.isPending}>
              {login.isPending ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthShell>
  );
}
