import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  KeyRound,
  LayoutDashboard,
  Monitor,
  Moon,
  Network,
  Server,
  Settings,
  ShieldCheck,
  Sun,
  type LucideIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { useTheme, type Theme } from "@/lib/theme";
import { cn } from "@/lib/utils";

type NavItem = { label: string; icon: LucideIcon; phase?: number };

const nav: NavItem[] = [
  { label: "Dashboard", icon: LayoutDashboard },
  { label: "Nodes", icon: Server, phase: 3 },
  { label: "Topology", icon: Network, phase: 5 },
  { label: "Enroll device", icon: KeyRound, phase: 3 },
  { label: "Access control", icon: ShieldCheck, phase: 5 },
  { label: "Settings", icon: Settings, phase: 3 },
];

const themeCycle: Record<Theme, { next: Theme; icon: LucideIcon; label: string }> = {
  system: { next: "light", icon: Monitor, label: "System theme" },
  light: { next: "dark", icon: Sun, label: "Light theme" },
  dark: { next: "system", icon: Moon, label: "Dark theme" },
};

export default function App() {
  const { theme, setTheme } = useTheme();
  const ThemeIcon = themeCycle[theme].icon;

  return (
    <div className="flex min-h-svh flex-col md:flex-row">
      <aside className="flex shrink-0 flex-col gap-1 border-b bg-card p-3 md:w-60 md:border-r md:border-b-0">
        <div className="flex items-center gap-2 px-2 py-3">
          <img src="/favicon.svg" alt="" className="size-7" />
          <span className="text-lg font-semibold tracking-tight">Transporter</span>
          <Button
            variant="ghost"
            size="icon"
            className="ml-auto"
            aria-label={`${themeCycle[theme].label}, switch to ${themeCycle[theme].next}`}
            title={themeCycle[theme].label}
            onClick={() => setTheme(themeCycle[theme].next)}
          >
            <ThemeIcon />
          </Button>
        </div>
        <nav className="flex gap-1 overflow-x-auto md:flex-col">
          {nav.map((item) => (
            <button
              key={item.label}
              type="button"
              disabled={item.phase !== undefined}
              aria-current={item.phase === undefined ? "page" : undefined}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium whitespace-nowrap",
                item.phase === undefined
                  ? "bg-accent text-accent-foreground"
                  : "cursor-not-allowed text-muted-foreground",
              )}
            >
              <item.icon className="size-4" />
              {item.label}
              {item.phase !== undefined && (
                <span className="ml-auto text-[10px] tracking-wide uppercase opacity-70">soon</span>
              )}
            </button>
          ))}
        </nav>
      </aside>

      <main className="flex-1 p-4 md:p-8">
        <div className="mx-auto max-w-5xl space-y-6">
          <header>
            <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
            <p className="text-sm text-muted-foreground">Overview of your mesh network.</p>
          </header>
          <div className="grid gap-4 sm:grid-cols-2">
            <CoordinatorCard />
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="size-4" /> Mesh
                </CardTitle>
                <CardDescription>Nodes and connections appear here once agents can join.</CardDescription>
              </CardHeader>
              <CardContent className="grid grid-cols-3 gap-4 text-center">
                <Stat label="Nodes" value="0" />
                <Stat label="Online" value="0" />
                <Stat label="Direct" value="—" />
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}

function CoordinatorCard() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 10_000 });
  const version = useQuery({ queryKey: ["version"], queryFn: api.version });

  const healthy = health.data?.status === "ok";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="size-4" /> Coordinator
          {health.isPending ? (
            <Badge variant="secondary">checking…</Badge>
          ) : healthy ? (
            <Badge variant="success">healthy</Badge>
          ) : (
            <Badge variant="destructive">unreachable</Badge>
          )}
        </CardTitle>
        <CardDescription>Control server, relay and configuration API.</CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-muted-foreground">Version</dt>
          <dd className="font-mono">{version.data?.version ?? "—"}</dd>
          <dt className="text-muted-foreground">Commit</dt>
          <dd className="truncate font-mono">{version.data?.commit ?? "—"}</dd>
          <dt className="text-muted-foreground">Platform</dt>
          <dd className="font-mono">{version.data?.platform ?? "—"}</dd>
        </dl>
      </CardContent>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}
