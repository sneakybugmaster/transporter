import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import {
  Globe,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Monitor,
  Moon,
  Network,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Sun,
  Waypoints,
  type LucideIcon,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { api, queryKeys } from "@/lib/api";
import { pendingRoutes } from "@/lib/routes";
import { useLiveUpdates } from "@/lib/live";
import { useTheme, type Theme } from "@/lib/theme";

type NavPath = "/" | "/nodes" | "/topology" | "/routes" | "/access" | "/dns" | "/enroll" | "/audit" | "/settings";

const nav: { to: NavPath; label: string; icon: LucideIcon }[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/nodes", label: "Nodes", icon: Server },
  { to: "/topology", label: "Topology", icon: Network },
  { to: "/routes", label: "Routes", icon: Waypoints },
  { to: "/access", label: "Access control", icon: ShieldCheck },
  { to: "/dns", label: "DNS", icon: Globe },
  { to: "/enroll", label: "Enroll device", icon: KeyRound },
  { to: "/audit", label: "Audit log", icon: ScrollText },
  { to: "/settings", label: "Settings", icon: Settings },
];

const themeCycle: Record<Theme, { next: Theme; icon: LucideIcon; label: string }> = {
  system: { next: "light", icon: Monitor, label: "System theme" },
  light: { next: "dark", icon: Sun, label: "Light theme" },
  dark: { next: "system", icon: Moon, label: "Dark theme" },
};

const linkClass =
  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium whitespace-nowrap text-muted-foreground hover:bg-accent hover:text-accent-foreground";

export function AppLayout() {
  useLiveUpdates();
  const { theme, setTheme } = useTheme();
  const ThemeIcon = themeCycle[theme].icon;
  const me = useQuery({ queryKey: queryKeys.me, queryFn: api.me });
  const nodes = useQuery({ queryKey: queryKeys.nodes, queryFn: api.nodes });
  const pending = (nodes.data ?? []).reduce((sum, n) => sum + pendingRoutes(n).length, 0);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const logout = useMutation({
    mutationFn: api.logout,
    onSettled: () => {
      qc.clear();
      void navigate({ to: "/login" });
    },
  });

  return (
    <div className="flex min-h-svh flex-col md:flex-row">
      <aside className="flex shrink-0 flex-col gap-1 border-b bg-card p-3 md:sticky md:top-0 md:h-svh md:w-60 md:border-r md:border-b-0">
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
            <Link
              key={item.to}
              to={item.to}
              className={linkClass}
              activeOptions={{ exact: item.to === "/" }}
              activeProps={{ className: "bg-accent text-accent-foreground", "aria-current": "page" }}
            >
              <item.icon className="size-4" />
              {item.label}
              {item.to === "/routes" && pending > 0 && (
                <span
                  className="ml-auto rounded-full bg-warning/15 px-1.5 text-xs text-warning"
                  title={`${pending} route${pending > 1 ? "s" : ""} awaiting approval`}
                >
                  {pending}
                </span>
              )}
            </Link>
          ))}
        </nav>
        <div className="mt-auto hidden items-center gap-2 border-t px-2 pt-3 md:flex">
          <span className="truncate text-sm text-muted-foreground" title="Signed in">
            {me.data?.username}
          </span>
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto"
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
          >
            <LogOut /> Sign out
          </Button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-4 md:p-8">
        <div className="mx-auto max-w-5xl space-y-6">
          <Outlet />
        </div>
        <div className="mt-8 flex justify-center md:hidden">
          <Button variant="outline" size="sm" onClick={() => logout.mutate()}>
            <LogOut /> Sign out {me.data?.username}
          </Button>
        </div>
      </main>
    </div>
  );
}

export function PageHeader({ title, description, children }: { title: string; description: string; children?: React.ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {children}
    </header>
  );
}
