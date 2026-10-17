import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useNavigate } from "@tanstack/react-router";
import {
  KeyRound,
  LayoutDashboard,
  LogOut,
  Monitor,
  Moon,
  Network,
  Server,
  Settings,
  ShieldCheck,
  Sun,
  type LucideIcon,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { api, queryKeys } from "@/lib/api";
import { useLiveUpdates } from "@/lib/live";
import { useTheme, type Theme } from "@/lib/theme";

const nav: { to: "/" | "/nodes" | "/enroll" | "/settings"; label: string; icon: LucideIcon }[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/nodes", label: "Nodes", icon: Server },
  { to: "/enroll", label: "Enroll device", icon: KeyRound },
  { to: "/settings", label: "Settings", icon: Settings },
];

const comingSoon: { label: string; icon: LucideIcon }[] = [
  { label: "Topology", icon: Network },
  { label: "Access control", icon: ShieldCheck },
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
            </Link>
          ))}
          {comingSoon.map((item) => (
            <span key={item.label} className={`${linkClass} cursor-not-allowed opacity-60 hover:bg-transparent`}>
              <item.icon className="size-4" />
              {item.label}
              <span className="ml-auto text-[10px] tracking-wide uppercase">soon</span>
            </span>
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
