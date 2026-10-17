import type { QueryClient } from "@tanstack/react-query";
import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  Outlet,
  redirect,
  type RouterHistory,
} from "@tanstack/react-router";
import { Toaster } from "sonner";

import { ErrorScreen } from "@/components/error-screen";
import { AppLayout } from "@/components/app-layout";
import { api, ApiError, queryKeys } from "@/lib/api";
import { AccessPage } from "@/pages/access";
import { AuditPage } from "@/pages/audit";
import { DashboardPage } from "@/pages/dashboard";
import { DNSPage } from "@/pages/dns";
import { EnrollPage } from "@/pages/enroll";
import { LoginPage } from "@/pages/login";
import { NodesPage } from "@/pages/nodes";
import { RoutesPage } from "@/pages/routes";
import { SettingsPage } from "@/pages/settings";
import { SetupPage } from "@/pages/setup";
import { TopologyPage } from "@/pages/topology";

type Ctx = { queryClient: QueryClient };

const setupStatus = (qc: QueryClient) =>
  qc.fetchQuery({ queryKey: queryKeys.setup, queryFn: api.setupStatus, staleTime: 30_000 });

/** loggedIn returns whether the session cookie is valid (caching the answer). */
async function loggedIn(qc: QueryClient): Promise<boolean> {
  try {
    await qc.ensureQueryData({ queryKey: queryKeys.me, queryFn: api.me });
    return true;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return false;
    throw e;
  }
}

const rootRoute = createRootRouteWithContext<Ctx>()({
  component: () => (
    <>
      <Outlet />
      <Toaster richColors closeButton position="bottom-right" />
    </>
  ),
  errorComponent: ErrorScreen,
});

const setupRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/setup",
  beforeLoad: async ({ context }) => {
    if (!(await setupStatus(context.queryClient)).needsSetup) throw redirect({ to: "/login" });
  },
  component: SetupPage,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  validateSearch: (s: Record<string, unknown>): { redirect?: string } =>
    typeof s.redirect === "string" && s.redirect.startsWith("/") ? { redirect: s.redirect } : {},
  beforeLoad: async ({ context }) => {
    if ((await setupStatus(context.queryClient)).needsSetup) throw redirect({ to: "/setup" });
    if (await loggedIn(context.queryClient)) throw redirect({ to: "/" });
  },
  component: LoginPage,
});

const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  beforeLoad: async ({ context, location }) => {
    if ((await setupStatus(context.queryClient)).needsSetup) throw redirect({ to: "/setup" });
    if (!(await loggedIn(context.queryClient))) {
      throw redirect({ to: "/login", search: { redirect: location.href } });
    }
  },
  component: AppLayout,
});

const dashboardRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: DashboardPage });
const nodesRoute = createRoute({ getParentRoute: () => appRoute, path: "/nodes", component: NodesPage });
const enrollRoute = createRoute({ getParentRoute: () => appRoute, path: "/enroll", component: EnrollPage });
const settingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/settings", component: SettingsPage });
const topologyRoute = createRoute({ getParentRoute: () => appRoute, path: "/topology", component: TopologyPage });
const routesRoute = createRoute({ getParentRoute: () => appRoute, path: "/routes", component: RoutesPage });
const accessRoute = createRoute({ getParentRoute: () => appRoute, path: "/access", component: AccessPage });
const dnsRoute = createRoute({ getParentRoute: () => appRoute, path: "/dns", component: DNSPage });
const auditRoute = createRoute({ getParentRoute: () => appRoute, path: "/audit", component: AuditPage });

const routeTree = rootRoute.addChildren([
  setupRoute,
  loginRoute,
  appRoute.addChildren([
    dashboardRoute,
    nodesRoute,
    topologyRoute,
    routesRoute,
    accessRoute,
    dnsRoute,
    enrollRoute,
    auditRoute,
    settingsRoute,
  ]),
]);

export function makeRouter(queryClient: QueryClient, history?: RouterHistory) {
  return createRouter({ routeTree, context: { queryClient }, defaultPreload: "intent", history });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof makeRouter>;
  }
}
