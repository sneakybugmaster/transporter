import type { Node } from "./api";

export const exitRoute = "0.0.0.0/0";

export const isExit = (route: string) => route === exitRoute;

/** pendingRoutes lists a node's advertised routes that are not approved. */
export function pendingRoutes(n: Node): string[] {
  return n.advertisedRoutes.filter((r) => !n.approvedRoutes.includes(r));
}

/** routeLabel names a route for people: subnets as-is, the default route as "exit node". */
export const routeLabel = (route: string) => (isExit(route) ? "exit node" : route);

/** parseTags splits user input like "web, tag:db" into normalised tags. */
export function parseTags(input: string): string[] {
  const out: string[] = [];
  for (const raw of input.split(/[\s,]+/)) {
    const t = raw.trim().toLowerCase();
    if (!t) continue;
    const tag = t.startsWith("tag:") ? t : `tag:${t}`;
    if (!out.includes(tag)) out.push(tag);
  }
  return out;
}
