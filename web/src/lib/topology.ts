import type { Node, TopologyLink } from "./api";

export type Edge = { a: string; b: string; path: "direct" | "relay"; latencyMs?: number };

/**
 * mergeLinks folds the per-node reports (each node reports how it reaches
 * each peer) into one undirected edge per pair: direct if either side has a
 * direct path, with the lowest latency reported.
 */
export function mergeLinks(links: TopologyLink[], nodes: Node[]): Edge[] {
  const known = new Set(nodes.map((n) => n.id));
  const edges = new Map<string, Edge>();
  for (const l of links) {
    if (!known.has(l.from) || !known.has(l.to) || l.from === l.to) continue;
    const [a, b] = l.from < l.to ? [l.from, l.to] : [l.to, l.from];
    const key = `${a}|${b}`;
    const prev = edges.get(key);
    const path = prev?.path === "direct" || l.path === "direct" ? "direct" : "relay";
    const lats = [prev?.latencyMs, l.latencyMs].filter((x): x is number => typeof x === "number" && x > 0);
    edges.set(key, { a, b, path, latencyMs: lats.length ? Math.min(...lats) : undefined });
  }
  return [...edges.values()];
}

/** circleLayout places n points evenly on a circle (the first at the top). */
export function circleLayout(n: number, cx: number, cy: number, r: number): { x: number; y: number }[] {
  if (n === 1) return [{ x: cx, y: cy }];
  return Array.from({ length: n }, (_, i) => {
    const t = (2 * Math.PI * i) / n - Math.PI / 2;
    return { x: cx + r * Math.cos(t), y: cy + r * Math.sin(t) };
  });
}
