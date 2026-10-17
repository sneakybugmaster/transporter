import { expect, test } from "vitest";

import type { Node, TopologyLink } from "./api";
import { parseTags, pendingRoutes, routeLabel } from "./routes";
import { circleLayout, mergeLinks } from "./topology";

const node = (id: string, extra: Partial<Node> = {}): Node => ({
  id,
  name: id,
  hostname: id,
  os: "linux",
  publicKey: "k",
  addresses: [],
  endpoints: [],
  online: true,
  lastSeen: "",
  createdAt: "",
  tags: [],
  advertisedRoutes: [],
  approvedRoutes: [],
  routes: [],
  ...extra,
});

test("parseTags normalises input", () => {
  expect(parseTags(" web, tag:DB  web\ttag:x ")).toEqual(["tag:web", "tag:db", "tag:x"]);
  expect(parseTags("")).toEqual([]);
});

test("pendingRoutes and labels", () => {
  const n = node("gw", { advertisedRoutes: ["10.0.0.0/24", "0.0.0.0/0"], approvedRoutes: ["10.0.0.0/24"] });
  expect(pendingRoutes(n)).toEqual(["0.0.0.0/0"]);
  expect(routeLabel("0.0.0.0/0")).toBe("exit node");
  expect(routeLabel("10.0.0.0/24")).toBe("10.0.0.0/24");
});

test("mergeLinks folds both directions into one edge", () => {
  const nodes = [node("a"), node("b"), node("c")];
  const links: TopologyLink[] = [
    { from: "a", to: "b", path: "relay" },
    { from: "b", to: "a", path: "direct", latencyMs: 3 },
    { from: "a", to: "c", path: "relay" },
    { from: "c", to: "ghost", path: "direct" },
  ];
  expect(mergeLinks(links, nodes)).toEqual([
    { a: "a", b: "b", path: "direct", latencyMs: 3 },
    { a: "a", b: "c", path: "relay", latencyMs: undefined },
  ]);
});

test("circleLayout starts at the top", () => {
  const [first] = circleLayout(4, 100, 100, 50);
  expect(first!.x).toBeCloseTo(100);
  expect(first!.y).toBeCloseTo(50);
  expect(circleLayout(1, 10, 20, 5)).toEqual([{ x: 10, y: 20 }]);
});
