import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { makeRouter } from "./router";

type Handler = (body: unknown) => { status: number; body?: unknown };

let routes: Record<string, Handler>;
let calls: { method: string; path: string; body: unknown; contentType: string | null }[];

function json(status: number, body?: unknown) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  calls = [];
  routes = {
    "GET /api/v1/setup": () => ({ status: 200, body: { needsSetup: false } }),
    "GET /api/v1/auth/me": () => ({ status: 401, body: { error: "not logged in" } }),
    "GET /api/v1/stats": () => ({ status: 200, body: { nodes: 2, online: 1 } }),
    "GET /api/v1/nodes": () => ({
      status: 200,
      body: [
        {
          id: "n1",
          name: "alpha",
          hostname: "alpha",
          os: "linux",
          publicKey: "k",
          addresses: ["100.64.0.1/32"],
          endpoints: [],
          online: true,
          lastSeen: new Date().toISOString(),
          createdAt: new Date().toISOString(),
        },
      ],
    }),
    "GET /api/v1/settings": () => ({
      status: 200,
      body: { publicURL: "", networkPrefix: "100.64.0.0/10", stunPort: 3478, relayEnabled: true, version: "test" },
    }),
    "GET /api/v1/version": () => ({
      status: 200,
      body: { version: "1.2.3", commit: "c", date: "", goVersion: "go", platform: "linux/amd64" },
    }),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      const body = input.method === "GET" ? undefined : await input.text().then((t) => (t ? JSON.parse(t) : undefined));
      calls.push({ method: input.method, path: url.pathname, body, contentType: input.headers.get("Content-Type") });
      const h = routes[`${input.method} ${url.pathname}`];
      if (!h) return json(404, { error: "not found" });
      const r = h(body);
      return json(r.status, r.body);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = makeRouter(qc, createMemoryHistory({ initialEntries: [path] }));
  render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

test("redirects to the setup wizard on a fresh coordinator", async () => {
  routes["GET /api/v1/setup"] = () => ({ status: 200, body: { needsSetup: true } });
  const router = renderAt("/nodes");
  expect(await screen.findByText("Welcome to Transporter")).toBeInTheDocument();
  expect(router.state.location.pathname).toBe("/setup");
});

test("setup wizard validates and submits", async () => {
  const user = userEvent.setup();
  routes["GET /api/v1/setup"] = () => ({ status: 200, body: { needsSetup: true } });
  routes["POST /api/v1/setup"] = () => ({ status: 200, body: { username: "root" } });
  routes["GET /api/v1/authkeys"] = () => ({ status: 200, body: [] });
  renderAt("/setup");

  await user.type(await screen.findByLabelText("Setup code"), "abcd-efgh");
  await user.click(screen.getByRole("button", { name: /next/i }));

  await user.clear(screen.getByLabelText("Username"));
  await user.type(screen.getByLabelText("Username"), "root");
  await user.type(screen.getByLabelText("Password"), "long enough pw");
  await user.type(screen.getByLabelText("Confirm password"), "different pw!");
  await user.click(screen.getByRole("button", { name: /next/i }));
  expect(await screen.findByRole("alert")).toHaveTextContent("don't match");

  await user.clear(screen.getByLabelText("Confirm password"));
  await user.type(screen.getByLabelText("Confirm password"), "long enough pw");
  await user.click(screen.getByRole("button", { name: /next/i }));
  await user.click(await screen.findByRole("button", { name: /finish setup/i }));

  expect(await screen.findByText("Enroll device", { selector: "h1" })).toBeInTheDocument();
  const post = calls.find((c) => c.method === "POST" && c.path === "/api/v1/setup");
  expect(post?.body).toMatchObject({ setupCode: "abcd-efgh", username: "root", password: "long enough pw" });
  expect(post?.contentType).toBe("application/json");
});

test("login then dashboard with live data", async () => {
  const user = userEvent.setup();
  let loggedIn = false;
  routes["GET /api/v1/auth/me"] = () => (loggedIn ? { status: 200, body: { username: "admin" } } : { status: 401, body: { error: "no" } });
  routes["POST /api/v1/auth/login"] = (b) => {
    const { password } = b as { password: string };
    if (password !== "right password") return { status: 401, body: { error: "invalid username or password" } };
    loggedIn = true;
    return { status: 200, body: { username: "admin" } };
  };

  const router = renderAt("/");
  await user.type(await screen.findByLabelText("Username"), "admin");
  await user.type(screen.getByLabelText("Password"), "wrong");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("invalid username or password");

  await user.clear(screen.getByLabelText("Password"));
  await user.type(screen.getByLabelText("Password"), "right password");
  await user.click(screen.getByRole("button", { name: "Sign in" }));

  expect(await screen.findByTestId("stat-nodes")).toHaveTextContent("2");
  expect(screen.getByTestId("stat-online")).toHaveTextContent("1");
  expect(screen.getByTestId("stat-offline")).toHaveTextContent("1");
  expect(await screen.findByText("alpha")).toBeInTheDocument();
  expect(router.state.location.pathname).toBe("/");
});
