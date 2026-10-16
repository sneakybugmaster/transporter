import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import App from "./App";

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  );
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === "/healthz") return jsonResponse({ status: "ok" });
      if (url === "/api/v1/version")
        return jsonResponse({ version: "1.2.3", commit: "abc123", date: "", goVersion: "go1.24", platform: "linux/amd64" });
      return jsonResponse({ error: "not found" }, 404);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

test("shows coordinator health and version", async () => {
  renderApp();
  expect(await screen.findByText("healthy")).toBeInTheDocument();
  expect(await screen.findByText("1.2.3")).toBeInTheDocument();
  expect(screen.getByText("linux/amd64")).toBeInTheDocument();
});

test("shows unreachable when health check fails", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({}, 503)));
  renderApp();
  expect(await screen.findByText("unreachable")).toBeInTheDocument();
});
