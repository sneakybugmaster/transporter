import createClient, { type Middleware } from "openapi-fetch";

import type { components, paths } from "./api.gen";

export type Node = components["schemas"]["Node"];
export type AuthKey = components["schemas"]["AuthKey"];
export type AuthKeyCreated = components["schemas"]["AuthKeyCreated"];
export type Settings = components["schemas"]["Settings"];
export type Stats = components["schemas"]["Stats"];
export type VersionInfo = components["schemas"]["Version"];

/** ApiError carries the HTTP status and the server's error message. */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// The server requires a JSON content type on every request that changes
// state (it is how cross-site form posts are refused), including bodiless
// DELETEs and logout.
const jsonForWrites: Middleware = {
  onRequest({ request }) {
    if (request.method !== "GET" && request.method !== "HEAD" && !request.headers.has("Content-Type")) {
      request.headers.set("Content-Type", "application/json");
    }
    return request;
  },
};

// Absolute so it also works where Request() rejects relative URLs (tests).
export const client = createClient<paths>({
  baseUrl: `${window.location.origin}/api/v1`,
  credentials: "same-origin",
  // Resolve fetch per call rather than capturing it at load time.
  fetch: (req) => globalThis.fetch(req),
});
client.use(jsonForWrites);

/** unwrap turns an openapi-fetch result into data or a thrown ApiError. */
export async function unwrap<T>(
  p: Promise<{ data?: T; error?: { error: string } | unknown; response: Response }>,
): Promise<T> {
  const { data, error, response } = await p;
  if (!response.ok) {
    const msg =
      error && typeof error === "object" && "error" in error && typeof error.error === "string"
        ? error.error
        : `${response.status} ${response.statusText}`;
    throw new ApiError(response.status, msg);
  }
  return data as T;
}

export const api = {
  version: () => unwrap(client.GET("/version")),
  setupStatus: () => unwrap(client.GET("/setup")),
  completeSetup: (body: components["schemas"]["SetupRequest"]) => unwrap(client.POST("/setup", { body })),
  login: (body: components["schemas"]["LoginRequest"]) => unwrap(client.POST("/auth/login", { body })),
  logout: () => unwrap(client.POST("/auth/logout")),
  me: () => unwrap(client.GET("/auth/me")),
  changePassword: (body: components["schemas"]["PasswordChange"]) => unwrap(client.POST("/auth/password", { body })),
  stats: () => unwrap(client.GET("/stats")),
  nodes: () => unwrap(client.GET("/nodes")),
  renameNode: (id: string, name: string) =>
    unwrap(client.PATCH("/nodes/{id}", { params: { path: { id } }, body: { name } })),
  deleteNode: (id: string) => unwrap(client.DELETE("/nodes/{id}", { params: { path: { id } } })),
  authKeys: () => unwrap(client.GET("/authkeys")),
  createAuthKey: (body: components["schemas"]["AuthKeyCreate"]) => unwrap(client.POST("/authkeys", { body })),
  revokeAuthKey: (id: string) => unwrap(client.DELETE("/authkeys/{id}", { params: { path: { id } } })),
  settings: () => unwrap(client.GET("/settings")),
  updateSettings: (body: components["schemas"]["SettingsUpdate"]) => unwrap(client.PATCH("/settings", { body })),
};

export const queryKeys = {
  me: ["me"] as const,
  setup: ["setup"] as const,
  version: ["version"] as const,
  stats: ["stats"] as const,
  nodes: ["nodes"] as const,
  authKeys: ["authkeys"] as const,
  settings: ["settings"] as const,
};
