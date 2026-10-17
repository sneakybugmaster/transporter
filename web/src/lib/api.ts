import createClient, { type Middleware } from "openapi-fetch";

import type { components, paths } from "./api.gen";

export type Node = components["schemas"]["Node"];
export type AuthKey = components["schemas"]["AuthKey"];
export type AuthKeyCreated = components["schemas"]["AuthKeyCreated"];
export type Settings = components["schemas"]["Settings"];
export type Stats = components["schemas"]["Stats"];
export type VersionInfo = components["schemas"]["Version"];
export type NodeUpdate = components["schemas"]["NodeUpdate"];
export type DNSConfig = components["schemas"]["DNSConfig"];
export type PolicyCheck = components["schemas"]["PolicyCheck"];
export type PolicyCheckResult = components["schemas"]["PolicyCheckResult"];
export type TopologyLink = components["schemas"]["TopologyLink"];
export type AuditEntry = components["schemas"]["AuditEntry"];
export type APIToken = components["schemas"]["APIToken"];

/** ApiError carries the HTTP status and the server's error message. */
export class ApiError extends Error {
  readonly status: number;
  /** details lists individual problems, e.g. why a policy was rejected. */
  readonly details: string[];
  constructor(status: number, message: string, details: string[] = []) {
    super(details.length ? details.join("\n") : message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
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
    const details =
      error && typeof error === "object" && "details" in error && Array.isArray(error.details)
        ? error.details.filter((d): d is string => typeof d === "string")
        : [];
    throw new ApiError(response.status, msg, details);
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
  authMethods: () => unwrap(client.GET("/auth/methods")),
  tokens: () => unwrap(client.GET("/tokens")),
  createToken: (body: components["schemas"]["APITokenCreate"]) => unwrap(client.POST("/tokens", { body })),
  deleteToken: (id: string) => unwrap(client.DELETE("/tokens/{id}", { params: { path: { id } } })),
  changePassword: (body: components["schemas"]["PasswordChange"]) => unwrap(client.POST("/auth/password", { body })),
  stats: () => unwrap(client.GET("/stats")),
  nodes: () => unwrap(client.GET("/nodes")),
  updateNode: (id: string, body: NodeUpdate) => unwrap(client.PATCH("/nodes/{id}", { params: { path: { id } }, body })),
  deleteNode: (id: string) => unwrap(client.DELETE("/nodes/{id}", { params: { path: { id } } })),
  authKeys: () => unwrap(client.GET("/authkeys")),
  createAuthKey: (body: components["schemas"]["AuthKeyCreate"]) => unwrap(client.POST("/authkeys", { body })),
  revokeAuthKey: (id: string) => unwrap(client.DELETE("/authkeys/{id}", { params: { path: { id } } })),
  settings: () => unwrap(client.GET("/settings")),
  updateSettings: (body: components["schemas"]["SettingsUpdate"]) => unwrap(client.PATCH("/settings", { body })),
  policy: () => unwrap(client.GET("/policy")),
  setPolicy: (policy: string) => unwrap(client.PUT("/policy", { body: { policy } })),
  checkPolicy: (body: PolicyCheck) => unwrap(client.POST("/policy/check", { body })),
  dns: () => unwrap(client.GET("/dns")),
  setDNS: (body: DNSConfig) => unwrap(client.PUT("/dns", { body })),
  topology: () => unwrap(client.GET("/topology")),
  audit: (before?: number) =>
    unwrap(client.GET("/audit", { params: { query: { limit: 100, ...(before ? { before } : {}) } } })),
};

export const queryKeys = {
  me: ["me"] as const,
  authMethods: ["auth-methods"] as const,
  tokens: ["tokens"] as const,
  setup: ["setup"] as const,
  version: ["version"] as const,
  stats: ["stats"] as const,
  nodes: ["nodes"] as const,
  authKeys: ["authkeys"] as const,
  settings: ["settings"] as const,
  policy: ["policy"] as const,
  dns: ["dns"] as const,
  topology: ["topology"] as const,
  audit: ["audit"] as const,
};
