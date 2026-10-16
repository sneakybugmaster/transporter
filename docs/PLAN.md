# Transporter — Implementation Plan

A self-hosted mesh VPN: every node gets a stable private IP and talks to every
other node directly over WireGuard. One **public coordinator** handles identity,
key exchange, peer discovery, NAT traversal help and relaying when a direct path
is impossible. All data traffic is end-to-end encrypted; the coordinator never
sees plaintext.

Hard requirements:

1. Mesh tunnel with exactly one publicly reachable coordinator.
2. Runs in Docker **and** compiles to native single binaries (Linux, macOS, Windows; amd64 + arm64).
3. Modern configuration UI.

---

## 1. Architecture

```
                        ┌────────────────────────────────────┐
                        │      Coordinator (public host)     │
                        │                                    │
  browser ── HTTPS ───▶ │  Web UI (embedded SPA)             │
                        │  REST/JSON API  (admin, /api/v1)   │
                        │  Control plane  (gRPC/WebSocket)   │◀── long-lived stream ──┐
                        │  STUN server    (UDP 3478)         │◀── endpoint discovery ─┤
                        │  Relay (DERP-style, TLS 443)       │◀── fallback traffic ───┤
                        │  SQLite / Postgres                 │                        │
                        └────────────────────────────────────┘                        │
                                                                                      │
      ┌───────────────┐   WireGuard (UDP, direct, hole-punched)   ┌───────────────┐   │
      │   Agent  A    │◀────────────────────────────────────────▶│   Agent  B    │───┘
      │ 100.64.0.1    │                                           │ 100.64.0.2    │
      └───────────────┘                                           └───────────────┘
```

### Components (one Go module, two binaries)

| Binary | Role |
|---|---|
| `transporter-coordinator` | Control plane, admin API, web UI, STUN, relay, database. The only component that must be publicly reachable. |
| `transporter` (agent) | Runs on every node. Owns the WireGuard interface, talks to the coordinator, does NAT traversal, falls back to the relay, serves a small local UI/API on `127.0.0.1`. |

The CLI is the agent binary (`transporter up`, `transporter status`, `transporter login`, …).

### Control-plane flow

1. Agent generates a WireGuard keypair (private key never leaves the node) plus a separate node identity key.
2. Agent registers with the coordinator using a **pre-auth key** (or interactive OIDC login in a later phase). Coordinator assigns an IP from the overlay CIDR (default `100.64.0.0/10`, configurable) and stores the node.
3. Agent opens a long-lived control stream. Coordinator pushes a **netmap**: peer public keys, overlay IPs, known endpoints, allowed routes and ACL-filtered visibility.
4. Agent queries STUN to learn its public `ip:port`, reports endpoints (LAN + public) to the coordinator, which forwards them to peers.
5. Peers attempt simultaneous UDP hole-punching using exchanged endpoints ("call-me-maybe" message sent through the coordinator/relay).
6. If no direct path within a timeout (symmetric NAT, blocked UDP), traffic goes through the relay: still WireGuard-encrypted end to end, the relay only forwards opaque packets addressed by node public key.
7. Agents keep probing; when a direct path appears, they upgrade transparently.

### Data plane

- **WireGuard** via `golang.zx2c4.com/wireguard` (userspace, works everywhere) with optional kernel WireGuard on Linux when available (configured through `wgctrl`).
- A custom `conn.Bind` implementation multiplexes the single UDP socket between direct WireGuard packets, disco/ping packets and the relay connection — this is the key piece that makes direct-vs-relayed transparent to WireGuard (same approach Tailscale's `magicsock` uses).
- TUN: Linux `/dev/net/tun`, macOS `utun`, Windows `wintun.dll`.
- Optional userspace netstack mode (gVisor `netstack`) so the agent can run **without root/TUN** — useful for unprivileged Docker containers and acting as a SOCKS5/HTTP proxy into the mesh.

---

## 2. Technology choices

| Concern | Choice | Why |
|---|---|---|
| Language | **Go 1.23+** | First-class WireGuard libs, trivial static cross-compilation (`CGO_ENABLED=0`), single binary, great networking stdlib. |
| Control protocol | gRPC over HTTP/2 (protobuf via `buf`) with a WebSocket fallback | Typed, streaming; WebSocket passes through restrictive proxies. |
| Relay | Custom framed protocol over TLS on 443 (DERP-like) | Works through almost any firewall. |
| STUN | `pion/stun` | Small, pure Go. |
| Database | SQLite (default, pure-Go `modernc.org/sqlite`) / Postgres (optional) via `sqlc` + `goose` migrations | No CGO keeps native builds simple; SQLite = zero-dependency single-host deploy. |
| Config | YAML file + env vars + flags (`koanf`) ; runtime settings stored in DB and editable from UI | Docker-friendly (env), ops-friendly (file), user-friendly (UI). |
| Web UI | **React + TypeScript + Vite**, **Tailwind CSS + shadcn/ui**, TanStack Query/Router, Zod forms | Modern look, accessible components, fast build. |
| UI delivery | Built assets embedded in the Go binary with `//go:embed` | The UI ships inside the native binary and the Docker image — no separate web server. |
| API contract | OpenAPI 3 spec → generated TS client (`openapi-typescript`) + Go server stubs (`oapi-codegen`) | UI and backend can't drift. |
| Auth (UI) | Local admin account (argon2id) + session cookies; OIDC later | |
| Logging/metrics | `log/slog` JSON logs, Prometheus `/metrics` | |
| Build/release | `goreleaser` (binaries, archives, deb/rpm, Homebrew, Docker multi-arch), GitHub Actions | One tool produces every artifact. |

License note: the repo is AGPL-3.0; all dependencies above are MIT/BSD/Apache-2.0 and compatible.

---

## 3. Repository layout

```
transporter/
├── cmd/
│   ├── coordinator/          # main for transporter-coordinator
│   └── transporter/          # main for agent + CLI
├── internal/
│   ├── coordinator/
│   │   ├── api/              # REST admin API (OpenAPI-generated handlers)
│   │   ├── control/          # gRPC control stream, netmap computation
│   │   ├── ipam/             # overlay IP allocation
│   │   ├── acl/              # policy evaluation
│   │   ├── relay/            # DERP-style relay server
│   │   ├── stun/
│   │   └── store/            # sqlc queries + migrations
│   ├── agent/
│   │   ├── engine/           # orchestrates wg device, netmap updates
│   │   ├── magicsock/        # custom conn.Bind: direct/relay/disco multiplexing
│   │   ├── nat/              # STUN client, hole punching, endpoint discovery
│   │   ├── tun/              # per-OS TUN + route/DNS setup (build tags)
│   │   ├── netstack/         # userspace mode
│   │   └── localapi/         # 127.0.0.1 API for CLI + local UI
│   ├── proto/                # .proto files and generated code
│   ├── config/
│   └── version/
├── web/                      # React app (Vite)
│   ├── src/
│   └── embed.go              # //go:embed dist
├── api/openapi.yaml
├── deploy/
│   ├── docker/               # Dockerfiles
│   ├── compose/              # docker-compose examples
│   └── systemd/, launchd/, windows-service/
├── docs/
├── .goreleaser.yaml
├── Makefile
└── .github/workflows/
```

---

## 4. Docker and native builds

### Native

- `CGO_ENABLED=0 go build` for every target: `linux/{amd64,arm64,arm}`, `darwin/{amd64,arm64}`, `windows/{amd64,arm64}`, `freebsd/amd64` (coordinator).
- UI is built first (`pnpm build`) and embedded, so each binary is fully self-contained.
- Service integration: systemd unit, launchd plist, Windows service (`golang.org/x/sys/windows/svc`). `transporter service install` sets it up.
- Packages via goreleaser: `.tar.gz`/`.zip`, `.deb`, `.rpm`, `apk`, Homebrew tap, Scoop/winget manifest.
- Windows ships `wintun.dll` alongside (or embedded and extracted at runtime).

### Docker

Multi-stage, multi-arch (`linux/amd64`, `linux/arm64`) images built by goreleaser/buildx:

```Dockerfile
# stage 1: web
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ .
RUN pnpm build

# stage 2: go
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/coordinator ./cmd/coordinator

# stage 3: runtime
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/coordinator /usr/local/bin/coordinator
EXPOSE 443/tcp 3478/udp
VOLUME /data
ENTRYPOINT ["/usr/local/bin/coordinator"]
```

- **Coordinator image**: distroless, non-root, `/data` volume, ports `443/tcp` (UI+API+control+relay), `3478/udp` (STUN). Built-in ACME (Let's Encrypt via `autocert`) or run behind a reverse proxy.
- **Agent image**: alpine-based (needs `iptables`/`ip`), runs with `--cap-add NET_ADMIN --device /dev/net/tun`, or with no privileges in netstack mode. Usable as a sidecar (`network_mode: service:transporter`) to put other containers on the mesh.
- `deploy/compose/` ships a ready-to-run `docker-compose.yml` for the coordinator and an example agent.

---

## 5. Configuration UI

Served by the coordinator at `https://<coordinator>/`. Dark/light theme, responsive, keyboard accessible.

| Page | Contents |
|---|---|
| **Onboarding wizard** | First-run: create admin, set public URL, overlay CIDR, DNS suffix, TLS mode. |
| **Dashboard** | Online/offline nodes, direct vs relayed connection ratio, relay bandwidth, recent events. |
| **Nodes** | Table with search/filter; per-node detail: IPs, OS/version, endpoints, last seen, latency to peers, routes, tags; rename, expire key, disable, delete. |
| **Topology** | Live graph of the mesh (React Flow), edges coloured by direct/relayed and latency. |
| **Enroll device** | Generate pre-auth keys (reusable/ephemeral/expiry/tags), shows copy-paste commands for Linux/macOS/Windows/Docker and a QR code. |
| **Access control** | ACL policy editor: visual rule builder (source tags → destination tags:ports) plus a raw JSON/HuJSON editor (Monaco) with validation and a "test a connection" simulator. |
| **Routes & exit nodes** | Approve advertised subnet routes and exit nodes. |
| **DNS** | MagicDNS-style names (`node.mesh.internal`), split DNS, upstream resolvers. |
| **Settings** | Coordinator URL, relay/STUN settings, key expiry policy, OIDC, admin users, API tokens. |
| **Audit log** | Who changed what, when. |

Real-time updates via Server-Sent Events from the API. The agent also serves a minimal local status page on `127.0.0.1:41641` (same component library) showing connection state and peers.

---

## 6. Security model

- WireGuard keys are generated on the node; the coordinator only stores public keys.
- Coordinator ↔ agent traffic is TLS 1.3; the agent pins the coordinator's identity key after first registration (TOFU, optional explicit pin in config).
- The relay forwards only already-encrypted WireGuard packets; a compromised coordinator can disrupt or add peers but cannot decrypt existing traffic. (Mitigation for malicious peer injection: optional **node-signing / tailnet lock** in a later phase.)
- ACLs enforced twice: coordinator filters what peers each node sees; agent applies a packet filter on the TUN as well.
- Pre-auth keys hashed at rest; admin passwords with argon2id; CSRF protection, secure cookies, rate limiting on login and registration.
- Key expiry and node re-auth configurable.

---

## 7. Milestones

Each phase ends with something runnable and tested.

### Phase 0 — Foundations (week 1)
- Go module, repo layout, Makefile, `golangci-lint`, `buf`, pre-commit.
- GitHub Actions: lint, test, cross-compile matrix, Docker build.
- Vite + React + Tailwind + shadcn skeleton embedded into the coordinator binary; `/healthz`.
- goreleaser config producing snapshot artifacts.

### Phase 1 — Static mesh, direct only (weeks 2–3)
- Coordinator: SQLite store, IPAM, pre-auth keys, node registration, netmap push over gRPC stream.
- Agent: keygen, registration, userspace WireGuard + TUN on Linux, apply netmap, routes.
- CLI: `up`, `down`, `status`, `ping`.
- **Exit criterion:** three Linux nodes with public IPs (or same LAN) form a full mesh; verified in a docker-compose integration test.

### Phase 2 — NAT traversal + relay (weeks 4–6)
- STUN server/client, endpoint discovery and reporting.
- `magicsock` bind: disco ping/pong, hole punching, path selection, upgrade/downgrade.
- DERP-style relay over TLS 443.
- **Exit criterion:** integration tests with network namespaces simulating cone and symmetric NATs; symmetric↔symmetric falls back to relay, others go direct.

### Phase 3 — Configuration UI v1 (weeks 6–8, overlaps Phase 2)
- OpenAPI spec, generated clients, admin auth.
- Onboarding wizard, dashboard, nodes, enroll device, settings.
- SSE live updates.
- **Exit criterion:** a new user can deploy the coordinator with one `docker run`, finish the wizard and enroll a node only from the UI.

### Phase 4 — Cross-platform agent (weeks 9–10)
- macOS (`utun`, route + DNS via `scutil`), Windows (wintun, routes via `winipcfg`, service), Linux kernel-WG fast path.
- Netstack (no-root) mode + SOCKS5 proxy; agent Docker image + sidecar example.
- Service installers.
- **Exit criterion:** CI builds and smoke-tests on Linux, macOS, Windows runners.

### Phase 5 — Policy, DNS, routing (weeks 11–13)
- ACL engine + UI editor + simulator; agent-side packet filter.
- MagicDNS resolver in agent, split DNS.
- Subnet routers and exit nodes with approval flow.
- Topology view, audit log.

### Phase 6 — Hardening and release (weeks 14–16)
- OIDC login, API tokens, key expiry, Postgres backend.
- Prometheus metrics, structured logs, backup/restore of `/data`.
- Fuzz tests for protocol parsers, `govulncheck`, security review, load test (1,000 simulated nodes against one coordinator).
- Docs site, v1.0.0 release via goreleaser (signed with cosign, SBOMs).

### Later
Tailnet lock (signed node keys), mobile clients (Android via gomobile + VpnService, iOS via NetworkExtension), multiple relay regions, HA coordinator.

---

## 8. Testing strategy

- **Unit:** IPAM, ACL evaluation, netmap diffing, protocol framing (plus `go test -fuzz`).
- **Integration:** docker-compose / Linux network-namespace topologies with `iptables` NAT rules simulating each NAT type; assert direct vs relayed paths and ping/iperf3 throughput.
- **UI:** Vitest + Testing Library for components, Playwright end-to-end against a real coordinator container.
- **Cross-platform:** GitHub Actions matrix (ubuntu, macos, windows) running agent smoke tests.

---

## 9. Key risks

| Risk | Mitigation |
|---|---|
| NAT traversal is the hardest part and easy to get subtly wrong | Build the NAT simulation test harness early (Phase 2 start); study Tailscale's open-source `magicsock`/`disco` design. |
| Single coordinator is a single point of failure | Existing tunnels keep working when it's down (agents cache the last netmap); only new joins/changes and relayed traffic are affected. HA is a later goal. |
| Relay bandwidth cost on the coordinator | Per-node relay rate limits, metrics showing relayed traffic, aggressive direct-path upgrades. |
| Windows/macOS networking quirks | Reuse proven libs (`wireguard-go`, `wintun`, `winipcfg`); dedicated CI runners. |
| Scope creep vs existing tools (Headscale, NetBird) | Keep v1 focused: one coordinator, one tailnet, pre-auth keys, ACLs, great UI. |

---

## 10. Open decisions

1. **Wire-compatibility with Tailscale clients?** Reusing the Tailscale protocol (Headscale-style) would give mature clients for free but ties us to their protocol. This plan assumes our own protocol and agent.
2. **Multi-tenant (several isolated networks) or single network** in v1? Plan assumes single network, schema ready for multiple.
3. **Coordinator-hosted relay only, or allow agents to act as relays?** Plan assumes coordinator only for v1.
