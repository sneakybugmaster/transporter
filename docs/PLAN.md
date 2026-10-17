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
| Language | **Go 1.26+** | First-class WireGuard libs, trivial static cross-compilation (`CGO_ENABLED=0`), single binary, great networking stdlib. |
| Control protocol | Protobuf services via [Connect](https://connectrpc.com) (`buf` codegen) | Typed, streaming; speaks the gRPC protocol over HTTP/2 *and* the Connect protocol over plain HTTP/1.1, so it passes restrictive proxies without a separate WebSocket fallback. |
| Relay | Binary frames over a WebSocket on the coordinator's HTTPS port (DERP-like) | Works through almost any firewall and HTTP proxy. |
| STUN | Minimal in-repo RFC 5389 binding implementation | The subset needed is ~150 lines; avoids pulling in DTLS and friends. |
| Database | SQLite (default, pure-Go `modernc.org/sqlite`) / Postgres (optional, Phase 6); plain `database/sql` with embedded, numbered SQL migrations | No CGO keeps native builds simple; SQLite = zero-dependency single-host deploy. Revisit `sqlc` when Postgres support lands. |
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
FROM golang:1.26-alpine AS build
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
- Coordinator ↔ agent traffic is TLS 1.3 (built-in ACME or a reverse proxy; until then run the coordinator behind a TLS-terminating proxy); the agent pins the coordinator's identity key after first registration (TOFU, optional explicit pin in config) — Phase 6.
- The relay forwards only already-encrypted WireGuard packets; a compromised coordinator can disrupt or add peers but cannot decrypt existing traffic. (Mitigation for malicious peer injection: optional **node-signing / tailnet lock** in a later phase.)
- ACLs enforced twice: coordinator filters what peers each node sees; agent applies a packet filter on the TUN as well.
- Pre-auth keys hashed at rest; admin passwords with argon2id; CSRF protection, secure cookies, rate limiting on login and registration.
- Key expiry and node re-auth configurable.

---

## 7. Milestones

Each phase ends with something runnable and tested.

### Phase 0 — Foundations (week 1) — ✅ done
- Go module, repo layout, Makefile, `golangci-lint`, `buf` (pre-commit hooks deferred; `make lint` covers the same checks).
- GitHub Actions: lint, test, cross-compile matrix, Docker build.
- Vite + React + Tailwind + shadcn skeleton embedded into the coordinator binary; `/healthz`.
- goreleaser config producing snapshot artifacts.

### Phase 1 — Static mesh, direct only (weeks 2–3) — ✅ done
- Coordinator: SQLite store, IPAM, pre-auth keys, node registration, netmap push over a Connect server stream.
  Admin subcommands (`authkey create|list|revoke`, `nodes list|delete`) work on the database until the admin API arrives in Phase 3.
- Agent: keygen, registration, userspace WireGuard + TUN on Linux, apply netmap, routes (the interface address carries the mesh prefix length, so one kernel route covers the mesh).
- CLI: `up`, `down`, `status`, `ping` (UDP echo over the mesh on port 41642; no root needed).
- Endpoints are each node's interface addresses plus the address the coordinator observes; the agent rotates through candidates until a handshake succeeds. (Replaced by STUN and disco in Phase 2.)
- Nodes authenticate RPCs with a coordinator-issued bearer token (hashed at rest). The separate node identity key and coordinator key pinning move to Phase 6 with TLS.
- **Exit criterion met:** `test/integration/run.sh` (also in CI) starts a coordinator and three agents with real TUN devices; every pair pings through the mesh, before and after an agent restart.

### Phase 2 — NAT traversal + relay (weeks 4–6) — ✅ done
- STUN: a minimal RFC 5389 binding implementation (`internal/stun`, fuzzed) shared by the coordinator's server (UDP 3478) and the agent, which sends requests from its WireGuard socket to learn its public mapping. Agents push endpoint changes with a new `UpdateEndpoints` RPC; the Phase 1 "observed address" heuristic is gone.
- `magicsock` bind: WireGuard addresses peers by key; per packet the bind uses a direct address that answered a disco ping within the last 12 s, else the relay. Disco ping/pong/call-me-maybe messages share the UDP socket, sealed with XChaCha20-Poly1305 under a key derived from the two nodes' WireGuard keys (no separate disco keys). Peer-reflexive addresses learned from pings become candidates; paths upgrade to direct as soon as a pong arrives and fall back to the relay when pongs stop.
- Relay: WebSocket (`/relay/v1`, so it rides the coordinator's HTTPS port and passes proxies) forwarding already-encrypted frames addressed by WireGuard key; node-token auth, per-node rate limit (`-relay-rate`, default 4 MiB/s), bounded queues that drop rather than block.
- Agent registration now retries while the coordinator is unreachable.
- IPv4 only for now: the bind opens a `udp4` socket. IPv6 paths are a follow-up.
- **Exit criterion met:** `test/integration/nat/run.sh` (in CI) builds a network-namespace lab with two cone and two symmetric NAT routers. Cone↔cone pairs hole-punch to a direct path; every pair involving a symmetric NAT uses the relay. (With port-restricted cone NATs, cone↔symmetric cannot go direct either; that needs port prediction, which is out of scope.) All pairs reach each other in every case.

### Phase 3 — Configuration UI v1 (weeks 6–8, overlaps Phase 2) — ✅ done
- REST admin API described in `api/openapi.yaml`; Go types and a `net/http` server interface are generated with oapi-codegen, TypeScript types with openapi-typescript (used through `openapi-fetch`). CI fails if generated code is stale, and a test checks that the API's list of public operations matches the spec.
- Admin auth: argon2id passwords, server-side sessions in an HttpOnly, SameSite=Strict cookie (Secure over HTTPS), per-IP rate limit on login and setup. State-changing requests must be JSON (cross-site forms can't send it without a CORS preflight, which is never granted) and pass an Origin check.
- First-run setup needs a one-time setup code printed in the coordinator log (`-setup-code` to choose it), so a freshly deployed coordinator can't be claimed by whoever reaches it first.
- UI (React, TanStack Router + Query, shadcn/ui): setup wizard, login, dashboard, nodes (search, details, rename, remove), enroll device (auth keys with expiry, install commands for Linux and Docker, QR code, live "device enrolled" confirmation, revoke), settings (public URL, password). Light/dark, works at phone width.
- Live updates over Server-Sent Events (`/api/v1/events`): pages refetch when nodes join, leave, connect or change.
- **Exit criterion met:** `test/e2e/run.sh` (in CI) starts a fresh coordinator container, completes the wizard in Chromium (including a rejected wrong setup code), creates an auth key on the enroll page, starts an agent container with that key and waits for it to show up online, then renames it and signs out and back in.
- Deferred: OIDC and multiple admins in the UI (Phase 6; the API already stores admins in a table), audit log (Phase 5).

### Phase 4 — Cross-platform agent (weeks 9–10) — ✅ done
- macOS: `utun` interface configured with `ifconfig`/`route`. Windows: Wintun adapter with addresses set through `winipcfg`; runs as a real Windows service; `wintun.dll` (pinned by SHA-256) ships in the Windows zips. Per-OS default state directories.
- Userspace mode (`--userspace`): WireGuard over gVisor's netstack, no root/TUN/capabilities; a SOCKS5 proxy (resolving peer names) gives programs access to the mesh; `transporter ping` now runs inside the agent so it works in both modes. Sidecar example in `deploy/compose/agent-sidecar.yml`; verified as `nobody` with all capabilities dropped.
- `transporter service install|uninstall`: systemd unit (hardened: ProtectSystem, ProtectHome, only CAP_NET_ADMIN/CAP_NET_RAW), launchd daemon, Windows service with restart-on-failure. Install enrolls first, so the auth key is never written into service configuration.
- Found while testing: right after start, a node's first WireGuard handshake was lost (no direct path yet and the relay still connecting), costing WireGuard's 5 s retry. magicsock now holds packets briefly until a path exists, on one side of each pair only, since releasing both sides' handshakes at once makes them cancel each other out.
- Dropped: the Linux kernel-WireGuard fast path. The kernel module talks UDP directly, so it can't use magicsock's relay fallback or disco-based path selection; it would only help nodes with public addresses. Revisit if throughput demands it.
- **Exit criterion met:** CI runs unit tests and `test/smoke/run.sh` on Linux, macOS and Windows runners. Each run covers userspace agents (ping, SOCKS5), a kernel-TUN agent (ping, kernel ICMP into the mesh, HTTP through SOCKS5 by peer name) and `service install`/`uninstall`.

### Phase 5 — Policy, DNS, routing (weeks 11–13)
- ACL engine + UI editor + simulator; agent-side packet filter.
- MagicDNS resolver in agent, split DNS.
- Subnet routers and exit nodes with approval flow.
- Topology view, audit log.

### Phase 6 — Hardening and release (weeks 14–16)
- OIDC login, API tokens, key expiry, Postgres backend.
- Prometheus metrics, structured logs, backup/restore of `/data`.
- Fuzz tests for protocol parsers, `govulncheck`, security review, load test (1,000 simulated nodes against one coordinator).
- Disco replay protection (a timestamp or counter in sealed messages): today a captured ping replayed from another address is answered with one pong and one probe. It cannot redirect traffic, since paths only change on a fresh pong, but it is avoidable noise. Close relay connections of deleted nodes immediately rather than at their next reconnect.
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
