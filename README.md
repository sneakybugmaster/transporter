# Transporter

Self-hosted WireGuard mesh VPN with a single public coordinator and a web configuration UI.
Ships as native single binaries (Linux, macOS, Windows, FreeBSD for the coordinator) and as Docker images.

> **Status:** early development (Phase 3 done). Linux nodes enroll and form a WireGuard mesh, punching
> through NATs to connect directly when possible and relaying through the coordinator otherwise. The web
> console handles first-run setup, enrollment and node management. macOS/Windows agents (Phase 4) are next.
> See [docs/PLAN.md](docs/PLAN.md) for the roadmap.
>
> The coordinator speaks plain HTTP for now. Put it behind a TLS-terminating reverse proxy before exposing
> it to the internet: node tokens and auth keys travel in requests.

## Components

| Binary | Role |
|---|---|
| `transporter-coordinator` | Public control server: control plane, STUN, packet relay, admin API and the embedded web console. |
| `transporter` | Agent and CLI that runs on every node in the mesh. |

## Quick start

### 1. Start the coordinator

```sh
docker run -d --name transporter-coordinator --restart unless-stopped \
  -p 8080:8080 -p 3478:3478/udp -v transporter-data:/data \
  ghcr.io/sneakybugmaster/transporter-coordinator:latest
docker logs transporter-coordinator 2>&1 | grep setupCode
```

(Or `docker compose -f deploy/compose/docker-compose.yml up -d --build` to build from source.)

### 2. Finish setup in the browser

Open http://localhost:8080. The setup wizard asks for the one-time **setup code** from the log, which proves
you run this coordinator. It then creates your admin account and asks for the URL devices will use to reach
the coordinator.

### 3. Enroll devices

On **Enroll device**, create an auth key and run the command shown on each Linux device (as root):

```sh
sudo transporter up --coordinator https://mesh.example.com --authkey trk_...
```

or in Docker (needs `NET_ADMIN` and the TUN device):

```sh
docker run -d --name transporter --restart unless-stopped --cap-add NET_ADMIN --device /dev/net/tun \
  -v transporter-state:/var/lib/transporter \
  -e TRANSPORTER_COORDINATOR=https://mesh.example.com -e TRANSPORTER_AUTHKEY=trk_... \
  ghcr.io/sneakybugmaster/transporter:latest up
```

The device appears on the **Nodes** page as soon as it connects. On the device, `transporter status` lists
peers and how each is reached, and `transporter ping <peer>` measures round trips.

The node keeps its key and address in `--state-dir` (default `/var/lib/transporter`), so later runs need no auth key.

**How nodes connect.** Each node learns its public address from the coordinator's STUN server (UDP 3478) and
advertises it with its LAN addresses. Peers probe those addresses with small encrypted "disco" packets and,
through the coordinator, ask each other to probe back at the same time, which opens most NATs. Until a direct
path answers, and whenever none can (e.g. both sides behind symmetric NATs), WireGuard traffic is relayed
through the coordinator over a WebSocket; it stays end-to-end encrypted. `transporter status` shows each
peer's path. The coordinator must be reachable on its HTTP port and on UDP 3478.

### From source

Requirements: Go 1.26+, Node.js 22+, pnpm 10 (`corepack enable`).

```sh
make all                      # build the web UI, then bin/transporter-coordinator and bin/transporter
./bin/transporter-coordinator # serves http://localhost:8080
./bin/transporter-coordinator authkey create --reusable
sudo ./bin/transporter up --coordinator http://localhost:8080 --authkey trk_...
```

## Development

```sh
make run-coordinator   # Go server on :8080 (serves the last built UI)
make dev-web           # Vite dev server with hot reload, proxies /api to :8080
make test              # Go and web tests
make test-integration  # 3-node mesh + NAT traversal lab in Docker (needs /dev/net/tun, privileged containers)
make test-e2e          # Playwright: setup wizard and enrollment against real containers
make generate          # regenerate code after editing proto/ or api/openapi.yaml
make lint              # golangci-lint, eslint + tsc, buf lint
make cross             # cross-compile every release platform into bin/<os>_<arch>/
make docker            # build both Docker images from source
make help              # list all targets
```

Releases are produced by [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) when a `v*` tag is pushed:
archives, `.deb`/`.rpm`/`.apk` packages and multi-arch images on `ghcr.io`.

### Coordinator configuration

| Flag | Environment variable | Default |
|---|---|---|
| `-listen` | `TRANSPORTER_LISTEN` | `:8080` |
| `-data-dir` | `TRANSPORTER_DATA_DIR` | `./data` (`/data` in Docker) |
| `-network-prefix` | `TRANSPORTER_NETWORK_PREFIX` | `100.64.0.0/10` |
| `-bootstrap-authkey` | `TRANSPORTER_BOOTSTRAP_AUTHKEY` | unset; ensures a reusable key with this value exists |
| `-setup-code` | `TRANSPORTER_SETUP_CODE` | random, printed in the log while setup is pending |
| `-stun-listen` | `TRANSPORTER_STUN_LISTEN` | `:3478` (UDP; empty disables) |
| `-relay` | `TRANSPORTER_RELAY` | `true` |
| `-relay-rate` | `TRANSPORTER_RELAY_RATE` | `4194304` bytes/s per node (0 = unlimited) |
| `-log-level` | `TRANSPORTER_LOG_LEVEL` | `info` |

Admin subcommands (`authkey create|list|revoke`, `nodes list|delete`) take `--data-dir` and can run alongside the
server. The web console uses the REST API described in [`api/openapi.yaml`](api/openapi.yaml).

### Agent configuration (`transporter up`)

| Flag | Environment variable | Default |
|---|---|---|
| `--coordinator` | `TRANSPORTER_COORDINATOR` | required |
| `--authkey` | `TRANSPORTER_AUTHKEY` | needed only to enroll |
| `--hostname` | `TRANSPORTER_HOSTNAME` | system hostname |
| `--state-dir` | `TRANSPORTER_STATE_DIR` | `/var/lib/transporter` |
| `--listen-port` | | `41641` (UDP) |
| `--interface` | | `transporter0` |
| `--advertise-endpoints` | `TRANSPORTER_ADVERTISE_ENDPOINTS` | extra `ip:port` endpoints, comma-separated |

### Layout

```
cmd/           entry points for both binaries
internal/      Go packages: coordinator (store, control plane), agent (engine, magicsock, CLI backends),
               relay, stun, wgkey
api/           admin REST API (OpenAPI); Go server types and TS client types are generated from it
proto/         control-plane protobuf definitions (buf); generated code in internal/proto
web/           React + TypeScript + Tailwind + shadcn/ui configuration UI, embedded via go:embed
deploy/        Dockerfiles and docker-compose examples
docs/          plan and design docs
test/          end-to-end tests: docker compose mesh, network-namespace NAT lab, browser e2e
```

## License

[AGPL-3.0](LICENSE)
