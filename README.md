# Transporter

Self-hosted WireGuard mesh VPN with a single public coordinator and a web configuration UI.
Ships as native single binaries (Linux, macOS, Windows, FreeBSD for the coordinator) and as Docker images.

> **Status:** early development (Phase 1 done). Linux nodes can enroll and form a direct WireGuard mesh;
> NAT traversal and relaying (Phase 2), the admin UI (Phase 3) and macOS/Windows agents (Phase 4) are next.
> See [docs/PLAN.md](docs/PLAN.md) for the roadmap.
>
> The coordinator speaks plain HTTP for now. Put it behind a TLS-terminating reverse proxy before exposing
> it to the internet: node tokens and auth keys travel in requests.

## Components

| Binary | Role |
|---|---|
| `transporter-coordinator` | Public control server: control plane, embedded web UI, and later the admin API, STUN and relay. |
| `transporter` | Agent and CLI that runs on every node in the mesh. |

## Quick start

### 1. Start the coordinator

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --build
# UI on http://localhost:8080
```

### 2. Create an auth key

```sh
docker compose -f deploy/compose/docker-compose.yml exec coordinator \
  /usr/local/bin/transporter-coordinator authkey create --reusable --ttl 24h --data-dir /data
```

### 3. Connect nodes (Linux, as root)

```sh
transporter up --coordinator http://<coordinator-host>:8080 --authkey trk_...
transporter status          # in another shell
transporter ping <peer-name>
```

Or in Docker (needs `NET_ADMIN` and the TUN device):

```sh
docker run -d --name transporter --cap-add NET_ADMIN --device /dev/net/tun \
  -v transporter-state:/var/lib/transporter \
  -e TRANSPORTER_COORDINATOR=http://<coordinator-host>:8080 -e TRANSPORTER_AUTHKEY=trk_... \
  transporter:dev up
```

The node keeps its key and address in `--state-dir` (default `/var/lib/transporter`), so later runs need no auth key.
Nodes find each other on the addresses they report plus the address the coordinator sees them connect from;
until NAT traversal lands (Phase 2), nodes need to be on the same network or have public addresses, or you
can forward UDP 41641 and pass `--advertise-endpoints <public-ip>:41641`.

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
make test-integration  # 3-node mesh in Docker (needs /dev/net/tun)
make generate          # regenerate protobuf/Connect code after editing proto/
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
| `-log-level` | `TRANSPORTER_LOG_LEVEL` | `info` |

Admin subcommands (`authkey create|list|revoke`, `nodes list|delete`) take `--data-dir` and can run alongside the server.

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
internal/      Go packages: coordinator (store, control plane), agent (engine, CLI backends)
proto/         control-plane protobuf definitions (buf); generated code in internal/proto
web/           React + TypeScript + Tailwind + shadcn/ui configuration UI, embedded via go:embed
deploy/        Dockerfiles and docker-compose examples
docs/          plan and design docs
test/          end-to-end tests (docker compose)
```

## License

[AGPL-3.0](LICENSE)
