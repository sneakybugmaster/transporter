# Transporter

Self-hosted WireGuard mesh VPN with a single public coordinator and a web configuration UI.
Ships as native single binaries (Linux, macOS, Windows, FreeBSD for the coordinator) and as Docker images.

> **Status:** early development (Phase 4 done). Linux, macOS and Windows nodes enroll and form a WireGuard
> mesh, punching through NATs to connect directly when possible and relaying through the coordinator otherwise.
> The web console handles first-run setup, enrollment and node management. Access control, DNS and subnet
> routing (Phase 5) are next.
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

On **Enroll device**, create an auth key; the page shows the command for each platform. The usual way is to
enroll and install the agent as a service in one step, so it reconnects after reboots:

```sh
# Linux (systemd) and macOS (launchd); on Linux put the binary in /usr/local/bin first
sudo transporter service install --coordinator https://mesh.example.com --authkey trk_...

# Windows (Administrator PowerShell, with wintun.dll next to transporter.exe as shipped in the zip)
.\transporter.exe service install --coordinator https://mesh.example.com --authkey trk_...
```

The auth key is only used to enroll; it is not stored in the service configuration. `transporter service
uninstall` removes the service. To run in the foreground instead, use `transporter up` with the same flags.

In Docker, with a TUN interface (needs `NET_ADMIN` and the TUN device):

```sh
docker run -d --name transporter --restart unless-stopped --cap-add NET_ADMIN --device /dev/net/tun \
  -v transporter-state:/var/lib/transporter \
  -e TRANSPORTER_COORDINATOR=https://mesh.example.com -e TRANSPORTER_AUTHKEY=trk_... \
  ghcr.io/sneakybugmaster/transporter:latest up
```

The device appears on the **Nodes** page as soon as it connects. On the device, `transporter status` lists
peers and how each is reached, and `transporter ping <peer>` measures round trips.

The node keeps its key and address in `--state-dir` (default `/var/lib/transporter`; macOS
`/Library/Application Support/Transporter`; Windows `%ProgramData%\Transporter`), so later runs need no auth key.

### Without root: userspace mode

`transporter up --userspace` runs WireGuard over an in-process network stack (gVisor). It needs no root, no
TUN device and no capabilities, so it works in locked-down containers, CI jobs and on unsupported OSes.
The OS doesn't see the mesh; programs reach it through the agent's SOCKS5 proxy (default `127.0.0.1:1055`),
which resolves peer names:

```sh
transporter up --userspace --coordinator https://mesh.example.com --authkey trk_...
curl --socks5-hostname 127.0.0.1:1055 http://build-server:8080/
```

Non-mesh destinations are passed straight through, so you can point a whole program at the proxy
(`ALL_PROXY=socks5h://127.0.0.1:1055`). [`deploy/compose/agent-sidecar.yml`](deploy/compose/agent-sidecar.yml)
puts an app container on the mesh this way, without any privileges. Keep the proxy on a loopback address: it
does not authenticate clients.

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
make test-smoke        # coordinator + agents on this machine (add SMOKE_TUN=1 SUDO=sudo for a TUN agent)
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
| `--state-dir` | `TRANSPORTER_STATE_DIR` | `/var/lib/transporter` (see above for macOS/Windows) |
| `--listen-port` | | `41641` (UDP) |
| `--interface` | | `transporter0` (macOS always uses the next free `utunN`) |
| `--advertise-endpoints` | `TRANSPORTER_ADVERTISE_ENDPOINTS` | extra `ip:port` endpoints, comma-separated |
| `--userspace` | `TRANSPORTER_USERSPACE` | `false`; in-process network stack instead of a TUN interface |
| `--socks5` | `TRANSPORTER_SOCKS5` | `127.0.0.1:1055` with `--userspace`, otherwise off; `off` disables |

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
test/          end-to-end tests: docker compose mesh, network-namespace NAT lab, browser e2e,
               cross-platform smoke test (CI runs it on Linux, macOS and Windows)
```

## License

[AGPL-3.0](LICENSE)
