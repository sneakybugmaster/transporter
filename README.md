# Transporter

Self-hosted WireGuard mesh VPN with a single public coordinator and a web configuration UI.
Ships as native single binaries (Linux, macOS, Windows, FreeBSD for the coordinator) and as Docker images.

> **Status:** early development (Phase 0: foundations). The coordinator serves the UI and a health/version API;
> the agent is a CLI stub. See [docs/PLAN.md](docs/PLAN.md) for the roadmap.

## Components

| Binary | Role |
|---|---|
| `transporter-coordinator` | Public control server: admin API, embedded web UI, and later the control plane, STUN and relay. |
| `transporter` | Agent and CLI that runs on every node in the mesh. |

## Quick start

### Docker

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --build
# open http://localhost:8080
```

### From source

Requirements: Go 1.24+, Node.js 22+, pnpm 10 (`corepack enable`).

```sh
make all                      # build the web UI, then bin/transporter-coordinator and bin/transporter
./bin/transporter-coordinator # serves http://localhost:8080
./bin/transporter version
```

## Development

```sh
make run-coordinator   # Go server on :8080 (serves the last built UI)
make dev-web           # Vite dev server with hot reload, proxies /api to :8080
make test              # Go and web tests
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
| `-log-level` | `TRANSPORTER_LOG_LEVEL` | `info` |

### Layout

```
cmd/           entry points for both binaries
internal/      Go packages (coordinator, version, ...)
proto/         control-plane protobuf definitions (buf)
web/           React + TypeScript + Tailwind + shadcn/ui configuration UI, embedded via go:embed
deploy/        Dockerfiles and docker-compose examples
docs/          plan and design docs
```

## License

[AGPL-3.0](LICENSE)
