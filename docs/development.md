# Development

Requirements: Go 1.26+, Node.js 22+, pnpm 10 (`corepack enable`), Docker for the integration tests.

```sh
make all               # build the web UI, then bin/transporter-coordinator and bin/transporter
make run-coordinator   # Go server on :8080 (serves the last built UI)
make dev-web           # Vite dev server with hot reload, proxies /api to :8080
make test              # Go and web tests
make fuzz              # run every fuzz target for FUZZTIME (default 30s)
make test-integration  # 3-node mesh, NAT lab, routing/policy/DNS test in Docker (needs /dev/net/tun)
make test-e2e          # Playwright: setup wizard and enrollment against real containers
make test-smoke        # coordinator + agents on this machine (add SMOKE_TUN=1 SUDO=sudo for a TUN agent)
make generate          # regenerate code after editing proto/ or api/openapi.yaml
make lint              # golangci-lint, eslint + tsc, buf lint
make cross             # cross-compile every release platform into bin/<os>_<arch>/
make docker            # build both Docker images from source
```

Store tests also run against Postgres when `TRANSPORTER_TEST_POSTGRES` points at a server
(`postgres://postgres:pw@127.0.0.1:5432/postgres?sslmode=disable`); each test gets its own schema.

## Load test

`test/load` simulates many nodes against a running coordinator: it registers them, keeps a netmap stream
open for each, and measures how long changes take to reach everyone.

```sh
transporter-coordinator --data-dir /tmp/load --bootstrap-authkey trk_load &
go run ./test/load -coordinator http://127.0.0.1:8080 -authkey trk_load -nodes 1000
```

## Docs

This site is built with MkDocs Material from `docs/`:

```sh
pip install mkdocs-material==9.6.14
mkdocs serve
```

## Releases

Pushing a `v*` tag runs GoReleaser in GitHub Actions: archives for every platform, `.deb`/`.rpm`/`.apk`
packages, multi-arch images on `ghcr.io`, SBOMs, and cosign signatures for the checksums and images.
