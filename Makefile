# Transporter build entry points. Run `make help` for a list of targets.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

PKG     := github.com/sneakybugmaster/transporter
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

GO_BUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"
BIN      := bin

# Release targets for `make cross`. The coordinator also builds for FreeBSD.
PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: help all web web-deps build coordinator agent cross test test-go test-web test-integration \
	lint lint-go lint-web lint-proto generate fmt run-coordinator dev-web docker clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: web build ## Build the UI and both binaries

web-deps:
	cd web && pnpm install --frozen-lockfile

web: web-deps ## Build the web UI into web/dist (embedded by the coordinator)
	cd web && pnpm build

build: coordinator agent ## Build both binaries for the host platform

coordinator: ## Build bin/transporter-coordinator
	$(GO_BUILD) -o $(BIN)/transporter-coordinator$(shell go env GOEXE) ./cmd/coordinator

agent: ## Build bin/transporter
	$(GO_BUILD) -o $(BIN)/transporter$(shell go env GOEXE) ./cmd/transporter

cross: ## Cross-compile both binaries for all release platforms into bin/<os>_<arch>/
	@set -e; for p in $(PLATFORMS) freebsd/amd64; do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "==> $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO_BUILD) -o $(BIN)/$${os}_$${arch}/transporter-coordinator$$ext ./cmd/coordinator; \
		if [ $$os != freebsd ]; then \
			GOOS=$$os GOARCH=$$arch $(GO_BUILD) -o $(BIN)/$${os}_$${arch}/transporter$$ext ./cmd/transporter; \
		fi; \
	done

test: test-go test-web ## Run all tests

test-go:
	go test -race ./...

test-web:
	cd web && pnpm test

test-integration: ## Run the 3-node mesh test in Docker (needs /dev/net/tun)
	test/integration/run.sh

lint: lint-go lint-web lint-proto ## Run all linters

lint-go:
	golangci-lint run

lint-web:
	cd web && pnpm lint && pnpm typecheck

lint-proto:
	buf lint && buf format -d --exit-code

generate: ## Regenerate protobuf/Connect code from proto/
	buf generate

fmt: ## Format Go and proto sources
	golangci-lint fmt
	buf format -w

run-coordinator: ## Run the coordinator locally on :8080
	go run ./cmd/coordinator -log-level debug -data-dir ./data

dev-web: ## Run the Vite dev server (proxies API calls to :8080)
	cd web && pnpm dev

docker: ## Build the coordinator and agent Docker images
	docker build -f deploy/docker/coordinator.Dockerfile -t transporter-coordinator:dev \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) .
	docker build -f deploy/docker/agent.Dockerfile -t transporter:dev \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) .

clean: ## Remove build outputs
	rm -rf $(BIN) dist
	find web/dist -mindepth 1 ! -name .gitkeep -delete
