# syntax=docker/dockerfile:1
# Builds the coordinator from source, including the embedded web UI.
#   docker build -f deploy/docker/coordinator.Dockerfile -t transporter-coordinator .

FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev COMMIT=none DATE=unknown
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w \
        -X github.com/sneakybugmaster/transporter/internal/version.Version=$VERSION \
        -X github.com/sneakybugmaster/transporter/internal/version.Commit=$COMMIT \
        -X github.com/sneakybugmaster/transporter/internal/version.Date=$DATE" \
      -o /out/transporter-coordinator ./cmd/coordinator \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/transporter-coordinator /usr/local/bin/transporter-coordinator
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV TRANSPORTER_LISTEN=:8080 \
    TRANSPORTER_DATA_DIR=/data
EXPOSE 8080/tcp 443/tcp 3478/udp
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD ["/usr/local/bin/transporter-coordinator", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/transporter-coordinator"]
