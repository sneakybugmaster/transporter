# syntax=docker/dockerfile:1
# Builds the mesh agent from source.
#   docker build -f deploy/docker/agent.Dockerfile -t transporter .
# Run with --cap-add NET_ADMIN --device /dev/net/tun (kernel TUN mode).

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev COMMIT=none DATE=unknown
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w \
        -X github.com/sneakybugmaster/transporter/internal/version.Version=$VERSION \
        -X github.com/sneakybugmaster/transporter/internal/version.Commit=$COMMIT \
        -X github.com/sneakybugmaster/transporter/internal/version.Date=$DATE" \
      -o /out/transporter ./cmd/transporter

FROM alpine:3.22
RUN apk add --no-cache ca-certificates iproute2 iptables ip6tables
COPY --from=build /out/transporter /usr/local/bin/transporter
VOLUME ["/var/lib/transporter"]
ENTRYPOINT ["/usr/local/bin/transporter"]
CMD ["version"]
