# Release image: packages the binary goreleaser already built.
# For building from source use deploy/docker/agent.Dockerfile.
FROM alpine:3.22
ARG TARGETPLATFORM
RUN apk add --no-cache ca-certificates iproute2 iptables ip6tables
COPY $TARGETPLATFORM/transporter /usr/local/bin/transporter
VOLUME ["/var/lib/transporter"]
ENTRYPOINT ["/usr/local/bin/transporter"]
CMD ["version"]
