# Release image: packages the binary goreleaser already built (with embedded UI).
# For building from source use deploy/docker/coordinator.Dockerfile.
FROM busybox:1.37 AS prep
RUN mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY --from=prep --chown=nonroot:nonroot /data /data
COPY $TARGETPLATFORM/transporter-coordinator /usr/local/bin/transporter-coordinator
ENV TRANSPORTER_LISTEN=:8080 \
    TRANSPORTER_DATA_DIR=/data
EXPOSE 8080/tcp 3478/udp
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD ["/usr/local/bin/transporter-coordinator", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/transporter-coordinator"]
