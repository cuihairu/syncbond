# deploy/Dockerfile (todo.md DSR-49): the standalone self-hosted relay image,
# the deploy/ layout default-server.md §2 assigns. Two stages: a builder
# compiles the release binary from the workspace, a minimal runtime runs it.
#
# The image carries no credential material. The admin bootstrap credential is
# written by the server into the data volume on first boot, and every channel
# credential is issued afterwards through the admin API — never baked in.
#
# Build (context = repository root, where the workspace manifests live):
#   docker build -f deploy/Dockerfile -t syncbond-server .

FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
# --locked: the committed Cargo.lock is authoritative, so a manifest drift
# fails the image build instead of silently re-resolving. -p keeps the build
# to the server and its own dependencies; the rest of the workspace (wasm,
# napi, python, ffi bindings) is not compiled into the image.
RUN cargo build --release --locked --package syncbond-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 syncbond \
    && useradd --system --uid 1000 --gid syncbond --shell /usr/sbin/nologin syncbond \
    && mkdir -p /data /etc/syncbond \
    && chown syncbond:syncbond /data /etc/syncbond
COPY --from=builder /src/target/release/syncbond-server /usr/local/bin/syncbond-server
COPY --chown=syncbond:syncbond deploy/config.json /etc/syncbond/config.json
# State lives here: relay.db (and its WAL) plus the admin bootstrap
# credential. Name or bind a volume; a host bind must be writable by UID
# 1000, the user the container runs as (docker run -v /host/data:/data).
VOLUME ["/data"]
USER syncbond
# Container-facing listener. A public deployment terminates TLS in a reverse
# proxy in front of the container and reaches it over the docker network, so
# the container itself speaks plaintext to that proxy (default-server.md §4:
# plaintext is local-development-only; the proxy is the public edge).
EXPOSE 8080
# /v1/ready flips only after the listener is up and the store is open, so it
# is the probe; /v1/health answers liveness earlier. The default config binds
# 8080 — a config that binds another port must override this command too
# (docker run --health-cmd ...).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/v1/ready || exit 1
CMD ["/usr/local/bin/syncbond-server", "/etc/syncbond/config.json"]
