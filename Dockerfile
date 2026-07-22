FROM rust:latest AS builder

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Cargo.toml Cargo.lock /src/
COPY dtt /src/dtt
COPY gossip-listener /src/gossip-listener

RUN cargo build --release --locked -p gossip-listener

FROM debian:trixie-slim AS runner

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data/gossip /opt/gossip-listener \
    && chown -R 1000:1000 /data /opt/gossip-listener

WORKDIR /opt/gossip-listener
COPY --from=builder /src/target/release/gossip-listener /opt/gossip-listener/gossip-listener

USER 1000

EXPOSE 8089

ENTRYPOINT ["/opt/gossip-listener/gossip-listener"]
