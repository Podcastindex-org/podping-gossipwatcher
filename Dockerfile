FROM rust:latest AS builder

WORKDIR /src

COPY Cargo.toml Cargo.lock /src/
COPY podping-gossipwatcher /src/podping-gossipwatcher

RUN cargo build --release --locked -p podping-gossipwatcher

FROM debian:trixie-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data/gossip /opt/podping-gossipwatcher \
    && chown -R 1000:1000 /data /opt/podping-gossipwatcher

WORKDIR /opt/podping-gossipwatcher
COPY --from=builder /src/target/release/podping-gossipwatcher /opt/podping-gossipwatcher/podping-gossipwatcher

USER 1000

EXPOSE 8089

ENTRYPOINT ["/opt/podping-gossipwatcher/podping-gossipwatcher"]
