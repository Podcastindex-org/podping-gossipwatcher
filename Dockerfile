FROM --platform=$BUILDPLATFORM rust:slim-bookworm AS builder
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl-dev \
        pkg-config \
        gcc-aarch64-linux-gnu \
        gcc-x86-64-linux-gnu \
        libc6-dev-arm64-cross \
        libc6-dev-amd64-cross \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
ENV CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc

WORKDIR /src

COPY Cargo.toml Cargo.lock /src/
COPY podping-gossipwatcher /src/podping-gossipwatcher

RUN if [ "$TARGETARCH" = "arm64" ]; then \
        RUST_TARGET=aarch64-unknown-linux-gnu; \
    else \
        RUST_TARGET=x86_64-unknown-linux-gnu; \
    fi \
    && cargo build --release --locked --target "$RUST_TARGET" -p podping-gossipwatcher \
    && cp "target/$RUST_TARGET/release/podping-gossipwatcher" target/release/podping-gossipwatcher

FROM debian:trixie-slim AS runner

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data/gossip /opt/podping-gossipwatcher \
    && chown -R 1000:1000 /data /opt/podping-gossipwatcher

WORKDIR /opt/podping-gossipwatcher
COPY --from=builder /src/target/release/podping-gossipwatcher /opt/podping-gossipwatcher/podping-gossipwatcher

USER 1000

EXPOSE 8089

ENTRYPOINT ["/opt/podping-gossipwatcher/podping-gossipwatcher"]
