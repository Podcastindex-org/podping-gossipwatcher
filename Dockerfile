FROM debian:trixie-slim

ARG TARGETPLATFORM

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data /opt/podping-gossipwatcher

WORKDIR /opt/podping-gossipwatcher

COPY artifacts /tmp/artifacts

RUN set -ex; \
    case "$TARGETPLATFORM" in \
        "linux/amd64") \
            cp /tmp/artifacts/x86_64-unknown-linux-gnu-binary/podping-gossipwatcher /opt/podping-gossipwatcher/podping-gossipwatcher ;; \
        "linux/arm64") \
            cp /tmp/artifacts/aarch64-unknown-linux-gnu-binary/podping-gossipwatcher /opt/podping-gossipwatcher/podping-gossipwatcher ;; \
        "linux/arm/v7") \
            cp /tmp/artifacts/armv7-unknown-linux-gnueabihf-binary/podping-gossipwatcher /opt/podping-gossipwatcher/podping-gossipwatcher ;; \
        *) \
            echo "Unsupported platform: $TARGETPLATFORM"; exit 1 ;; \
    esac; \
    chmod +x /opt/podping-gossipwatcher/podping-gossipwatcher; \
    rm -rf /tmp/artifacts

EXPOSE 8089

ENTRYPOINT ["/opt/podping-gossipwatcher/podping-gossipwatcher"]
