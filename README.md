# podping-gossipwatcher

Receives podcast feed update notifications ("podpings") over
[Iroh](https://iroh.computer/) p2p gossip — no blockchain account or API key
required.

> **Naming:** the repo follows the Podcastindex-org watcher convention
> (cf. [podping-hivewatcher](https://github.com/Podcastindex-org/podping-hivewatcher));
> the crate and binary keep their original name **`gossip-listener`** from the
> [podping.alpha](https://github.com/Podcastindex-org/podping.alpha) R&D repo,
> where this code was developed.

## What it does

`gossip-listener` joins the `gossipping/v1/all` gossip topic, discovers peers
via DHT and a local bootstrap list, verifies each notification's ed25519
signature against a trusted-publishers list, and prints valid notifications
to stdout. Optionally it can:

- archive notifications to SQLite (`ARCHIVE_ENABLED`),
- catch up on missed notifications from peer archives after downtime
  (`CATCHUP_ENABLED`),
- re-serve notifications to local consumers as Server-Sent Events
  (`SSE_ENABLED`, port 8089: `GET /` health, `GET /events` stream).

It also participates in the swarm's trust and discovery layers: it saves
`PeerAnnounce`/`NeighborUp` node IDs for bootstrap, accepts signed
`PeerEndorse` messages from already-trusted senders, and re-bootstraps from
known peers if no notification arrives within 180 seconds.

## Running with Docker

```sh
docker run -d --name gossip-watcher \
  -v $(pwd)/data:/data/gossip \
  -e IROH_NODE_KEY_FILE=/data/gossip/node.key \
  -e KNOWN_PEERS_FILE=/data/gossip/known_peers.txt \
  -e TRUSTED_PUBLISHERS_FILE=/data/gossip/trusted_publishers.txt \
  -e TRUSTED_MONITORS_FILE=/data/gossip/trusted_monitors.txt \
  -e SSE_ENABLED=true -p 8089:8089 \
  podcastindexorg/podping-gossipwatcher:latest
```

## Building from source

```sh
cargo build --release --locked -p gossip-listener
./target/release/gossip-listener
```

The workspace vendors `dtt/`, a fork of
[distributed-topic-tracker](https://crates.io/crates/distributed-topic-tracker)
0.2.8 (MIT, © Zacharias Boehler) — see `dtt/README.md` for the fork's changes.

`Cargo.lock` pins pre-release transitive deps that ed25519-dalek 3.0.0-pre.1
requires (`ed25519 3.0.0-rc.4`, `pkcs8 0.11.0-rc.11`, `spki 0.8.0-rc.4`).
Always build `--locked`; do not re-resolve these.

## Configuration

All configuration is via environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `BOOTSTRAP_PEER_IDS` | (empty) | Comma-separated iroh node IDs to join directly, skipping DHT |
| `IROH_NODE_KEY_FILE` | `gossip_listener_node.key` | Iroh transport key (created if missing) |
| `KNOWN_PEERS_FILE` | `gossip_listener_known_peers.txt` | Learned-peer cache for DHT-less restarts (max 15) |
| `DHT_INITIAL_SECRET` | `podping_gossip_default_secret` | Shared secret for DHT topic discovery |
| `TRUSTED_PUBLISHERS_FILE` | `trusted_publishers.txt` | ed25519 pubkeys whose notifications are accepted |
| `TRUSTED_MONITORS_FILE` | `trusted_monitors.txt` | Pubkeys allowed to send swarm-management messages |
| `PEER_ANNOUNCE_INTERVAL` | `300` | Seconds between self-announcements (0 disables) |
| `PEER_ENDORSE_INTERVAL` | `45` | Seconds between trust endorsements |
| `ARCHIVE_ENABLED` | `false` | Archive notifications to SQLite |
| `ARCHIVE_PATH` | `listener_archive.db` | SQLite archive location |
| `CATCHUP_ENABLED` | `false` | Fetch missed notifications from peer archives on join |
| `SSE_ENABLED` | `false` | Serve notifications as SSE |
| `SSE_BIND_ADDR` | `0.0.0.0:8089` | SSE listen address |
| `SSE_BUFFER_SIZE` | `1000` | SSE replay-buffer size |
| `NODE_FRIENDLY_NAME` | (unset) | Human-readable name shown to monitors |
| `TRACE_FD3` | (off) | Set to `1` to emit debug tracing on file descriptor 3 |

## Releases

Tagging `vX.Y.Z` publishes `podcastindexorg/podping-gossipwatcher:X.Y.Z` and
`:latest` to Docker Hub via GitHub Actions.
