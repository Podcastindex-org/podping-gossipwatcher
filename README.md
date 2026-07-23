# podping-gossipwatcher

Receives podcast feed update notifications ("podpings") over
[Iroh](https://iroh.computer/) p2p gossip — no blockchain account or API key
required.

## What it does

`podping-gossipwatcher` joins the `gossipping/v1/all` gossip topic, discovers peers
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
  -e NODE_FRIENDLY_NAME="MySpecialPodcastNode"
  -e IROH_NODE_KEY_FILE=/data/gossip/node.key \
  -e KNOWN_PEERS_FILE=/data/gossip/known_peers.txt \
  -e TRUSTED_PUBLISHERS_FILE=/data/gossip/trusted_publishers.txt \
  -e TRUSTED_MONITORS_FILE=/data/gossip/trusted_monitors.txt \
  -e ARCHIVE_PATH=/data/gossip/listener_archive.db \
  -e SSE_ENABLED=true -p 8089:8089 \
  podcastindexorg/podping-gossipwatcher:latest
```

## Consuming the output

Three ways to feed notifications into another tool:

**SSE endpoint (recommended).** With `SSE_ENABLED=true` and port 8089
published (as in the example above), any process outside the container can
consume a clean, machine-readable stream:

```sh
curl -N http://localhost:8089/events | your-tool
```

Each notification arrives as an `event: podping` carrying the full JSON
payload (including `sig_status` and `sender_name`). The stream supports
server-side filtering via query parameters (`?medium=`, `?reason=`,
`?sender=`), keeps a replay buffer of the last `SSE_BUFFER_SIZE`
notifications, and allows multiple simultaneous consumers — a consumer can
disconnect and reconnect without affecting the watcher.

**Piping stdout (foreground).** Without `-d`, the container's stdout is your
stdout. Notifications print as `PODPING: [{json}]` lines, interleaved with
status output, so filter on the prefix:

```sh
docker run ... podcastindexorg/podping-gossipwatcher:latest \
  | grep --line-buffered '^PODPING:' | your-tool
```

Output is line-buffered, so lines arrive promptly through a pipe.

**`docker logs` (detached).** With `-d`, pipe the log stream instead:

```sh
docker logs -f gossip-watcher | grep --line-buffered '^PODPING:' | your-tool
```

For programmatic use prefer the SSE endpoint — stdout is a human/debug
surface and its non-`PODPING` lines may change between releases.

## Building from source

```sh
cargo build --release --locked -p podping-gossipwatcher
./target/release/podping-gossipwatcher
```

The workspace vendors `dtt/`, a fork of
[distributed-topic-tracker](https://crates.io/crates/distributed-topic-tracker)
0.2.8 (MIT, © Zacharias Boehler) with local modifications to peer management
and memory behavior.

`Cargo.lock` pins pre-release transitive deps that ed25519-dalek 3.0.0-pre.1
requires (`ed25519 3.0.0-rc.4`, `pkcs8 0.11.0-rc.11`, `spki 0.8.0-rc.4`).
Always build `--locked`; do not re-resolve these.

## Configuration

All configuration is via environment variables:

| Variable | Default | Purpose                                                      |
|---|---|--------------------------------------------------------------|
| `BOOTSTRAP_PEER_IDS` | (empty) | Comma-separated iroh node IDs to join directly, skipping DHT |
| `IROH_NODE_KEY_FILE` | `gossip_listener_node.key` | Iroh transport key (created if missing)                      |
| `KNOWN_PEERS_FILE` | `gossip_listener_known_peers.txt` | Learned-peer cache for DHT-less restarts (max 15)            |
| `DHT_INITIAL_SECRET` | `podping_gossip_default_secret` | Shared secret for DHT topic discovery                        |
| `TRUSTED_PUBLISHERS_FILE` | `trusted_publishers.txt` | ed25519 pubkeys whose notifications are accepted             |
| `TRUSTED_MONITORS_FILE` | `trusted_monitors.txt` | Pubkeys allowed to send swarm-management messages            |
| `PEER_ANNOUNCE_INTERVAL` | `300` | Seconds between self-announcements (0 disables)              |
| `PEER_ENDORSE_INTERVAL` | `45` | Seconds between trust endorsements                           |
| `ARCHIVE_ENABLED` | `false` | Archive notifications to SQLite                              |
| `ARCHIVE_PATH` | `listener_archive.db` | SQLite archive location                                      |
| `CATCHUP_ENABLED` | `false` | Fetch missed notifications from peer archives on join        |
| `SSE_ENABLED` | `false` | Serve notifications as SSE                                   |
| `SSE_BIND_ADDR` | `0.0.0.0:8089` | SSE listen address                                           |
| `SSE_BUFFER_SIZE` | `1000` | SSE replay-buffer size                                       |
| `NODE_FRIENDLY_NAME` | (unset) | Human-readable name shown to the rest of the swarm           |
| `TRACE_FD3` | (off) | Set to `1` to emit debug tracing on file descriptor 3        |

## Releases

Tagging `vX.Y.Z` publishes `podcastindexorg/podping-gossipwatcher:X.Y.Z` and
`:latest` to Docker Hub via GitHub Actions.