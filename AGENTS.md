# AGENTS.md

## Build

```sh
cargo build --release --locked -p podping-gossipwatcher
```

- `--locked` is **mandatory**: `Cargo.lock` pins pre-release transitive deps (`ed25519-dalek 3.0.0-pre.1` → `ed25519 3.0.0-rc.4`, `pkcs8 0.11.0-rc.11`, `spki 0.8.0-rc.4`). Never re-resolve.
- `-p podping-gossipwatcher` is required because this is a workspace.

## Workspace layout

```
Cargo.toml          # workspace: members = ["podping-gossipwatcher", "dtt"]
podping-gossipwatcher/  # main binary (v0.11.0-alpha.0) — the app
dtt/                    # vendored fork of distributed-topic-tracker 0.2.8
```

`dtt/` is a **vendored fork** with local modifications to peer management. It is not the crates.io version. The path dependency in `podping-gossipwatcher/Cargo.toml` points to `../dtt`. Changes to `dtt/` affect the build without needing a version bump.

## Tests

The main crate (`podping-gossipwatcher/`) has **no tests**. `cargo test --workspace` runs only dtt's tests, which require the `iroh-gossip` feature (enabled by default) and Docker for e2e.

## Platform

**Linux only.** Uses `/proc/self/statm`, `/proc/self/stat`, `/proc/self/status`, `/proc/uptime`, and `libc::fstat`. Will not compile or run on macOS/Windows.

## Dev shell

```sh
nix develop    # or direnv allow (flake.nix provides rust-stable, cargo-watch, rust-analyzer)
```

## Docker build

The `Dockerfile` expects pre-built binaries under `artifacts/`:
- `artifacts/x86_64-unknown-linux-gnu-binary/podping-gossipwatcher`
- `artifacts/aarch64-unknown-linux-gnu-binary/podping-gossipwatcher`
- `artifacts/armv7-unknown-linux-gnueabihf-binary/podping-gossipwatcher`

These are produced by the release CI workflow (GitHub Actions). Local Docker builds need them staged manually.

## Debug tracing

`TRACE_FD3=1` redirects tracing (log spam from iroh internals) to file descriptor 3 instead of stderr:
```sh
RUST_LOG=debug TRACE_FD3=1 cargo run -p podping-gossipwatcher 3>trace.log
```

## Entrypoint

`podping-gossipwatcher/src/main.rs` (~2050 lines) — a single-binary tokio app. No library crate. All logic is in `main.rs`, `archive.rs` (SQLite), and `sse.rs` (axum SSE server).

## Configuration

Config is available via environment variables or equivalent CLI flags — see README table.
No config file.
