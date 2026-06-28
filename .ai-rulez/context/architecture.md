---
priority: critical
---

# Architecture

Starmetal is a self-hosted, armored universal package registry built with hexagonal architecture.

## Crate Structure

All code lives under `crates/` — there is no top-level `src/`.

| Crate | Role |
|-------|------|
| `starmetal-core` | Domain types, port traits (`PackageService`, `StoragePort`, `UpstreamClient`), policy engine, lock file, config |
| `starmetal-service` | Application service layer. `CachingPackageService` implements pull-through caching, blake3 integrity verification (sidecar `.blake3` files), and policy enforcement. Sits between adapters and core. |
| `starmetal-storage` | OpenDAL-backed `StoragePort` implementation. Feature-gated backends: `backend-fs`, `backend-s3`, `backend-gcs`, `backend-memory` |
| `starmetal-adapters` | Inbound protocol adapters (axum routers) + outbound upstream clients. Feature-gated: `pypi`, `npm`, `cargo-registry`, `hex`. Each adapter defines a state trait (`HasPypiState`, `HasNpmState`, `HasCargoState`, `HasHexState`) for accessing `PackageService` + ecosystem-specific upstream client. |
| `starmetal-server` | Axum app assembly, Tower middleware stack (tracing, CORS, auth, compression), shared `AppState` |
| `starmetal-cli` | Binary crate. Clap CLI with commands: `serve`, `sync`, `lock`, `config` |
| `tests/integration` | Integration test crate with 31 tests covering pip, npm, cargo, and mix client workflows |

## Dependency Flow

`starmetal-cli → starmetal-server → starmetal-adapters → starmetal-core`
`→ starmetal-service  → starmetal-core`
`→ starmetal-storage  → starmetal-core`

The core crate has zero framework dependencies — all I/O goes through port traits.

## Key Design Decisions

- Protocol adapters call `list_versions` to trigger caching, then serve the upstream client's cached response directly with URL rewriting (preserving all protocol-specific fields like npm dependencies, PyPI requires-python, Cargo deps/features)
- Pull-through cache in `CachingPackageService`: fetch from upstream on miss, verify with blake3, apply policy, store via OpenDAL, serve
- Blake3 hashes are stored as `.blake3` sidecar files alongside artifacts and verified on every cache read
- Upstream hashes are preserved in `ArtifactDigest.upstream_hashes`
- All upstream client caches use 5-minute TTL via `(Instant, T)` tuples
- npm adapter stores/serves raw `serde_json::Value` to handle the wide variety of npm field shapes
- npm adapter performs recursive BFS dependency prefetch (max depth 10) when serving a packument
- Hex adapter includes a protobuf registry proxy at `/hex/packages/{name}` for mix checksum verification
- Storage keys: `<ecosystem>/<name>/<version>/<filename>`
- Lock file: TOML-based, ecosystem-agnostic, blake3 hashes
- Feature flags control compile-time inclusion of adapters and storage backends
- TOML config with clap CLI

## ADRs

Architecture Decision Records are in `docs/adr/`. Read them before making architectural changes.
