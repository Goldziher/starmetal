# Depot

Self-hosted, armored universal package registry.

Depot speaks native registry protocols and acts as a pull-through cache between package manager clients and upstream registries. Artifacts are stored with blake3 integrity verification and policy enforcement. At-rest encryption, rate limiting, full sync, and lockfile update workflows are deferred production-hardening work.

## Registry Support

| Protocol | Spec | Status |
|----------|------|--------|
| PyPI | PEP 503/691 Simple Repository API | Working (`pip install` verified) |
| npm | Registry API | Working (`npm install` verified) |
| Cargo | Sparse Index (RFC 2789) | Working (`cargo fetch` verified) |
| Hex | Repository API | Working (`mix hex.package fetch` verified) |
| Maven | Maven Central-compatible artifact layout | MVP pull-through adapter |
| RubyGems | Bundler Compact Index | MVP pull-through adapter |
| NuGet | V3 restore API | MVP pull-through adapter |
| pub.dev | Hosted Pub Repository v2 | MVP pull-through adapter |

## Requirements

- Rust (edition 2024 — requires Rust 1.85+)
- [Task](https://taskfile.dev/) (optional, for dev workflow commands)

## Getting Started

```bash
# First-time setup (installs hooks, generates AI config)
task setup

# Build
cargo build --workspace

# Run the server
cargo run -p depot-cli -- serve

# Run unit tests
cargo test --workspace

# Run integration tests (requires a running server)
cargo test -p integration-tests

# Lint
cargo clippy --workspace
```

## Architecture

Depot uses a hexagonal architecture with Tower middleware. The crate structure is:

| Crate | Role |
|-------|------|
| `depot-core` | Domain types, port traits, policy engine, lock file, config |
| `depot-service` | Application service layer (`CachingPackageService`): pull-through caching, blake3 integrity, policy enforcement |
| `depot-storage` | OpenDAL-backed `StoragePort` (feature-gated: fs, S3, GCS, memory) |
| `depot-adapters` | Protocol adapters (axum routers) + upstream clients (feature-gated per ecosystem) |
| `depot-server` | Axum app assembly, Tower middleware, shared `AppState` |
| `depot-cli` | Binary crate, Clap CLI |

See the [Architecture Overview](docs/architecture.md) for Mermaid diagrams and detailed component descriptions.

### ADRs

- [0001 — Hexagonal Architecture](docs/adr/0001-hexagonal-architecture.md)
- [0002 — Tower Middleware](docs/adr/0002-tower-middleware.md)
- [0003 — OpenDAL Storage](docs/adr/0003-opendal-storage.md)
- [0004 — Blake3 & Lock File](docs/adr/0004-blake3-lockfile.md)
- [0005 — Protocol Adapters](docs/adr/0005-protocol-adapters.md)
- [0006 — Feature Flags](docs/adr/0006-feature-flags.md)
- [0007 — JSON Schema Validation](docs/adr/0007-json-schema-validation.md)

### Schemas

Canonical JSON Schemas for all registry protocols and depot's own formats are in [`schemas/`](schemas/):

- [`schemas/registries/`](schemas/registries/) — derived registry schemas where the protocol is JSON-like
- [`schemas/depot/`](schemas/depot/) — config and lockfile schemas

## License

[BUSL-1.1](LICENSE)
