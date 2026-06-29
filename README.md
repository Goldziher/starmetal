<!-- markdownlint-disable MD013 MD033 MD041 -->
<div align="center">

<img src="docs/media/starmetal-banner.svg" alt="StarMetal - armored registry proxy" width="820">

**High-performance, self-hosted multi-language package registry and pull-through registry proxy for private software supply chains.**

Starmetal gives teams one controlled path for package-manager traffic across ecosystems. It speaks
native registry protocols, proxies upstream reads, stores artifacts behind a common service layer,
verifies cached bytes with Blake3, and applies policy before dependencies reach clients.

StarMetal is experimental. All currently implemented registry read/proxy workflows are experimental
core capabilities; native publishing is not supported yet, and local publishing remains experimental
and disabled by default.

PyPI · npm · Cargo · Hex · Maven · RubyGems · NuGet · pub.dev

[![CI](https://img.shields.io/github/actions/workflow/status/Goldziher/starmetal/ci.yaml?style=flat-square)](https://github.com/Goldziher/starmetal/actions/workflows/ci.yaml)
[![Rust 2024](https://img.shields.io/badge/rust-2024-orange?style=flat-square)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

[Install](#install) · [Quick Start](#quick-start) · [Registry Support](#registry-support) · [Docker](#docker) · [Configuration](docs/configuration.md) · [Deployment](#deployment) · [Release](docs/release.md) · [Architecture](#architecture) · [ADRs](#adrs)

</div>

---

## Why It Exists

Modern teams pull dependencies from several registries, each with different protocols, metadata
formats, auth expectations, and client behavior. Starmetal puts those workflows behind one self-hosted
service boundary so operators can centralize caching, integrity checks, policy, storage, and
observability without asking developers to stop using native package-manager clients.

## What It Does

Starmetal sits between package-manager clients and upstream registries:

| Capability | Current shape |
|---|---|
| Registry proxy | Speaks native package-manager routes and rewrites upstream metadata for Starmetal URLs |
| Pull-through cache | Fetches from upstream on miss, stores artifacts, and serves cache hits |
| Integrity | Stores Blake3 sidecars and re-verifies cached artifacts before serving |
| Policy | Blocks packages, licenses, and vulnerability severities through shared service checks |
| Protocol adapters | Feature-gated routers for PyPI, npm, Cargo, Hex, Maven, RubyGems, NuGet, and pub.dev |
| Storage | OpenDAL-backed filesystem, S3, GCS, and memory backends |
| Operations | CLI plus stdio MCP tools over the same local operations layer |

Starmetal is built for private/internal deployments first. It is not yet a public internet-facing
registry product, and every registry workflow should be treated as experimental until fresh live
native-client E2E passes for that ecosystem.

## Registry Support

| Registry | Route | Default | Status |
|---|---:|---:|---|
| PyPI | `/pypi` | Enabled | Experimental core read/proxy adapter |
| npm | `/npm` | Enabled | Experimental core read/proxy adapter |
| Cargo | `/cargo` | Enabled | Experimental core read/proxy adapter |
| Hex | `/hex` | Enabled | Experimental core read/proxy adapter |
| Maven | `/maven` | Enabled | Experimental core read/proxy adapter |
| RubyGems | `/rubygems` | Enabled | Experimental core read/proxy adapter |
| NuGet | `/nuget` | Enabled | Experimental core read/proxy adapter |
| pub.dev | `/pub` | Enabled | Experimental core read/proxy adapter |

Planned registry work includes OCI/distribution, Go modules, Composer, Conda, Debian/APT, and RPM/YUM.
See [ADR-0011](docs/adr/0011-mvp-support-matrix.md) for experimental support criteria and promotion gates.

## Install

Docker is the primary deployment path. Release builds also publish verified `sm` installers for npm
and PyPI, Homebrew bottles through `Goldziher/homebrew-tap`, and GitHub release archives for direct
download.

```bash
docker run --rm -p 8080:8080 -v starmetal-data:/var/lib/starmetal ghcr.io/goldziher/starmetal:latest
brew install Goldziher/tap/starmetal
npm install -g starmetal
pipx install starmetal
```

The npm package requires Node 22+. The PyPI package requires Python 3.10+. Both download the
matching prebuilt binary from GitHub Releases and verify it against the release checksums file. The
crates.io `starmetal` package currently holds the public namespace while the Rust crate publishing
layout is finalized.

## Quick Start

Requirements:

- Rust edition 2024, Rust 1.85+
- [Task](https://taskfile.dev/) for the documented workflow commands
- [sccache](https://github.com/mozilla/sccache), optional but used automatically by Taskfile cargo commands

```bash
# First-time setup: hooks, sccache check, generated AI config
task setup

# Build and run tests
task ci

# Install the local sm binary from this checkout
cargo install --path crates/starmetal-cli --bin sm

# Start Starmetal with defaults on 127.0.0.1:8080
sm serve

# Write a starter config
sm config init

# Inspect registries without a config file
sm --no-config --storage-backend memory registry status

# Fetch one artifact through the cache path
sm package fetch pypi six 1.16.0 six-1.16.0.tar.gz
```

Run live native-client E2E before treating an experimental read workflow as ready:

```bash
task test:e2e:pypi
task test:e2e:npm
task test:e2e:cargo
task test:e2e:hex
```

`task ci:live-e2e` runs the same live gate plus live schema freshness checks.

## Docker

Docker is the primary deployment path for private experimental installs. The image uses Chainguard
builder and runtime bases, runs as non-root, and uses one image for both API and CLI operations. Its
entrypoint is `sm`; its default command is `serve`, so no args starts the API server, and args after
the image name run normal CLI or MCP commands.

Published images use GitHub Container Registry: `ghcr.io/goldziher/starmetal`.

```bash
docker build -t starmetal:local .
docker run --rm -p 8080:8080 -v starmetal-data:/var/lib/starmetal starmetal:local
docker run --rm starmetal:local config validate
docker run --rm starmetal:local mcp serve
```

Run the deterministic local proxy gate:

```bash
task docker:proxy:e2e
```

That gate builds the image, runs a local fixture upstream plus StarMetal on an isolated Docker
network, exercises every implemented registry route with HTTP assertions, runs native client
containers for PyPI, npm, Cargo, Maven, RubyGems, NuGet, and pub.dev, restarts StarMetal with the
same OpenDAL filesystem volume, and repeats the checks with the fixture upstream stopped. It also
runs pnpm read-through install, cached reinstall with a fresh pnpm store, and experimental local npm
publish-then-install. The native client pass disables read auth because package-manager support for
Bearer read auth is uneven; the HTTP pass covers auth behavior.

Use a mounted config file for production settings, auth tokens, `public_base_url`, and S3/GCS
OpenDAL options:

```bash
docker run --rm \
  -p 8080:8080 \
  -v ./starmetal.toml:/etc/starmetal/starmetal.toml:ro \
  -v starmetal-data:/var/lib/starmetal \
  starmetal:local
```

The default container config is [docker/starmetal.toml](docker/starmetal.toml).

## Configuration

Starmetal defaults to loopback binding and filesystem storage. A minimal private deployment usually
starts from:

```toml
[server]
bind = "127.0.0.1:8080"
public_base_url = "https://starmetal.internal.example.com"
cors_allowed_origins = []
max_upload_bytes = 536870912

[storage]
backend = "fs"
path = "/var/lib/starmetal"

[auth]
enabled = true
tokens = ["replace-with-a-secret-token"]
```

Upstream URLs must be HTTPS and public by default. Local, private-network, or insecure upstreams
require explicit `allow_private_network` and `allow_insecure` settings. See
[docs/configuration.md](docs/configuration.md) for every option and validation rule, and
[docs/deployment.md](docs/deployment.md) for private deployment guidance.

## CLI and MCP

The CLI command is `sm`. Config lookup still supports `STARMETAL_CONFIG` and `starmetal.toml` for
compatibility; the CLI and MCP server can run without a config file using built-in defaults plus
explicit flags.

Common CLI operations:

```bash
sm config show
sm config validate
sm registry status
sm package list pypi
sm package versions npm is-odd
sm package metadata cargo once_cell 1.19.0
sm package fetch npm is-odd 3.0.1 is-odd-3.0.1.tgz --output ./is-odd.tgz
sm cache delete-artifact npm is-odd 3.0.1 is-odd-3.0.1.tgz --yes
```

Use `--output json` for machine-readable output. MCP runs over stdio:

```bash
sm mcp serve
sm mcp serve --allow-writes
```

MCP read tools are always available. Mutating tools, including experimental local publish, yank,
unyank, and cache delete, require `--allow-writes`.

## Architecture

Starmetal uses hexagonal architecture: protocol adapters and storage backends sit outside a shared
service/core boundary.

| Crate | Role |
|---|---|
| `starmetal-core` | Domain types, config, policy, ports, lock file, registry schema types |
| `starmetal-service` | Pull-through cache, Blake3 verification, policy checks, experimental local publishing |
| `starmetal-storage` | OpenDAL-backed `StoragePort` implementation |
| `starmetal-adapters` | Feature-gated protocol routers and upstream clients |
| `starmetal-server` | Axum app assembly and Tower middleware |
| `starmetal-ops` | Shared local operator API used by CLI and MCP |
| `starmetal-cli` | Clap CLI and stdio MCP server |

See [docs/architecture.md](docs/architecture.md) for diagrams and component details.

## Development Gates

Normal PR-safe gate:

```bash
task fmt:check
task clippy
task test:all
task schema:check
task schema:validate
task conformance
task docker:proxy:e2e
task security
task ci
```

`task docker:proxy:e2e` uses disposable client containers, not host package-manager CLIs. Live E2E
and live Docker pressure tests are intentionally separate from normal PR CI because they require
public registry access.

## Schemas

Schema provenance, fetched upstream artifacts, Starmetal-derived JSON Schemas, and grammar fixtures live
under [`schemas/`](schemas/):

- [`schemas/registries/`](schemas/registries/) - derived registry schemas where the protocol is JSON-like
- [`schemas/starmetal/`](schemas/starmetal/) - config and lockfile schemas
- [`schemas/README.md`](schemas/README.md) - source links and registry-by-registry derivation notes

## ADRs

- [0001 - Hexagonal Architecture](docs/adr/0001-hexagonal-architecture.md)
- [0002 - Tower Middleware](docs/adr/0002-tower-middleware.md)
- [0003 - OpenDAL Storage](docs/adr/0003-opendal-storage.md)
- [0004 - Blake3 and Lock File](docs/adr/0004-blake3-lockfile.md)
- [0005 - Protocol Adapters](docs/adr/0005-protocol-adapters.md)
- [0006 - Feature Flags](docs/adr/0006-feature-flags.md)
- [0007 - JSON Schema Validation](docs/adr/0007-json-schema-validation.md)
- [0008 - Registry Expansion, superseded](docs/adr/0008-registry-expansion.md)
- [0009 - Publishing and Upload Workflows](docs/adr/0009-publishing-upload-workflows.md)
- [0010 - CLI and MCP Operations](docs/adr/0010-cli-mcp-operations.md)
- [0011 - Experimental Support Matrix](docs/adr/0011-mvp-support-matrix.md)
- [0012 - CI Quality Gates](docs/adr/0012-ci-quality-gates.md)
- [0013 - Basemind and AI-Rulez Alignment](docs/adr/0013-basemind-ai-rulez-alignment.md)
- [0014 - Management Admin Surface](docs/adr/0014-management-admin-surface.md)
- [0015 - Statistics and Operational Metrics](docs/adr/0015-statistics-operational-metrics.md)

## License

[MIT](LICENSE)
