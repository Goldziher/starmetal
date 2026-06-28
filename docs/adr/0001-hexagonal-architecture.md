# ADR-0001: Hexagonal Architecture

## Status

Accepted

## Context

Starmetal is a private/internal MVP for a package registry cache. It must isolate package protocol
details, storage backends, policy checks, integrity verification, and operator workflows so each can
move independently.

The MVP support claim is intentionally narrow. PyPI, npm, Cargo, and Hex are read candidates after
fresh live native-client E2E verification. Maven, RubyGems, NuGet, and pub.dev are opt-in beta read
adapters. Native publishing is outside MVP.

## Decision

Starmetal uses hexagonal architecture.

Implemented ports in `depot-core`:

| Port | Direction | Purpose |
|------|-----------|---------|
| `PackageService` | Inbound | Read package versions, metadata, artifacts, and raw upstream cache data |
| `PublishingService` | Inbound | Experimental local publish and yank operations |
| `StoragePort` | Outbound | Store and retrieve opaque bytes by key |
| `UpstreamClient` | Outbound | Fetch versions, metadata, and artifacts from upstream registries |

Implemented crate boundaries:

| Crate | Boundary |
|-------|----------|
| `depot-core` | Domain types, config, policy, ports, lock file, registry schema types |
| `depot-service` | `CachingPackageService` and experimental local publishing workflow |
| `depot-storage` | OpenDAL-backed `StoragePort` implementations |
| `depot-adapters` | Axum protocol adapters and upstream clients |
| `depot-server` | Axum app assembly and Tower middleware |
| `depot-ops` | Shared local operations for CLI and MCP |
| `depot-cli` | Clap CLI and stdio MCP entry points |

`depot-core` remains framework-free. It must not depend on axum, tower, opendal, reqwest, or other
I/O framework crates.

## Implemented

- Pull-through reads go through `PackageService`.
- Adapters can access ecosystem upstream clients directly to preserve native response shapes.
- Storage access is hidden behind `StoragePort`.
- Local operator commands and MCP tools share `depot-ops`.
- Experimental local publishing goes through `PublishingService`, not direct adapter storage writes.

## Deferred

- Public support claims for any registry before live native-client E2E evidence.
- Native publishing support claims.
- Upstream publish forwarding.
- Remote administration over HTTP.
- Database-backed transaction semantics.
- At-rest encryption.

## Consequences

- Core behavior is testable without network or storage services.
- Protocol adapters can evolve without changing storage backends.
- Experimental write behavior stays isolated from MVP read-support claims.
- New framework dependencies in `depot-core` require a new ADR.
