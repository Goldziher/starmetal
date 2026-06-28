# ADR-0001: Hexagonal Architecture

## Status

Accepted

## Context

Starmetal is a private/internal experimental package registry cache. It must isolate package protocol
details, storage backends, policy checks, integrity verification, and operator workflows so each can
move independently.

All implemented read/proxy adapters are experimental core capabilities. Native publishing is not
supported; local publishing is experimental and disabled by default.

## Decision

Starmetal uses hexagonal architecture.

Implemented ports in `starmetal-core`:

| Port | Direction | Purpose |
|------|-----------|---------|
| `PackageService` | Inbound | Read package versions, metadata, artifacts, and raw upstream cache data |
| `PublishingService` | Inbound | Experimental local publish and yank operations |
| `StoragePort` | Outbound | Store and retrieve opaque bytes by key |
| `UpstreamClient` | Outbound | Fetch versions, metadata, and artifacts from upstream registries |

Implemented crate boundaries:

| Crate | Boundary |
|-------|----------|
| `starmetal-core` | Domain types, config, policy, ports, lock file, registry schema types |
| `starmetal-service` | `CachingPackageService` and experimental local publishing workflow |
| `starmetal-storage` | OpenDAL-backed `StoragePort` implementations |
| `starmetal-adapters` | Axum protocol adapters and upstream clients |
| `starmetal-server` | Axum app assembly and Tower middleware |
| `starmetal-ops` | Shared local operations for CLI and MCP |
| `starmetal-cli` | Clap CLI and stdio MCP entry points |

`starmetal-core` remains framework-free. It must not depend on axum, tower, opendal, reqwest, or other
I/O framework crates.

## Implemented

- Pull-through reads go through `PackageService`.
- Adapters can access ecosystem upstream clients directly to preserve native response shapes.
- Storage access is hidden behind `StoragePort`.
- Local operator commands and MCP tools share `starmetal-ops`.
- Experimental local publishing goes through `PublishingService`, not direct adapter storage writes.

## Deferred

- Public support claims beyond experimental before live native-client E2E evidence.
- Native publishing support claims.
- Upstream publish forwarding.
- Remote administration over HTTP.
- Database-backed transaction semantics.
- At-rest encryption.

## Consequences

- Core behavior is testable without network or storage services.
- Protocol adapters can evolve without changing storage backends.
- Experimental write behavior stays isolated from read/proxy support claims.
- New framework dependencies in `starmetal-core` require a new ADR.
