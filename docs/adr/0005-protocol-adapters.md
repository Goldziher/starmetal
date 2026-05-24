# ADR-0005: Protocol Adapters as Axum Routers

## Status

Accepted

## Context

Depot must serve packages using each ecosystem's native protocol so that existing tools (pip, npm,
cargo, mix, mvn, bundle, dotnet, and dart pub) work without modification. Each protocol has
different URL schemes, response formats, authentication conventions, upload formats, and mutation
semantics.

## Decision

Each protocol adapter is implemented as an axum `Router` that:

1. Handles incoming requests in the native protocol format
2. Translates them into `PackageService` trait calls
3. Translates native upload and mutation requests into publishing service calls when publishing is
   supported for that ecosystem
4. Formats the response back into the native protocol format

Adapters are mounted under path prefixes:

| Prefix | Protocol | Spec |
|--------|----------|------|
| `/pypi` | PEP 503 Simple Repository API | HTML index pages + file downloads |
| `/npm` | npm registry API | JSON metadata + tarball downloads |
| `/cargo` | Cargo sparse index | JSON config + version metadata |
| `/hex` | Hex.pm API | JSON/protobuf metadata + tarball downloads |
| `/maven` | Maven repository layout | XML metadata + artifact files |
| `/rubygems` | RubyGems Compact Index/API | Text index + gem downloads |
| `/nuget` | NuGet V3 | Service index + flat container + registration |
| `/pub` | Hosted Pub Repository | JSON metadata + archive downloads |

Each adapter also provides an `UpstreamClient` implementation for fetching from the corresponding public registry.

## Implementation Notes

### Adapter State Traits

Each adapter defines its own state trait for accessing both `PackageService` and the ecosystem-specific upstream client:

- `HasPypiState` — `package_service` + `pypi_upstream`
- `HasNpmState` — `package_service` + `npm_upstream`
- `HasCargoState` — `package_service` + `cargo_upstream`
- `HasHexState` — `package_service` + `hex_upstream`

This lets handlers serve cached upstream data directly (preserving all protocol-specific fields) while still going through `PackageService` for the caching lifecycle.

### Serving Cached Upstream Data

Adapters call `list_versions` to trigger the caching lifecycle, then serve the upstream client's cached response with URL rewriting rather than reconstructing responses from `VersionMetadata`. This preserves protocol-specific data (npm dependencies, PyPI requires-python, Cargo deps/features) that would be lost in conversion to domain types.

### npm Raw JSON

The npm adapter stores and serves `serde_json::Value` instead of a typed `NpmPackument` struct. This handles the wide variety of npm field shapes without deserialization failures. When a packument is served, all transitive dependencies are pre-fetched using BFS with a visited set and max depth of 10 levels.

### Hex Protobuf Registry Proxy

The Hex adapter includes a protobuf registry proxy at `/hex/packages/{name}` that proxies the protobuf registry entry from `repo.hex.pm`. This is required for mix checksum verification.

### Registry Schema Provenance

Each adapter owns the registry contract documentation for its ecosystem. Official sources may be
published as JSON Schema, prose specifications, protobuf definitions, XML Schema, OpenAPI documents,
or a mix of formats. Adapter documentation must link to the authoritative source used to model each
schema and explain any Depot interpretation when the upstream contract is incomplete or split across
multiple documents.

Schema changes for an adapter require conformance tests using representative official responses,
fixtures, or wire-format samples. Tests must prove that Depot's JSON Schema and adapter behavior
continue to match the linked source.

### Cache TTL

All upstream client caches use 5-minute TTL via `(Instant, T)` tuples. Cached data is served directly until the TTL expires, then re-fetched from upstream.

### Publishing Responsibilities

Write support is adapter-specific at the protocol edge and shared below that edge:

- Adapters parse native upload, yank, unyank, unlist, relist, and revert requests.
- Adapters translate successful native parsing into publish-domain requests.
- `PublishingService` performs shared validation, integrity computation, duplicate and shadowing
  checks, policy checks, storage writes, metadata/index updates, and optional upstream forwarding.
- Adapters format ecosystem-native success and failure responses, including client-visible warning
  payloads where the protocol supports them.

Adapters must not write artifacts, indexes, or forwarding status directly to storage.

Publishing support for a registry cannot be documented as supported until it has official source
linkage, route-level conformance tests, native-client publish/install E2E tests, and documented
failure semantics.

## Consequences

- Each adapter is self-contained: protocol-specific types, handlers, and upstream client in one module.
- Adding a new protocol requires no changes to existing code — only a new module and router registration.
- Feature flags gate each adapter, so unused protocols are not compiled.
- Adapters share no protocol-specific logic with each other; all shared behavior goes through `PackageService`.
- Adapter-owned schemas remain traceable to official registry sources and covered by conformance
  tests.
- Read compatibility and write compatibility are separate claims. Pull-through support does not imply
  publishing support.
- Supported read adapters pass client-level integration tests. Supported publishing adapters must
  additionally pass native publish then install/restore/fetch tests.
