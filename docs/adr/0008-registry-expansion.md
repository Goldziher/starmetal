# ADR-0008: Registry Expansion Order and Compatibility Bar

## Status

Accepted

## Context

Depot is expanding beyond PyPI, npm, Cargo, and Hex. Candidate ecosystems differ significantly:
some publish JSON APIs, some use text indexes, some use XML schemas, and some are mostly static file
repositories. A protocol should not be called supported just because its schemas or source documents
are recorded.

## Decision

A registry is first-class supported only when it has:

1. Official source linkage in `schemas/sources.toml`
2. Fetched upstream artifacts where machine-readable artifacts exist
3. Depot-derived schemas or grammar fixtures where upstream has no JSON Schema
4. A feature-gated adapter and upstream client
5. Offline conformance tests for protocol shape and route behavior
6. Integrity behavior through `PackageService`
7. Native-client E2E coverage for the supported read workflows

The next expansion order is:

1. Maven/Sonatype artifact serving
2. RubyGems/Bundler Compact Index
3. NuGet V3 restore
4. pub.dev Hosted Pub repositories

Go module support is tracked separately as a GOPROXY/module-proxy protocol, not as a conventional
package registry. It remains a valid future adapter but does not change the RubyGems/NuGet priority.

Publishing support is scoped by ADR-0009. A registry can be first-class pull-through supported
without write support, but it cannot be documented as publishing-compatible until it also has:

1. Official source linkage for upload and mutation protocol behavior
2. Native upload/yank/unlist route implementation where the ecosystem requires it
3. Route-level publish conformance tests
4. Native-client publish then install/restore/fetch E2E tests
5. Documented duplicate, shadowing, auth, forwarding, and failure semantics

Search APIs and administrative APIs remain out of MVP unless a later ADR explicitly scopes them in.

## Consequences

- RubyGems Compact Index is modeled as a text protocol with grammar fixtures, not JSON Schema.
- NuGet V3 and pub.dev schemas are Depot-derived validation artifacts because upstream does not
  publish registry JSON Schema or OpenAPI documents.
- Maven uses XSDs as authoritative machine-readable source artifacts.
- New registry work must include docs, schemas/provenance, feature flags, adapter behavior, and tests
  before public support is claimed.
