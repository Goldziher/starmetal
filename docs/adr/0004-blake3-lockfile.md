# ADR-0004: Blake3 Integrity and Depot Lock File Format

## Status

Accepted

## Context

Package ecosystems use different integrity algorithms. Depot needs one internal cache integrity
mechanism while preserving upstream hashes where registries provide them.

Depot also has a TOML lock file format, but lock verification and update CLI workflows are not part
of the private MVP.

## Decision

Depot uses Blake3 as its canonical stored-artifact integrity hash.

Implemented cache behavior in `CachingPackageService`:

- On artifact fetch, Depot verifies supported upstream hashes when present.
- Depot computes a Blake3 hash for stored artifact bytes.
- Depot stores the hash as a `.blake3` sidecar next to the artifact.
- On cache read, Depot verifies the sidecar before serving bytes.
- Cached artifacts without a sidecar fail closed.

Supported upstream hash evidence:

| Source form | Used for |
|-------------|----------|
| `sha256` | PyPI, Cargo, Hex, RubyGems, pub.dev, some Maven artifacts |
| npm SRI `integrity` | npm tarballs |
| `sha1` | Maven checksum sidecars |
| `sha512` | NuGet package hashes |

Depot lock files are TOML and ecosystem-agnostic:

```toml
[metadata]
schema_version = 1
generated_at = "2026-06-28T00:00:00Z"
depot_version = "0.1.0"

[[packages]]
ecosystem = "pypi"
name = "requests"
version = "2.31.0"
artifacts = [
  { filename = "requests-2.31.0.tar.gz", blake3 = "d1e2f3...", size = 110293 },
]
resolved_from = "https://pypi.org"
pinned = true
```

## Implemented

- Blake3 cache sidecars.
- Upstream hash preservation in `ArtifactDigest.upstream_hashes`.
- Lock file domain types and generated JSON Schema.

## Deferred

- `depot lock verify`.
- `depot lock update`.
- Full sync workflows based on lock files.
- Replacing ecosystem-native lock files.

## Consequences

- Stored artifacts have one uniform internal integrity check.
- Upstream integrity remains available for provenance and ecosystem-specific responses.
- Lock files describe Depot registry state, not application dependency resolution.
