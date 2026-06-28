# ADR-0006: Feature Flags for Compile-Time Configuration

## Status

Accepted

## Context

Starmetal compiles optional protocol adapters and storage backends. Private MVP defaults should keep the
core four read adapters available while letting operators opt into beta adapters.

Feature availability is not the same as a support claim.

## Decision

Cargo feature flags gate adapters and storage backends.

Implemented `depot-adapters` features:

| Feature | Default in `depot-adapters` | MVP position |
|---------|-----------------------------|--------------|
| `pypi` | Yes | Read candidate after live E2E |
| `npm` | Yes | Read candidate after live E2E |
| `cargo-registry` | Yes | Read candidate after live E2E |
| `hex` | Yes | Read candidate after live E2E |
| `maven` | No | Opt-in beta |
| `rubygems` | No | Opt-in beta |
| `nuget` | No | Opt-in beta |
| `pub` | No | Opt-in beta |

Implemented `depot-storage` features:

| Feature | Purpose |
|---------|---------|
| `backend-fs` | Default filesystem storage |
| `backend-s3` | S3-compatible object storage |
| `backend-gcs` | Google Cloud Storage |
| `backend-memory` | Tests and local workflows |

`depot-cli` defaults to `full`, which compiles all adapters plus filesystem storage. Runtime config
still disables Maven, RubyGems, NuGet, and pub.dev upstreams by default.

Example minimal build:

```sh
cargo build -p depot-cli --no-default-features --features pypi,backend-s3
```

## Implemented

- Adapter module gates in `depot-adapters`.
- Server route gates in `depot-server`.
- Runtime construction gates in `depot-ops`.
- Pass-through CLI features.
- Additive storage backend features.

## Deferred

- Treating compiled beta adapters as MVP-supported by default.
- At-rest encryption, despite config and schema fields.
- Matrix CI for every feature combination.

## Consequences

- Build-time inclusion and runtime enablement must both be documented.
- Operators can compile a smaller private binary.
- CI must cover default, full, and representative minimal feature sets before public support claims.
