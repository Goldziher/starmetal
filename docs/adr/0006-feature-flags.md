# ADR-0006: Feature Flags for Compile-Time Configuration

## Status

Accepted

## Context

Starmetal compiles optional protocol adapters and storage backends. The default CLI build should keep
all implemented registry adapters available while still allowing smaller operator builds.

Feature availability is not the same as a support claim.

## Decision

Cargo feature flags gate adapters and storage backends.

Implemented `depot-adapters` features:

| Feature | Default in `depot-adapters` | Status |
|---------|-----------------------------|--------------|
| `pypi` | Yes | Experimental core |
| `npm` | Yes | Experimental core |
| `cargo-registry` | Yes | Experimental core |
| `hex` | Yes | Experimental core |
| `maven` | No | Experimental core in full CLI builds |
| `rubygems` | No | Experimental core in full CLI builds |
| `nuget` | No | Experimental core in full CLI builds |
| `pub` | No | Experimental core in full CLI builds |

Implemented `depot-storage` features:

| Feature | Purpose |
|---------|---------|
| `backend-fs` | Default filesystem storage |
| `backend-s3` | S3-compatible object storage |
| `backend-gcs` | Google Cloud Storage |
| `backend-memory` | Tests and local workflows |

`depot-cli` defaults to `full`, which compiles all adapters plus filesystem storage. Runtime config
enables all implemented upstreams by default.

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

- Production support claims without live E2E evidence.
- At-rest encryption, despite config and schema fields.
- Matrix CI for every feature combination.

## Consequences

- Build-time inclusion and runtime enablement must both be documented.
- Operators can compile a smaller private binary.
- CI must cover default, full, and representative minimal feature sets before public support claims.
