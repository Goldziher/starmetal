# ADR-0003: OpenDAL as Storage Abstraction

## Status

Accepted

## Context

Depot must store package artifacts on user-chosen backends: local filesystem for small deployments, S3-compatible storage for production, GCS for Google Cloud users. Writing and maintaining separate implementations for each backend is costly and error-prone.

## Decision

We use [Apache OpenDAL](https://opendal.apache.org/) as the storage abstraction layer. OpenDAL provides a unified `Operator` API across 30+ storage services. Our `StoragePort` trait wraps an OpenDAL `Operator`, translating between depot's domain types and OpenDAL's API.

Storage backends are configured dynamically with an OpenDAL service name and
string options:

```toml
[storage]
backend = "fs"

[storage.options]
root = "./depot-data"
```

Available services are still controlled by feature flags:

- `backend-fs` (default) — local filesystem
- `backend-s3` — S3-compatible (AWS, MinIO, R2)
- `backend-gcs` — Google Cloud Storage
- `backend-memory` — in-memory (for testing)

Publishing support reserves Depot-owned internal key prefixes for mutable registry state:

- `_depot/published/` — locally published package metadata and per-version manifests
- `_depot/indexes/` — generated native registry indexes and compact metadata
- `_depot/forwarding/` — upstream forwarding attempts and final status

Artifact bytes continue to use ecosystem storage keys so read paths can serve pull-through and
locally published artifacts through the same service boundary. Internal prefixes must not be exposed
as registry package names.

OpenDAL does not provide a database transaction model across all services. Publishing workflows must
therefore be designed around idempotent writes, deterministic regenerated indexes, and recoverable
status records instead of assuming atomic multi-object transactions.

## Consequences

- Adding a new storage backend is typically a feature flag and documentation addition — OpenDAL already supports the runtime option map.
- We depend on a large external crate, but it's well-maintained (Apache project) and the feature-flag gating keeps binary size manageable.
- The `StoragePort` trait keeps our core decoupled from OpenDAL, so swapping it out (unlikely) would only affect `depot-storage`.
- Publishing does not introduce a database as a required dependency. If stronger transactional
  guarantees are needed later, they require a separate ADR.
