# ADR-0003: OpenDAL as Storage Abstraction

## Status

Accepted

## Context

Depot needs filesystem storage for private MVP deployments and object-store options for later
production hardening. The service layer should not know which backend stores artifacts.

## Decision

Depot uses Apache OpenDAL behind `StoragePort`.

Implemented storage backends:

| Feature | Backend | Status |
|---------|---------|--------|
| `backend-fs` | Local filesystem | Default |
| `backend-s3` | S3-compatible storage | Available |
| `backend-gcs` | Google Cloud Storage | Available |
| `backend-memory` | In-memory storage | Tests and local workflows |

Storage is configured with a backend name plus OpenDAL options:

```toml
[storage]
backend = "fs"

[storage.options]
root = "./depot-data"
```

Artifact keys use:

```text
<ecosystem>/<name>/<version>/<filename>
```

The service also stores implementation metadata under ordinary storage keys:

| Key pattern | Purpose |
|-------------|---------|
| `<artifact>.blake3` | Cache integrity sidecar |
| `<ecosystem>/<name>/_versions.json` | Cached or locally generated version list |
| `<ecosystem>/<name>/<version>/_metadata.json` | Cached or locally generated version metadata |
| `<ecosystem>/<name>/_raw_upstream` | Raw upstream protocol payload for adapters that need it |
| `_depot/published/<ecosystem>/<name>/<version>.json` | Experimental local publish manifest |

## Implemented

- OpenDAL-backed `StoragePort`.
- Filesystem, S3, GCS, and memory feature flags.
- Blake3 sidecar storage for every cached or locally published artifact.
- Experimental local publish manifests under `_depot/published/`.

## Deferred

- Database-backed metadata indexes.
- Multi-object transactions.
- Upstream publish forwarding status storage.
- General-purpose `_depot/indexes/` registry index storage.
- Storage-level registry semantics.

## Consequences

- Storage backends remain opaque byte/key stores.
- Publishing and cache writes must be idempotent and recoverable without transactions.
- Registry-specific index behavior belongs above storage, not in storage backends.
