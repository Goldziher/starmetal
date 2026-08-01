# ADR-0020: Universal Content Model and Reference-Counted Garbage Collection

## Status

Accepted

## Context

Hosted and group repositories (ADR-0019) need a persistent metadata model that serves every ecosystem
without per-ecosystem schema churn, and a way to reclaim storage when versions are deleted or retained
out. The current design stores artifacts and Blake3 sidecars by storage key
(`<ecosystem>/<name>/<version>/<filename>`) with no shared component/asset/blob metadata layer and no
garbage collection.

Three inspected codebases converged on the same shape:

- Nexus: `component (coordinate) → asset (path) → asset_blob (bytes + checksums)` with JSON attribute
  columns per level; reference-counted GC via a usage checker plus soft-delete-then-compact.
- Gitea: `Package → PackageVersion → PackageFile → PackageBlob`, blob dedup via `GetOrInsertBlob`,
  metadata as a JSON column, reference-counted blob deletion.
- OneDev: `Pack → PackBlob → PackBlobReference` (many-to-many for dedup), opaque metadata blob.

Notably, Nexus keys blobs by random UUID and therefore does **not** deduplicate identical bytes.
Starmetal's Blake3 content-addressing (ADR-0004) can key storage by hash and get real byte dedup
across ecosystems — a genuine advantage to preserve.

## Decision

Adopt a three-level universal content model with content-addressed storage and reference-counted GC.

- **Content model:** `Component (namespace, name, version) → Asset (path) → Blob (Blake3 digest, size,
  upstream hashes, content-type)`. Ecosystem-specific metadata lives in a JSON `attributes` column at
  each level (serde-tagged enum deserialized by ecosystem), plus a generic key/value property table as
  the queryable escape hatch. Only the three-level spine is relational; no per-ecosystem tables.
- **Content-addressed storage:** the Blake3 digest is the storage key. Identical bytes across
  versions, ecosystems, and container layers share one blob. An `asset → blob` reference table records
  usage. This extends ADR-0004 from per-artifact sidecars to a first-class content-addressed store and
  keeps the `StoragePort` (OpenDAL) as the low-level object driver beneath it.
- **Reference-counted GC:** a blob is eligible for deletion only when no asset references it. GC runs
  as a scheduled sweep: mark unreferenced blobs, soft-delete with a grace window (to survive races and
  publish rollbacks), then hard-delete on compaction. Soft-deleted blobs can be undeleted within the
  window.
- **Retention decoupled from GC:** retention is a logical policy that deletes asset/version rows
  (`keep-N latest`, `last-downloaded`, `last-updated`, `regex`, `is-prerelease`); GC is the physical
  reclaim that follows once blobs become unreferenced. The two are separate stages with separate
  configuration.
- **Metadata sidecar for recovery:** each stored blob keeps a headers/checksums sidecar so the
  metadata store can be reconstructed from storage after loss.

## Implemented

- `starmetal-metadata`'s `PostgresContentStore` implements the `Component → Asset → Blob` model with
  Blake3 content-addressed dedup and publish-path dual-write; reads verify integrity against the
  stored digest.
- Reference-counted GC (`run_gc_sweep`: mark unreferenced blobs → soft-delete with a grace window →
  compact) and retention (`apply_retention`, union-of-rules across the configured policies) are wired
  to scheduled tasks (`metadata.gc_interval_secs`, `metadata.retention_interval_secs`) and to admin
  `POST /gc` and `POST /retention` triggers.

## Deferred

- Per-repository or per-ecosystem retention policies — one global `metadata.retention` policy applies
  today.
- Physical per-ecosystem table partitioning (Nexus's `${format}_*` optimization) — start with a single
  set of tables discriminated by ecosystem; partition only if scale requires.
- An embedded-database option; Postgres is the only backing store today. Prefer an embedded default
  (per Zot's lean posture) over a mandatory external DB.
- Cross-repository (global) dedup versus per-repository dedup boundary.

## Consequences

- Starmetal gains real cross-ecosystem byte deduplication that Nexus lacks, plus GC that Starmetal
  currently lacks — closing the one true storage gap while keeping a competitive edge.
- The content model underpins publishing (ADR-0021), access-control selectors (ADR-0022), and
  supply-chain artifact linkage (ADR-0024).
- Integrity verification (ADR-0004) is preserved: reads verify the Blake3 digest, now as the storage
  key itself.
- GC and retention are operator-configurable scheduled tasks; deleting content is guarded by the
  grace-window soft-delete to prevent accidental loss (verify-before-acting).
