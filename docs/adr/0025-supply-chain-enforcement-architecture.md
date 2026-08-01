# ADR-0025: Supply-Chain Enforcement Architecture (As-Built)

## Status

Accepted

## Context

ADR-0024 proposed supply-chain enforcement as an ordered Tower-layer policy pipeline — authorization
(ADR-0022) → immutability/quota (ADR-0021) → vulnerability gate → license gate → signature/provenance
gate → write/serve — with SBOM and provenance linked to each artifact. The first increments shipped a
narrower, working core: an OSV scanner behind the `Scanner` port, a vulnerability gate enforced at both
ingest and serve, and a serve-time quarantine/promotion workflow. Building that core surfaced two
concrete architectural choices worth recording now, ahead of the full Tower-layer composition.

## Decision

- **Imperative in-service gating, not a composed Tower stack.** The vulnerability gate runs as direct
  calls inside `CachingPackageService`, at publish/ingest time and at serve time — both at the
  cache-hit return path and at the fresh-upstream-fetch return path. It is not yet expressed as an
  independent Tower layer in the request pipeline. The ordered Tower-layer assembly remains ADR-0024's
  target architecture; it becomes the right shape once more gate types (license, signature/provenance)
  exist to compose alongside the vulnerability gate. Composing a pipeline of one layer would add
  indirection without benefit.
- **Blake3-digest-keyed JSON sidecars via `StoragePort`, not the Postgres content store.** Scan reports
  and quarantine records persist as `_starmetal/scans/<digest>.json` and
  `_starmetal/quarantine/<digest>.json` sidecars in the object store, keyed by the artifact's Blake3
  digest, rather than as rows in the metadata database (ADR-0020). The object store is always present;
  the metadata database is optional. Digest-keying also lets identical bytes share one scan report
  regardless of which component/version references them, and — critically — lets proxy-cached
  artifacts that never enter the content database still be gated, re-correlated against refreshed
  advisories, and quarantined.

## Implemented

- The vulnerability gate at ingest (publish and cache-fill) and at serve time.
- Sidecar persistence of scan reports and quarantine records, keyed by Blake3 digest, via `StoragePort`.
- A `PersistedScanReport` envelope carrying the artifact's coordinate so a stored report can be
  re-scanned without re-fetching the artifact.
- Scheduled re-correlation of stored reports against refreshed advisory data.
- Serve-time quarantine with an admin promotion workflow.

## Deferred

- The ordered Tower-layer refactor from ADR-0024 — awaiting the license and signature/provenance gates
  that make composition worthwhile.
- Ingest-time quarantine: holding hosted-publish bytes for approval instead of hard-denying them.
- SBOM generation.
- The signature/provenance gate.
- Moving scan-report and quarantine linkage into the content graph (ADR-0020) once the metadata
  database is a hard dependency rather than optional.

## Consequences

- Ingest and serve enforcement is uniform and has no dependency on the metadata database being
  configured, which matters because proxy-only deployments never populate the content store.
- Quarantine is a serve-time-only concept today; there is no ingest-time hold state.
- Sidecars are self-healing GC candidates: when their artifact is evicted from storage, the orphaned
  scan/quarantine sidecar becomes reclaimable the same way.
- The Tower-layer composition described in ADR-0024 is still the north star for this pipeline; this ADR
  documents why the current increment diverges from it rather than replacing that target.
- See ADR-0024 for the proposed pipeline design and ADR-0020 for the content model this enforcement
  layer deliberately sits alongside rather than inside.
