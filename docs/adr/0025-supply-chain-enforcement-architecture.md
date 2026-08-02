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
- **Centralized, reason-aware decision surfacing, not a re-checking Tower layer (Stage N9).** Every
  gate below already enforces in-process and fails closed with `StarmetalError::PolicyViolation`; the
  gap Stage N9 closes is that two hand-written `StarmetalError` → HTTP mappings (`map_public_error` in
  `starmetal-adapters`, used by all eight protocol adapters, and a byte-for-byte duplicate
  `map_admin_error` in `starmetal-server::admin`) flattened every `PolicyViolation` to a bare 403,
  discarding which gate fired. Stage N9 adds one canonical mapping,
  `PolicyReason::http_status`/`http_status_for_message` in `starmetal-core::supply_chain`, and makes
  `map_admin_error` delegate to `map_public_error` instead of duplicating its match — so the reason a
  gate denied a request now determines its HTTP status uniformly everywhere, without adding a second
  place that re-evaluates policy.

## Enforcement order

Gates run in-process, imperatively, inside `CachingPackageService`, in this order (a gate that fires
short-circuits everything after it):

1. **Authorization (ADR-0022)** — each protocol adapter checks `PublishAuthorization` before calling
   into `PackageService` at all; unauthenticated → 401, forbidden → 403.
2. **Blocked coordinate** — `check_package_allowed` rejects a blocklisted package name before any
   other check runs (ingest) or before serving (proxy read path).
3. **Immutability** — an existing, non-overwrite publish to the same `ecosystem/name/version` is
   rejected (`StarmetalError::Publish`, 409) before any bytes are staged.
4. **Anti-shadowing** — refusing to publish a hosted version that collides with an existing upstream
   version (`StarmetalError::Publish`, 409).
5. **License/blocked-package policy (`PolicyConfig::check`)** — the legacy `block_unlicensed` /
   `allowed_licenses` / `blocked_packages` checks.
6. **Vulnerability gate** — `evaluate_scan_report` against `policy.max_vuln_severity`, at ingest
   (`scan_artifacts_for_publish`) and at serve (`enforce_scan_gate`), with serve-time quarantine.
7. **Quota (ADR-0021)** — `reserve_quota` charges the publish's version/byte delta against the
   `(ecosystem, namespace)` ledger, after the vulnerability gate so a denied scan never reserves quota
   it will not use.
8. **Signature/provenance gate** — `enforce_verification` (built-in or an attached external verifier),
   at ingest per artifact and at serve, denying on a missing signature or failing provenance.
9. **Write/serve** — the artifact is committed to storage or served to the caller.

Steps 2 and 5-8 (and step 3/4, for a future immutability gate expressed as a `PolicyReason`) are the
ones a `PolicyReason` can name; steps 1, 3, and 4 today use other `StarmetalError` variants
(`Unauthorized`/`Publish`) that were already correctly mapped before Stage N9 and are unchanged by it.

## Decision → HTTP status table

Stage N9's canonical mapping (`PolicyReason::http_status`, applied by both `map_public_error` and
`map_admin_error`):

| `PolicyReason`           | Code                     | Gate                                  | HTTP status            |
|--------------------------|--------------------------|----------------------------------------|-------------------------|
| `BlockedCoordinate`      | `blocked-coordinate`     | coordinate blocklist                   | 403 Forbidden           |
| `DisallowedLicense`      | `disallowed-license`     | license policy                         | 403 Forbidden           |
| `VulnSeverityExceeded`   | `vuln-severity-exceeded` | vulnerability gate                     | 403 Forbidden           |
| `MissingSignature`       | `missing-signature`      | signature/provenance gate              | 403 Forbidden           |
| `FailingProvenance`      | `failing-provenance`     | signature/provenance gate              | 403 Forbidden           |
| `MissingScanReport`      | `missing-scan-report`    | vulnerability gate ("no scan = violation") | 403 Forbidden      |
| `IncompleteScan`         | `incomplete-scan`        | vulnerability gate                     | 403 Forbidden           |
| `QuotaExceeded`          | `quota-exceeded`         | quota gate                             | 413 Content Too Large   |
| `ImmutableVersion`       | `immutable-version`      | reserved for a future immutability gate expressed as `PolicyViolation`; today's overwrite conflict already returns `StarmetalError::Publish` (409) directly | 409 Conflict |
| *(no recognizable code prefix)* | — | any `PolicyViolation` whose message isn't `"<code>: <prose>"` | 403 Forbidden (fallback, matches pre-N9 behavior) |

`QuotaExceeded` and `ImmutableVersion` are the only reasons that diverge from the 403 default: a quota
denial is a size/rate limit ("not now, under these conditions"), not a standing prohibition, so it
surfaces as 413; a write against an immutable, already-published version conflicts with existing
state, so it surfaces as 409 — consistent with the 409 the overwrite-conflict path already returns via
`StarmetalError::Publish`.

## Implemented

- The vulnerability gate at ingest (publish and cache-fill) and at serve time.
- Sidecar persistence of scan reports and quarantine records, keyed by Blake3 digest, via `StoragePort`.
- A `PersistedScanReport` envelope carrying the artifact's coordinate so a stored report can be
  re-scanned without re-fetching the artifact.
- Scheduled re-correlation of stored reports against refreshed advisory data.
- Serve-time quarantine with an admin promotion workflow.
- Stage N9: `PolicyReason::http_status` / `http_status_for_message` / `from_code` in
  `starmetal-core::supply_chain`, and a single `map_public_error` (`starmetal-adapters`) that
  `map_admin_error` (`starmetal-server::admin`) now delegates to, replacing its duplicated match. Every
  protocol adapter and the admin API surface the same status for the same `PolicyReason`.

## Deferred

- The ordered Tower-layer *enforcement* pipeline from ADR-0024 — expressing each gate above as an
  independent Tower `Layer`/`Service` in the request path, rather than as imperative calls inside
  `CachingPackageService`. Stage N9 (this ADR, "Centralized, reason-aware decision surfacing", above)
  implements the pipeline's outward-facing seam — one canonical decision→status mapping applied
  uniformly — without a re-checking middleware layer; it does not re-architect enforcement itself, and
  the gates keep running exactly as imperative in-service calls as before.
- Ingest-time quarantine: holding hosted-publish bytes for approval instead of hard-denying them.
- SBOM generation.
- Moving scan-report and quarantine linkage into the content graph (ADR-0020) once the metadata
  database is a hard dependency rather than optional.

## Consequences

- Ingest and serve enforcement is uniform and has no dependency on the metadata database being
  configured, which matters because proxy-only deployments never populate the content store.
- Quarantine is a serve-time-only concept today; there is no ingest-time hold state.
- Sidecars are self-healing GC candidates: when their artifact is evicted from storage, the orphaned
  scan/quarantine sidecar becomes reclaimable the same way.
- A policy denial now surfaces a status a client can act on programmatically (403 vs. 409 vs. 413)
  instead of a uniform 403 for every reason, with no change to when or why a gate denies — Stage N9 is
  surfacing-only, not a second enforcement path.
- The Tower-layer *enforcement* composition described in ADR-0024 is still the north star for this
  pipeline; this ADR documents why the current increment diverges from it rather than replacing that
  target.
- See ADR-0024 for the proposed pipeline design and ADR-0020 for the content model this enforcement
  layer deliberately sits alongside rather than inside.
