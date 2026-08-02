# ADR-0024: Supply-Chain Security Pipeline

## Status

Accepted (partial)

## Context

Starmetal already verifies Blake3 integrity (ADR-0004) and enforces a policy engine (block packages,
licenses, and vulnerability severities). Research identified this as the differentiating wedge: no
open-source tool combines multi-ecosystem breadth, pull-through caching, and deep policy. The closest
product category — the "dependency firewall" (Bytesafe, Socket) — is proprietary. To own this wedge,
Starmetal must make supply-chain security a first-class, standards-interoperable pipeline rather than a
single policy check.

The frontier, distilled from Harbor, Zot, and the Sigstore/SBOM/scanner ecosystem:

- **Policy as an ordered middleware chain** enforced at ingest *and* at serve time (Harbor models each
  concern — auth, immutability, quota, vulnerability gate, signature gate — as an independent layer;
  "no scan report = violation" blocks unscanned artifacts).
- **Pluggable scanners** behind a capability-negotiated contract (Trivy/Grype/OSV), in-process or
  out-of-process.
- **SBOM generation and storage** in standard formats (CycloneDX + SPDX), with continuous re-scanning
  of stored artifacts as new advisories land (the Dependency-Track pattern).
- **Signatures and provenance as first-class referrer artifacts** (Sigstore/cosign, in-toto/DSSE,
  SLSA), verified on ingest and refuse-serve on failure.

## Decision

Model supply-chain security as a composable policy pipeline over the content model (ADR-0020),
enforced by ordered middleware on both push and pull paths, with pluggable scanner and signing ports.

- **Policy pipeline:** express each cross-cutting control as an independent Tower layer (ADR-0002) in
  the request path — authorization (ADR-0022) → immutability/quota (ADR-0021) → vulnerability gate →
  license gate → signature/provenance gate → write/serve. The existing policy engine becomes the
  decision core these layers consult, evaluated at both ingest and serve time. Policy is data-driven
  (declarative rules), composable, and default-deny where configured (block by CVE severity, SPDX
  license expression, coordinate, missing signature, or failing provenance).
- **Scanner port:** a capability-negotiated `Scanner` port (`scan(artifact) -> report`, `capabilities()`)
  in `starmetal-core`, transport-agnostic so an in-process (embedded) or out-of-process (REST adapter,
  e.g. Trivy/Grype/OSV) implementation satisfies it. Reports are stored and associated with the
  artifact.
- **SBOM:** generate an SBOM per artifact (CycloneDX and SPDX), store it as an associated artifact, and
  re-correlate stored SBOMs against refreshed advisory feeds on a schedule — scan-once-then-monitor,
  not scan-only-at-ingest.
- **Signing and provenance:** verify Sigstore/cosign signatures and SLSA/in-toto provenance on ingest;
  store signatures, SBOMs, and attestations as referrer/accessory artifacts linked to the subject
  digest (extending Starmetal's Ed25519 DSSE work, ADR-0011). Signature verification is delegated to
  established libraries; Starmetal owns the linkage graph and the refuse-serve enforcement.
- **Quarantine workflow:** artifacts failing policy are quarantined (not served) with an approval/
  promotion path, rather than silently dropped — the dependency-firewall behavior.

## Implemented

- Blake3 integrity (ADR-0004) and the block-by-package/license/severity policy engine are the starting
  point this generalizes.
- Experimental Ed25519 DSSE sidecars (ADR-0011) are the signing starting point.
- The `Scanner` port and the `OsvScanner` adapter; `evaluate_scan_report`, `PolicyDecision`, and
  `PolicyReason` drive gate decisions from scan results.
- A vulnerability gate at both ingest (publish/cache-fill) and serve time.
- Scan reports persisted as blake3-digest-keyed JSON sidecars (`_starmetal/scans/<digest>.json`) via
  the `StoragePort`, re-correlated on a schedule (`SupplyChainMaintenance`).
- Serve-time quarantine and promotion (`_starmetal/quarantine/<digest>.json`), with admin endpoints to
  inspect and promote quarantined artifacts.
- Centralized, reason-aware policy-decision surfacing (Stage N9): a single `PolicyReason` → HTTP
  status mapping (`PolicyReason::http_status` / `http_status_for_message` in
  `starmetal-core::supply_chain`) applied uniformly by every protocol adapter and the admin API, so a
  given policy denial surfaces the same HTTP status no matter which surface produced it. This
  realizes this ADR's "ordered policy layer" as a shared surfacing seam rather than a re-checking
  Tower pipeline — see ADR-0025 for the full decision→status table and the argument against
  double-enforcement.
- SBOM generation: `starmetal-core::sbom::generate` emits CycloneDX 1.5 and SPDX 2.3 JSON documents
  per artifact. The service layer (`store_sbom_documents`) stores them as coordinate-keyed sidecars
  (`_starmetal/sbom/<coordinate>.<format>.json`, not digest-keyed, since an SBOM embeds coordinate
  identity and license) on publish, staged through the same rollback-safe write path as the artifact
  itself. `SbomIndex::list_sboms`/`get_sbom_document` expose them for admin retrieval.
- Signature and provenance gate: `enforce_verification` runs at both ingest (`publish_package`) and
  serve (`get_artifact`), denying with `PolicyViolation` (fail-closed) on a missing signature or
  failing provenance. The built-in check is a DSSE-signed in-toto provenance attestation over
  Starmetal's own signing graph (`verify_provenance`, `starmetal_core::attestation`), gated by
  `supply_chain.require_signature`/`require_provenance`. An attached external `Verifier` port
  (`starmetal-core::supply_chain::VerificationTarget`) replaces the built-in check entirely — the
  cosign/sigstore seam this ADR calls for.
- Ingest-time quarantine: with `supply_chain.ingest_quarantine` enabled, a publish blocked by the
  ingest vulnerability gate (`scan_artifacts_for_publish`) is held — both the staged bytes and a
  `QuarantineRecord` — instead of hard-denied. `IngestQuarantine::promote_ingest`/`reject_ingest`
  replay the deferred publish or purge the held bytes; promotion is bound to the exact reviewed
  coordinate, so approving one digest never silently clears the gate for a different package that
  happens to share bytes.
- Quota gate (ADR-0021): `reserve_quota` now denies with `PolicyReason::QuotaExceeded` when a
  publish's version/byte delta would exceed the `(ecosystem, namespace)` ledger limit.

## Deferred

- The ordered Tower-layer *enforcement* pipeline assembly described in this ADR's Decision — express-
  ing each gate as an independent Tower layer in the request path — remains deferred. Enforcement
  today is still **imperative in-service gating** inside `CachingPackageService`, not a composed Tower
  layer stack. What Stage N9 implements instead (see Implemented, above, and ADR-0025) is the
  pipeline's outward-facing seam: one canonical mapping from each gate's `PolicyReason` to an HTTP
  status, applied uniformly across proxy, hosted, and admin paths, without re-running policy checks
  in a middleware layer. ADR-0025 records the as-built enforcement architecture and the reasoning for
  this divergence.
- Per-ecosystem dependency enumeration in SBOMs: the generator accepts a dependency list and is
  dependency-ready, but no adapter yet extracts declared dependencies from protocol metadata to
  populate it.
- Bundling a specific scanner beyond OSV; keep scanners external and swappable (no vendored CVE
  database in core).
- Live sigstore/cosign/Rekor (keyless) verification and Starmetal-published transparency for re-hosted
  artifacts: the `Verifier` port is the seam, but no adapter calls out to Sigstore yet — today's
  built-in gate verifies only Starmetal's own DSSE-signed graph.
- Protocol-native and post-quantum signing claims remain gated by ADR-0011 until clients verify them
  in deterministic tests.

## Consequences

- Supply-chain security becomes the productized differentiator, prioritized alongside the
  repository-model work (ADR-0018), not deferred.
- Policy enforcement is uniform across pull-through and hosted publishing because both share the Tower
  layer chain and the content model.
- Scanning, SBOM, and signing are ports with swappable adapters, keeping `starmetal-core` framework-
  free (ADR-0001) and avoiding a hard dependency on any one vendor.
- Standards interoperability (CycloneDX/SPDX, cosign/DSSE/SLSA) is a requirement, not optional; Blake3
  remains Starmetal's integrity primitive but sits alongside the standard stack to be adoptable.
