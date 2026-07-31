# ADR-0024: Supply-Chain Security Pipeline

## Status

Proposed

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

## Deferred

- Bundling a specific scanner; the port ships first, with an initial adapter (Trivy or OSV) behind a
  feature flag. Keep scanners external and swappable (no vendored CVE database in core).
- Keyless Sigstore (Fulcio/Rekor) verification and Starmetal-published transparency for re-hosted
  artifacts — verify supplied signatures first.
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
