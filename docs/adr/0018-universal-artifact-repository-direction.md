# ADR-0018: Product Direction — Universal Artifact Repository

## Status

Proposed

## Context

Starmetal today is a read/proxy-focused pull-through cache across eight ecosystems (ADR-0005,
ADR-0011), with experimental local publishing (ADR-0009). Competitive research (2026-07) compared the
universal artifact repository tier (JFrog Artifactory, Sonatype Nexus, Cloudsmith, ProGet, the cloud
services) against git forges with bundled registries (GitLab, Gitea, Forgejo, OneDev) and the
supply-chain frontier (Harbor, Zot, Pulp, Sigstore, SBOM/scanner tooling). Two findings frame this
direction:

1. A universal artifact repository is an *extension* of Starmetal's existing hexagonal architecture.
   The hard foundation — port traits, per-ecosystem adapters, OpenDAL storage, policy engine, Blake3
   integrity — already exists. Nexus (`nexus-public`, the only open-core universal repo) supplies a
   direct blueprint for the missing pieces.
2. A git forge is a separate product an order of magnitude larger (registry is ~1.5–7% of a forge's
   code; the rest is git transport, code review, CI, and UI). Building one is out of scope.

The competitive wedge is unoccupied: no open-source tool combines multi-ecosystem breadth, deep
policy enforcement, and pull-through caching. Forges notably lack pull-through entirely — the single
most-requested, never-delivered forge-registry feature — which Starmetal already has.

## Decision

Starmetal's product direction is a **self-hosted universal artifact repository** with a supply-chain
policy focus, not a git forge. Concretely:

- Grow from proxy-only to the standard hosted/proxy/group repository model (ADR-0019).
- Adopt a universal content model with reference-counted garbage collection (ADR-0020).
- Promote hosted native publishing from experimental substrate to a supported surface (ADR-0021).
- Add access control suitable for multi-tenant use (ADR-0022).
- Support git as a dependency source for VCS-based ecosystems — Go, Swift, Zig — as a bounded
  registry capability, not a forge (ADR-0023).
- Make supply-chain security (SBOM, scanning, signing, policy) a first-class differentiator
  (ADR-0024).

Explicitly out of scope: pull requests, issue tracking, CI/CD, code review, and a general-purpose git
hosting UI. Where deep forge integration is valuable (e.g. build-to-artifact provenance), Starmetal
integrates behind an existing forge through the narrow identity/permission/storage contract rather
than reimplementing a forge. This preserves the framework-free core boundary (ADR-0001).

## Consequences

- ADR-0005, ADR-0009, and ADR-0011 remain the record of the current experimental read/proxy and
  local-publish surfaces; ADR-0019 through ADR-0024 extend them and will update the support matrix as
  each capability lands with evidence.
- "Universal artifact repository" is a direction, not a present claim. Each capability stays
  experimental until it meets the promotion gates in its ADR.
- Git-as-a-dependency-source (ADR-0023) introduces an on-disk bare-repository storage model alongside
  the object store; it does not make Starmetal a forge.
- The supply-chain policy pipeline (ADR-0024) is the primary differentiator and should be prioritized
  alongside the repository-model work, not deferred to the end.
