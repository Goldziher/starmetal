# ADR-0019: Repository Kinds and the Recipe/Facet Model

## Status

Proposed

## Context

Starmetal adapters currently model one behavior: pull-through proxy. A universal artifact repository
(ADR-0018) must offer three repository kinds per ecosystem:

- **proxy** — caches an upstream registry (what exists today);
- **hosted** — stores artifacts published directly to Starmetal (ADR-0021);
- **group** (virtual/aggregate) — presents multiple proxy/hosted/group repositories behind one URL
  with resolution ordering and metadata merging.

The naive design — three trait implementations per ecosystem — multiplies work across eight-plus
ecosystems and duplicates the fetch/store/merge logic that is ecosystem-independent. Nexus solves this
with a **recipe/facet** model: one `Repository` is a composed bag of capability facets selected by a
recipe keyed on `(kind, format)`; the proxy fetch loop and group member fan-out live once in shared
components, and a format author writes three thin recipes to get all three kinds. Gitea and OneDev
independently confirm that per-ecosystem code should be thin protocol translation over a shared core.

## Decision

Model a repository as a **composition of facets selected by a recipe**, where a recipe is identified
by `(RepositoryKind, Ecosystem)`.

- Define `RepositoryKind` as an enum (`Proxy`, `Hosted`, `Group`) — a newtype-style distinction, not a
  boolean, per rust-conventions.
- Define capability facets as ports in `starmetal-core`, e.g. `ProxyFacet` (fetch/store/negative-cache),
  `HostedFacet` (accept/validate/store uploads), `GroupFacet` (member iteration + merge). A repository
  instance holds the facets its recipe attached.
- Keep the kind-generic machinery in `starmetal-service`: the proxy `fetch → verify → policy → store →
  cache` pipeline (the existing `CachingPackageService` becomes the `ProxyFacet` engine) and the group
  member fan-out (`first-match` for artifacts, `merge-all` for indexes).
- Adapters in `starmetal-adapters` implement only the ecosystem-specific hooks each facet needs:
  `cached_content`/`store` for proxy, coordinate parsing/validation for hosted, and index `merge` for
  group. Adapters remain axum routers (ADR-0005); route wiring is selected by the recipe.
- A recipe registry maps `"{ecosystem}-{kind}"` to a constructor. Feature flags (ADR-0006) still gate
  which ecosystems compile in; kinds are additive within an enabled ecosystem.

Group metadata merging is per-ecosystem (maven-metadata.xml, npm packument, PyPI simple index, Cargo
index) and is the one place group repositories need ecosystem knowledge; it is a facet hook, not
shared code.

## Implemented

- Nothing yet; this ADR defines the target model.

## Deferred

- Federated/replicated multi-site repositories (Artifactory "federated" equivalent).
- Per-member routing rules beyond ordered first-match/merge-all.
- UI for repository composition; configuration is TOML-first initially.

## Consequences

- The existing pull-through implementation is refactored into the `ProxyFacet` engine rather than
  rewritten; behavior is preserved and covered by existing conformance/E2E evidence.
- Adding a repository kind to an ecosystem becomes a thin recipe plus facet hooks, not a new subsystem.
- The content model (ADR-0020), publishing (ADR-0021), and policy pipeline (ADR-0024) attach as facets
  or middleware within this model.
- This is the load-bearing architectural change of the universal-repo direction and should land first,
  behind experimental config, with conformance evidence for each kind before any support claim.
