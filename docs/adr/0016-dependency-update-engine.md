# ADR-0016: Dependency Update Engine

## Status

Accepted

## Context

Starmetal is a pull-through package registry cache/proxy. It already knows how to query every
supported upstream registry for the versions of a package and their metadata, through the
`PackageService` inbound port (`list_versions`, `get_version_metadata`), which layers caching,
blake3 verification, and policy enforcement on top of the ecosystem `UpstreamClient`s.

A frequently requested capability adjacent to a registry proxy is dependency-update automation:
scan a repository's manifests, determine which dependencies have newer versions, and open update
pull requests — the capability Renovate and Dependabot provide. Starmetal owns the hardest-to-build
piece of that pipeline (the version datasource) but has none of the rest: no manifest parsing, no
versioning/semver logic, no update-determination engine, no version-control-forge integration, and
no update configuration model.

The `version` field on domain types is a plain `String` with no ordering semantics, and there is no
concept of a dependency (a package plus a version constraint). This work is therefore almost entirely
net-new and must not compromise the framework-free core boundary (ADR-0001) or the experimental,
evidence-gated support posture (ADR-0011).

## Decision

Add a dependency-update engine as a set of new crates that mirror the existing hexagonal split, reuse
the registry layer as the version datasource, and stay compile-time optional.

New crates:

| Crate | Boundary |
|-------|----------|
| `starmetal-update-core` | Framework-free update domain types and update port traits |
| `starmetal-versioning` | `Versioning` implementations per scheme (semver, PEP 440, node-semver, ...) |
| `starmetal-managers` | `Manager` implementations that detect, parse, and patch manifests |
| `starmetal-forge` | `Forge`/git implementations for repository and pull-request operations |
| `starmetal-updater` | Update engine service composing the ports into scan and run workflows |

New ports defined in `starmetal-update-core`:

| Port | Direction | Purpose |
|------|-----------|---------|
| `Manager` | Inbound | Detect manifest files, extract dependencies, patch a dependency's value in file text |
| `Datasource` | Outbound | Return available versions and release metadata for a package |
| `Versioning` | Outbound | Parse, validate, compare versions; test range membership; compute a new constraint value |
| `Forge` | Outbound | Read a repository, create branches/commits, open and update pull requests |

Datasource reuse: the production `Datasource` implementation is an adapter over the existing
`PackageService`. Update runs therefore query versions through the same cached, integrity-verified,
policy-gated path the proxy already uses, rather than talking to upstreams directly. `starmetal-updater`
depends on the `PackageService` trait, not on `starmetal-service` internals.

Boundary rules (extend ADR-0001):

- `starmetal-update-core` remains framework-free. It must not depend on axum, tower, opendal, reqwest,
  octocrab, or a git library. It may depend on `starmetal-core` for `Ecosystem` and `PackageName`.
- `Manager` implementations must not perform registry lookups or forge operations; they only read and
  rewrite manifest text.
- `Versioning` implementations must be pure (no I/O) and are the single source of version-ordering and
  constraint-rewriting truth. String comparison of versions is prohibited outside this crate.
- Every manager, versioning scheme, and forge is behind a Cargo feature (ADR-0006). Features are
  additive; the CLI `full` feature enables them all.

Trigger and coupling:

- The initial trigger is the on-demand CLI (`sm update`), composed through `starmetal-ops`.
  Server-side scheduling and webhook-driven runs are deferred.
- The engine is integrated into the existing workspace and shares configuration, the runtime, and the
  CLI, rather than being a separate product.

## Implemented (Phase 0 target)

- Update domain types and the four ports in `starmetal-update-core`.
- `Versioning` for Cargo semver.
- `Manager` for Cargo manifests (`Cargo.toml`).
- `Datasource` adapter over `PackageService`.
- `Forge` for GitHub via its HTTP API (branch/commit/pull-request through git-data and contents
  endpoints; no local git clone).
- `starmetal-updater` engine with a scan workflow (report available updates) and a run workflow
  (open a pull request).
- `sm update scan` and `sm update run` CLI commands.

## Deferred

- Additional managers, versioning schemes, and datasources toward full parity (npm, pip, and beyond).
- Lockfile updating via native package managers.
- Update grouping, scheduling, dependency-dashboard, auto-merge, and changelog/release-note rendering.
- Server-side scheduler and forge-webhook trigger model.
- Non-GitHub forges (GitLab, Bitbucket).
- Vulnerability-driven updates wired to `policies.max_vuln_severity`.

## Consequences

- The engine reuses the proxy's cached, policy-gated version data, which is the differentiating,
  integrated behavior.
- Version-ordering correctness is concentrated in one pure, property-tested crate.
- The core boundary is preserved; forge and git dependencies never reach domain or versioning code.
- Support remains experimental and evidence-gated (ADR-0011); shipping the engine is not a support
  claim for any ecosystem's update workflow until live evidence exists.
- Forge and git integration are a new outbound concern; their design is recorded in ADR-0017.
