# ADR-0017: Forge and Git Integration Port

## Status

Accepted

## Context

The dependency-update engine (ADR-0016) must read repository manifests and propose changes as pull
requests. This is the first time Starmetal needs to talk to a version-control forge (GitHub, later
GitLab/Bitbucket) to read files and create branches, commits, and pull requests. Starmetal previously
had no forge client anywhere in the workspace.

Forge APIs differ (GitHub pull requests vs. GitLab merge requests), authentication is sensitive, and
outbound network access to a forge is an SSRF and least-privilege concern. The framework-free core
boundary (ADR-0001, ADR-0016) must not be breached by pulling a forge SDK or git library into domain
or versioning code.

## Decision

Define a single `Forge` outbound port in `starmetal-update-core` and implement it in a dedicated,
feature-gated `starmetal-forge` crate.

The `Forge` port abstracts, at minimum:

- read a repository's manifest files at a ref;
- create a branch and commit a set of file edits;
- open a pull request, and find/update an existing one for the same branch.

Implementation rules:

- GitHub is the first backend (`octocrab`), behind a `github` feature. GitLab and Bitbucket are
  deferred but the port is shaped so they slot in as additional features.
- Branch, commit, and pull-request operations are performed through the forge's HTTP API
  (GitHub's git-data and contents endpoints), not a local git clone/worktree. No git library is a
  dependency. A clone-based path may be added later if a backend requires it.
- Credentials are supplied through the CLI flag or environment and are never logged
  (secrets-handling). Reading a repository and opening a pull request both use the authenticated
  API, so a token is required for any run.
- Outbound requests target `api.github.com` by default. A configurable enterprise base URL is
  validated (scheme and host) before use; a broader host allowlist is deferred until a
  multi-host/config-driven forge target is exposed.
- `starmetal-forge` may depend on `starmetal-update-core`; the reverse is forbidden. No forge or
  HTTP-client dependency may appear in `starmetal-update-core`, `starmetal-versioning`, or
  `starmetal-managers`.

## Implemented (Phase 0 target)

- `Forge` port in `starmetal-update-core`.
- GitHub backend in `starmetal-forge`: read repository contents, create a branch, commit an edit,
  open a pull request.
- Token-based auth via configuration; pull-request creation gated on token presence.

## Deferred

- GitLab and Bitbucket backends.
- Pull-request rebase/update/close lifecycle, labels, reviewers, and auto-merge.
- Onboarding pull requests and dependency-dashboard issues.
- Forge-webhook ingestion (belongs to the deferred server scheduler in ADR-0016).

## Consequences

- All forge- and git-specific code is isolated in one feature-gated crate; the domain and versioning
  crates stay pure and framework-free.
- A second forge is an additive feature, not a refactor.
- Credential handling and outbound-host allowlisting are localized to one crate, easing security review.
