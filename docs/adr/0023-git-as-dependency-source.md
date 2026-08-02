# ADR-0023: Git as a Dependency Source

## Status

Accepted (partial)

## Context

Several ecosystems resolve dependencies from version control rather than a package-index protocol, so
supporting them as planned universal-repo ecosystems requires Starmetal to mirror, cache, and serve
git — a bounded registry capability, not a forge (ADR-0018):

- **Go** — `go get` uses the GOPROXY HTTP protocol (`/@v/list`, `/@v/<v>.info`, `/@v/<v>.mod`,
  `/@v/<v>.zip`). A proxy either forwards an upstream GOPROXY or synthesizes these from a git
  repository (tags → versions, tree → module zip). `GOPROXY=direct` fetches straight from VCS.
- **Swift** — SwiftPM resolves packages as git repositories (tags as semver), and SwiftPM 5.7+ adds
  the Package Registry HTTP protocol (SE-0292): list versions, version metadata, `Package.swift`
  manifest, and a source archive per version.
- **Zig** — `zig fetch` resolves `build.zig.zon` entries by URL: either a tarball (e.g. a forge
  codeload `.tar.gz`) or `git+https://…#<ref>`, verified against a manifest hash.

The common substrate is: mirror upstream git repositories, keep their refs/tags fresh, serve read-only
git smart-HTTP for clients that fetch git directly, and translate git tags/trees into the ecosystem's
archive (Go module zip, Swift source archive, Zig tarball) served through the content model
(ADR-0020). This introduces an on-disk bare-repository storage model distinct from the object store —
the one storage difference the research flagged between a registry and a forge.

ADR-0017 already defines an **outbound** `Forge` port (Starmetal as an HTTP client of GitHub to open
dependency-update PRs, deliberately with no git library). This ADR is the **inbound** direction —
Starmetal serving/mirroring git to package clients — and is separate in both direction and crate.

## Decision

Add git-as-a-dependency-source as a feature-gated capability, not a forge.

- **Git mirror/cache port:** define a port for mirroring an upstream repository (bare clone, ref/tag
  refresh with TTL like other upstream caches), resolving refs, and reading trees/blobs at a ref.
  Implement it in a dedicated feature-gated crate using a pure-Rust git library (`gitoxide`
  preferred; libgit2 fallback), isolating all git-library dependencies exactly as ADR-0017 isolates
  the outbound forge client. The framework-free core (ADR-0001) and the update-side purity boundary
  (ADR-0017) are preserved — no git library enters `starmetal-core`, `-update-core`, `-versioning`, or
  `-managers`.
- **Read/fetch only:** serve git smart-HTTP `upload-pack` (advertise refs, fetch) for direct git
  resolution. `receive-pack` (push) is out of scope — publishing *to* git is not a goal.
- **Archive translation as ecosystem adapters:** Go, Swift, and Zig are ecosystems (ADR-0005) whose
  proxy facet (ADR-0019) resolves through the git mirror and produces the ecosystem archive on demand,
  storing it content-addressed by Blake3 (ADR-0020). Go serves the GOPROXY protocol; Swift serves the
  Package Registry protocol and/or git; Zig serves tarball and `git+https` resolution. Upstream hashes
  (Go `go.sum`/sumdb, Zig manifest hash, Swift checksum) are preserved alongside the Blake3 digest.
- **On-disk bare-repo storage:** mirrored repositories live in a git-object store separate from the
  artifact object store, with the same OpenDAL-backed filesystem/S3 substrate where the git library
  permits; large-repo packing and gc follow the git library's mechanisms.

## Implemented

- The `starmetal-git` crate provides the `GitMirror` port (`ensure_mirror`, `list_refs`, `resolve`,
  `read_blob`, `archive` with `ArchiveFormat::{TarGz,Zip}`, `commit_time`) with a `gitoxide` (`gix`
  0.86) backend behind bare-repository mirrors refreshed on a TTL, producing byte-deterministic
  archives. All git-library dependencies are quarantined to this crate.
- **Go**: GOPROXY adapter (`@v/list`, `.info`, `.mod`, `.zip`, `@latest`), module zip re-prefixed
  `{module}@{version}/`; `[go].module_overrides` maps a module path to a git remote. Live `go mod
  download` E2E coverage.
- **Zig**: tarball proxy (`GET /zig/{host}/{user}/{repo}/{ref}.tar.gz`), archive served as-is with tag
  validation; `[zig].repo_overrides`. Live `zig fetch` E2E coverage.
- **Swift**: Package Registry (SE-0292) — list-releases, release-metadata (SHA-256 checksum),
  `Package.swift`, and `.zip` endpoints, archive re-prefixed `{name}/`; `[swift].package_overrides`
  maps `{scope}.{name}` to a git URL with **no host default**, so every package requires an explicit
  override. Live `swift package resolve` + `build` E2E coverage.
- Go, Zig, and Swift bypass `CachingPackageService` and the `ProxyFacet` pipeline entirely, reading
  directly through `Arc<dyn GitMirror>` via a `Has*State` trait; `build_app` mounts them
  unconditionally once resolved as a `Proxy` repository (still feature-gated at compile time).

## Deferred

- Smart-HTTP `upload-pack` — proved unnecessary: Go, Zig, and Swift all resolve through their
  ecosystem's HTTP archive/registry protocol, not the git wire protocol, so no client needs Starmetal
  to speak git directly.
- `receive-pack`/push and any write-to-git workflow.
- SSH git transport.
- Go pseudo-versions, `+incompatible` suffixes, nested and `/v2`+ modules, vanity `go-import`
  resolution, and checksum-database (`sumdb`) proxying beyond preserving upstream sums.
- Zig `git+https` direct fetch, `build.zig.zon` transitive dependency resolution, and server-side
  manifest hash verification.
- Swift's no-host-default: every package requires an explicit `package_overrides` entry; there is no
  fallback derivation from the package identifier.
- Any pull-request, issue, CI, or code-hosting UI surface — permanently out of scope (ADR-0018).

## Consequences

- Starmetal gains Go/Swift/Zig by treating git as an upstream source, extending pull-through to
  VCS-based ecosystems while remaining a registry, not a forge.
- Git-library dependencies are quarantined in one feature-gated crate; the core and update crates stay
  pure, consistent with ADR-0001 and ADR-0017.
- A new on-disk bare-repository storage model coexists with the content-addressed artifact store; GC
  and retention (ADR-0020) apply to the derived archives, while git-object packing is managed by the
  git library.
- Each ecosystem stays experimental until it meets ADR-0011 promotion gates with live native-client
  evidence (`go get`, `swift package resolve`, `zig fetch`).
