# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `starmetal-oidc` crate: an offline static-JWKS OIDC bearer validator (ADR-0022) that proves the
  `Authenticator` port is a clean seam for a second identity backend. `OidcAuthenticator` verifies JWT
  bearer tokens (RS256/ES256 only — `alg: none` and HMAC algorithms are rejected as an
  algorithm-confusion defense) against a static JWKS from `[oidc]` config, checking `exp`/`iss`/`aud`
  and mapping a configurable claim (`oidc.principal_claim`, default `sub`) to a principal. It is
  composed ahead of the flat-token authenticator via the core `CompositeAuthenticator`, so a JWT
  authenticates via OIDC while an unchanged flat token still authenticates via the fallback;
  authorization stays on `LocalAuthorizer`. Off by default and gated behind the `oidc` build feature
  (included in `full`). Deliberately offline — no JWKS-URL fetch, OIDC discovery, or token refresh
  (a live-IdP backend is a later stage).

- `starmetal-metadata` crate: an optional Postgres-backed content model (ADR-0020) that dual-writes a
  `Component → Asset → Blob` graph alongside the flat object store on publish. Blobs are addressed by
  blake3 digest, so identical bytes published across ecosystems share one stored blob (dedup), and
  reads re-verify against the digest key. A reference-counted garbage collector (mark, soft-delete with
  a grace window, compact) and configurable retention policies reclaim unreferenced blobs; both run on
  optional interval schedulers and as admin-triggered sweeps (`POST /admin/api/v1/gc`,
  `POST /admin/api/v1/retention`). Gated by `[metadata].enabled` and the `metadata` build feature
  (included in `full`).
- `starmetal-authz` crate: `LocalAuthorizer`, a deny-by-default implementation of a new `Authorizer` /
  `Authenticator` port (ADR-0022). It migrates the existing flat `[auth]`/`[admin]`/`[publishing]`
  token config into a BREAD-action grant model at startup; no new config section is required. Wired
  into all eight publish adapters and the admin API.
- Supply-chain vulnerability pipeline: a `Scanner` port with an OSV-backed implementation gates
  publish against `policies.max_vuln_severity`, and, with `supply_chain.enforce_on_serve`, gates
  `get_artifact` reads the same way. Scan reports persist as blake3-keyed sidecars shared across
  identical bytes. A scheduled re-correlation sweep re-scans stored reports against refreshed
  advisories. With `supply_chain.quarantine` enabled, a serve-time block becomes a recoverable hold,
  promoted or rejected through `POST /admin/api/v1/quarantine/{digest}/promote` and `.../reject`.
  Gated by `[supply_chain].enabled` and the `scanner-osv` build feature (included in `full`).
  ADR-0025 documents the enforcement architecture.

### Changed

- Bumped `opendal` to 0.58.

## [0.3.0] - 2026-07-24

### Added

- Dependency-update engine (experimental, Phase 0). `sm update scan <path>` scans a local checkout's
  Cargo manifests and reports available updates classified as patch/minor/major (with `--pin` and
  `--allow-prerelease`); `sm update run <owner>/<name>` scans a GitHub repository and opens or updates
  a pull request (`--dry-run` reports without opening one). The GitHub token is read from `--token` or
  the `STARMETAL_GITHUB_TOKEN` environment variable.
- Five feature-gated crates mirroring the hexagonal split: `starmetal-update-core` (framework-free
  domain types and the `Manager`, `Versioning`, `Datasource`, and `Forge` ports),
  `starmetal-versioning` (Cargo semver), `starmetal-managers` (Cargo.toml parse and
  formatting-preserving edits), `starmetal-forge` (GitHub over its HTTP API), and `starmetal-updater`
  (the update engine).
- The update engine reuses `PackageService` as its version datasource, so update lookups flow through
  the registry proxy's pull-through cache, blake3 integrity verification, and policy enforcement.
- ADR-0016 (dependency-update engine) and ADR-0017 (forge and git integration port).

### Changed

- Added a `StarmetalError::Update` variant so update-engine errors surface as a dedicated kind at the
  CLI boundary.

## [0.2.0] - 2026-07-04

### Added

- Starmetal signing substrate with Ed25519 DSSE-style statements, key configuration, signature sidecars, and
  read-time verification paths.
- Admin management metrics API and ADRs for the management surface and operational statistics.
- Deterministic Docker proxy E2E coverage, including pnpm read-through and local publish/install cache validation.
- Native local publish/readback coverage improvements across npm, PyPI, Cargo, Hex, Maven, RubyGems, NuGet, and
  pub.dev conformance routes.

### Changed

- Migrated repository formatting, linting, and git hooks from prek-specific configuration to `poly`.
- Refreshed Rust dependencies, including the `rmcp` 2.1 update and lockfile regeneration.
- Stabilized generated schema JSON formatting so schema checks and `poly` formatting agree.
- Clarified README and ADR support matrices: publishing remains experimental local substrate until native
  publish-then-install E2E is green per ecosystem.
- Hardened release and Docker CI paths, including native Docker image builds and GHCR dry-run validation.

### Fixed

- npm local publish now works when no upstream package metadata exists.
- RubyGems compact index responses now emit checksum data correctly.
- Signing verification paths now reject tampered or mismatched payloads more consistently.
- CI release scripts now retain executable bits for Docker, namespace, package, Homebrew, version-sync, dry-run,
  and tag workflows.

## [0.1.0] - 2026-06-28

### Added

- `starmetal-service` crate: application service layer with `CachingPackageService` implementing pull-through caching, blake3 integrity verification, and policy enforcement.
- Blake3 integrity verification: hash computed on first artifact fetch, stored as `.blake3` sidecar file, verified on every cache read.
- Policy enforcement on `get_artifact`: `blocked_packages` checked before fetching to prevent policy bypass.
- Adapter state traits for accessing `PackageService` and ecosystem-specific upstream clients.
- npm recursive BFS dependency prefetch with visited set and max depth of 10 levels.
- Hex protobuf registry proxy at `/hex/packages/{name}` for mix checksum verification and tarball integrity.
- 5-minute TTL cache for all upstream client responses using `(Instant, T)` tuples.
- Integration test crate (`tests/integration/`) with 31 tests covering pip, npm, cargo, and mix client workflows.
- All four registries now pass client-level integration tests.
- Dynamic OpenDAL storage configuration with generic `backend` + `options`, legacy filesystem `path`, and legacy `[storage.s3]` compatibility.
- Minimal bearer-token auth middleware when `auth.enabled = true`, including startup rejection for empty token sets.
- Public feature flags for all adapter and backend combinations, including pass-through CLI features for PyPI, npm, Cargo, Hex, Maven, RubyGems, NuGet, pub.dev, fs, memory, S3, and GCS.
- Runtime adapter support for Maven Central-compatible repositories, RubyGems Compact Index, NuGet V3, and hosted pub.dev repositories.
- Canonical registry schema provenance in `schemas/sources.toml` and generated `schemas/manifest.json`.
- `tools/schema-manager` for fetching upstream spec artifacts, generating Starmetal-derived schemas, checking committed schema drift, and optional live source checks.
- Upstream source artifacts for Hex protobufs, Maven XSDs, npm types, NuGet nuspec XSD, pub.dev DTO evidence, RubyGems Compact Index/gem schema evidence, OSV advisories, and Sonatype/Nexus API evidence.
- Starmetal-derived schemas for PyPI, npm, Cargo sparse index/config, Hex, NuGet service/package/registration resources, pub.dev package metadata, Starmetal config, and lockfiles.
- Fixture-based conformance tests and representative fixtures for PyPI, npm, Cargo, Hex, Maven, RubyGems, NuGet, and pub.dev.
- Route-level conformance coverage for Maven, RubyGems, NuGet, and pub.dev.
- Required live native-client E2E coverage for PyPI, npm, Cargo, Hex, Maven, RubyGems, NuGet, and pub.dev via `task test:e2e`.
- Focused `task test:e2e:<registry>` commands for per-registry live validation.
- Service-backed conformance tests using `CachingPackageService` with in-memory OpenDAL storage.
- Schema and conformance task runner commands: `schema:fetch`, `schema:generate`, `schema:refresh`, `schema:check`, `schema:check-live`, `schema:validate`, `conformance`, and `generate`.
- `Ecosystem` variants and normalization behavior for Maven, RubyGems, NuGet, and pub.dev.
- `UpstreamConfig.artifact_url` for registries that separate metadata/index and artifact bases.
- `PackageService::validate_metadata` for adapter-side policy checks before serving raw protocol metadata.
- ADR-0009 defining publishing/upload workflow scope, safety defaults, scoped-token authorization, OpenDAL persistence boundaries, and opt-in upstream forwarding.
- Publishing domain types and `PublishingService` port for local hosted package uploads, yank state updates, duplicate-version checks, shadowing protection, and published metadata manifests.
- Scoped publishing token config with `read`, `publish`, `yank`, and `admin` scopes plus optional ecosystem and package allowlists.
- Native publish-route conformance coverage for PyPI legacy upload, npm packument publish, Cargo Registry Web API publish, and Maven repository `PUT` uploads.
- Native local hosted publishing routes for Hex tarball uploads, RubyGems gem uploads, NuGet V2 package uploads, and hosted pub.dev archive uploads.
- Archive metadata extraction for RubyGems `.gem`, NuGet `.nupkg`/`.nuspec`, pub.dev `.tar.gz`, and Hex tarball publish payloads.
- Publish-route conformance coverage for Hex, RubyGems, NuGet, and pub.dev, including metadata/index readback, artifact downloads, and checksum sidecars where applicable.
- `starmetal-ops` crate as the shared local operator API for CLI and MCP frontends.
- Fuller CLI command tree for config, registry, package, cache, server, and MCP operations with no-config execution support.
- stdio MCP server backed by the same operations layer as the CLI, with mutating tools gated by `--allow-writes`.
- Explicit artifact publish operation in both CLI and MCP for locally hosted package metadata.
- ADR-0010 documenting the local-first CLI/MCP operations model and parity boundary.

### Changed

- Adapters now serve cached upstream data directly with URL rewriting instead of reconstructing responses from `VersionMetadata`. This preserves protocol-specific fields (npm dependencies, PyPI requires-python, Cargo deps/features).
- npm adapter uses raw `serde_json::Value` instead of typed `NpmPackument` struct to handle the variety of npm field shapes.
- Upstream hashes preserved in `ArtifactDigest.upstream_hashes`.
- Dependency flow updated: `starmetal-server -> starmetal-service -> starmetal-core` added alongside existing paths.
- `starmetal config` now serializes a redacted config representation so auth tokens are never printed.
- `starmetal serve` now builds storage via `OpenDalStorage::from_config`.
- Disabled upstream registries are no longer mounted; disabled routes return normal router `404`.
- Encryption config remains deserializable for compatibility, but `encryption.enabled = true` is rejected for the MVP.
- `sync`, `lock verify`, and `lock update` return controlled not-implemented errors instead of panicking.
- Cached `VersionMetadata` is rechecked against policy before being returned.
- PyPI now falls back from PEP 691 JSON to PEP 503 HTML parsing, including anchors, hash fragments, `data-requires-python`, and `data-yanked`.
- Cargo supports separate sparse index and crate artifact bases through `artifact_url`.
- npm metadata serving validates derived version metadata and preserves raw packument fields and tarball rewriting.
- Hex raw protobuf registry resources are durably cached through `PackageService`.
- `task schema:check` is reproducible and offline; `task schema:check-live` performs explicit live upstream drift checks.
- `task check` now includes live native-client E2E, so it requires network access and installed package-manager CLIs.
- Hex registry checksum parsing now handles signed, gzipped protobuf registry entries.
- Maven path conversion now maps `group.id:artifact` to Maven repository paths and parses checksum sidecar tokens correctly.
- Integration tests isolate package-manager homes and caches with temporary directories.
- Documentation and ADRs now describe MVP reality for auth, rate limiting, encryption, lock/sync workflows, schema provenance, adapter acceptance criteria, OpenDAL storage, and deferred production hardening.
- `.agents/` is ignored by git.
- PyPI, npm, Cargo, and Maven adapters now have initial local hosted publishing routes that write through `PublishingService` and serve the published artifacts through existing native read paths.
- Hex, RubyGems, NuGet, and pub.dev adapters now write local hosted publishes through `PublishingService` and serve those packages through their native read/index routes.
- Cargo `config.json` advertises an API endpoint and `auth-required` when publishing is enabled.
- npm and PyPI read adapters can synthesize local metadata responses from Starmetal-published versions when no raw upstream response exists.
- Cargo dependencies were refreshed with `cargo upgrade --incompatible`; `zip` moved to the latest incompatible major release and the workspace lockfile was regenerated with `cargo update`.
- `starmetal serve` now builds its runtime through the shared operations layer used by CLI and MCP commands.

### Fixed

- Cache hits without `.blake3` sidecars now fail closed instead of serving unverified bytes.
- Upstream artifact hash verification now covers PyPI/Cargo SHA-256, npm SRI and SHA-1, Maven SHA-1/SHA-256, NuGet SHA-512, RubyGems SHA-256, pub.dev archive SHA-256, and Hex outer checksums where available.
- Policy enforcement now applies to cached metadata and adapter-served raw protocol metadata where metadata can be derived.
- Maven repository paths now correctly translate package names from `group_id:artifact_id` to path layout.
- Hex checksum parsing now decodes the signed, gzipped protobuf wrapper used by live `repo.hex.pm`.
- Bundler E2E uses `bundle config set path` for modern Bundler versions.
- `starmetal-server` no longer enables `starmetal-storage` default features implicitly.
- Digest formatting after the `sha1`/`sha2` incompatible updates now uses explicit hex encoding instead of formatter traits removed from the upgraded digest output types.
