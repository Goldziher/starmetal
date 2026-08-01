# ADR-0011: Experimental Support Matrix

## Status

Accepted

## Context

Starmetal currently implements several registry read/proxy adapters, but the whole product remains
experimental. Documentation needs one source of truth that distinguishes implemented experimental
capability from production-ready support.

## Decision

All implemented registry read/proxy adapters are core experimental capabilities and are enabled by
default in runtime config. Native publishing is not supported. Local publishing is experimental,
disabled by default, and requires explicit scoped tokens when enabled.

| Registry | Default route enablement | Read/proxy status | Local publish substrate | Native publish status | Evidence |
|----------|--------------------------|-------------------|-------------------------|-----------------------|----------|
| PyPI | Enabled | Experimental core capability | Experimental, disabled by default | Not supported | HTTP route conformance and Docker proxy E2E |
| npm | Enabled | Experimental core capability | Experimental, disabled by default | Not supported | HTTP/native Docker proxy E2E plus pnpm local publish-then-install |
| Cargo | Enabled | Experimental core capability | Experimental, disabled by default | Not supported | HTTP route conformance and Docker proxy E2E |
| Hex | Enabled | Experimental core capability | Experimental, disabled by default | Not supported | HTTP/protobuf route conformance and Docker proxy E2E |
| Maven | Enabled | Experimental core capability | Experimental, disabled by default | Not supported | HTTP route conformance and Docker proxy E2E |
| RubyGems | Enabled | Experimental core capability | Experimental, disabled by default | Not supported | HTTP/native Docker proxy E2E |
| NuGet | Enabled | Experimental core capability | Experimental, disabled by default | Not supported | HTTP/native Docker proxy E2E |
| pub.dev | Enabled | Experimental core capability | Experimental, disabled by default | Not supported | HTTP/native Docker proxy E2E |

Planned registry work includes OCI/distribution, Go modules, Composer, Conda, Debian/APT, and
RPM/YUM. Planned registries must not be described as implemented until adapters, upstream clients,
fixtures, and route coverage exist.

Supply-chain vulnerability scanning (ADR-0024), access control (ADR-0022), and the metadata content
model (ADR-0020) are experimental cross-cutting capabilities gated by feature flags and config, not
per-ecosystem read/publish promotions in this matrix.

Deterministic Docker proxy E2E is required evidence for the experimental read/proxy matrix. It uses
local fixture upstreams and disposable client containers to prove route behavior, Docker
configuration, OpenDAL filesystem storage, cache persistence, and restart behavior without public
registry network access. The native-client Docker pass covers PyPI, npm, Cargo, Maven, RubyGems,
NuGet, and pub.dev; Hex is covered at the HTTP and protobuf route level, with native Mix coverage
remaining live/deferred until a local signed fixture registry is proven.

The npm Docker evidence includes pnpm read-through behavior: `pnpm add` writes `package.json` and
`pnpm-lock.yaml`, Starmetal persists the tarball and raw packument, and a second install with a fresh
pnpm store succeeds after the fixture upstream is stopped. Experimental local npm publishing also has
Docker pnpm publish-then-install evidence, but this remains a local publishing claim only.

## Promotion Criteria

Before describing any workflow as ready beyond experimental, the registry must have:

1. Feature-gated adapter and runtime route.
2. Source provenance in `schemas/sources.toml`.
3. Schema or protocol evidence in `schemas/manifest.json`.
4. Offline conformance tests.
5. Deterministic Docker proxy E2E for container, config, storage, cache, and restart behavior.
6. Fresh live native-client E2E pass for the documented workflow.
7. README and deployment documentation that match the exact supported client command.

To promote native publishing in a future ADR, the registry must also have:

1. Native upload and mutation source provenance.
2. Route-level publish conformance tests.
3. Native publish-then-install or publish-then-restore E2E tests.
4. Documented duplicate, shadowing, auth, rollback, and failure semantics.

Native publish promotion gates are per ecosystem:

| Ecosystem | Required native publish evidence before support claim |
|-----------|-------------------------------------------------------|
| PyPI | `twine` upload plus `pip` install after restart and fixture-upstream shutdown |
| npm/pnpm | Native publish plus npm/pnpm install after restart and fixture-upstream shutdown |
| Cargo | `cargo publish` plus fetch/install workflow after restart and fixture-upstream shutdown |
| Hex | `mix hex.publish` against valid signed registry resources |
| Maven | Native deploy plus Maven restore after restart and fixture-upstream shutdown |
| RubyGems | `gem push` plus Bundler install after restart and fixture-upstream shutdown |
| NuGet | `dotnet nuget push` plus restore after restart and fixture-upstream shutdown |
| pub.dev | Hosted publish upload-info/finalize flow plus Dart install after restart |

Signing support follows the same evidence rule. Configured Ed25519 Starmetal DSSE sidecars are
experimental. Protocol-native signing, PQ signing, and client-verified PQ support are planned only
until protocol clients verify them in deterministic tests.

## Consequences

- README, architecture, deployment, and AI instruction sources must use this ADR.
- All current registry adapters are core experimental capabilities, not production support claims.
- Tests may exist before support claims, but docs must label those paths accurately.
