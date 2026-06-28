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

| Registry | Default route enablement | Read/proxy status | Write status |
|----------|--------------------------|-------------------|--------------|
| PyPI | Enabled | Experimental core capability | Native publishing not supported |
| npm | Enabled | Experimental core capability | Native publishing not supported |
| Cargo | Enabled | Experimental core capability | Native publishing not supported |
| Hex | Enabled | Experimental core capability | Native publishing not supported |
| Maven | Enabled | Experimental core capability | Native publishing not supported |
| RubyGems | Enabled | Experimental core capability | Native publishing not supported |
| NuGet | Enabled | Experimental core capability | Native publishing not supported |
| pub.dev | Enabled | Experimental core capability | Native publishing not supported |

Planned registry work includes OCI/distribution, Go modules, Composer, Conda, Debian/APT, and
RPM/YUM. Planned registries must not be described as implemented until adapters, upstream clients,
fixtures, and route coverage exist.

## Promotion Criteria

Before describing any workflow as ready beyond experimental, the registry must have:

1. Feature-gated adapter and runtime route.
2. Source provenance in `schemas/sources.toml`.
3. Schema or protocol evidence in `schemas/manifest.json`.
4. Offline conformance tests.
5. Fresh live native-client E2E pass for the documented workflow.
6. README and deployment documentation that match the exact supported client command.

To promote native publishing in a future ADR, the registry must also have:

1. Native upload and mutation source provenance.
2. Route-level publish conformance tests.
3. Native publish-then-install or publish-then-restore E2E tests.
4. Documented duplicate, shadowing, auth, rollback, and failure semantics.

## Consequences

- README, architecture, deployment, and AI instruction sources must use this ADR.
- All current registry adapters are core experimental capabilities, not production support claims.
- Tests may exist before support claims, but docs must label those paths accurately.
