# ADR-0011: Private MVP Support Matrix

## Status

Accepted

## Context

Starmetal has implementation for more registries than the private MVP should claim as supported. The
project needs one source of truth for README, architecture, deployment, and ADR language.

## Decision

Starmetal's MVP is private/internal. Support claims are limited to read workflows and require fresh live
native-client E2E evidence.

| Registry | Default route enablement | Read status | Write status |
|----------|--------------------------|-------------|--------------|
| PyPI | Enabled | MVP read candidate after live E2E | Native publishing out of MVP |
| npm | Enabled | MVP read candidate after live E2E | Native publishing out of MVP |
| Cargo | Enabled | MVP read candidate after live E2E | Native publishing out of MVP |
| Hex | Enabled | MVP read candidate after live E2E | Native publishing out of MVP |
| Maven | Disabled | Opt-in beta | Native publishing out of MVP |
| RubyGems | Disabled | Opt-in beta | Native publishing out of MVP |
| NuGet | Disabled | Opt-in beta | Native publishing out of MVP |
| pub.dev | Disabled | Opt-in beta | Native publishing out of MVP |

Local publishing is experimental for all ecosystems. It is disabled by default, requires scoped
publishing tokens when enabled, and must not be described as native publishing support.

## Promotion Criteria

To promote a read workflow into MVP-ready documentation, the registry must have:

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

- README and architecture support tables must use this ADR.
- Beta adapters can stay compiled in full builds without becoming MVP-supported.
- Tests may exist before support claims, but docs must label those paths accurately.
