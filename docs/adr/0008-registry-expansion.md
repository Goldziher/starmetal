# ADR-0008: Registry Expansion Order and Compatibility Bar

## Status

Superseded by [ADR-0011](0011-mvp-support-matrix.md)

## Context

This ADR recorded an expansion order for registries beyond PyPI, npm, Cargo, and Hex. That order no
longer reflects the private MVP readiness plan.

## Superseded Decision

Do not use this ADR to make support claims.

ADR-0011 replaces the expansion order with a support matrix that distinguishes:

- Private/internal MVP scope.
- MVP read candidates pending live E2E.
- Opt-in beta read adapters.
- Experimental local publishing.
- Native publishing outside MVP.

## Consequences

- Existing implementation may include adapters listed here, but support status is governed by
  ADR-0011.
- Documentation must not describe Maven, RubyGems, NuGet, or pub.dev as MVP-supported by default.
