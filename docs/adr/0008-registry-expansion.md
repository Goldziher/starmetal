# ADR-0008: Registry Expansion Order and Compatibility Bar

## Status

Superseded by [ADR-0011](0011-mvp-support-matrix.md)

## Context

This ADR recorded an expansion order for registries beyond PyPI, npm, Cargo, and Hex. That order no
longer reflects the experimental support plan.

## Superseded Decision

Do not use this ADR to make support claims.

ADR-0011 replaces the expansion order with a support matrix that distinguishes:

- Private/internal experimental scope.
- Experimental core registry read/proxy adapters.
- Planned registry adapters.
- Experimental local publishing.
- Native publishing as unsupported.

## Consequences

- Existing implementation may include adapters listed here, but support status is governed by
  ADR-0011.
- Documentation must not describe any registry as production-supported until the relevant live E2E
  and promotion criteria are satisfied.
