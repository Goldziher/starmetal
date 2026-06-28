# ADR-0005: Protocol Adapters as Axum Routers

## Status

Accepted

## Context

Starmetal must speak native registry protocols so existing package-manager clients can read through a
private cache without client-side plugins.

Support status is separate from implementation existence. An adapter can exist, compile, and have
tests while still being experimental.

## Decision

Each protocol adapter is an axum `Router` in `starmetal-adapters`.

Implemented adapters:

| Feature | Prefix | Protocol | Status |
|---------|--------|----------|--------------|
| `pypi` | `/pypi` | PyPI Simple Repository API, PEP 503/691 | Experimental core |
| `npm` | `/npm` | npm registry API | Experimental core |
| `cargo-registry` | `/cargo` | Cargo sparse index | Experimental core |
| `hex` | `/hex` | Hex API and registry proxy | Experimental core |
| `maven` | `/maven` | Maven repository layout | Experimental core |
| `rubygems` | `/rubygems` | RubyGems Compact Index | Experimental core |
| `nuget` | `/nuget` | NuGet V3 restore API | Experimental core |
| `pub` | `/pub` | Hosted Pub Repository v2 | Experimental core |

Each adapter owns:

- Native route parsing and response formatting.
- An ecosystem-specific `Has*State` trait.
- An upstream client when pull-through reads need network access.
- Schema or protocol provenance for the registry surfaces it models.

## Implemented

- Pull-through read routes for all eight adapters behind feature flags.
- Runtime default enablement for all implemented adapters.
- Route-level conformance and ignored live E2E tests.
- Raw upstream response preservation where native fields would be lost by domain conversion.
- npm packument handling with raw `serde_json::Value`.
- Hex protobuf registry proxy for mix checksum behavior.
- Experimental local publish route plumbing when `publishing.enabled = true`.

## Deferred

- Public support claims for read paths before live native-client E2E passes.
- Native publishing support.
- Search APIs.
- Owner, organization, invitation, and admin APIs.
- Cross-registry sharing of protocol-specific logic.

## Compatibility Rules

Read compatibility and write compatibility are separate claims.

A read adapter can be documented beyond experimental only when it has:

1. Source linkage in `schemas/sources.toml`.
2. Fixture or route conformance coverage.
3. Live native-client E2E evidence for the claimed workflow.
4. Accurate README and deployment documentation.

Publishing cannot be documented as supported until a later ADR scopes native publish behavior,
credential semantics, failure modes, and native publish-then-install E2E evidence.

## Consequences

- Adapters remain self-contained protocol edges.
- Shared cache, policy, integrity, and local publish behavior stays in `starmetal-service`.
- Feature flags and runtime upstream settings must both be considered when describing support.
