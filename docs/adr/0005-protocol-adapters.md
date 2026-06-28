# ADR-0005: Protocol Adapters as Axum Routers

## Status

Accepted

## Context

Starmetal must speak native registry protocols so existing package-manager clients can read through a
private cache without client-side plugins.

Support status is separate from implementation existence. An adapter can exist, compile, and have
tests while still being a private MVP candidate or opt-in beta.

## Decision

Each protocol adapter is an axum `Router` in `depot-adapters`.

Implemented adapters:

| Feature | Prefix | Protocol | MVP position |
|---------|--------|----------|--------------|
| `pypi` | `/pypi` | PyPI Simple Repository API, PEP 503/691 | Read candidate after live E2E |
| `npm` | `/npm` | npm registry API | Read candidate after live E2E |
| `cargo-registry` | `/cargo` | Cargo sparse index | Read candidate after live E2E |
| `hex` | `/hex` | Hex API and registry proxy | Read candidate after live E2E |
| `maven` | `/maven` | Maven repository layout | Opt-in beta |
| `rubygems` | `/rubygems` | RubyGems Compact Index | Opt-in beta |
| `nuget` | `/nuget` | NuGet V3 restore API | Opt-in beta |
| `pub` | `/pub` | Hosted Pub Repository v2 | Opt-in beta |

Each adapter owns:

- Native route parsing and response formatting.
- An ecosystem-specific `Has*State` trait.
- An upstream client when pull-through reads need network access.
- Schema or protocol provenance for the registry surfaces it models.

## Implemented

- Pull-through read routes for all eight adapters behind feature flags.
- Runtime default enablement for PyPI, npm, Cargo, and Hex.
- Runtime default disablement for Maven, RubyGems, NuGet, and pub.dev.
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

A read adapter can be documented as MVP-ready only when it has:

1. Source linkage in `schemas/sources.toml`.
2. Fixture or route conformance coverage.
3. Live native-client E2E evidence for the claimed workflow.
4. Accurate README and deployment documentation.

Publishing cannot be documented as supported until a later ADR scopes native publish behavior,
credential semantics, failure modes, and native publish-then-install E2E evidence.

## Consequences

- Adapters remain self-contained protocol edges.
- Shared cache, policy, integrity, and local publish behavior stays in `depot-service`.
- Feature flags and runtime upstream settings must both be considered when describing support.
