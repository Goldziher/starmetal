# ADR-0002: Tower Middleware for Cross-Cutting Concerns

## Status

Accepted

## Context

Depot serves several native registry protocols through one HTTP server. Cross-cutting behavior must
be applied consistently while adapters remain focused on protocol translation.

The private MVP is read-focused. Write routes exist for experimental local publishing, but native
publishing is not an MVP support claim.

## Decision

`depot-server` composes the axum application with Tower middleware in `crates/depot-server/src/app.rs`.

Implemented stack, from request entry inward:

| Layer | Implemented behavior |
|-------|----------------------|
| `TraceLayer` | Structured request tracing |
| `CorsLayer::permissive()` | Broad CORS policy for MVP development and local clients |
| Bearer auth middleware | Optional read-token enforcement when `auth.enabled = true` |
| `CompressionLayer` | Response compression |

Adapter routers are mounted by feature flag and runtime upstream enablement:

| Prefix | Runtime default | MVP position |
|--------|-----------------|--------------|
| `/pypi` | Enabled | Read candidate after live E2E |
| `/npm` | Enabled | Read candidate after live E2E |
| `/cargo` | Enabled | Read candidate after live E2E |
| `/hex` | Enabled | Read candidate after live E2E |
| `/maven` | Disabled | Opt-in beta |
| `/rubygems` | Disabled | Opt-in beta |
| `/nuget` | Disabled | Opt-in beta |
| `/pub` | Disabled | Opt-in beta |

## Implemented

- Optional bearer-token auth for server requests.
- Runtime route mounting based on `Config::upstream_enabled`.
- Compression, tracing, and permissive CORS.
- Experimental write-route token checks inside adapters against scoped publishing tokens.

## Deferred

- Production CORS allowlist configuration.
- Rate limiting.
- Integrity response headers beyond ecosystem-native metadata.
- Central middleware-owned scoped write authorization.
- Remote admin authentication and authorization.

## Consequences

- Read middleware behavior is uniform across adapters.
- Write authorization is currently adapter-owned because native credential shapes differ.
- The permissive CORS policy must be tightened before any non-private deployment.
