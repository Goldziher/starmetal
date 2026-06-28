# ADR-0002: Tower Middleware for Cross-Cutting Concerns

## Status

Accepted

## Context

Starmetal serves several native registry protocols through one HTTP server. Cross-cutting behavior must
be applied consistently while adapters remain focused on protocol translation.

The product is experimental and read/proxy focused. Write routes exist for experimental local
publishing, but native publishing is not supported.

## Decision

`starmetal-server` composes the axum application with Tower middleware in `crates/starmetal-server/src/app.rs`.

Implemented stack, from request entry inward:

| Layer | Implemented behavior |
|-------|----------------------|
| `TraceLayer` | Structured request tracing |
| `CorsLayer::permissive()` | Broad CORS policy for experimental development and local clients |
| Bearer auth middleware | Optional read-token enforcement when `auth.enabled = true` |
| `CompressionLayer` | Response compression |

Adapter routers are mounted by feature flag and runtime upstream enablement:

| Prefix | Runtime default | Status |
|--------|-----------------|--------------|
| `/pypi` | Enabled | Experimental core |
| `/npm` | Enabled | Experimental core |
| `/cargo` | Enabled | Experimental core |
| `/hex` | Enabled | Experimental core |
| `/maven` | Enabled | Experimental core |
| `/rubygems` | Enabled | Experimental core |
| `/nuget` | Enabled | Experimental core |
| `/pub` | Enabled | Experimental core |

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
