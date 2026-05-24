# ADR-0002: Tower Middleware for Cross-Cutting Concerns

## Status

Accepted

## Context

Cross-cutting concerns — authentication, authorization, rate limiting, request tracing,
compression, integrity headers — must apply uniformly across all protocol adapters without
duplicating logic in each adapter.

## Decision

We use Tower's `Layer`/`Service` abstraction to compose middleware. The stack is assembled in `depot-server/src/app.rs` and wraps all adapter routes.

MVP middleware stack (outermost first):

1. **TraceLayer** — structured request/response logging via `tracing`
2. **CorsLayer** — required for npm web clients and browser-based tooling
3. **Auth** — optional bearer token validation when `auth.enabled = true`
4. **CompressionLayer** — response compression (gzip, brotli, zstd)

Rate limiting and integrity response headers are deferred production-hardening
features. They are not part of the MVP middleware stack.

Protocol adapters are mounted as nested axum routers under path prefixes (`/pypi`, `/npm`,
`/cargo`, `/hex`, `/maven`, `/rubygems`, `/nuget`, `/pub`).

Publishing routes add write authorization requirements. Read routes keep the existing optional
bearer-token behavior. Write routes must extract native client credentials and resolve them to scoped
Depot tokens before the adapter calls publishing services. Supported extraction forms include:

- Bearer-style tokens where native clients send bearer or raw authorization headers.
- Basic authentication for clients such as twine and Maven.
- API-key headers such as RubyGems `Authorization` and NuGet `X-NuGet-ApiKey`.
- Ecosystem-specific token conventions used by npm, Cargo, Hex, and pub.dev clients.

The middleware layer performs credential extraction and request-scoped auth context creation.
Adapters remain responsible for native protocol parsing, and `depot-service` remains responsible for
publish-policy enforcement.

## Consequences

- All cross-cutting logic is defined once and applies to every adapter.
- Middleware ordering is explicit and documented.
- Individual adapters remain focused on protocol translation.
- Tower's `Service` trait composes well with axum's router, avoiding framework lock-in for the middleware implementations themselves.
- Publishing authorization can evolve without duplicating token parsing and scope checks in every
  adapter.
