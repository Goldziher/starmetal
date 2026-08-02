# ADR-0022: Access Control — Actions, Permission Planes, and Content Selectors

## Status

Accepted

## Context

Current auth is a flat bearer-token scheme (ADR-0011: startup requires scoped publish/yank/admin
tokens when publishing is enabled). A universal artifact repository (ADR-0018) used by multiple teams
needs per-repository authorization, service accounts, and content-scoped access. This is also the one
real coupling seam a forge integration would target: research showed the registry↔forge contract
reduces to namespace, identity/token, permission check, and storage — so authorization must be an
injected port, not baked into handlers.

Nexus's model is the reference: a **BREAD** action set (browse, read, edit, add, delete), three
permission planes (content-view, repository-admin, content-selector), and **content selectors** — named
expressions compiled into query predicates so authorization filters what a principal can even list,
enforced in-query rather than per-asset. Gitea and OneDev both resolve all access through a single
`determineAccessMode`/`can_read`/`can_write` seam, confirming authorization belongs behind one port.

## Decision

Define access control as an injected `Authorizer` port in `starmetal-core`, consulted by adapters and
services but implemented outside the domain.

- **Actions:** adopt the BREAD set (`browse`, `read`, `edit`, `add`, `delete`) plus `admin`, as a typed
  action enum (no bare booleans, per rust-conventions).
- **Principals:** users and **service/robot accounts** scoped to a namespace or system-wide, plus API
  tokens with action + ecosystem + repository scopes (superseding the flat token scheme).
- **Permission planes:** separate content-plane access (`RepositoryView`: browse/read/add/edit/delete on
  a repository, wildcardable by ecosystem/name), config-plane access (`RepositoryAdmin`: manage the
  repository), and selector-scoped access (`ContentSelector`).
- **Content selectors:** named expressions over `(ecosystem, path, coordinate)` that both gate access
  and compile to a query-filter predicate pushed into browse/search (ADR-0020). The `Authorizer` port
  returns both a boolean decision and an optional query predicate.
- **Namespaces:** a repository (and its hosted packages) belong to a namespace; the namespace is the
  tenancy boundary and the integration point an external forge/identity provider maps onto. Identity
  can be local (built-in users/tokens) or delegated (OIDC/LDAP, or a forge) by swapping the port
  implementation — the registry runs standalone or embedded without a rewrite.

## Implemented

- `LocalAuthorizer` implements the core `Authorizer` port (with a separate `Authenticator` port for
  identity), deny-by-default, migrating the flat `auth`/`admin`/`publishing` tokens (ADR-0011) into the
  grant model. It is wired into the publish path across all eight adapters and into the admin API.
- A second identity backend proves the `Authenticator` port is a clean seam: `starmetal-oidc`'s
  `OidcAuthenticator` validates OIDC JWT bearer tokens (RS256/ES256, rejecting `alg: none` and HMAC
  algorithms as an algorithm-confusion defense) against a **static** JWKS from config, and is composed
  ahead of the flat-token authenticator via the core `CompositeAuthenticator`. A JWT authenticates via
  OIDC while an unchanged flat token still authenticates via the fallback; authorization (grant
  evaluation) stays on `LocalAuthorizer`. Off by default and gated behind the `oidc` feature, so the
  server behaves exactly as before when unconfigured.
  - **Explicitly out of scope for this stage:** a live IdP integration — no JWKS-URL fetch, OIDC
    discovery, or token refresh. The validator takes a static JWKS from config and performs no network
    I/O. A live-IdP backend slots behind the same `Authenticator` port later.
- Read-path migration off the legacy scheme: `require_bearer_token` (`starmetal-server`'s auth
  middleware) now authenticates the bearer to a `Principal` and requires `Action::Read` through
  `state.authorizer`; the legacy `Config::authorize_bearer_token`/`authorize_admin_token` path it
  replaced no longer exists in `starmetal-core::config`. Every decision emits a structured `tracing`
  event on the `starmetal::audit` target (`debug` on allow, `warn` on deny) — read and admin decisions
  are both audited (OWASP A09).
- Content-selector push-down: `QueryPredicate` (`starmetal-core::authz`) compiles to a parameterized
  Postgres `WHERE` fragment (`starmetal-metadata::predicate_sql::compile`, every value bound as `$n`,
  never interpolated). `GET /api/v1/components` (`starmetal-server::browse`) authorizes `Action::Browse`
  and pushes the returned predicate into the metadata store, so a scoped principal receives a scoped
  listing filtered in-query rather than post-filtered.

## Deferred

- Live-IdP OIDC (JWKS-URL fetch, OIDC discovery, token refresh) and SAML/LDAP delegated identity
  backends. The offline static-JWKS OIDC backend above lands the port; these extend it.
- Forge-delegated identity integration (the standalone-vs-embedded swap) — enabled by this port, not
  built here.
- A scoped, read-capable download-authorization surface — browse push-down proves the selector model
  end-to-end at the authorization and database layers, but per-artifact download gating by selector is
  not wired.
- Full audit logging (OWASP logging) beyond the structured allow/deny events emitted today.
- A management UI for roles/permissions; TOML/admin-API configuration first.

## Consequences

- Authorization is a port; the domain and adapters depend on the trait, not an implementation
  (hexagonal-boundaries). This is what makes standalone and forge-embedded deployments the same code.
- Content selectors require the metadata store (ADR-0020) to accept a pushed-down predicate; the model
  is designed for this from the start even though selectors ship after basic RBAC.
- Deny-by-default: every content and admin request is authorized (OWASP broken-access-control); missing
  authorization is a denied request, not an allowed one.
- Service accounts and scoped tokens replace the flat token scheme; migration keeps existing tokens
  working as a coarse `RepositoryView` grant until reconfigured.
