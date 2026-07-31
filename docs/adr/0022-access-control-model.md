# ADR-0022: Access Control — Actions, Permission Planes, and Content Selectors

## Status

Proposed

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

- Flat scoped publish/yank/admin tokens (ADR-0011) are the starting point and become one `Authorizer`
  implementation.

## Deferred

- OIDC/SAML/LDAP delegated identity backends (design the port for them now; implement later).
- Forge-delegated identity integration (the standalone-vs-embedded swap) — enabled by this port, not
  built here.
- Full audit logging (OWASP logging) beyond security-event emission.
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
