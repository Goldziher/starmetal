# ADR-0014: Management Admin Surface

## Status

Accepted

## Context

Starmetal needs operator visibility without turning the private experimental proxy into a public
administration product. CLI and MCP already cover local operations, but containerized deployments
need a remote management surface for status, redacted config, registry inventory, package cache
inspection, and statistics.

A browser admin UI is useful, but adding it before the API, authentication, metrics, and Docker
package-manager workflows are stable would expand the MVP too far.

## Decision

MVP management is an authenticated JSON API, not a browser frontend.

Implemented admin API:

| Route | Purpose |
|-------|---------|
| `GET /admin/api/v1/status` | Version, storage backend, feature state, and registry status |
| `GET /admin/api/v1/config` | Redacted effective config |
| `GET /admin/api/v1/registries` | Configured, enabled, and compiled registry status |
| `GET /admin/api/v1/packages?ecosystem=...` | Cached packages for one ecosystem |
| `GET /admin/api/v1/versions?ecosystem=...&name=...` | Versions for one package |
| `GET /admin/api/v1/metadata?ecosystem=...&name=...&version=...` | Version metadata |
| `GET /admin/api/v1/metrics` | In-memory operational statistics |

Admin API configuration:

```toml
[admin]
enabled = false
tokens = []
```

When enabled, at least one admin token is required. Admin routes require
`Authorization: Bearer <admin-token>` and are not mounted when disabled. Admin tokens also satisfy
server read auth for admin routes when global read auth is enabled.

Future browser UI direction:

- Use Next.js, TypeScript, shadcn/ui, and Tailwind by default.
- Build the UI against `/admin/api/v1/*`.
- Ship it only after the admin API, auth, metrics, and deterministic Docker install/publish evidence
  are stable.

## Deferred

- Browser admin frontend.
- Config editing through the admin API.
- Token management through the admin API.
- Destructive cache operations through the admin UI.
- Remote audit log browsing.
- Multi-user identity, RBAC, sessions, and organizations.

## Consequences

- The MVP gains remote operational visibility without a separate frontend project.
- Documentation must describe the admin API as private deployment tooling.
- Any future UI must stay behind the admin API and must not bypass core service boundaries.
