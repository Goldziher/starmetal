# ADR-0009: Publishing and Upload Workflows

## Status

Accepted for direction; MVP support deferred

## Context

Publishing has a larger blast radius than pull-through reads. It accepts untrusted archives, mutates
metadata, requires write authorization, and has ecosystem-specific failure modes.

The private MVP is read-focused. Native publishing is out of MVP. Local publishing exists only as
experimental plumbing for internal validation and operator workflows.

## Decision

Starmetal separates three concepts:

| Concept | MVP position |
|---------|--------------|
| Pull-through reads | Private MVP read candidates or opt-in beta, per ADR-0011 |
| Local publishing | Experimental, disabled by default |
| Native publishing support | Out of MVP |

Implemented local publishing behavior:

- `PublishingService` stores locally published metadata and artifacts.
- `publishing.enabled` defaults to `false`.
- Startup validation requires at least one scoped publish, yank, or admin token when publishing is
  enabled.
- Versions are immutable by default unless `allow_overwrite = true`.
- Shadowing upstream package versions is blocked by default unless `allow_shadowing = true`.
- CLI and MCP can publish one explicit artifact when publishing is enabled.
- MCP mutating tools require `sm mcp serve --allow-writes`.
- Native upload routes call `PublishingService` when publishing is enabled, but these routes are
  experimental and do not create an MVP support claim.

## Implemented

- Local publish metadata and artifact writes.
- Blake3 sidecars for published artifacts.
- Scoped publish token config with ecosystem and package constraints.
- CLI explicit artifact publish.
- MCP explicit artifact publish behind `--allow-writes`.
- Route-level experimental publish parsing for multiple ecosystems.
- Yank and unyank service operations for locally known versions.

## Deferred

- Native publishing support claims.
- Native publish-then-install E2E promotion criteria.
- Upstream publish forwarding.
- Full identity, owners, invitations, organizations, and audit logging.
- Native yanking/unlisting parity for every ecosystem.
- Search and administration APIs.
- Maven `SNAPSHOT` semantics beyond current experimental local behavior.

## Consequences

- Documentation must say "experimental local publishing" unless a later ADR changes support status.
- Read readiness does not imply write readiness.
- Any future publishing support requires native-client E2E coverage, documented failure semantics,
  and credential behavior per ecosystem.
