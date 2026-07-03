# ADR-0009: Publishing and Upload Workflows

## Status

Accepted for direction; production support deferred

## Context

Publishing has a larger blast radius than pull-through reads. It accepts untrusted archives, mutates
metadata, requires write authorization, and has ecosystem-specific failure modes.

The product is experimental and read/proxy focused. Native publishing is unsupported. Local
publishing exists only as experimental plumbing for internal validation and operator workflows.

## Decision

Starmetal separates three concepts:

| Concept | Position |
|---------|--------------|
| Pull-through reads | Experimental core capabilities, per ADR-0011 |
| Local publishing | Experimental, disabled by default |
| Native publishing support | Unsupported |

Implemented local publishing behavior:

- `PublishingService` stores locally published metadata and artifacts.
- `publishing.enabled` defaults to `false`.
- Startup validation requires at least one scoped publish, yank, or admin token when publishing is
  enabled.
- Versions are immutable by default unless `allow_overwrite = true`.
- Shadowing upstream package versions is blocked by default unless `allow_shadowing = true`.
- CLI and MCP can publish one explicit artifact when publishing is enabled.
- MCP mutating tools require `sm mcp serve --allow-writes`.
- Deterministic Docker pnpm E2E proves local npm publishing can publish a fixture package into
  Starmetal and install it back through Starmetal.
- Local RubyGems publishing writes Bundler-compatible Compact Index metadata:
  `/versions` includes the per-gem info checksum and `/info/<gem>` uses `|checksum:<sha256>`.
- Native upload routes call `PublishingService` when publishing is enabled, but these routes are
  experimental and do not create a native publishing support claim.

Local publish substrate by ecosystem:

| Ecosystem | Local route substrate | Position |
|-----------|-----------------------|----------|
| PyPI | `/legacy/` multipart upload | Experimental local only |
| npm | `PUT /{package}` and scoped package routes | Experimental local only |
| Cargo | `/api/v1/crates/new` | Experimental local only |
| Hex | `/api/packages` | Experimental local only |
| Maven | `PUT /{path}` deploy-style uploads | Experimental local only |
| RubyGems | `/api/v1/gems` | Experimental local only |
| NuGet | `/api/v2/package` | Experimental local only |
| pub.dev | `/api/packages/versions/new` | Experimental local only |

## Implemented

- Local publish metadata and artifact writes.
- Blake3 sidecars for published artifacts.
- Scoped publish token config with ecosystem and package constraints.
- CLI explicit artifact publish.
- MCP explicit artifact publish behind `--allow-writes`.
- Route-level experimental publish parsing for all eight implemented ecosystems.
- Docker pnpm local npm publish-then-install evidence.
- Bundler-compatible local RubyGems Compact Index metadata generation.
- Yank and unyank service operations for locally known versions.

## Deferred

- Native publishing support claims.
- Upstream publish forwarding.
- Full identity, owners, invitations, organizations, and audit logging.
- Native yanking/unlisting parity for every ecosystem.
- Search and administration APIs.
- Maven `SNAPSHOT` semantics beyond current experimental local behavior.

## Consequences

- Documentation must say "experimental local publishing" unless a later ADR changes support status.
- Read readiness does not imply write readiness.
- Route-level publish parsing and local metadata generation do not imply native package-manager
  publishing support.
- Any future publishing support requires native-client E2E coverage, documented failure semantics,
  and credential behavior per ecosystem.
- Per-ecosystem native publishing promotion requires native client publish, fresh install or restore
  through Starmetal, restart with persisted storage, cached reinstall or restore with fixture upstream
  offline where applicable, auth behavior coverage, duplicate and shadowing failure coverage,
  rollback or cleanup behavior, and exact documented client commands.
