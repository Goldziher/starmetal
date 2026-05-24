# ADR-0009: Publishing and Upload Workflows

## Status

Accepted

## Context

Depot currently acts as a pull-through registry cache. Native package clients can install and restore
through Depot, but publish, upload, yank, unlist, relist, and revert workflows are not implemented.

Full publishing support has a larger blast radius than pull-through reads. Upload routes accept
untrusted archive bytes, mutate registry indexes, require write authorization, and may optionally
forward package releases to public or upstream registries. Each ecosystem also has a different
native write protocol: PyPI uses the legacy multipart upload API, npm uses registry document writes,
Cargo uses the Registry Web API, Hex uses Hex API publishing, Maven uses repository-layout HTTP
PUTs, RubyGems posts built `.gem` files, NuGet uses the `PackagePublish` resource, and pub.dev uses
the Hosted Pub Repository protocol.

## Decision

Depot will support publishing in two modes:

1. **Local hosted publishing** — Depot accepts uploads, stores them in OpenDAL, updates local
   registry metadata, and serves them to native clients.
2. **Explicit upstream forwarding** — Depot may forward accepted uploads to an upstream registry
   only when forwarding is enabled for that ecosystem and credentials are configured outside the
   static config file.

Local hosted publishing is the default. Upstream forwarding is opt-in.

Publishing scope for the first implementation includes:

- New package/version upload through native package-manager clients.
- Yank, unyank, unlist, relist, or revert operations where the native protocol requires them for
  credible private registry behavior.
- Native install/restore/fetch of locally published artifacts after upload.

The first implementation does not include a full user, owner, invitation, organization, search, or
administrative platform. All write routes require scoped tokens. Token scopes must distinguish at
least `read`, `publish`, `yank`, and `admin`, and may be constrained to specific ecosystems or
package-name allowlists.

Safety defaults:

- Package versions are immutable by default after successful publish.
- Maven `SNAPSHOT` handling is the only planned mutable-version exception.
- Shadowing an upstream package/version is disabled by default to reduce dependency-confusion risk.
- Config may name environment variables for upstream credentials, but must not contain upstream
  secret values.
- Upload parsing and validation must reject malformed archives and inconsistent metadata before
  storing them as published releases.

Persistence:

- OpenDAL remains the storage abstraction.
- Published artifacts, generated metadata, native indexes, and forwarding status are stored under
  reserved Depot-owned keys.
- Storage remains an opaque byte/key port; registry-specific index mutation lives above storage.
- Index updates must be designed for object stores and filesystems without database transactions.

Architecture boundaries:

- `depot-core` owns publish domain types, policy inputs, and publish/write port traits.
- Protocol adapters parse native upload requests and format native responses.
- `depot-service` owns shared publishing workflow: authorization result consumption, duplicate and
  shadowing checks, integrity computation, policy checks, storage writes, metadata/index updates,
  and optional upstream forwarding orchestration.
- Protocol adapters must not write storage directly.
- Storage backends must not contain registry-specific behavior.

## Consequences

- Read support and write support are separate compatibility claims. A registry can remain
  pull-through supported while publishing support is still incomplete.
- Every publishing adapter needs source linkage, route-level conformance tests, native-client
  publish/install E2E tests, and documented failure semantics before Depot documentation can claim
  write compatibility for that registry.
- Upstream forwarding introduces partial-failure states. Local hosted publishing must remain useful
  when forwarding is disabled or fails in an explicitly local-and-forward mode.
- The scoped-token model is intentionally smaller than a full identity platform, but it creates a
  clear upgrade path for future users, owners, organizations, OIDC, and audit logging.
