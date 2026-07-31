# ADR-0021: Native Hosted Publishing

## Status

Proposed

## Context

ADR-0009 established experimental local publishing: per-ecosystem upload routes exist behind
`publishing.enabled = false`, write to a `PublishingService`, and make no native support claim.
A universal artifact repository (ADR-0018) requires hosted repositories (ADR-0019) to be a **supported**
place teams publish to, which is the primary capability gap versus Artifactory/Nexus and the
prerequisite for any future forge integration (a forge needs a publish-capable registry).

The inspected codebases share one publish design: a **generic upload handler SPI** where each
ecosystem declares the coordinate fields it needs and validates the upload, while storage, dedup,
indexing, and integrity are shared. Nexus's `UploadHandler`/`UploadDefinition`, Gitea's single
`CreatePackageAndAddFile` write path guarded by a per-`(type,name,version)` named lock with
compensating blob delete on failure, and OneDev's `PackHandler` all follow this shape.

## Decision

Promote hosted publishing to a first-class, per-ecosystem-gated capability built on the content model
(ADR-0020) and the `HostedFacet` (ADR-0019).

- **Generic publish SPI:** one shared publish path (evolving `PublishingService`) performs
  authorization (ADR-0022), coordinate validation via a per-ecosystem `UploadDefinition`, streaming
  hash-once buffering, `get-or-insert` blob by Blake3 digest, asset/component upsert, index update, and
  policy enforcement (ADR-0024). Ecosystem adapters implement only parsing/coordinate-mapping and
  wire-protocol responses.
- **Concurrency and consistency:** wrap the metadata transaction in a named lock keyed on
  `(ecosystem, name, version)` and, on failure after a blob write, compensate by deleting the
  just-written blob — matching Gitea's proven pattern, avoiding distributed transactions across DB and
  object store.
- **Immutability and shadowing:** versions are immutable by default (`allow_overwrite = false`);
  shadowing an upstream version in a group is blocked by default (`allow_shadowing = false`), carried
  forward from ADR-0009.
- **Quotas:** enforce per-namespace count/size and per-ecosystem size limits with a reserve-before-write,
  reconcile-after-success two-phase check (Harbor's quota pattern).
- **Promotion, not reclassification:** this ADR keeps ADR-0009's per-ecosystem native-publish
  promotion gates. Native publishing for an ecosystem is supported only when it meets those gates
  (native client publish, install/restore through Starmetal, restart with persisted storage, cached
  reinstall with fixture upstream offline, auth/duplicate/shadowing/rollback coverage, documented
  client commands).

## Implemented

- Experimental local-publish substrate for all eight ecosystems (ADR-0009) is the starting point; this
  ADR restructures it onto the shared SPI and content model.

## Deferred

- Native support claims per ecosystem until each meets ADR-0009/ADR-0011 promotion gates.
- Staging/promotion pipelines between repositories (build-promotion workflows).
- Upstream publish forwarding.
- Full owner/organization/audit surfaces beyond the access-control model in ADR-0022.

## Consequences

- Hosted repositories become the supported publish target once per-ecosystem gates pass; until then
  they remain experimental per ADR-0011.
- Publishing shares one authorization, integrity, quota, and policy path with pull-through, reducing
  per-ecosystem surface to protocol translation.
- Read readiness still does not imply write readiness; each ecosystem is promoted independently with
  native-client E2E evidence.
