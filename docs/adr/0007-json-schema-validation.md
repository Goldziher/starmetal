# ADR-0007: Registry Schema Provenance and JSON Schema Validation

## Status

Accepted

## Context

Depot proxies four different registry protocols, each with its own response format. Official registry
contracts are rarely published as JSON Schema. Depending on the ecosystem, the source of truth may
be prose specifications, protobuf definitions, XML Schema, OpenAPI documents, implementation source,
JSON examples, or a combination of these. When Depot generates JSON Schema for such protocols, that
schema is a Depot-owned validation artifact, not the upstream protocol authority.

We need to:

1. Define Rust types that match the official registry contracts
2. Validate representative upstream responses and schema files in tests
3. Provide canonical JSON Schema files for external tooling and documentation
4. Preserve the source linkage and interpretation rules used to derive each schema

## Decision

Depot-maintained schemas must document provenance alongside the generated or hand-maintained JSON
Schema files. For each registry schema, documentation must identify:

- The official source document, repository, file, or endpoint used as the authority
- The source format, such as JSON Schema, prose specification, protobuf, XML Schema, or OpenAPI
- Any Depot interpretation required when the official contract is incomplete or spread across
  multiple sources
- The conformance tests or fixtures that prove Depot still matches the documented source
- Whether a JSON Schema file is official upstream material or Depot-derived

We use two complementary crates for JSON Schema generation and validation:

- **`schemars`** — derive `JsonSchema` on Rust types to generate JSON Schema definitions.
  Hand-written Rust types are the implementation source of truth for Depot-owned shapes. Registry
  schemas generated this way must be marked `depot-derived-json-schema` and must link back to the
  official registry source they model.
- **`jsonschema`** — validate representative samples and schema files in tests.
  Runtime validation of upstream responses is deferred until it is needed for
  production hardening.

Canonical JSON Schema files are stored at `schemas/` in the repo root, organized as:

```text
schemas/
├── sources.toml    # Reviewed registry source index
├── manifest.json   # Generated provenance and content hashes
├── upstream/       # Fetched official protobuf, XSD, OpenAPI, and type artifacts
├── registries/    # Official registry protocol schemas
│   ├── pypi.schema.json
│   ├── pypi-index.schema.json
│   ├── npm.schema.json
│   ├── cargo.schema.json
│   ├── cargo-config.schema.json
│   ├── hex.schema.json
│   ├── nuget-*.schema.json
│   └── pub-package.schema.json
└── depot/         # Depot's own formats
    ├── config.schema.json
    └── lockfile.schema.json
```

`tools/schema-manager` owns schema refresh and drift detection:

- `task schema:fetch` downloads pinned official machine-readable artifacts.
- `task schema:generate` regenerates Depot JSON Schemas and `schemas/manifest.json`.
- `task schema:check` fails when committed fetched artifacts, generated schemas, or manifest hashes
  are stale; it does not compare against mutable live upstream sources.
- `task schema:check-live` compares fetched artifacts with current upstream sources for explicit
  maintainer refresh checks.
- `task conformance` runs fixture-based adapter conformance tests.

Registry types live in `depot-core/src/registry/` with one module per ecosystem. These types use
`std::collections::HashMap` (not `AHashMap`) since `schemars` requires `JsonSchema` on all fields,
and these are serialization types, not hot-path internal data structures.

RubyGems Compact Index is a text protocol and is not represented as JSON Schema. Maven metadata is
represented by upstream XSDs rather than generated JSON Schema. Hex registry resources are
protobuf-first; JSON Schema only covers Depot's HTTP API fixture shapes. NuGet and pub.dev registry
schemas are Depot-derived from official prose and implementation/model evidence because upstream
does not publish registry JSON Schema or OpenAPI artifacts.

Every registry schema change requires conformance coverage. At minimum, tests must validate
representative official responses or fixtures against the schema and must fail when a documented
required field, response shape, or wire-format rule drifts from the upstream contract.

## Consequences

- Test-time validation catches schema drift in representative fixtures.
- JSON Schema files serve as machine-readable documentation of every protocol we support.
- Registry schema documentation remains auditable because each schema records the official source and
  the source format used to derive it.
- `HashMap` in registry types is acceptable — these are used at I/O boundaries, not in tight loops.
- Schema files can be used by external tools (editors, CI, documentation generators).
- Prose-only, protobuf, XML Schema, and OpenAPI sources may require hand-maintained JSON Schema
  translations, but those translations must be backed by conformance tests.
- Depot must not label a generated registry JSON Schema as official unless it was fetched directly
  from an upstream authority.
