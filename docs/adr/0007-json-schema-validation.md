# ADR-0007: Registry Schema Provenance and JSON Schema Validation

## Status

Accepted

## Context

Starmetal models registries whose official contracts come from prose specs, protobuf files, XML Schema,
OpenAPI, source code, and examples. JSON Schema files in this repo are usually Starmetal-derived
validation artifacts, not upstream authority.

Schema evidence supports implementation and documentation. It does not by itself make a registry
MVP-supported.

## Decision

Registry schema provenance lives under `schemas/`.

Implemented layout:

```text
schemas/
├── sources.toml
├── manifest.json
├── upstream/
├── registries/
└── depot/
```

Implemented tooling:

| Command | Purpose |
|---------|---------|
| `task schema:fetch` | Download pinned official artifacts |
| `task schema:generate` | Generate Starmetal schemas and manifest |
| `task schema:check` | Verify committed artifacts and generated schemas are current |
| `task schema:check-live` | Compare fetched artifacts with mutable live upstream sources |
| `task schema:validate` | Validate schemas against representative fixtures |
| `task conformance` | Run fixture-based registry conformance tests |

Registry source treatment:

| Registry | Source treatment |
|----------|------------------|
| PyPI | Derived JSON Schema from PyPA specs |
| npm | Derived flexible JSON Schema from docs and npm-maintained TypeScript types |
| Cargo | Derived JSON Schema from Cargo sparse index spec |
| Hex | Protobuf is authoritative; JSON Schema covers HTTP fixture shapes |
| Maven | XSDs are authoritative; no invented JSON Schema for artifact serving |
| RubyGems | Compact Index is text grammar; no registry JSON Schema |
| NuGet | Derived JSON Schemas from Microsoft V3 prose and NuSpec XSD evidence |
| pub.dev | Derived JSON Schema from Hosted Pub prose and pub.dev Dart DTO evidence |

## Implemented

- `schemars` generation for Starmetal-owned Rust types.
- `jsonschema` fixture validation in tests.
- Manifest provenance with content hashes.
- Offline schema and conformance tasks.

## Deferred

- Runtime validation of every upstream response.
- Treating generated schemas as official upstream material.
- Support claims based only on schema presence.

## Consequences

- Schema changes must include provenance and conformance updates.
- JSON Schema files are developer-facing contract documentation.
- Registry support documentation must also account for route behavior and live native-client E2E.
