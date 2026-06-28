# Schemas

This directory contains Starmetal's registry schema evidence and generated JSON Schema artifacts.

## Files

- `sources.toml`: manually reviewed list of official source documents and downloadable artifacts.
- `manifest.json`: generated provenance, hashes, source links, and schema ownership metadata.
- `upstream/`: fetched official machine-readable artifacts such as protobuf, XSD, and OpenAPI files.
- `registries/`: Starmetal-derived JSON Schemas for registry-facing payloads.
- `depot/`: Starmetal-owned JSON Schemas for config and lockfile formats.

## Registry Sources

| Registry | Official source format | Starmetal artifact |
|----------|------------------------|----------------|
| PyPI | PyPA Simple Repository API and PyPI API prose specs | Derived JSON Schema for PEP 691 project JSON |
| npm | npm registry docs and npm-maintained TypeScript definitions | Derived flexible JSON Schema for packuments |
| Cargo | Cargo Book registry index prose spec | Derived JSON Schema for sparse index entries |
| Hex | Hex Registry v2 prose plus official protobuf files | Protobuf is authoritative; JSON Schema covers HTTP API fixtures |
| Maven | Official Maven POM and repository metadata XSDs | XSDs are authoritative; JSON Schema is not invented for artifact serving |
| Sonatype | Central Publisher OpenAPI and Nexus REST Swagger | OpenAPI documents admin/publisher APIs only, not Maven artifact layout |
| RubyGems | Compact Index prose grammar plus Bundler parser and Ruby validator source | Compact Index is text grammar; no registry JSON Schema is generated |
| NuGet | Microsoft Learn V3 prose plus NuGet.Client NuSpec XSD | Derived JSON Schemas for service index, package base address, and registration metadata |
| pub.dev | Hosted Pub Repository v2 prose plus pub.dev Dart DTO source | Derived JSON Schema for package metadata; OSV schema applies only to advisories |

## Commands

```sh
task schema:fetch
task schema:generate
task schema:refresh
task schema:check
task schema:check-live
task schema:validate
task conformance
```

Use `task schema:refresh` when intentionally updating upstream artifacts or generated schemas. Use
`task schema:check` in review and CI to fail on stale committed artifacts, generated schemas, or
manifest hashes without depending on mutable live upstream state. Use `task schema:check-live` when
explicitly comparing committed fetched artifacts against current upstream sources.

## Conformance Requirement

No registry adapter should be documented as supported unless it has:

- Official source linkage in `sources.toml`.
- Schema/protocol provenance in `manifest.json`.
- Fixture-based conformance tests under `tests/conformance`.
- Route-level behavior coverage for Starmetal-served metadata where the adapter exists.

Runtime schema validation is optional and explicit. These artifacts are required for documentation,
test-time validation, and adapter conformance.

Generated JSON Schemas under `schemas/registries/` are Starmetal-derived unless the manifest explicitly
states otherwise. Official upstream artifacts are stored under `schemas/upstream/` in their native
formats, such as protobuf, XSD, OpenAPI, Ruby source, Dart source, or JSON Schema.
