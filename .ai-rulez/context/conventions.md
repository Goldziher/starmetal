---
priority: high
---

# Conventions

## Build & Test

```bash
task fmt:check
task clippy
task test:all
task schema:check
task schema:validate
task conformance
task feature:check
task docker:integration
task security
task ci
```

## Commit step

Use `poly lint .` and `poly fmt --check .` (apply fixes with `poly fmt --fix .`). poly enforces formatting, linting, sorted Cargo.toml, unused deps, markdown lint, spell check, and actionlint. poly runs in CI via the shared reusable validate workflow.

## Commits

Conventional commits enforced by gitfluff: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`.
Do NOT add AI co-author signatures.

## Code Style

- Rust edition 2024
- No top-level `src/` — all code under `crates/`
- Feature flags for optional functionality (adapters, storage backends, encryption)
- `async-trait` for async port traits
- `thiserror` for error types
- `tracing` for structured logging
- Config: TOML files, `serde::Deserialize`
- Documentation: keep `docs/configuration.md` aligned with `schemas/starmetal/config.schema.json`
