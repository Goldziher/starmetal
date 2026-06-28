---
priority: high
---

# Conventions

## Build & Test

```bash
cargo build --workspace
cargo check --workspace
cargo test --workspace
cargo test -p starmetal-core
cargo clippy --workspace
cargo fmt --check
```

## Pre-commit

Use `prek run --all-files` (NOT `pre-commit`). Hooks enforce formatting, linting, sorted Cargo.toml, unused deps, markdown lint, spell check, and actionlint.

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
