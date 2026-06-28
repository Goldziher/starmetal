# ADR-0012: CI Quality Gates for MVP Readiness

## Status

Accepted

## Context

Depot's private MVP readiness depends on generated schemas, offline conformance, Rust correctness,
and live native-client behavior. These checks have different cost profiles and should be separated.

## Decision

Use three quality-gate tiers.

## Required Offline Gate

Run for normal review and before merging docs or code that changes behavior:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
task schema:check
task schema:validate
task conformance
```

`prek run --all-files` remains the full repository pre-commit gate. It may run formatters and other
non-doc hooks, so targeted checks are acceptable for docs-only changes when full hooks are not
practical.

## Live E2E Gate

Run before documenting a registry as MVP-ready:

```sh
task test:e2e:pypi
task test:e2e:npm
task test:e2e:cargo
task test:e2e:hex
```

Run beta E2E checks before promoting opt-in beta adapters:

```sh
task test:e2e:maven
task test:e2e:rubygems
task test:e2e:nuget
task test:e2e:pub
```

Live E2E tests are ignored by default in Cargo because they require network access and native client
CLIs.

## Release Gate

Before any non-private release claim:

- Pass the required offline gate.
- Pass the relevant live E2E gate.
- Verify README, `docs/architecture.md`, `docs/deployment.md`, and ADR-0011 agree.
- Verify generated AI instructions are regenerated if `.ai-rulez/` sources changed.

## Consequences

- Schema freshness and conformance are required before support claims.
- Live E2E is the promotion signal for read support.
- Docs-only changes can use targeted docs checks, but final claims still require evidence.
