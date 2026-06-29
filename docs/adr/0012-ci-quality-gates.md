# ADR-0012: CI Quality Gates for Experimental Readiness

## Status

Accepted

## Context

Starmetal's experimental readiness depends on generated schemas, offline conformance, Rust correctness,
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
task docker:integration
task docker:proxy:e2e
```

`task docker:integration` is the CI Docker gate. It runs the image smoke test and then
`task docker:proxy:e2e`. The proxy E2E harness builds `starmetal:local`, starts StarMetal with a
mounted config and OpenDAL filesystem volume, serves deterministic fixture upstreams, and proves
cache persistence across restart without public package-registry network access.

`task docker:proxy:e2e` runs deterministic HTTP assertions for all eight registry routes plus
disposable native client containers for PyPI, npm, Cargo, Maven, RubyGems, NuGet, and pub.dev. Hex
is covered by the HTTP/protobuf route pass; native Hex/Mix remains a live or future signed-fixture
gate. The native pass runs without read auth because package managers do not consistently support
Bearer auth for read-through registries; the HTTP pass remains the auth, CORS, URL rewriting, cache,
response-size-limit, and sanitized-error check.

`task docker:proxy:e2e:pnpm` is included in the Docker gate. It proves read-through pnpm install
with `package.json` and `pnpm-lock.yaml` updates, reinstall from the Starmetal cache with the
fixture upstream offline, and experimental local npm publish-then-install through Starmetal.

Docker proxy E2E writes logs, client output, and stored-file listings under
`.artifacts/docker-proxy-e2e/`. CI uploads these artifacts on failure.

`prek run --all-files` remains the full repository pre-commit gate. It may run formatters and other
non-doc hooks, so targeted checks are acceptable for docs-only changes when full hooks are not
practical.

## Live E2E Gate

Run before documenting a registry beyond experimental:

```sh
task test:e2e:pypi
task test:e2e:npm
task test:e2e:cargo
task test:e2e:hex
```

Run live E2E checks before promoting additional registry confidence:

```sh
task test:e2e:maven
task test:e2e:rubygems
task test:e2e:nuget
task test:e2e:pub
```

Live E2E tests are ignored by default in Cargo because they require network access and native client
CLIs.

Live Docker pressure remains separate from the required offline gate:

```sh
task docker:pressure:live
```

## Release Gate

Before any non-private release claim:

- Pass the required offline gate.
- Pass the relevant live E2E gate.
- Verify README, `docs/architecture.md`, `docs/deployment.md`, and ADR-0011 agree.
- Verify generated AI instructions are regenerated if `.ai-rulez/` sources changed.

## Consequences

- Schema freshness and conformance are required before support claims.
- Deterministic Docker integration is required for containerized proxy changes.
- Live E2E is the promotion signal for read support.
- Docs-only changes can use targeted docs checks, but final claims still require evidence.
