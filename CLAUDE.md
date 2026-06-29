<!--
🤖 AI-RULEZ :: GENERATED FILE — DO NOT EDIT DIRECTLY
Project: starmetal
Generated: 2026-06-29 20:28:09
Source: .ai-rulez/config.toml
Target: CLAUDE.md
Content: rules=39, sections=0, agents=9

WHAT IS AI-RULEZ
AI-Rulez is a directory-based AI governance tool. All configuration lives in
the .ai-rulez/ directory. This file is auto-generated from source files.

.AI-RULEZ FOLDER ORGANIZATION
Root content (always included):
  .ai-rulez/config.toml    Main configuration (presets, profiles)
  .ai-rulez/rules/         Mandatory rules for AI assistants
  .ai-rulez/context/       Reference documentation
  .ai-rulez/skills/        Specialized AI prompts
  .ai-rulez/agents/        Agent definitions

Domain content (profile-specific):
  .ai-rulez/domains/{name}/rules/    Domain-specific rules
  .ai-rulez/domains/{name}/context/  Domain-specific documentation
  .ai-rulez/domains/{name}/skills/   Domain-specific AI prompts

Profiles in config.toml control which domains are included.

INSTRUCTIONS FOR AI AGENTS
1. NEVER edit this file (CLAUDE.md) - it is auto-generated

2. ALWAYS edit files in .ai-rulez/ instead:
   - Add/modify rules: .ai-rulez/rules/*.md
   - Add/modify context: .ai-rulez/context/*.md
   - Update config: .ai-rulez/config.toml
   - Domain-specific: .ai-rulez/domains/{name}/rules/*.md

3. PREFER using the MCP Server (if available):
   Command: npx -y ai-rulez@latest mcp
   Provides safe CRUD tools for reading and modifying .ai-rulez/ content

4. After making changes: ai-rulez generate

5. Complete workflow:
   a. Edit source files in .ai-rulez/
   b. Run: ai-rulez generate
   c. Commit both .ai-rulez/ and generated files

Documentation: https://github.com/Goldziher/ai-rulez
Content-Hash: blake3:a6f638f08c222e12fd264315a19894add7b5e99c72f7b1151928045063301ee5
Source-Hash: blake3:0a7f7340ea1e19de55e77848e58143d8cb09e1bb6cfb5bb969e7dbe1a72a61f0
-->

# starmetal

Multi-language high-performance self-hosted package registry and registry proxy

## Rules

### agent-workflow

**Priority:** high

Prefer subagents for non-trivial work — implementation, research, file exploration. Parallelize aggressively — launch independent subagents in a single message. Always critically review subagent output — check actual file changes, verify correctness, fix issues before reporting done. Never trust subagent summaries at face value; the summary describes intent, not necessarily what happened. Work in iterations: delegate → critically review → fix → verify. Run tests after every change — never assume code works without verification.

### anti-patterns

**Priority:** high

No magic numbers — use named constants. No global state — use dependency injection. No inheritance for code reuse — prefer composition. No bare exception handlers — catch specific types. No mocking internal services — use real objects for integration tests. No blocking I/O in async code paths — keep async paths fully async.

### atomic-commits

**Priority:** high

Each commit represents one logical change. Don't mix unrelated changes. Use conventional commits format (`feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `test:`). Keep commits small and focused for easier review and bisection.

### avoid-duplication

**Priority:** medium

Extract shared logic after the third repetition, not before. Three similar lines of code are better than a premature abstraction. When extracting, ensure the shared code has a single reason to change — if two callers would evolve the logic differently, keep them separate. Premature abstraction creates worse coupling than duplication.

### basemind-mcp

**Priority:** high

- Keep Basemind configured as an ai-rulez plugin through `[[plugins]]`; do not add Basemind as a raw `mcp_server`.
- Configure the ai-rulez MCP server with `npx -y ai-rulez@latest mcp` so agents can manage `.ai-rulez/` safely.
- Edit ai-rulez source files first, then regenerate outputs with `npx -y ai-rulez@latest generate --gitignore`.
- When Basemind MCP tools are available, prefer them for code navigation and repository context before falling back to shell tools:
  `outline`, `search_symbols`, `find_references`, `find_callers`, and `workspace_grep` for code search;
  `recent_changes`, `blame_file`, `blame_symbol`, `diff_file`, `diff_outline`, and `commits_touching` for git history;
  `search_documents`, `web_scrape`, `web_crawl`, and `web_map` for docs and web retrieval.
- Use shell, `rg`, and raw `git` when Basemind is unavailable, when exact raw output is required, or when a task runner/check is the source of truth.

### batch-operations

**Priority:** medium

Group related file reads and writes into single operations. Combine independent tool calls in parallel rather than sequentially. When making multiple edits to the same file, batch them into one edit operation. Prefer multi-file search tools over individual file reads when exploring.

### branch-hygiene

**Priority:** medium

Use descriptive branch names. Keep branches short-lived. Delete merged branches. Rebase or merge from main regularly to avoid drift.

### commit-messages

**Priority:** high

Use conventional commits: `feat: add user auth`, `fix: handle null input`, `chore: update deps`, `refactor: extract parser`, `docs: add API guide`, `test: cover edge case`. First line under 72 chars, imperative mood. Body explains *why*, not *what*. Add scope when useful: `feat(api): add pagination`.

### communication-style

**Priority:** critical

Be concise and precise — no fluff, no emojis, no unnecessary checklists. PR descriptions: state what changed and why in 1-3 sentences, not bullet-point essays. Issue comments: answer the question directly. Code review: point out the problem and suggest the fix, skip praise and filler. Commit messages: imperative mood, under 72 chars, body explains why not what. Never pad output to appear thorough — brevity is clarity.

### complexity-limits

**Priority:** medium

Enforce concrete limits: max 20 cyclomatic complexity per function, max 4 levels of nesting depth, max 50 lines per function. Use early returns to flatten conditionals. Break complex functions into well-named helpers that each do one thing.

### context-preservation

**Priority:** medium

Record key findings (file paths, function signatures, patterns discovered) before they scroll out of context. Summarize investigation results before acting on them. When working on multi-step tasks, note intermediate decisions and their rationale to avoid re-deriving them later.

### dead-code

**Priority:** low

Remove dead code instead of commenting it out. Version control preserves history. Commented-out code creates confusion and maintenance burden.

### dependency-awareness

**Priority:** high

Audit dependencies before adding them. Prefer well-maintained, widely-used packages with active maintenance. Pin versions and commit lock files. Use language-specific audit tools in CI:

- Rust: `cargo audit`, `cargo deny` (license + advisory policies)
- Python: `pip-audit`, `bandit` (SAST)
- JavaScript/TypeScript: `npm audit`, `pnpm audit`
- Go: `govulncheck`
- Ruby: `bundler-audit`
- PHP: `composer audit`
- Java: OWASP `dependency-check` Maven/Gradle plugin
- C#: `dotnet list package --vulnerable`
- Elixir: `mix_audit`
Zero tolerance for critical/high CVEs. Automate dependency update PRs where possible.

### error-handling

**Priority:** high

- Each crate converts external errors into `StarmetalError` at the boundary using `From` impls or `.map_err()`.
- HTTP handlers map `StarmetalError` variants to appropriate status codes.
- Use `thiserror` for all error enums.
- Never use `.unwrap()` or `.expect()` in library crates. The CLI binary may use `.unwrap_or_else()` with proper error messages for startup code only.

### error-handling

**Priority:** high

Always wrap errors with context describing what operation failed. Never swallow errors silently — either handle, propagate, or log them. Use language-idiomatic patterns: `Result<T, E>` in Rust, `if err != nil` with `fmt.Errorf("doing X: %w", err)` in Go, typed exceptions in Python/Java. Fail fast on unrecoverable errors.

### explain-reasoning

**Priority:** medium

Briefly explain your reasoning for non-obvious decisions. State trade-offs when multiple approaches exist. Be transparent about uncertainty.

### feature-flags

**Priority:** high

- All protocol adapters are gated behind feature flags in `starmetal-adapters`.
- All storage backends are gated behind feature flags in `starmetal-storage`.
- Feature flags are additive — combining features must never break builds.
- Use `#[cfg(feature = "...")]` on modules, not on individual functions.
- When adding a new adapter or backend, add corresponding feature flags and update `starmetal-cli`'s `full` feature.

### hexagonal-boundaries

**Priority:** critical

- `starmetal-core` must NEVER depend on axum, tower, opendal, reqwest, or any framework crate. All I/O goes through port traits.
- Protocol adapters must NEVER access storage directly — always go through `PackageService`.
- Adapters must NOT share protocol-specific logic with each other. Shared behavior belongs in `PackageService`.
- New dependencies in `starmetal-core` require justification — keep it framework-free.

### incremental-approach

**Priority:** medium

Start with the smallest viable change, verify it works, then extend. Avoid generating large blocks of speculative code. Build iteratively: implement one piece, test, then move to the next. When uncertain about an approach, prototype the critical part first before committing to the full implementation.

### input-validation

**Priority:** high

Validate and sanitize all external input at system boundaries. Use allowlists over denylists. Validate types, ranges, and formats. Never trust user input.

### least-privilege

**Priority:** medium

Request only necessary permissions. Minimize file system access, network access, and API scopes. Run processes with minimal required privileges.

### meaningful-assertions

**Priority:** medium

Assert exact expected values, not just truthiness (`assert result == 42`, not `assert result`). Use snapshot testing for complex structured output. Consider property-based testing for functions with wide input ranges. Include descriptive failure messages. Always test error paths and edge cases, not just the happy path.

### minimal-changes

**Priority:** high

Make the smallest change that achieves the goal. Avoid unnecessary refactoring, reformatting, or scope creep. Don't fix what isn't broken.

### no-ai-signatures

**Priority:** critical

Never add AI attribution to commits (no Co-Authored-By AI lines, no "Generated by AI/Claude/GPT"). Never add AI attribution to PR titles or descriptions. Never add AI-generated comments or watermarks in code.

### output-awareness

**Priority:** medium

Limit explanations to 1-3 sentences unless asked for detail. Use code blocks for code, not prose. Omit unchanged code when showing diffs — use comments like `// ... existing code ...` to indicate skipped sections. Never repeat information already visible in context. Prefer short, direct answers over comprehensive walkthroughs.

### read-before-write

**Priority:** critical

Read and understand existing files before editing them. Understand the codebase conventions, patterns, and architecture before making changes. Check imports, naming styles, and project structure to ensure new code fits the existing codebase.

### readability-first

**Priority:** high

Max 120 character line width. Prefer explicit code over clever tricks — if it needs a comment to explain what it does, rewrite it. No abbreviations in public API names (`context` not `ctx` in public signatures, `repository` not `repo`). Keep functions short and focused on a single responsibility.

### rust-conventions

**Priority:** high

- Rust 2024 edition, `cargo fmt` + `clippy -D warnings`, zero warnings policy.
- `Result<T, E>` with `thiserror` for library errors, `anyhow` for applications. `?` for propagation — never `.unwrap()` in library code.
- Minimize `unsafe` — every block needs `// SAFETY:` comment explaining invariants.
- Prefer `&str` over `String` in params, `Cow<'_, str>` for conditional ownership, `Arc` for shared ownership.
- `impl Trait` in argument position for static dispatch, `dyn Trait` for dynamic dispatch when heterogeneous collections needed.
- Small, focused modules. Use `pub(crate)` for internal visibility. Workspace inheritance for multi-crate repos.
- `#[cfg(test)]` for unit tests, `tests/` for integration, `cargo-llvm-cov` for coverage.
- Benchmarking: `criterion` for microbenchmarks, profile with `cargo flamegraph`.
- Async: `tokio` runtime, `'static + Send + Sync` bounds, `tokio::spawn` for concurrency.
- Security: `cargo audit` for CVE scanning, `cargo deny` for license and advisory policies.
- Dependencies: pin versions, commit `Cargo.lock`, prefer well-maintained crates.
- Structured logging with `tracing` crate — use spans and events, not `println!`.
- API naming: follow `as_`/`to_`/`into_` conventions for conversions, `iter()`/`iter_mut()`/`into_iter()` for iterators. Getters are `field()` not `get_field()`. See [Rust API Guidelines](https://rust-lang.github.io/api-guidelines).
- Eagerly implement common traits: `Clone`, `Debug`, `Default`, `Eq`, `PartialEq`, `Hash`, `Send`, `Sync`. Use `From`/`AsRef`/`AsMut` for conversions, `FromIterator`/`Extend` for collections.
- Type safety: newtypes for static distinctions, builder pattern for complex construction, `bitflags` over enums for flag sets. Avoid `bool` params — use custom types or enums.
- Constructors: `new()` as static inherent methods. No out-parameters. Only smart pointers implement `Deref`/`DerefMut`.
- API flexibility: minimize parameter assumptions via generics, make traits object-safe when trait objects may be useful. Let callers decide where to copy and place data.
- Rustdoc: all public items have doc examples using `?` (not `unwrap`). Document errors, panics, and safety invariants. Hyperlink related items.
- Future-proofing: seal traits to prevent downstream implementations, keep struct fields private, don't duplicate derived trait bounds on structs. See [Rust Design Patterns](https://rust-unofficial.github.io/patterns).
- Anti-patterns: `unwrap()`, unguarded `unsafe`, panics in libraries, `Vec`/`HashMap` across FFI.

### safe-git-operations

**Priority:** critical

Never force-push to shared branches. Always pull before pushing. Use `--force-with-lease` instead of `--force` when necessary. Confirm destructive operations with the user.

### secrets-handling

**Priority:** critical

Never hardcode secrets, API keys, tokens, or passwords. Use environment variables or secret management systems. Never log or expose sensitive values. Reject commits containing secrets.

### systematic-debugging

**Priority:** high

Never guess at bugs. Trace the root cause backward through the call stack to find the original trigger. Analyze patterns — is this a one-off or systemic? Form a hypothesis and verify it before implementing a fix. No shotgun debugging, no random changes hoping something works.

### task-runner

**Priority:** high

Prefer `task` commands over raw build/test/lint commands when a Taskfile.yaml exists. Task runners provide consistent, documented workflows. Use `task --list` to discover available tasks. Always check for a Taskfile before running manual commands. Standard task names: setup, build, test, lint, format, bench — prefer these conventions. Lock files always committed for reproducible builds.

### tdd-workflow

**Priority:** high

Write tests before writing code, update tests when modifying behavior. When fixing bugs, write a failing test first — RED (failing test) → GREEN (minimal code to pass) → REFACTOR. Wrote production code before the test? Delete it, start over — no exceptions, don't keep as reference. Integration tests for API surfaces, unit tests for business logic, property tests for edge-case-heavy code. Run the full test suite before committing — never push untested code.

### test-alongside-code

**Priority:** high

Write tests when writing code, update tests when modifying behavior. When fixing bugs, write a failing test first (TDD). Use integration tests for the public API surface and unit tests for complex internal logic. Run the full test suite before committing.

### test-independence

**Priority:** high

Tests must be independent and idempotent — runnable in any order, in parallel. No shared mutable state between tests. Use factories or fixtures for setup. Clean up created resources (files, DB rows, env vars) after each test. Never rely on test execution order.

### test-naming

**Priority:** medium

Name tests to describe behavior: `should_return_error_when_input_is_empty`, `test_parse_handles_nested_objects`. Use `describe`/`it` blocks for grouping in languages that support them. Follow `given_when_then` or `should_when` patterns. Test names are specifications — a reader should understand the expected behavior without reading the test body.

### testing-anti-patterns

**Priority:** high

Do not test mock behavior instead of real behavior. Do not add test-only methods to production code. Do not mock what you don't own — wrap it and test the wrapper. Do not test implementation details — test observable behavior. Do not write tests that pass when the code is broken. If a test never fails, it's not testing anything.

### verification-before-completion

**Priority:** critical

Never claim success without fresh verification. Run the test and see it pass. Check the file exists. Verify the build succeeds. Evidence before assertions — always. If you can't verify, say so explicitly rather than claiming success.

### verify-before-acting

**Priority:** critical

Verify assumptions before taking action. Check current state (branch, working directory, running processes) before making changes. Confirm file existence before editing. Test that build passes before committing. Never assume — confirm.

## Context

### architecture

Starmetal is a self-hosted, armored universal package registry built with hexagonal architecture.

## Crate Structure

All code lives under `crates/` — there is no top-level `src/`.

| Crate | Role |
|-------|------|
| `starmetal-core` | Domain types, port traits (`PackageService`, `StoragePort`, `UpstreamClient`, `StatisticsService`), policy engine, lock file, config |
| `starmetal-service` | Application service layer. `CachingPackageService` implements pull-through caching, blake3 integrity verification (sidecar `.blake3` files), in-memory statistics, and policy enforcement. Sits between adapters and core. |
| `starmetal-storage` | OpenDAL-backed `StoragePort` implementation. Feature-gated backends: `backend-fs`, `backend-s3`, `backend-gcs`, `backend-memory` |
| `starmetal-adapters` | Inbound protocol adapters (axum routers) + outbound upstream clients. Feature-gated: `pypi`, `npm`, `cargo-registry`, `hex`, `maven`, `rubygems`, `nuget`, `pub`. Each adapter defines a state trait for accessing `PackageService` plus ecosystem-specific upstream clients. |
| `starmetal-server` | Axum app assembly, Tower middleware stack (tracing, CORS, auth, compression), admin API, shared `AppState` |
| `starmetal-ops` | Shared local runtime and operator operations used by CLI and MCP |
| `starmetal-cli` | Binary crate. Clap CLI with commands for serving, config, registry, package, cache, and MCP operations |
| `tests/conformance` | Offline fixture-backed conformance tests for protocol routes and publishing behavior |
| `tests/integration` | Integration test crate for server APIs and live ignored native-client workflows |

## Dependency Flow

`starmetal-cli → starmetal-ops → starmetal-server → starmetal-adapters → starmetal-core`
`starmetal-ops → starmetal-service → starmetal-core`
`starmetal-ops → starmetal-storage → starmetal-core`

The core crate has zero framework dependencies — all I/O goes through port traits.

## Key Design Decisions

- Protocol adapters call `list_versions` to trigger caching, then serve the upstream client's cached response directly with URL rewriting (preserving all protocol-specific fields like npm dependencies, PyPI requires-python, Cargo deps/features)
- Pull-through cache in `CachingPackageService`: fetch from upstream on miss, verify with blake3, apply policy, store via OpenDAL, serve
- Blake3 hashes are stored as `.blake3` sidecar files alongside artifacts and verified on every cache read
- Upstream hashes are preserved in `ArtifactDigest.upstream_hashes`
- All upstream client caches use 5-minute TTL via `(Instant, T)` tuples
- npm adapter stores/serves raw `serde_json::Value` to handle the wide variety of npm field shapes
- npm adapter performs recursive BFS dependency prefetch (max depth 10) when serving a packument
- Hex adapter includes a protobuf registry proxy at `/hex/packages/{name}` for mix checksum verification
- Maven, RubyGems, NuGet, and pub.dev adapters are experimental core read/proxy surfaces
- Storage keys: `<ecosystem>/<name>/<version>/<filename>`
- Lock file: TOML-based, ecosystem-agnostic, blake3 hashes
- Admin API is disabled by default and mounted at `/admin/api/v1` only when configured
- Metrics are in-memory process counters exposed through the admin API
- Feature flags control compile-time inclusion of adapters and storage backends
- TOML config with clap CLI

## ADRs

Architecture Decision Records are in `docs/adr/`. Read them before making architectural changes.

### conventions

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
- Documentation: keep `docs/configuration.md` aligned with `schemas/starmetal/config.schema.json`

### owasp-quick-reference

1. **Broken Access Control** — enforce authorization checks on every request, deny by default.
2. **Cryptographic Failures** — use strong standard algorithms, never roll your own crypto.
3. **Injection** — parameterize all queries, sanitize and validate all inputs.
4. **Insecure Design** — threat model early, validate business logic at every layer.
5. **Security Misconfiguration** — harden defaults, disable unnecessary features and endpoints.
6. **Vulnerable Components** — keep dependencies updated, audit regularly with language-specific tools.
7. **Authentication Failures** — require MFA, enforce strong passwords, implement rate limiting.
8. **Data Integrity Failures** — verify software updates, use signed artifacts and checksums.
9. **Logging Failures** — log all security events with context, protect log data from tampering.
10. **SSRF** — validate and allowlist URLs, restrict outbound network requests.

## Agents

When a task aligns with a specialized agent listed below, delegate to that agent instead of handling it directly. Launch multiple independent agent calls in parallel when possible.

- **cli-engineer**: CLI binary and user-facing command specialist
- **code-reviewer**: Use when reviewing code changes for quality, security, and convention compliance
- **core-architect**: Domain modeling and core business logic specialist for starmetal-core
- **docs-writer**: Use when writing or updating documentation, READMEs, or changelogs
- **infra-engineer**: Storage, middleware, and server infrastructure specialist
- **protocol-engineer**: Registry protocol adapter specialist for PyPI, npm, Cargo, Hex, Maven, RubyGems, NuGet, and pub.dev
- **qa-engineer**: Testing, CI, and quality assurance specialist
- **security-auditor**: Use when auditing code or dependencies for security vulnerabilities
- **test-writer**: Use when writing tests — follows TDD red-green-refactor cycle
