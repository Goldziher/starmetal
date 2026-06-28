# ADR-0013: Basemind and AI-Rulez Alignment

## Status

Accepted

## Context

Depot uses AI-Rulez to generate assistant instructions. The generated `AGENTS.md` file says not to
edit it directly. `.ai-rulez/config.toml` enables the `basemind` marketplace plugin from
`Goldziher/basemind`.

AI instructions can drift from ADRs if support language is changed in documentation but not reflected
in AI-Rulez source files.

## Decision

ADRs are the authoritative architecture and support-scope record. AI-Rulez source files should
summarize the ADR decisions, not expand support claims beyond them.

Rules:

- Do not edit `AGENTS.md` directly.
- Edit `.ai-rulez/` source files when AI instructions need to change.
- Run `task setup:ai-rulez` or `npx -y ai-rulez@latest generate` after AI-Rulez source changes.
- Keep Basemind-provided guidance subordinate to repo ADRs, tests, and generated support matrices.
- Do not let AI instructions describe beta adapters or publishing as more supported than ADR-0011
  and ADR-0009 allow.

## Implemented

- `.ai-rulez/config.toml` declares the `basemind` marketplace and enables the `basemind` plugin.
- Generated assistant instructions point agents to ADRs before architectural changes.

## Deferred

- Updating `.ai-rulez/` source files in this docs-only ADR rewrite.
- Adding automated drift detection between ADR support tables and AI-Rulez context.

## Consequences

- Future AI instruction updates must go through AI-Rulez sources and regeneration.
- Documentation claims remain the source of truth for private MVP readiness.
