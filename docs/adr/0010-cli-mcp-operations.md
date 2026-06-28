# ADR-0010: CLI and MCP Operations Surface

## Status

Accepted

## Context

Depot needs local operator workflows for private deployments and agent integrations. CLI and MCP
must share behavior rather than duplicating config, storage, or service construction.

## Decision

`depot-ops` is the shared local operations layer for `depot-cli` and the stdio MCP server.

Implemented CLI surface:

| Command | Status |
|---------|--------|
| `depot serve` | Implemented |
| `depot config show` | Implemented |
| `depot config validate` | Implemented |
| `depot config init` | Implemented |
| `depot registry list` | Implemented |
| `depot registry status` | Implemented |
| `depot package list` | Implemented |
| `depot package versions` | Implemented |
| `depot package metadata` | Implemented |
| `depot package fetch` | Implemented |
| `depot package publish` | Experimental local publishing |
| `depot package yank` | Experimental local publishing |
| `depot package unyank` | Experimental local publishing |
| `depot cache delete-artifact` | Implemented local cache operation |
| `depot mcp serve` | Implemented stdio MCP |
| `depot sync` | Not implemented in MVP |
| `depot lock verify` | Not implemented in MVP |
| `depot lock update` | Not implemented in MVP |

MCP runs over stdio. Read tools are available by default. Mutating tools require
`depot mcp serve --allow-writes`.

## Implemented

- Config lookup through defaults, `DEPOT_CONFIG`, local `depot.toml`, explicit config path, and CLI
  overrides.
- `--no-config` local workflows.
- Human output plus `--output json` for stable machine-readable output.
- Shared runtime construction through `DepotRuntime`.
- MCP tools backed by the same operations as CLI commands.

## Deferred

- Remote administration over HTTP.
- Full sync workflows.
- Lock file verify and update workflows.
- Native archive inference for operator publishing.
- Treating MCP writes as safe without explicit startup opt-in.

## Consequences

- CLI and MCP stay aligned through `depot-ops`.
- The private MVP can be operated locally without a config file.
- Remote admin behavior needs a separate ADR.
