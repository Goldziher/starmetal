# ADR-0010: CLI and MCP Operations Surface

## Status

Accepted

## Context

Starmetal needs local operator workflows for private deployments and agent integrations. CLI and MCP
must share behavior rather than duplicating config, storage, or service construction.

## Decision

`depot-ops` is the shared local operations layer for `depot-cli` and the stdio MCP server.

Implemented CLI surface:

| Command | Status |
|---------|--------|
| `sm serve` | Implemented |
| `sm config show` | Implemented |
| `sm config validate` | Implemented |
| `sm config init` | Implemented |
| `sm registry list` | Implemented |
| `sm registry status` | Implemented |
| `sm package list` | Implemented |
| `sm package versions` | Implemented |
| `sm package metadata` | Implemented |
| `sm package fetch` | Implemented |
| `sm package publish` | Experimental local publishing |
| `sm package yank` | Experimental local publishing |
| `sm package unyank` | Experimental local publishing |
| `sm cache delete-artifact` | Implemented local cache operation |
| `sm mcp serve` | Implemented stdio MCP |
| `sm sync` | Not implemented in MVP |
| `sm lock verify` | Not implemented in MVP |
| `sm lock update` | Not implemented in MVP |

MCP runs over stdio. Read tools are available by default. Mutating tools require
`sm mcp serve --allow-writes`.

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
