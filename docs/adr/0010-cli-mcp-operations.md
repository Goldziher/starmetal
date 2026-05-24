# ADR-0010: CLI and MCP Operations Surface

## Status

Accepted

## Context

Depot needs an operator interface in addition to native package registry routes. The CLI and MCP
server should expose the same capabilities without duplicating registry, storage, config, or policy
logic. Depot also needs to remain useful without a configuration file for local development and
agent-driven workflows.

## Decision

Depot exposes operator functionality through a shared local operations crate used by both the CLI
and MCP server.

- `depot-ops` owns config resolution, runtime construction, and typed operator operations.
- `depot-cli` owns command-line parsing, human/JSON output, and process exit behavior.
- MCP is served over stdio in the first implementation using the official Rust MCP SDK.
- CLI and MCP default to local-first execution: they build services from config/defaults and operate
  directly on OpenDAL storage and configured upstream clients.
- Config precedence is built-in defaults, config file, environment-driven config file selection, and
  CLI overrides for the current invocation.
- MCP read tools are always available. MCP write tools require an explicit startup flag.

The first operator surface includes server startup, config display and validation, registry status,
package listing, version and metadata lookup, artifact fetch, explicit artifact publish,
yank/unyank, and cache deletion. The initial CLI/MCP publish command requires explicit package
name, version, artifact filename, and optional license metadata. Native archive parsing and
ecosystem-specific publish semantics remain adapter-owned work and must not be inferred loosely by
operator commands.

## Consequences

- CLI and MCP remain behaviorally aligned because they call the same operation functions.
- The CLI can work without `depot.toml` by using safe defaults.
- MCP does not add a network listener or remote admin API surface in the first implementation.
- Remote administration over HTTP requires a separate ADR because it introduces authentication,
  authorization, and compatibility concerns beyond stdio MCP.
