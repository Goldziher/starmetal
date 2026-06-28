# Architecture

## Overview

Starmetal is a private/internal package registry cache. It speaks native package registry protocols,
stores artifacts through OpenDAL, verifies cached bytes with Blake3 sidecars, and applies policy in
the service layer.

Support is experimental and read/proxy focused:

- PyPI, npm, Cargo, Hex, Maven, RubyGems, NuGet, and pub.dev are experimental core capabilities.
- Native publishing is not supported.
- Local publishing is experimental and disabled by default.

See [ADR-0011](adr/0011-mvp-support-matrix.md) for the support matrix.

## Component Model

```mermaid
graph TB
    subgraph Clients
        pip[pip]
        npm_cli[npm]
        cargo_cli[cargo]
        mix[mix]
        extra_clients[Maven / Bundler / dotnet / dart pub]
    end

    subgraph Middleware
        trace[TraceLayer]
        cors[CorsLayer]
        auth[Optional bearer auth]
        compress[CompressionLayer]
    end

    subgraph Adapters
        pypi[PyPI]
        npm[npm]
        cargo[Cargo]
        hex[Hex]
        extra[Maven / RubyGems / NuGet / pub.dev]
    end

    subgraph Service
        package_service[PackageService]
        caching[CachingPackageService]
        publishing[PublishingService experimental]
        policy[Policy]
        integrity[Blake3 sidecars]
    end

    subgraph Ports
        storage[StoragePort]
        upstreams[UpstreamClient]
    end

    subgraph Backends
        fs[Filesystem]
        s3[S3-compatible]
        gcs[GCS]
        memory[Memory]
    end

    pip --> trace
    npm_cli --> trace
    cargo_cli --> trace
    mix --> trace
    extra_clients --> trace

    trace --> cors --> auth --> compress

    compress --> pypi
    compress --> npm
    compress --> cargo
    compress --> hex
    compress --> extra

    pypi --> package_service
    npm --> package_service
    cargo --> package_service
    hex --> package_service
    extra --> package_service

    pypi -. native shape .-> upstreams
    npm -. native shape .-> upstreams
    cargo -. native shape .-> upstreams
    hex -. native shape .-> upstreams
    extra -. native shape .-> upstreams

    package_service --> caching
    publishing --> caching
    caching --> policy
    caching --> integrity
    caching --> storage
    caching --> upstreams

    storage --> fs
    storage --> s3
    storage --> gcs
    storage --> memory
```

## Crate Boundaries

```mermaid
graph LR
    cli[depot-cli] --> ops[depot-ops]
    ops --> server[depot-server]
    ops --> service[depot-service]
    ops --> storage[depot-storage]
    ops --> adapters[depot-adapters]
    server --> adapters
    server --> service
    adapters --> core[depot-core]
    service --> core
    storage --> core
```

| Crate | Purpose |
|-------|---------|
| `depot-core` | Domain types, config, policy, ports, lock file, registry schema types |
| `depot-service` | Pull-through cache, Blake3 verification, policy checks, experimental local publishing |
| `depot-storage` | OpenDAL `StoragePort` implementation |
| `depot-adapters` | Feature-gated protocol routers and upstream clients |
| `depot-server` | Axum app assembly and Tower middleware |
| `depot-ops` | Shared local runtime and operator operations |
| `depot-cli` | Clap CLI and stdio MCP server |
| `tests/conformance` | Offline schema, protocol, and route conformance tests |
| `tests/integration` | Ignored live native-client E2E tests |

`depot-core` must stay framework-free. All I/O crosses port traits.

## Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant Adapter
    participant UpstreamClient
    participant Service as CachingPackageService
    participant Storage

    Client->>Adapter: Native metadata request
    Adapter->>Service: list_versions(ecosystem, name)
    Service->>UpstreamClient: fetch_versions(name)
    UpstreamClient-->>Service: version list
    Service-->>Adapter: VersionMetadata
    Adapter->>UpstreamClient: read cached native payload
    Adapter-->>Client: Native response with Starmetal URLs

    Client->>Adapter: Artifact download
    Adapter->>Service: get_artifact(artifact_id)
    Service->>Storage: read artifact and .blake3 sidecar
    alt Cache hit
        Service->>Service: verify Blake3
    else Cache miss
        Service->>UpstreamClient: fetch_artifact(artifact_id)
        Service->>Service: verify upstream hash when present
        Service->>Storage: store artifact and .blake3 sidecar
    end
    Service-->>Adapter: artifact bytes
    Adapter-->>Client: native artifact response
```

## Registry Read Surface

| Registry | Route prefix | Default enabled | Read status |
|----------|--------------|-----------------|-------------|
| PyPI | `/pypi` | Yes | Experimental core |
| npm | `/npm` | Yes | Experimental core |
| Cargo | `/cargo` | Yes | Experimental core |
| Hex | `/hex` | Yes | Experimental core |
| Maven | `/maven` | Yes | Experimental core |
| RubyGems | `/rubygems` | Yes | Experimental core |
| NuGet | `/nuget` | Yes | Experimental core |
| pub.dev | `/pub` | Yes | Experimental core |

Runtime defaults are defined in `Config::default()`. Full CLI builds compile all adapters, but
compiled does not mean production-supported.

## Publishing Scope

Native publishing is not supported. Existing write routes and `sm package publish` are experimental
local publishing surfaces:

- Disabled by default through `[publishing] enabled = false`.
- Require scoped publish, yank, or admin tokens when enabled.
- Store local metadata and artifacts through `PublishingService`.
- Do not forward uploads upstream.
- Do not provide full owner, organization, invitation, search, or admin behavior.

## Storage

Artifact keys use:

```text
<ecosystem>/<name>/<version>/<filename>
```

Additional service-managed keys include:

- `<artifact>.blake3`
- `<ecosystem>/<name>/_versions.json`
- `<ecosystem>/<name>/<version>/_metadata.json`
- `<ecosystem>/<name>/_raw_upstream`
- `_depot/published/<ecosystem>/<name>/<version>.json`

## Schemas

Schema provenance and generated validation artifacts live in `schemas/`.

```text
schemas/
├── sources.toml
├── manifest.json
├── upstream/
├── registries/
└── depot/
```

Use:

```sh
task schema:check
task schema:validate
task conformance
```

Runtime upstream-response validation is deferred. Schemas support documentation and tests; they do
not create support claims without live E2E evidence.

## ADRs

- [0001 - Hexagonal Architecture](adr/0001-hexagonal-architecture.md)
- [0002 - Tower Middleware](adr/0002-tower-middleware.md)
- [0003 - OpenDAL Storage](adr/0003-opendal-storage.md)
- [0004 - Blake3 and Lock File](adr/0004-blake3-lockfile.md)
- [0005 - Protocol Adapters](adr/0005-protocol-adapters.md)
- [0006 - Feature Flags](adr/0006-feature-flags.md)
- [0007 - JSON Schema Validation](adr/0007-json-schema-validation.md)
- [0008 - Registry Expansion, superseded](adr/0008-registry-expansion.md)
- [0009 - Publishing and Upload Workflows](adr/0009-publishing-upload-workflows.md)
- [0010 - CLI and MCP Operations](adr/0010-cli-mcp-operations.md)
- [0011 - Experimental Support Matrix](adr/0011-mvp-support-matrix.md)
- [0012 - CI Quality Gates](adr/0012-ci-quality-gates.md)
- [0013 - Basemind and AI-Rulez Alignment](adr/0013-basemind-ai-rulez-alignment.md)
