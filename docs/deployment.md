# Private Deployment Guide

## Scope

This guide is for private/internal MVP deployments.

Supported deployment posture:

- Pull-through reads only.
- PyPI, npm, Cargo, and Hex as read candidates after live E2E.
- Maven, RubyGems, NuGet, and pub.dev only when explicitly opted into beta testing.
- Native publishing disabled.
- Experimental local publishing disabled unless testing it intentionally.

## Build

```sh
cargo build --release -p depot-cli
```

For development workflows, prefer the Taskfile:

```sh
task setup
task sccache:stats
```

`sccache` is optional. The Taskfile uses it automatically when it is installed.

## Minimal Config

Generate a starter config:

```sh
cargo run -p depot-cli -- config init
```

Private MVP baseline:

```toml
[server]
bind = "127.0.0.1:8080"

[storage]
backend = "fs"

[storage.options]
root = "./depot-data"

[auth]
enabled = false
tokens = []

[publishing]
enabled = false
```

Defaults already configure public upstream URLs. By default, PyPI, npm, Cargo, and Hex are enabled;
Maven, RubyGems, NuGet, and pub.dev are disabled.

## Opt Into Beta Read Adapters

Enable beta adapters only for explicit validation:

```toml
[upstream.maven]
enabled = true
url = "https://repo1.maven.org/maven2"

[upstream.rubygems]
enabled = true
url = "https://rubygems.org"
artifact_url = "https://rubygems.org"

[upstream.nuget]
enabled = true
url = "https://api.nuget.org/v3/index.json"

[upstream.pub]
enabled = true
url = "https://pub.dev"
```

Run the matching live E2E task before treating a beta workflow as ready:

```sh
task test:e2e:maven
task test:e2e:rubygems
task test:e2e:nuget
task test:e2e:pub
```

## Start the Server

```sh
cargo run -p depot-cli -- --config depot.toml serve
```

For a release binary:

```sh
./target/release/depot-cli --config depot.toml serve
```

Depot serves HTTP. Put it behind a private network boundary or a TLS-terminating reverse proxy. Do
not expose the MVP server directly to the public internet.

## Authentication

Read authentication is optional. If enabled, configure bearer tokens in an uncommitted private config
or secret-managed deployment file:

```toml
[auth]
enabled = true
tokens = ["replace-with-private-token"]
```

Do not commit real tokens.

## Publishing

Native publishing is out of MVP. Keep publishing disabled for normal private deployments:

```toml
[publishing]
enabled = false
```

Experimental local publishing requires explicit enablement and scoped tokens. Use it only for
internal validation:

```toml
[publishing]
enabled = true
allow_shadowing = false
allow_overwrite = false

[[publishing.tokens]]
token = "replace-with-private-publish-token"
scopes = ["publish"]
ecosystems = ["pypi"]
packages = ["example"]
```

Do not commit real publishing tokens.

## Readiness Checks

Offline checks:

```sh
cargo fmt --check
cargo test --workspace
task schema:check
task schema:validate
task conformance
```

Live read E2E for MVP candidates:

```sh
task test:e2e:pypi
task test:e2e:npm
task test:e2e:cargo
task test:e2e:hex
```

These live tests require network access and native package-manager CLIs.

## Client URLs

Use these route bases when configuring private clients:

| Client | Depot URL |
|--------|-----------|
| pip | `http://<host>:8080/pypi/simple/` |
| npm | `http://<host>:8080/npm` |
| Cargo | `sparse+http://<host>:8080/cargo/` |
| Hex | `http://<host>:8080/hex` |
| Maven beta | `http://<host>:8080/maven` |
| RubyGems beta | `http://<host>:8080/rubygems` |
| NuGet beta | `http://<host>:8080/nuget/v3/index.json` |
| pub.dev beta | `http://<host>:8080/pub` |

Replace `http` with `https` at the reverse proxy boundary when TLS is enabled there.
