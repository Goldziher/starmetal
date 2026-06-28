# Private Deployment Guide

## Scope

This guide is for private/internal MVP deployments.

Supported deployment posture:

- Pull-through reads only.
- PyPI, npm, Cargo, and Hex as read candidates after live E2E.
- Maven, RubyGems, NuGet, and pub.dev only when explicitly opted into beta testing.
- Native publishing disabled.
- Experimental local publishing disabled unless testing it intentionally.

## Container Deploy

Docker is the primary private-MVP deployment path. The Dockerfile uses Chainguard images for both
the Rust builder and the shell-less glibc runtime, pins the default image digests, and runs the final
container as non-root UID/GID `65532`. The single image is used for both modes: `ENTRYPOINT` is
`sm`, and `CMD` is `serve`.

Build the default image:

```sh
docker build -t starmetal:local .
```

Run the repeatable container pressure test:

```sh
task docker:pressure
```

The pressure test starts the image with a named volume, warms the PyPI route, fetches a real artifact
through Starmetal, verifies the OpenDAL filesystem writes and Blake3 sidecar, and sends concurrent
requests against cached metadata and artifact routes.

With no extra args, the image runs `sm serve`, reads `/etc/starmetal/depot.toml`, listens on
`0.0.0.0:8080`, and uses OpenDAL filesystem storage rooted at `/var/lib/starmetal`.

```sh
docker run --rm \
  --publish 8080:8080 \
  --volume starmetal-data:/var/lib/starmetal \
  starmetal:local
```

Passing args after the image name overrides the default `serve` command and runs the same binary as a
CLI or MCP tool:

```sh
docker run --rm starmetal:local config validate
docker run --rm starmetal:local registry list
docker run --rm starmetal:local mcp serve
```

For production settings, bind-mount a config file. Keep real auth and publishing tokens out of the
repository.

```sh
docker run --rm \
  --publish 8080:8080 \
  --volume "$PWD/depot.toml:/etc/starmetal/depot.toml:ro" \
  --volume starmetal-data:/var/lib/starmetal \
  starmetal:local
```

Build a smaller MVP-read image by compiling only the read candidate adapters and filesystem storage:

```sh
docker build \
  --build-arg CARGO_FEATURES=pypi,npm,cargo-registry,hex,backend-fs \
  -t starmetal:mvp .
```

## Build From Source

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
sm config init
```

Private MVP baseline:

```toml
[server]
bind = "0.0.0.0:8080"

[storage]
backend = "fs"

[storage.options]
root = "./starmetal-data"

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
sm --config depot.toml serve
```

For a release binary:

```sh
./target/release/sm --config depot.toml serve
```

Starmetal serves HTTP. Put it behind a private network boundary or a TLS-terminating reverse proxy. Do
not expose the MVP server directly to the public internet.

## OpenDAL Storage

Starmetal passes `[storage]` to OpenDAL. The `backend` value selects the OpenDAL service, and
`[storage.options]` carries backend-specific key-value options.

Filesystem storage:

```toml
[storage]
backend = "fs"

[storage.options]
root = "/var/lib/starmetal"
```

S3-compatible storage:

```toml
[storage]
backend = "s3"

[storage.s3]
bucket = "starmetal-packages"
region = "us-east-1"
# endpoint = "https://s3.amazonaws.com"
```

GCS storage:

```toml
[storage]
backend = "gcs"

[storage.gcs]
bucket = "starmetal-packages"
# credential_path = "/run/secrets/gcs.json"
```

Additional OpenDAL options can be supplied under `[storage.options]` when a deployment needs a
backend knob that is not modeled by the typed `s3` or `gcs` sections.

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

| Client | Starmetal URL |
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
