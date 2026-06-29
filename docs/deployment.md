# Private Deployment Guide

## Scope

This guide is for private/internal experimental deployments.

Supported deployment posture:

- Pull-through reads/proxying only.
- PyPI, npm, Cargo, Hex, Maven, RubyGems, NuGet, and pub.dev as experimental core capabilities.
- Native publishing disabled.
- Experimental local publishing disabled unless testing it intentionally.

## Container Deploy

Docker is the primary private deployment path. The Dockerfile uses Chainguard images for both
the Rust builder and the shell-less glibc runtime, pins the default image digests, and runs the final
container as non-root UID/GID `65532`. The single image is used for both modes: `ENTRYPOINT` is
`sm`, and `CMD` is `serve`.

Build the default image:

```sh
docker build -t starmetal:local .
```

Run the deterministic container proxy E2E test:

```sh
task docker:proxy:e2e
```

This starts a local fixture upstream, starts the StarMetal image with a mounted private config and
OpenDAL filesystem volume, exercises all implemented registry proxy routes with HTTP assertions,
runs native client containers for PyPI, npm, Cargo, Maven, RubyGems, NuGet, and pub.dev, stops the
fixture upstream, restarts StarMetal with the same volume, and verifies the cached routes still
work. It also runs pnpm read-through install, cached reinstall with a fresh pnpm store, and
experimental local npm publish-then-install. Native clients run without read auth; the HTTP pass
covers Bearer auth, CORS, response limits, URL rewriting, cache writes, and sanitized error
responses.

Run the live PyPI container pressure test when you want public-network pressure coverage:

```sh
task docker:pressure:live
```

The live pressure test starts the image with a named volume, warms the PyPI route, fetches a real
artifact through Starmetal, verifies the OpenDAL filesystem writes and Blake3 sidecar, and sends
concurrent requests against cached metadata and artifact routes.

With no extra args, the image runs `sm serve`, reads `/etc/starmetal/starmetal.toml`, listens on
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
repository. The complete option reference is in [Configuration Reference](configuration.md).

```sh
docker run --rm \
  --publish 8080:8080 \
  --volume "$PWD/starmetal.toml:/etc/starmetal/starmetal.toml:ro" \
  --volume starmetal-data:/var/lib/starmetal \
  starmetal:local
```

Build a smaller image by compiling only selected adapters and filesystem storage:

```sh
docker build \
  --build-arg CARGO_FEATURES=pypi,npm,cargo-registry,hex,backend-fs \
  -t starmetal:minimal .
```

## Build From Source

```sh
cargo build --release -p starmetal-cli
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

Private experimental baseline:

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

[admin]
enabled = false
tokens = []

[publishing]
enabled = false
```

Defaults already configure public upstream URLs. By default, all implemented upstreams are enabled:
PyPI, npm, Cargo, Hex, Maven, RubyGems, NuGet, and pub.dev.

## Registry Upstreams

Override upstreams when you need a private mirror or an explicit policy boundary:

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

Run matching live E2E tasks before treating any experimental workflow as ready:

```sh
task test:e2e:maven
task test:e2e:rubygems
task test:e2e:nuget
task test:e2e:pub
```

## Start the Server

```sh
sm --config starmetal.toml serve
```

For a release binary:

```sh
./target/release/sm --config starmetal.toml serve
```

Starmetal serves HTTP. Put it behind a private network boundary or a TLS-terminating reverse proxy. Do
not expose the experimental server directly to the public internet.

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

## Admin API

Remote management is available through the admin JSON API when explicitly enabled:

```toml
[admin]
enabled = true
tokens = ["replace-with-private-admin-token"]
```

Admin routes live under `/admin/api/v1` and require `Authorization: Bearer <admin-token>`. Keep the
admin surface private and behind the same network boundary as the registry service.

## Publishing

Native publishing is not supported. Keep local publishing disabled for normal private deployments:

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
task docker:proxy:e2e
```

Use `task docker:proxy:e2e:http`, `task docker:proxy:e2e:native`, or
`task docker:proxy:e2e:pnpm` for targeted Docker proxy debugging.

Live read E2E:

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
| Maven | `http://<host>:8080/maven` |
| RubyGems | `http://<host>:8080/rubygems` |
| NuGet | `http://<host>:8080/nuget/v3/index.json` |
| pub.dev | `http://<host>:8080/pub` |

Replace `http` with `https` at the reverse proxy boundary when TLS is enabled there.
