# Configuration Reference

Starmetal configuration is TOML. The runtime loads config in this order unless the CLI command
provides explicit overrides:

1. `--config <path>` when a command supports it.
2. `STARMETAL_CONFIG`.
3. `./starmetal.toml` in the current directory.
4. Built-in defaults.

Use `--no-config` on supported CLI commands to skip file lookup and use defaults plus explicit CLI
flags. Use `sm config validate` before deploying a config file.

## Minimal Docker Config

```toml
[server]
bind = "0.0.0.0:8080"

[storage]
backend = "fs"

[storage.options]
root = "/var/lib/starmetal"

[auth]
enabled = false
tokens = []

[admin]
enabled = false
tokens = []

[publishing]
enabled = false
```

Run with a mounted config:

```sh
docker run --rm \
  --publish 8080:8080 \
  --volume "$PWD/starmetal.toml:/etc/starmetal/starmetal.toml:ro" \
  --volume starmetal-data:/var/lib/starmetal \
  ghcr.io/goldziher/starmetal:latest
```

## Validation Rules

- `server.public_base_url` and every `server.cors_allowed_origins` entry must be HTTP or HTTPS URLs
  with hosts.
- `server.max_upload_bytes` must be greater than zero.
- `upstream.*.url` and `upstream.*.artifact_url` must be HTTPS unless
  `upstream.*.allow_insecure = true`.
- Local or private upstream hosts require `upstream.*.allow_private_network = true`.
- `upstream.*.max_response_bytes` must be greater than zero.
- `auth.enabled = true` requires at least one `auth.tokens` value.
- `admin.enabled = true` requires at least one `admin.tokens` value.
- `publishing.enabled = true` only supports `publishing.mode = "local"` in the MVP.
- `publishing.enabled = true` rejects any enabled `publishing.upstream.*` forwarding config.
- `publishing.enabled = true` requires at least one publish, yank, or admin scoped token.
- `signing.enabled = true` requires at least one signing key.
- Signing currently supports Starmetal DSSE-style Ed25519 PKCS#8 keys. Other configured algorithms
  are rejected until protocol-native or PQ signing implementations are added.
- Active signing keys require `private_key_file`; verify-only keys require `public_key_file`; inline
  keys and empty password environment names are rejected.
- `encryption.enabled = true` is rejected because at-rest encryption is not implemented yet.

## Server

| Option | Default | Description |
|--------|---------|-------------|
| `server.bind` | `"127.0.0.1:8080"` | Socket address the HTTP server binds. Containers normally use `0.0.0.0:8080`. |
| `server.public_base_url` | `null` | External base URL used when adapters need a public URL. |
| `server.cors_allowed_origins` | `[]` | Exact HTTP or HTTPS origins allowed by CORS. Empty means no configured origins. |
| `server.max_upload_bytes` | `536870912` | Maximum accepted upload size in bytes. |

## Storage

| Option | Default | Description |
|--------|---------|-------------|
| `storage.backend` | `"fs"` | OpenDAL backend name. Built builds include feature-gated backends such as `fs`, `s3`, `gcs`, and `memory`. |
| `storage.options` | `{}` | Extra OpenDAL key-value options passed to the selected backend. |
| `storage.path` | `null` | Filesystem convenience path. For `fs`, it becomes `storage.options.root` when `root` is not set. |
| `storage.s3` | `null` | Typed S3-compatible storage options. |
| `storage.s3.bucket` | Required when `storage.s3` is set | S3 bucket name. |
| `storage.s3.region` | Required when `storage.s3` is set | S3 region. |
| `storage.s3.endpoint` | `null` | Optional S3-compatible endpoint override. |
| `storage.gcs` | `null` | Typed Google Cloud Storage options. |
| `storage.gcs.bucket` | Required when `storage.gcs` is set | GCS bucket name. |
| `storage.gcs.credential_path` | `null` | Optional service-account credential file path. |
| `storage.gcs.endpoint` | `null` | Optional GCS-compatible endpoint override. |

Filesystem example:

```toml
[storage]
backend = "fs"
path = "/var/lib/starmetal"
```

S3-compatible example:

```toml
[storage]
backend = "s3"

[storage.s3]
bucket = "starmetal-packages"
region = "us-east-1"
endpoint = "https://s3.amazonaws.com"
```

## Read Auth

| Option | Default | Description |
|--------|---------|-------------|
| `auth.enabled` | `false` | Enables bearer-token read authentication for registry routes. |
| `auth.tokens` | `[]` | Accepted read bearer tokens. Values are redacted in admin config output. |

```toml
[auth]
enabled = true
tokens = ["replace-with-private-read-token"]
```

Do not commit real tokens.

## Admin

The admin API is mounted under `/admin/api/v1` only when `admin.enabled = true`.

| Option | Default | Description |
|--------|---------|-------------|
| `admin.enabled` | `false` | Enables the authenticated admin JSON API. |
| `admin.tokens` | `[]` | Accepted admin bearer tokens. Values are redacted in admin config output. |

Admin routes require `Authorization: Bearer <admin-token>`.

```toml
[admin]
enabled = true
tokens = ["replace-with-private-admin-token"]
```

Admin endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /admin/api/v1/status` | Version, enabled registries, compiled registries, storage backend, and feature state. |
| `GET /admin/api/v1/config` | Redacted effective config. |
| `GET /admin/api/v1/registries` | Configured, enabled, and compiled registry status. |
| `GET /admin/api/v1/packages?ecosystem=npm` | Cached package names for one ecosystem. |
| `GET /admin/api/v1/versions?ecosystem=npm&name=sample-npm` | Cached versions for one package. |
| `GET /admin/api/v1/metadata?ecosystem=npm&name=sample-npm&version=1.0.0` | Cached version metadata. |
| `GET /admin/api/v1/metrics` | In-memory statistics snapshot. |

## Publishing

Native upstream publishing is not supported. MVP publishing is local-only, experimental, and disabled
by default.

| Option | Default | Description |
|--------|---------|-------------|
| `publishing.enabled` | `false` | Enables experimental local package publishing routes. |
| `publishing.mode` | `"local"` | Publish mode. Only `"local"` is valid when publishing is enabled in the MVP. |
| `publishing.allow_shadowing` | `false` | Allows publishing a local version that shadows an upstream version. |
| `publishing.allow_overwrite` | `false` | Allows overwriting an existing local published version. |
| `publishing.tokens` | `[]` | Scoped publish tokens. Secret token values are redacted in admin config output. |
| `publishing.tokens.*.token` | Required for each token | Bearer token value used for publish or yank routes. |
| `publishing.tokens.*.scopes` | `[]` | Allowed scopes: `read`, `publish`, `yank`, or `admin`. |
| `publishing.tokens.*.ecosystems` | `[]` | Optional ecosystem allowlist. Empty means all ecosystems. |
| `publishing.tokens.*.packages` | `[]` | Optional package-name allowlist. Empty means all packages. |
| `publishing.upstream` | `{}` | Reserved map for future upstream forwarding configuration. |
| `publishing.upstream.*.enabled` | `false` | Reserved. Rejected when true in the MVP. |
| `publishing.upstream.*.token_env` | `null` | Reserved future upstream token environment variable name. |
| `publishing.upstream.*.username_env` | `null` | Reserved future upstream username environment variable name. |
| `publishing.upstream.*.password_env` | `null` | Reserved future upstream password environment variable name. |

Local npm publish test config:

```toml
[publishing]
enabled = true
mode = "local"
allow_shadowing = false
allow_overwrite = false

[[publishing.tokens]]
token = "replace-with-private-publish-token"
scopes = ["publish"]
ecosystems = ["npm"]
packages = ["local-pnpm"]
```

## Upstreams

Defaults configure all currently implemented upstreams: `pypi`, `npm`, `cargo`, `hex`, `maven`,
`rubygems`, `nuget`, and `pub`.

| Option | Default | Description |
|--------|---------|-------------|
| `upstream` | Built-in registry map | Per-registry upstream configuration map. |
| `upstream.*.enabled` | `true` | Enables the upstream registry at runtime. |
| `upstream.*.url` | Registry-specific | Metadata or index base URL. |
| `upstream.*.artifact_url` | Registry-specific or `null` | Optional artifact host when metadata and artifacts use different origins. |
| `upstream.*.allow_insecure` | `false` | Allows HTTP upstream URLs. Use only for local fixtures or trusted private networks. |
| `upstream.*.allow_private_network` | `false` | Allows local, loopback, or private-network upstream hosts. |
| `upstream.*.max_response_bytes` | `536870912` | Maximum upstream response body accepted in bytes. |

Local fixture example:

```toml
[upstream.npm]
enabled = true
url = "http://fixture-upstream:9000/npm"
allow_insecure = true
allow_private_network = true
max_response_bytes = 536870912
```

## Policies

| Option | Default | Description |
|--------|---------|-------------|
| `policies.blocked_packages` | `[]` | Exact package names blocked by policy. |
| `policies.allowed_licenses` | `[]` | Optional license allowlist. Empty means licenses are not allowlisted. |
| `policies.block_unlicensed` | `false` | Rejects packages with no license metadata when true. |
| `policies.max_vuln_severity` | `"critical"` | Reserved vulnerability severity threshold: `low`, `medium`, `high`, or `critical`. |

## Encryption

At-rest encryption config is accepted by the schema but not implemented in the MVP. Keep it disabled.

| Option | Default | Description |
|--------|---------|-------------|
| `encryption.enabled` | `false` | Must remain false. Validation rejects true. |
| `encryption.key_file` | `null` | Reserved key-file path for future encryption support. |

## Signing

Signing is disabled by default. When enabled, Starmetal signs immutable local publish statements and
metadata sidecars with DSSE-style Ed25519 signatures. Private keys are loaded from PKCS#8 PEM files;
inline keys and inline passphrases are not supported. On Unix, private key files must not grant group
or world permissions.

| Option | Default | Description |
|--------|---------|-------------|
| `signing.enabled` | `false` | Enables Starmetal signature generation and verification. |
| `signing.mode` | `"sign-and-verify"` | `sign-only`, `sign-and-verify`, or `verify-only`. `verify-only` requires public verification keys. |
| `signing.verify_on_read` | `false` | Verifies Starmetal signature sidecars before serving signed cached metadata or artifacts. `sign-and-verify` and `verify-only` enable read verification at runtime even when this is omitted. |
| `signing.sign_cached_upstream` | `false` | Signs policy-accepted upstream metadata and artifacts as Starmetal cache observations. |
| `signing.keys.*.id` | Required | Unique key identifier stored in signature envelopes. |
| `signing.keys.*.algorithm` | Required | Currently only `ed25519` is implemented. `ecdsa-p256-sha256` and `ml-dsa65` are reserved. |
| `signing.keys.*.private_key_file` | Required for active signing keys | Path to an Ed25519 PKCS#8 PEM private key file. Verify-only keys must not use private key files. |
| `signing.keys.*.public_key_file` | Required for verify-only keys | Path to an Ed25519 SPKI PEM public key file used for signature verification. |
| `signing.keys.*.private_key_password_env` | `null` | Reserved for encrypted private keys. Empty values are rejected. |
| `signing.keys.*.certificate_file` | `null` | Optional certificate file. Its SHA-256 fingerprint is embedded for identity pinning metadata. |
| `signing.keys.*.certificate_chain_file` | `null` | Optional PEM chain embedded in signature metadata. |
| `signing.keys.*.ecosystems` | `[]` | Optional ecosystem allowlist for this signing key. Empty means all ecosystems. |
| `signing.keys.*.packages` | `[]` | Optional package-name allowlist for this signing key. Empty means all packages. |
| `signing.keys.*.status` | `"active"` | `active`, `verify-only`, or `disabled`. |
| `signing.trust_roots` | `[]` | Reserved trust-root metadata for certificate pinning and future certificate-chain validation. |
| `signing.trust_roots.*.id` | Required for each trust root | Unique trust-root identifier. |
| `signing.trust_roots.*.certificate_file` | Required for each trust root | Path to a PEM certificate reserved for future trust-root validation. |
| `signing.trust_roots.*.allowed_algorithms` | `[]` | Optional algorithm allowlist for the trust root. |

Example:

```toml
[signing]
enabled = true
mode = "sign-and-verify"
verify_on_read = true
sign_cached_upstream = false

[[signing.keys]]
id = "release-2026q3"
algorithm = "ed25519"
private_key_file = "/run/secrets/starmetal/signing.pk8"
certificate_file = "/run/secrets/starmetal/signing.crt.pem"
certificate_chain_file = "/run/secrets/starmetal/chain.pem"
ecosystems = ["npm", "cargo"]
packages = []
status = "active"

[[signing.keys]]
id = "release-2026q3-public"
algorithm = "ed25519"
public_key_file = "/run/secrets/starmetal/signing.pub.pem"
ecosystems = ["npm", "cargo"]
packages = []
status = "verify-only"
```

## PQ Readiness

The `pq` feature flag reserves Starmetal-level ML-DSA/ML-KEM configuration and schema surface for
future countersignature and hybrid key-wrapping work. Native package clients do not currently verify
Starmetal PQ signatures, so do not claim package-client post-quantum verification until a native
client path exists.

## Operational Notes

- The admin config endpoint returns a redacted config; it does not expose auth, admin, or publishing
  token values, signing key paths, signing verification key paths, signing password environment
  names, certificate paths, or trust root paths.
- Metrics are in-memory process counters exposed through `GET /admin/api/v1/metrics`; they reset on
  restart.
- Blake3 sidecar files are stored beside artifacts and verified before cached artifacts are served.
- Public TLS, identity, and network isolation should be handled by private infrastructure in front of
  Starmetal for now.
