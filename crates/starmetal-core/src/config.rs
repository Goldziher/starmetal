use std::collections::HashMap;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Result, StarmetalError};
use crate::package::Ecosystem;
use crate::policy::PolicyConfig;
use crate::publishing::{PublishMode, PublishTokenConfig, TokenScope};
use crate::repository::RepositoryKind;
use crate::signing::{SigningAlgorithm, SigningConfig, SigningKeyStatus, SigningMode};

pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_MAX_UPSTREAM_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default = "default_upstreams")]
    pub upstream: HashMap<String, UpstreamConfig>,
    #[serde(default)]
    pub repositories: Vec<RepositoryConfig>,
    #[serde(default)]
    pub policies: PolicyConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub publishing: PublishingConfig,
    #[serde(default)]
    pub encryption: EncryptionConfig,
    #[serde(default)]
    pub signing: SigningConfig,
    #[serde(default)]
    pub metadata: MetadataConfig,
    #[serde(default)]
    pub supply_chain: SupplyChainConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub public_base_url: Option<String>,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            public_base_url: None,
            cors_allowed_origins: Vec::new(),
            max_upload_bytes: default_max_upload_bytes(),
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1:8080".into()
}

fn default_max_upload_bytes() -> u64 {
    DEFAULT_MAX_UPLOAD_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub s3: Option<S3Config>,
    #[serde(default)]
    pub gcs: Option<GcsConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_backend(),
            options: HashMap::new(),
            path: None,
            s3: None,
            gcs: None,
        }
    }
}

fn default_backend() -> String {
    "fs".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GcsConfig {
    pub bucket: String,
    pub credential_path: Option<PathBuf>,
    pub endpoint: Option<String>,
}

impl StorageConfig {
    pub fn opendal_options(&self) -> HashMap<String, String> {
        let mut options = self.options.clone();

        if self.backend == "fs"
            && let Some(path) = &self.path
        {
            options
                .entry("root".to_string())
                .or_insert_with(|| path.to_string_lossy().to_string());
        }

        if self.backend == "s3"
            && let Some(s3) = &self.s3
        {
            options.entry("bucket".to_string()).or_insert_with(|| s3.bucket.clone());
            options.entry("region".to_string()).or_insert_with(|| s3.region.clone());
            if let Some(endpoint) = &s3.endpoint {
                options
                    .entry("endpoint".to_string())
                    .or_insert_with(|| endpoint.clone());
            }
        }

        if self.backend == "gcs"
            && let Some(gcs) = &self.gcs
        {
            options
                .entry("bucket".to_string())
                .or_insert_with(|| gcs.bucket.clone());
            if let Some(path) = &gcs.credential_path {
                options
                    .entry("credential_path".to_string())
                    .or_insert_with(|| path.to_string_lossy().to_string());
            }
            if let Some(endpoint) = &gcs.endpoint {
                options
                    .entry("endpoint".to_string())
                    .or_insert_with(|| endpoint.clone());
            }
        }

        options
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpstreamConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub url: String,
    #[serde(default)]
    pub artifact_url: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub allow_private_network: bool,
    #[serde(default = "default_max_upstream_bytes")]
    pub max_response_bytes: u64,
}

fn default_true() -> bool {
    true
}

fn default_max_upstream_bytes() -> u64 {
    DEFAULT_MAX_UPSTREAM_BYTES
}

/// A declared repository (ADR-0019): a `(kind, ecosystem)` surface mounted under
/// its own URL segment.
///
/// When [`Config::repositories`] is empty, Starmetal derives one `proxy`
/// repository per enabled `[upstream]` ecosystem (see
/// [`Config::resolved_repositories`]), preserving the historical proxy-only
/// behavior. Only `proxy` repositories are supported today; `hosted` and `group`
/// are reserved for later stages and rejected by [`Config::validate_mvp`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RepositoryConfig {
    /// URL mount segment and identity of the repository (e.g. `pypi`). Must be
    /// unique across repositories.
    pub name: String,
    /// The repository kind: `proxy`, `hosted`, or `group`.
    pub kind: RepositoryKind,
    /// The ecosystem this repository serves.
    pub ecosystem: Ecosystem,
}

#[derive(Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tokens: Vec<String>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("enabled", &self.enabled)
            .field("tokens", &format!("[{} redacted]", self.tokens.len()))
            .finish()
    }
}

#[derive(Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tokens: Vec<String>,
}

impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("enabled", &self.enabled)
            .field("tokens", &format!("[{} redacted]", self.tokens.len()))
            .finish()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct EncryptionConfig {
    #[serde(default)]
    pub enabled: bool,
    pub key_file: Option<PathBuf>,
}

/// Optional Postgres-backed content model (ADR-0020). When enabled, publishes dual-write the
/// component -> asset -> blob content model, giving cross-ecosystem blob dedup, content-address
/// integrity, and reference-counted garbage collection alongside the flat object store.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MetadataConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Postgres connection URL (`postgresql://user:password@host:port/database`). Required when
    /// `enabled` is true; redacted from the admin API's config view.
    pub database_url: Option<String>,
    /// Apply the content-model schema on startup — convenient for turnkey deployments. Disable when
    /// migrations are managed out of band.
    #[serde(default = "default_true")]
    pub apply_schema: bool,
    /// Interval in seconds between scheduled garbage-collection sweeps (ADR-0020 Stage 2d). `0`
    /// (the default) disables the scheduler. Only effective when `enabled`.
    #[serde(default)]
    pub gc_interval_secs: u64,
    /// Grace window in seconds applied to every blob newly soft-deleted by a GC sweep before a
    /// later sweep's compact step may hard-delete it.
    #[serde(default = "default_gc_grace_secs")]
    pub gc_grace_secs: u64,
    /// Interval in seconds between scheduled retention sweeps (ADR-0020 Stage 2c). `0` (the
    /// default) disables the scheduler. Only effective when `enabled`.
    #[serde(default)]
    pub retention_interval_secs: u64,
    /// The retention policy applied by the scheduled retention sweep when neither a per-repository
    /// nor a per-ecosystem policy matches a component family. An empty policy (the default) is a
    /// no-op. Precedence is `retention_per_repository` > `retention_per_ecosystem` > `retention`.
    #[serde(default)]
    pub retention: crate::content::RetentionPolicy,
    /// Retention policies keyed by canonical ecosystem name (`"pypi"`, `"npm"`, `"cargo"`, `"hex"`,
    /// `"maven"`, `"rubygems"`, `"nuget"`, `"pub"`). A family whose ecosystem matches uses this
    /// policy in preference to the global `retention` (but a matching `retention_per_repository`
    /// still wins). Empty by default.
    #[serde(default)]
    pub retention_per_ecosystem: HashMap<String, crate::content::RetentionPolicy>,
    /// Retention policies keyed by repository attribution string (see
    /// [`crate::content::Component::repository`]). A family whose repository matches uses this
    /// policy in preference to both `retention_per_ecosystem` and the global `retention`. Keys are
    /// free-form (no validation). Empty by default.
    #[serde(default)]
    pub retention_per_repository: HashMap<String, crate::content::RetentionPolicy>,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_url: None,
            apply_schema: true,
            gc_interval_secs: 0,
            gc_grace_secs: default_gc_grace_secs(),
            retention_interval_secs: 0,
            retention: crate::content::RetentionPolicy::default(),
            retention_per_ecosystem: HashMap::new(),
            retention_per_repository: HashMap::new(),
        }
    }
}

/// Default GC grace window: 24 hours, in seconds.
fn default_gc_grace_secs() -> u64 {
    24 * 60 * 60
}

/// Which artifact scanner backs the supply-chain vulnerability gate (ADR-0024).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScannerKind {
    /// The OSV.dev query-API scanner.
    #[default]
    Osv,
}

/// Optional supply-chain security controls (ADR-0024). When enabled, publishes are gated at ingest:
/// each artifact is scanned and denied when a finding exceeds `policies.max_vuln_severity`. Requires
/// the corresponding scanner build feature (e.g. `scanner-osv`); disabled by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct SupplyChainConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The scanner backend to use.
    #[serde(default)]
    pub scanner: ScannerKind,
    /// Override the OSV endpoint base URL (defaults to the public `https://api.osv.dev`). Useful for
    /// a self-hosted OSV mirror.
    #[serde(default)]
    pub osv_endpoint: Option<String>,
    /// Also enforce the vulnerability gate at serve: `get_artifact` consults each artifact's stored
    /// scan report (scanning on demand and caching it when absent) and refuses to serve a finding
    /// that exceeds `policies.max_vuln_severity`. Off by default — ingest gating only.
    #[serde(default)]
    pub enforce_on_serve: bool,
    /// Interval in seconds between scheduled re-correlation sweeps. Each sweep re-scans every stored
    /// scan report against the (refreshed) advisory feed and rewrites it, so an artifact that was
    /// clean when first scanned is re-evaluated as new advisories land ("scan once, then monitor").
    /// `0` (the default) disables the scheduler. Only effective when a scanner is attached.
    #[serde(default)]
    pub recorrelation_interval_secs: u64,
    /// Hold a serve-time gate block as a recoverable quarantine record (an operator can promote or
    /// reject it via the admin API) instead of a terminal deny. Off by default — blocks are hard
    /// denials. Only effective with `enforce_on_serve` and a scanner attached.
    #[serde(default)]
    pub quarantine: bool,
    /// Hold a blocked hosted *publish* as a recoverable quarantine record instead of hard-denying it:
    /// the uploaded bytes are parked off the live path for operator review, then promoted (which
    /// completes the deferred publish) or rejected (which purges the bytes) via the admin API. Off by
    /// default — a blocked publish is denied. Only effective with a scanner attached.
    #[serde(default)]
    pub ingest_quarantine: bool,
    /// SBOM generation controls. When enabled, each published artifact gets an SBOM document per
    /// configured format, stored digest-keyed and retrievable via the admin API.
    #[serde(default)]
    pub sbom: SbomConfig,
    /// Require a valid Starmetal DSSE signature to serve/publish an artifact (ADR-0024). A missing
    /// or invalid signature is denied (`missing-signature`) at both ingest and serve. Requires
    /// signing to be configured (`[signing]`). Off by default.
    #[serde(default)]
    pub require_signature: bool,
    /// Require a valid Starmetal in-toto/SLSA provenance attestation to serve/publish an artifact
    /// (ADR-0024). When set, publishes and cache-fills emit a signed provenance attestation, and a
    /// missing or invalid one is denied (`failing-provenance`) at both ingest and serve. Requires
    /// signing to be configured. Off by default.
    #[serde(default)]
    pub require_provenance: bool,
    /// Publish quota reserve/reconcile controls (ADR-0021): a ceiling on published version count
    /// and/or cumulative artifact bytes per `(ecosystem, namespace)` coordinate, enforced by an
    /// in-memory ledger around the publish path. Off by default.
    #[serde(default)]
    pub quota: QuotaConfig,
}

/// Publish quota controls (ADR-0021). When enabled, a hosted publish that would push its
/// `(ecosystem, namespace)` coordinate over its resolved [`QuotaLimits`] is denied with
/// [`crate::supply_chain::PolicyReason::QuotaExceeded`]. The namespace is the component's grouping
/// (npm scope, Maven group id; see [`crate::package::PackageName::publish_namespace`]) — `None` for
/// ecosystems without one. Off by default so it is inert until an operator configures a limit; the
/// reserve/reconcile ledger itself is process-local and lives in `starmetal-service`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct QuotaConfig {
    /// Enable publish quota enforcement. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Quota limits for a specific ecosystem, keyed by its config name (`"pypi"`, `"npm"`, `"cargo"`,
    /// `"hex"`, `"maven"`, `"rubygems"`, `"nuget"`, `"pub"`). Takes precedence over `default_limits`
    /// for a matching ecosystem.
    #[serde(default)]
    pub per_ecosystem: HashMap<String, QuotaLimits>,
    /// Fallback limits applied to any ecosystem without a `per_ecosystem` entry. `None` leaves an
    /// unlisted ecosystem unlimited.
    #[serde(default)]
    pub default_limits: Option<QuotaLimits>,
}

/// One quota ceiling pair (ADR-0021) for a `(ecosystem, namespace)` coordinate. Each dimension is
/// independently optional; `None` leaves that dimension unlimited.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct QuotaLimits {
    /// Maximum number of published versions for the coordinate. `None` is unlimited.
    #[serde(default)]
    pub max_versions: Option<u64>,
    /// Maximum cumulative artifact bytes for the coordinate. `None` is unlimited.
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

/// SBOM generation controls (ADR-0024). Independent of the scanner: SBOMs are generated from the
/// publish request, so this needs no scanner feature or backend.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SbomConfig {
    /// Generate and store SBOM documents on publish. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Formats to generate for each artifact. Defaults to both CycloneDX and SPDX.
    #[serde(default = "default_sbom_formats")]
    pub formats: Vec<crate::supply_chain::SbomFormat>,
}

impl Default for SbomConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            formats: default_sbom_formats(),
        }
    }
}

fn default_sbom_formats() -> Vec<crate::supply_chain::SbomFormat> {
    vec![
        crate::supply_chain::SbomFormat::CycloneDx,
        crate::supply_chain::SbomFormat::Spdx,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PublishingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: PublishMode,
    #[serde(default)]
    pub allow_shadowing: bool,
    #[serde(default)]
    pub allow_overwrite: bool,
    #[serde(default)]
    pub tokens: Vec<PublishTokenConfig>,
    #[serde(default)]
    pub upstream: HashMap<String, PublishingUpstreamConfig>,
}

impl Default for PublishingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: PublishMode::Local,
            allow_shadowing: false,
            allow_overwrite: false,
            tokens: Vec::new(),
            upstream: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PublishingUpstreamConfig {
    #[serde(default)]
    pub enabled: bool,
    pub token_env: Option<String>,
    pub username_env: Option<String>,
    pub password_env: Option<String>,
}

impl Config {
    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(StarmetalError::ConfigNotFound(path.to_path_buf()));
        }
        let contents = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&contents)?;
        config.apply_default_upstreams();
        Ok(config)
    }

    /// Load config with default lookup chain:
    /// 1. `STARMETAL_CONFIG` env var
    /// 2. `./starmetal.toml` in current directory
    /// 3. Defaults
    pub fn load() -> Result<Self> {
        if let Ok(path) = std::env::var("STARMETAL_CONFIG") {
            let p = PathBuf::from(path);
            if p.exists() {
                return Self::load_from(&p);
            }
            return Err(StarmetalError::ConfigNotFound(p));
        }

        let local = PathBuf::from("starmetal.toml");
        if local.exists() {
            return Self::load_from(&local);
        }

        Ok(Self::default())
    }

    pub fn validate_mvp(&self) -> Result<()> {
        if let Some(base_url) = &self.server.public_base_url {
            validate_public_base_url(base_url)?;
        }

        if self.server.max_upload_bytes == 0 {
            return Err(StarmetalError::Config(
                "server.max_upload_bytes must be greater than zero".to_string(),
            ));
        }

        for origin in &self.server.cors_allowed_origins {
            validate_public_base_url(origin)?;
        }

        for (name, upstream) in &self.upstream {
            validate_upstream_url(name, &upstream.url, upstream)?;
            if let Some(artifact_url) = &upstream.artifact_url {
                validate_upstream_url(name, artifact_url, upstream)?;
            }
            if upstream.max_response_bytes == 0 {
                return Err(StarmetalError::Config(format!(
                    "upstream.{name}.max_response_bytes must be greater than zero"
                )));
            }
        }

        let mut repository_names = std::collections::HashSet::new();
        for repository in &self.repositories {
            if repository.name.trim().is_empty() {
                return Err(StarmetalError::Config("repository name must not be empty".to_string()));
            }
            if !repository_names.insert(repository.name.as_str()) {
                return Err(StarmetalError::Config(format!(
                    "duplicate repository name: {}",
                    repository.name
                )));
            }
            if repository.kind != RepositoryKind::Proxy {
                return Err(StarmetalError::Config(format!(
                    "repository '{}' uses kind '{}'; only 'proxy' repositories are supported in this MVP",
                    repository.name, repository.kind
                )));
            }
        }

        validate_encryption_config(&self.encryption)?;
        validate_signing_config(&self.signing)?;
        validate_quota_config(&self.supply_chain.quota)?;
        validate_retention_config(&self.metadata)?;

        if self.auth.enabled && self.auth.tokens.is_empty() {
            return Err(StarmetalError::Config(
                "auth.enabled requires at least one bearer token".to_string(),
            ));
        }

        if self.admin.enabled && self.admin.tokens.is_empty() {
            return Err(StarmetalError::Config(
                "admin.enabled requires at least one bearer token".to_string(),
            ));
        }

        if self.publishing.enabled {
            if self.publishing.mode != PublishMode::Local {
                return Err(StarmetalError::Config(
                    "publishing.enabled only supports mode = \"local\" in this MVP".to_string(),
                ));
            }
            if self.publishing.upstream.values().any(|upstream| upstream.enabled) {
                return Err(StarmetalError::Config(
                    "publishing upstream forwarding is not implemented in this MVP".to_string(),
                ));
            }
            let has_write_token = self.publishing.tokens.iter().any(|token| {
                token.scopes.contains(&TokenScope::Admin)
                    || token.scopes.contains(&TokenScope::Publish)
                    || token.scopes.contains(&TokenScope::Yank)
            });
            if !has_write_token {
                return Err(StarmetalError::Config(
                    "publishing.enabled requires at least one scoped publish, yank, or admin token".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn apply_default_upstreams(&mut self) {
        for (name, config) in default_upstreams() {
            self.upstream.entry(name).or_insert(config);
        }
    }

    pub fn upstream_enabled(&self, name: &str) -> bool {
        self.upstream.get(name).map(|config| config.enabled).unwrap_or(true)
    }

    /// The effective set of repositories to mount (ADR-0019).
    ///
    /// If [`Config::repositories`] is non-empty, it is returned verbatim
    /// (sorted by name for deterministic mounting). Otherwise one `proxy`
    /// repository is derived per **enabled** `[upstream]` ecosystem, mounted
    /// under the ecosystem's own name — reproducing the historical proxy-only
    /// behavior. Upstream keys that do not name a known ecosystem are skipped.
    pub fn resolved_repositories(&self) -> Vec<RepositoryConfig> {
        let mut repositories = if self.repositories.is_empty() {
            self.upstream
                .iter()
                .filter(|(_, upstream)| upstream.enabled)
                .filter_map(|(name, _)| {
                    name.parse::<Ecosystem>().ok().map(|ecosystem| RepositoryConfig {
                        name: name.clone(),
                        kind: RepositoryKind::Proxy,
                        ecosystem,
                    })
                })
                .collect()
        } else {
            self.repositories.clone()
        };
        repositories.sort_by(|a, b| a.name.cmp(&b.name));
        repositories
    }

    pub fn redacted_value(&self) -> toml::Value {
        let mut value = toml::Value::try_from(self).unwrap_or_else(|_| toml::Value::Table(Default::default()));
        if let Some(auth) = value.get_mut("auth").and_then(toml::Value::as_table_mut)
            && let Some(tokens) = auth.get_mut("tokens").and_then(toml::Value::as_array_mut)
        {
            for token in tokens {
                *token = toml::Value::String("<redacted>".to_string());
            }
        }
        if let Some(admin) = value.get_mut("admin").and_then(toml::Value::as_table_mut)
            && let Some(tokens) = admin.get_mut("tokens").and_then(toml::Value::as_array_mut)
        {
            for token in tokens {
                *token = toml::Value::String("<redacted>".to_string());
            }
        }
        if let Some(publishing) = value.get_mut("publishing").and_then(toml::Value::as_table_mut)
            && let Some(tokens) = publishing.get_mut("tokens").and_then(toml::Value::as_array_mut)
        {
            for token in tokens {
                if let Some(table) = token.as_table_mut()
                    && let Some(secret) = table.get_mut("token")
                {
                    *secret = toml::Value::String("<redacted>".to_string());
                }
            }
        }
        if let Some(metadata) = value.get_mut("metadata").and_then(toml::Value::as_table_mut)
            && let Some(database_url) = metadata.get_mut("database_url")
        {
            *database_url = toml::Value::String("<redacted>".to_string());
        }
        redact_signing_config(&mut value);
        value
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            upstream: default_upstreams(),
            repositories: Vec::new(),
            policies: PolicyConfig::default(),
            auth: AuthConfig::default(),
            admin: AdminConfig::default(),
            publishing: PublishingConfig::default(),
            encryption: EncryptionConfig::default(),
            signing: SigningConfig::default(),
            metadata: MetadataConfig::default(),
            supply_chain: SupplyChainConfig::default(),
        }
    }
}

fn default_upstreams() -> HashMap<String, UpstreamConfig> {
    let mut upstream = HashMap::new();
    upstream.insert(
        "pypi".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://pypi.org".into(),
            artifact_url: None,
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: default_max_upstream_bytes(),
        },
    );
    upstream.insert(
        "npm".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://registry.npmjs.org".into(),
            artifact_url: None,
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: default_max_upstream_bytes(),
        },
    );
    upstream.insert(
        "cargo".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://index.crates.io".into(),
            artifact_url: Some("https://static.crates.io/crates".into()),
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: default_max_upstream_bytes(),
        },
    );
    upstream.insert(
        "hex".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://hex.pm".into(),
            artifact_url: Some("https://repo.hex.pm".into()),
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: default_max_upstream_bytes(),
        },
    );
    upstream.insert(
        "maven".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://repo1.maven.org/maven2".into(),
            artifact_url: None,
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: default_max_upstream_bytes(),
        },
    );
    upstream.insert(
        "rubygems".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://rubygems.org".into(),
            artifact_url: Some("https://rubygems.org".into()),
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: default_max_upstream_bytes(),
        },
    );
    upstream.insert(
        "nuget".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://api.nuget.org/v3/index.json".into(),
            artifact_url: None,
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: default_max_upstream_bytes(),
        },
    );
    upstream.insert(
        "pub".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://pub.dev".into(),
            artifact_url: None,
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: default_max_upstream_bytes(),
        },
    );
    upstream
}

fn validate_public_base_url(value: &str) -> Result<()> {
    let parsed =
        url::Url::parse(value).map_err(|err| StarmetalError::Config(format!("invalid URL '{value}': {err}")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(StarmetalError::Config(format!(
                "URL '{value}' must use http or https, not {scheme}"
            )));
        }
    }
    if parsed.host_str().is_none() {
        return Err(StarmetalError::Config(format!("URL '{value}' must include a host")));
    }
    Ok(())
}

fn validate_upstream_url(name: &str, value: &str, config: &UpstreamConfig) -> Result<()> {
    let parsed = url::Url::parse(value)
        .map_err(|err| StarmetalError::Config(format!("invalid upstream URL for {name} ('{value}'): {err}")))?;

    match parsed.scheme() {
        "https" => {}
        "http" if config.allow_insecure => {}
        scheme => {
            return Err(StarmetalError::Config(format!(
                "upstream.{name} URL must use https unless allow_insecure is true; got {scheme}"
            )));
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| StarmetalError::Config(format!("upstream.{name} URL must include a host")))?;
    if is_private_host(host) && !config.allow_private_network {
        return Err(StarmetalError::Config(format!(
            "upstream.{name} URL points at a private/local host; set allow_private_network = true to permit it"
        )));
    }

    Ok(())
}

fn is_private_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast()
        }
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local(),
        Err(_) => false,
    }
}

fn validate_encryption_config(config: &EncryptionConfig) -> Result<()> {
    if config.enabled {
        return Err(StarmetalError::Config(
            "at-rest encryption is not implemented; config is reserved for the signing/PQ roadmap".to_string(),
        ));
    }
    Ok(())
}

fn validate_signing_config(config: &SigningConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    if config.keys.is_empty() {
        return Err(StarmetalError::Config(
            "signing.enabled requires at least one signing key".to_string(),
        ));
    }

    let mut ids = std::collections::HashSet::new();
    let mut active_keys = 0usize;
    let mut verification_keys = 0usize;
    for key in &config.keys {
        if key.id.trim().is_empty() {
            return Err(StarmetalError::Config("signing key id must not be empty".to_string()));
        }
        if !ids.insert(key.id.as_str()) {
            return Err(StarmetalError::Config(format!("duplicate signing key id: {}", key.id)));
        }
        if key.algorithm != SigningAlgorithm::Ed25519 {
            return Err(StarmetalError::Config(format!(
                "signing key {} uses unsupported algorithm {:?}; only ed25519 is implemented",
                key.id, key.algorithm
            )));
        }
        if key.status == SigningKeyStatus::VerifyOnly && key.private_key_file.is_some() {
            return Err(StarmetalError::Config(format!(
                "verify-only signing key {} must use public_key_file instead of private_key_file",
                key.id
            )));
        }
        if key.status == SigningKeyStatus::VerifyOnly && key.public_key_file.is_none() {
            return Err(StarmetalError::Config(format!(
                "verify-only signing key {} requires public_key_file",
                key.id
            )));
        }
        if matches!(config.mode, SigningMode::SignOnly | SigningMode::SignAndVerify)
            && key.status == SigningKeyStatus::Active
        {
            active_keys += 1;
            if key.private_key_file.is_none() {
                return Err(StarmetalError::Config(format!(
                    "active signing key {} requires private_key_file",
                    key.id
                )));
            }
        }
        if matches!(config.mode, SigningMode::SignAndVerify | SigningMode::VerifyOnly)
            && key.status != SigningKeyStatus::Disabled
            && (key.public_key_file.is_some() || key.private_key_file.is_some())
        {
            verification_keys += 1;
        }
        if key.private_key_password_env.as_deref() == Some("") {
            return Err(StarmetalError::Config(format!(
                "signing key {} private_key_password_env must not be empty",
                key.id
            )));
        }
    }

    if matches!(config.mode, SigningMode::SignOnly | SigningMode::SignAndVerify) && active_keys == 0 {
        return Err(StarmetalError::Config(
            "signing requires at least one active signing key".to_string(),
        ));
    }
    if matches!(config.mode, SigningMode::SignAndVerify | SigningMode::VerifyOnly) && verification_keys == 0 {
        return Err(StarmetalError::Config(
            "signature verification requires at least one public or active signing key".to_string(),
        ));
    }

    Ok(())
}

/// Reject a `supply_chain.quota.per_ecosystem` map keyed by anything other than a canonical ecosystem
/// name. The quota gate resolves a limit via `ecosystem.to_string()` (the `Display` form), so a key
/// that is misspelled (`NPM`) or a non-canonical alias (`crates`, which `FromStr` accepts but `Display`
/// never produces) would silently never match and fail open to `default_limits`/unlimited. Failing
/// startup instead turns that operator footgun into a loud error.
fn validate_quota_config(config: &QuotaConfig) -> Result<()> {
    for key in config.per_ecosystem.keys() {
        match key.parse::<Ecosystem>() {
            Ok(ecosystem) if &ecosystem.to_string() == key => {}
            Ok(ecosystem) => {
                return Err(StarmetalError::Config(format!(
                    "supply_chain.quota.per_ecosystem key '{key}' is not the canonical ecosystem name; \
                     use '{ecosystem}'"
                )));
            }
            Err(_) => {
                return Err(StarmetalError::Config(format!(
                    "supply_chain.quota.per_ecosystem key '{key}' is not a known ecosystem"
                )));
            }
        }
    }
    Ok(())
}

/// Reject a `metadata.retention_per_ecosystem` map keyed by anything other than a canonical
/// ecosystem name. The retention sweep resolves a per-ecosystem policy by matching the family's
/// `ecosystem.to_string()` (the `Display` form), so a misspelled (`NPM`) or non-canonical alias
/// (`crates`) key would silently never match and fall through to the global policy. Failing startup
/// turns that footgun into a loud error, mirroring [`validate_quota_config`].
/// `retention_per_repository` keys are free-form and intentionally not validated.
fn validate_retention_config(config: &MetadataConfig) -> Result<()> {
    for key in config.retention_per_ecosystem.keys() {
        match key.parse::<Ecosystem>() {
            Ok(ecosystem) if &ecosystem.to_string() == key => {}
            Ok(ecosystem) => {
                return Err(StarmetalError::Config(format!(
                    "metadata.retention_per_ecosystem key '{key}' is not the canonical ecosystem name; \
                     use '{ecosystem}'"
                )));
            }
            Err(_) => {
                return Err(StarmetalError::Config(format!(
                    "metadata.retention_per_ecosystem key '{key}' is not a known ecosystem"
                )));
            }
        }
    }
    Ok(())
}

fn redact_signing_config(value: &mut toml::Value) {
    let Some(signing) = value.get_mut("signing").and_then(toml::Value::as_table_mut) else {
        return;
    };
    if let Some(keys) = signing.get_mut("keys").and_then(toml::Value::as_array_mut) {
        for key in keys {
            let Some(table) = key.as_table_mut() else {
                continue;
            };
            for field in [
                "private_key_file",
                "public_key_file",
                "private_key_password_env",
                "certificate_file",
                "certificate_chain_file",
            ] {
                if table.contains_key(field) {
                    table.insert(field.to_string(), toml::Value::String("<redacted>".to_string()));
                }
            }
        }
    }
    if let Some(roots) = signing.get_mut("trust_roots").and_then(toml::Value::as_array_mut) {
        for root in roots {
            if let Some(table) = root.as_table_mut()
                && table.contains_key("certificate_file")
            {
                table.insert(
                    "certificate_file".to_string(),
                    toml::Value::String("<redacted>".to_string()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixtures() -> Vec<serde_json::Value> {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testing_data/config/01_config_parsing.json");
        let content = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(&content).unwrap()
    }

    #[test]
    fn fixture_driven_config_parsing() {
        let fixtures = load_fixtures();
        for fix in &fixtures {
            let name = fix["name"].as_str().unwrap_or("?");
            let toml_input = fix["input"]["toml"].as_str().unwrap();

            if let Some(expected_err) = fix["error"].as_str() {
                let result: std::result::Result<Config, _> = toml::from_str(toml_input);
                assert!(result.is_err(), "fixture '{name}' should fail to parse");
                let _ = expected_err;
                continue;
            }

            let config: Config = toml::from_str(toml_input).unwrap_or_else(|e| panic!("fixture '{name}': {e}"));

            if let Some(bind) = fix["expected"]["bind"].as_str() {
                assert_eq!(config.server.bind, bind, "fixture '{name}' bind");
            }
            if let Some(backend) = fix["expected"]["storage_backend"].as_str() {
                assert_eq!(config.storage.backend, backend, "fixture '{name}' backend");
            }
            if let Some(bucket) = fix["expected"]["s3_bucket"].as_str() {
                assert_eq!(
                    config.storage.s3.as_ref().unwrap().bucket,
                    bucket,
                    "fixture '{name}' s3 bucket"
                );
                assert_eq!(
                    config.storage.opendal_options().get("bucket"),
                    Some(&bucket.to_string()),
                    "fixture '{name}' s3 bucket option"
                );
            }
            if let Some(block) = fix["expected"]["block_unlicensed"].as_bool() {
                assert_eq!(
                    config.policies.block_unlicensed, block,
                    "fixture '{name}' block_unlicensed"
                );
            }
            if let Some(auth) = fix["expected"]["auth_enabled"].as_bool() {
                assert_eq!(config.auth.enabled, auth, "fixture '{name}' auth_enabled");
            }
        }
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("starmetal.toml");
        std::fs::write(&path, "[server]\nbind = \"127.0.0.1:9999\"\n").unwrap();

        let config = Config::load_from(&path).unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:9999");
    }

    #[test]
    fn load_from_missing_file() {
        let result = Config::load_from(Path::new("/nonexistent/starmetal.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn defaults_have_all_upstreams() {
        let config = Config::default();
        for ecosystem in ["pypi", "npm", "cargo", "hex", "maven", "rubygems", "nuget", "pub"] {
            assert!(
                config.upstream_enabled(ecosystem),
                "{ecosystem} should be enabled by default"
            );
        }
    }

    #[test]
    fn storage_options_are_preserved() {
        let config: Config =
            toml::from_str("[storage]\nbackend = \"gcs\"\n\n[storage.options]\nbucket = \"pkg-cache\"\ncredential_path = \"/tmp/gcs.json\"\n")
                .unwrap();

        let options = config.storage.opendal_options();
        assert_eq!(options.get("bucket"), Some(&"pkg-cache".to_string()));
        assert_eq!(options.get("credential_path"), Some(&"/tmp/gcs.json".to_string()));
    }

    #[test]
    fn legacy_fs_path_maps_to_root_option() {
        let config: Config = toml::from_str("[storage]\nbackend = \"fs\"\npath = \"./cache\"\n").unwrap();

        assert_eq!(
            config.storage.opendal_options().get("root"),
            Some(&"./cache".to_string())
        );
    }

    #[test]
    fn startup_validation_rejects_empty_auth_tokens() {
        let config: Config = toml::from_str("[auth]\nenabled = true\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("auth.enabled requires"));
    }

    #[test]
    fn startup_validation_rejects_encryption() {
        let config: Config = toml::from_str("[encryption]\nenabled = true\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("encryption is not implemented"));
    }

    #[test]
    fn startup_validation_rejects_signing_without_keys() {
        let config: Config = toml::from_str("[signing]\nenabled = true\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("signing.enabled requires"));
    }

    #[test]
    fn startup_validation_rejects_a_noncanonical_quota_ecosystem_key() {
        let config: Config = toml::from_str("[supply_chain.quota.per_ecosystem.NPM]\nmax_versions = 5\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(
            err.contains("canonical ecosystem name") && err.contains("'npm'"),
            "expected a canonical-name hint, got: {err}"
        );
    }

    #[test]
    fn startup_validation_rejects_an_unknown_quota_ecosystem_key() {
        let config: Config = toml::from_str("[supply_chain.quota.per_ecosystem.banana]\nmax_versions = 5\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("not a known ecosystem"), "got: {err}");
    }

    #[test]
    fn startup_validation_accepts_a_canonical_quota_ecosystem_key() {
        let config: Config = toml::from_str("[supply_chain.quota.per_ecosystem.npm]\nmax_versions = 5\n").unwrap();
        assert!(config.validate_mvp().is_ok());
    }

    #[test]
    fn startup_validation_rejects_a_noncanonical_retention_ecosystem_key() {
        let config: Config = toml::from_str("[metadata.retention_per_ecosystem.NPM]\nrules = []\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(
            err.contains("canonical ecosystem name") && err.contains("'npm'"),
            "expected a canonical-name hint, got: {err}"
        );
    }

    #[test]
    fn startup_validation_rejects_an_unknown_retention_ecosystem_key() {
        let config: Config = toml::from_str("[metadata.retention_per_ecosystem.banana]\nrules = []\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("not a known ecosystem"), "got: {err}");
    }

    #[test]
    fn startup_validation_accepts_a_canonical_retention_ecosystem_key() {
        let config: Config = toml::from_str(
            "[metadata.retention_per_ecosystem.pypi]\nrules = [{ strategy = \"keep-latest\", count = 3 }]\n",
        )
        .unwrap();
        assert!(config.validate_mvp().is_ok());
    }

    #[test]
    fn startup_validation_does_not_validate_retention_repository_keys() {
        // Repository keys are free-form: an arbitrary string that is not an ecosystem is accepted.
        let config: Config = toml::from_str(
            "[metadata.retention_per_repository.\"team-internal\"]\nrules = [{ strategy = \"keep-latest\", count = 5 }]\n",
        )
        .unwrap();
        assert!(config.validate_mvp().is_ok());
        assert_eq!(config.metadata.retention_per_repository.len(), 1);
    }

    #[test]
    fn metadata_per_family_retention_maps_default_empty() {
        let metadata = MetadataConfig::default();
        assert!(metadata.retention_per_ecosystem.is_empty());
        assert!(metadata.retention_per_repository.is_empty());
    }

    #[test]
    fn startup_validation_rejects_duplicate_signing_key_ids() {
        let config: Config = toml::from_str(
            r#"
[signing]
enabled = true

[[signing.keys]]
id = "release"
algorithm = "ed25519"
private_key_file = "/run/secrets/starmetal/signing-a.pk8"

[[signing.keys]]
id = "release"
algorithm = "ed25519"
private_key_file = "/run/secrets/starmetal/signing-b.pk8"
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("duplicate signing key id: release"));
    }

    #[test]
    fn startup_validation_rejects_unsupported_signing_algorithm() {
        let config: Config = toml::from_str(
            r#"
[signing]
enabled = true

[[signing.keys]]
id = "release"
algorithm = "ecdsa-p256-sha256"
private_key_file = "/run/secrets/starmetal/signing.pk8"
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("unsupported algorithm"));
    }

    #[test]
    fn startup_validation_rejects_active_signing_key_without_private_key_file() {
        let config: Config = toml::from_str(
            r#"
[signing]
enabled = true

[[signing.keys]]
id = "release"
algorithm = "ed25519"
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("requires private_key_file"));
    }

    #[test]
    fn startup_validation_rejects_verify_only_key_without_public_key_file() {
        let config: Config = toml::from_str(
            r#"
[signing]
enabled = true
mode = "verify-only"

[[signing.keys]]
id = "release"
algorithm = "ed25519"
status = "verify-only"
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("requires public_key_file"));
    }

    #[test]
    fn startup_validation_accepts_verify_only_public_key_file() {
        let config: Config = toml::from_str(
            r#"
[signing]
enabled = true
mode = "verify-only"

[[signing.keys]]
id = "release"
algorithm = "ed25519"
public_key_file = "/run/secrets/starmetal/signing.pub.pem"
status = "verify-only"
"#,
        )
        .unwrap();

        assert!(config.validate_mvp().is_ok());
    }

    #[test]
    fn startup_validation_rejects_empty_signing_password_env() {
        let config: Config = toml::from_str(
            r#"
[signing]
enabled = true

[[signing.keys]]
id = "release"
algorithm = "ed25519"
private_key_file = "/run/secrets/starmetal/signing.pk8"
private_key_password_env = ""
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("private_key_password_env must not be empty"));
    }

    #[test]
    fn redacted_value_hides_auth_tokens() {
        let config: Config = toml::from_str("[auth]\nenabled = true\ntokens = [\"secret-token\"]\n").unwrap();
        let output = toml::to_string_pretty(&config.redacted_value()).unwrap();
        assert!(!output.contains("secret-token"));
        assert!(output.contains("<redacted>"));
    }

    #[test]
    fn startup_validation_rejects_publishing_without_write_tokens() {
        let config: Config = toml::from_str("[publishing]\nenabled = true\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("publishing.enabled requires"));
    }

    #[test]
    fn startup_validation_rejects_admin_without_tokens() {
        let config: Config = toml::from_str("[admin]\nenabled = true\n").unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("admin.enabled requires"));
    }

    #[test]
    fn startup_validation_rejects_non_local_publishing_mode() {
        let config: Config = toml::from_str(
            r#"
[publishing]
enabled = true
mode = "forward-only"

[[publishing.tokens]]
token = "publish-secret"
scopes = ["publish"]
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("only supports mode = \"local\""));
    }

    #[test]
    fn startup_validation_rejects_enabled_publishing_upstream_forwarding() {
        let config: Config = toml::from_str(
            r#"
[publishing]
enabled = true

[[publishing.tokens]]
token = "publish-secret"
scopes = ["publish"]

[publishing.upstream.npm]
enabled = true
token_env = "NPM_TOKEN"
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("publishing upstream forwarding is not implemented"));
    }

    #[test]
    fn redacted_value_hides_publishing_tokens() {
        let config: Config = toml::from_str(
            r#"
[publishing]
enabled = true

[[publishing.tokens]]
token = "publish-secret"
scopes = ["publish"]
"#,
        )
        .unwrap();

        let output = toml::to_string_pretty(&config.redacted_value()).unwrap();
        assert!(!output.contains("publish-secret"));
        assert!(output.contains("<redacted>"));
    }

    #[test]
    fn redacted_value_hides_admin_tokens() {
        let config: Config = toml::from_str(
            r#"
[admin]
enabled = true
tokens = ["admin-secret"]
"#,
        )
        .unwrap();

        let output = toml::to_string_pretty(&config.redacted_value()).unwrap();
        assert!(!output.contains("admin-secret"));
        assert!(output.contains("<redacted>"));
    }

    #[test]
    fn redacted_value_hides_signing_paths_and_trust_roots() {
        let config: Config = toml::from_str(
            r#"
[signing]
enabled = true

[[signing.keys]]
id = "release"
algorithm = "ed25519"
private_key_file = "/run/secrets/starmetal/signing.pk8"
public_key_file = "/run/secrets/starmetal/signing.pub.pem"
private_key_password_env = "STARMETAL_SIGNING_KEY_PASSWORD"
certificate_file = "/run/secrets/starmetal/signing.crt.pem"
certificate_chain_file = "/run/secrets/starmetal/chain.pem"

[[signing.trust_roots]]
id = "internal-ca"
certificate_file = "/etc/starmetal/trust/internal-ca.pem"
"#,
        )
        .unwrap();

        let output = toml::to_string_pretty(&config.redacted_value()).unwrap();
        assert!(!output.contains("/run/secrets"));
        assert!(!output.contains("STARMETAL_SIGNING_KEY_PASSWORD"));
        assert!(!output.contains("/etc/starmetal/trust"));
        assert!(output.contains("<redacted>"));
    }

    #[test]
    fn metadata_defaults_to_disabled_with_schema_provisioning() {
        let metadata = MetadataConfig::default();
        assert!(!metadata.enabled);
        assert!(metadata.database_url.is_none());
        assert!(
            metadata.apply_schema,
            "schema provisioning is on by default for turnkey deploys"
        );
        assert_eq!(metadata.gc_interval_secs, 0, "GC scheduler is disabled by default");
        assert_eq!(metadata.gc_grace_secs, 24 * 60 * 60, "default GC grace is 24 hours");
        assert_eq!(
            metadata.retention_interval_secs, 0,
            "retention scheduler is disabled by default"
        );
        assert!(
            metadata.retention.rules.is_empty(),
            "default retention policy is a no-op"
        );
    }

    #[test]
    fn supply_chain_defaults_to_disabled_osv() {
        let supply_chain = SupplyChainConfig::default();
        assert!(!supply_chain.enabled);
        assert_eq!(supply_chain.scanner, ScannerKind::Osv);
        assert!(supply_chain.osv_endpoint.is_none());
        assert!(!supply_chain.enforce_on_serve);
        assert_eq!(
            supply_chain.recorrelation_interval_secs, 0,
            "re-correlation scheduler is disabled by default"
        );
        assert!(!supply_chain.quarantine, "quarantine mode is off by default");
        assert!(
            !supply_chain.ingest_quarantine,
            "ingest quarantine mode is off by default"
        );
        assert!(
            !supply_chain.require_signature,
            "signature gate is off by default (fail-open guard)"
        );
        assert!(
            !supply_chain.require_provenance,
            "provenance gate is off by default (fail-open guard)"
        );
        assert!(!supply_chain.quota.enabled, "publish quota is off by default");
        assert!(
            supply_chain.quota.per_ecosystem.is_empty(),
            "no per-ecosystem quota limits by default"
        );
        assert!(
            supply_chain.quota.default_limits.is_none(),
            "no fallback quota limits by default"
        );
    }

    #[test]
    fn redacted_value_hides_metadata_database_url() {
        let config: Config = toml::from_str(
            r#"
[metadata]
enabled = true
database_url = "postgresql://starmetal:s3cr3t@db.internal:5432/starmetal"
"#,
        )
        .unwrap();

        assert!(config.metadata.enabled);
        let output = toml::to_string_pretty(&config.redacted_value()).unwrap();
        assert!(!output.contains("s3cr3t"));
        assert!(!output.contains("db.internal"));
        assert!(output.contains("<redacted>"));
    }

    #[test]
    fn startup_validation_rejects_insecure_upstream_by_default() {
        let config: Config = toml::from_str(
            r#"
[upstream.pypi]
url = "http://pypi.example.test"
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("allow_insecure"));
    }

    #[test]
    fn startup_validation_rejects_private_upstream_by_default() {
        let config: Config = toml::from_str(
            r#"
[upstream.pypi]
url = "https://127.0.0.1:9000"
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("private/local host"));
    }

    #[test]
    fn startup_validation_allows_explicit_local_insecure_upstream() {
        let config: Config = toml::from_str(
            r#"
[upstream.pypi]
url = "http://127.0.0.1:9000"
allow_insecure = true
allow_private_network = true
"#,
        )
        .unwrap();

        config.validate_mvp().unwrap();
    }

    #[test]
    fn startup_validation_rejects_zero_upload_limit() {
        let config: Config = toml::from_str(
            r#"
[server]
max_upload_bytes = 0
"#,
        )
        .unwrap();

        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("max_upload_bytes"));
    }

    #[test]
    fn resolved_repositories_derives_one_proxy_per_enabled_upstream() {
        let config = Config::default();
        let repositories = config.resolved_repositories();
        assert_eq!(repositories.len(), 8, "one proxy per default upstream");
        assert!(
            repositories.iter().all(|repo| repo.kind == RepositoryKind::Proxy),
            "derived repositories are all proxies"
        );
        // Deterministic ordering by name.
        let names: Vec<&str> = repositories.iter().map(|repo| repo.name.as_str()).collect();
        assert_eq!(
            names,
            ["cargo", "hex", "maven", "npm", "nuget", "pub", "pypi", "rubygems"]
        );
        let pypi = repositories.iter().find(|repo| repo.name == "pypi").unwrap();
        assert_eq!(pypi.ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn resolved_repositories_skips_disabled_upstreams() {
        let mut config = Config::default();
        config.upstream.get_mut("npm").unwrap().enabled = false;
        let repositories = config.resolved_repositories();
        assert_eq!(repositories.len(), 7);
        assert!(repositories.iter().all(|repo| repo.name != "npm"));
    }

    #[test]
    fn explicit_repositories_override_derivation() {
        let config: Config = toml::from_str(
            r#"
[[repositories]]
name = "python"
kind = "proxy"
ecosystem = "pypi"
"#,
        )
        .unwrap();
        let repositories = config.resolved_repositories();
        assert_eq!(repositories.len(), 1);
        assert_eq!(repositories[0].name, "python");
        assert_eq!(repositories[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(repositories[0].kind, RepositoryKind::Proxy);
    }

    #[test]
    fn startup_validation_rejects_non_proxy_repositories() {
        let config: Config = toml::from_str(
            r#"
[[repositories]]
name = "hosted-pypi"
kind = "hosted"
ecosystem = "pypi"
"#,
        )
        .unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("only 'proxy' repositories are supported"), "got: {err}");
    }

    #[test]
    fn startup_validation_rejects_duplicate_repository_names() {
        let config: Config = toml::from_str(
            r#"
[[repositories]]
name = "dup"
kind = "proxy"
ecosystem = "pypi"

[[repositories]]
name = "dup"
kind = "proxy"
ecosystem = "npm"
"#,
        )
        .unwrap();
        let err = config.validate_mvp().unwrap_err().to_string();
        assert!(err.contains("duplicate repository name: dup"), "got: {err}");
    }
}
