use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahash::AHashMap;
use bytes::Bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use starmetal_core::config::{Config, DEFAULT_MAX_UPSTREAM_BYTES, UpstreamConfig};
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName, VersionMetadata};
use starmetal_core::ports::{
    PackageService, PublishingService, StatisticsService, StoragePort, UpstreamClient,
};
use starmetal_core::publishing::{PublishRequest, PublishedArtifact, YankRequest};
use starmetal_server::state::{AppState, UpstreamClients};
use starmetal_service::CachingPackageService;
use starmetal_storage::OpenDalStorage;

#[derive(Debug, Clone, Default)]
pub struct ConfigLoadOptions {
    pub path: Option<PathBuf>,
    pub no_config: bool,
    pub overrides: ConfigOverrides,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigOverrides {
    pub bind: Option<String>,
    pub storage_backend: Option<String>,
    pub storage_options: Vec<(String, String)>,
    pub upstreams: Vec<UpstreamOverride>,
}

#[derive(Debug, Clone)]
pub struct UpstreamOverride {
    pub name: String,
    pub enabled: Option<bool>,
    pub url: Option<String>,
    pub artifact_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegistryStatus {
    pub ecosystem: Ecosystem,
    pub configured: bool,
    pub enabled: bool,
    pub compiled: bool,
    pub url: Option<String>,
    pub artifact_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeStatus {
    pub bind: String,
    pub storage_backend: String,
    pub registries: Vec<RegistryStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactFetchResult {
    pub artifact: ArtifactId,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CacheDeleteResult {
    pub deleted_keys: Vec<String>,
}

#[derive(Clone)]
pub struct StarmetalRuntime {
    pub config: Config,
    pub storage: Arc<dyn StoragePort>,
    pub package_service: Arc<dyn PackageService>,
    pub publishing_service: Arc<dyn PublishingService>,
    pub statistics_service: Arc<dyn StatisticsService>,
    pub upstreams: UpstreamClients,
}

impl StarmetalRuntime {
    pub async fn new(options: ConfigLoadOptions) -> Result<Self> {
        let config = load_config(options)?;
        config.validate_mvp()?;
        Self::from_config(config).await
    }

    pub async fn from_config(config: Config) -> Result<Self> {
        let storage = Arc::new(OpenDalStorage::from_config(&config.storage)?);
        #[allow(unused_mut)]
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();

        #[cfg(feature = "pypi")]
        let pypi_upstream = register_pypi_upstream(&config, &mut clients);
        #[cfg(feature = "cargo-registry")]
        let cargo_upstream = register_cargo_upstream(&config, &mut clients);
        #[cfg(feature = "npm")]
        let npm_upstream = register_npm_upstream(&config, &mut clients);
        #[cfg(feature = "hex")]
        let hex_upstream = register_hex_upstream(&config, &mut clients);
        #[cfg(feature = "maven")]
        let maven_upstream = register_maven_upstream(&config, &mut clients);
        #[cfg(feature = "rubygems")]
        let rubygems_upstream = register_rubygems_upstream(&config, &mut clients);
        #[cfg(feature = "nuget")]
        let nuget_upstream = register_nuget_upstream(&config, &mut clients);
        #[cfg(feature = "pub")]
        let pub_upstream = register_pub_upstream(&config, &mut clients);

        let service = Arc::new(CachingPackageService::new(
            storage.clone(),
            clients,
            config.policies.clone(),
        ));
        let upstreams = UpstreamClients {
            #[cfg(feature = "pypi")]
            pypi_upstream,
            #[cfg(feature = "cargo-registry")]
            cargo_upstream,
            #[cfg(feature = "npm")]
            npm_upstream,
            #[cfg(feature = "hex")]
            hex_upstream,
            #[cfg(feature = "maven")]
            maven_upstream,
            #[cfg(feature = "rubygems")]
            rubygems_upstream,
            #[cfg(feature = "nuget")]
            nuget_upstream,
            #[cfg(feature = "pub")]
            pub_upstream,
        };

        Ok(Self {
            config,
            storage,
            package_service: service.clone(),
            publishing_service: service.clone(),
            statistics_service: service,
            upstreams,
        })
    }

    pub fn app_state(&self) -> AppState {
        AppState::new(
            self.config.clone(),
            self.package_service.clone(),
            self.publishing_service.clone(),
            self.statistics_service.clone(),
            self.upstreams.clone(),
        )
    }

    pub fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            bind: self.config.server.bind.clone(),
            storage_backend: self.config.storage.backend.clone(),
            registries: registry_statuses(&self.config),
        }
    }

    pub async fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<PackageRef>> {
        let mut packages = self.package_service.list_packages(ecosystem).await?;
        packages.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(packages
            .into_iter()
            .map(|name| PackageRef {
                ecosystem,
                name: name.as_str().to_string(),
            })
            .collect())
    }

    pub async fn versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<starmetal_core::package::VersionInfo>> {
        let name = normalize_name(ecosystem, name);
        self.package_service.list_versions(ecosystem, &name).await
    }

    pub async fn metadata(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
    ) -> Result<VersionMetadata> {
        let name = normalize_name(ecosystem, name);
        self.package_service
            .get_version_metadata(ecosystem, &name, version)
            .await
    }

    pub async fn fetch_artifact(&self, artifact: ArtifactId) -> Result<(ArtifactId, Bytes)> {
        let data = self.package_service.get_artifact(&artifact).await?;
        Ok((artifact, data))
    }

    pub async fn set_yanked(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        yanked: bool,
    ) -> Result<VersionMetadata> {
        self.publishing_service
            .set_yanked(YankRequest {
                ecosystem,
                name: normalize_name(ecosystem, name),
                version: version.to_string(),
                yanked,
            })
            .await
    }

    pub async fn publish_artifact(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        filename: String,
        data: Bytes,
        license: Option<String>,
    ) -> Result<starmetal_core::publishing::PublishResult> {
        if !self.config.publishing.enabled {
            return Err(StarmetalError::Config(
                "publishing is disabled in the effective config".to_string(),
            ));
        }
        self.publishing_service
            .publish_package(PublishRequest {
                ecosystem,
                name: normalize_name(ecosystem, name),
                version: version.to_string(),
                license,
                yanked: false,
                artifacts: vec![PublishedArtifact {
                    filename,
                    data,
                    upstream_hashes: Default::default(),
                }],
                allow_overwrite: self.config.publishing.allow_overwrite,
                allow_shadowing: self.config.publishing.allow_shadowing,
            })
            .await
    }

    pub async fn delete_cached_artifact(&self, artifact: &ArtifactId) -> Result<CacheDeleteResult> {
        let key = artifact.validated_storage_key()?.into_string();
        let sidecar = format!("{key}.blake3");
        let mut deleted_keys = Vec::new();
        for candidate in [&key, &sidecar] {
            if self.storage.exists(candidate).await? {
                self.storage.delete(candidate).await?;
                deleted_keys.push(candidate.to_string());
            }
        }
        Ok(CacheDeleteResult { deleted_keys })
    }
}

pub fn load_config(options: ConfigLoadOptions) -> Result<Config> {
    let mut config = if options.no_config {
        Config::default()
    } else if let Some(path) = &options.path {
        Config::load_from(path)?
    } else {
        Config::load()?
    };
    apply_overrides(&mut config, options.overrides);
    Ok(config)
}

pub fn write_minimal_config(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(StarmetalError::Config(format!(
            "config file already exists: {}",
            path.display()
        )));
    }
    std::fs::write(path, minimal_config())?;
    Ok(())
}

pub fn minimal_config() -> &'static str {
    r#"# Starmetal configuration

[server]
bind = "127.0.0.1:8080"
max_upload_bytes = 536870912

[storage]
backend = "fs"

[storage.options]
root = "./starmetal-data"

[auth]
enabled = false
tokens = []

[publishing]
enabled = false
"#
}

fn apply_overrides(config: &mut Config, overrides: ConfigOverrides) {
    if let Some(bind) = overrides.bind {
        config.server.bind = bind;
    }
    if let Some(backend) = overrides.storage_backend {
        config.storage.backend = backend;
    }
    for (key, value) in overrides.storage_options {
        config.storage.options.insert(key, value);
    }
    for upstream in overrides.upstreams {
        let entry = config
            .upstream
            .entry(upstream.name)
            .or_insert_with(|| UpstreamConfig {
                enabled: true,
                url: String::new(),
                artifact_url: None,
                allow_insecure: false,
                allow_private_network: false,
                max_response_bytes: DEFAULT_MAX_UPSTREAM_BYTES,
            });
        if let Some(enabled) = upstream.enabled {
            entry.enabled = enabled;
        }
        if let Some(url) = upstream.url {
            entry.url = url;
        }
        if upstream.artifact_url.is_some() {
            entry.artifact_url = upstream.artifact_url;
        }
    }
}

fn normalize_name(ecosystem: Ecosystem, name: &str) -> PackageName {
    let raw = PackageName::new(name);
    PackageName::new(raw.normalized(ecosystem).into_owned())
}

fn registry_statuses(config: &Config) -> Vec<RegistryStatus> {
    [
        (Ecosystem::PyPI, "pypi", cfg!(feature = "pypi")),
        (Ecosystem::Npm, "npm", cfg!(feature = "npm")),
        (Ecosystem::Cargo, "cargo", cfg!(feature = "cargo-registry")),
        (Ecosystem::Hex, "hex", cfg!(feature = "hex")),
        (Ecosystem::Maven, "maven", cfg!(feature = "maven")),
        (Ecosystem::RubyGems, "rubygems", cfg!(feature = "rubygems")),
        (Ecosystem::NuGet, "nuget", cfg!(feature = "nuget")),
        (Ecosystem::Pub, "pub", cfg!(feature = "pub")),
    ]
    .into_iter()
    .map(|(ecosystem, key, compiled)| {
        let upstream = config.upstream.get(key);
        RegistryStatus {
            ecosystem,
            configured: upstream.is_some(),
            enabled: upstream.map(|upstream| upstream.enabled).unwrap_or(false),
            compiled,
            url: upstream.map(|upstream| upstream.url.clone()),
            artifact_url: upstream.and_then(|upstream| upstream.artifact_url.clone()),
        }
    })
    .collect()
}

#[cfg(feature = "maven")]
fn register_maven_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::maven::upstream::MavenUpstreamClient> {
    let upstream_config = config
        .upstream
        .get("maven")
        .expect("default maven upstream");
    let client = Arc::new(
        starmetal_adapters::maven::upstream::MavenUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Maven, client.clone());
    }
    client
}

#[cfg(feature = "rubygems")]
fn register_rubygems_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient> {
    let upstream_config = config
        .upstream
        .get("rubygems")
        .expect("default rubygems upstream");
    let client = Arc::new(
        starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient::with_max_response_bytes(
            upstream_config
                .artifact_url
                .clone()
                .unwrap_or_else(|| upstream_config.url.clone()),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::RubyGems, client.clone());
    }
    client
}

#[cfg(feature = "nuget")]
fn register_nuget_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::nuget::upstream::NuGetUpstreamClient> {
    let upstream_config = config
        .upstream
        .get("nuget")
        .expect("default nuget upstream");
    let client = Arc::new(
        starmetal_adapters::nuget::upstream::NuGetUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::NuGet, client.clone());
    }
    client
}

#[cfg(feature = "pub")]
fn register_pub_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::pubdev::upstream::PubUpstreamClient> {
    let upstream_config = config.upstream.get("pub").expect("default pub upstream");
    let client = Arc::new(
        starmetal_adapters::pubdev::upstream::PubUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Pub, client.clone());
    }
    client
}

#[cfg(feature = "pypi")]
fn register_pypi_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::pypi::upstream::PypiUpstreamClient> {
    let upstream_config = config.upstream.get("pypi").expect("default pypi upstream");
    let client = Arc::new(
        starmetal_adapters::pypi::upstream::PypiUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::PyPI, client.clone());
    }
    client
}

#[cfg(feature = "npm")]
fn register_npm_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::npm::upstream::NpmUpstreamClient> {
    let upstream_config = config.upstream.get("npm").expect("default npm upstream");
    let client = Arc::new(
        starmetal_adapters::npm::upstream::NpmUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Npm, client.clone());
    }
    client
}

#[cfg(feature = "cargo-registry")]
fn register_cargo_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::cargo::upstream::CargoUpstreamClient> {
    let upstream_config = config
        .upstream
        .get("cargo")
        .expect("default cargo upstream");
    let artifact_url = upstream_config
        .artifact_url
        .clone()
        .unwrap_or_else(|| "https://static.crates.io/crates".to_string());
    let client = Arc::new(
        starmetal_adapters::cargo::upstream::CargoUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            artifact_url,
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Cargo, client.clone());
    }
    client
}

#[cfg(feature = "hex")]
fn register_hex_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::hex::upstream::HexUpstreamClient> {
    let upstream_config = config.upstream.get("hex").expect("default hex upstream");
    let artifact_url = upstream_config
        .artifact_url
        .clone()
        .unwrap_or_else(|| "https://repo.hex.pm".to_string());
    let client = Arc::new(
        starmetal_adapters::hex::upstream::HexUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            artifact_url,
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Hex, client.clone());
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_config_uses_defaults_and_overrides() {
        let config = load_config(ConfigLoadOptions {
            no_config: true,
            overrides: ConfigOverrides {
                bind: Some("127.0.0.1:9999".to_string()),
                storage_backend: Some("memory".to_string()),
                storage_options: vec![("root".to_string(), "/tmp/ignored".to_string())],
                upstreams: vec![UpstreamOverride {
                    name: "pypi".to_string(),
                    enabled: Some(false),
                    url: Some("https://example.test".to_string()),
                    artifact_url: None,
                }],
            },
            path: None,
        })
        .expect("config should load");
        assert_eq!(config.server.bind, "127.0.0.1:9999");
        assert_eq!(config.storage.backend, "memory");
        assert!(!config.upstream["pypi"].enabled);
        assert_eq!(config.upstream["pypi"].url, "https://example.test");
    }

    #[test]
    fn config_init_refuses_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("starmetal.toml");
        std::fs::write(&path, "exists").expect("write");
        let err = write_minimal_config(&path).expect_err("existing config should fail");
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn publish_artifact_stores_metadata() {
        let mut config = Config::default();
        config.storage.backend = "memory".to_string();
        config.publishing.enabled = true;
        for upstream in config.upstream.values_mut() {
            upstream.enabled = false;
        }
        let runtime = StarmetalRuntime::from_config(config)
            .await
            .expect("runtime should build");
        runtime
            .publish_artifact(
                Ecosystem::Npm,
                "sample",
                "1.0.0",
                "sample-1.0.0.tgz".to_string(),
                Bytes::from_static(b"artifact"),
                Some("MIT".to_string()),
            )
            .await
            .expect("publish should succeed");
        let metadata = runtime
            .metadata(Ecosystem::Npm, "sample", "1.0.0")
            .await
            .expect("metadata should load");
        assert_eq!(metadata.artifacts[0].filename, "sample-1.0.0.tgz");
    }
}
