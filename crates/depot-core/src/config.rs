use std::collections::HashMap;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{DepotError, Result};
use crate::policy::PolicyConfig;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default = "default_upstreams")]
    pub upstream: HashMap<String, UpstreamConfig>,
    #[serde(default)]
    pub policies: PolicyConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub encryption: EncryptionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0:8080".into()
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
            options
                .entry("bucket".to_string())
                .or_insert_with(|| s3.bucket.clone());
            options
                .entry("region".to_string())
                .or_insert_with(|| s3.region.clone());
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
}

fn default_true() -> bool {
    true
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct EncryptionConfig {
    #[serde(default)]
    pub enabled: bool,
    pub key_file: Option<PathBuf>,
}

impl Config {
    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(DepotError::ConfigNotFound(path.to_path_buf()));
        }
        let contents = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&contents)?;
        config.apply_default_upstreams();
        Ok(config)
    }

    /// Load config with default lookup chain:
    /// 1. `DEPOT_CONFIG` env var
    /// 2. `./depot.toml` in current directory
    /// 3. Defaults
    pub fn load() -> Result<Self> {
        if let Ok(path) = std::env::var("DEPOT_CONFIG") {
            let p = PathBuf::from(path);
            if p.exists() {
                return Self::load_from(&p);
            }
            return Err(DepotError::ConfigNotFound(p));
        }

        let local = PathBuf::from("depot.toml");
        if local.exists() {
            return Self::load_from(&local);
        }

        Ok(Self::default())
    }

    pub fn validate_mvp(&self) -> Result<()> {
        if self.encryption.enabled {
            return Err(DepotError::Config(
                "at-rest encryption is not implemented in this MVP".to_string(),
            ));
        }

        if self.auth.enabled && self.auth.tokens.is_empty() {
            return Err(DepotError::Config(
                "auth.enabled requires at least one bearer token".to_string(),
            ));
        }

        Ok(())
    }

    pub fn apply_default_upstreams(&mut self) {
        for (name, config) in default_upstreams() {
            self.upstream.entry(name).or_insert(config);
        }
    }

    pub fn upstream_enabled(&self, name: &str) -> bool {
        self.upstream
            .get(name)
            .map(|config| config.enabled)
            .unwrap_or(true)
    }

    pub fn redacted_value(&self) -> toml::Value {
        let mut value =
            toml::Value::try_from(self).unwrap_or_else(|_| toml::Value::Table(Default::default()));
        if let Some(auth) = value.get_mut("auth").and_then(toml::Value::as_table_mut)
            && let Some(tokens) = auth.get_mut("tokens").and_then(toml::Value::as_array_mut)
        {
            for token in tokens {
                *token = toml::Value::String("<redacted>".to_string());
            }
        }
        value
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            upstream: default_upstreams(),
            policies: PolicyConfig::default(),
            auth: AuthConfig::default(),
            encryption: EncryptionConfig::default(),
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
        },
    );
    upstream.insert(
        "npm".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://registry.npmjs.org".into(),
            artifact_url: None,
        },
    );
    upstream.insert(
        "cargo".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://index.crates.io".into(),
            artifact_url: Some("https://static.crates.io/crates".into()),
        },
    );
    upstream.insert(
        "hex".into(),
        UpstreamConfig {
            enabled: true,
            url: "https://hex.pm".into(),
            artifact_url: Some("https://repo.hex.pm".into()),
        },
    );
    upstream.insert(
        "maven".into(),
        UpstreamConfig {
            enabled: false,
            url: "https://repo1.maven.org/maven2".into(),
            artifact_url: None,
        },
    );
    upstream.insert(
        "rubygems".into(),
        UpstreamConfig {
            enabled: false,
            url: "https://rubygems.org".into(),
            artifact_url: Some("https://rubygems.org".into()),
        },
    );
    upstream.insert(
        "nuget".into(),
        UpstreamConfig {
            enabled: false,
            url: "https://api.nuget.org/v3/index.json".into(),
            artifact_url: None,
        },
    );
    upstream.insert(
        "pub".into(),
        UpstreamConfig {
            enabled: false,
            url: "https://pub.dev".into(),
            artifact_url: None,
        },
    );
    upstream
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixtures() -> Vec<serde_json::Value> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testing_data/config/01_config_parsing.json");
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
                let _ = expected_err; // error type verified by is_err
                continue;
            }

            let config: Config =
                toml::from_str(toml_input).unwrap_or_else(|e| panic!("fixture '{name}': {e}"));

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
        let path = dir.path().join("depot.toml");
        std::fs::write(&path, "[server]\nbind = \"127.0.0.1:9999\"\n").unwrap();

        let config = Config::load_from(&path).unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:9999");
    }

    #[test]
    fn load_from_missing_file() {
        let result = Config::load_from(Path::new("/nonexistent/depot.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn defaults_have_all_upstreams() {
        let config = Config::default();
        assert!(config.upstream.contains_key("pypi"));
        assert!(config.upstream.contains_key("npm"));
        assert!(config.upstream.contains_key("cargo"));
        assert!(config.upstream.contains_key("hex"));
        assert!(config.upstream.contains_key("maven"));
        assert!(config.upstream.contains_key("rubygems"));
        assert!(config.upstream.contains_key("nuget"));
        assert!(config.upstream.contains_key("pub"));
    }

    #[test]
    fn storage_options_are_preserved() {
        let config: Config =
            toml::from_str("[storage]\nbackend = \"gcs\"\n\n[storage.options]\nbucket = \"pkg-cache\"\ncredential_path = \"/tmp/gcs.json\"\n")
                .unwrap();

        let options = config.storage.opendal_options();
        assert_eq!(options.get("bucket"), Some(&"pkg-cache".to_string()));
        assert_eq!(
            options.get("credential_path"),
            Some(&"/tmp/gcs.json".to_string())
        );
    }

    #[test]
    fn legacy_fs_path_maps_to_root_option() {
        let config: Config =
            toml::from_str("[storage]\nbackend = \"fs\"\npath = \"./cache\"\n").unwrap();

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
    fn redacted_value_hides_auth_tokens() {
        let config: Config =
            toml::from_str("[auth]\nenabled = true\ntokens = [\"secret-token\"]\n").unwrap();
        let output = toml::to_string_pretty(&config.redacted_value()).unwrap();
        assert!(!output.contains("secret-token"));
        assert!(output.contains("<redacted>"));
    }
}
