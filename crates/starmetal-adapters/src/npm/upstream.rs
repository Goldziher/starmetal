//! Upstream client for registry.npmjs.org using the npm registry API.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use starmetal_core::config::DEFAULT_MAX_UPSTREAM_BYTES;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use starmetal_core::ports::UpstreamClient;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

/// Time-to-live for cached upstream metadata responses.
const CACHE_TTL: Duration = Duration::from_secs(300);

use super::models;

/// HTTP client for fetching packages from an upstream npm-compatible registry.
///
/// Stores packuments as raw `serde_json::Value` to handle the wide variety of
/// field shapes across npm packages (e.g., `license` as string vs `licenses` as
/// array, extra fields like `_id`, `maintainers`, etc.).
pub struct NpmUpstreamClient {
    client: reqwest::Client,
    base_url: String,
    max_response_bytes: u64,
    /// Cache of normalized package name -> (insertion time, raw packument JSON).
    packument_cache: Arc<RwLock<AHashMap<String, (Instant, serde_json::Value)>>>,
}

impl NpmUpstreamClient {
    /// Create a new upstream client targeting the given base URL.
    pub fn new(base_url: String) -> Self {
        Self::with_max_response_bytes(base_url, DEFAULT_MAX_UPSTREAM_BYTES)
    }

    pub fn with_max_response_bytes(base_url: String, max_response_bytes: u64) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            base_url,
            max_response_bytes,
            packument_cache: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    /// Get a previously cached raw packument JSON, if available.
    pub async fn get_cached_packument(&self, name: &PackageName) -> Option<serde_json::Value> {
        let normalized = name.normalized(Ecosystem::Npm).to_string();
        let cache = self.packument_cache.read().await;
        cache.get(&normalized).and_then(|(inserted, packument)| {
            if inserted.elapsed() < CACHE_TTL {
                Some(packument.clone())
            } else {
                None
            }
        })
    }

    /// Fetch the raw packument JSON, returning a cached response if available.
    async fn fetch_packument_raw(&self, name: &PackageName) -> Result<serde_json::Value> {
        let normalized = name.normalized(Ecosystem::Npm).to_string();

        // Check cache first
        {
            let cache = self.packument_cache.read().await;
            if let Some((inserted, packument)) = cache.get(&normalized)
                && inserted.elapsed() < CACHE_TTL
            {
                debug!(name = %normalized, "packument cache hit");
                return Ok(packument.clone());
            }
        }

        let url = format!("{}/{normalized}", self.base_url);
        debug!(url = %url, "fetching npm packument from upstream");

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|err| StarmetalError::Upstream(err.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(StarmetalError::PackageNotFound {
                ecosystem: "npm".to_string(),
                name: name.as_str().to_string(),
            });
        }
        if !status.is_success() {
            return Err(StarmetalError::Upstream(format!(
                "upstream returned HTTP {status}"
            )));
        }

        // Fetch as raw JSON Value — handles any field shape without strict typing
        let packument: serde_json::Value =
            crate::upstream_http::json_limited(response, self.max_response_bytes, "npm packument")
                .await?;

        self.packument_cache
            .write()
            .await
            .insert(normalized, (Instant::now(), packument.clone()));

        Ok(packument)
    }
}

#[async_trait]
impl UpstreamClient for NpmUpstreamClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    #[instrument(skip(self), fields(ecosystem = "npm"))]
    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let packument = self.fetch_packument_raw(name).await?;
        Ok(models::extract_version_infos(&packument))
    }

    #[instrument(skip(self), fields(ecosystem = "npm"))]
    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
        let packument = self.fetch_packument_raw(name).await?;
        models::extract_version_metadata(name, version, &packument).ok_or_else(|| {
            StarmetalError::VersionNotFound {
                ecosystem: "npm".to_string(),
                name: name.as_str().to_string(),
                version: version.to_string(),
            }
        })
    }

    #[instrument(skip(self), fields(ecosystem = "npm"))]
    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        let packument = self.fetch_packument_raw(&artifact_id.name).await?;

        let tarball_url = packument["versions"][&artifact_id.version]["dist"]["tarball"]
            .as_str()
            .ok_or_else(|| StarmetalError::ArtifactNotFound(artifact_id.filename.clone()))?;

        debug!(url = %tarball_url, "downloading npm tarball from upstream");

        let response = self
            .client
            .get(tarball_url)
            .send()
            .await
            .map_err(|err| StarmetalError::Upstream(err.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(StarmetalError::Upstream(format!(
                "artifact download returned HTTP {status}"
            )));
        }

        crate::upstream_http::bytes_limited(
            response,
            self.max_response_bytes,
            "npm tarball download",
        )
        .await
    }
}
