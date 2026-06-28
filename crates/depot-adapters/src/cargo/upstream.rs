//! Upstream client for index.crates.io and static.crates.io.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use depot_core::config::DEFAULT_MAX_UPSTREAM_BYTES;
use depot_core::error::{DepotError, Result};
use depot_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use depot_core::ports::UpstreamClient;
use depot_core::registry::cargo::{CargoIndexEntry, sparse_index_path};
use tokio::sync::RwLock;
use tracing::{debug, instrument};

/// Time-to-live for cached upstream metadata responses.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Cache type for Cargo index entries, keyed by normalized crate name.
type CargoEntriesCache = AHashMap<String, (Instant, Vec<CargoIndexEntry>)>;

use super::models;

/// HTTP client for fetching crate metadata from the Cargo sparse index
/// and downloading crate archives from the static CDN.
pub struct CargoUpstreamClient {
    client: reqwest::Client,
    index_url: String,
    dl_url: String,
    max_response_bytes: u64,
    entries_cache: Arc<RwLock<CargoEntriesCache>>,
}

impl CargoUpstreamClient {
    /// Create a new upstream client targeting the given index and download URLs.
    ///
    /// Typical values:
    /// - `index_url`: `https://index.crates.io`
    /// - `dl_url`: `https://static.crates.io/crates`
    pub fn new(index_url: String, dl_url: String) -> Self {
        Self::with_max_response_bytes(index_url, dl_url, DEFAULT_MAX_UPSTREAM_BYTES)
    }

    pub fn with_max_response_bytes(
        index_url: String,
        dl_url: String,
        max_response_bytes: u64,
    ) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            index_url,
            dl_url,
            max_response_bytes,
            entries_cache: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    /// Fetch index entries for a crate, using the cache when available.
    async fn fetch_index(&self, name: &PackageName) -> Result<Vec<CargoIndexEntry>> {
        let normalized = name.normalized(Ecosystem::Cargo).to_string();

        // Check cache first
        {
            let cache = self.entries_cache.read().await;
            if let Some((inserted, entries)) = cache.get(&normalized)
                && inserted.elapsed() < CACHE_TTL
            {
                debug!(name = %normalized, "cargo index cache hit");
                return Ok(entries.clone());
            }
        }

        let path = sparse_index_path(&normalized);
        let url = format!("{}/{path}", self.index_url);
        debug!(url = %url, "fetching Cargo index from upstream");

        let response = self
            .client
            .get(&url)
            .header("Accept", "text/plain")
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(DepotError::PackageNotFound {
                ecosystem: "cargo".to_string(),
                name: name.as_str().to_string(),
            });
        }
        if !status.is_success() {
            return Err(DepotError::Upstream(format!(
                "upstream returned HTTP {status}"
            )));
        }

        let body = crate::upstream_http::text_limited(
            response,
            self.max_response_bytes,
            "Cargo sparse index",
        )
        .await?;

        let entries: Vec<CargoIndexEntry> = body
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_str(line).map_err(|err| {
                    DepotError::Upstream(format!("failed to parse index line: {err}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Cache the entries
        self.entries_cache
            .write()
            .await
            .insert(normalized, (Instant::now(), entries.clone()));

        Ok(entries)
    }

    /// Get cached entries for a crate name, if previously fetched and not expired.
    ///
    /// This allows handlers to access the raw index data (including deps and
    /// features) after the caching lifecycle has been triggered via PackageService.
    pub async fn get_cached_entries(&self, name: &PackageName) -> Option<Vec<CargoIndexEntry>> {
        let normalized = name.normalized(Ecosystem::Cargo).to_string();
        let cache = self.entries_cache.read().await;
        cache.get(&normalized).and_then(|(inserted, entries)| {
            if inserted.elapsed() < CACHE_TTL {
                Some(entries.clone())
            } else {
                None
            }
        })
    }
}

#[async_trait]
impl UpstreamClient for CargoUpstreamClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    #[instrument(skip(self), fields(ecosystem = "cargo"))]
    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let entries = self.fetch_index(name).await?;
        Ok(models::cargo_entries_to_version_infos(&entries))
    }

    #[instrument(skip(self), fields(ecosystem = "cargo"))]
    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
        let entries = self.fetch_index(name).await?;
        entries
            .iter()
            .find(|e| e.vers == version)
            .map(|entry| models::cargo_entry_to_metadata(name, entry))
            .ok_or_else(|| DepotError::VersionNotFound {
                ecosystem: "cargo".to_string(),
                name: name.as_str().to_string(),
                version: version.to_string(),
            })
    }

    #[instrument(skip(self), fields(ecosystem = "cargo"))]
    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        let name = artifact_id.name.as_str();
        let version = &artifact_id.version;
        let url = format!("{}/{name}/{name}-{version}.crate", self.dl_url);

        debug!(url = %url, "downloading crate from upstream");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(DepotError::Upstream(format!(
                "crate download returned HTTP {status}"
            )));
        }

        crate::upstream_http::bytes_limited(
            response,
            self.max_response_bytes,
            "Cargo crate download",
        )
        .await
    }
}
