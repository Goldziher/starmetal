//! Upstream client for hex.pm using the Hex HTTP API.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use depot_core::config::DEFAULT_MAX_UPSTREAM_BYTES;
use depot_core::error::{DepotError, Result};
use depot_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use depot_core::ports::UpstreamClient;
use depot_core::registry::hex::HexPackage;
use flate2::read::GzDecoder;
use prost::Message;
use std::io::Read;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

/// Time-to-live for cached upstream metadata responses.
const CACHE_TTL: Duration = Duration::from_secs(300);

use super::{models, proto};

/// HTTP client for fetching packages from an upstream Hex-compatible registry.
pub struct HexUpstreamClient {
    client: reqwest::Client,
    base_url: String,
    repo_url: String,
    max_response_bytes: u64,
    /// Cache of normalized package name -> package response, so multiple calls
    /// for the same package (e.g. fetch_versions then N x fetch_metadata) only
    /// hit upstream once.
    package_cache: Arc<RwLock<AHashMap<String, (Instant, HexPackage)>>>,
    /// Cache of package name -> (insertion time, protobuf registry entry bytes).
    registry_cache: Arc<RwLock<AHashMap<String, (Instant, Bytes)>>>,
}

impl HexUpstreamClient {
    /// Create a new upstream client targeting the given base URL.
    ///
    /// The base URL should be the root of a Hex-compatible registry
    /// (e.g., `https://hex.pm`).
    /// Create a new upstream client.
    ///
    /// `base_url` is the API domain (e.g., `https://hex.pm`).
    /// `repo_url` is the repository domain for tarball downloads (e.g., `https://repo.hex.pm`).
    pub fn new(base_url: String, repo_url: String) -> Self {
        Self::with_max_response_bytes(base_url, repo_url, DEFAULT_MAX_UPSTREAM_BYTES)
    }

    pub fn with_max_response_bytes(
        base_url: String,
        repo_url: String,
        max_response_bytes: u64,
    ) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("depot/0.1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            base_url,
            repo_url,
            max_response_bytes,
            package_cache: Arc::new(RwLock::new(AHashMap::new())),
            registry_cache: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    /// Fetch the Hex package metadata, returning a cached response if available.
    async fn fetch_package(&self, name: &PackageName) -> Result<HexPackage> {
        let normalized = name.normalized(Ecosystem::Hex).to_string();

        // Check cache first
        {
            let cache = self.package_cache.read().await;
            if let Some((inserted, pkg)) = cache.get(&normalized)
                && inserted.elapsed() < CACHE_TTL
            {
                debug!(name = %normalized, "hex package cache hit");
                return Ok(pkg.clone());
            }
        }

        let url = format!("{}/api/packages/{normalized}", self.base_url);
        debug!(url = %url, "fetching Hex package metadata from upstream");

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(DepotError::PackageNotFound {
                ecosystem: "hex".to_string(),
                name: name.as_str().to_string(),
            });
        }
        if !status.is_success() {
            return Err(DepotError::Upstream(format!(
                "upstream returned HTTP {status}"
            )));
        }

        let pkg: HexPackage =
            crate::upstream_http::json_limited(response, self.max_response_bytes, "Hex package")
                .await?;

        // Populate cache
        self.package_cache
            .write()
            .await
            .insert(normalized, (Instant::now(), pkg.clone()));

        Ok(pkg)
    }

    /// Return the cached upstream package if present and not expired.
    pub async fn get_cached_package(&self, name: &PackageName) -> Option<HexPackage> {
        let normalized = name.normalized(Ecosystem::Hex).to_string();
        let cache = self.package_cache.read().await;
        cache.get(&normalized).and_then(|(inserted, pkg)| {
            if inserted.elapsed() < CACHE_TTL {
                Some(pkg.clone())
            } else {
                None
            }
        })
    }

    /// Fetch the protobuf registry entry for a package from the repository.
    ///
    /// Mix uses `GET /packages/{name}` to get checksums for tarball verification.
    /// We proxy and cache the raw bytes without parsing protobuf.
    pub async fn fetch_registry_entry(&self, name: &str) -> Result<Bytes> {
        let normalized = name.to_ascii_lowercase();

        // Check cache
        {
            let cache = self.registry_cache.read().await;
            if let Some((inserted, bytes)) = cache.get(&normalized)
                && inserted.elapsed() < CACHE_TTL
            {
                debug!(name = %normalized, "hex registry cache hit");
                return Ok(bytes.clone());
            }
        }

        let url = format!("{}/packages/{normalized}", self.repo_url);
        debug!(url = %url, "fetching hex registry entry from upstream");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(DepotError::PackageNotFound {
                ecosystem: "hex".to_string(),
                name: name.to_string(),
            });
        }
        if !status.is_success() {
            return Err(DepotError::Upstream(format!(
                "upstream returned HTTP {status}"
            )));
        }

        let bytes = crate::upstream_http::bytes_limited(
            response,
            self.max_response_bytes,
            "Hex registry protobuf",
        )
        .await?;

        self.registry_cache
            .write()
            .await
            .insert(normalized, (Instant::now(), bytes.clone()));

        Ok(bytes)
    }
}

#[async_trait]
impl UpstreamClient for HexUpstreamClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Hex
    }

    #[instrument(skip(self), fields(ecosystem = "hex"))]
    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let pkg = self.fetch_package(name).await?;
        Ok(models::hex_package_to_version_infos(&pkg))
    }

    #[instrument(skip(self), fields(ecosystem = "hex"))]
    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
        let pkg = self.fetch_package(name).await?;
        let mut metadata =
            models::hex_release_to_metadata(name, &pkg, version).ok_or_else(|| {
                DepotError::VersionNotFound {
                    ecosystem: "hex".to_string(),
                    name: name.as_str().to_string(),
                    version: version.to_string(),
                }
            })?;

        if let Some(checksum) = self.outer_checksum(name.as_str(), version).await?
            && let Some(artifact) = metadata.artifacts.first_mut()
        {
            artifact
                .upstream_hashes
                .insert("sha256".to_string(), checksum);
        }
        Ok(metadata)
    }

    #[instrument(skip(self), fields(ecosystem = "hex"))]
    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        let name = artifact_id.name.as_str();
        let version = &artifact_id.version;
        let url = format!("{}/tarballs/{name}-{version}.tar", self.repo_url);

        debug!(url = %url, "downloading hex tarball from upstream");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(DepotError::Upstream(format!(
                "artifact download returned HTTP {status}"
            )));
        }

        crate::upstream_http::bytes_limited(
            response,
            self.max_response_bytes,
            "Hex tarball download",
        )
        .await
    }
}

impl HexUpstreamClient {
    async fn outer_checksum(&self, name: &str, version: &str) -> Result<Option<String>> {
        let bytes = self.fetch_registry_entry(name).await?;
        let registry_bytes = decode_registry_entry(bytes.as_ref())?;
        let signed = proto::Signed::decode(registry_bytes.as_slice()).map_err(|err| {
            DepotError::Upstream(format!("invalid signed Hex package protobuf: {err}"))
        })?;
        let package = proto::Package::decode(signed.payload.as_slice())
            .map_err(|err| DepotError::Upstream(format!("invalid Hex package protobuf: {err}")))?;
        Ok(package
            .releases
            .into_iter()
            .find(|release| release.version == version)
            .and_then(|release| release.outer_checksum.or(Some(release.inner_checksum)))
            .map(hex_encode))
    }
}

fn decode_registry_entry(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(bytes);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).map_err(|err| {
            DepotError::Upstream(format!("invalid gzipped Hex package protobuf: {err}"))
        })?;
        Ok(decoded)
    } else {
        Ok(bytes.to_vec())
    }
}

fn hex_encode(bytes: Vec<u8>) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
