//! Upstream client for pypi.org using the PEP 691 Simple Repository API.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use depot_core::config::DEFAULT_MAX_UPSTREAM_BYTES;
use depot_core::error::{DepotError, Result};
use depot_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use depot_core::ports::UpstreamClient;
use depot_core::registry::pypi::{PypiFile, PypiMeta, PypiProject, PypiYanked};
use tokio::sync::RwLock;
use tracing::{debug, instrument};

/// Time-to-live for cached upstream metadata responses.
const CACHE_TTL: Duration = Duration::from_secs(300);

use super::models;

/// HTTP client for fetching packages from an upstream PyPI-compatible registry.
pub struct PypiUpstreamClient {
    client: reqwest::Client,
    base_url: String,
    max_response_bytes: u64,
    /// Cache of filename -> absolute download URL, populated during fetch_versions
    /// and fetch_metadata calls so that fetch_artifact can resolve download URLs.
    url_cache: Arc<RwLock<AHashMap<String, (Instant, String)>>>,
    /// Cache of normalized package name -> project response, so multiple calls
    /// for the same package (e.g. fetch_versions then N x fetch_metadata) only
    /// hit upstream once.
    project_cache: Arc<RwLock<AHashMap<String, (Instant, PypiProject)>>>,
}

impl PypiUpstreamClient {
    /// Create a new upstream client targeting the given base URL.
    ///
    /// The base URL should be the root of a PEP 503/691 simple repository
    /// (e.g., `https://pypi.org`).
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
            url_cache: Arc::new(RwLock::new(AHashMap::new())),
            project_cache: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    /// Return the cached upstream project if present and not expired.
    pub async fn get_cached_project(&self, name: &PackageName) -> Option<PypiProject> {
        let normalized = name.normalized(Ecosystem::PyPI).to_string();
        let cache = self.project_cache.read().await;
        cache.get(&normalized).and_then(|(inserted, project)| {
            if inserted.elapsed() < CACHE_TTL {
                Some(project.clone())
            } else {
                None
            }
        })
    }

    /// Fetch the PyPI project metadata, returning a cached response if available.
    async fn fetch_project(&self, name: &PackageName) -> Result<PypiProject> {
        let normalized = name.normalized(Ecosystem::PyPI).to_string();

        // Check project cache first
        {
            let cache = self.project_cache.read().await;
            if let Some((inserted, project)) = cache.get(&normalized)
                && inserted.elapsed() < CACHE_TTL
            {
                debug!(name = %normalized, "project cache hit");
                return Ok(project.clone());
            }
        }

        let url = format!("{}/simple/{normalized}/", self.base_url);
        debug!(url = %url, "fetching PyPI project metadata from upstream");

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/vnd.pypi.simple.v1+json")
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(DepotError::PackageNotFound {
                ecosystem: "pypi".to_string(),
                name: name.as_str().to_string(),
            });
        }
        if !status.is_success() {
            return Err(DepotError::Upstream(format!(
                "upstream returned HTTP {status}"
            )));
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let project: PypiProject = if content_type.contains("application/vnd.pypi.simple.v1+json")
            || content_type.contains("application/json")
        {
            crate::upstream_http::json_limited(
                response,
                self.max_response_bytes,
                "PyPI project metadata",
            )
            .await?
        } else {
            let html = crate::upstream_http::text_limited(
                response,
                self.max_response_bytes,
                "PyPI project metadata",
            )
            .await?;
            parse_pep503_html(&normalized, &url, &html)
        };

        // Populate caches
        self.cache_file_urls(&project).await;
        self.project_cache
            .write()
            .await
            .insert(normalized, (Instant::now(), project.clone()));

        Ok(project)
    }

    /// Store the mapping from filename -> upstream download URL for every file
    /// in the project response.
    async fn cache_file_urls(&self, project: &PypiProject) {
        let now = Instant::now();
        let mut cache = self.url_cache.write().await;
        for file in &project.files {
            cache.insert(file.filename.clone(), (now, file.url.clone()));
        }
    }
}

fn parse_pep503_html(name: &str, base_url: &str, html: &str) -> PypiProject {
    let mut files = Vec::new();
    let mut rest = html;
    while let Some(anchor_start) = rest.find("<a ") {
        rest = &rest[anchor_start + 3..];
        let Some(anchor_end) = rest.find('>') else {
            break;
        };
        let attrs = &rest[..anchor_end];
        rest = &rest[anchor_end + 1..];
        let Some(text_end) = rest.find("</a>") else {
            break;
        };
        let filename = html_unescape(rest[..text_end].trim());
        rest = &rest[text_end + 4..];
        let Some(href) = attr(attrs, "href") else {
            continue;
        };
        let (url, hashes) = split_hash_fragment(&absolute_url(base_url, &href));
        files.push(PypiFile {
            filename,
            url,
            hashes,
            requires_python: attr(attrs, "data-requires-python").map(|value| html_unescape(&value)),
            yanked: attr(attrs, "data-yanked")
                .map(|value| {
                    if value.is_empty() {
                        PypiYanked::Bool(true)
                    } else {
                        PypiYanked::Reason(html_unescape(&value))
                    }
                })
                .unwrap_or_default(),
            size: None,
            upload_time: None,
            dist_info_metadata: None,
            gpg_sig: None,
        });
    }
    PypiProject {
        meta: PypiMeta {
            api_version: "1.0".to_string(),
        },
        name: name.to_string(),
        versions: Vec::new(),
        files,
    }
}

fn attr(attrs: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = attrs.find(&needle)? + needle.len();
    let value = &attrs[start..];
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

fn absolute_url(base_url: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        href.to_string()
    } else if href.starts_with('/') {
        let Some((scheme_host, _)) = base_url.split_once("/simple/") else {
            return href.to_string();
        };
        format!("{scheme_host}{href}")
    } else {
        format!("{base_url}{href}")
    }
}

fn split_hash_fragment(url: &str) -> (String, std::collections::HashMap<String, String>) {
    let Some((url, fragment)) = url.split_once('#') else {
        return (url.to_string(), Default::default());
    };
    let mut hashes = std::collections::HashMap::new();
    if let Some((algorithm, value)) = fragment.split_once('=') {
        hashes.insert(algorithm.to_string(), value.to_string());
    }
    (url.to_string(), hashes)
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
}

#[async_trait]
impl UpstreamClient for PypiUpstreamClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }

    #[instrument(skip(self), fields(ecosystem = "pypi"))]
    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let project = self.fetch_project(name).await?;
        Ok(models::pypi_project_to_version_infos(&project))
    }

    #[instrument(skip(self), fields(ecosystem = "pypi"))]
    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
        let project = self.fetch_project(name).await?;
        models::pypi_files_to_metadata(name, version, &project.files).ok_or_else(|| {
            DepotError::VersionNotFound {
                ecosystem: "pypi".to_string(),
                name: name.as_str().to_string(),
                version: version.to_string(),
            }
        })
    }

    #[instrument(skip(self), fields(ecosystem = "pypi"))]
    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        // Look up the upstream URL from cache
        let url = {
            let cache = self.url_cache.read().await;
            cache
                .get(&artifact_id.filename)
                .and_then(|(inserted, url)| {
                    if inserted.elapsed() < CACHE_TTL {
                        Some(url.clone())
                    } else {
                        None
                    }
                })
        };

        let url = match url {
            Some(u) => u,
            None => {
                // Cache miss: fetch project metadata to populate cache, then retry
                debug!(
                    filename = %artifact_id.filename,
                    "url cache miss, fetching project to populate"
                );
                self.fetch_project(&artifact_id.name).await?;
                let cache = self.url_cache.read().await;
                cache
                    .get(&artifact_id.filename)
                    .map(|(_inserted, url)| url.clone())
                    .ok_or_else(|| DepotError::ArtifactNotFound(artifact_id.filename.clone()))?
            }
        };

        debug!(url = %url, "downloading artifact from upstream");

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
            "PyPI artifact download",
        )
        .await
    }
}
