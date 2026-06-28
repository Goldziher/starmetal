use async_trait::async_trait;
use bytes::Bytes;
use depot_core::config::DEFAULT_MAX_UPSTREAM_BYTES;
use depot_core::error::{DepotError, Result};
use depot_core::package::{
    ArtifactDigest, ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata,
};
use depot_core::ports::UpstreamClient;

pub struct PubUpstreamClient {
    client: reqwest::Client,
    base_url: String,
    max_response_bytes: u64,
}

impl PubUpstreamClient {
    pub fn new(base_url: String) -> Self {
        Self::with_max_response_bytes(base_url, DEFAULT_MAX_UPSTREAM_BYTES)
    }

    pub fn with_max_response_bytes(base_url: String, max_response_bytes: u64) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            max_response_bytes,
        }
    }

    pub async fn fetch_package_json(&self, name: &PackageName) -> Result<serde_json::Value> {
        let response = self
            .client
            .get(format!("{}/api/packages/{}", self.base_url, name.as_str()))
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;
        if !response.status().is_success() {
            return Err(DepotError::Upstream(format!(
                "upstream returned HTTP {}",
                response.status()
            )));
        }
        crate::upstream_http::json_limited(response, self.max_response_bytes, "Pub package").await
    }
}

#[async_trait]
impl UpstreamClient for PubUpstreamClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pub
    }

    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let package = self.fetch_package_json(name).await?;
        Ok(package["versions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|version| version["version"].as_str())
            .map(|version| VersionInfo {
                version: version.to_string(),
                yanked: false,
            })
            .collect())
    }

    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
        let package = self.fetch_package_json(name).await?;
        let version_json = package["versions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|value| value["version"].as_str() == Some(version))
            .ok_or_else(|| DepotError::VersionNotFound {
                ecosystem: "pub".to_string(),
                name: name.as_str().to_string(),
                version: version.to_string(),
            })?;
        Ok(metadata_from_version(name, version, version_json))
    }

    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        let package = self.fetch_package_json(&artifact_id.name).await?;
        let url = package["versions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|value| value["version"].as_str() == Some(artifact_id.version.as_str()))
            .and_then(|value| value["archive_url"].as_str())
            .ok_or_else(|| DepotError::ArtifactNotFound(artifact_id.filename.clone()))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;
        if !response.status().is_success() {
            return Err(DepotError::Upstream(format!(
                "artifact download returned HTTP {}",
                response.status()
            )));
        }
        crate::upstream_http::bytes_limited(
            response,
            self.max_response_bytes,
            "Pub archive download",
        )
        .await
    }
}

pub fn metadata_from_version(
    name: &PackageName,
    version: &str,
    version_json: &serde_json::Value,
) -> VersionMetadata {
    let mut upstream_hashes = ahash::AHashMap::new();
    if let Some(hash) = version_json["archive_sha256"].as_str() {
        upstream_hashes.insert("sha256".to_string(), hash.to_string());
    }
    VersionMetadata {
        name: name.clone(),
        version: version.to_string(),
        artifacts: vec![ArtifactDigest {
            filename: format!("{}-{version}.tar.gz", name.as_str()),
            blake3: String::new(),
            size: 0,
            upstream_hashes,
        }],
        license: None,
        yanked: false,
    }
}
