use async_trait::async_trait;
use bytes::Bytes;
use depot_core::error::{DepotError, Result};
use depot_core::package::{
    ArtifactDigest, ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata,
};
use depot_core::ports::UpstreamClient;

pub struct RubyGemsUpstreamClient {
    client: reqwest::Client,
    base_url: String,
}

impl RubyGemsUpstreamClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub async fn fetch_path(&self, path: &str) -> Result<Bytes> {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;
        if !response.status().is_success() {
            return Err(DepotError::Upstream(format!(
                "upstream returned HTTP {}",
                response.status()
            )));
        }
        response
            .bytes()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))
    }
}

#[async_trait]
impl UpstreamClient for RubyGemsUpstreamClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::RubyGems
    }

    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let info = self.fetch_path(&format!("info/{}", name.as_str())).await?;
        let text = String::from_utf8_lossy(&info);
        Ok(text
            .lines()
            .filter(|line| !line.is_empty() && *line != "---")
            .map(|line| VersionInfo {
                version: line
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                yanked: false,
            })
            .filter(|info| !info.version.is_empty())
            .collect())
    }

    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
        let info = self.fetch_path(&format!("info/{}", name.as_str())).await?;
        let text = String::from_utf8_lossy(&info);
        let mut upstream_hashes = ahash::AHashMap::new();
        for line in text.lines() {
            if !line.starts_with(version) {
                continue;
            }
            if let Some((_, checksum)) = line.split_once("checksum:sha256=") {
                let checksum = checksum.split_whitespace().next().unwrap_or(checksum);
                upstream_hashes.insert("sha256".to_string(), checksum.to_string());
            }
        }
        Ok(VersionMetadata {
            name: name.clone(),
            version: version.to_string(),
            artifacts: vec![ArtifactDigest {
                filename: format!("{}-{version}.gem", name.as_str()),
                blake3: String::new(),
                size: 0,
                upstream_hashes,
            }],
            license: None,
            yanked: false,
        })
    }

    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        self.fetch_path(&format!("gems/{}", artifact_id.filename))
            .await
    }
}
