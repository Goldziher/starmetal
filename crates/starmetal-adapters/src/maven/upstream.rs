use async_trait::async_trait;
use bytes::Bytes;
use starmetal_core::config::DEFAULT_MAX_UPSTREAM_BYTES;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::{
    ArtifactDigest, ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata,
};
use starmetal_core::ports::UpstreamClient;

pub struct MavenUpstreamClient {
    client: reqwest::Client,
    base_url: String,
    max_response_bytes: u64,
}

impl MavenUpstreamClient {
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

    pub async fn fetch_path(&self, path: &str) -> Result<Bytes> {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|err| StarmetalError::Upstream(err.to_string()))?;
        if !response.status().is_success() {
            return Err(StarmetalError::Upstream(format!(
                "upstream returned HTTP {}",
                response.status()
            )));
        }
        crate::upstream_http::bytes_limited(response, self.max_response_bytes, "Maven artifact")
            .await
    }

    async fn fetch_optional_text(&self, path: &str) -> Result<Option<String>> {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|err| StarmetalError::Upstream(err.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(StarmetalError::Upstream(format!(
                "upstream returned HTTP {}",
                response.status()
            )));
        }
        crate::upstream_http::text_limited(response, self.max_response_bytes, "Maven metadata")
            .await
            .map(Some)
    }
}

#[async_trait]
impl UpstreamClient for MavenUpstreamClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let metadata_path = format!("{}/maven-metadata.xml", maven_path(name)?);
        let metadata = self.fetch_path(&metadata_path).await?;
        let text = String::from_utf8_lossy(&metadata);
        Ok(extract_versions(&text)
            .into_iter()
            .map(|version| VersionInfo {
                version,
                yanked: false,
            })
            .collect())
    }

    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
        let (_, artifact) =
            name.as_str()
                .rsplit_once(':')
                .ok_or_else(|| StarmetalError::PackageNotFound {
                    ecosystem: "maven".to_string(),
                    name: name.as_str().to_string(),
                })?;
        let mut artifacts = Vec::new();
        for filename in [
            format!("{artifact}-{version}.pom"),
            format!("{artifact}-{version}.jar"),
        ] {
            let path = format!("{}/{version}/{filename}", maven_path(name)?);
            let mut upstream_hashes = ahash::AHashMap::new();
            if let Some(sha256) = self.fetch_optional_text(&format!("{path}.sha256")).await? {
                upstream_hashes.insert("sha256".to_string(), checksum_token(&sha256).to_string());
            } else if let Some(sha1) = self.fetch_optional_text(&format!("{path}.sha1")).await? {
                upstream_hashes.insert("sha1".to_string(), checksum_token(&sha1).to_string());
            }
            artifacts.push(ArtifactDigest {
                filename,
                blake3: String::new(),
                size: 0,
                upstream_hashes,
            });
        }
        Ok(VersionMetadata {
            name: name.clone(),
            version: version.to_string(),
            artifacts,
            license: None,
            yanked: false,
        })
    }

    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        let path = format!(
            "{}/{}/{}",
            maven_path(&artifact_id.name)?,
            artifact_id.version,
            artifact_id.filename
        );
        self.fetch_path(&path).await
    }
}

fn maven_path(name: &PackageName) -> Result<String> {
    let (group, artifact) =
        name.as_str()
            .rsplit_once(':')
            .ok_or_else(|| StarmetalError::PackageNotFound {
                ecosystem: "maven".to_string(),
                name: name.as_str().to_string(),
            })?;
    Ok(format!("{}/{}", group.replace('.', "/"), artifact))
}

fn extract_versions(metadata: &str) -> Vec<String> {
    let mut versions = Vec::new();
    let mut rest = metadata;
    while let Some(start) = rest.find("<version>") {
        rest = &rest[start + "<version>".len()..];
        let Some(end) = rest.find("</version>") else {
            break;
        };
        versions.push(rest[..end].to_string());
        rest = &rest[end + "</version>".len()..];
    }
    versions
}

fn checksum_token(sidecar_body: &str) -> &str {
    sidecar_body.split_whitespace().next().unwrap_or("").trim()
}
