use async_trait::async_trait;
use bytes::Bytes;
use depot_core::error::{DepotError, Result};
use depot_core::package::{
    ArtifactDigest, ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata,
};
use depot_core::ports::UpstreamClient;

pub struct NuGetUpstreamClient {
    client: reqwest::Client,
    service_index_url: String,
}

impl NuGetUpstreamClient {
    pub fn new(service_index_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            service_index_url,
        }
    }

    fn flat_base(&self) -> String {
        if self.service_index_url.ends_with("/index.json") {
            self.service_index_url
                .trim_end_matches("v3/index.json")
                .trim_end_matches("index.json")
                .trim_end_matches('/')
                .to_string()
                + "/v3-flatcontainer"
        } else {
            self.service_index_url.trim_end_matches('/').to_string()
        }
    }

    async fn fetch_json(&self, url: String) -> Result<serde_json::Value> {
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
            .json()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))
    }

    async fn fetch_optional_text(&self, url: String) -> Result<Option<String>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(DepotError::Upstream(format!(
                "upstream returned HTTP {}",
                response.status()
            )));
        }
        response
            .text()
            .await
            .map(Some)
            .map_err(|err| DepotError::Upstream(err.to_string()))
    }
}

#[async_trait]
impl UpstreamClient for NuGetUpstreamClient {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }

    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let url = format!("{}/{}/index.json", self.flat_base(), name.as_str());
        let json = self.fetch_json(url).await?;
        Ok(json["versions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str())
            .map(|version| VersionInfo {
                version: version.to_string(),
                yanked: false,
            })
            .collect())
    }

    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
        let base = format!("{}/{}/{version}", self.flat_base(), name.as_str());
        let package_filename = format!("{}.{}.nupkg", name.as_str(), version);
        let nuspec_filename = format!("{}.nuspec", name.as_str());
        let mut upstream_hashes = ahash::AHashMap::new();
        if let Some(hash) = self
            .fetch_optional_text(format!("{base}/{package_filename}.sha512"))
            .await?
        {
            upstream_hashes.insert("sha512".to_string(), hash.trim().to_string());
        }
        Ok(VersionMetadata {
            name: name.clone(),
            version: version.to_string(),
            artifacts: vec![
                ArtifactDigest {
                    filename: package_filename,
                    blake3: String::new(),
                    size: 0,
                    upstream_hashes,
                },
                ArtifactDigest {
                    filename: nuspec_filename,
                    blake3: String::new(),
                    size: 0,
                    upstream_hashes: ahash::AHashMap::new(),
                },
            ],
            license: None,
            yanked: false,
        })
    }

    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        let url = format!(
            "{}/{}/{}/{}",
            self.flat_base(),
            artifact_id.name.as_str(),
            artifact_id.version,
            artifact_id.filename
        );
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
        response
            .bytes()
            .await
            .map_err(|err| DepotError::Upstream(err.to_string()))
    }
}

pub fn registration_json(name: &PackageName, versions: Vec<VersionInfo>) -> serde_json::Value {
    let items = versions
        .into_iter()
        .map(|version| {
            serde_json::json!({
                "@id": format!("{}/{}.json", name.as_str(), version.version),
                "catalogEntry": {
                    "@id": format!("{}/{}", name.as_str(), version.version),
                    "id": name.as_str(),
                    "version": version.version
                },
                "packageContent": format!("../v3-flatcontainer/{}/{}/{}.{}.nupkg", name.as_str(), version.version, name.as_str(), version.version)
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "@id": format!("{}/index.json", name.as_str()),
        "count": 1,
        "items": [{
            "@id": format!("{}/page.json", name.as_str()),
            "count": items.len(),
            "items": items
        }]
    })
}
