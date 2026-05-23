use std::sync::Arc;

use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use depot_core::error::{DepotError, Result};
use depot_core::integrity;
use depot_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use depot_core::policy::PolicyConfig;
use depot_core::ports::{PackageService, StoragePort, UpstreamClient};

/// Pull-through caching implementation of `PackageService`.
///
/// Sits between protocol adapters (inbound) and storage/upstream (outbound),
/// applying policy checks and integrity verification on cache misses.
pub struct CachingPackageService {
    storage: Arc<dyn StoragePort>,
    upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
    policy: PolicyConfig,
}

impl CachingPackageService {
    pub fn new(
        storage: Arc<dyn StoragePort>,
        upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
        policy: PolicyConfig,
    ) -> Self {
        Self {
            storage,
            upstream_clients,
            policy,
        }
    }

    fn upstream(&self, ecosystem: Ecosystem) -> Result<&Arc<dyn UpstreamClient>> {
        self.upstream_clients
            .get(&ecosystem)
            .ok_or_else(|| DepotError::Config(format!("no upstream configured for {ecosystem}")))
    }

    fn check_artifact_policy(&self, artifact_id: &ArtifactId) -> Result<()> {
        if self
            .policy
            .blocked_packages
            .iter()
            .any(|b| b == artifact_id.name.as_str())
        {
            return Err(DepotError::PolicyViolation(format!(
                "package {} is blocked",
                artifact_id.name
            )));
        }
        Ok(())
    }

    fn versions_key(ecosystem: Ecosystem, name: &PackageName) -> String {
        format!("{ecosystem}/{name}/_versions.json")
    }

    fn metadata_key(ecosystem: Ecosystem, name: &PackageName, version: &str) -> String {
        format!("{ecosystem}/{name}/{version}/_metadata.json")
    }

    fn raw_upstream_key(ecosystem: Ecosystem, name: &PackageName) -> String {
        format!("{ecosystem}/{name}/_raw_upstream")
    }
}

#[async_trait]
impl PackageService for CachingPackageService {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Vec<VersionInfo>> {
        let key = Self::versions_key(ecosystem, name);

        if let Some(cached) = self.storage.get(&key).await? {
            tracing::debug!(ecosystem = %ecosystem, name = %name, "cache hit for versions");
            let versions: Vec<VersionInfo> = serde_json::from_slice(&cached)?;
            return Ok(versions);
        }

        tracing::info!(ecosystem = %ecosystem, name = %name, "fetching versions from upstream");
        let upstream = self.upstream(ecosystem)?;
        let versions = upstream.fetch_versions(name).await?;

        let serialized = serde_json::to_vec(&versions)?;
        self.storage.put(&key, Bytes::from(serialized)).await?;

        Ok(versions)
    }

    async fn get_version_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<VersionMetadata> {
        let key = Self::metadata_key(ecosystem, name, version);

        if let Some(cached) = self.storage.get(&key).await? {
            tracing::debug!(ecosystem = %ecosystem, name = %name, version, "cache hit for metadata");
            let metadata: VersionMetadata = serde_json::from_slice(&cached)?;
            return Ok(metadata);
        }

        tracing::info!(ecosystem = %ecosystem, name = %name, version, "fetching metadata from upstream");
        let upstream = self.upstream(ecosystem)?;
        let metadata = upstream.fetch_metadata(name, version).await?;

        self.policy.check(&metadata)?;

        let serialized = serde_json::to_vec(&metadata)?;
        self.storage.put(&key, Bytes::from(serialized)).await?;

        Ok(metadata)
    }

    async fn get_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        self.check_artifact_policy(artifact_id)?;

        let key = artifact_id.storage_key();
        let hash_key = format!("{key}.blake3");

        if let Some(cached) = self.storage.get(&key).await? {
            if let Some(expected_hash) = self.storage.get(&hash_key).await? {
                let expected = std::str::from_utf8(&expected_hash)
                    .map_err(|e| DepotError::Storage(e.to_string()))?;
                integrity::verify_or_err(&cached, expected)?;
            } else {
                tracing::warn!(
                    key,
                    "serving artifact without integrity verification (no hash sidecar)"
                );
            }
            return Ok(cached);
        }

        tracing::info!(key, "fetching artifact from upstream");
        let upstream = self.upstream(artifact_id.ecosystem)?;
        let data = upstream.fetch_artifact(artifact_id).await?;

        let hash = integrity::blake3_hex(&data);
        self.storage.put(&hash_key, Bytes::from(hash)).await?;
        self.storage.put(&key, data.clone()).await?;

        Ok(data)
    }

    async fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<PackageName>> {
        let prefix = format!("{ecosystem}/");
        let keys = self.storage.list_prefix(&prefix).await?;

        let mut seen = ahash::AHashSet::new();
        let mut packages = Vec::new();

        for key in &keys {
            // Keys are "<ecosystem>/<name>/..." — extract second component
            let rest = key.strip_prefix(&prefix).unwrap_or(key);
            if let Some(name) = rest.split('/').next()
                && !name.is_empty()
                && seen.insert(name.to_string())
            {
                packages.push(PackageName::new(name));
            }
        }

        Ok(packages)
    }

    async fn get_raw_upstream(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Option<Bytes>> {
        let key = Self::raw_upstream_key(ecosystem, name);
        self.storage.get(&key).await
    }

    async fn put_raw_upstream(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        data: Bytes,
    ) -> Result<()> {
        let key = Self::raw_upstream_key(ecosystem, name);
        self.storage.put(&key, data).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use depot_core::package::ArtifactDigest;

    struct MockStorage {
        data: Mutex<AHashMap<String, Bytes>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(AHashMap::new()),
            }
        }

        fn with_data(entries: Vec<(&str, Bytes)>) -> Self {
            let mut map = AHashMap::new();
            for (k, v) in entries {
                map.insert(k.to_string(), v);
            }
            Self {
                data: Mutex::new(map),
            }
        }
    }

    #[async_trait]
    impl StoragePort for MockStorage {
        async fn get(&self, key: &str) -> Result<Option<Bytes>> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }

        async fn put(&self, key: &str, data: Bytes) -> Result<()> {
            self.data.lock().unwrap().insert(key.to_string(), data);
            Ok(())
        }

        async fn exists(&self, key: &str) -> Result<bool> {
            Ok(self.data.lock().unwrap().contains_key(key))
        }

        async fn delete(&self, key: &str) -> Result<()> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }

        async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
            Ok(self
                .data
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    struct MockUpstream {
        eco: Ecosystem,
        versions: Vec<VersionInfo>,
        metadata: AHashMap<String, VersionMetadata>,
        artifacts: AHashMap<String, Bytes>,
    }

    #[async_trait]
    impl UpstreamClient for MockUpstream {
        fn ecosystem(&self) -> Ecosystem {
            self.eco
        }

        async fn fetch_versions(&self, _name: &PackageName) -> Result<Vec<VersionInfo>> {
            Ok(self.versions.clone())
        }

        async fn fetch_metadata(
            &self,
            _name: &PackageName,
            version: &str,
        ) -> Result<VersionMetadata> {
            self.metadata
                .get(version)
                .cloned()
                .ok_or_else(|| DepotError::VersionNotFound {
                    ecosystem: self.eco.to_string(),
                    name: "test".to_string(),
                    version: version.to_string(),
                })
        }

        async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
            self.artifacts
                .get(&artifact_id.filename)
                .cloned()
                .ok_or_else(|| DepotError::ArtifactNotFound(artifact_id.storage_key()))
        }
    }

    fn test_metadata(name: &str, version: &str) -> VersionMetadata {
        VersionMetadata {
            name: PackageName::new(name),
            version: version.to_string(),
            artifacts: vec![ArtifactDigest {
                filename: format!("{name}-{version}.tar.gz"),
                blake3: "0".repeat(64),
                size: 1024,
                upstream_hashes: AHashMap::new(),
            }],
            license: Some("MIT".to_string()),
            yanked: false,
        }
    }

    fn build_service(
        storage: Arc<MockStorage>,
        upstream: MockUpstream,
        policy: PolicyConfig,
    ) -> CachingPackageService {
        let eco = upstream.ecosystem();
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();
        clients.insert(eco, Arc::new(upstream));
        CachingPackageService::new(storage, clients, policy)
    }

    #[tokio::test]
    async fn cache_hit_returns_stored_artifact() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "2.31.0".to_string(),
            filename: "requests-2.31.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"fake tarball content");
        let storage = Arc::new(MockStorage::with_data(vec![(
            &artifact_id.storage_key(),
            artifact_data.clone(),
        )]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts: AHashMap::new(), // Empty: should never be called
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data, "should return cached artifact data");
    }

    #[tokio::test]
    async fn cache_miss_fetches_and_stores() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"fetched from upstream");
        let mut artifacts = AHashMap::new();
        artifacts.insert("serde-1.0.0.tar.gz".to_string(), artifact_data.clone());

        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts,
        };

        let service = build_service(storage.clone(), upstream, PolicyConfig::default());

        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("serde"),
            version: "1.0.0".to_string(),
            filename: "serde-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data, "should return upstream data");

        // Verify it was stored
        let stored = storage
            .get(&artifact_id.storage_key())
            .await
            .unwrap()
            .expect("artifact should be cached after fetch");
        assert_eq!(
            stored, artifact_data,
            "stored data should match fetched data"
        );
    }

    #[tokio::test]
    async fn policy_blocks_forbidden_package() {
        let storage = Arc::new(MockStorage::new());
        let meta = test_metadata("evil-pkg", "1.0.0");
        let mut metadata_map = AHashMap::new();
        metadata_map.insert("1.0.0".to_string(), meta);

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata: metadata_map,
            artifacts: AHashMap::new(),
        };

        let policy = PolicyConfig {
            blocked_packages: vec!["evil-pkg".to_string()],
            ..Default::default()
        };

        let service = build_service(storage, upstream, policy);
        let name = PackageName::new("evil-pkg");
        let result = service
            .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
            .await;

        assert!(result.is_err(), "should reject blocked package");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("policy violation"),
            "error should be a policy violation, got: {err}"
        );
    }

    #[tokio::test]
    async fn blocked_metadata_never_cached() {
        let storage = Arc::new(MockStorage::new());
        let meta = test_metadata("blocked-pkg", "2.0.0");
        let mut metadata_map = AHashMap::new();
        metadata_map.insert("2.0.0".to_string(), meta);

        let upstream = MockUpstream {
            eco: Ecosystem::Npm,
            versions: vec![],
            metadata: metadata_map,
            artifacts: AHashMap::new(),
        };

        let policy = PolicyConfig {
            blocked_packages: vec!["blocked-pkg".to_string()],
            ..Default::default()
        };

        let service = build_service(storage.clone(), upstream, policy);
        let name = PackageName::new("blocked-pkg");
        let _ = service
            .get_version_metadata(Ecosystem::Npm, &name, "2.0.0")
            .await;

        let key = CachingPackageService::metadata_key(Ecosystem::Npm, &name, "2.0.0");
        let cached = storage.get(&key).await.unwrap();
        assert!(
            cached.is_none(),
            "blocked metadata must not be stored in cache"
        );
    }

    #[tokio::test]
    async fn list_packages_extracts_names() {
        let storage = Arc::new(MockStorage::with_data(vec![
            ("pypi/requests/2.31.0/_metadata.json", Bytes::new()),
            ("pypi/requests/2.30.0/_metadata.json", Bytes::new()),
            ("pypi/flask/3.0.0/_metadata.json", Bytes::new()),
            ("pypi/django/4.2.0/_metadata.json", Bytes::new()),
        ]));

        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());
        let packages = service.list_packages(Ecosystem::PyPI).await.unwrap();

        let mut names: Vec<String> = packages.iter().map(|p| p.as_str().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["django", "flask", "requests"]);
    }

    #[tokio::test]
    async fn missing_upstream_returns_error() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());

        let name = PackageName::new("anything");
        let result = service.list_versions(Ecosystem::Hex, &name).await;

        assert!(
            result.is_err(),
            "should error when no upstream is configured"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no upstream configured for hex"),
            "error should mention missing upstream, got: {err}"
        );
    }

    #[tokio::test]
    async fn integrity_verified_on_cache_hit() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "2.31.0".to_string(),
            filename: "requests-2.31.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"fake tarball content");
        let hash = integrity::blake3_hex(&artifact_data);

        let storage = Arc::new(MockStorage::with_data(vec![
            (&artifact_id.storage_key(), artifact_data.clone()),
            (
                &format!("{}.blake3", artifact_id.storage_key()),
                Bytes::from(hash),
            ),
        ]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts: AHashMap::new(),
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(
            result, artifact_data,
            "should return verified cached artifact"
        );
    }

    #[tokio::test]
    async fn integrity_rejects_corrupted_artifact() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "2.31.0".to_string(),
            filename: "requests-2.31.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"corrupted data");
        let wrong_hash = "0".repeat(64);

        let storage = Arc::new(MockStorage::with_data(vec![
            (&artifact_id.storage_key(), artifact_data),
            (
                &format!("{}.blake3", artifact_id.storage_key()),
                Bytes::from(wrong_hash),
            ),
        ]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts: AHashMap::new(),
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await;
        assert!(result.is_err(), "should reject corrupted artifact");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("integrity check failed"),
            "error should be integrity failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn policy_blocks_artifact_download() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("evil-pkg"),
            version: "1.0.0".to_string(),
            filename: "evil-pkg-1.0.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"evil content");

        let storage = Arc::new(MockStorage::with_data(vec![(
            &artifact_id.storage_key(),
            artifact_data,
        )]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts: AHashMap::new(),
        };

        let policy = PolicyConfig {
            blocked_packages: vec!["evil-pkg".to_string()],
            ..Default::default()
        };

        let service = build_service(storage, upstream, policy);
        let result = service.get_artifact(&artifact_id).await;
        assert!(
            result.is_err(),
            "should block artifact download for blocked package"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("policy violation"),
            "error should be a policy violation, got: {err}"
        );
    }

    #[tokio::test]
    async fn hash_sidecar_stored_on_fetch() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"upstream content");
        let expected_hash = integrity::blake3_hex(&artifact_data);
        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tar.gz".to_string(), artifact_data.clone());

        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts,
        };

        let service = build_service(storage.clone(), upstream, PolicyConfig::default());

        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data);

        let hash_key = format!("{}.blake3", artifact_id.storage_key());
        let stored_hash = storage
            .get(&hash_key)
            .await
            .unwrap()
            .expect("blake3 sidecar should be stored after fetch");
        assert_eq!(
            std::str::from_utf8(&stored_hash).unwrap(),
            expected_hash,
            "stored hash should match computed blake3"
        );
    }
}
