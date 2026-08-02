//! Facet trait implementations on [`CachingPackageService`] (ADR-0019).
//!
//! These make the ADR-0019 capability ports load-bearing by *wrapping* the
//! existing pull-through engine — every method delegates to the same
//! cache/storage/publish code the proxy path already uses, so no behavior
//! changes. The composition half (group facet, recipes) lives in
//! [`crate::facets`].

use async_trait::async_trait;
use bytes::Bytes;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::integrity;
use starmetal_core::package::{ArtifactDigest, ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use starmetal_core::ports::PublishingService;
use starmetal_core::publishing::{PublishRequest, PublishResult};
use starmetal_core::repository::{HostedFacet, ProxyFacet};

use super::CachingPackageService;

#[async_trait]
impl ProxyFacet for CachingPackageService {
    async fn cached_versions(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<Option<Vec<VersionInfo>>> {
        let key = Self::versions_key(ecosystem, name)?;
        match self.storage.get(&key).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn store_versions(&self, ecosystem: Ecosystem, name: &PackageName, versions: &[VersionInfo]) -> Result<()> {
        let key = Self::versions_key(ecosystem, name)?;
        self.storage.put(&key, Bytes::from(serde_json::to_vec(versions)?)).await
    }

    async fn cached_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<Option<VersionMetadata>> {
        let key = Self::metadata_key(ecosystem, name, version)?;
        match self.storage.get(&key).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn store_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
        metadata: &VersionMetadata,
    ) -> Result<()> {
        let key = Self::metadata_key(ecosystem, name, version)?;
        self.storage.put(&key, Bytes::from(serde_json::to_vec(metadata)?)).await
    }

    async fn cached_artifact(&self, artifact_id: &ArtifactId) -> Result<Option<Bytes>> {
        let key = artifact_id.validated_storage_key()?.into_string();
        let hash_key = format!("{key}.blake3");
        // Fetch bytes and blake3 sidecar concurrently, matching `get_artifact`'s cache-hit read.
        let (cached, cached_hash) = futures::try_join!(self.storage.get(&key), self.storage.get(&hash_key))?;
        let Some(cached) = cached else {
            return Ok(None);
        };
        // A present artifact with no (or an invalid) integrity sidecar is corruption, not a miss.
        let expected_hash = cached_hash.ok_or_else(|| StarmetalError::IntegrityError {
            expected: format!("missing sidecar {hash_key}"),
            actual: "unverified cached artifact".to_string(),
        })?;
        let expected =
            std::str::from_utf8(&expected_hash).map_err(|error| StarmetalError::Storage(error.to_string()))?;
        integrity::verify_or_err(&cached, expected)?;
        Ok(Some(cached))
    }

    async fn store_artifact(&self, artifact_id: &ArtifactId, data: Bytes) -> Result<()> {
        let key = artifact_id.validated_storage_key()?.into_string();
        let hash_key = format!("{key}.blake3");
        let hash = integrity::blake3_hex(&data);
        // Sidecar first, then bytes — the same order `fetch_and_cache_artifact` writes them, so a
        // reader never sees bytes without their hash.
        self.storage.put(&hash_key, Bytes::from(hash)).await?;
        self.storage.put(&key, data).await
    }

    async fn is_negatively_cached(&self, _ecosystem: Ecosystem, _name: &PackageName) -> Result<bool> {
        // The caching service keeps no negative cache today, so nothing is ever known-absent: the
        // engine always attempts the upstream query. Returning `false` preserves that behavior
        // exactly. (A real negative cache, when added, backs this method.)
        Ok(false)
    }

    async fn record_negative_cache(&self, _ecosystem: Ecosystem, _name: &PackageName) -> Result<()> {
        // No negative cache exists yet; recording a miss is a behavior-preserving no-op.
        Ok(())
    }
}

#[async_trait]
impl HostedFacet for CachingPackageService {
    async fn validate_upload(&self, request: &PublishRequest) -> Result<()> {
        // Mirrors `publish_package`'s pre-write checks (same error strings), without storing:
        // block-list, non-empty artifact set, per-artifact filename + storage-key validation, and the
        // policy check on the resulting metadata.
        self.check_package_allowed(&request.name)?;
        if request.artifacts.is_empty() {
            return Err(StarmetalError::Publish(
                "publish requires at least one artifact".to_string(),
            ));
        }
        for artifact in &request.artifacts {
            if artifact.filename.trim().is_empty() {
                return Err(StarmetalError::Publish(
                    "artifact filename must not be empty".to_string(),
                ));
            }
            let artifact_id = ArtifactId {
                ecosystem: request.ecosystem,
                name: request.name.clone(),
                version: request.version.clone(),
                filename: artifact.filename.clone(),
            };
            let _ = artifact_id.validated_storage_key()?;
        }
        let digests: Vec<ArtifactDigest> = request
            .artifacts
            .iter()
            .map(|artifact| artifact.digest(integrity::blake3_hex(&artifact.data)))
            .collect();
        self.policy.check(&request.metadata(digests))?;
        Ok(())
    }

    async fn store_upload(&self, request: PublishRequest) -> Result<PublishResult> {
        // The full transactional publish pipeline (validation, quota, scan gate, signing, storage)
        // already lives in `publish_package`; the hosted facet is a thin alias onto it.
        PublishingService::publish_package(self, request).await
    }
}
