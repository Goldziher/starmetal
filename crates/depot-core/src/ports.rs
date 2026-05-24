use async_trait::async_trait;
use bytes::Bytes;

use crate::error::Result;
use crate::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use crate::publishing::{PublishRequest, PublishResult, YankRequest};

// ---------------------------------------------------------------------------
// Inbound port: the core service that protocol adapters call into
// ---------------------------------------------------------------------------

#[async_trait]
pub trait PackageService: Send + Sync {
    /// List all versions of a package.
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Vec<VersionInfo>>;

    /// Get metadata for a specific version.
    async fn get_version_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<VersionMetadata>;

    /// Validate metadata against current service policy.
    async fn validate_metadata(&self, metadata: &VersionMetadata) -> Result<()>;

    /// Download an artifact.
    async fn get_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes>;

    /// List all cached packages for an ecosystem.
    async fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<PackageName>>;

    /// Get the raw upstream response for a package, stored as an opaque blob.
    ///
    /// Protocol adapters use this to serve the full upstream response
    /// (preserving all protocol-specific fields) without depending on
    /// the upstream client's memory cache.
    async fn get_raw_upstream(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Option<Bytes>>;

    /// Store the raw upstream response for a package.
    async fn put_raw_upstream(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        data: Bytes,
    ) -> Result<()>;
}

#[async_trait]
pub trait PublishingService: Send + Sync {
    async fn publish_package(&self, request: PublishRequest) -> Result<PublishResult>;

    async fn set_yanked(&self, request: YankRequest) -> Result<VersionMetadata>;
}

// ---------------------------------------------------------------------------
// Outbound port: storage
// ---------------------------------------------------------------------------

#[async_trait]
pub trait StoragePort: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Bytes>>;
    async fn put(&self, key: &str, data: Bytes) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>>;
}

// ---------------------------------------------------------------------------
// Outbound port: upstream registry client
// ---------------------------------------------------------------------------

#[async_trait]
pub trait UpstreamClient: Send + Sync {
    /// Which ecosystem this client fetches from.
    fn ecosystem(&self) -> Ecosystem;

    /// Fetch available versions from upstream.
    async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>>;

    /// Fetch metadata for a specific version.
    async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata>;

    /// Fetch artifact bytes from upstream.
    async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes>;
}
