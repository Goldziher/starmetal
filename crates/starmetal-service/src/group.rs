//! The group repository service (ADR-0019).
//!
//! [`GroupPackageService`] implements the core [`PackageService`] port over an
//! ordered set of member services, presenting several proxy repositories of one
//! ecosystem behind a single mount. It is the pull-through-capable counterpart to
//! the cache-only [`CompositeGroupFacet`](crate::CompositeGroupFacet): each member
//! is a full [`PackageService`], so a group read that misses every member's cache
//! still triggers that member's normal upstream pull-through, in member order.
//!
//! Resolution semantics:
//! - **version listings** union across all members (deduplicated, deterministically
//!   ordered by [`merge_version_lists`]); earlier members win a duplicated version.
//! - **metadata and artifacts** resolve first-match: the first member that has the
//!   coordinate serves it, and later members are not consulted.
//!
//! A group is **read-only**: its [`PublishingService`] impl rejects every publish
//! and yank, because there is no single member a write could unambiguously target.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use starmetal_core::ports::{PackageService, PublishingService, StatisticsService};
use starmetal_core::publishing::{PublishRequest, PublishResult, YankRequest};
use starmetal_core::statistics::StatisticsSnapshot;

use crate::merge_version_lists;

/// A read-only virtual repository merging ordered member services of one ecosystem.
///
/// Members are held as `Arc<dyn PackageService>` so a group read falls through to each member's live
/// pull-through on a cache miss (see the module docs). Construct with [`GroupPackageService::new`].
pub struct GroupPackageService {
    ecosystem: Ecosystem,
    members: Vec<Arc<dyn PackageService>>,
}

impl GroupPackageService {
    /// Build a group over ordered `members`, all serving `ecosystem`.
    ///
    /// Member order is the resolution order: [`PackageService::get_artifact`] and
    /// [`PackageService::get_version_metadata`] return the first member that has the coordinate, and
    /// [`PackageService::list_versions`] gives earlier members precedence for a duplicated version.
    pub fn new(ecosystem: Ecosystem, members: Vec<Arc<dyn PackageService>>) -> Self {
        Self { ecosystem, members }
    }

    /// The ecosystem every member of this group serves.
    pub fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }
}

impl std::fmt::Debug for GroupPackageService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupPackageService")
            .field("ecosystem", &self.ecosystem)
            .field("members", &self.members.len())
            .finish()
    }
}

#[async_trait]
impl PackageService for GroupPackageService {
    async fn list_versions(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<Vec<VersionInfo>> {
        // Union across members: collect every member's listing, then merge. A member that errors
        // (e.g. the package is absent from its upstream) is skipped so one member's miss does not sink
        // the group; only when *every* member errors is the last error surfaced.
        let mut member_lists = Vec::with_capacity(self.members.len());
        let mut last_error = None;
        for member in &self.members {
            match member.list_versions(ecosystem, name).await {
                Ok(versions) => member_lists.push(versions),
                Err(error) => last_error = Some(error),
            }
        }
        if member_lists.is_empty() {
            return match last_error {
                Some(error) => Err(error),
                None => Ok(Vec::new()),
            };
        }
        Ok(merge_version_lists(&member_lists))
    }

    async fn get_version_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<VersionMetadata> {
        // First-match: the first member that resolves the version wins; later members are not
        // consulted. Every member's error is remembered so an all-miss group returns a real error.
        let mut last_error = None;
        for member in &self.members {
            match member.get_version_metadata(ecosystem, name, version).await {
                Ok(metadata) => return Ok(metadata),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| StarmetalError::VersionNotFound {
            ecosystem: ecosystem.to_string(),
            name: name.as_str().to_string(),
            version: version.to_string(),
        }))
    }

    async fn validate_metadata(&self, metadata: &VersionMetadata) -> Result<()> {
        // Members share the same policy surface, so validating against the first member is
        // representative. An empty group cannot be constructed through the assembly path (validation
        // requires at least one member), but guard defensively rather than panic.
        match self.members.first() {
            Some(member) => member.validate_metadata(metadata).await,
            None => Ok(()),
        }
    }

    async fn get_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        // First-match: serve the first member that has the artifact (each member runs its own
        // pull-through on a cache miss). Later members are untouched once one succeeds.
        let mut last_error = None;
        for member in &self.members {
            match member.get_artifact(artifact_id).await {
                Ok(bytes) => return Ok(bytes),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| StarmetalError::ArtifactNotFound(artifact_id.storage_key())))
    }

    async fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<PackageName>> {
        // Union of each member's cached package names, deduplicated and deterministically ordered.
        let mut seen = ahash::AHashSet::new();
        let mut packages = Vec::new();
        for member in &self.members {
            for name in member.list_packages(ecosystem).await? {
                if seen.insert(name.as_str().to_string()) {
                    packages.push(name);
                }
            }
        }
        packages.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        Ok(packages)
    }

    async fn get_raw_upstream(&self, _ecosystem: Ecosystem, _name: &PackageName) -> Result<Option<Bytes>> {
        // A group has no single upstream blob to replay; a merged index has no meaningful raw form.
        // Returning `None` makes protocol adapters rebuild the response from the group-merged
        // `list_versions`/`get_version_metadata` instead of a single member's cached upstream body.
        Ok(None)
    }

    async fn put_raw_upstream(&self, _ecosystem: Ecosystem, _name: &PackageName, _data: Bytes) -> Result<()> {
        // No raw blob is stored for a group (see `get_raw_upstream`); a write is a no-op rather than
        // an error so adapters that opportunistically cache the rebuilt body stay on the happy path.
        Ok(())
    }
}

#[async_trait]
impl PublishingService for GroupPackageService {
    async fn publish_package(&self, _request: PublishRequest) -> Result<PublishResult> {
        Err(StarmetalError::Publish(format!(
            "group repository (ecosystem '{}') is read-only and cannot be published to; \
             publish to a member repository instead",
            self.ecosystem
        )))
    }

    async fn set_yanked(&self, _request: YankRequest) -> Result<VersionMetadata> {
        Err(StarmetalError::Publish(format!(
            "group repository (ecosystem '{}') is read-only; yank a version through its member \
             repository instead",
            self.ecosystem
        )))
    }
}

impl StatisticsService for GroupPackageService {
    fn statistics(&self) -> StatisticsSnapshot {
        // A group keeps no counters of its own; each member's own service records its statistics.
        StatisticsSnapshot::default()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A fake member `PackageService` with fixed per-version data, used to exercise group resolution
    /// without storage or upstreams. Records artifact lookups so first-match order is verifiable.
    struct FakeMember {
        versions: Vec<VersionInfo>,
        artifacts: Vec<(ArtifactId, Bytes)>,
        artifact_lookups: Mutex<Vec<ArtifactId>>,
    }

    impl FakeMember {
        fn new(versions: Vec<VersionInfo>, artifacts: Vec<(ArtifactId, Bytes)>) -> Self {
            Self {
                versions,
                artifacts,
                artifact_lookups: Mutex::new(Vec::new()),
            }
        }
    }

    fn version(v: &str) -> VersionInfo {
        VersionInfo {
            version: v.to_string(),
            yanked: false,
        }
    }

    fn artifact_id(name: &str, version: &str) -> ArtifactId {
        ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new(name),
            version: version.to_string(),
            filename: format!("{name}-{version}.tar.gz"),
        }
    }

    #[async_trait]
    impl PackageService for FakeMember {
        async fn list_versions(&self, _ecosystem: Ecosystem, _name: &PackageName) -> Result<Vec<VersionInfo>> {
            Ok(self.versions.clone())
        }

        async fn get_version_metadata(
            &self,
            ecosystem: Ecosystem,
            name: &PackageName,
            version: &str,
        ) -> Result<VersionMetadata> {
            if self.versions.iter().any(|info| info.version == version) {
                Ok(VersionMetadata {
                    name: name.clone(),
                    version: version.to_string(),
                    artifacts: Vec::new(),
                    license: None,
                    yanked: false,
                    listed: Some(true),
                    protocol_metadata: None,
                })
            } else {
                Err(StarmetalError::VersionNotFound {
                    ecosystem: ecosystem.to_string(),
                    name: name.as_str().to_string(),
                    version: version.to_string(),
                })
            }
        }

        async fn validate_metadata(&self, _metadata: &VersionMetadata) -> Result<()> {
            Ok(())
        }

        async fn get_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
            self.artifact_lookups.lock().expect("lock").push(artifact_id.clone());
            self.artifacts
                .iter()
                .find(|(id, _)| id == artifact_id)
                .map(|(_, bytes)| bytes.clone())
                .ok_or_else(|| StarmetalError::ArtifactNotFound(artifact_id.storage_key()))
        }

        async fn list_packages(&self, _ecosystem: Ecosystem) -> Result<Vec<PackageName>> {
            Ok(Vec::new())
        }

        async fn get_raw_upstream(&self, _ecosystem: Ecosystem, _name: &PackageName) -> Result<Option<Bytes>> {
            Ok(None)
        }

        async fn put_raw_upstream(&self, _ecosystem: Ecosystem, _name: &PackageName, _data: Bytes) -> Result<()> {
            Ok(())
        }
    }

    fn group(members: Vec<Arc<FakeMember>>) -> GroupPackageService {
        GroupPackageService::new(
            Ecosystem::PyPI,
            members.into_iter().map(|m| m as Arc<dyn PackageService>).collect(),
        )
    }

    #[tokio::test]
    async fn list_versions_unions_member_listings() {
        let first = Arc::new(FakeMember::new(vec![version("1.0.0"), version("1.2.0")], vec![]));
        let second = Arc::new(FakeMember::new(vec![version("1.1.0"), version("1.2.0")], vec![]));
        let group = group(vec![first, second]);

        let versions = group
            .list_versions(Ecosystem::PyPI, &PackageName::new("widget"))
            .await
            .expect("merge");
        let rendered: Vec<&str> = versions.iter().map(|info| info.version.as_str()).collect();
        assert_eq!(rendered, ["1.0.0", "1.1.0", "1.2.0"]);
    }

    #[tokio::test]
    async fn get_artifact_serves_first_member_and_falls_through_to_the_second() {
        let wanted = artifact_id("widget", "2.0.0");
        // The first member lacks the version entirely; the second holds the artifact.
        let first = Arc::new(FakeMember::new(vec![version("1.0.0")], vec![]));
        let second = Arc::new(FakeMember::new(
            vec![version("2.0.0")],
            vec![(wanted.clone(), Bytes::from_static(b"payload"))],
        ));
        let third = Arc::new(FakeMember::new(
            vec![version("2.0.0")],
            vec![(wanted.clone(), Bytes::from_static(b"shadow"))],
        ));
        let group = group(vec![first, second, third.clone()]);

        let bytes = group.get_artifact(&wanted).await.expect("artifact");
        assert_eq!(bytes.as_ref(), b"payload");
        // Resolution stops at the first hit: the third member is never consulted.
        assert!(
            third.artifact_lookups.lock().expect("lock").is_empty(),
            "first-match must not consult members past the first hit"
        );
    }

    #[tokio::test]
    async fn get_artifact_reports_not_found_when_no_member_has_it() {
        let wanted = artifact_id("widget", "9.9.9");
        let first = Arc::new(FakeMember::new(vec![version("1.0.0")], vec![]));
        let second = Arc::new(FakeMember::new(vec![version("2.0.0")], vec![]));
        let group = group(vec![first, second]);

        let error = group.get_artifact(&wanted).await.expect_err("missing artifact");
        assert!(matches!(error, StarmetalError::ArtifactNotFound(_)), "got: {error:?}");
    }

    #[tokio::test]
    async fn get_version_metadata_returns_the_first_member_with_the_version() {
        let first = Arc::new(FakeMember::new(vec![version("1.0.0")], vec![]));
        let second = Arc::new(FakeMember::new(vec![version("2.0.0")], vec![]));
        let group = group(vec![first, second]);

        let metadata = group
            .get_version_metadata(Ecosystem::PyPI, &PackageName::new("widget"), "2.0.0")
            .await
            .expect("second member resolves 2.0.0");
        assert_eq!(metadata.version, "2.0.0");
    }

    #[tokio::test]
    async fn publish_is_rejected_because_a_group_is_read_only() {
        let group = group(vec![Arc::new(FakeMember::new(vec![version("1.0.0")], vec![]))]);
        let request = PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("widget"),
            version: "1.0.0".to_string(),
            license: None,
            yanked: false,
            listed: true,
            artifacts: vec![],
            protocol_metadata: Default::default(),
            allow_overwrite: false,
            allow_shadowing: false,
            repository: None,
        };
        let error = group
            .publish_package(request)
            .await
            .expect_err("group publish must fail");
        assert!(matches!(error, StarmetalError::Publish(_)), "got: {error:?}");
    }

    #[tokio::test]
    async fn get_raw_upstream_is_always_none() {
        let group = group(vec![Arc::new(FakeMember::new(vec![version("1.0.0")], vec![]))]);
        let raw = group
            .get_raw_upstream(Ecosystem::PyPI, &PackageName::new("widget"))
            .await
            .expect("raw upstream");
        assert!(raw.is_none(), "a group has no raw upstream body to replay");
    }
}
