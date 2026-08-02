//! Concrete facet composition types (ADR-0019).
//!
//! This module carries the *composition* half of the facet model: the group
//! capability implementation ([`CompositeGroupFacet`]) and the concrete recipes
//! ([`ProxyRecipe`], [`GroupRecipe`]) that expose facets to the
//! [`RecipeRegistry`](starmetal_core::repository::RecipeRegistry) at assembly.
//!
//! The proxy/hosted facets themselves are implemented on
//! [`CachingPackageService`](crate::CachingPackageService) (see `service`), which
//! wraps the existing pull-through engine rather than duplicating it.

use std::sync::Arc;

use ahash::AHashSet;
use async_trait::async_trait;
use bytes::Bytes;
use starmetal_core::error::Result;
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo};
use starmetal_core::repository::{
    GroupFacet, HostedFacet, ProxyFacet, Recipe, RecipeKey, RepositoryId, RepositoryKind,
};

/// Merge per-member version listings into a single deduplicated, deterministically ordered list.
///
/// Union semantics: a version is kept the first time it is seen in member order, so earlier members
/// take precedence for a version's `yanked` flag (mirroring the first-match resolution of
/// [`CompositeGroupFacet::first_artifact`]). The result is sorted by version string, so the same set
/// of members always produces byte-identical output regardless of per-member ordering.
pub fn merge_version_lists(member_lists: &[Vec<VersionInfo>]) -> Vec<VersionInfo> {
    let mut seen = AHashSet::new();
    let mut merged = Vec::new();
    for list in member_lists {
        for info in list {
            if seen.insert(info.version.clone()) {
                merged.push(info.clone());
            }
        }
    }
    merged.sort_by(|left, right| left.version.cmp(&right.version));
    merged
}

/// A concrete [`GroupFacet`] fanning out over ordered member proxy facets.
///
/// First-match for artifacts, merge-all for indexes. Members are held as
/// `(RepositoryId, Arc<dyn ProxyFacet>)` pairs so a group resolves against each member's cached
/// view through the same [`ProxyFacet`] port every proxy repository exposes.
pub struct CompositeGroupFacet {
    members: Vec<(RepositoryId, Arc<dyn ProxyFacet>)>,
}

impl CompositeGroupFacet {
    /// Build a group facet over ordered members. Resolution follows member order: `first_artifact`
    /// returns the first member with the artifact cached, and `merge_index` gives earlier members
    /// precedence for a duplicated version.
    pub fn new(members: Vec<(RepositoryId, Arc<dyn ProxyFacet>)>) -> Self {
        Self { members }
    }
}

#[async_trait]
impl GroupFacet for CompositeGroupFacet {
    fn members(&self) -> Vec<RepositoryId> {
        self.members.iter().map(|(id, _)| id.clone()).collect()
    }

    async fn first_artifact(&self, artifact_id: &ArtifactId) -> Result<Option<Bytes>> {
        // First-match: return the first member that has the artifact cached. Resolution goes through
        // each member's `ProxyFacet::cached_artifact`, which verifies integrity before returning.
        for (_, member) in &self.members {
            if let Some(bytes) = member.cached_artifact(artifact_id).await? {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    async fn merge_index(
        &self,
        _ecosystem: Ecosystem,
        _name: &PackageName,
        member_indexes: Vec<Bytes>,
    ) -> Result<Bytes> {
        // Member indexes are the internal `_versions.json` representation (a `Vec<VersionInfo>`),
        // which is ecosystem-agnostic; they are unioned by version. Per-ecosystem *wire-format*
        // index merging (maven-metadata.xml, npm packument, PyPI simple index) is deferred — see the
        // Stage N8 report.
        let mut member_lists = Vec::with_capacity(member_indexes.len());
        for bytes in &member_indexes {
            member_lists.push(serde_json::from_slice::<Vec<VersionInfo>>(bytes)?);
        }
        let merged = merge_version_lists(&member_lists);
        Ok(Bytes::from(serde_json::to_vec(&merged)?))
    }
}

/// A proxy recipe: exposes the shared pull-through service as both the [`ProxyFacet`] and the
/// [`HostedFacet`] for a `(ecosystem, proxy)` pair. The same `CachingPackageService` backs both, so
/// no behavior diverges from the historical single-service proxy path.
pub struct ProxyRecipe {
    ecosystem: Ecosystem,
    proxy: Arc<dyn ProxyFacet>,
    hosted: Arc<dyn HostedFacet>,
}

impl ProxyRecipe {
    /// Build a proxy recipe for `ecosystem` from the shared service's facets.
    pub fn new(ecosystem: Ecosystem, proxy: Arc<dyn ProxyFacet>, hosted: Arc<dyn HostedFacet>) -> Self {
        Self {
            ecosystem,
            proxy,
            hosted,
        }
    }
}

impl Recipe for ProxyRecipe {
    fn key(&self) -> RecipeKey {
        RecipeKey::new(self.ecosystem, RepositoryKind::Proxy)
    }

    fn proxy_facet(&self) -> Option<Arc<dyn ProxyFacet>> {
        Some(self.proxy.clone())
    }

    fn hosted_facet(&self) -> Option<Arc<dyn HostedFacet>> {
        Some(self.hosted.clone())
    }
}

/// A group recipe: exposes a [`GroupFacet`] for a `(ecosystem, group)` pair.
pub struct GroupRecipe {
    ecosystem: Ecosystem,
    group: Arc<dyn GroupFacet>,
}

impl GroupRecipe {
    /// Build a group recipe for `ecosystem` from a group facet.
    pub fn new(ecosystem: Ecosystem, group: Arc<dyn GroupFacet>) -> Self {
        Self { ecosystem, group }
    }
}

impl Recipe for GroupRecipe {
    fn key(&self) -> RecipeKey {
        RecipeKey::new(self.ecosystem, RepositoryKind::Group)
    }

    fn group_facet(&self) -> Option<Arc<dyn GroupFacet>> {
        Some(self.group.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use starmetal_core::error::StarmetalError;
    use starmetal_core::package::VersionMetadata;
    use starmetal_core::repository::{RecipeRegistry, RepositoryKind};

    use super::*;

    /// A fake proxy facet with a fixed artifact cache, used to exercise group resolution without a
    /// real storage backend. Records which members were consulted so first-match order is verifiable.
    struct FakeProxy {
        artifacts: Vec<(ArtifactId, Bytes)>,
        consulted: Mutex<Vec<ArtifactId>>,
    }

    impl FakeProxy {
        fn new(artifacts: Vec<(ArtifactId, Bytes)>) -> Self {
            Self {
                artifacts,
                consulted: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ProxyFacet for FakeProxy {
        async fn cached_versions(
            &self,
            _ecosystem: Ecosystem,
            _name: &PackageName,
        ) -> Result<Option<Vec<VersionInfo>>> {
            Ok(None)
        }
        async fn store_versions(
            &self,
            _ecosystem: Ecosystem,
            _name: &PackageName,
            _versions: &[VersionInfo],
        ) -> Result<()> {
            Ok(())
        }
        async fn cached_metadata(
            &self,
            _ecosystem: Ecosystem,
            _name: &PackageName,
            _version: &str,
        ) -> Result<Option<VersionMetadata>> {
            Ok(None)
        }
        async fn store_metadata(
            &self,
            _ecosystem: Ecosystem,
            _name: &PackageName,
            _version: &str,
            _metadata: &VersionMetadata,
        ) -> Result<()> {
            Ok(())
        }
        async fn cached_artifact(&self, artifact_id: &ArtifactId) -> Result<Option<Bytes>> {
            self.consulted.lock().expect("lock").push(artifact_id.clone());
            Ok(self
                .artifacts
                .iter()
                .find(|(id, _)| id == artifact_id)
                .map(|(_, bytes)| bytes.clone()))
        }
        async fn store_artifact(&self, _artifact_id: &ArtifactId, _data: Bytes) -> Result<()> {
            Ok(())
        }
        async fn is_negatively_cached(&self, _ecosystem: Ecosystem, _name: &PackageName) -> Result<bool> {
            Ok(false)
        }
        async fn record_negative_cache(&self, _ecosystem: Ecosystem, _name: &PackageName) -> Result<()> {
            Ok(())
        }
    }

    fn version(v: &str, yanked: bool) -> VersionInfo {
        VersionInfo {
            version: v.to_string(),
            yanked,
        }
    }

    fn artifact_id(name: &str, filename: &str) -> ArtifactId {
        ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new(name),
            version: "1.0.0".to_string(),
            filename: filename.to_string(),
        }
    }

    #[test]
    fn merge_version_lists_unions_dedups_and_sorts() {
        let first = vec![version("1.0.0", false), version("1.2.0", false)];
        let second = vec![version("1.1.0", false), version("1.2.0", true)];
        let merged = merge_version_lists(&[first, second]);

        let versions: Vec<&str> = merged.iter().map(|info| info.version.as_str()).collect();
        assert_eq!(versions, ["1.0.0", "1.1.0", "1.2.0"]);
        // Earlier member wins for the duplicated 1.2.0: its `yanked = false` is retained.
        let dup = merged
            .iter()
            .find(|info| info.version == "1.2.0")
            .expect("1.2.0 present");
        assert!(!dup.yanked, "earlier member precedence for duplicate version");
    }

    #[tokio::test]
    async fn merge_index_merges_two_members() {
        let first = Bytes::from(serde_json::to_vec(&vec![version("1.0.0", false)]).unwrap());
        let second = Bytes::from(serde_json::to_vec(&vec![version("2.0.0", false)]).unwrap());
        let group = CompositeGroupFacet::new(vec![
            (
                RepositoryId::new("a"),
                Arc::new(FakeProxy::new(vec![])) as Arc<dyn ProxyFacet>,
            ),
            (
                RepositoryId::new("b"),
                Arc::new(FakeProxy::new(vec![])) as Arc<dyn ProxyFacet>,
            ),
        ]);
        let merged_bytes = group
            .merge_index(Ecosystem::PyPI, &PackageName::new("pkg"), vec![first, second])
            .await
            .expect("merge");
        let merged: Vec<VersionInfo> = serde_json::from_slice(&merged_bytes).unwrap();
        let versions: Vec<&str> = merged.iter().map(|info| info.version.as_str()).collect();
        assert_eq!(versions, ["1.0.0", "2.0.0"]);
    }

    #[tokio::test]
    async fn first_artifact_returns_first_member_hit() {
        let wanted = artifact_id("pkg", "pkg-1.0.0.tar.gz");
        let first = Arc::new(FakeProxy::new(vec![])); // miss
        let second = Arc::new(FakeProxy::new(vec![(wanted.clone(), Bytes::from_static(b"payload"))]));
        let third = Arc::new(FakeProxy::new(vec![(wanted.clone(), Bytes::from_static(b"shadow"))]));
        let group = CompositeGroupFacet::new(vec![
            (RepositoryId::new("first"), first.clone() as Arc<dyn ProxyFacet>),
            (RepositoryId::new("second"), second.clone() as Arc<dyn ProxyFacet>),
            (RepositoryId::new("third"), third.clone() as Arc<dyn ProxyFacet>),
        ]);

        let bytes = group.first_artifact(&wanted).await.expect("first_artifact");
        assert_eq!(bytes.as_deref(), Some(b"payload".as_slice()));
        // The third member must never be consulted once the second hits.
        assert!(
            third.consulted.lock().expect("lock").is_empty(),
            "resolution stops at first hit"
        );
    }

    #[tokio::test]
    async fn first_artifact_returns_none_when_no_member_has_it() {
        let wanted = artifact_id("pkg", "pkg-1.0.0.tar.gz");
        let group = CompositeGroupFacet::new(vec![
            (
                RepositoryId::new("a"),
                Arc::new(FakeProxy::new(vec![])) as Arc<dyn ProxyFacet>,
            ),
            (
                RepositoryId::new("b"),
                Arc::new(FakeProxy::new(vec![])) as Arc<dyn ProxyFacet>,
            ),
        ]);
        assert!(group.first_artifact(&wanted).await.expect("first_artifact").is_none());
    }

    #[test]
    fn recipe_registry_looks_up_by_kind_and_ecosystem() {
        let mut registry = RecipeRegistry::new();

        let group = Arc::new(CompositeGroupFacet::new(vec![])) as Arc<dyn GroupFacet>;
        registry.register(Arc::new(GroupRecipe::new(Ecosystem::Npm, group)));

        let group_key = RecipeKey::new(Ecosystem::Npm, RepositoryKind::Group);
        let recipe = registry.get(&group_key).expect("group recipe registered");
        assert_eq!(recipe.key(), group_key);
        assert!(recipe.group_facet().is_some());
        assert!(recipe.proxy_facet().is_none());

        // A different (ecosystem, kind) pair is a distinct key with no recipe.
        assert!(
            registry
                .get(&RecipeKey::new(Ecosystem::PyPI, RepositoryKind::Group))
                .is_none()
        );
        assert!(
            registry
                .get(&RecipeKey::new(Ecosystem::Npm, RepositoryKind::Proxy))
                .is_none()
        );
    }

    #[tokio::test]
    async fn merge_index_propagates_malformed_member_index() {
        let group = CompositeGroupFacet::new(vec![]);
        let bad = Bytes::from_static(b"not json");
        let err = group
            .merge_index(Ecosystem::PyPI, &PackageName::new("pkg"), vec![bad])
            .await
            .expect_err("malformed index must error");
        assert!(matches!(err, StarmetalError::Json(_)), "got: {err:?}");
    }
}
