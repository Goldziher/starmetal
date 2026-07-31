//! Repository kinds, capability facets, and the recipe registry skeleton.
//!
//! This module realizes the model described in ADR-0019: a repository is a
//! composition of capability *facets* selected by a *recipe* keyed on a
//! [`RepositoryKind`] and an [`Ecosystem`]. The three facet traits defined here
//! ([`ProxyFacet`], [`HostedFacet`], [`GroupFacet`]) are ports: framework-free
//! abstractions that `starmetal-service` and `starmetal-adapters` implement.
//!
//! This is a definitions-only stage (Stage 0-A). The traits describe the method
//! surface each kind needs; no behavior is implemented here and no concrete
//! recipes are registered. Stage 1 populates the [`RecipeRegistry`] and wires the
//! facet implementations.

use std::str::FromStr;
use std::sync::Arc;

use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Result, StarmetalError};
use crate::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use crate::publishing::{PublishRequest, PublishResult};

// ---------------------------------------------------------------------------
// Repository kind
// ---------------------------------------------------------------------------

/// The kind of a repository, per ADR-0018/ADR-0019.
///
/// This is a typed distinction rather than a boolean: a repository is exactly one
/// of proxy, hosted, or group. The value is config-facing and serializes as a
/// lowercase string (`"proxy"`, `"hosted"`, `"group"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RepositoryKind {
    /// Caches an upstream registry (the pull-through behavior that exists today).
    Proxy,
    /// Stores artifacts published directly to Starmetal.
    Hosted,
    /// Virtual/aggregate repository presenting multiple members behind one URL.
    Group,
}

impl RepositoryKind {
    /// The lowercase string form used in configuration and recipe keys.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Hosted => "hosted",
            Self::Group => "group",
        }
    }
}

impl std::fmt::Display for RepositoryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RepositoryKind {
    type Err = StarmetalError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "proxy" => Ok(Self::Proxy),
            "hosted" => Ok(Self::Hosted),
            "group" => Ok(Self::Group),
            _ => Err(StarmetalError::Config(format!("unknown repository kind: {s}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Member identity (group facet)
// ---------------------------------------------------------------------------

/// Identifies a repository within a deployment.
///
/// Group repositories iterate their members by identity; this newtype keeps
/// member references distinct from arbitrary strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RepositoryId(String);

impl RepositoryId {
    /// Construct a repository identifier from any string-like value.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RepositoryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Capability facets (ports)
// ---------------------------------------------------------------------------

/// The pull-through proxy capability.
///
/// Models the `fetch → verify → policy → store → cache` pipeline that the
/// existing `CachingPackageService` performs: each read attempts to serve cached
/// content and, on a miss, the caller fetches from upstream and stores the result
/// through this facet. Negative-cache methods let the engine remember recent
/// upstream misses so it does not re-query for known-absent packages.
///
/// Implementations are held behind `Arc<dyn ProxyFacet>`, so every method is
/// object-safe.
#[async_trait]
pub trait ProxyFacet: Send + Sync {
    /// Return cached version listings for a package, or `None` on a cache miss.
    async fn cached_versions(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<Option<Vec<VersionInfo>>>;

    /// Store version listings fetched from upstream.
    async fn store_versions(&self, ecosystem: Ecosystem, name: &PackageName, versions: &[VersionInfo]) -> Result<()>;

    /// Return cached metadata for a specific version, or `None` on a cache miss.
    async fn cached_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<Option<VersionMetadata>>;

    /// Store version metadata fetched from upstream.
    async fn store_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
        metadata: &VersionMetadata,
    ) -> Result<()>;

    /// Return cached artifact bytes, or `None` on a cache miss.
    ///
    /// Implementations verify integrity (blake3 sidecar) before returning bytes.
    async fn cached_artifact(&self, artifact_id: &ArtifactId) -> Result<Option<Bytes>>;

    /// Store artifact bytes fetched from upstream (alongside any integrity sidecar).
    async fn store_artifact(&self, artifact_id: &ArtifactId, data: Bytes) -> Result<()>;

    /// Report whether the package is currently negatively cached (a known-recent
    /// upstream miss), letting the engine skip a redundant upstream query.
    async fn is_negatively_cached(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<bool>;

    /// Record a negative-cache entry after an upstream miss.
    async fn record_negative_cache(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<()>;
}

/// The direct-publish (hosted) capability.
///
/// Coordinates validation and storage of an artifact published directly to
/// Starmetal (ADR-0021): the caller submits a [`PublishRequest`], the facet
/// validates it, then stores the coordinates and returns a [`PublishResult`].
///
/// Implementations are held behind `Arc<dyn HostedFacet>`, so every method is
/// object-safe.
#[async_trait]
pub trait HostedFacet: Send + Sync {
    /// Validate an upload without storing it (coordinate, policy, and integrity checks).
    async fn validate_upload(&self, request: &PublishRequest) -> Result<()>;

    /// Validate and store an upload, returning the published coordinates.
    async fn store_upload(&self, request: PublishRequest) -> Result<PublishResult>;
}

/// The virtual/aggregate (group) capability.
///
/// A group repository fans out over ordered member repositories: first-match for
/// artifacts, merge-all for indexes. Index merging is per-ecosystem
/// (maven-metadata.xml, npm packument, PyPI simple index, Cargo index) and is the
/// one place a group needs ecosystem knowledge — hence [`GroupFacet::merge_index`]
/// is a hook implemented per ecosystem rather than shared code.
///
/// Implementations are held behind `Arc<dyn GroupFacet>`, so every method is
/// object-safe.
#[async_trait]
pub trait GroupFacet: Send + Sync {
    /// The ordered member repositories this group resolves against.
    fn members(&self) -> Vec<RepositoryId>;

    /// Return the first member's bytes for an artifact (first-match resolution),
    /// or `None` if no member has it.
    async fn first_artifact(&self, artifact_id: &ArtifactId) -> Result<Option<Bytes>>;

    /// Merge the per-member index responses into a single ecosystem-specific index.
    ///
    /// `member_indexes` holds the raw index bytes from each member that returned
    /// one, in member order; the implementation combines them according to the
    /// ecosystem's index format.
    async fn merge_index(&self, ecosystem: Ecosystem, name: &PackageName, member_indexes: Vec<Bytes>) -> Result<Bytes>;
}

// ---------------------------------------------------------------------------
// Recipe registry skeleton
// ---------------------------------------------------------------------------

/// Identifies a recipe by the `(kind, ecosystem)` pair it builds.
///
/// The string form is `"{ecosystem}-{kind}"` (for example `"pypi-proxy"`), which
/// is the key ADR-0019 uses for the recipe registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RecipeKey {
    /// The repository kind this recipe builds.
    pub kind: RepositoryKind,
    /// The ecosystem this recipe builds for.
    pub ecosystem: Ecosystem,
}

impl RecipeKey {
    /// Construct a recipe key from an ecosystem and a kind.
    pub fn new(ecosystem: Ecosystem, kind: RepositoryKind) -> Self {
        Self { kind, ecosystem }
    }
}

impl std::fmt::Display for RecipeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.ecosystem, self.kind)
    }
}

impl FromStr for RecipeKey {
    type Err = StarmetalError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Ecosystem names never contain '-', so split on the final separator.
        let (ecosystem, kind) = s
            .rsplit_once('-')
            .ok_or_else(|| StarmetalError::Config(format!("invalid recipe key: {s}")))?;
        Ok(Self {
            ecosystem: ecosystem.parse()?,
            kind: kind.parse()?,
        })
    }
}

/// Describes how to attach capability facets for a `(kind, ecosystem)` pair.
///
/// A recipe is the thin, per-format description that ADR-0019 calls for: it names
/// the pair it builds and exposes the facets a repository of that pair should
/// hold. The default facet accessors return `None`; Stage 1 recipes override the
/// ones relevant to their kind (a proxy recipe provides a [`ProxyFacet`], a hosted
/// recipe a [`HostedFacet`], a group recipe a [`GroupFacet`]).
pub trait Recipe: Send + Sync {
    /// The `(kind, ecosystem)` pair this recipe builds.
    fn key(&self) -> RecipeKey;

    /// The proxy facet this recipe attaches, if any.
    fn proxy_facet(&self) -> Option<Arc<dyn ProxyFacet>> {
        None
    }

    /// The hosted facet this recipe attaches, if any.
    fn hosted_facet(&self) -> Option<Arc<dyn HostedFacet>> {
        None
    }

    /// The group facet this recipe attaches, if any.
    fn group_facet(&self) -> Option<Arc<dyn GroupFacet>> {
        None
    }
}

/// A registry mapping [`RecipeKey`] to the [`Recipe`] that builds it.
///
/// This is the skeleton Stage 1 populates. It holds no concrete recipes yet; it
/// only provides registration and lookup so wiring can be added without changing
/// this type's shape.
#[derive(Clone, Default)]
pub struct RecipeRegistry {
    recipes: AHashMap<RecipeKey, Arc<dyn Recipe>>,
}

impl RecipeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a recipe under its own [`RecipeKey`], replacing any existing entry
    /// for that key and returning the previous recipe if one was present.
    pub fn register(&mut self, recipe: Arc<dyn Recipe>) -> Option<Arc<dyn Recipe>> {
        self.recipes.insert(recipe.key(), recipe)
    }

    /// Look up the recipe for a `(kind, ecosystem)` pair.
    pub fn get(&self, key: &RecipeKey) -> Option<&Arc<dyn Recipe>> {
        self.recipes.get(key)
    }

    /// Report whether a recipe is registered for the given key.
    pub fn contains(&self, key: &RecipeKey) -> bool {
        self.recipes.contains_key(key)
    }

    /// The number of registered recipes.
    pub fn len(&self) -> usize {
        self.recipes.len()
    }

    /// Whether the registry holds no recipes.
    pub fn is_empty(&self) -> bool {
        self.recipes.is_empty()
    }
}

impl std::fmt::Debug for RecipeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipeRegistry")
            .field("recipes", &self.recipes.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_kind_display_matches_lowercase() {
        assert_eq!(RepositoryKind::Proxy.to_string(), "proxy");
        assert_eq!(RepositoryKind::Hosted.to_string(), "hosted");
        assert_eq!(RepositoryKind::Group.to_string(), "group");
    }

    #[test]
    fn repository_kind_from_str_round_trips() {
        for kind in [RepositoryKind::Proxy, RepositoryKind::Hosted, RepositoryKind::Group] {
            let parsed: RepositoryKind = kind.to_string().parse().unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn repository_kind_from_str_is_case_insensitive() {
        assert_eq!("PROXY".parse::<RepositoryKind>().unwrap(), RepositoryKind::Proxy);
        assert_eq!("Group".parse::<RepositoryKind>().unwrap(), RepositoryKind::Group);
    }

    #[test]
    fn repository_kind_from_str_rejects_unknown() {
        let err = "federated".parse::<RepositoryKind>().unwrap_err().to_string();
        assert!(err.contains("unknown repository kind"), "unexpected error: {err}");
    }

    #[test]
    fn recipe_key_display_is_ecosystem_dash_kind() {
        let key = RecipeKey::new(Ecosystem::PyPI, RepositoryKind::Proxy);
        assert_eq!(key.to_string(), "pypi-proxy");
    }

    #[test]
    fn recipe_key_from_str_round_trips() {
        let cases = [
            (Ecosystem::PyPI, RepositoryKind::Proxy),
            (Ecosystem::Npm, RepositoryKind::Hosted),
            (Ecosystem::Cargo, RepositoryKind::Group),
            (Ecosystem::RubyGems, RepositoryKind::Proxy),
        ];
        for (ecosystem, kind) in cases {
            let key = RecipeKey::new(ecosystem, kind);
            let parsed: RecipeKey = key.to_string().parse().unwrap();
            assert_eq!(parsed, key);
        }
    }

    #[test]
    fn recipe_key_from_str_rejects_missing_separator() {
        assert!("pypi".parse::<RecipeKey>().is_err());
    }

    #[test]
    fn repository_id_exposes_inner_str() {
        let id = RepositoryId::new("central");
        assert_eq!(id.as_str(), "central");
        assert_eq!(id.to_string(), "central");
    }

    #[test]
    fn recipe_registry_registers_and_looks_up() {
        struct StubRecipe(RecipeKey);
        impl Recipe for StubRecipe {
            fn key(&self) -> RecipeKey {
                self.0
            }
        }

        let key = RecipeKey::new(Ecosystem::PyPI, RepositoryKind::Proxy);
        let mut registry = RecipeRegistry::new();
        assert!(registry.is_empty());

        let previous = registry.register(Arc::new(StubRecipe(key)));
        assert!(previous.is_none());
        assert_eq!(registry.len(), 1);
        assert!(registry.contains(&key));
        assert_eq!(registry.get(&key).unwrap().key(), key);

        // Registering the same key replaces and returns the prior recipe.
        let replaced = registry.register(Arc::new(StubRecipe(key)));
        assert!(replaced.is_some());
        assert_eq!(registry.len(), 1);
    }
}
