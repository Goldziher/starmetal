//! Universal content model and reference-counted garbage collection (ADR-0020).
//!
//! This module defines the framework-free domain types and the [`ContentStore`] port that back
//! Starmetal's three-level content model:
//!
//! ```text
//! Component (coordinate) -> Asset (path) -> Blob (bytes, keyed by Blake3 digest)
//! ```
//!
//! Ecosystem-specific metadata lives in a JSON `attributes` value at the [`Component`] and
//! [`Asset`] levels, with a generic [`Property`] key/value escape hatch for queryable fields. Blobs
//! are content-addressed by their Blake3 digest so identical bytes across versions, ecosystems, and
//! container layers share a single stored object.
//!
//! The [`ContentStore`] trait is a higher-level metadata and lifecycle port. The low-level
//! [`crate::ports::StoragePort`] (OpenDAL-backed in `starmetal-storage`) remains the byte driver
//! beneath it; `ContentStore` orchestrates that driver and owns the reference table and
//! garbage-collection lifecycle. No relational or storage dependencies live here — the persistent
//! implementation lands in a later stage in a different crate.

use std::time::Duration;

use ahash::AHashMap;
use async_trait::async_trait;
use bytes::Bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;
use crate::package::{Ecosystem, PackageName};

// ---------------------------------------------------------------------------
// Content model domain types
// ---------------------------------------------------------------------------

/// A Blake3 content-address that identifies a [`Blob`] and doubles as its storage key.
///
/// The wrapped string is the lowercase hex Blake3 digest of the blob's bytes (ADR-0004). Because
/// storage is content-addressed, two blobs with equal digests are the same stored object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlobDigest(String);

impl BlobDigest {
    /// Construct a digest from a hex Blake3 string.
    pub fn new(digest: impl Into<String>) -> Self {
        Self(digest.into())
    }

    /// Borrow the digest as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BlobDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for BlobDigest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The byte level of the content model: a content-addressed, deduplicated stored object.
///
/// A blob is keyed by its Blake3 [`digest`](Self::digest). The same bytes referenced from many
/// assets are stored exactly once. `upstream_hashes` preserves checksums advertised by the upstream
/// registry (for example `{"sha256": "abc..."}`), mirroring
/// [`crate::package::ArtifactDigest::upstream_hashes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    /// Blake3 content-address and storage-key identity of this blob.
    pub digest: BlobDigest,
    /// Size of the blob in bytes.
    pub size: u64,
    /// Checksums advertised by the upstream registry, keyed by algorithm name.
    #[serde(default)]
    pub upstream_hashes: AHashMap<String, String>,
    /// MIME content type of the bytes, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// The coordinate level of the content model: an ecosystem-scoped package version.
///
/// A component is the logical `(namespace, name, version)` coordinate within an [`Ecosystem`].
/// `attributes` carries ecosystem-specific metadata as an opaque JSON value (the `attributes`
/// column in ADR-0020), interpreted by the owning ecosystem.
///
/// This type does not derive `Eq` because `attributes` is a [`serde_json::Value`], which is only
/// `PartialEq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Component {
    /// Optional grouping namespace (npm scope, Maven group id, and similar). `None` when the
    /// ecosystem has no namespace concept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Normalized package name.
    pub name: PackageName,
    /// Version string, verbatim as published upstream.
    pub version: String,
    /// Ecosystem this component belongs to.
    pub ecosystem: Ecosystem,
    /// Ecosystem-specific metadata as opaque JSON.
    #[serde(default)]
    pub attributes: Value,
}

/// A stable logical reference to a [`Component`] by its coordinate.
///
/// Used to link an [`Asset`] to its owning component and to identify components in
/// [`ContentStore`] operations without leaking a store-specific row identifier into the domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ComponentRef {
    /// Ecosystem of the referenced component.
    pub ecosystem: Ecosystem,
    /// Optional grouping namespace, matching [`Component::namespace`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Normalized package name.
    pub name: PackageName,
    /// Version string.
    pub version: String,
}

/// The path level of the content model: a named file within a [`Component`], backed by a [`Blob`].
///
/// An asset points at its owning component via [`component_ref`](Self::component_ref). Its link to
/// the underlying blob is recorded separately in the reference table (see
/// [`ContentStore::add_reference`]), which is what makes reference-counted garbage collection
/// possible. `attributes` carries path-level ecosystem metadata as opaque JSON.
///
/// This type does not derive `Eq` because `attributes` is a [`serde_json::Value`], which is only
/// `PartialEq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    /// Path of the asset within its component (for example `pkg-1.0.0-py3-none-any.whl`).
    pub path: String,
    /// Reference to the owning component.
    pub component_ref: ComponentRef,
    /// MIME content type of the asset, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Ecosystem-specific path-level metadata as opaque JSON.
    #[serde(default)]
    pub attributes: Value,
}

/// A stable logical reference to an [`Asset`] by its owning component and path.
///
/// Used as the left-hand side of the `asset -> blob` reference table in [`ContentStore`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetRef {
    /// Owning component of the referenced asset.
    pub component_ref: ComponentRef,
    /// Path of the asset within that component.
    pub path: String,
}

/// A generic queryable key/value property attached to content-model rows.
///
/// This is the escape hatch described in ADR-0020: fields that need to be indexed and queried
/// without a per-ecosystem column live here as flat key/value pairs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Property {
    /// Property key.
    pub key: String,
    /// Property value.
    pub value: String,
}

// ---------------------------------------------------------------------------
// ContentStore port
// ---------------------------------------------------------------------------

/// Higher-level metadata and lifecycle port over content-addressed storage (ADR-0020).
///
/// `ContentStore` owns the three-level content model, the `asset -> blob` reference table, and the
/// garbage-collection lifecycle. It sits above the low-level [`crate::ports::StoragePort`] byte
/// driver, which it uses to persist and remove blob bytes.
///
/// Implementations are held behind `Arc<dyn ContentStore>`, so this trait is object-safe: every
/// method takes `&self` and uses only owned or borrowed arguments.
#[async_trait]
pub trait ContentStore: Send + Sync {
    /// Deduplicating insert of a blob by its Blake3 digest.
    ///
    /// If a blob with the same [`BlobDigest`] already exists, the stored blob is returned and
    /// `data` is not written again. Otherwise the bytes are persisted (via the underlying storage
    /// driver) and the new blob record is created. Identical bytes therefore always resolve to one
    /// stored object.
    async fn get_or_insert_blob(&self, blob: &Blob, data: Bytes) -> Result<Blob>;

    /// Look up a blob by digest, returning `None` if it is not present.
    async fn get_blob(&self, digest: &BlobDigest) -> Result<Option<Blob>>;

    /// Read a blob's bytes, verifying them against its Blake3 digest-key.
    ///
    /// Returns `None` when no blob with `digest` is known to the store. Otherwise the bytes are
    /// fetched via the underlying [`crate::ports::StoragePort`] and re-hashed; because the storage
    /// key *is* the Blake3 digest, a mismatch means on-disk corruption or tampering and yields
    /// [`crate::error::StarmetalError::IntegrityError`].
    async fn read_blob(&self, digest: &BlobDigest) -> Result<Option<Bytes>>;

    /// Insert or update a component by its coordinate.
    async fn upsert_component(&self, component: &Component) -> Result<()>;

    /// Insert or update an asset by its owning component and path.
    async fn upsert_asset(&self, asset: &Asset) -> Result<()>;

    /// Record that `asset` references the blob identified by `digest`.
    ///
    /// This is the increment side of reference counting: it adds a row to the `asset -> blob`
    /// reference table.
    async fn add_reference(&self, asset: &AssetRef, digest: &BlobDigest) -> Result<()>;

    /// Remove the reference from `asset` to the blob identified by `digest`.
    ///
    /// This is the decrement side of reference counting. It does not delete the blob; a blob whose
    /// last reference is removed becomes a garbage-collection candidate.
    async fn remove_reference(&self, asset: &AssetRef, digest: &BlobDigest) -> Result<()>;

    /// Report whether any asset currently references the blob identified by `digest`.
    async fn is_referenced(&self, digest: &BlobDigest) -> Result<bool>;

    /// List blobs that no asset references — the candidate set for garbage collection.
    async fn list_unreferenced_blobs(&self) -> Result<Vec<BlobDigest>>;

    /// Mark an unreferenced blob as a garbage-collection candidate (the first GC stage).
    ///
    /// Marking records intent without removing anything; a marked blob can still be rescued simply
    /// by a new [`add_reference`](Self::add_reference).
    async fn mark_unreferenced(&self, digest: &BlobDigest) -> Result<()>;

    /// Soft-delete a marked blob, starting a `grace` window before it can be hard-deleted.
    ///
    /// The blob's bytes remain recoverable via [`undelete`](Self::undelete) until the grace window
    /// elapses and [`compact`](Self::compact) reclaims it. The grace window guards against races
    /// and publish rollbacks.
    async fn soft_delete(&self, digest: &BlobDigest, grace: Duration) -> Result<()>;

    /// Restore a soft-deleted blob to the active state, cancelling its pending reclaim.
    async fn undelete(&self, digest: &BlobDigest) -> Result<()>;

    /// Hard-delete every soft-deleted blob whose grace window has elapsed.
    ///
    /// This is the final, irreversible GC stage. It returns the digests that were reclaimed so the
    /// caller can reconcile downstream state.
    async fn compact(&self) -> Result<Vec<BlobDigest>>;
}

/// The outcome of one garbage-collection sweep (ADR-0020 Stage 2d).
///
/// Produced by `starmetal_metadata::gc::run_gc_sweep` and returned by
/// [`ContentMaintenance::gc_sweep`]. See that function's documentation for the two-phase
/// mark/soft-delete-then-compact semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcReport {
    /// Number of blobs marked as garbage-collection candidates this sweep.
    pub marked: usize,
    /// Number of blobs soft-deleted this sweep (equal to `marked`; kept as a separate field so the
    /// report reads as a lifecycle trace rather than a single count).
    pub soft_deleted: usize,
    /// Digests hard-deleted (bytes and metadata reclaimed) by this sweep's compact step.
    pub reclaimed: Vec<BlobDigest>,
}

/// The outcome of applying a [`RetentionPolicy`] (ADR-0020 Stage 2c): the versions it deleted.
///
/// Produced by `PostgresContentStore::apply_retention` (one component family) and aggregated
/// across every family by [`ContentMaintenance::retention_sweep`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionOutcome {
    /// Version strings that were deleted, in no particular order.
    pub deleted: Vec<String>,
}

// ---------------------------------------------------------------------------
// Retention policy value types
// ---------------------------------------------------------------------------

/// A single logical retention rule (ADR-0020).
///
/// Retention is decoupled from garbage collection: these rules decide which component and asset
/// rows to *delete*, after which reference-counted GC physically reclaims any blobs that become
/// unreferenced. This enum is the typed, config-facing description of a rule only — it carries no
/// evaluation engine.
///
/// The serde representation is internally tagged on a `strategy` field, for example:
///
/// ```json
/// { "strategy": "keep-latest", "count": 10 }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "strategy", rename_all = "kebab-case")]
pub enum RetentionRule {
    /// Keep only the N most recent versions of a component.
    KeepLatest {
        /// Number of latest versions to retain.
        count: usize,
    },
    /// Retain versions downloaded within the trailing window; delete the rest.
    LastDownloaded {
        /// Retention window, in days, measured from the last download.
        within_days: u32,
    },
    /// Retain versions updated within the trailing window; delete the rest.
    LastUpdated {
        /// Retention window, in days, measured from the last update.
        within_days: u32,
    },
    /// Retain versions whose version string matches the given regular expression.
    #[serde(rename = "regex")]
    MatchesRegex {
        /// Regular expression evaluated against the version string.
        pattern: String,
    },
    /// Select versions by their prerelease status.
    IsPrerelease {
        /// When `true`, the rule targets prerelease versions; when `false`, stable versions.
        prerelease: bool,
    },
}

/// An ordered set of [`RetentionRule`]s applied together as a retention policy.
///
/// This is a plain configuration container; it holds no evaluation logic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RetentionPolicy {
    /// Rules that make up this policy, evaluated by a later stage.
    #[serde(default)]
    pub rules: Vec<RetentionRule>,
}

// ---------------------------------------------------------------------------
// Content maintenance port
// ---------------------------------------------------------------------------

/// Scheduled metadata maintenance over a [`ContentStore`] (ADR-0020 Stages 2c/2d): the
/// retention-then-garbage-collection lifecycle, driven by a runtime scheduler rather than a
/// request path.
///
/// Kept separate from [`ContentStore`] itself (which is the low-level metadata/lifecycle port)
/// so a runtime can hold a single `Arc<dyn ContentMaintenance>` handle for its background sweeps
/// without needing the full `ContentStore` surface. The trait is object-safe.
#[async_trait]
pub trait ContentMaintenance: Send + Sync {
    /// Run one garbage-collection sweep: mark and soft-delete every unreferenced blob, then
    /// compact (hard-delete) whatever has already passed its grace window.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying [`ContentStore`] sweep fails.
    async fn gc_sweep(&self) -> Result<GcReport>;

    /// Apply the configured retention policy across every known component family, deleting the
    /// union of what each family's rule evaluation selects.
    ///
    /// # Errors
    ///
    /// Returns an error only on a systemic failure (e.g. the store is unreadable); a single
    /// family that cannot be evaluated should be skipped rather than aborting the whole sweep.
    async fn retention_sweep(&self) -> Result<RetentionOutcome>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(rule: &RetentionRule) -> RetentionRule {
        let json = serde_json::to_string(rule).expect("serialize retention rule");
        serde_json::from_str(&json).expect("deserialize retention rule")
    }

    #[test]
    fn keep_latest_serializes_with_tagged_strategy() {
        let rule = RetentionRule::KeepLatest { count: 10 };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json, serde_json::json!({ "strategy": "keep-latest", "count": 10 }));
        assert_eq!(round_trip(&rule), rule);
    }

    #[test]
    fn last_downloaded_uses_kebab_case_tag() {
        let rule = RetentionRule::LastDownloaded { within_days: 30 };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "strategy": "last-downloaded", "within_days": 30 })
        );
        assert_eq!(round_trip(&rule), rule);
    }

    #[test]
    fn last_updated_uses_kebab_case_tag() {
        let rule = RetentionRule::LastUpdated { within_days: 90 };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "strategy": "last-updated", "within_days": 90 })
        );
        assert_eq!(round_trip(&rule), rule);
    }

    #[test]
    fn regex_rule_serializes_with_regex_tag() {
        let rule = RetentionRule::MatchesRegex {
            pattern: r"^\d+\.\d+\.\d+$".to_string(),
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "strategy": "regex", "pattern": r"^\d+\.\d+\.\d+$" })
        );
        assert_eq!(round_trip(&rule), rule);
    }

    #[test]
    fn is_prerelease_round_trips() {
        let rule = RetentionRule::IsPrerelease { prerelease: true };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "strategy": "is-prerelease", "prerelease": true })
        );
        assert_eq!(round_trip(&rule), rule);
    }

    #[test]
    fn retention_policy_defaults_to_no_rules() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.rules.len(), 0);
        let json = serde_json::to_value(&policy).unwrap();
        assert_eq!(json, serde_json::json!({ "rules": [] }));
    }

    #[test]
    fn blob_digest_exposes_inner_string() {
        let digest = BlobDigest::new("abc123");
        assert_eq!(digest.as_str(), "abc123");
        assert_eq!(digest.to_string(), "abc123");
    }

    #[test]
    fn gc_report_serializes_with_expected_fields() {
        let report = GcReport {
            marked: 2,
            soft_deleted: 2,
            reclaimed: vec![BlobDigest::new("a".repeat(64))],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "marked": 2,
                "soft_deleted": 2,
                "reclaimed": ["a".repeat(64)],
            })
        );
        let roundtripped: GcReport = serde_json::from_value(json).unwrap();
        assert_eq!(roundtripped, report);
    }

    #[test]
    fn retention_outcome_serializes_with_expected_fields() {
        let outcome = RetentionOutcome {
            deleted: vec!["1.0.0".to_string(), "1.0.1".to_string()],
        };
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json, serde_json::json!({ "deleted": ["1.0.0", "1.0.1"] }));
        let roundtripped: RetentionOutcome = serde_json::from_value(json).unwrap();
        assert_eq!(roundtripped, outcome);
    }

    /// A trivial in-memory [`ContentMaintenance`] impl, asserting the trait is object-safe and
    /// usable behind `Arc<dyn ContentMaintenance>` the way a runtime holds it.
    struct StubMaintenance;

    #[async_trait]
    impl ContentMaintenance for StubMaintenance {
        async fn gc_sweep(&self) -> Result<GcReport> {
            Ok(GcReport {
                marked: 0,
                soft_deleted: 0,
                reclaimed: Vec::new(),
            })
        }

        async fn retention_sweep(&self) -> Result<RetentionOutcome> {
            Ok(RetentionOutcome { deleted: Vec::new() })
        }
    }

    #[test]
    fn content_maintenance_is_object_safe() {
        // Core carries no async runtime dependency, so this only proves the trait compiles behind
        // a trait object (the property a runtime relies on to hold `Arc<dyn ContentMaintenance>`)
        // rather than driving the futures to completion.
        let maintenance: std::sync::Arc<dyn ContentMaintenance> = std::sync::Arc::new(StubMaintenance);
        let _gc_future = maintenance.gc_sweep();
        let _retention_future = maintenance.retention_sweep();
    }
}
