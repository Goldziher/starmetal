mod gate;
mod signing;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ahash::AHashMap;
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bytes::Bytes;
use chrono::{SecondsFormat, Utc};
use sha2::Digest;
use starmetal_core::attestation;
use starmetal_core::content::{Asset, AssetRef, Blob, BlobDigest, Component, ComponentRef, ContentStore};
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::integrity;
use starmetal_core::package::{
    ArtifactDigest, ArtifactId, Ecosystem, PackageName, StorageKey, VersionInfo, VersionMetadata,
    decode_storage_segment, validate_storage_segment,
};
use starmetal_core::policy::PolicyConfig;
use starmetal_core::ports::{PackageService, PublishingService, StatisticsService, StoragePort, UpstreamClient};
use starmetal_core::publishing::{
    ProtocolMetadata, PublishMode, PublishRecord, PublishRequest, PublishResult, PublishSource, PublishedArtifact,
    YankRequest,
};
use starmetal_core::sbom::{self, SbomHash, SbomSubject};
use starmetal_core::signing::{SignatureSource, SignatureStatement};
use starmetal_core::statistics::{EcosystemStatistics, StatisticsSnapshot};
use starmetal_core::supply_chain::{
    IngestQuarantine, PolicyReason, QuarantineOrigin, QuarantineRecord, QuarantineState, SbomFormat, ScanTarget,
    Scanner, Verifier, evaluate_scan_report,
};

use gate::{PersistedScanReport, QUARANTINE_PREFIX, SBOM_PREFIX, SCAN_REPORT_PREFIX};
pub use signing::SigningService;
use signing::StatementInput;

/// The SLSA builder identity Starmetal stamps into the provenance attestations it produces.
const STARMETAL_BUILDER_ID: &str = "https://starmetal.dev";

/// Pull-through caching implementation of `PackageService`.
///
/// Sits between protocol adapters (inbound) and storage/upstream (outbound),
/// applying policy checks and integrity verification on cache misses.
pub struct CachingPackageService {
    storage: Arc<dyn StoragePort>,
    upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
    policy: PolicyConfig,
    signing: Option<Arc<SigningService>>,
    statistics: Mutex<StatisticsSnapshot>,
    content_store: Option<Arc<dyn ContentStore>>,
    /// Optional vulnerability scanner (ADR-0024). When present, publishes are gated at ingest:
    /// each artifact is scanned and denied when a finding exceeds `policy.max_vuln_severity`.
    scanner: Option<Arc<dyn Scanner>>,
    /// When true (and a scanner is attached), the same vulnerability gate is enforced at serve:
    /// `get_artifact` loads the artifact's stored scan report (scanning on demand and caching it
    /// when absent) and denies serving when a finding exceeds `policy.max_vuln_severity`.
    enforce_on_serve: bool,
    /// When true, a serve-time gate block records a digest-keyed quarantine hold (recoverable via
    /// operator promote/reject) instead of a terminal deny. Off by default (blocks are hard denials).
    quarantine: bool,
    /// When true, a blocked hosted publish is held for operator review instead of hard-denied: the
    /// uploaded bytes are parked under `_starmetal/held/<blake3>` off the live path and an
    /// ingest-origin quarantine record is written. Promote completes the deferred publish; reject
    /// purges the held bytes. Off by default (a blocked publish is denied).
    ingest_quarantine: bool,
    /// SBOM formats generated for each artifact on publish (ADR-0024). Empty (the default) disables
    /// SBOM generation; otherwise each published artifact gets one digest-keyed SBOM sidecar per
    /// format. Independent of the scanner — SBOMs are generated from the publish request.
    sbom_formats: Vec<SbomFormat>,
    /// Require a valid Starmetal signature to serve/publish (ADR-0024). Gated by reusing the same
    /// `verify_artifact_signature` used for signing verify-on-read (no second read), mapping a
    /// failure to a `MissingSignature` denial. Off by default.
    require_signature: bool,
    /// Require a valid Starmetal provenance attestation to serve/publish (ADR-0024). Off by default.
    require_provenance: bool,
    /// When true (and signing is configured), publishes and cache-fills emit a DSSE-signed
    /// in-toto/SLSA provenance attestation alongside the artifact, so the provenance gate has one to
    /// verify. Off by default.
    emit_provenance: bool,
    /// External signature/provenance verifier override (ADR-0024). When attached, it *replaces* the
    /// built-in own-graph verification at the gate — the seam a cosign/sigstore backend plugs into.
    /// Absent by default (the built-in own-graph verifier is used when `require_*` is set).
    verifier: Option<Arc<dyn Verifier>>,
    /// Named per-coordinate locks serializing concurrent publishes of the same
    /// `ecosystem/name/version`. `publish_package` prunes an entry once its guard drops and no other
    /// publish still holds a clone of the lock (see `prune_publish_lock`), so the map only grows with
    /// coordinates that are currently being published, not with every coordinate ever published.
    publish_locks: Mutex<AHashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

struct StoredObjectSignatureCheck<'a> {
    ecosystem: Ecosystem,
    name: &'a PackageName,
    version: &'a str,
    filename: Option<&'a str>,
    storage_key: &'a str,
    data: &'a Bytes,
    /// The signature sources this check accepts. The sidecar is read and verified once; the
    /// statement's declared source must be one of these (an artifact may have been signed either
    /// locally or as an upstream cache-fill, so both are accepted without re-reading).
    allowed_sources: &'a [SignatureSource],
}

struct StagedWrite {
    key: String,
    previous: Option<Bytes>,
}

/// Storage key prefix under which ingest-quarantined (held) publish bytes and their reconstruction
/// manifest are parked, off the live artifact path, keyed by the artifact's blake3 digest. Promote
/// replays the manifest through the real publish path; reject purges these keys.
const HELD_PREFIX: &str = "_starmetal/held/";

/// RAII guard holding a publish coordinate's lock. On drop it releases the lock and prunes the
/// coordinate's entry from `publish_locks`, so the map is cleaned up on *every* exit path of
/// `publish_package` — success or early-return error — not just the happy path. Without this, a
/// publish that fails after acquiring the lock (duplicate version, refused shadowing, a blocking
/// scan, a rollback) would leak its map entry, reintroducing the unbounded growth this prunes.
struct PublishLockGuard<'a> {
    service: &'a CachingPackageService,
    key: String,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for PublishLockGuard<'_> {
    fn drop(&mut self) {
        // Release the coordinate lock first so this guard's `Arc` clone is gone before the strong-count
        // check; `prune_publish_lock` then removes the entry iff the map is its sole remaining holder.
        self.guard = None;
        self.service.prune_publish_lock(&self.key);
    }
}

/// Outcome of the ingest scan gate for a publish request under ingest-quarantine mode.
enum ScanGateOutcome {
    /// Every artifact scanned within the threshold; carries the passing reports to persist.
    Passed(Vec<(String, PersistedScanReport)>),
    /// An artifact exceeded the threshold and the publish is to be held for review (ADR-0024).
    Held(IngestHold),
}

/// The blocking finding that triggers an ingest-quarantine hold: which artifact blocked, its blake3
/// (the digest that keys the held bytes, manifest, and quarantine record), and the typed reason.
struct IngestHold {
    blocking_artifact: ArtifactId,
    blocking_blake3: String,
    reason_code: PolicyReason,
    reason: String,
}

/// On-disk manifest for an ingest-quarantined publish, addressed by the blocking artifact's blake3.
/// Captures every field of the deferred [`PublishRequest`] except the artifact bytes themselves
/// (which live at `_starmetal/held/<blake3>`, one per artifact), so promotion can reconstruct the
/// request faithfully — preserving license, protocol metadata, and every artifact.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct HeldPublish {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    license: Option<String>,
    yanked: bool,
    listed: bool,
    allow_overwrite: bool,
    allow_shadowing: bool,
    protocol_metadata: ProtocolMetadata,
    artifacts: Vec<HeldArtifact>,
}

/// One artifact within a [`HeldPublish`] manifest: its filename, the blake3 that keys its held
/// bytes, and the upstream hashes to restore on the reconstructed [`PublishedArtifact`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct HeldArtifact {
    filename: String,
    blake3: String,
    upstream_hashes: AHashMap<String, String>,
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
            signing: None,
            statistics: Mutex::new(StatisticsSnapshot::default()),
            content_store: None,
            scanner: None,
            enforce_on_serve: false,
            quarantine: false,
            ingest_quarantine: false,
            sbom_formats: Vec::new(),
            require_signature: false,
            require_provenance: false,
            emit_provenance: false,
            verifier: None,
            publish_locks: Mutex::new(AHashMap::new()),
        }
    }

    pub fn new_with_signing(
        storage: Arc<dyn StoragePort>,
        upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
        policy: PolicyConfig,
        signing: Option<SigningService>,
    ) -> Self {
        Self {
            storage,
            upstream_clients,
            policy,
            signing: signing.map(Arc::new),
            statistics: Mutex::new(StatisticsSnapshot::default()),
            content_store: None,
            scanner: None,
            enforce_on_serve: false,
            quarantine: false,
            ingest_quarantine: false,
            sbom_formats: Vec::new(),
            require_signature: false,
            require_provenance: false,
            emit_provenance: false,
            verifier: None,
            publish_locks: Mutex::new(AHashMap::new()),
        }
    }

    /// Attach a content-addressed metadata store; publishes then also record the ADR-0020 content
    /// model (component -> asset -> blob) with cross-ecosystem blob dedup. Absent by default.
    pub fn with_content_store(mut self, content_store: Arc<dyn ContentStore>) -> Self {
        self.content_store = Some(content_store);
        self
    }

    /// Attach a vulnerability scanner (ADR-0024). Publishes are then gated at ingest: each artifact
    /// is scanned and the publish is denied when a finding exceeds `policy.max_vuln_severity`.
    /// Absent by default (the publish path performs no scanning).
    pub fn with_scanner(mut self, scanner: Arc<dyn Scanner>) -> Self {
        self.scanner = Some(scanner);
        self
    }

    /// Enable (or disable) serve-time vulnerability enforcement. When enabled and a scanner is
    /// attached, `get_artifact` consults each artifact's stored scan report — scanning on demand and
    /// caching the report when absent — and denies serving a finding that exceeds the threshold.
    /// Off by default, so serving is unchanged until an operator opts in.
    pub fn enforce_scan_on_serve(mut self, enabled: bool) -> Self {
        self.enforce_on_serve = enabled;
        self
    }

    /// Enable (or disable) quarantine mode. When enabled, a serve-time gate block records a
    /// recoverable quarantine hold (an operator can later promote or reject the artifact) instead of a
    /// terminal deny. Off by default, so a blocked artifact is hard-denied unless an operator opts in.
    pub fn with_quarantine(mut self, enabled: bool) -> Self {
        self.quarantine = enabled;
        self
    }

    /// Enable (or disable) ingest quarantine mode (ADR-0024). When enabled, a hosted publish blocked
    /// by the ingest scan gate is held for operator review — its bytes parked off the live path and
    /// an ingest-origin quarantine record written — instead of hard-denied. Off by default, so a
    /// blocked publish is denied unless an operator opts in.
    pub fn with_ingest_quarantine(mut self, enabled: bool) -> Self {
        self.ingest_quarantine = enabled;
        self
    }

    /// Enable SBOM generation for the given formats (ADR-0024). Each published artifact then gets one
    /// digest-keyed SBOM sidecar per format. An empty list (the default) disables generation.
    pub fn with_sbom_formats(mut self, formats: Vec<SbomFormat>) -> Self {
        self.sbom_formats = formats;
        self
    }

    /// Require a valid signature to serve/publish (ADR-0024). The built-in own-graph gate reuses
    /// `verify_artifact_signature`; enabling this also suppresses the redundant signing verify-on-read
    /// so an artifact's signature is verified exactly once. Off by default.
    pub fn require_signature(mut self, enabled: bool) -> Self {
        self.require_signature = enabled;
        self
    }

    /// Require a valid provenance attestation to serve/publish (ADR-0024). Off by default.
    pub fn require_provenance(mut self, enabled: bool) -> Self {
        self.require_provenance = enabled;
        self
    }

    /// Enable (or disable) provenance-attestation emission. When enabled and signing is configured,
    /// publishes and cache-fills emit a signed in-toto/SLSA attestation. Off by default.
    pub fn emit_provenance(mut self, enabled: bool) -> Self {
        self.emit_provenance = enabled;
        self
    }

    /// Attach an external signature/provenance verifier that replaces the built-in own-graph gate
    /// (ADR-0024) — the seam for a cosign/sigstore backend. Absent by default.
    pub fn with_verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Storage key for an artifact's quarantine record, addressed by its blake3 digest.
    pub(in crate::service) fn quarantine_record_key(blake3: &str) -> String {
        format!("{QUARANTINE_PREFIX}{blake3}.json")
    }

    /// Storage key for one held (ingest-quarantined) artifact's raw bytes, addressed by its blake3.
    fn held_bytes_key(blake3: &str) -> String {
        format!("{HELD_PREFIX}{blake3}")
    }

    /// Storage key for the held-publish manifest, addressed by the *blocking* artifact's blake3 (the
    /// digest that also keys the quarantine record). The manifest carries everything needed to
    /// replay the deferred publish on promotion.
    fn held_manifest_key(blocking_blake3: &str) -> String {
        format!("{HELD_PREFIX}{blocking_blake3}.manifest.json")
    }

    /// Storage key for an artifact's cached scan report, addressed by the artifact's blake3 digest so
    /// identical bytes (across ecosystems/coordinates) share a single report ("scan once").
    pub(in crate::service) fn scan_report_key(blake3: &str) -> String {
        format!("{SCAN_REPORT_PREFIX}{blake3}.json")
    }

    /// Storage key for an artifact's SBOM document in `format`, addressed by the artifact's validated
    /// coordinate storage key (ecosystem/name/version/filename) — *not* its content digest. An SBOM
    /// embeds coordinate identity and license, so two coordinates sharing bytes must not collide on
    /// one document; coordinate-keying also inherits the artifact key's traversal validation.
    pub(in crate::service) fn sbom_key(artifact_key: &str, format: SbomFormat) -> String {
        format!("{SBOM_PREFIX}{artifact_key}.{format}.json")
    }

    /// Build the SBOM subject for one published artifact: the package coordinate, its declared
    /// license, and its content hashes (blake3 plus any upstream hashes, sorted for determinism).
    fn sbom_subject(request: &PublishRequest, artifact: &PublishedArtifact, blake3: &str) -> SbomSubject {
        let mut hashes = vec![SbomHash {
            algorithm: "BLAKE3".to_string(),
            value: blake3.to_string(),
        }];
        let mut upstream: Vec<SbomHash> = artifact
            .upstream_hashes
            .iter()
            .filter_map(|(algorithm, value)| {
                cyclonedx_hash_algorithm(algorithm).map(|label| SbomHash {
                    algorithm: label.to_string(),
                    value: value.clone(),
                })
            })
            .collect();
        upstream.sort_by(|left, right| left.algorithm.cmp(&right.algorithm));
        hashes.extend(upstream);

        SbomSubject {
            ecosystem: request.ecosystem,
            name: request.name.as_str().to_string(),
            version: request.version.clone(),
            license: request.license.clone(),
            hashes,
            // Per-ecosystem dependency enumeration from protocol metadata is a separate concern; the
            // generator is dependency-ready and this list stays empty until a caller supplies one.
            dependencies: Vec::new(),
        }
    }

    /// Generate and stage one SBOM sidecar per configured format for a published artifact. A no-op
    /// when SBOM generation is disabled (`sbom_formats` empty). Staged via `put_and_track` so a
    /// publish rollback removes the documents.
    async fn store_sbom_documents(
        &self,
        request: &PublishRequest,
        artifact: &PublishedArtifact,
        blake3: &str,
        artifact_key: &str,
        created_at: &str,
        staged_writes: &mut Vec<StagedWrite>,
    ) -> Result<()> {
        if self.sbom_formats.is_empty() {
            return Ok(());
        }
        let subject = Self::sbom_subject(request, artifact, blake3);
        for format in &self.sbom_formats {
            let document = sbom::generate(&subject, *format, created_at);
            let bytes = Bytes::from(serde_json::to_vec(&document)?);
            self.put_and_track(&Self::sbom_key(artifact_key, *format), bytes, staged_writes)
                .await?;
        }
        Ok(())
    }

    /// The `publish_locks` map key for a single `ecosystem/name/version` publish coordinate. Shared
    /// by `acquire_publish_lock` (to find-or-insert the coordinate's lock) and `prune_publish_lock`
    /// (to remove it once uncontended), so both agree on identity for the same coordinate.
    fn publish_lock_key(ecosystem: Ecosystem, name: &PackageName, version: &str) -> String {
        format!("{ecosystem}/{}/{version}", name.as_str())
    }

    /// Acquire an owned lock scoped to a single `ecosystem/name/version` publish coordinate,
    /// serializing concurrent publishes that target the same version.
    async fn acquire_publish_lock(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> PublishLockGuard<'_> {
        let key = Self::publish_lock_key(ecosystem, name, version);
        let lock = {
            // A poisoned lock only means some other publish panicked while holding it; the guarded
            // value is just the per-coordinate lock map, so recovering it is safe (matches the
            // statistics mutex handling elsewhere in this file).
            let mut locks = self
                .publish_locks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(
                locks
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let guard = lock.lock_owned().await;
        PublishLockGuard {
            service: self,
            key,
            guard: Some(guard),
        }
    }

    /// Remove a coordinate's publish lock from the map once it is no longer contended.
    ///
    /// Race-free by construction: the emptiness check (`Arc::strong_count(&lock) == 1`) and the
    /// removal both happen while holding the same `std::sync::Mutex` that guards the map, and
    /// `acquire_publish_lock` only ever clones the `Arc` out of the map while holding that same
    /// mutex. So if the strong count is 1 here, no other task can be mid-clone of this entry — the
    /// map is provably the sole remaining holder — and the removal cannot race a concurrent publish
    /// that is about to reuse the coordinate (it would either see the entry before this removal, or
    /// find it absent and insert a fresh lock after).
    fn prune_publish_lock(&self, key: &str) {
        let mut locks = self
            .publish_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lock) = locks.get(key)
            && Arc::strong_count(lock) == 1
        {
            locks.remove(key);
        }
    }

    /// Vulnerability gate (ADR-0024) for a publish request: when a scanner is attached, scan each
    /// artifact and block the publish if a finding exceeds `policy.max_vuln_severity`. A scan that
    /// cannot complete (transport failure) propagates as an error — the publish fails closed.
    ///
    /// A blocking finding is resolved by mode: with ingest quarantine off it returns a
    /// `PolicyViolation` error (a hard deny, unchanged); with it on it returns
    /// [`ScanGateOutcome::Held`] so the caller parks the publish for review. Returns
    /// [`ScanGateOutcome::Passed`] (empty when no scanner is attached) when every artifact is within
    /// the threshold.
    ///
    /// `digests` must be index-aligned with `request.artifacts` (the caller's precomputed blake3
    /// hashes), so each passing report is paired with its digest without re-hashing the artifact.
    async fn scan_artifacts_for_publish(
        &self,
        request: &PublishRequest,
        digests: &[String],
    ) -> Result<ScanGateOutcome> {
        let Some(scanner) = &self.scanner else {
            return Ok(ScanGateOutcome::Passed(Vec::new()));
        };

        let mut scan_reports = Vec::with_capacity(request.artifacts.len());
        for (artifact, blake3) in request.artifacts.iter().zip(digests) {
            let artifact_id = ArtifactId {
                ecosystem: request.ecosystem,
                name: request.name.clone(),
                version: request.version.clone(),
                filename: artifact.filename.clone(),
            };
            let report = scanner.scan(ScanTarget::new(&artifact_id, &artifact.data)).await?;
            let decision = evaluate_scan_report(&report, self.policy.max_vuln_severity);
            if decision.blocks_serving() && !self.coordinate_is_promoted(&artifact_id, blake3).await? {
                let reason = decision
                    .reason()
                    .unwrap_or("vulnerability policy violation")
                    .to_string();
                if !self.ingest_quarantine {
                    return Err(StarmetalError::PolicyViolation(reason));
                }
                return Ok(ScanGateOutcome::Held(IngestHold {
                    blocking_artifact: artifact_id,
                    blocking_blake3: blake3.clone(),
                    reason_code: decision.reason_code().unwrap_or(PolicyReason::VulnSeverityExceeded),
                    reason,
                }));
            }
            scan_reports.push((
                blake3.clone(),
                PersistedScanReport {
                    artifact: artifact_id,
                    report,
                },
            ));
        }
        Ok(ScanGateOutcome::Passed(scan_reports))
    }

    async fn store_content_model(
        &self,
        content_store: &dyn ContentStore,
        request: &PublishRequest,
        _metadata: &VersionMetadata,
    ) -> Result<()> {
        let component_ref = ComponentRef {
            ecosystem: request.ecosystem,
            namespace: None,
            name: request.name.clone(),
            version: request.version.clone(),
        };
        content_store
            .upsert_component(&Component {
                namespace: None,
                name: request.name.clone(),
                version: request.version.clone(),
                ecosystem: request.ecosystem,
                attributes: serde_json::json!({}),
            })
            .await?;
        for artifact in &request.artifacts {
            content_store
                .upsert_asset(&Asset {
                    path: artifact.filename.clone(),
                    component_ref: component_ref.clone(),
                    content_type: None,
                    attributes: serde_json::json!({}),
                })
                .await?;
            let blob = Blob {
                digest: BlobDigest::new(integrity::blake3_hex(&artifact.data)),
                size: artifact.data.len() as u64,
                upstream_hashes: artifact.upstream_hashes.clone(),
                content_type: None,
            };
            content_store.get_or_insert_blob(&blob, artifact.data.clone()).await?;
            // If adding the reference below fails, the blob inserted just above is left
            // unreferenced. No compensating delete is wired here: an unreferenced blob is simply a
            // GC candidate, reclaimed by the Stage-2d GC sweep (self-healing).
            content_store
                .add_reference(
                    &AssetRef {
                        component_ref: component_ref.clone(),
                        path: artifact.filename.clone(),
                    },
                    &blob.digest,
                )
                .await?;
        }
        Ok(())
    }

    fn upstream(&self, ecosystem: Ecosystem) -> Result<&Arc<dyn UpstreamClient>> {
        self.upstream_clients
            .get(&ecosystem)
            .ok_or_else(|| StarmetalError::Config(format!("no upstream configured for {ecosystem}")))
    }

    fn check_package_allowed(&self, name: &PackageName) -> Result<()> {
        if self.policy.blocked_packages.iter().any(|b| b == name.as_str()) {
            return Err(StarmetalError::PolicyViolation(format!("package {name} is blocked")));
        }
        Ok(())
    }

    fn verify_upstream_hash(data: &Bytes, digest: &ArtifactDigest) -> Result<()> {
        if let Some(integrity) = digest.upstream_hashes.get("integrity") {
            return verify_subresource_integrity(data, integrity);
        }

        if let Some(expected) = digest.upstream_hashes.get("sha256") {
            let actual = hex::encode(sha2::Sha256::digest(data));
            return verify_hex_digest("sha256", expected, &actual);
        }

        if let Some(expected) = digest.upstream_hashes.get("sha1") {
            let actual = hex::encode(sha1::Sha1::digest(data));
            return verify_hex_digest("sha1", expected, &actual);
        }

        if let Some(expected) = digest.upstream_hashes.get("sha512") {
            let actual = base64::Engine::encode(&BASE64_STANDARD, sha2::Sha512::digest(data));
            return verify_hex_digest("sha512", expected, &actual);
        }

        Ok(())
    }

    fn versions_key(ecosystem: Ecosystem, name: &PackageName) -> Result<String> {
        let name = name.storage_segment()?;
        let ecosystem = ecosystem.to_string();
        Ok(StorageKey::from_segments(&[&ecosystem, &name, "_versions.json"])?.into_string())
    }

    fn metadata_key(ecosystem: Ecosystem, name: &PackageName, version: &str) -> Result<String> {
        let name = name.storage_segment()?;
        validate_storage_segment("version", version)?;
        let ecosystem = ecosystem.to_string();
        Ok(StorageKey::from_segments(&[&ecosystem, &name, version, "_metadata.json"])?.into_string())
    }

    fn raw_upstream_key(ecosystem: Ecosystem, name: &PackageName) -> Result<String> {
        let name = name.storage_segment()?;
        let ecosystem = ecosystem.to_string();
        Ok(StorageKey::from_segments(&[&ecosystem, &name, "_raw_upstream"])?.into_string())
    }

    fn published_record_key(ecosystem: Ecosystem, name: &PackageName, version: &str) -> Result<String> {
        let name = name.storage_segment()?;
        validate_storage_segment("version", version)?;
        let ecosystem = ecosystem.to_string();
        Ok(
            StorageKey::from_segments(&["_starmetal", "published", &ecosystem, &name, version, "record.json"])?
                .into_string(),
        )
    }

    fn published_legacy_manifest_key(ecosystem: Ecosystem, name: &PackageName, version: &str) -> Result<String> {
        let name = name.storage_segment()?;
        validate_storage_segment("version", version)?;
        let ecosystem = ecosystem.to_string();
        let manifest = format!("{version}.json");
        validate_storage_segment("published manifest filename", &manifest)?;
        Ok(StorageKey::from_segments(&["_starmetal", "published", &ecosystem, &name, &manifest])?.into_string())
    }

    fn signature_sidecar_key(storage_key: &str) -> String {
        format!("{storage_key}.starmetal.sig.json")
    }

    /// Storage key for an artifact's provenance attestation sidecar (a DSSE-wrapped in-toto/SLSA
    /// statement), addressed relative to the artifact's storage key.
    pub(in crate::service) fn attestation_sidecar_key(storage_key: &str) -> String {
        format!("{storage_key}.intoto.att.json")
    }

    fn signature_bundle_key(ecosystem: Ecosystem, name: &PackageName, version: &str, filename: &str) -> Result<String> {
        let name = name.storage_segment()?;
        validate_storage_segment("version", version)?;
        let filename = crate_safe_signature_filename(filename)?;
        let ecosystem = ecosystem.to_string();
        Ok(
            StorageKey::from_segments(&["_starmetal", "signatures", &ecosystem, &name, version, &filename])?
                .into_string(),
        )
    }

    async fn put_and_track(&self, key: &str, data: Bytes, staged_writes: &mut Vec<StagedWrite>) -> Result<()> {
        if !staged_writes.iter().any(|write| write.key == key) {
            let previous = self.storage.get(key).await?;
            staged_writes.push(StagedWrite {
                key: key.to_string(),
                previous,
            });
        }
        self.storage.put(key, data).await?;
        Ok(())
    }

    async fn rollback_staged_writes(&self, writes: &[StagedWrite]) {
        for write in writes.iter().rev() {
            let result = if let Some(previous) = &write.previous {
                self.storage.put(&write.key, previous.clone()).await
            } else {
                self.storage.delete(&write.key).await
            };
            if let Err(err) = result {
                tracing::warn!(
                    key = %write.key,
                    error = %err,
                    "failed to roll back staged storage write"
                );
            }
        }
    }

    async fn sign_and_store_statement(
        &self,
        statement: SignatureStatement,
        sidecar_key: &str,
        bundle_key: &str,
        staged_writes: &mut Vec<StagedWrite>,
    ) -> Result<()> {
        let Some(signing) = &self.signing else {
            return Ok(());
        };
        let envelope = signing.sign_statement(statement)?;
        let bytes = Bytes::from(serde_json::to_vec(&envelope)?);
        self.put_and_track(sidecar_key, bytes.clone(), staged_writes).await?;
        self.put_and_track(bundle_key, bytes, staged_writes).await
    }

    /// Produce and store a DSSE-signed in-toto/SLSA provenance attestation for an artifact, keyed by
    /// its storage key (ADR-0024). A no-op when signing is not configured (nothing can be signed).
    /// Staged via `put_and_track`, so a publish rollback removes it.
    async fn sign_and_store_attestation(
        &self,
        ecosystem: Ecosystem,
        package: &PackageName,
        storage_key: &str,
        blake3: &str,
        built_at: &str,
        staged_writes: &mut Vec<StagedWrite>,
    ) -> Result<()> {
        let Some(signing) = &self.signing else {
            return Ok(());
        };
        let statement = attestation::provenance_statement(storage_key, blake3, STARMETAL_BUILDER_ID, built_at);
        let payload = serde_json::to_vec(&statement)?;
        let envelope = signing.sign_attestation(ecosystem, package, &payload)?;
        let bytes = Bytes::from(serde_json::to_vec(&envelope)?);
        self.put_and_track(&Self::attestation_sidecar_key(storage_key), bytes, staged_writes)
            .await
    }

    fn verify_on_read(&self) -> bool {
        self.signing.as_ref().is_some_and(|signing| signing.verify_on_read())
    }

    /// Whether the supply-chain gate (`enforce_verification`) already verifies the signature — the
    /// built-in `require_signature` path or any attached external verifier — so signing
    /// verify-on-read need not repeat it.
    fn gates_signature(&self) -> bool {
        self.require_signature || self.verifier.is_some()
    }

    async fn verify_storage_signature(&self, check: StoredObjectSignatureCheck<'_>) -> Result<()> {
        let Some(signing) = &self.signing else {
            return Ok(());
        };
        let sidecar_key = Self::signature_sidecar_key(check.storage_key);
        let envelope_bytes = self
            .storage
            .get(&sidecar_key)
            .await?
            .ok_or_else(|| StarmetalError::IntegrityError {
                expected: format!("signature sidecar {sidecar_key}"),
                actual: "missing signature sidecar".to_string(),
            })?;
        let statement = signing.verify_envelope(&envelope_bytes)?;
        let actual = integrity::blake3_hex(check.data);
        if statement.storage_key != check.storage_key
            || statement.ecosystem != check.ecosystem
            || statement.package != *check.name
            || statement.version != check.version
            || statement.filename.as_deref() != check.filename
            || statement.blake3 != actual
            || statement.size != check.data.len() as u64
            || !check.allowed_sources.contains(&statement.source)
        {
            return Err(StarmetalError::IntegrityError {
                expected: "signature statement matching stored object".to_string(),
                actual: "signature statement mismatch".to_string(),
            });
        }
        Ok(())
    }

    pub(in crate::service) async fn verify_artifact_signature(
        &self,
        artifact_id: &ArtifactId,
        storage_key: &str,
        data: &Bytes,
    ) -> Result<()> {
        // An artifact signature may carry either a local-publish or upstream-cache source; accept
        // both from a single sidecar read + verify (rather than reading and verifying twice).
        self.verify_storage_signature(StoredObjectSignatureCheck {
            ecosystem: artifact_id.ecosystem,
            name: &artifact_id.name,
            version: &artifact_id.version,
            filename: Some(artifact_id.filename.as_str()),
            storage_key,
            data,
            allowed_sources: &[SignatureSource::Local, SignatureSource::UpstreamCache],
        })
        .await
    }

    async fn verify_metadata_signature(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
        storage_key: &str,
        data: &Bytes,
    ) -> Result<()> {
        self.verify_storage_signature(StoredObjectSignatureCheck {
            ecosystem,
            name,
            version,
            filename: None,
            storage_key,
            data,
            allowed_sources: &[SignatureSource::Metadata],
        })
        .await
    }

    async fn load_versions_for_publish(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<Vec<VersionInfo>> {
        let key = Self::versions_key(ecosystem, name)?;
        if let Some(cached) = self.storage.get(&key).await? {
            return Ok(serde_json::from_slice(&cached)?);
        }

        if let Some(upstream) = self.upstream_clients.get(&ecosystem) {
            return match upstream.fetch_versions(name).await {
                Ok(versions) => Ok(versions),
                Err(StarmetalError::PackageNotFound { .. }) => Ok(Vec::new()),
                Err(err) => Err(err),
            };
        }

        Ok(Vec::new())
    }

    fn record_statistics(&self, ecosystem: Ecosystem, update: impl FnOnce(&mut EcosystemStatistics)) {
        let Ok(mut snapshot) = self.statistics.lock() else {
            tracing::warn!("statistics lock is poisoned; skipping statistics update");
            return;
        };
        let stats = snapshot
            .ecosystems
            .entry(ecosystem.to_string())
            .or_insert_with(EcosystemStatistics::default);
        update(stats);
        stats.last_activity_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs());
    }

    fn record_upstream_error(&self, ecosystem: Ecosystem) {
        self.record_statistics(ecosystem, |stats| {
            stats.upstream_errors = stats.upstream_errors.saturating_add(1);
        });
    }

    fn record_integrity_failure(&self, ecosystem: Ecosystem) {
        self.record_statistics(ecosystem, |stats| {
            stats.integrity_failures = stats.integrity_failures.saturating_add(1);
        });
    }
}

#[async_trait]
impl PackageService for CachingPackageService {
    async fn list_versions(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<Vec<VersionInfo>> {
        self.check_package_allowed(name)?;

        let key = Self::versions_key(ecosystem, name)?;

        if let Some(cached) = self.storage.get(&key).await? {
            tracing::debug!(ecosystem = %ecosystem, name = %name, "cache hit for versions");
            self.record_statistics(ecosystem, |stats| {
                stats.versions_cache_hits = stats.versions_cache_hits.saturating_add(1);
            });
            let versions: Vec<VersionInfo> = serde_json::from_slice(&cached)?;
            return Ok(versions);
        }

        self.record_statistics(ecosystem, |stats| {
            stats.versions_cache_misses = stats.versions_cache_misses.saturating_add(1);
        });
        tracing::info!(ecosystem = %ecosystem, name = %name, "fetching versions from upstream");
        let upstream = self.upstream(ecosystem)?;
        let versions = upstream.fetch_versions(name).await.inspect_err(|_err| {
            self.record_upstream_error(ecosystem);
        })?;

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
        self.check_package_allowed(name)?;

        let key = Self::metadata_key(ecosystem, name, version)?;

        if let Some(cached) = self.storage.get(&key).await? {
            tracing::debug!(ecosystem = %ecosystem, name = %name, version, "cache hit for metadata");
            self.record_statistics(ecosystem, |stats| {
                stats.metadata_cache_hits = stats.metadata_cache_hits.saturating_add(1);
            });
            if self.verify_on_read() {
                self.verify_metadata_signature(ecosystem, name, version, &key, &cached)
                    .await?;
            }
            let metadata: VersionMetadata = serde_json::from_slice(&cached)?;
            self.policy.check(&metadata)?;
            return Ok(metadata);
        }

        self.record_statistics(ecosystem, |stats| {
            stats.metadata_cache_misses = stats.metadata_cache_misses.saturating_add(1);
        });
        tracing::info!(ecosystem = %ecosystem, name = %name, version, "fetching metadata from upstream");
        let upstream = self.upstream(ecosystem)?;
        let metadata = upstream.fetch_metadata(name, version).await.inspect_err(|_err| {
            self.record_upstream_error(ecosystem);
        })?;

        self.policy.check(&metadata)?;

        let serialized = Bytes::from(serde_json::to_vec(&metadata)?);
        let mut staged_writes = Vec::new();
        let result = async {
            if let Some(signing) = &self.signing
                && signing.sign_cached_upstream()
            {
                let statement = signing.statement(StatementInput {
                    ecosystem,
                    package: name.clone(),
                    version: version.to_string(),
                    filename: None,
                    storage_key: key.clone(),
                    size: serialized.len() as u64,
                    blake3: integrity::blake3_hex(&serialized),
                    upstream_hashes: AHashMap::new(),
                    source: SignatureSource::Metadata,
                })?;
                let sidecar_key = Self::signature_sidecar_key(&key);
                let bundle_key = Self::signature_bundle_key(ecosystem, name, version, "metadata.sig.json")?;
                self.sign_and_store_statement(statement, &sidecar_key, &bundle_key, &mut staged_writes)
                    .await?;
            }
            self.put_and_track(&key, serialized, &mut staged_writes).await
        }
        .await;
        if let Err(err) = result {
            self.rollback_staged_writes(&staged_writes).await;
            return Err(err);
        }

        Ok(metadata)
    }

    async fn validate_metadata(&self, metadata: &VersionMetadata) -> Result<()> {
        self.check_package_allowed(&metadata.name)?;
        self.policy.check(metadata)
    }

    async fn get_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        self.check_package_allowed(&artifact_id.name)?;
        let metadata = self
            .get_version_metadata(artifact_id.ecosystem, &artifact_id.name, &artifact_id.version)
            .await?;
        let artifact_digest = metadata
            .artifacts
            .iter()
            .find(|artifact| artifact.filename == artifact_id.filename)
            .ok_or_else(|| StarmetalError::ArtifactNotFound(artifact_id.storage_key()))?;

        let key = artifact_id.validated_storage_key()?.into_string();
        let hash_key = format!("{key}.blake3");

        // The artifact bytes and their blake3 sidecar are both needed on every cache hit and their
        // keys are independent, so fetch them concurrently — one round-trip instead of two on
        // object-store backends. On a miss the sidecar fetch is discarded (it overlapped the bytes
        // fetch, so it added no latency).
        let (cached, cached_hash) = futures::try_join!(self.storage.get(&key), self.storage.get(&hash_key))?;
        if let Some(cached) = cached {
            return self
                .serve_cached_artifact(artifact_id, &key, &hash_key, cached, cached_hash)
                .await;
        }
        self.fetch_and_cache_artifact(artifact_id, &key, &hash_key, artifact_digest)
            .await
    }

    async fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<PackageName>> {
        let prefix = format!("{ecosystem}/");
        let keys = self.storage.list_prefix(&prefix).await?;

        let mut seen = ahash::AHashSet::new();
        let mut packages = Vec::new();

        for key in &keys {
            let rest = key.strip_prefix(&prefix).unwrap_or(key);
            if let Some(name) = rest.split('/').next()
                && !name.is_empty()
                && seen.insert(name.to_string())
            {
                packages.push(PackageName::new(decode_storage_segment(name)));
            }
        }

        Ok(packages)
    }

    async fn get_raw_upstream(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<Option<Bytes>> {
        self.check_package_allowed(name)?;
        let key = Self::raw_upstream_key(ecosystem, name)?;
        self.storage.get(&key).await
    }

    async fn put_raw_upstream(&self, ecosystem: Ecosystem, name: &PackageName, data: Bytes) -> Result<()> {
        self.check_package_allowed(name)?;
        let key = Self::raw_upstream_key(ecosystem, name)?;
        self.storage.put(&key, data).await
    }
}

impl CachingPackageService {
    /// Serve an artifact from a cache hit: verify its blake3 sidecar and (unless the supply-chain
    /// gate already covers it) its signature, run the serve-time scan and signature/provenance
    /// gates, then record the hit. Extracted from `get_artifact`'s cache-hit branch.
    async fn serve_cached_artifact(
        &self,
        artifact_id: &ArtifactId,
        key: &str,
        hash_key: &str,
        cached: Bytes,
        cached_hash: Option<Bytes>,
    ) -> Result<Bytes> {
        let expected_hash = cached_hash.ok_or_else(|| {
            self.record_integrity_failure(artifact_id.ecosystem);
            StarmetalError::IntegrityError {
                expected: format!("missing sidecar {hash_key}"),
                actual: "unverified cached artifact".to_string(),
            }
        })?;
        let expected = std::str::from_utf8(&expected_hash).map_err(|e| StarmetalError::Storage(e.to_string()))?;
        if let Err(err) = integrity::verify_or_err(&cached, expected) {
            self.record_integrity_failure(artifact_id.ecosystem);
            return Err(err);
        }
        // Signing verify-on-read is skipped when the supply-chain signature gate already covers
        // it (it reuses the same `verify_artifact_signature`), so the signature is checked once.
        if self.verify_on_read() && !self.gates_signature() {
            self.verify_artifact_signature(artifact_id, key, &cached).await?;
        }
        self.enforce_serve_scan(artifact_id, expected, &cached).await?;
        self.enforce_verification(artifact_id, key, expected, &cached).await?;
        // Recorded only after all gates pass, so a denied/quarantined serve is never counted as
        // served (matches the cache-miss branch, which records bytes_served in the same place).
        self.record_statistics(artifact_id.ecosystem, |stats| {
            stats.artifact_cache_hits = stats.artifact_cache_hits.saturating_add(1);
            stats.bytes_served = stats.bytes_served.saturating_add(cached.len() as u64);
        });
        Ok(cached)
    }

    /// Fetch an artifact from upstream on a cache miss: verify the upstream hash, optionally sign and
    /// emit provenance, cache the bytes and their sidecar, then run the serve-time gates (rolling
    /// back a signature/provenance denial). Extracted from `get_artifact`'s cache-miss branch.
    async fn fetch_and_cache_artifact(
        &self,
        artifact_id: &ArtifactId,
        key: &str,
        hash_key: &str,
        artifact_digest: &ArtifactDigest,
    ) -> Result<Bytes> {
        self.record_statistics(artifact_id.ecosystem, |stats| {
            stats.artifact_cache_misses = stats.artifact_cache_misses.saturating_add(1);
        });
        tracing::info!(key, "fetching artifact from upstream");
        let upstream = self.upstream(artifact_id.ecosystem)?;
        let data = upstream.fetch_artifact(artifact_id).await.inspect_err(|_err| {
            self.record_upstream_error(artifact_id.ecosystem);
        })?;
        if let Err(err) = Self::verify_upstream_hash(&data, artifact_digest) {
            self.record_integrity_failure(artifact_id.ecosystem);
            return Err(err);
        }

        let hash = integrity::blake3_hex(&data);
        let mut staged_writes = Vec::new();
        let result = async {
            if let Some(signing) = &self.signing
                && signing.sign_cached_upstream()
            {
                let statement = signing.statement(StatementInput {
                    ecosystem: artifact_id.ecosystem,
                    package: artifact_id.name.clone(),
                    version: artifact_id.version.clone(),
                    filename: Some(artifact_id.filename.clone()),
                    storage_key: key.to_string(),
                    size: data.len() as u64,
                    blake3: hash.clone(),
                    upstream_hashes: artifact_digest.upstream_hashes.clone(),
                    source: SignatureSource::UpstreamCache,
                })?;
                let sidecar_key = Self::signature_sidecar_key(key);
                let bundle_key = Self::signature_bundle_key(
                    artifact_id.ecosystem,
                    &artifact_id.name,
                    &artifact_id.version,
                    &format!("{}.sig.json", artifact_id.filename),
                )?;
                self.sign_and_store_statement(statement, &sidecar_key, &bundle_key, &mut staged_writes)
                    .await?;
                if self.emit_provenance {
                    let fetched_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
                    self.sign_and_store_attestation(
                        artifact_id.ecosystem,
                        &artifact_id.name,
                        key,
                        &hash,
                        &fetched_at,
                        &mut staged_writes,
                    )
                    .await?;
                }
            }
            self.put_and_track(hash_key, Bytes::from(hash.clone()), &mut staged_writes)
                .await?;
            self.put_and_track(key, data.clone(), &mut staged_writes).await
        }
        .await;
        if let Err(err) = result {
            self.rollback_staged_writes(&staged_writes).await;
            return Err(err);
        }
        self.enforce_serve_scan(artifact_id, &hash, &data).await?;
        // A signature/provenance denial at cache-fill must not leave the just-cached (unverifiable)
        // bytes behind — roll them back, unlike the scan gate above whose quarantine intentionally
        // holds them.
        if let Err(err) = self.enforce_verification(artifact_id, key, &hash, &data).await {
            self.rollback_staged_writes(&staged_writes).await;
            return Err(err);
        }
        self.record_statistics(artifact_id.ecosystem, |stats| {
            stats.bytes_served = stats.bytes_served.saturating_add(data.len() as u64);
        });

        Ok(data)
    }
}

#[async_trait]
impl PublishingService for CachingPackageService {
    async fn publish_package(&self, request: PublishRequest) -> Result<PublishResult> {
        self.check_package_allowed(&request.name)?;
        if request.artifacts.is_empty() {
            return Err(StarmetalError::Publish(
                "publish requires at least one artifact".to_string(),
            ));
        }

        // Hashed once and reused (index-aligned with `request.artifacts`) across digest
        // construction, the vulnerability gate, and the transactional write loop below, instead of
        // re-hashing the same bytes three times.
        let blake3_digests: Vec<String> = request
            .artifacts
            .iter()
            .map(|artifact| integrity::blake3_hex(&artifact.data))
            .collect();

        // Serializes concurrent publishes targeting the same ecosystem/name/version coordinate;
        // held until this function returns. The guard prunes its `publish_locks` entry on drop, so
        // the map is cleaned up on every exit path (success or early-return error), not just success. ~keep
        let _publish_guard = self
            .acquire_publish_lock(request.ecosystem, &request.name, &request.version)
            .await;

        let metadata_key = Self::metadata_key(request.ecosystem, &request.name, &request.version)?;
        if !request.allow_overwrite && self.storage.exists(&metadata_key).await? {
            return Err(StarmetalError::Publish(format!(
                "version already exists: {}/{}@{}",
                request.ecosystem, request.name, request.version
            )));
        }

        if !request.allow_shadowing
            && let Some(upstream) = self.upstream_clients.get(&request.ecosystem)
            && upstream.fetch_metadata(&request.name, &request.version).await.is_ok()
        {
            return Err(StarmetalError::Publish(format!(
                "refusing to shadow upstream version: {}/{}@{}",
                request.ecosystem, request.name, request.version
            )));
        }

        let mut staged_keys = Vec::new();
        let mut digests = Vec::with_capacity(request.artifacts.len());
        for (artifact, blake3) in request.artifacts.iter().zip(&blake3_digests) {
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
            digests.push(artifact.digest(blake3.clone()));
        }

        let mut metadata = request.metadata(digests.clone());
        if request.allow_overwrite
            && let Some(existing) = self.storage.get(&metadata_key).await?
        {
            let mut existing_metadata: VersionMetadata = serde_json::from_slice(&existing)?;
            for digest in digests {
                existing_metadata
                    .artifacts
                    .retain(|artifact| artifact.filename != digest.filename);
                existing_metadata.artifacts.push(digest);
            }
            existing_metadata.license = metadata.license.clone().or(existing_metadata.license);
            existing_metadata.yanked = metadata.yanked;
            existing_metadata.listed = Some(request.listed);
            if !matches!(request.protocol_metadata, ProtocolMetadata::Generic) {
                existing_metadata.protocol_metadata = Some(request.protocol_metadata.clone());
            }
            metadata = existing_metadata;
        }
        self.policy.check(&metadata)?;

        // Vulnerability gate (ADR-0024): runs before the transactional block so a denied artifact
        // leaves no staged writes. Passing reports are carried into the transactional block and
        // stored (digest-keyed) so the serve-time gate finds them without re-scanning.
        let scan_reports = match self.scan_artifacts_for_publish(&request, &blake3_digests).await? {
            ScanGateOutcome::Passed(reports) => reports,
            // Ingest quarantine (ADR-0024): a blocked publish is parked off the live path for
            // operator review instead of denied. No staged writes exist yet, so the live path stays
            // untouched; the held bytes, manifest, and record are written under `_starmetal/held/`.
            ScanGateOutcome::Held(hold) => {
                return self.hold_ingest_publish(&request, &blake3_digests, hold).await;
            }
        };

        // One RFC3339 timestamp for every accessory this publish emits (SBOM documents, provenance
        // attestations), so they agree on a single build time.
        let publish_timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

        let result = async {
            for (blake3, persisted) in &scan_reports {
                self.put_and_track(
                    &Self::scan_report_key(blake3),
                    Bytes::from(serde_json::to_vec(persisted)?),
                    &mut staged_keys,
                )
                .await?;
            }
            for (artifact, blake3) in request.artifacts.iter().zip(&blake3_digests) {
                let artifact_id = ArtifactId {
                    ecosystem: request.ecosystem,
                    name: request.name.clone(),
                    version: request.version.clone(),
                    filename: artifact.filename.clone(),
                };
                let key = artifact_id.validated_storage_key()?.into_string();
                self.put_and_track(&format!("{key}.blake3"), Bytes::from(blake3.clone()), &mut staged_keys)
                    .await?;
                self.put_and_track(&key, artifact.data.clone(), &mut staged_keys)
                    .await?;

                let statement = self
                    .signing
                    .as_ref()
                    .map(|signing| {
                        signing.statement(StatementInput {
                            ecosystem: request.ecosystem,
                            package: request.name.clone(),
                            version: request.version.clone(),
                            filename: Some(artifact.filename.clone()),
                            storage_key: key.clone(),
                            size: artifact.data.len() as u64,
                            blake3: blake3.clone(),
                            upstream_hashes: artifact.upstream_hashes.clone(),
                            source: SignatureSource::Local,
                        })
                    })
                    .transpose()?;
                if let Some(statement) = statement {
                    let sidecar_key = Self::signature_sidecar_key(&key);
                    let bundle_key = Self::signature_bundle_key(
                        request.ecosystem,
                        &request.name,
                        &request.version,
                        &format!("{}.sig.json", artifact.filename),
                    )?;
                    self.sign_and_store_statement(statement, &sidecar_key, &bundle_key, &mut staged_keys)
                        .await?;
                }

                self.store_sbom_documents(&request, artifact, blake3, &key, &publish_timestamp, &mut staged_keys)
                    .await?;

                if self.emit_provenance {
                    self.sign_and_store_attestation(
                        request.ecosystem,
                        &request.name,
                        &key,
                        blake3,
                        &publish_timestamp,
                        &mut staged_keys,
                    )
                    .await?;
                }

                // Ingest gate (ADR-0024): verify the just-produced signature/provenance for this
                // artifact. A denial (e.g. required signing not configured) propagates out of the
                // transactional block and rolls back every staged write for this publish.
                self.enforce_verification(&artifact_id, &key, blake3, &artifact.data)
                    .await?;
            }

            let metadata_bytes = Bytes::from(serde_json::to_vec(&metadata)?);
            self.put_and_track(&metadata_key, metadata_bytes.clone(), &mut staged_keys)
                .await?;
            let metadata_statement = self
                .signing
                .as_ref()
                .map(|signing| {
                    signing.statement(StatementInput {
                        ecosystem: request.ecosystem,
                        package: request.name.clone(),
                        version: request.version.clone(),
                        filename: None,
                        storage_key: metadata_key.clone(),
                        size: metadata_bytes.len() as u64,
                        blake3: integrity::blake3_hex(&metadata_bytes),
                        upstream_hashes: AHashMap::new(),
                        source: SignatureSource::Metadata,
                    })
                })
                .transpose()?;
            if let Some(statement) = metadata_statement {
                let sidecar_key = Self::signature_sidecar_key(&metadata_key);
                let bundle_key = Self::signature_bundle_key(
                    request.ecosystem,
                    &request.name,
                    &request.version,
                    "metadata.sig.json",
                )?;
                self.sign_and_store_statement(statement, &sidecar_key, &bundle_key, &mut staged_keys)
                    .await?;
            }

            let published_manifest_key =
                Self::published_legacy_manifest_key(request.ecosystem, &request.name, &request.version)?;
            self.put_and_track(&published_manifest_key, metadata_bytes, &mut staged_keys)
                .await?;

            let record = PublishRecord {
                ecosystem: request.ecosystem,
                name: request.name.clone(),
                version: request.version.clone(),
                artifacts: metadata.artifacts.clone(),
                source: PublishSource::Local,
                protocol_metadata: request.protocol_metadata.clone(),
                published_at_unix_seconds: unix_now(),
                yanked: metadata.yanked,
                listed: request.listed,
            };
            let record_key = Self::published_record_key(request.ecosystem, &request.name, &request.version)?;
            self.put_and_track(&record_key, Bytes::from(serde_json::to_vec(&record)?), &mut staged_keys)
                .await?;

            let mut versions = self.load_versions_for_publish(request.ecosystem, &request.name).await?;
            if let Some(version) = versions.iter_mut().find(|version| version.version == request.version) {
                version.yanked = request.yanked;
            } else {
                versions.push(VersionInfo {
                    version: request.version.clone(),
                    yanked: request.yanked,
                });
            }
            let versions_key = Self::versions_key(request.ecosystem, &request.name)?;
            self.put_and_track(
                &versions_key,
                Bytes::from(serde_json::to_vec(&versions)?),
                &mut staged_keys,
            )
            .await?;

            if let Some(content_store) = self.content_store.clone() {
                self.store_content_model(content_store.as_ref(), &request, &metadata)
                    .await?;
            }

            Ok(PublishResult {
                ecosystem: request.ecosystem,
                name: request.name.clone(),
                version: request.version.clone(),
                artifacts: metadata.artifacts.clone(),
                mode: PublishMode::Local,
            })
        }
        .await;

        let result = match result {
            Ok(result) => result,
            Err(err) => {
                self.rollback_staged_writes(&staged_keys).await;
                return Err(err);
            }
        };

        self.record_statistics(request.ecosystem, |stats| {
            stats.publishes = stats.publishes.saturating_add(1);
        });

        Ok(result)
    }

    async fn set_yanked(&self, request: YankRequest) -> Result<VersionMetadata> {
        self.check_package_allowed(&request.name)?;
        let metadata_key = Self::metadata_key(request.ecosystem, &request.name, &request.version)?;
        let cached = self
            .storage
            .get(&metadata_key)
            .await?
            .ok_or_else(|| StarmetalError::VersionNotFound {
                ecosystem: request.ecosystem.to_string(),
                name: request.name.to_string(),
                version: request.version.clone(),
            })?;
        let mut metadata: VersionMetadata = serde_json::from_slice(&cached)?;
        metadata.yanked = request.yanked;
        self.policy.check(&metadata)?;

        let mut staged_writes = Vec::new();
        let result = async {
            let metadata_bytes = Bytes::from(serde_json::to_vec(&metadata)?);
            let metadata_statement = self
                .signing
                .as_ref()
                .map(|signing| {
                    signing.statement(StatementInput {
                        ecosystem: request.ecosystem,
                        package: request.name.clone(),
                        version: request.version.clone(),
                        filename: None,
                        storage_key: metadata_key.clone(),
                        size: metadata_bytes.len() as u64,
                        blake3: integrity::blake3_hex(&metadata_bytes),
                        upstream_hashes: AHashMap::new(),
                        source: SignatureSource::Metadata,
                    })
                })
                .transpose()?;
            if let Some(statement) = metadata_statement {
                let sidecar_key = Self::signature_sidecar_key(&metadata_key);
                let bundle_key = Self::signature_bundle_key(
                    request.ecosystem,
                    &request.name,
                    &request.version,
                    "metadata.sig.json",
                )?;
                self.sign_and_store_statement(statement, &sidecar_key, &bundle_key, &mut staged_writes)
                    .await?;
            }
            self.put_and_track(&metadata_key, metadata_bytes.clone(), &mut staged_writes)
                .await?;
            let published_manifest_key =
                Self::published_legacy_manifest_key(request.ecosystem, &request.name, &request.version)?;
            self.put_and_track(&published_manifest_key, metadata_bytes, &mut staged_writes)
                .await?;
            let record_key = Self::published_record_key(request.ecosystem, &request.name, &request.version)?;
            if let Some(record_bytes) = self.storage.get(&record_key).await? {
                let mut record: PublishRecord = serde_json::from_slice(&record_bytes)?;
                record.yanked = request.yanked;
                self.put_and_track(
                    &record_key,
                    Bytes::from(serde_json::to_vec(&record)?),
                    &mut staged_writes,
                )
                .await?;
            }

            let mut versions = self.load_versions_for_publish(request.ecosystem, &request.name).await?;
            if let Some(version) = versions.iter_mut().find(|version| version.version == request.version) {
                version.yanked = request.yanked;
            } else {
                versions.push(VersionInfo {
                    version: request.version.clone(),
                    yanked: request.yanked,
                });
            }
            let versions_key = Self::versions_key(request.ecosystem, &request.name)?;
            self.put_and_track(
                &versions_key,
                Bytes::from(serde_json::to_vec(&versions)?),
                &mut staged_writes,
            )
            .await
        }
        .await;
        if let Err(err) = result {
            self.rollback_staged_writes(&staged_writes).await;
            return Err(err);
        }
        self.record_statistics(request.ecosystem, |stats| {
            stats.yanks = stats.yanks.saturating_add(1);
        });

        Ok(metadata)
    }
}

impl StatisticsService for CachingPackageService {
    fn statistics(&self) -> StatisticsSnapshot {
        match self.statistics.lock() {
            Ok(snapshot) => snapshot.clone(),
            Err(_) => {
                tracing::warn!("statistics lock is poisoned; returning empty statistics snapshot");
                StatisticsSnapshot::default()
            }
        }
    }
}

/// Ingest-time quarantine (ADR-0024): holding a scan-blocked hosted publish for review, and the
/// operator promote/reject workflow that completes or purges it. Kept as inherent methods appended
/// beside the ingest publish path, distinct from the serve-side [`QuarantineReview`] impl.
impl CachingPackageService {
    /// Whether an operator promoted a quarantine hold for *exactly this coordinate and digest*.
    /// Consulted by the ingest scan gate so replaying an already-reviewed held publish on promotion
    /// clears the gate instead of being re-held — mirroring the serve gate.
    ///
    /// The match is bound to the record's `artifact` coordinate, not the content digest alone
    /// (records are digest-keyed, but blake3 carries no coordinate binding): an operator's decision
    /// to promote one held publish must not become an unscoped amnesty that clears the gate for a
    /// *different* package that happens to share bytes. Without the coordinate check, an attacker
    /// could republish previously-promoted bytes under an arbitrary coordinate and bypass the
    /// vulnerability gate entirely (CWE-863).
    async fn coordinate_is_promoted(&self, artifact_id: &ArtifactId, blake3: &str) -> Result<bool> {
        let Some(bytes) = self.storage.get(&Self::quarantine_record_key(blake3)).await? else {
            return Ok(false);
        };
        let record: QuarantineRecord = serde_json::from_slice(&bytes)?;
        Ok(record.state == QuarantineState::Promoted && &record.artifact == artifact_id)
    }

    /// Park a scan-blocked hosted publish for operator review (ADR-0024 ingest quarantine): store
    /// each artifact's raw bytes under `_starmetal/held/<blake3>`, a reconstruction manifest under
    /// `_starmetal/held/<blocking_blake3>.manifest.json`, and an ingest-origin quarantine record
    /// keyed by the blocking digest. Nothing lands on the live artifact path, so the publish does
    /// not take effect until an operator promotes it.
    async fn hold_ingest_publish(
        &self,
        request: &PublishRequest,
        blake3_digests: &[String],
        hold: IngestHold,
    ) -> Result<PublishResult> {
        let mut held_artifacts = Vec::with_capacity(request.artifacts.len());
        let mut digests = Vec::with_capacity(request.artifacts.len());
        for (artifact, blake3) in request.artifacts.iter().zip(blake3_digests) {
            self.storage
                .put(&Self::held_bytes_key(blake3), artifact.data.clone())
                .await?;
            held_artifacts.push(HeldArtifact {
                filename: artifact.filename.clone(),
                blake3: blake3.clone(),
                upstream_hashes: artifact.upstream_hashes.clone(),
            });
            digests.push(artifact.digest(blake3.clone()));
        }

        let manifest = HeldPublish {
            ecosystem: request.ecosystem,
            name: request.name.as_str().to_string(),
            version: request.version.clone(),
            license: request.license.clone(),
            yanked: request.yanked,
            listed: request.listed,
            allow_overwrite: request.allow_overwrite,
            allow_shadowing: request.allow_shadowing,
            protocol_metadata: request.protocol_metadata.clone(),
            artifacts: held_artifacts,
        };
        self.storage
            .put(
                &Self::held_manifest_key(&hold.blocking_blake3),
                Bytes::from(serde_json::to_vec(&manifest)?),
            )
            .await?;

        let record = QuarantineRecord {
            subject_digest: hold.blocking_blake3.clone(),
            artifact: hold.blocking_artifact,
            origin: QuarantineOrigin::Ingest,
            state: QuarantineState::Quarantined,
            reason_code: hold.reason_code,
            reason: hold.reason,
            quarantined_at: unix_now(),
            decided_at: None,
        };
        self.storage
            .put(
                &Self::quarantine_record_key(&hold.blocking_blake3),
                Bytes::from(serde_json::to_vec(&record)?),
            )
            .await?;

        Ok(PublishResult {
            ecosystem: request.ecosystem,
            name: request.name.clone(),
            version: request.version.clone(),
            artifacts: digests,
            mode: PublishMode::Local,
        })
    }

    /// Reconstruct the deferred [`PublishRequest`] for an ingest hold from its manifest and parked
    /// bytes. Errors with `ArtifactNotFound` if the manifest or any held artifact's bytes are gone.
    async fn rebuild_held_request(&self, blocking_blake3: &str) -> Result<(HeldPublish, PublishRequest)> {
        let manifest_bytes = self
            .storage
            .get(&Self::held_manifest_key(blocking_blake3))
            .await?
            .ok_or_else(|| StarmetalError::ArtifactNotFound(format!("no held publish for {blocking_blake3}")))?;
        let manifest: HeldPublish = serde_json::from_slice(&manifest_bytes)?;

        let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
        for held in &manifest.artifacts {
            let data = self
                .storage
                .get(&Self::held_bytes_key(&held.blake3))
                .await?
                .ok_or_else(|| StarmetalError::ArtifactNotFound(format!("held bytes missing for {}", held.blake3)))?;
            artifacts.push(PublishedArtifact {
                filename: held.filename.clone(),
                data,
                upstream_hashes: held.upstream_hashes.clone(),
            });
        }

        let request = PublishRequest {
            ecosystem: manifest.ecosystem,
            name: PackageName::new(manifest.name.clone()),
            version: manifest.version.clone(),
            license: manifest.license.clone(),
            yanked: manifest.yanked,
            listed: manifest.listed,
            artifacts,
            protocol_metadata: manifest.protocol_metadata.clone(),
            allow_overwrite: manifest.allow_overwrite,
            allow_shadowing: manifest.allow_shadowing,
        };
        Ok((manifest, request))
    }

    /// Delete every parked key for an ingest hold: each artifact's bytes and the manifest.
    async fn purge_held_publish(&self, manifest: &HeldPublish, blocking_blake3: &str) -> Result<()> {
        for held in &manifest.artifacts {
            self.storage.delete(&Self::held_bytes_key(&held.blake3)).await?;
        }
        self.storage.delete(&Self::held_manifest_key(blocking_blake3)).await?;
        Ok(())
    }

    /// Load the ingest-origin quarantine record for a decision: validate the digest (CWE-22 defense
    /// in depth, mirroring `transition_quarantine`), require the record to exist, and require it to
    /// be ingest-origin. Shared by promote/reject.
    async fn load_ingest_record(&self, subject_digest: &str) -> Result<QuarantineRecord> {
        if !integrity::is_blake3_hex(subject_digest) {
            return Err(StarmetalError::Adapter(format!(
                "invalid blake3 digest: {subject_digest}"
            )));
        }
        let bytes = self
            .storage
            .get(&Self::quarantine_record_key(subject_digest))
            .await?
            .ok_or_else(|| StarmetalError::ArtifactNotFound(format!("no quarantine record for {subject_digest}")))?;
        let record: QuarantineRecord = serde_json::from_slice(&bytes)?;
        if record.origin != QuarantineOrigin::Ingest {
            return Err(StarmetalError::ArtifactNotFound(format!(
                "no ingest quarantine hold for {subject_digest}"
            )));
        }
        Ok(record)
    }
}

#[async_trait]
impl IngestQuarantine for CachingPackageService {
    async fn promote_ingest(&self, subject_digest: &str) -> Result<QuarantineRecord> {
        let mut record = self.load_ingest_record(subject_digest).await?;
        let (manifest, request) = self.rebuild_held_request(subject_digest).await?;

        // Mark promoted first so the ingest scan gate clears this known-blocking digest when the
        // publish is replayed through the real publish path, instead of re-holding it.
        record.state = QuarantineState::Promoted;
        record.decided_at = Some(unix_now());
        self.storage
            .put(
                &Self::quarantine_record_key(subject_digest),
                Bytes::from(serde_json::to_vec(&record)?),
            )
            .await?;

        // Complete the deferred publish through the real path. On failure, revert the record to
        // quarantined so the hold stays recoverable rather than stranded promoted-but-unpublished.
        if let Err(error) = self.publish_package(request).await {
            record.state = QuarantineState::Quarantined;
            record.decided_at = None;
            let _ = self
                .storage
                .put(
                    &Self::quarantine_record_key(subject_digest),
                    Bytes::from(serde_json::to_vec(&record)?),
                )
                .await;
            return Err(error);
        }

        self.purge_held_publish(&manifest, subject_digest).await?;
        Ok(record)
    }

    async fn reject_ingest(&self, subject_digest: &str) -> Result<QuarantineRecord> {
        let mut record = self.load_ingest_record(subject_digest).await?;
        // Purge the parked bytes so the publish can never land. Tolerate a missing manifest (a prior
        // partial decision) — the record transition below is the authoritative outcome.
        if let Ok((manifest, _)) = self.rebuild_held_request(subject_digest).await {
            self.purge_held_publish(&manifest, subject_digest).await?;
        }
        record.state = QuarantineState::Rejected;
        record.decided_at = Some(unix_now());
        self.storage
            .put(
                &Self::quarantine_record_key(subject_digest),
                Bytes::from(serde_json::to_vec(&record)?),
            )
            .await?;
        Ok(record)
    }
}

/// Map an upstream hash algorithm label (as advertised by a registry, e.g. `sha256`) to the
/// CycloneDX spelling, or `None` for an algorithm the SBOM formats do not define.
fn cyclonedx_hash_algorithm(upstream_algorithm: &str) -> Option<&'static str> {
    match upstream_algorithm.to_ascii_lowercase().as_str() {
        "sha256" | "sha-256" => Some("SHA-256"),
        "sha512" | "sha-512" => Some("SHA-512"),
        "sha1" | "sha-1" => Some("SHA-1"),
        "md5" => Some("MD5"),
        _ => None,
    }
}

pub(in crate::service) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map_or(0, |duration| duration.as_secs())
}

fn crate_safe_signature_filename(filename: &str) -> Result<String> {
    let encoded = filename
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' => char::from(byte).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect::<String>();
    validate_storage_segment("signature filename", &encoded)?;
    Ok(encoded)
}

fn verify_hex_digest(algorithm: &str, expected: &str, actual: &str) -> Result<()> {
    if expected.trim().eq_ignore_ascii_case(actual.trim()) {
        Ok(())
    } else {
        Err(StarmetalError::IntegrityError {
            expected: format!("{algorithm}:{expected}"),
            actual: format!("{algorithm}:{actual}"),
        })
    }
}

fn verify_subresource_integrity(data: &Bytes, integrity_value: &str) -> Result<()> {
    for token in integrity_value.split_ascii_whitespace() {
        let Some((algorithm, encoded)) = token.split_once('-') else {
            continue;
        };

        let actual = match algorithm {
            "sha512" => sha2::Sha512::digest(data).to_vec(),
            "sha384" => sha2::Sha384::digest(data).to_vec(),
            "sha256" => sha2::Sha256::digest(data).to_vec(),
            _ => continue,
        };

        let expected = BASE64_STANDARD
            .decode(encoded)
            .map_err(|e| StarmetalError::IntegrityError {
                expected: format!("{algorithm}:{encoded}"),
                actual: format!("invalid SRI digest: {e}"),
            })?;

        if expected == actual {
            return Ok(());
        }

        return Err(StarmetalError::IntegrityError {
            expected: format!("{algorithm}:{encoded}"),
            actual: format!("{algorithm}:mismatch"),
        });
    }

    Err(StarmetalError::IntegrityError {
        expected: integrity_value.to_string(),
        actual: "no supported SRI digest".to_string(),
    })
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    #[cfg(unix)]
    use ed25519_dalek::SigningKey;
    use starmetal_core::package::ArtifactDigest;
    use starmetal_core::publishing::PublishedArtifact;
    #[cfg(unix)]
    use starmetal_core::signing::{SigningAlgorithm, SigningConfig, SigningKeyConfig, SigningKeyStatus, SigningMode};
    use starmetal_core::supply_chain::{
        PolicyDecision, PolicyReason, QuarantineReview, QuarantineState, RecorrelationReport, SbomIndex,
        SupplyChainMaintenance, VerificationTarget,
    };

    #[cfg(unix)]
    use super::signing::ED25519_KEY_BYTES;
    use super::*;

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
            Self { data: Mutex::new(map) }
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

        async fn fetch_metadata(&self, _name: &PackageName, version: &str) -> Result<VersionMetadata> {
            self.metadata
                .get(version)
                .cloned()
                .ok_or_else(|| StarmetalError::VersionNotFound {
                    ecosystem: self.eco.to_string(),
                    name: "test".to_string(),
                    version: version.to_string(),
                })
        }

        async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
            self.artifacts
                .get(&artifact_id.filename)
                .cloned()
                .ok_or_else(|| StarmetalError::ArtifactNotFound(artifact_id.storage_key()))
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
            listed: None,
            protocol_metadata: None,
        }
    }

    fn test_metadata_with_artifact(
        name: &str,
        version: &str,
        filename: &str,
        upstream_hashes: AHashMap<String, String>,
    ) -> VersionMetadata {
        VersionMetadata {
            name: PackageName::new(name),
            version: version.to_string(),
            artifacts: vec![ArtifactDigest {
                filename: filename.to_string(),
                blake3: String::new(),
                size: 1024,
                upstream_hashes,
            }],
            license: Some("MIT".to_string()),
            yanked: false,
            listed: None,
            protocol_metadata: None,
        }
    }

    fn build_service(storage: Arc<MockStorage>, upstream: MockUpstream, policy: PolicyConfig) -> CachingPackageService {
        let eco = upstream.ecosystem();
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();
        clients.insert(eco, Arc::new(upstream));
        CachingPackageService::new(storage, clients, policy)
    }

    struct MissingPackageUpstream {
        eco: Ecosystem,
    }

    #[async_trait]
    impl UpstreamClient for MissingPackageUpstream {
        fn ecosystem(&self) -> Ecosystem {
            self.eco
        }

        async fn fetch_versions(&self, name: &PackageName) -> Result<Vec<VersionInfo>> {
            Err(StarmetalError::PackageNotFound {
                ecosystem: self.eco.to_string(),
                name: name.as_str().to_string(),
            })
        }

        async fn fetch_metadata(&self, name: &PackageName, version: &str) -> Result<VersionMetadata> {
            Err(StarmetalError::VersionNotFound {
                ecosystem: self.eco.to_string(),
                name: name.as_str().to_string(),
                version: version.to_string(),
            })
        }

        async fn fetch_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
            Err(StarmetalError::ArtifactNotFound(artifact_id.storage_key()))
        }
    }

    fn build_service_with_missing_package_upstream(
        storage: Arc<MockStorage>,
        ecosystem: Ecosystem,
    ) -> CachingPackageService {
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();
        clients.insert(ecosystem, Arc::new(MissingPackageUpstream { eco: ecosystem }));
        CachingPackageService::new(storage, clients, PolicyConfig::default())
    }

    #[cfg(unix)]
    fn write_test_signing_key(path: &Path, mode: u32) {
        let secret = [7_u8; 32];
        let pem = test_private_key_pem(&secret);
        fs::write(path, pem.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn write_test_verification_key(path: &Path, mode: u32) {
        let secret = [7_u8; 32];
        let pem = test_public_key_pem(&secret);
        fs::write(path, pem.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn test_private_key_pem(secret: &[u8; ED25519_KEY_BYTES]) -> String {
        const PKCS8_ED25519_PREFIX: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        ];
        let mut der = Vec::with_capacity(PKCS8_ED25519_PREFIX.len() + secret.len());
        der.extend_from_slice(&PKCS8_ED25519_PREFIX);
        der.extend_from_slice(secret);
        pem_block("PRIVATE KEY", &der)
    }

    #[cfg(unix)]
    fn test_public_key_pem(secret: &[u8; ED25519_KEY_BYTES]) -> String {
        const SPKI_ED25519_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        let public_key = SigningKey::from_bytes(secret).verifying_key().to_bytes();
        let mut der = Vec::with_capacity(SPKI_ED25519_PREFIX.len() + public_key.len());
        der.extend_from_slice(&SPKI_ED25519_PREFIX);
        der.extend_from_slice(&public_key);
        pem_block("PUBLIC KEY", &der)
    }

    #[cfg(unix)]
    fn pem_block(label: &str, der: &[u8]) -> String {
        let encoded = BASE64_STANDARD.encode(der);
        format!("-----BEGIN {label}-----\n{encoded}\n-----END {label}-----\n")
    }

    #[cfg(unix)]
    fn signing_config(private_key_file: PathBuf) -> SigningConfig {
        SigningConfig {
            enabled: true,
            mode: SigningMode::SignAndVerify,
            verify_on_read: true,
            sign_cached_upstream: false,
            keys: vec![SigningKeyConfig {
                id: "test-key".to_string(),
                algorithm: SigningAlgorithm::Ed25519,
                private_key_file: Some(private_key_file),
                public_key_file: None,
                private_key_password_env: None,
                certificate_file: None,
                certificate_chain_file: None,
                ecosystems: vec![Ecosystem::PyPI],
                packages: Vec::new(),
                status: SigningKeyStatus::Active,
            }],
            trust_roots: Vec::new(),
        }
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
        let hash = integrity::blake3_hex(&artifact_data);
        let storage = Arc::new(MockStorage::with_data(vec![
            (&artifact_id.storage_key(), artifact_data.clone()),
            (&format!("{}.blake3", artifact_id.storage_key()), Bytes::from(hash)),
        ]));
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact("requests", "2.31.0", "requests-2.31.0.tar.gz", AHashMap::new()),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
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
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("serde", "1.0.0", "serde-1.0.0.tar.gz", AHashMap::new()),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata,
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

        let stored = storage
            .get(&artifact_id.storage_key())
            .await
            .unwrap()
            .expect("artifact should be cached after fetch");
        assert_eq!(stored, artifact_data, "stored data should match fetched data");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sign_cached_upstream_signs_metadata_cache_hits() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let mut config = signing_config(key_path);
        config.sign_cached_upstream = true;
        let signing = SigningService::from_config(&config).unwrap().unwrap();
        let storage = Arc::new(MockStorage::new());
        let name = PackageName::new("requests");
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact("requests", "2.31.0", "requests-2.31.0.tar.gz", AHashMap::new()),
        );
        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
        };
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();
        clients.insert(Ecosystem::PyPI, Arc::new(upstream));
        let service =
            CachingPackageService::new_with_signing(storage.clone(), clients, PolicyConfig::default(), Some(signing));

        let first = service
            .get_version_metadata(Ecosystem::PyPI, &name, "2.31.0")
            .await
            .unwrap();
        let second = service
            .get_version_metadata(Ecosystem::PyPI, &name, "2.31.0")
            .await
            .unwrap();

        assert_eq!(first.version, "2.31.0");
        assert_eq!(second.version, "2.31.0");
        let metadata_key = CachingPackageService::metadata_key(Ecosystem::PyPI, &name, "2.31.0").unwrap();
        let sidecar_key = CachingPackageService::signature_sidecar_key(&metadata_key);
        assert!(
            storage.get(&sidecar_key).await.unwrap().is_some(),
            "upstream metadata signature sidecar should be stored"
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
        let result = service.get_version_metadata(Ecosystem::PyPI, &name, "1.0.0").await;

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
        let _ = service.get_version_metadata(Ecosystem::Npm, &name, "2.0.0").await;

        let key = CachingPackageService::metadata_key(Ecosystem::Npm, &name, "2.0.0").unwrap();
        let cached = storage.get(&key).await.unwrap();
        assert!(cached.is_none(), "blocked metadata must not be stored in cache");
    }

    #[tokio::test]
    async fn list_packages_extracts_names() {
        let storage = Arc::new(MockStorage::with_data(vec![
            ("pypi/requests/2.31.0/_metadata.json", Bytes::new()),
            ("pypi/requests/2.30.0/_metadata.json", Bytes::new()),
            ("pypi/flask/3.0.0/_metadata.json", Bytes::new()),
            ("pypi/django/4.2.0/_metadata.json", Bytes::new()),
        ]));

        let service = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
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

        assert!(result.is_err(), "should error when no upstream is configured");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no upstream configured for hex"),
            "error should mention missing upstream, got: {err}"
        );
    }

    #[tokio::test]
    async fn publish_package_stores_metadata_artifact_and_versions() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        let artifact_data = Bytes::from_static(b"published artifact");
        let request = PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.tar.gz".to_string(),
                data: artifact_data.clone(),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite: false,
            allow_shadowing: false,
        };

        let result = service.publish_package(request).await.unwrap();

        assert_eq!(result.version, "1.0.0");
        assert_eq!(result.artifacts[0].blake3, integrity::blake3_hex(&artifact_data));

        let name = PackageName::new("sample");
        let metadata = service
            .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
            .await
            .unwrap();
        assert_eq!(metadata.license.as_deref(), Some("MIT"));

        let artifact = service
            .get_artifact(&ArtifactId {
                ecosystem: Ecosystem::PyPI,
                name: name.clone(),
                version: "1.0.0".to_string(),
                filename: "sample-1.0.0.tar.gz".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(artifact, artifact_data);

        let versions = service.list_versions(Ecosystem::PyPI, &name).await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");

        let manifest = storage
            .get("_starmetal/published/pypi/sample/1.0.0.json")
            .await
            .unwrap();
        assert!(manifest.is_some(), "published manifest should be stored");

        let record_key = CachingPackageService::published_record_key(Ecosystem::PyPI, &name, "1.0.0").unwrap();
        let record = storage
            .get(&record_key)
            .await
            .unwrap()
            .expect("publish record should be stored");
        let record: PublishRecord = serde_json::from_slice(&record).unwrap();
        assert_eq!(record.source, PublishSource::Local);
        assert!(!record.yanked);
        assert!(record.listed);
    }

    #[tokio::test]
    async fn publish_generates_and_stores_sbom_documents_when_enabled() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default())
            .with_sbom_formats(vec![SbomFormat::CycloneDx, SbomFormat::Spdx]);
        let artifact_data = Bytes::from_static(b"published artifact for sbom");
        let blake3 = integrity::blake3_hex(&artifact_data);
        let request = PublishRequest {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("left-pad"),
            version: "1.3.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "left-pad-1.3.0.tgz".to_string(),
                data: artifact_data.clone(),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Npm),
            allow_overwrite: false,
            allow_shadowing: false,
        };
        service.publish_package(request).await.unwrap();

        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("left-pad"),
            version: "1.3.0".to_string(),
            filename: "left-pad-1.3.0.tgz".to_string(),
        };
        let artifact_key = artifact_id.validated_storage_key().unwrap().into_string();

        // Both SBOM sidecars are stored, coordinate-keyed, and the CycloneDX document is well-formed.
        let cyclonedx = storage
            .get(&format!("_starmetal/sbom/{artifact_key}.cyclonedx.json"))
            .await
            .unwrap()
            .expect("cyclonedx sbom stored");
        let document: serde_json::Value = serde_json::from_slice(&cyclonedx).unwrap();
        assert_eq!(document["bomFormat"], "CycloneDX");
        assert_eq!(document["metadata"]["component"]["purl"], "pkg:npm/left-pad@1.3.0");
        assert_eq!(document["metadata"]["component"]["hashes"][0]["alg"], "BLAKE3");
        assert_eq!(document["metadata"]["component"]["hashes"][0]["content"], blake3);
        assert!(
            storage
                .get(&format!("_starmetal/sbom/{artifact_key}.spdx.json"))
                .await
                .unwrap()
                .is_some(),
            "spdx sbom stored"
        );

        // The SbomIndex port lists both formats for the coordinate and fetches the stored bytes.
        let records = service.list_sboms(&artifact_id).await.unwrap();
        assert_eq!(records.len(), 2, "one record per configured format");
        assert_eq!(
            records[0].subject_digest, blake3,
            "record carries the artifact's blake3 subject"
        );
        let fetched = service
            .get_sbom_document(&artifact_id, SbomFormat::CycloneDx)
            .await
            .unwrap();
        assert_eq!(fetched, Some(cyclonedx));
    }

    #[tokio::test]
    async fn publish_stores_no_sbom_when_disabled() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());
        let artifact_data = Bytes::from_static(b"no sbom please");
        let request = PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: None,
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.tar.gz".to_string(),
                data: artifact_data,
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite: false,
            allow_shadowing: false,
        };
        service.publish_package(request).await.unwrap();
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            filename: "sample-1.0.0.tar.gz".to_string(),
        };
        assert!(
            service.list_sboms(&artifact_id).await.unwrap().is_empty(),
            "no sbom generated when disabled"
        );
    }

    #[tokio::test]
    async fn identical_bytes_under_two_coordinates_keep_distinct_sboms() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default())
            .with_sbom_formats(vec![SbomFormat::CycloneDx]);
        let shared_bytes = Bytes::from_static(b"identical bytes across two coordinates");

        let publish = |name: &str, version: &str, filename: &str, license: &str| PublishRequest {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new(name),
            version: version.to_string(),
            license: Some(license.to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: filename.to_string(),
                data: shared_bytes.clone(),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Npm),
            allow_overwrite: false,
            allow_shadowing: false,
        };

        // Two distinct coordinates publish byte-identical artifacts with different licenses; the
        // second must not overwrite the first's SBOM (the digest-keying bug the audit caught).
        service
            .publish_package(publish("real-lib", "1.0.0", "real-lib-1.0.0.tgz", "MIT"))
            .await
            .unwrap();
        service
            .publish_package(publish("impostor", "9.9.9", "impostor-9.9.9.tgz", "GPL-3.0"))
            .await
            .unwrap();

        let real = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("real-lib"),
            version: "1.0.0".to_string(),
            filename: "real-lib-1.0.0.tgz".to_string(),
        };
        let impostor = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("impostor"),
            version: "9.9.9".to_string(),
            filename: "impostor-9.9.9.tgz".to_string(),
        };

        let real_doc = service
            .get_sbom_document(&real, SbomFormat::CycloneDx)
            .await
            .unwrap()
            .expect("real sbom present");
        let impostor_doc = service
            .get_sbom_document(&impostor, SbomFormat::CycloneDx)
            .await
            .unwrap()
            .expect("impostor sbom present");
        assert_ne!(real_doc, impostor_doc, "each coordinate keeps its own SBOM");

        let real_json: serde_json::Value = serde_json::from_slice(&real_doc).unwrap();
        assert_eq!(
            real_json["metadata"]["component"]["licenses"][0]["license"]["name"], "MIT",
            "the original SBOM still declares MIT, not the impostor's license"
        );
        let impostor_json: serde_json::Value = serde_json::from_slice(&impostor_doc).unwrap();
        assert_eq!(
            impostor_json["metadata"]["component"]["licenses"][0]["license"]["name"],
            "GPL-3.0"
        );
    }

    #[tokio::test]
    async fn publishing_the_same_coordinate_repeatedly_does_not_grow_the_lock_map() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());

        let request = |allow_overwrite: bool| PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: None,
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.tar.gz".to_string(),
                data: Bytes::from_static(b"published artifact"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite,
            allow_shadowing: false,
        };

        service.publish_package(request(false)).await.unwrap();
        assert_eq!(
            service.publish_locks.lock().unwrap().len(),
            0,
            "the coordinate's lock should be pruned once the publish completes"
        );

        // Re-publishing the same coordinate must reuse (not accumulate) map entries.
        service.publish_package(request(true)).await.unwrap();
        assert_eq!(
            service.publish_locks.lock().unwrap().len(),
            0,
            "repeated publishes of the same coordinate must not grow the lock map"
        );
    }

    #[tokio::test]
    async fn a_failed_publish_still_prunes_its_lock_map_entry() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());

        let request = |allow_overwrite: bool| PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: None,
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.tar.gz".to_string(),
                data: Bytes::from_static(b"published artifact"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite,
            allow_shadowing: false,
        };

        service.publish_package(request(false)).await.unwrap();
        // Publishing the same version again without overwrite fails *after* acquiring the lock.
        service
            .publish_package(request(false))
            .await
            .expect_err("a duplicate version must be rejected");

        // The RAII guard must have pruned the entry on the error path too — a failed publish must not
        // leak a lock into the map.
        assert_eq!(
            service.publish_locks.lock().unwrap().len(),
            0,
            "a failed publish must still prune its lock map entry"
        );
    }

    /// A [`Scanner`] test double (a fake for our own port — not a mock of an external service):
    /// it reports a single finding of the configured severity, or a clean report when `None`.
    struct FakeScanner {
        severity: Option<starmetal_core::policy::VulnSeverity>,
    }

    #[async_trait]
    impl Scanner for FakeScanner {
        async fn scan(&self, target: ScanTarget<'_>) -> Result<starmetal_core::supply_chain::ScanReport> {
            let vulnerabilities = self
                .severity
                .map(|severity| {
                    vec![starmetal_core::supply_chain::Vulnerability {
                        id: "CVE-TEST-1".to_string(),
                        severity,
                        package: None,
                        description: None,
                        fixed_version: None,
                    }]
                })
                .unwrap_or_default();
            Ok(starmetal_core::supply_chain::ScanReport {
                scanner: "fake".to_string(),
                subject_digest: integrity::blake3_hex(target.content),
                vulnerabilities,
                completed: true,
            })
        }

        fn capabilities(&self) -> starmetal_core::supply_chain::ScannerCapabilities {
            starmetal_core::supply_chain::ScannerCapabilities {
                name: "fake".to_string(),
                version: "0".to_string(),
                ecosystems: Vec::new(),
                supports_vulnerabilities: true,
                produces_sbom: false,
                sbom_formats: Vec::new(),
            }
        }
    }

    /// A [`Scanner`] that always fails its scan, to prove the ingest gate fails closed.
    struct UnavailableScanner;

    #[async_trait]
    impl Scanner for UnavailableScanner {
        async fn scan(&self, _target: ScanTarget<'_>) -> Result<starmetal_core::supply_chain::ScanReport> {
            Err(StarmetalError::Upstream("scanner unavailable".to_string()))
        }

        fn capabilities(&self) -> starmetal_core::supply_chain::ScannerCapabilities {
            starmetal_core::supply_chain::ScannerCapabilities {
                name: "unavailable".to_string(),
                version: "0".to_string(),
                ecosystems: Vec::new(),
                supports_vulnerabilities: true,
                produces_sbom: false,
                sbom_formats: Vec::new(),
            }
        }
    }

    fn scan_gate_request() -> PublishRequest {
        PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.tar.gz".to_string(),
                data: Bytes::from_static(b"scanned artifact"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite: false,
            allow_shadowing: false,
        }
    }

    /// Like [`scan_gate_request`], but for a distinct package coordinate and artifact payload, so
    /// callers can publish several artifacts with distinct blake3 digests (and thus distinct
    /// `_starmetal/scans/<digest>.json` reports) in one test.
    fn scan_gate_request_for(name: &str, version: &str, data: &'static [u8]) -> PublishRequest {
        PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new(name),
            version: version.to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: format!("{name}-{version}.tar.gz"),
                data: Bytes::from_static(data),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite: false,
            allow_shadowing: false,
        }
    }

    #[tokio::test]
    async fn publish_is_denied_and_writes_nothing_when_a_scan_exceeds_the_threshold() {
        let storage = Arc::new(MockStorage::new());
        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), policy).with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Critical),
            }));

        let error = service.publish_package(scan_gate_request()).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::PolicyViolation(_)),
            "a scan over the threshold must be a policy violation, got: {error}"
        );

        // The gate runs before any staged write, so nothing was persisted.
        let name = PackageName::new("sample");
        assert!(
            service
                .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
                .await
                .is_err(),
            "a denied publish must leave no metadata behind"
        );
    }

    #[tokio::test]
    async fn publish_succeeds_when_a_scan_finding_is_within_the_threshold() {
        let storage = Arc::new(MockStorage::new());
        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        let service =
            CachingPackageService::new(storage, AHashMap::new(), policy).with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Medium),
            }));

        let result = service.publish_package(scan_gate_request()).await.unwrap();
        assert_eq!(result.version, "1.0.0");
    }

    #[tokio::test]
    async fn publish_fails_closed_when_the_scanner_is_unavailable() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default())
            .with_scanner(Arc::new(UnavailableScanner));

        let error = service.publish_package(scan_gate_request()).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::Upstream(_)),
            "an unavailable scanner must fail the publish closed, got: {error}"
        );
    }

    fn sample_artifact_id() -> ArtifactId {
        ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            filename: "sample-1.0.0.tar.gz".to_string(),
        }
    }

    #[tokio::test]
    async fn publish_stores_a_digest_keyed_scan_report_for_serve_time_reuse() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default())
            .with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Low),
            }));
        let request = scan_gate_request();
        let blake3 = integrity::blake3_hex(&request.artifacts[0].data);
        service.publish_package(request).await.unwrap();

        let stored = storage
            .get(&format!("_starmetal/scans/{blake3}.json"))
            .await
            .unwrap()
            .expect("a scan report is stored at ingest, keyed by the artifact digest");
        let persisted: PersistedScanReport = serde_json::from_slice(&stored).unwrap();
        assert_eq!(persisted.artifact, sample_artifact_id());
        assert_eq!(persisted.report.vulnerabilities.len(), 1);
        assert_eq!(
            persisted.report.vulnerabilities[0].severity,
            starmetal_core::policy::VulnSeverity::Low
        );
    }

    /// A [`Scanner`] that always reports a clean but incomplete scan (`completed: false`), to prove
    /// an inconclusive scan is blocked rather than treated as passing.
    struct IncompleteScanner;

    #[async_trait]
    impl Scanner for IncompleteScanner {
        async fn scan(&self, target: ScanTarget<'_>) -> Result<starmetal_core::supply_chain::ScanReport> {
            Ok(starmetal_core::supply_chain::ScanReport {
                scanner: "incomplete".to_string(),
                subject_digest: integrity::blake3_hex(target.content),
                vulnerabilities: Vec::new(),
                completed: false,
            })
        }

        fn capabilities(&self) -> starmetal_core::supply_chain::ScannerCapabilities {
            starmetal_core::supply_chain::ScannerCapabilities {
                name: "incomplete".to_string(),
                version: "0".to_string(),
                ecosystems: Vec::new(),
                supports_vulnerabilities: true,
                produces_sbom: false,
                sbom_formats: Vec::new(),
            }
        }
    }

    #[tokio::test]
    async fn publish_is_denied_and_writes_nothing_when_the_scan_did_not_complete() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default())
            .with_scanner(Arc::new(IncompleteScanner));

        let error = service.publish_package(scan_gate_request()).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::PolicyViolation(_)),
            "an incomplete scan must be a policy violation, got: {error}"
        );

        let name = PackageName::new("sample");
        assert!(
            service
                .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
                .await
                .is_err(),
            "a publish blocked by an incomplete scan must leave no metadata behind"
        );
    }

    #[tokio::test]
    async fn serve_is_denied_when_the_scan_on_demand_did_not_complete() {
        let storage = Arc::new(MockStorage::new());
        // Publish without a scanner so no report is stored: the serve gate must scan on demand.
        let publisher = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        publisher.publish_package(scan_gate_request()).await.unwrap();

        let server = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default())
            .with_scanner(Arc::new(IncompleteScanner))
            .enforce_scan_on_serve(true);

        let error = server.get_artifact(&sample_artifact_id()).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::PolicyViolation(_)),
            "an incomplete scan must deny serving even at the default (most permissive) threshold, got: {error}"
        );
    }

    /// A [`Scanner`] whose findings can be swapped after construction, to simulate an advisory feed
    /// that discloses a new vulnerability between the first scan and a later re-correlation sweep.
    struct MutableScanner {
        severity: std::sync::Mutex<Option<starmetal_core::policy::VulnSeverity>>,
    }

    impl MutableScanner {
        fn new(severity: Option<starmetal_core::policy::VulnSeverity>) -> Self {
            Self {
                severity: std::sync::Mutex::new(severity),
            }
        }

        fn set(&self, severity: Option<starmetal_core::policy::VulnSeverity>) {
            *self.severity.lock().unwrap() = severity;
        }
    }

    #[async_trait]
    impl Scanner for MutableScanner {
        async fn scan(&self, target: ScanTarget<'_>) -> Result<starmetal_core::supply_chain::ScanReport> {
            let vulnerabilities = self
                .severity
                .lock()
                .unwrap()
                .map(|severity| {
                    vec![starmetal_core::supply_chain::Vulnerability {
                        id: "CVE-TEST-1".to_string(),
                        severity,
                        package: None,
                        description: None,
                        fixed_version: None,
                    }]
                })
                .unwrap_or_default();
            Ok(starmetal_core::supply_chain::ScanReport {
                scanner: "mutable".to_string(),
                subject_digest: integrity::blake3_hex(target.content),
                vulnerabilities,
                completed: true,
            })
        }

        fn capabilities(&self) -> starmetal_core::supply_chain::ScannerCapabilities {
            starmetal_core::supply_chain::ScannerCapabilities {
                name: "mutable".to_string(),
                version: "0".to_string(),
                ecosystems: Vec::new(),
                supports_vulnerabilities: true,
                produces_sbom: false,
                sbom_formats: Vec::new(),
            }
        }
    }

    #[tokio::test]
    async fn recorrelation_rewrites_a_report_and_flags_a_newly_blocking_artifact() {
        let storage = Arc::new(MockStorage::new());
        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        // Publish while the feed reports the artifact clean, so a passing report is persisted.
        let scanner = Arc::new(MutableScanner::new(None));
        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), policy).with_scanner(scanner.clone());
        service.publish_package(scan_gate_request()).await.unwrap();

        // A new Critical advisory lands; the next sweep must re-scan, rewrite, and flag the artifact.
        scanner.set(Some(starmetal_core::policy::VulnSeverity::Critical));
        let report = service.recorrelate().await.unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.updated, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.newly_blocking, vec!["pypi/sample/1.0.0".to_string()]);

        // The rewritten report now carries the Critical finding.
        let blake3 = integrity::blake3_hex(b"scanned artifact");
        let stored = storage
            .get(&format!("_starmetal/scans/{blake3}.json"))
            .await
            .unwrap()
            .expect("the report is still stored");
        let persisted: PersistedScanReport = serde_json::from_slice(&stored).unwrap();
        assert_eq!(
            persisted.report.highest_severity(),
            Some(starmetal_core::policy::VulnSeverity::Critical)
        );
    }

    #[tokio::test]
    async fn recorrelation_skips_an_evicted_artifact() {
        let storage = Arc::new(MockStorage::new());
        let scanner = Arc::new(MutableScanner::new(None));
        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default()).with_scanner(scanner);
        service.publish_package(scan_gate_request()).await.unwrap();

        // Evict the artifact bytes but leave the stale report behind.
        let artifact_key = sample_artifact_id().validated_storage_key().unwrap().into_string();
        storage.delete(&artifact_key).await.unwrap();

        let report = service.recorrelate().await.unwrap();
        assert_eq!(report.scanned, 0, "an evicted artifact is not re-scanned");
        assert_eq!(report.updated, 0);
        assert!(report.newly_blocking.is_empty());
    }

    #[tokio::test]
    async fn recorrelation_is_a_noop_without_a_scanner() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());
        let report = service.recorrelate().await.unwrap();
        assert_eq!(report, RecorrelationReport::default());
    }

    /// A per-artifact outcome for [`PerArtifactScanner`]: clean, vulnerable at a given severity, or
    /// unavailable (simulating a transient scan failure).
    #[derive(Clone, Copy)]
    enum ScanOutcome {
        Clean,
        Vulnerable(starmetal_core::policy::VulnSeverity),
        Unavailable,
    }

    /// A [`Scanner`] whose outcome can be swapped independently per artifact filename after
    /// construction, modeling an advisory feed where different subjects evolve independently between
    /// scans — unlike [`MutableScanner`], which swaps a single severity shared by every subject. Used
    /// to prove `recorrelate`'s multi-report fold aggregates disparate per-item outcomes (some
    /// updated, one failed, one unchanged) correctly under bounded concurrency.
    struct PerArtifactScanner {
        outcomes: std::sync::Mutex<AHashMap<String, ScanOutcome>>,
    }

    impl PerArtifactScanner {
        fn new() -> Self {
            Self {
                outcomes: std::sync::Mutex::new(AHashMap::new()),
            }
        }

        fn set(&self, filename: &str, outcome: ScanOutcome) {
            self.outcomes.lock().unwrap().insert(filename.to_string(), outcome);
        }
    }

    #[async_trait]
    impl Scanner for PerArtifactScanner {
        async fn scan(&self, target: ScanTarget<'_>) -> Result<starmetal_core::supply_chain::ScanReport> {
            let outcome = self
                .outcomes
                .lock()
                .unwrap()
                .get(target.artifact_id.filename.as_str())
                .copied()
                .unwrap_or(ScanOutcome::Clean);
            let vulnerabilities = match outcome {
                ScanOutcome::Clean => Vec::new(),
                ScanOutcome::Vulnerable(severity) => vec![starmetal_core::supply_chain::Vulnerability {
                    id: "CVE-TEST-1".to_string(),
                    severity,
                    package: None,
                    description: None,
                    fixed_version: None,
                }],
                ScanOutcome::Unavailable => return Err(StarmetalError::Upstream("scanner unavailable".to_string())),
            };
            Ok(starmetal_core::supply_chain::ScanReport {
                scanner: "per-artifact".to_string(),
                subject_digest: integrity::blake3_hex(target.content),
                vulnerabilities,
                completed: true,
            })
        }

        fn capabilities(&self) -> starmetal_core::supply_chain::ScannerCapabilities {
            starmetal_core::supply_chain::ScannerCapabilities {
                name: "per-artifact".to_string(),
                version: "0".to_string(),
                ecosystems: Vec::new(),
                supports_vulnerabilities: true,
                produces_sbom: false,
                sbom_formats: Vec::new(),
            }
        }
    }

    #[tokio::test]
    async fn recorrelation_aggregates_scanned_updated_and_failed_counts_across_multiple_reports() {
        let storage = Arc::new(MockStorage::new());
        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        let scanner = Arc::new(PerArtifactScanner::new());
        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), policy).with_scanner(scanner.clone());

        // Three distinct artifacts, all clean at ingest, so three digest-keyed reports are stored.
        service
            .publish_package(scan_gate_request_for("alpha", "1.0.0", b"alpha artifact"))
            .await
            .unwrap();
        service
            .publish_package(scan_gate_request_for("beta", "1.0.0", b"beta artifact"))
            .await
            .unwrap();
        service
            .publish_package(scan_gate_request_for("gamma", "1.0.0", b"gamma artifact"))
            .await
            .unwrap();

        // Between ingest and the sweep, the feed evolves independently per subject: beta discloses a
        // new Critical advisory (its gate decision flips allow -> block), gamma's scan becomes
        // unavailable, and alpha stays clean and unchanged. ~keep
        scanner.set(
            "beta-1.0.0.tar.gz",
            ScanOutcome::Vulnerable(starmetal_core::policy::VulnSeverity::Critical),
        );
        scanner.set("gamma-1.0.0.tar.gz", ScanOutcome::Unavailable);

        let report = service.recorrelate().await.unwrap();
        assert_eq!(report.scanned, 3, "all three still-present reports are re-scanned");
        assert_eq!(report.updated, 1, "only beta's findings changed");
        assert_eq!(report.failed, 1, "gamma's re-scan errored and is counted as failed");
        assert_eq!(
            report.newly_blocking.len(),
            1,
            "exactly one artifact flips to blocking, got: {:?}",
            report.newly_blocking
        );
        assert!(
            report.newly_blocking.contains(&"pypi/beta/1.0.0".to_string()),
            "beta must be the artifact flagged newly blocking, got: {:?}",
            report.newly_blocking
        );
    }

    /// A publishing service whose scanner blocks the sample artifact, with ingest quarantine on, so a
    /// blocked hosted publish is held for review instead of denied.
    fn ingest_quarantining_publisher(storage: Arc<MockStorage>) -> CachingPackageService {
        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        CachingPackageService::new(storage, AHashMap::new(), policy)
            .with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Critical),
            }))
            .with_ingest_quarantine(true)
    }

    #[tokio::test]
    async fn ingest_holds_a_blocking_publish_instead_of_denying() {
        let storage = Arc::new(MockStorage::new());
        let publisher = ingest_quarantining_publisher(storage.clone());

        // The publish is accepted (not denied) but held.
        let result = publisher.publish_package(scan_gate_request()).await.unwrap();
        assert_eq!(result.version, "1.0.0");

        // The uploaded bytes are parked off the live path.
        let blake3 = integrity::blake3_hex(b"scanned artifact");
        assert_eq!(
            storage.get(&format!("_starmetal/held/{blake3}")).await.unwrap(),
            Some(Bytes::from_static(b"scanned artifact")),
            "the blocked publish's bytes are held under _starmetal/held/<blake3>"
        );
        assert!(
            storage
                .get(&format!("_starmetal/held/{blake3}.manifest.json"))
                .await
                .unwrap()
                .is_some(),
            "a reconstruction manifest is parked alongside the held bytes"
        );

        // An ingest-origin quarantine record is written.
        let records = publisher.list_quarantine().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, QuarantineState::Quarantined);
        assert_eq!(records[0].origin, QuarantineOrigin::Ingest);
        assert_eq!(records[0].artifact, sample_artifact_id());
        assert_eq!(
            records[0].reason_code,
            starmetal_core::supply_chain::PolicyReason::VulnSeverityExceeded
        );

        // The live path stays empty: the publish did not land.
        let name = PackageName::new("sample");
        assert!(
            publisher
                .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
                .await
                .is_err(),
            "a held publish must not write any live metadata"
        );
    }

    #[tokio::test]
    async fn promoting_an_ingest_hold_completes_the_publish() {
        let storage = Arc::new(MockStorage::new());
        let publisher = ingest_quarantining_publisher(storage.clone());
        let blake3 = integrity::blake3_hex(b"scanned artifact");
        publisher.publish_package(scan_gate_request()).await.unwrap();

        let promoted = publisher.promote_ingest(&blake3).await.unwrap();
        assert_eq!(promoted.state, QuarantineState::Promoted);
        assert!(promoted.decided_at.is_some());

        // The artifact now serves from the live path, having gone through the real publish path.
        let served = publisher.get_artifact(&sample_artifact_id()).await.unwrap();
        assert_eq!(served, Bytes::from_static(b"scanned artifact"));

        // The deferred publish's metadata landed, faithfully preserving the request's license.
        let name = PackageName::new("sample");
        let metadata = publisher
            .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
            .await
            .unwrap();
        assert_eq!(metadata.license.as_deref(), Some("MIT"));

        // The held bytes and manifest are purged once the publish completes.
        assert!(
            storage
                .get(&format!("_starmetal/held/{blake3}"))
                .await
                .unwrap()
                .is_none(),
            "held bytes are cleared after promotion"
        );
        assert!(
            storage
                .get(&format!("_starmetal/held/{blake3}.manifest.json"))
                .await
                .unwrap()
                .is_none(),
            "the held manifest is cleared after promotion"
        );
    }

    #[tokio::test]
    async fn rejecting_an_ingest_hold_purges_the_held_publish() {
        let storage = Arc::new(MockStorage::new());
        let publisher = ingest_quarantining_publisher(storage.clone());
        let blake3 = integrity::blake3_hex(b"scanned artifact");
        publisher.publish_package(scan_gate_request()).await.unwrap();

        let rejected = publisher.reject_ingest(&blake3).await.unwrap();
        assert_eq!(rejected.state, QuarantineState::Rejected);
        assert!(rejected.decided_at.is_some());

        // The held bytes and manifest are gone, so the publish can never land.
        assert!(
            storage
                .get(&format!("_starmetal/held/{blake3}"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .get(&format!("_starmetal/held/{blake3}.manifest.json"))
                .await
                .unwrap()
                .is_none()
        );
        let name = PackageName::new("sample");
        assert!(
            publisher
                .get_version_metadata(Ecosystem::PyPI, &name, "1.0.0")
                .await
                .is_err(),
            "a rejected hold never publishes"
        );
    }

    #[tokio::test]
    async fn a_blocked_publish_is_still_denied_when_ingest_quarantine_is_off() {
        let storage = Arc::new(MockStorage::new());
        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        // A scanner is attached and the finding exceeds the threshold, but ingest quarantine is off.
        let service =
            CachingPackageService::new(storage.clone(), AHashMap::new(), policy).with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Critical),
            }));

        let error = service.publish_package(scan_gate_request()).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::PolicyViolation(_)),
            "with ingest quarantine off a blocked publish is hard-denied, got: {error}"
        );

        // Nothing is held: the deny leaves no parked bytes.
        let blake3 = integrity::blake3_hex(b"scanned artifact");
        assert!(
            storage
                .get(&format!("_starmetal/held/{blake3}"))
                .await
                .unwrap()
                .is_none(),
            "a hard-denied publish parks no held bytes"
        );
    }

    #[tokio::test]
    async fn promoting_an_unknown_ingest_digest_is_not_found() {
        let storage = Arc::new(MockStorage::new());
        let publisher = ingest_quarantining_publisher(storage);
        let error = publisher.promote_ingest(&"0".repeat(64)).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::ArtifactNotFound(_)),
            "promoting a nonexistent ingest hold must be a not-found error, got: {error}"
        );
    }

    #[tokio::test]
    async fn promoting_one_coordinate_does_not_clear_the_gate_for_another_sharing_bytes() {
        // Regression (CWE-863): a promotion is scoped to the reviewed coordinate, not the content
        // digest. Promoting `sample@1.0.0` must not let an attacker republish the identical bytes
        // under a different coordinate and bypass the vulnerability gate.
        let storage = Arc::new(MockStorage::new());
        let publisher = ingest_quarantining_publisher(storage);
        let blake3 = integrity::blake3_hex(b"scanned artifact");

        // Hold, then promote, the sample coordinate — its bytes are now an operator-approved digest.
        publisher.publish_package(scan_gate_request()).await.unwrap();
        publisher.promote_ingest(&blake3).await.unwrap();
        assert!(
            publisher
                .get_version_metadata(Ecosystem::PyPI, &PackageName::new("sample"), "1.0.0")
                .await
                .is_ok(),
            "the promoted coordinate publishes live"
        );

        // A *different* coordinate with byte-identical content (same blake3) must still be held —
        // the promoted record for `sample` must not clear the gate for `evil`.
        let evil = scan_gate_request_for("evil", "1.0.0", b"scanned artifact");
        publisher.publish_package(evil).await.unwrap();
        assert!(
            publisher
                .get_version_metadata(Ecosystem::PyPI, &PackageName::new("evil"), "1.0.0")
                .await
                .is_err(),
            "a foreign coordinate sharing promoted bytes must not publish live (gate bypass closed)"
        );
    }

    /// A serve-enforcing service whose scanner blocks the sample artifact, with quarantine mode on.
    fn quarantining_server(storage: Arc<MockStorage>) -> CachingPackageService {
        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        CachingPackageService::new(storage, AHashMap::new(), policy)
            .with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Critical),
            }))
            .enforce_scan_on_serve(true)
            .with_quarantine(true)
    }

    #[tokio::test]
    async fn serve_holds_a_blocking_artifact_in_quarantine_instead_of_denying() {
        let storage = Arc::new(MockStorage::new());
        let publisher = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        publisher.publish_package(scan_gate_request()).await.unwrap();

        let server = quarantining_server(storage.clone());
        let error = server.get_artifact(&sample_artifact_id()).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::PolicyViolation(_)),
            "a held artifact is not served, got: {error}"
        );

        // A recoverable quarantine record is written for the digest.
        let records = server.list_quarantine().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, QuarantineState::Quarantined);
        assert_eq!(records[0].artifact, sample_artifact_id());
        assert_eq!(
            records[0].reason_code,
            starmetal_core::supply_chain::PolicyReason::VulnSeverityExceeded
        );
    }

    #[tokio::test]
    async fn promoting_a_quarantined_artifact_releases_it_for_serving() {
        let storage = Arc::new(MockStorage::new());
        let publisher = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        publisher.publish_package(scan_gate_request()).await.unwrap();

        let server = quarantining_server(storage.clone());
        let digest = integrity::blake3_hex(b"scanned artifact");
        // Held on first serve.
        server.get_artifact(&sample_artifact_id()).await.unwrap_err();

        let promoted = server.promote_quarantine(&digest).await.unwrap();
        assert_eq!(promoted.state, QuarantineState::Promoted);
        assert!(promoted.decided_at.is_some());

        // The operator override now permits serving despite the blocking scan.
        let served = server.get_artifact(&sample_artifact_id()).await.unwrap();
        assert_eq!(served, Bytes::from_static(b"scanned artifact"));
    }

    #[tokio::test]
    async fn rejecting_a_quarantined_artifact_keeps_it_unservable() {
        let storage = Arc::new(MockStorage::new());
        let publisher = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        publisher.publish_package(scan_gate_request()).await.unwrap();

        let server = quarantining_server(storage.clone());
        let digest = integrity::blake3_hex(b"scanned artifact");
        server.get_artifact(&sample_artifact_id()).await.unwrap_err();

        let rejected = server.reject_quarantine(&digest).await.unwrap();
        assert_eq!(rejected.state, QuarantineState::Rejected);

        let error = server.get_artifact(&sample_artifact_id()).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::PolicyViolation(_)),
            "a rejected artifact stays unservable, got: {error}"
        );
    }

    #[tokio::test]
    async fn promoting_an_unknown_digest_is_not_found() {
        let storage = Arc::new(MockStorage::new());
        let server = quarantining_server(storage);
        let error = server.promote_quarantine(&"0".repeat(64)).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::ArtifactNotFound(_)),
            "promoting a nonexistent record must be a not-found error, got: {error}"
        );
    }

    #[tokio::test]
    async fn promote_quarantine_rejects_a_malformed_digest_at_the_service_boundary() {
        // Defense in depth: even without a scanner attached, a non-blake3-hex digest must be
        // rejected by `transition_quarantine` itself, before it ever reaches `quarantine_record_key`
        // — proving the service layer is safe independently of the HTTP admin boundary's validation.
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());

        let error = service.promote_quarantine("../../config").await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::Adapter(_)),
            "a path-traversal digest must be rejected as an adapter error, got: {error}"
        );

        let error = service.reject_quarantine("not-a-hex-digest").await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::Adapter(_)),
            "a malformed digest passed to reject must be rejected the same way, got: {error}"
        );

        // Neither call ever built a storage key or touched storage: no reads, no writes.
        assert!(
            storage.list_prefix("").await.unwrap().is_empty(),
            "a malformed digest must never reach storage"
        );
    }

    #[tokio::test]
    async fn serve_denies_when_a_scan_on_demand_exceeds_the_threshold() {
        let storage = Arc::new(MockStorage::new());
        // Publish without a scanner so no report is stored: the serve gate must scan on demand.
        let publisher = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        publisher.publish_package(scan_gate_request()).await.unwrap();

        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        let server = CachingPackageService::new(storage.clone(), AHashMap::new(), policy)
            .with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Critical),
            }))
            .enforce_scan_on_serve(true);

        let error = server.get_artifact(&sample_artifact_id()).await.unwrap_err();
        assert!(
            matches!(error, StarmetalError::PolicyViolation(_)),
            "the serve gate must deny an over-threshold artifact, got: {error}"
        );

        // The scan-on-demand report is cached for subsequent serves.
        let blake3 = integrity::blake3_hex(b"scanned artifact");
        assert!(
            storage
                .get(&format!("_starmetal/scans/{blake3}.json"))
                .await
                .unwrap()
                .is_some(),
            "a scan-on-demand report is cached at serve"
        );
    }

    #[tokio::test]
    async fn serve_denies_when_a_scan_on_demand_exceeds_the_threshold_does_not_count_the_bytes() {
        let storage = Arc::new(MockStorage::new());
        // Publish without a scanner so the artifact is already cached: the denied serve below takes
        // the cache-hit branch, not the upstream-fetch miss branch.
        let publisher = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        publisher.publish_package(scan_gate_request()).await.unwrap();

        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        let server = CachingPackageService::new(storage.clone(), AHashMap::new(), policy)
            .with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Critical),
            }))
            .enforce_scan_on_serve(true);

        server.get_artifact(&sample_artifact_id()).await.unwrap_err();

        // A denied cache-hit serve must not be counted as served: the gate ran before the artifact
        // bytes ever left the service.
        let snapshot = server.statistics();
        let pypi = snapshot
            .ecosystems
            .get("pypi")
            .expect("pypi statistics should be present after the denied serve attempt");
        assert_eq!(pypi.bytes_served, 0, "a denied serve must not count bytes_served");
        assert_eq!(
            pypi.artifact_cache_hits, 0,
            "a denied serve must not count artifact_cache_hits"
        );
    }

    #[tokio::test]
    async fn serve_allows_when_the_finding_is_within_the_threshold() {
        let storage = Arc::new(MockStorage::new());
        let publisher = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        publisher.publish_package(scan_gate_request()).await.unwrap();

        // Default (Critical) threshold tolerates a Critical finding.
        let server = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default())
            .with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Critical),
            }))
            .enforce_scan_on_serve(true);

        let served = server.get_artifact(&sample_artifact_id()).await.unwrap();
        assert_eq!(served, Bytes::from_static(b"scanned artifact"));
    }

    #[tokio::test]
    async fn serve_is_unenforced_unless_opted_in() {
        let storage = Arc::new(MockStorage::new());
        let publisher = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        publisher.publish_package(scan_gate_request()).await.unwrap();

        // A scanner is attached and the finding exceeds the threshold, but serve enforcement is off.
        let policy = PolicyConfig {
            max_vuln_severity: starmetal_core::policy::VulnSeverity::High,
            ..PolicyConfig::default()
        };
        let server =
            CachingPackageService::new(storage.clone(), AHashMap::new(), policy).with_scanner(Arc::new(FakeScanner {
                severity: Some(starmetal_core::policy::VulnSeverity::Critical),
            }));

        let served = server.get_artifact(&sample_artifact_id()).await.unwrap();
        assert_eq!(served, Bytes::from_static(b"scanned artifact"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn publish_package_signs_artifacts_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let signing = SigningService::from_config(&signing_config(key_path)).unwrap().unwrap();
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new_with_signing(
            storage.clone(),
            AHashMap::new(),
            PolicyConfig::default(),
            Some(signing),
        );
        let name = PackageName::new("signed");
        let artifact_data = Bytes::from_static(b"signed artifact");

        service
            .publish_package(PublishRequest {
                ecosystem: Ecosystem::PyPI,
                name: name.clone(),
                version: "1.0.0".to_string(),
                license: Some("MIT".to_string()),
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename: "signed-1.0.0.tar.gz".to_string(),
                    data: artifact_data,
                    upstream_hashes: AHashMap::new(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
                allow_overwrite: false,
                allow_shadowing: false,
            })
            .await
            .unwrap();

        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: name.clone(),
            version: "1.0.0".to_string(),
            filename: "signed-1.0.0.tar.gz".to_string(),
        };
        let storage_key = artifact_id.storage_key();
        let sidecar_key = CachingPackageService::signature_sidecar_key(&storage_key);
        assert!(
            storage.get(&sidecar_key).await.unwrap().is_some(),
            "artifact signature sidecar should be stored"
        );
        let bundle_key = CachingPackageService::signature_bundle_key(
            Ecosystem::PyPI,
            &name,
            "1.0.0",
            "signed-1.0.0.tar.gz.sig.json",
        )
        .unwrap();
        assert!(
            storage.get(&bundle_key).await.unwrap().is_some(),
            "signature bundle should be stored"
        );

        let tampered = Bytes::from_static(b"tampered artifact");
        storage.put(&storage_key, tampered.clone()).await.unwrap();
        storage
            .put(
                &format!("{storage_key}.blake3"),
                Bytes::from(integrity::blake3_hex(&tampered)),
            )
            .await
            .unwrap();
        let err = service.get_artifact(&artifact_id).await.unwrap_err();
        assert!(matches!(err, StarmetalError::IntegrityError { .. }));
        assert!(err.to_string().contains("signature statement mismatch"));
    }

    #[cfg(unix)]
    fn signing_backed_service(key_path: PathBuf, storage: Arc<MockStorage>) -> CachingPackageService {
        let signing = SigningService::from_config(&signing_config(key_path)).unwrap().unwrap();
        CachingPackageService::new_with_signing(storage, AHashMap::new(), PolicyConfig::default(), Some(signing))
    }

    /// A stub external [`Verifier`] returning a fixed decision, for the port-delegation contract test.
    struct StubVerifier(PolicyDecision);

    #[async_trait]
    impl Verifier for StubVerifier {
        async fn verify(&self, _target: &VerificationTarget<'_>) -> Result<PolicyDecision> {
            Ok(self.0.clone())
        }
    }

    /// A [`Verifier`] that always fails with an I/O-style error, for the fail-closed contract test.
    struct ErroringVerifier;

    #[async_trait]
    impl Verifier for ErroringVerifier {
        async fn verify(&self, _target: &VerificationTarget<'_>) -> Result<PolicyDecision> {
            Err(StarmetalError::Storage("verifier backend unavailable".to_string()))
        }
    }

    fn pypi_publish(name: &str, filename: &str, data: &'static [u8]) -> PublishRequest {
        PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new(name),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: filename.to_string(),
                data: Bytes::from_static(data),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite: false,
            allow_shadowing: false,
        }
    }

    fn pypi_artifact_id(name: &str, filename: &str) -> ArtifactId {
        ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new(name),
            version: "1.0.0".to_string(),
            filename: filename.to_string(),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signature_provenance_gate_serves_a_signed_and_attested_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let storage = Arc::new(MockStorage::new());
        let service = signing_backed_service(key_path, storage.clone())
            .require_signature(true)
            .require_provenance(true)
            .emit_provenance(true);

        service
            .publish_package(pypi_publish("attested", "attested-1.0.0.tar.gz", b"attested bytes"))
            .await
            .unwrap();

        let artifact_id = pypi_artifact_id("attested", "attested-1.0.0.tar.gz");
        // The provenance attestation sidecar was produced on publish.
        assert!(
            storage
                .get(&CachingPackageService::attestation_sidecar_key(
                    &artifact_id.storage_key()
                ))
                .await
                .unwrap()
                .is_some(),
            "attestation sidecar stored"
        );
        // The serve gate passes: valid signature + provenance let the artifact be served.
        let served = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(served, Bytes::from_static(b"attested bytes"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn builtin_gate_denies_a_missing_signature() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let storage = Arc::new(MockStorage::new());
        let service = signing_backed_service(key_path, storage).require_signature(true);

        // No signature sidecar was ever produced, so the built-in gate denies.
        let artifact_id = pypi_artifact_id("unsigned", "unsigned-1.0.0.tar.gz");
        let data = Bytes::from_static(b"unsigned");
        let error = service
            .enforce_verification(
                &artifact_id,
                &artifact_id.storage_key(),
                &integrity::blake3_hex(&data),
                &data,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, StarmetalError::PolicyViolation(_)));
        assert!(error.to_string().contains("signature"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn builtin_verify_provenance_binds_the_subject_name_and_digest() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let storage = Arc::new(MockStorage::new());
        // Publish with signing on but provenance emission off: a signature exists, no attestation.
        let service = signing_backed_service(key_path, storage);
        service
            .publish_package(pypi_publish("signed", "signed-1.0.0.tar.gz", b"signed bytes"))
            .await
            .unwrap();

        let artifact_id = pypi_artifact_id("signed", "signed-1.0.0.tar.gz");
        let storage_key = artifact_id.storage_key();
        let blake3 = integrity::blake3_hex(&Bytes::from_static(b"signed bytes"));

        // No attestation at all -> deny.
        let decision = service.verify_provenance(&storage_key, &blake3).await.unwrap();
        assert_eq!(
            decision.and_then(|d| d.reason_code()),
            Some(PolicyReason::FailingProvenance)
        );

        // Now emit an attestation, then confirm the check binds BOTH subject name and digest: a
        // matching pair passes, a mismatched digest (same key) is rejected — a valid attestation for
        // one artifact cannot cover a different-bytes artifact at the same key.
        let mut staged = Vec::new();
        service
            .sign_and_store_attestation(
                Ecosystem::PyPI,
                &artifact_id.name,
                &storage_key,
                &blake3,
                "t",
                &mut staged,
            )
            .await
            .unwrap();
        assert_eq!(
            service.verify_provenance(&storage_key, &blake3).await.unwrap(),
            None,
            "matching subject passes"
        );
        let decision = service.verify_provenance(&storage_key, "deadbeef").await.unwrap();
        assert_eq!(
            decision.and_then(|d| d.reason_code()),
            Some(PolicyReason::FailingProvenance),
            "a subject-digest mismatch is denied"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ingest_gate_denies_and_rolls_back_when_required_provenance_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let storage = Arc::new(MockStorage::new());
        // Require provenance at the gate, but do NOT emit it — the ingest gate must deny the publish.
        let service = signing_backed_service(key_path, storage.clone()).require_provenance(true);

        let error = service
            .publish_package(pypi_publish("no-prov", "no-prov-1.0.0.tar.gz", b"no provenance"))
            .await
            .unwrap_err();
        assert!(matches!(error, StarmetalError::PolicyViolation(_)));
        assert!(error.to_string().contains(PolicyReason::FailingProvenance.as_str()));

        // The denied publish rolled back: the artifact bytes were not left in storage.
        let artifact_id = pypi_artifact_id("no-prov", "no-prov-1.0.0.tar.gz");
        assert!(
            storage.get(&artifact_id.storage_key()).await.unwrap().is_none(),
            "denied publish must roll back the staged artifact write"
        );
    }

    /// Build a service whose gate is driven only by an external stub verifier (no signing).
    fn service_with_stub_verifier(storage: Arc<MockStorage>, verifier: Arc<dyn Verifier>) -> CachingPackageService {
        CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default()).with_verifier(verifier)
    }

    #[tokio::test]
    async fn external_verifier_decision_drives_the_gate_across_all_variants() {
        // Contract test for the pluggable `Verifier` port. `blocks_serving()` semantics: Deny and
        // Quarantine block; Allow and Warn pass.
        let storage = Arc::new(MockStorage::new());
        let artifact_id = pypi_artifact_id("ext", "ext-1.0.0.tar.gz");
        let data = Bytes::from_static(b"ext");
        let gate = |verifier: Arc<dyn Verifier>| {
            let storage = storage.clone();
            let artifact_id = artifact_id.clone();
            let data = data.clone();
            async move {
                service_with_stub_verifier(storage, verifier)
                    .enforce_verification(&artifact_id, &artifact_id.storage_key(), "abc", &data)
                    .await
            }
        };

        let stub = |decision: PolicyDecision| Arc::new(StubVerifier(decision)) as Arc<dyn Verifier>;
        gate(stub(PolicyDecision::allow())).await.expect("Allow passes");
        gate(stub(PolicyDecision::warn(PolicyReason::MissingSignature, "advisory")))
            .await
            .expect("Warn passes (non-blocking)");
        assert!(
            matches!(
                gate(stub(PolicyDecision::deny(PolicyReason::FailingProvenance, "no"))).await,
                Err(StarmetalError::PolicyViolation(_))
            ),
            "Deny blocks"
        );
        assert!(
            matches!(
                gate(stub(PolicyDecision::quarantine(
                    PolicyReason::VulnSeverityExceeded,
                    "held"
                )))
                .await,
                Err(StarmetalError::PolicyViolation(_))
            ),
            "Quarantine blocks"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_external_verifier_replaces_the_builtin_signature_gate() {
        // With require_signature on AND an Allow-returning external verifier attached, the built-in
        // missing-signature check must be *replaced* (skipped) — proving the external verifier is the
        // sole authority, not an additional one. No signature is ever produced here.
        let storage = Arc::new(MockStorage::new());
        let allower = Arc::new(StubVerifier(PolicyDecision::allow())) as Arc<dyn Verifier>;
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default())
            .require_signature(true)
            .with_verifier(allower);
        let artifact_id = pypi_artifact_id("ext", "ext-1.0.0.tar.gz");
        service
            .enforce_verification(
                &artifact_id,
                &artifact_id.storage_key(),
                "abc",
                &Bytes::from_static(b"ext"),
            )
            .await
            .expect("an external Allow replaces (skips) the built-in require_signature check");
    }

    #[tokio::test]
    async fn cache_fill_verification_denial_rolls_back_the_cached_bytes() {
        let storage = Arc::new(MockStorage::new());
        let filename = "pkg-1.0.0.tar.gz";
        let mut artifacts = AHashMap::new();
        artifacts.insert(filename.to_string(), Bytes::from_static(b"upstream artifact"));
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", filename, AHashMap::new()),
        );
        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![VersionInfo {
                version: "1.0.0".to_string(),
                yanked: false,
            }],
            metadata,
            artifacts,
        };
        // require_provenance with no signing configured => the built-in gate denies at cache-fill,
        // exercising the upstream-fetch rollback path (distinct from the cache-hit/publish paths).
        let service = build_service(storage.clone(), upstream, PolicyConfig::default()).require_provenance(true);
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: filename.to_string(),
        };

        let error = service.get_artifact(&artifact_id).await.unwrap_err();
        assert!(matches!(error, StarmetalError::PolicyViolation(_)));
        assert!(error.to_string().contains(PolicyReason::FailingProvenance.as_str()));

        // The just-cached (unverifiable) bytes and their sidecar were rolled back, not left behind.
        let key = artifact_id.storage_key();
        assert!(storage.get(&key).await.unwrap().is_none(), "artifact bytes rolled back");
        assert!(
            storage.get(&format!("{key}.blake3")).await.unwrap().is_none(),
            "blake3 sidecar rolled back"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cache_fill_deny_also_rolls_back_a_staged_signature_sidecar() {
        // With signing + sign_cached_upstream on, a cache-fill stages a signature sidecar *before*
        // the provenance gate denies — the rollback must remove that sidecar too, not just the bytes.
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let mut config = signing_config(key_path);
        config.sign_cached_upstream = true;
        let signing = SigningService::from_config(&config).unwrap().unwrap();

        let storage = Arc::new(MockStorage::new());
        let filename = "pkg-1.0.0.tar.gz";
        let mut artifacts = AHashMap::new();
        artifacts.insert(filename.to_string(), Bytes::from_static(b"upstream artifact"));
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", filename, AHashMap::new()),
        );
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();
        clients.insert(
            Ecosystem::PyPI,
            Arc::new(MockUpstream {
                eco: Ecosystem::PyPI,
                versions: vec![VersionInfo {
                    version: "1.0.0".to_string(),
                    yanked: false,
                }],
                metadata,
                artifacts,
            }),
        );
        // require_provenance but emit none: the fill signs the artifact, then the gate denies.
        let service =
            CachingPackageService::new_with_signing(storage.clone(), clients, PolicyConfig::default(), Some(signing))
                .require_provenance(true);

        let artifact_id = pypi_artifact_id("pkg", filename);
        let error = service.get_artifact(&artifact_id).await.unwrap_err();
        assert!(matches!(error, StarmetalError::PolicyViolation(_)));

        let key = artifact_id.storage_key();
        assert!(storage.get(&key).await.unwrap().is_none(), "artifact bytes rolled back");
        assert!(
            storage
                .get(&CachingPackageService::signature_sidecar_key(&key))
                .await
                .unwrap()
                .is_none(),
            "the signature sidecar staged during cache-fill was rolled back"
        );
    }

    #[test]
    fn gates_signature_reflects_the_signature_controls() {
        let storage = Arc::new(MockStorage::new());
        let base = || CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        assert!(!base().gates_signature(), "off by default");
        assert!(
            base().require_signature(true).gates_signature(),
            "require_signature gates"
        );
        assert!(
            base()
                .with_verifier(Arc::new(StubVerifier(PolicyDecision::allow())))
                .gates_signature(),
            "an external verifier gates"
        );
        assert!(
            !base().require_provenance(true).gates_signature(),
            "provenance alone does not gate the signature (so verify-on-read still runs)"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verify_provenance_rejects_an_attestation_naming_a_different_subject() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let storage = Arc::new(MockStorage::new());
        // The service and a standalone signer share the same key, so the service verifies what the
        // signer produces.
        let service = signing_backed_service(key_path.clone(), storage.clone());
        let signer = SigningService::from_config(&signing_config(key_path)).unwrap().unwrap();

        let artifact_id = pypi_artifact_id("victim", "victim-1.0.0.tar.gz");
        let storage_key = artifact_id.storage_key();
        let blake3 = integrity::blake3_hex(&Bytes::from_static(b"victim bytes"));

        // Plant, at the victim's attestation sidecar, a validly-signed attestation whose subject NAME
        // is a different coordinate (but the same digest). Binding on digest alone would accept it.
        let statement = attestation::provenance_statement(
            "pypi/impostor/9.9.9/impostor.tgz",
            &blake3,
            "https://starmetal.dev",
            "t",
        );
        let envelope = signer
            .sign_attestation(
                Ecosystem::PyPI,
                &artifact_id.name,
                &serde_json::to_vec(&statement).unwrap(),
            )
            .unwrap();
        storage
            .put(
                &CachingPackageService::attestation_sidecar_key(&storage_key),
                Bytes::from(serde_json::to_vec(&envelope).unwrap()),
            )
            .await
            .unwrap();

        let decision = service.verify_provenance(&storage_key, &blake3).await.unwrap();
        assert_eq!(
            decision.and_then(|d| d.reason_code()),
            Some(PolicyReason::FailingProvenance),
            "a subject-name mismatch is denied even with a matching digest"
        );
    }

    #[tokio::test]
    async fn a_verifier_error_propagates_as_an_error_not_a_policy_denial() {
        // A broken external verifier (I/O failure) must fail closed as a genuine error, not be
        // silently swallowed or mis-mapped to a policy allow — mirroring the Scanner port's
        // fail-closed contract.
        let storage = Arc::new(MockStorage::new());
        let erroring = Arc::new(ErroringVerifier) as Arc<dyn Verifier>;
        let service = service_with_stub_verifier(storage, erroring);
        let artifact_id = pypi_artifact_id("ext", "ext-1.0.0.tar.gz");
        let error = service
            .enforce_verification(
                &artifact_id,
                &artifact_id.storage_key(),
                "abc",
                &Bytes::from_static(b"ext"),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, StarmetalError::Storage(_)),
            "a verifier I/O error propagates verbatim, not as a policy violation"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signed_artifact_read_does_not_depend_on_publish_record() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o600);
        let signing = SigningService::from_config(&signing_config(key_path)).unwrap().unwrap();
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new_with_signing(
            storage.clone(),
            AHashMap::new(),
            PolicyConfig::default(),
            Some(signing),
        );
        let name = PackageName::new("recordless");

        service
            .publish_package(PublishRequest {
                ecosystem: Ecosystem::PyPI,
                name: name.clone(),
                version: "1.0.0".to_string(),
                license: Some("MIT".to_string()),
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename: "recordless-1.0.0.tar.gz".to_string(),
                    data: Bytes::from_static(b"signed artifact"),
                    upstream_hashes: AHashMap::new(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
                allow_overwrite: false,
                allow_shadowing: false,
            })
            .await
            .unwrap();

        let record_key = CachingPackageService::published_record_key(Ecosystem::PyPI, &name, "1.0.0").unwrap();
        storage.delete(&record_key).await.unwrap();
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name,
            version: "1.0.0".to_string(),
            filename: "recordless-1.0.0.tar.gz".to_string(),
        };
        let storage_key = artifact_id.storage_key();
        let tampered = Bytes::from_static(b"tampered artifact");
        storage.put(&storage_key, tampered.clone()).await.unwrap();
        storage
            .put(
                &format!("{storage_key}.blake3"),
                Bytes::from(integrity::blake3_hex(&tampered)),
            )
            .await
            .unwrap();

        let err = service.get_artifact(&artifact_id).await.unwrap_err();

        assert!(matches!(err, StarmetalError::IntegrityError { .. }));
        assert!(err.to_string().contains("signature statement mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn signing_service_rejects_group_accessible_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("signing.pk8");
        write_test_signing_key(&key_path, 0o640);

        let err = match SigningService::from_config(&signing_config(key_path)) {
            Ok(_) => panic!("group-readable private key should be rejected"),
            Err(err) => err.to_string(),
        };

        assert!(err.contains("must not be group/world-readable or writable"));
    }

    #[cfg(unix)]
    #[test]
    fn signing_service_rejects_verify_only_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("verify-only.pk8");
        write_test_signing_key(&key_path, 0o600);
        let mut config = signing_config(key_path.clone());
        config.mode = SigningMode::VerifyOnly;
        config.keys[0].status = SigningKeyStatus::VerifyOnly;

        let err = match SigningService::from_config(&config) {
            Ok(_) => panic!("verify-only key with private material should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("must use public_key_file"));
    }

    #[cfg(unix)]
    #[test]
    fn verify_only_public_key_verifies_existing_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let private_key_path = dir.path().join("signing.pk8");
        let public_key_path = dir.path().join("signing.pub.pem");
        write_test_signing_key(&private_key_path, 0o600);
        write_test_verification_key(&public_key_path, 0o644);
        let signing = SigningService::from_config(&signing_config(private_key_path))
            .unwrap()
            .unwrap();
        let statement = signing
            .statement(StatementInput {
                ecosystem: Ecosystem::PyPI,
                package: PackageName::new("signed"),
                version: "1.0.0".to_string(),
                filename: None,
                storage_key: "pypi/signed/1.0.0/_metadata.json".to_string(),
                size: 2,
                blake3: integrity::blake3_hex(&Bytes::from_static(b"{}")),
                upstream_hashes: AHashMap::new(),
                source: SignatureSource::Metadata,
            })
            .unwrap();
        let envelope = signing.sign_statement(statement).unwrap();
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        let verify_config = SigningConfig {
            enabled: true,
            mode: SigningMode::VerifyOnly,
            verify_on_read: true,
            sign_cached_upstream: false,
            keys: vec![SigningKeyConfig {
                id: "test-key".to_string(),
                algorithm: SigningAlgorithm::Ed25519,
                private_key_file: None,
                public_key_file: Some(public_key_path),
                private_key_password_env: None,
                certificate_file: None,
                certificate_chain_file: None,
                ecosystems: vec![Ecosystem::PyPI],
                packages: Vec::new(),
                status: SigningKeyStatus::VerifyOnly,
            }],
            trust_roots: Vec::new(),
        };
        let verifier = SigningService::from_config(&verify_config).unwrap().unwrap();

        let verified = verifier.verify_envelope(&envelope_bytes).unwrap();

        assert_eq!(verified.key_id, "test-key");
        assert_eq!(verified.package, PackageName::new("signed"));
    }

    #[tokio::test]
    async fn publish_package_allows_new_local_package_when_upstream_package_not_found() {
        let storage = Arc::new(MockStorage::new());
        let service = build_service_with_missing_package_upstream(storage, Ecosystem::Npm);
        let name = PackageName::new("local-pnpm");

        service
            .publish_package(PublishRequest {
                ecosystem: Ecosystem::Npm,
                name: name.clone(),
                version: "1.0.0".to_string(),
                license: Some("MIT".to_string()),
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename: "local-pnpm-1.0.0.tgz".to_string(),
                    data: Bytes::from_static(b"published artifact"),
                    upstream_hashes: AHashMap::new(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Npm),
                allow_overwrite: false,
                allow_shadowing: false,
            })
            .await
            .unwrap();

        let versions = service.list_versions(Ecosystem::Npm, &name).await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "1.0.0");
        assert!(!versions[0].yanked);
    }

    #[tokio::test]
    async fn publish_package_rejects_duplicate_version_by_default() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        let request = PublishRequest {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.tgz".to_string(),
                data: Bytes::from_static(b"published artifact"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Npm),
            allow_overwrite: false,
            allow_shadowing: false,
        };

        service.publish_package(request.clone()).await.unwrap();
        let err = service.publish_package(request).await.unwrap_err();

        assert!(matches!(err, StarmetalError::Publish(_)));
        assert!(err.to_string().contains("version already exists"));
    }

    #[tokio::test]
    async fn publish_package_overwrite_merges_artifacts_for_existing_version() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());
        let base = PublishRequest {
            ecosystem: Ecosystem::Maven,
            name: PackageName::new("com.example:sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.pom".to_string(),
                data: Bytes::from_static(b"pom"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Maven),
            allow_overwrite: false,
            allow_shadowing: false,
        };
        service.publish_package(base).await.unwrap();

        service
            .publish_package(PublishRequest {
                artifacts: vec![PublishedArtifact {
                    filename: "sample-1.0.0.jar".to_string(),
                    data: Bytes::from_static(b"jar"),
                    upstream_hashes: AHashMap::new(),
                }],
                allow_overwrite: true,
                allow_shadowing: false,
                ecosystem: Ecosystem::Maven,
                name: PackageName::new("com.example:sample"),
                version: "1.0.0".to_string(),
                license: None,
                yanked: false,
                listed: true,
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Maven),
            })
            .await
            .unwrap();

        let metadata = service
            .get_version_metadata(Ecosystem::Maven, &PackageName::new("com.example:sample"), "1.0.0")
            .await
            .unwrap();
        let filenames = metadata
            .artifacts
            .iter()
            .map(|artifact| artifact.filename.as_str())
            .collect::<Vec<_>>();
        assert_eq!(filenames, vec!["sample-1.0.0.pom", "sample-1.0.0.jar"]);
        assert_eq!(metadata.license.as_deref(), Some("MIT"));
    }

    #[tokio::test]
    async fn publish_package_rejects_upstream_shadowing_by_default() {
        let storage = Arc::new(MockStorage::new());
        let mut metadata = AHashMap::new();
        metadata.insert("1.0.0".to_string(), test_metadata("sample", "1.0.0"));
        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
        };
        let service = build_service(storage, upstream, PolicyConfig::default());
        let request = PublishRequest {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("sample"),
            version: "1.0.0".to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: "sample-1.0.0.crate".to_string(),
                data: Bytes::from_static(b"published artifact"),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::Cargo),
            allow_overwrite: false,
            allow_shadowing: false,
        };

        let err = service.publish_package(request).await.unwrap_err();

        assert!(matches!(err, StarmetalError::Publish(_)));
        assert!(err.to_string().contains("refusing to shadow upstream"));
    }

    #[tokio::test]
    async fn set_yanked_updates_metadata_and_version_listing() {
        let storage = Arc::new(MockStorage::new());
        let service = CachingPackageService::new(storage.clone(), AHashMap::new(), PolicyConfig::default());
        let name = PackageName::new("sample");
        service
            .publish_package(PublishRequest {
                ecosystem: Ecosystem::RubyGems,
                name: name.clone(),
                version: "1.0.0".to_string(),
                license: Some("MIT".to_string()),
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename: "sample-1.0.0.gem".to_string(),
                    data: Bytes::from_static(b"published artifact"),
                    upstream_hashes: AHashMap::new(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(Ecosystem::RubyGems),
                allow_overwrite: false,
                allow_shadowing: false,
            })
            .await
            .unwrap();

        let metadata = service
            .set_yanked(YankRequest {
                ecosystem: Ecosystem::RubyGems,
                name: name.clone(),
                version: "1.0.0".to_string(),
                yanked: true,
            })
            .await
            .unwrap();

        assert!(metadata.yanked);
        let versions = service.list_versions(Ecosystem::RubyGems, &name).await.unwrap();
        assert!(versions[0].yanked);

        let record_key = CachingPackageService::published_record_key(Ecosystem::RubyGems, &name, "1.0.0").unwrap();
        let record = storage
            .get(&record_key)
            .await
            .unwrap()
            .expect("publish record should be stored");
        let record: PublishRecord = serde_json::from_slice(&record).unwrap();
        assert!(record.yanked);
    }

    #[tokio::test]
    async fn cached_metadata_is_rechecked_against_current_policy() {
        let name = PackageName::new("cached-pkg");
        let cached_metadata = VersionMetadata {
            license: Some("GPL-3.0".to_string()),
            ..test_metadata("cached-pkg", "1.0.0")
        };
        let key = CachingPackageService::metadata_key(Ecosystem::Npm, &name, "1.0.0").unwrap();
        let storage = Arc::new(MockStorage::with_data(vec![(
            &key,
            Bytes::from(serde_json::to_vec(&cached_metadata).unwrap()),
        )]));
        let upstream = MockUpstream {
            eco: Ecosystem::Npm,
            versions: vec![],
            metadata: AHashMap::new(),
            artifacts: AHashMap::new(),
        };
        let policy = PolicyConfig {
            allowed_licenses: vec!["MIT".to_string()],
            ..Default::default()
        };
        let service = build_service(storage, upstream, policy);

        let result = service.get_version_metadata(Ecosystem::Npm, &name, "1.0.0").await;

        assert!(matches!(result, Err(StarmetalError::PolicyViolation(_))));
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
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact("requests", "2.31.0", "requests-2.31.0.tar.gz", AHashMap::new()),
        );

        let storage = Arc::new(MockStorage::with_data(vec![
            (&artifact_id.storage_key(), artifact_data.clone()),
            (&format!("{}.blake3", artifact_id.storage_key()), Bytes::from(hash)),
        ]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data, "should return verified cached artifact");
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
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact("requests", "2.31.0", "requests-2.31.0.tar.gz", AHashMap::new()),
        );

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
            metadata,
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
    async fn integrity_rejects_cached_artifact_without_sidecar() {
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "2.31.0".to_string(),
            filename: "requests-2.31.0.tar.gz".to_string(),
        };
        let artifact_data = Bytes::from_static(b"unverified data");
        let mut metadata = AHashMap::new();
        metadata.insert(
            "2.31.0".to_string(),
            test_metadata_with_artifact("requests", "2.31.0", "requests-2.31.0.tar.gz", AHashMap::new()),
        );

        let storage = Arc::new(MockStorage::with_data(vec![(
            &artifact_id.storage_key(),
            artifact_data,
        )]));

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts: AHashMap::new(),
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let result = service.get_artifact(&artifact_id).await;
        assert!(result.is_err(), "should reject unverified cached artifact");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing sidecar"),
            "error should mention missing sidecar, got: {err}"
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
        assert!(result.is_err(), "should block artifact download for blocked package");
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
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", AHashMap::new()),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata,
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

    #[tokio::test]
    async fn records_cache_statistics_for_artifact_fetches() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"upstream content");
        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tgz".to_string(), artifact_data.clone());
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tgz", AHashMap::new()),
        );
        let upstream = MockUpstream {
            eco: Ecosystem::Npm,
            versions: vec![],
            metadata,
            artifacts,
        };
        let service = build_service(storage, upstream, PolicyConfig::default());
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tgz".to_string(),
        };

        let first = service.get_artifact(&artifact_id).await.unwrap();
        let second = service.get_artifact(&artifact_id).await.unwrap();

        assert_eq!(first, artifact_data);
        assert_eq!(second, artifact_data);
        let snapshot = service.statistics();
        let npm = snapshot
            .ecosystems
            .get("npm")
            .expect("npm statistics should be present");
        assert_eq!(npm.metadata_cache_misses, 1);
        assert_eq!(npm.metadata_cache_hits, 1);
        assert_eq!(npm.artifact_cache_misses, 1);
        assert_eq!(npm.artifact_cache_hits, 1);
        assert_eq!(npm.bytes_served, (artifact_data.len() * 2) as u64);
        assert!(npm.last_activity_unix_seconds.is_some());
    }

    #[tokio::test]
    async fn upstream_sha256_verified_before_cache_store() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"upstream content");
        let sha256 = hex::encode(sha2::Sha256::digest(&artifact_data));
        let mut upstream_hashes = AHashMap::new();
        upstream_hashes.insert("sha256".to_string(), sha256);

        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tar.gz".to_string(), artifact_data.clone());
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", upstream_hashes),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts,
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data);
    }

    #[tokio::test]
    async fn upstream_sha256_mismatch_rejected() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"upstream content");
        let mut upstream_hashes = AHashMap::new();
        upstream_hashes.insert("sha256".to_string(), "0".repeat(64));

        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tar.gz".to_string(), artifact_data);
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", upstream_hashes),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::Cargo,
            versions: vec![],
            metadata,
            artifacts,
        };

        let service = build_service(storage.clone(), upstream, PolicyConfig::default());
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await;
        assert!(result.is_err(), "should reject upstream hash mismatch");
        assert!(
            storage.get(&artifact_id.storage_key()).await.unwrap().is_none(),
            "mismatched artifact must not be cached"
        );
    }

    #[tokio::test]
    async fn upstream_npm_sri_verified_before_cache_store() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"npm tarball");
        let sri = format!(
            "sha512-{}",
            BASE64_STANDARD.encode(sha2::Sha512::digest(&artifact_data))
        );
        let mut upstream_hashes = AHashMap::new();
        upstream_hashes.insert("integrity".to_string(), sri);

        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tgz".to_string(), artifact_data.clone());
        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            test_metadata_with_artifact("pkg", "1.0.0", "pkg-1.0.0.tgz", upstream_hashes),
        );

        let upstream = MockUpstream {
            eco: Ecosystem::Npm,
            versions: vec![],
            metadata,
            artifacts,
        };

        let service = build_service(storage, upstream, PolicyConfig::default());
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tgz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await.unwrap();
        assert_eq!(result, artifact_data);
    }

    #[tokio::test]
    async fn license_policy_blocks_artifact_download() {
        let storage = Arc::new(MockStorage::new());
        let artifact_data = Bytes::from_static(b"package");
        let mut artifacts = AHashMap::new();
        artifacts.insert("pkg-1.0.0.tar.gz".to_string(), artifact_data);

        let mut metadata = AHashMap::new();
        metadata.insert(
            "1.0.0".to_string(),
            VersionMetadata {
                name: PackageName::new("pkg"),
                version: "1.0.0".to_string(),
                artifacts: vec![ArtifactDigest {
                    filename: "pkg-1.0.0.tar.gz".to_string(),
                    blake3: String::new(),
                    size: 0,
                    upstream_hashes: AHashMap::new(),
                }],
                license: None,
                yanked: false,
                listed: None,
                protocol_metadata: None,
            },
        );

        let upstream = MockUpstream {
            eco: Ecosystem::PyPI,
            versions: vec![],
            metadata,
            artifacts,
        };
        let policy = PolicyConfig {
            block_unlicensed: true,
            ..Default::default()
        };
        let service = build_service(storage, upstream, policy);
        let artifact_id = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("pkg"),
            version: "1.0.0".to_string(),
            filename: "pkg-1.0.0.tar.gz".to_string(),
        };

        let result = service.get_artifact(&artifact_id).await;
        assert!(result.is_err(), "license policy should block artifact");
        assert!(result.unwrap_err().to_string().contains("has no license"));
    }
}
