//! Serve-time supply-chain gate and maintenance surface (ADR-0024).
//!
//! Extends [`CachingPackageService`](super::CachingPackageService) with the serve/ingest
//! vulnerability, signature, and provenance gates, plus the quarantine, re-correlation, and SBOM
//! index surfaces. As a child module it reaches the service's private fields directly; the mod.rs
//! serve/publish paths drive the gate through the `pub(in crate::service)` methods here.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::{self, StreamExt};
use starmetal_core::attestation;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::integrity;
use starmetal_core::package::ArtifactId;
use starmetal_core::sbom;
use starmetal_core::supply_chain::{
    PolicyDecision, PolicyReason, QuarantineOrigin, QuarantineRecord, QuarantineReview, QuarantineState,
    RecorrelationReport, Sbom, SbomFormat, SbomIndex, ScanReport, ScanTarget, Scanner, SupplyChainMaintenance,
    VerificationTarget, evaluate_scan_report,
};

use super::{CachingPackageService, unix_now};

/// Storage key prefix under which digest-keyed scan reports are persisted. Scheduled re-correlation
/// enumerates this prefix to find every stored report.
pub(in crate::service) const SCAN_REPORT_PREFIX: &str = "_starmetal/scans/";

/// Storage key prefix under which digest-keyed quarantine records are persisted. The quarantine
/// review API enumerates this prefix to list held artifacts.
pub(in crate::service) const QUARANTINE_PREFIX: &str = "_starmetal/quarantine/";

/// Storage key prefix under which SBOM documents are persisted, keyed by the artifact's validated
/// coordinate (ecosystem/name/version/filename) plus format — *not* its content digest, since an
/// SBOM embeds coordinate identity and license and must not collide between two coordinates that
/// share bytes (see `sbom_key`).
pub(in crate::service) const SBOM_PREFIX: &str = "_starmetal/sbom/";

/// Bounded fan-out for the `recorrelate` re-scan sweep. Caps how many OSV lookups run concurrently
/// so scheduled maintenance overlaps network-bound scans without unbounded fan-out to the upstream
/// advisory feed (a bounded, not unbounded, concurrent request burst).
const RECORRELATION_CONCURRENCY: usize = 8;

/// Per-key outcome of re-correlating one persisted scan report, folded into the aggregate
/// `RecorrelationReport` by `recorrelate` after the bounded-concurrency sweep completes. Returned as
/// an owned value (rather than mutating a shared `&mut report`) so per-key work can run concurrently
/// without sharing mutable state across tasks.
struct RecorrelationOutcome {
    scanned: bool,
    updated: bool,
    failed: bool,
    newly_blocking: Option<String>,
}

impl RecorrelationOutcome {
    const SKIPPED: Self = Self {
        scanned: false,
        updated: false,
        failed: false,
        newly_blocking: None,
    };
}

/// On-disk envelope for a persisted scan report.
///
/// The digest-keyed sidecar carries the [`ScanReport`] plus the artifact coordinate it was produced
/// for. The coordinate is needed by scheduled re-correlation: coordinate-keyed scanners (OSV) query
/// the advisory feed by `ecosystem/name/version`, not by content digest, so a sweep must recover the
/// coordinate to re-scan. The serve gate reads only `report`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(in crate::service) struct PersistedScanReport {
    pub(in crate::service) artifact: ArtifactId,
    pub(in crate::service) report: ScanReport,
}

impl CachingPackageService {
    /// Enforce the serve-time vulnerability gate for one artifact's bytes. A no-op unless a scanner is
    /// attached and serve enforcement is enabled. Loads the digest-keyed scan report, scanning on
    /// demand and caching it when absent, then denies with a `PolicyViolation` when the report exceeds
    /// `policy.max_vuln_severity`. A scan that cannot complete fails the serve closed.
    pub(in crate::service) async fn enforce_serve_scan(
        &self,
        artifact_id: &ArtifactId,
        blake3: &str,
        data: &Bytes,
    ) -> Result<()> {
        let Some(scanner) = &self.scanner else {
            return Ok(());
        };
        if !self.enforce_on_serve {
            return Ok(());
        }

        let report_key = Self::scan_report_key(blake3);
        let report = match self.storage.get(&report_key).await? {
            Some(bytes) => serde_json::from_slice::<PersistedScanReport>(&bytes)?.report,
            None => {
                let report = scanner.scan(ScanTarget::new(artifact_id, data)).await?;
                // Cache the report so subsequent serves of the same bytes skip the upstream scan.
                let persisted = PersistedScanReport {
                    artifact: artifact_id.clone(),
                    report: report.clone(),
                };
                self.storage
                    .put(&report_key, Bytes::from(serde_json::to_vec(&persisted)?))
                    .await?;
                report
            }
        };

        let decision = evaluate_scan_report(&report, self.policy.max_vuln_severity);
        if !decision.blocks_serving() {
            return Ok(());
        }
        let reason = decision
            .reason()
            .unwrap_or("vulnerability policy violation")
            .to_string();
        if !self.quarantine {
            return Err(StarmetalError::PolicyViolation(reason));
        }
        self.enforce_quarantine(artifact_id, blake3, decision.reason_code(), reason)
            .await
    }

    /// Enforce the signature/provenance gate (ADR-0024) for one artifact. Used at both serve
    /// (`get_artifact`) and ingest (`publish_package`), it denies with `PolicyViolation` (fail
    /// closed) on any failure.
    ///
    /// An attached external verifier *replaces* the built-in check (the cosign/sigstore seam).
    /// Otherwise the built-in own-graph gate reuses [`verify_artifact_signature`](Self::verify_artifact_signature)
    /// for the signature — the same verification as signing verify-on-read, so the signature is read
    /// and checked once, not twice — and [`verify_provenance`](Self::verify_provenance) for the
    /// attestation.
    pub(in crate::service) async fn enforce_verification(
        &self,
        artifact_id: &ArtifactId,
        storage_key: &str,
        blake3: &str,
        data: &Bytes,
    ) -> Result<()> {
        if let Some(verifier) = &self.verifier {
            let target = VerificationTarget {
                artifact_id,
                storage_key,
                blake3,
            };
            return Self::apply_verification(verifier.verify(&target).await?);
        }

        if self.require_signature
            && self
                .verify_artifact_signature(artifact_id, storage_key, data)
                .await
                .is_err()
        {
            return Self::apply_verification(PolicyDecision::deny(
                PolicyReason::MissingSignature,
                "no valid signature for the artifact",
            ));
        }
        if self.require_provenance
            && let Some(decision) = self.verify_provenance(storage_key, blake3).await?
        {
            return Self::apply_verification(decision);
        }
        Ok(())
    }

    /// Map a verifier [`PolicyDecision`] to the gate's `Result`: a blocking decision (`Deny`/
    /// `Quarantine`) becomes a `PolicyViolation` whose message is prefixed with the stable reason
    /// code (`<code>: <prose>`) so callers can match on the code; otherwise `Ok`.
    fn apply_verification(decision: PolicyDecision) -> Result<()> {
        if decision.blocks_serving() {
            let code = decision.reason_code().map_or("policy-violation", PolicyReason::as_str);
            let prose = decision.reason().unwrap_or("signature or provenance policy violation");
            return Err(StarmetalError::PolicyViolation(format!("{code}: {prose}")));
        }
        Ok(())
    }

    /// Verify the provenance attestation sidecar for an artifact (built-in own-graph provenance
    /// check). `Ok(None)` when the attestation is present, DSSE-verifies, and names *this* artifact
    /// as its single subject (by both storage key and BLAKE3 digest); `Ok(Some(Deny))` when it is
    /// absent, does not verify, or attests a different subject.
    pub(in crate::service) async fn verify_provenance(
        &self,
        storage_key: &str,
        blake3: &str,
    ) -> Result<Option<PolicyDecision>> {
        let deny = |reason: &str| {
            Ok(Some(PolicyDecision::deny(
                PolicyReason::FailingProvenance,
                reason.to_string(),
            )))
        };
        let Some(signing) = &self.signing else {
            return deny("signing is not configured, so provenance cannot be verified");
        };
        let Some(envelope_bytes) = self.storage.get(&Self::attestation_sidecar_key(storage_key)).await? else {
            return deny("no provenance attestation for the artifact");
        };
        let Ok(payload) = signing.verify_attestation(&envelope_bytes) else {
            return deny("provenance attestation did not verify");
        };
        let Ok(statement) = serde_json::from_slice::<serde_json::Value>(&payload) else {
            return deny("provenance statement is not valid JSON");
        };
        match attestation::statement_subject(&statement) {
            Some((name, digest)) if name == storage_key && digest == blake3 => Ok(None),
            _ => deny("provenance subject does not match the artifact"),
        }
    }

    /// Resolve a serve-time gate block under quarantine mode. A promoted artifact is released
    /// (`Ok`); a rejected one is refused; a still-held or first-seen artifact is (re)recorded as
    /// quarantined and refused. The digest-keyed record makes the block recoverable via the operator
    /// promote/reject workflow rather than a terminal deny.
    async fn enforce_quarantine(
        &self,
        artifact_id: &ArtifactId,
        blake3: &str,
        reason_code: Option<starmetal_core::supply_chain::PolicyReason>,
        reason: String,
    ) -> Result<()> {
        let record_key = Self::quarantine_record_key(blake3);
        if let Some(bytes) = self.storage.get(&record_key).await? {
            let record: QuarantineRecord = serde_json::from_slice(&bytes)?;
            // Records are digest-keyed, but blake3 carries no coordinate binding, so a record found
            // here may belong to a *different* package that shares bytes. Only a decision made for
            // this exact coordinate may release or refuse it — otherwise an operator's promotion of
            // one package would silently clear the gate for any other package with identical bytes,
            // and its rejection would block one (CWE-863). A coordinate mismatch falls through to
            // (re)record this coordinate's own hold, failing closed.
            if &record.artifact == artifact_id {
                match record.state {
                    QuarantineState::Promoted => return Ok(()),
                    QuarantineState::Rejected => {
                        return Err(StarmetalError::PolicyViolation(format!(
                            "artifact is quarantined and was rejected: {reason}"
                        )));
                    }
                    QuarantineState::Quarantined => {
                        return Err(StarmetalError::PolicyViolation(format!(
                            "artifact is quarantined pending review: {reason}"
                        )));
                    }
                }
            }
        }

        // First time this digest is blocked: record the hold so an operator can review it.
        let record = QuarantineRecord {
            subject_digest: blake3.to_string(),
            artifact: artifact_id.clone(),
            origin: QuarantineOrigin::Serve,
            state: QuarantineState::Quarantined,
            reason_code: reason_code.unwrap_or(starmetal_core::supply_chain::PolicyReason::VulnSeverityExceeded),
            reason: reason.clone(),
            quarantined_at: unix_now(),
            decided_at: None,
        };
        self.storage
            .put(&record_key, Bytes::from(serde_json::to_vec(&record)?))
            .await?;
        Err(StarmetalError::PolicyViolation(format!(
            "artifact is quarantined pending review: {reason}"
        )))
    }

    /// Re-correlate a single persisted scan report against a fresh scan, used by `recorrelate`'s
    /// bounded-concurrency sweep. Storage/serialization failures propagate; a scan that cannot
    /// complete is recorded as `failed` and returns `Ok` so one bad subject never aborts the sweep.
    async fn recorrelate_one(&self, scanner: &Arc<dyn Scanner>, key: &str) -> Result<RecorrelationOutcome> {
        let Some(bytes) = self.storage.get(key).await? else {
            return Ok(RecorrelationOutcome::SKIPPED);
        };
        let persisted: PersistedScanReport = serde_json::from_slice(&bytes)?;
        // Re-scanning needs the artifact bytes to recompute the digest key and drive a
        // coordinate-keyed scanner. If the artifact was evicted from the cache, skip it — its
        // stale report is a GC candidate, not a re-correlation subject.
        let artifact_key = persisted.artifact.validated_storage_key()?.into_string();
        let Some(content) = self.storage.get(&artifact_key).await? else {
            return Ok(RecorrelationOutcome::SKIPPED);
        };

        let was_blocking = evaluate_scan_report(&persisted.report, self.policy.max_vuln_severity).blocks_serving();

        let fresh = match scanner.scan(ScanTarget::new(&persisted.artifact, &content)).await {
            Ok(fresh) => fresh,
            Err(error) => {
                // A transient scan failure must not abort the whole sweep: record it and move on,
                // leaving the previously stored report untouched.
                tracing::warn!(%error, key = %key, "re-correlation scan failed; keeping the stored report");
                return Ok(RecorrelationOutcome {
                    scanned: true,
                    updated: false,
                    failed: true,
                    newly_blocking: None,
                });
            }
        };

        let mut updated = false;
        if fresh != persisted.report {
            let rewritten = PersistedScanReport {
                artifact: persisted.artifact.clone(),
                report: fresh.clone(),
            };
            self.storage
                .put(key, Bytes::from(serde_json::to_vec(&rewritten)?))
                .await?;
            updated = true;
        }

        let now_blocking = evaluate_scan_report(&fresh, self.policy.max_vuln_severity).blocks_serving();
        let newly_blocking = (now_blocking && !was_blocking).then(|| coordinate_label(&persisted.artifact));

        Ok(RecorrelationOutcome {
            scanned: true,
            updated,
            failed: false,
            newly_blocking,
        })
    }
}

impl CachingPackageService {
    /// Apply an operator promote/reject decision to a quarantine record, stamping the decision time
    /// and persisting the new state. Errors with `ArtifactNotFound` when no record exists.
    async fn transition_quarantine(&self, subject_digest: &str, state: QuarantineState) -> Result<QuarantineRecord> {
        if !integrity::is_blake3_hex(subject_digest) {
            // Defense in depth: the admin adapter validates first, but never trust a caller across a
            // trait boundary — a malformed digest must never reach `quarantine_record_key` (CWE-22).
            return Err(StarmetalError::Adapter(format!(
                "invalid blake3 digest: {subject_digest}"
            )));
        }
        let record_key = Self::quarantine_record_key(subject_digest);
        let bytes =
            self.storage.get(&record_key).await?.ok_or_else(|| {
                StarmetalError::ArtifactNotFound(format!("no quarantine record for {subject_digest}"))
            })?;
        let mut record: QuarantineRecord = serde_json::from_slice(&bytes)?;
        record.state = state;
        record.decided_at = Some(unix_now());
        self.storage
            .put(&record_key, Bytes::from(serde_json::to_vec(&record)?))
            .await?;
        Ok(record)
    }
}

/// A human-readable `ecosystem/name/version` label for a scanned artifact, used in re-correlation
/// summaries and logs (not a storage key).
fn coordinate_label(artifact: &ArtifactId) -> String {
    format!("{}/{}/{}", artifact.ecosystem, artifact.name.as_str(), artifact.version)
}

#[async_trait]
impl SupplyChainMaintenance for CachingPackageService {
    async fn recorrelate(&self) -> Result<RecorrelationReport> {
        let mut report = RecorrelationReport::default();
        let Some(scanner) = self.scanner.clone() else {
            // No scanner attached: nothing to re-correlate against. A benign no-op sweep.
            return Ok(report);
        };

        let keys = self.storage.list_prefix(SCAN_REPORT_PREFIX).await?;
        // Bounded concurrency: each subject overlaps its two storage `get`s and the scanner's
        // network round trip with the others, capped at `RECORRELATION_CONCURRENCY` in flight so the
        // sweep cannot fan out an unbounded burst of requests to the advisory feed.
        let outcomes: Vec<Result<RecorrelationOutcome>> = stream::iter(keys)
            .map(|key| {
                let scanner = Arc::clone(&scanner);
                async move { self.recorrelate_one(&scanner, &key).await }
            })
            .buffer_unordered(RECORRELATION_CONCURRENCY)
            .collect()
            .await;

        for outcome in outcomes {
            let outcome = outcome?;
            if outcome.scanned {
                report.scanned += 1;
            }
            if outcome.updated {
                report.updated += 1;
            }
            if outcome.failed {
                report.failed += 1;
            }
            if let Some(label) = outcome.newly_blocking {
                report.newly_blocking.push(label);
            }
        }

        Ok(report)
    }
}

#[async_trait]
impl QuarantineReview for CachingPackageService {
    async fn list_quarantine(&self) -> Result<Vec<QuarantineRecord>> {
        let keys = self.storage.list_prefix(QUARANTINE_PREFIX).await?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(bytes) = self.storage.get(&key).await? {
                records.push(serde_json::from_slice::<QuarantineRecord>(&bytes)?);
            }
        }
        Ok(records)
    }

    async fn get_quarantine(&self, subject_digest: &str) -> Result<Option<QuarantineRecord>> {
        if !integrity::is_blake3_hex(subject_digest) {
            // Defense in depth: a malformed digest must never reach `quarantine_record_key` (CWE-22).
            return Err(StarmetalError::Adapter(format!(
                "invalid blake3 digest: {subject_digest}"
            )));
        }
        match self.storage.get(&Self::quarantine_record_key(subject_digest)).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn promote_quarantine(&self, subject_digest: &str) -> Result<QuarantineRecord> {
        self.transition_quarantine(subject_digest, QuarantineState::Promoted)
            .await
    }

    async fn reject_quarantine(&self, subject_digest: &str) -> Result<QuarantineRecord> {
        self.transition_quarantine(subject_digest, QuarantineState::Rejected)
            .await
    }
}

#[async_trait]
impl SbomIndex for CachingPackageService {
    async fn list_sboms(&self, artifact: &ArtifactId) -> Result<Vec<Sbom>> {
        let artifact_key = artifact.validated_storage_key()?.into_string();
        // The artifact's blake3 (its SBOM subject digest) is the sidecar written beside the bytes.
        let subject_digest = match self.storage.get(&format!("{artifact_key}.blake3")).await? {
            Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            None => String::new(),
        };
        let mut sboms = Vec::new();
        for format in [SbomFormat::CycloneDx, SbomFormat::Spdx] {
            if let Some(bytes) = self.storage.get(&Self::sbom_key(&artifact_key, format)).await? {
                sboms.push(Sbom {
                    format,
                    subject_digest: subject_digest.clone(),
                    document_digest: integrity::blake3_hex(&bytes),
                    media_type: sbom::media_type(format).to_string(),
                });
            }
        }
        Ok(sboms)
    }

    async fn get_sbom_document(&self, artifact: &ArtifactId, format: SbomFormat) -> Result<Option<Bytes>> {
        let artifact_key = artifact.validated_storage_key()?.into_string();
        self.storage.get(&Self::sbom_key(&artifact_key, format)).await
    }
}
