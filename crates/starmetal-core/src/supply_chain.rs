//! Supply-chain security pipeline definitions (ADR-0024).
//!
//! This module is the framework-free "decision core" and set of port traits that a later stage
//! wires into an ordered Tower middleware chain (authorization → immutability/quota → vulnerability
//! gate → license gate → signature/provenance gate → write/serve). It defines:
//!
//! - [`PolicyDecision`] + [`PolicyReason`]: a richer decision vocabulary that generalizes the bare
//!   `Ok(())` / `Err(PolicyViolation)` flow of [`crate::policy::PolicyConfig::check`], adding
//!   quarantine and warn outcomes plus typed, stable reason codes each layer can emit.
//! - [`Scanner`]: a capability-negotiated, transport-agnostic scanner port. An in-process embedded
//!   scanner or an out-of-process REST adapter (Trivy/Grype/OSV) both satisfy it. Concrete adapters
//!   land later in another crate behind a feature flag; core vendors no CVE database.
//! - SBOM and attestation/referrer linkage types ([`Sbom`], [`Referrer`], [`Attestation`]) modelling
//!   the linkage graph Starmetal owns: signatures, SBOMs, attestations, and scan reports linked to a
//!   subject Blake3 digest.
//! - [`QuarantineState`]: the quarantine workflow states for artifacts held back by policy.
//!
//! Nothing here performs I/O directly; all I/O crosses the [`Scanner`] port boundary.

use async_trait::async_trait;
use bytes::Bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::package::{ArtifactId, Ecosystem};
use crate::policy::VulnSeverity;

// ---------------------------------------------------------------------------
// Policy decision core
// ---------------------------------------------------------------------------

/// A typed, stable reason code explaining why a policy layer produced a non-allow decision.
///
/// Each variant corresponds to one cross-cutting control in the ADR-0024 pipeline. The string form
/// ([`PolicyReason::as_str`]) is a stable machine identifier suitable for API responses, metrics
/// labels, and audit logs; it must not change once shipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyReason {
    /// The package coordinate (ecosystem/name[/version]) is on a blocklist.
    BlockedCoordinate,
    /// The declared license is missing or not in the allowed set / SPDX expression.
    DisallowedLicense,
    /// A vulnerability exceeded the configured maximum severity gate.
    VulnSeverityExceeded,
    /// A required signature (e.g. cosign/DSSE) was absent.
    MissingSignature,
    /// Provenance (SLSA/in-toto) verification failed.
    FailingProvenance,
    /// No scan report is associated with the artifact and one is required ("no scan = violation").
    MissingScanReport,
    /// A storage, count, or rate quota was exceeded.
    QuotaExceeded,
    /// A write targeted an immutable, already-published version.
    ImmutableVersion,
}

impl PolicyReason {
    /// Return the stable, machine-readable reason code string.
    ///
    /// This matches the kebab-case serde representation and is guaranteed stable across releases.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockedCoordinate => "blocked-coordinate",
            Self::DisallowedLicense => "disallowed-license",
            Self::VulnSeverityExceeded => "vuln-severity-exceeded",
            Self::MissingSignature => "missing-signature",
            Self::FailingProvenance => "failing-provenance",
            Self::MissingScanReport => "missing-scan-report",
            Self::QuotaExceeded => "quota-exceeded",
            Self::ImmutableVersion => "immutable-version",
        }
    }
}

impl std::fmt::Display for PolicyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of evaluating one policy layer (or the composed pipeline) against an artifact.
///
/// This generalizes the bare `Result<()>` returned by [`crate::policy::PolicyConfig::check`]: instead
/// of a single pass/fail it distinguishes advisory warnings, quarantine (held for approval), and hard
/// denial, and it always carries a typed [`PolicyReason`] plus human-readable prose for non-allow
/// outcomes. A later stage replaces the bare flow by mapping each control onto these variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "decision", rename_all = "kebab-case")]
pub enum PolicyDecision {
    /// The artifact satisfies the policy and may be written/served.
    Allow,
    /// The artifact is permitted but a non-blocking concern was recorded for observability.
    Warn {
        /// The typed reason code for the warning.
        code: PolicyReason,
        /// Human-readable explanation.
        reason: String,
    },
    /// The artifact is held in quarantine (not served) pending an approval/promotion decision.
    Quarantine {
        /// The typed reason code that triggered quarantine.
        code: PolicyReason,
        /// Human-readable explanation.
        reason: String,
    },
    /// The artifact is rejected outright; the request must fail (default-deny controls).
    Deny {
        /// The typed reason code for the denial.
        code: PolicyReason,
        /// Human-readable explanation.
        reason: String,
    },
}

impl PolicyDecision {
    /// Construct an [`PolicyDecision::Allow`] decision.
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Construct a non-blocking [`PolicyDecision::Warn`] decision.
    pub fn warn(code: PolicyReason, reason: impl Into<String>) -> Self {
        Self::Warn {
            code,
            reason: reason.into(),
        }
    }

    /// Construct a [`PolicyDecision::Quarantine`] decision (held, not served, awaiting approval).
    pub fn quarantine(code: PolicyReason, reason: impl Into<String>) -> Self {
        Self::Quarantine {
            code,
            reason: reason.into(),
        }
    }

    /// Construct a hard [`PolicyDecision::Deny`] decision.
    pub fn deny(code: PolicyReason, reason: impl Into<String>) -> Self {
        Self::Deny {
            code,
            reason: reason.into(),
        }
    }

    /// Whether this decision permits the artifact to be written or served.
    ///
    /// `Allow` and `Warn` permit; `Quarantine` and `Deny` do not.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Warn { .. })
    }

    /// Whether this decision blocks writing/serving (`Quarantine` or `Deny`).
    pub fn blocks_serving(&self) -> bool {
        !self.is_allowed()
    }

    /// The typed reason code, or `None` for a plain [`PolicyDecision::Allow`].
    pub fn reason_code(&self) -> Option<PolicyReason> {
        match self {
            Self::Allow => None,
            Self::Warn { code, .. } | Self::Quarantine { code, .. } | Self::Deny { code, .. } => Some(*code),
        }
    }

    /// The human-readable explanation, or `None` for a plain [`PolicyDecision::Allow`].
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Warn { reason, .. } | Self::Quarantine { reason, .. } | Self::Deny { reason, .. } => {
                Some(reason.as_str())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scanner port
// ---------------------------------------------------------------------------

/// The artifact bytes and identity handed to a [`Scanner`].
///
/// Borrows its inputs so callers keep ownership and decide where data lives; the `content` is a
/// cheap [`Bytes`] handle. Kept separate from [`crate::package::ArtifactId`] so the port signature
/// can gain fields (e.g. an SBOM hint) without breaking implementors.
#[derive(Debug, Clone, Copy)]
pub struct ScanTarget<'a> {
    /// The identity of the artifact being scanned.
    pub artifact_id: &'a ArtifactId,
    /// The raw artifact bytes to scan.
    pub content: &'a Bytes,
}

impl<'a> ScanTarget<'a> {
    /// Construct a scan target from an artifact identity and its bytes.
    pub fn new(artifact_id: &'a ArtifactId, content: &'a Bytes) -> Self {
        Self { artifact_id, content }
    }
}

/// A single vulnerability finding produced by a [`Scanner`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Vulnerability {
    /// Advisory identifier (e.g. `CVE-2024-1234`, `GHSA-xxxx`).
    pub id: String,
    /// Normalized severity, reusing the shared [`VulnSeverity`] scale used by the policy engine.
    pub severity: VulnSeverity,
    /// The affected package/component name, if the scanner attributes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Human-readable description of the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The first version in which the vulnerability is fixed, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
}

/// The result of scanning one artifact.
///
/// Reports are stored and associated with the subject artifact (by its Blake3 digest) so the
/// vulnerability gate can consult them at ingest and serve time, and so stored SBOMs can be
/// re-correlated against refreshed advisory feeds ("scan-once-then-monitor").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScanReport {
    /// Identifier of the scanner that produced this report (matches [`ScannerCapabilities::name`]).
    pub scanner: String,
    /// Blake3 digest of the scanned artifact this report is bound to.
    pub subject_digest: String,
    /// All vulnerability findings; empty means the scan completed clean.
    #[serde(default)]
    pub vulnerabilities: Vec<Vulnerability>,
    /// Whether the scan ran to completion (`false` indicates a partial/errored scan).
    pub completed: bool,
}

impl ScanReport {
    /// The most severe finding in the report, or `None` when there are no vulnerabilities.
    pub fn highest_severity(&self) -> Option<VulnSeverity> {
        self.vulnerabilities
            .iter()
            .map(|vulnerability| vulnerability.severity)
            .max()
    }
}

/// Evaluate a scan report against the maximum tolerated vulnerability severity, yielding the
/// vulnerability-gate decision consulted at both ingest and serve (ADR-0024).
///
/// A finding strictly more severe than `max_allowed` denies with
/// [`PolicyReason::VulnSeverityExceeded`]; anything at or below the threshold — including a clean
/// report — allows. This is pure and framework-free so the same rule governs the publish path and
/// the serve path. With the default `max_allowed` of [`VulnSeverity::Critical`] nothing exceeds the
/// threshold, so an attached scanner never blocks until an operator lowers the bound — keeping the
/// gate additive and non-breaking. Quarantine-instead-of-deny and incomplete-scan (`completed ==
/// false`) handling are layered in by the caller; this function only ranks findings against the
/// threshold.
pub fn evaluate_scan_report(report: &ScanReport, max_allowed: VulnSeverity) -> PolicyDecision {
    match report.highest_severity() {
        Some(highest) if highest > max_allowed => PolicyDecision::deny(
            PolicyReason::VulnSeverityExceeded,
            format!(
                "artifact carries a {highest:?} vulnerability, exceeding the maximum allowed severity {max_allowed:?}"
            ),
        ),
        _ => PolicyDecision::allow(),
    }
}

/// Summary of one scheduled re-correlation sweep (ADR-0024).
///
/// A sweep re-scans every stored [`ScanReport`] against the (refreshed) advisory feed and rewrites
/// each one, so an artifact that was clean when first scanned is re-evaluated as new advisories land.
/// The counters let the scheduler log sweep outcomes and highlight artifacts whose gate decision
/// flipped from allow to block since their previous scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecorrelationReport {
    /// Number of stored reports whose subject artifact was still present and was re-scanned.
    pub scanned: usize,
    /// Number of re-scanned reports whose findings changed and were rewritten.
    pub updated: usize,
    /// Number of subjects whose re-scan could not complete (transport failure); their stored report
    /// is left unchanged and the sweep continues.
    pub failed: usize,
    /// Human-readable coordinates that now exceed the severity gate but did not at their prior scan.
    #[serde(default)]
    pub newly_blocking: Vec<String>,
}

/// Scheduled maintenance over the persisted supply-chain state (ADR-0024).
///
/// This is the "monitor" half of scan-once-then-monitor, kept separate from the request-path
/// [`Scanner`] port because it is driven by a scheduler rather than an ingest/serve request. The
/// trait is object-safe so a runtime can hold an `Arc<dyn SupplyChainMaintenance>` and drive it from
/// a background task.
#[async_trait]
pub trait SupplyChainMaintenance: Send + Sync {
    /// Re-scan every stored scan report against the (refreshed) advisory feed, rewrite the ones whose
    /// findings changed, and summarize the sweep.
    ///
    /// # Errors
    ///
    /// Returns an error only on a systemic failure (e.g. the report store is unreadable); a single
    /// subject whose re-scan fails is counted in [`RecorrelationReport::failed`], not surfaced as an
    /// error, so one transient failure does not abort the sweep.
    async fn recorrelate(&self) -> Result<RecorrelationReport>;
}

/// Capabilities a [`Scanner`] advertises so the pipeline can negotiate whether and how to use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScannerCapabilities {
    /// Stable scanner identifier (e.g. `trivy`, `osv`).
    pub name: String,
    /// Scanner version string.
    pub version: String,
    /// Ecosystems this scanner can meaningfully analyze; empty means ecosystem-agnostic.
    #[serde(default)]
    pub ecosystems: Vec<Ecosystem>,
    /// Whether the scanner emits vulnerability findings.
    pub supports_vulnerabilities: bool,
    /// Whether the scanner can generate an SBOM as part of scanning.
    pub produces_sbom: bool,
    /// SBOM formats the scanner can emit when [`ScannerCapabilities::produces_sbom`] is `true`.
    #[serde(default)]
    pub sbom_formats: Vec<SbomFormat>,
}

/// A pluggable, transport-agnostic artifact scanner port (ADR-0024).
///
/// Implementations may run in-process (embedded) or out-of-process (a REST adapter fronting Trivy,
/// Grype, or OSV); both satisfy this contract. The trait is object-safe so the service layer can hold
/// an `Arc<dyn Scanner>` and swap adapters behind a feature flag. Core ships no concrete scanner and
/// vendors no CVE database.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Scan an artifact and return its report.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan could not be attempted (transport failure, unsupported input);
    /// a completed scan that found issues is a successful [`ScanReport`], not an error.
    async fn scan(&self, target: ScanTarget<'_>) -> Result<ScanReport>;

    /// Report the scanner's advertised capabilities for pipeline negotiation.
    fn capabilities(&self) -> ScannerCapabilities;
}

// ---------------------------------------------------------------------------
// SBOM + attestation / referrer linkage graph
// ---------------------------------------------------------------------------

/// Standard SBOM document formats Starmetal generates and stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum SbomFormat {
    /// CycloneDX (<https://cyclonedx.org>).
    #[serde(rename = "cyclonedx")]
    CycloneDx,
    /// SPDX (<https://spdx.dev>).
    #[serde(rename = "spdx")]
    Spdx,
}

impl SbomFormat {
    /// The stable serialized identifier for this format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CycloneDx => "cyclonedx",
            Self::Spdx => "spdx",
        }
    }
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata for an SBOM document associated with a subject artifact.
///
/// The SBOM document itself is stored as an associated artifact and referenced here by its own
/// Blake3 digest, keeping this type serde-friendly and decoupled from the storage bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Sbom {
    /// The document format.
    pub format: SbomFormat,
    /// Blake3 digest of the subject artifact this SBOM describes.
    pub subject_digest: String,
    /// Blake3 digest of the stored SBOM document itself.
    pub document_digest: String,
    /// IANA media type of the stored document (e.g. `application/vnd.cyclonedx+json`).
    pub media_type: String,
}

/// The kind of accessory artifact a [`Referrer`] links to its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReferrerType {
    /// A detached signature (e.g. cosign / DSSE).
    Signature,
    /// A Software Bill of Materials document.
    Sbom,
    /// An in-toto / SLSA attestation.
    Attestation,
    /// A stored scan report.
    ScanReport,
}

/// An accessory artifact linked to a subject artifact by its Blake3 digest.
///
/// Referrers form the linkage graph Starmetal owns (signatures, SBOMs, attestations, scan reports).
/// Signature verification itself is delegated to established libraries; this type records the graph
/// edge and the identity of the accessory so the refuse-serve enforcement can consult it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Referrer {
    /// Blake3 digest of the subject artifact this accessory refers to.
    pub subject_digest: String,
    /// Blake3 digest of the referrer (accessory) artifact itself.
    pub referrer_digest: String,
    /// What kind of accessory this is.
    pub artifact_type: ReferrerType,
    /// IANA media type of the referrer artifact.
    pub media_type: String,
    /// RFC 3339 creation timestamp, if recorded (kept as a string to avoid a time-crate dependency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// The envelope format of an [`Attestation`] statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationFormat {
    /// Dead Simple Signing Envelope.
    Dsse,
    /// in-toto statement.
    InToto,
    /// SLSA provenance.
    Slsa,
}

/// An attestation (e.g. SLSA provenance) bound to a subject artifact.
///
/// The statement document is stored as an associated artifact and referenced here by its Blake3
/// digest. `predicate_type` is the in-toto predicate URI (e.g. `https://slsa.dev/provenance/v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Attestation {
    /// Blake3 digest of the subject artifact this attestation covers.
    pub subject_digest: String,
    /// Blake3 digest of the stored attestation statement document.
    pub statement_digest: String,
    /// The envelope format of the statement.
    pub format: AttestationFormat,
    /// The in-toto predicate type URI (e.g. `https://slsa.dev/provenance/v1`).
    pub predicate_type: String,
}

// ---------------------------------------------------------------------------
// Quarantine workflow
// ---------------------------------------------------------------------------

/// The lifecycle state of an artifact under the quarantine workflow.
///
/// Artifacts failing policy are quarantined rather than silently dropped, then either promoted
/// (approved and served) or rejected (permanently withheld) via an operator decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum QuarantineState {
    /// Held back and not served, awaiting an approval/promotion decision.
    Quarantined,
    /// Approved and released for serving.
    Promoted,
    /// Permanently rejected and never served.
    Rejected,
}

/// A record of one artifact held under the quarantine workflow (ADR-0024).
///
/// When quarantine mode is enabled, an artifact that fails the vulnerability gate is recorded here
/// (keyed by its Blake3 digest) and held rather than hard-denied, so an operator can later promote it
/// (release for serving) or reject it (withhold permanently). The coordinate is retained for operator
/// context; the reason captures why the gate blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuarantineRecord {
    /// Blake3 digest of the held artifact — the record's stable identity.
    pub subject_digest: String,
    /// The artifact coordinate (ecosystem/name/version/filename) that was held.
    pub artifact: ArtifactId,
    /// The current lifecycle state.
    pub state: QuarantineState,
    /// The typed policy reason the artifact was quarantined for.
    pub reason_code: PolicyReason,
    /// Human-readable explanation of the quarantine.
    pub reason: String,
    /// Unix timestamp (seconds) when the artifact was first quarantined.
    pub quarantined_at: u64,
    /// Unix timestamp (seconds) of the promote/reject decision, if one has been made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<u64>,
}

/// Operator review of the quarantine workflow (ADR-0024).
///
/// Kept separate from the request-path [`Scanner`] and the scheduled [`SupplyChainMaintenance`]: these
/// are operator-driven decisions surfaced through the admin API. The trait is object-safe so the
/// server can hold an `Arc<dyn QuarantineReview>`.
#[async_trait]
pub trait QuarantineReview: Send + Sync {
    /// List every quarantine record, in an unspecified order.
    async fn list_quarantine(&self) -> Result<Vec<QuarantineRecord>>;

    /// Promote a held artifact (identified by its Blake3 digest) so it may be served.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::StarmetalError::ArtifactNotFound`] when no record exists for the digest.
    async fn promote_quarantine(&self, subject_digest: &str) -> Result<QuarantineRecord>;

    /// Reject a held artifact (identified by its Blake3 digest) so it is never served.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::StarmetalError::ArtifactNotFound`] when no record exists for the digest.
    async fn reject_quarantine(&self, subject_digest: &str) -> Result<QuarantineRecord>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_report_allow_as_permitting() {
        let decision = PolicyDecision::allow();
        assert!(decision.is_allowed());
        assert!(!decision.blocks_serving());
        assert_eq!(decision.reason_code(), None);
        assert_eq!(decision.reason(), None);
    }

    #[test]
    fn should_permit_but_carry_reason_for_warn() {
        let decision = PolicyDecision::warn(PolicyReason::MissingScanReport, "no scan report yet");
        assert!(decision.is_allowed());
        assert!(!decision.blocks_serving());
        assert_eq!(decision.reason_code(), Some(PolicyReason::MissingScanReport));
        assert_eq!(decision.reason(), Some("no scan report yet"));
    }

    #[test]
    fn should_block_serving_for_quarantine_and_deny() {
        let quarantine = PolicyDecision::quarantine(PolicyReason::VulnSeverityExceeded, "critical CVE");
        let deny = PolicyDecision::deny(PolicyReason::BlockedCoordinate, "coordinate blocked");

        assert!(quarantine.blocks_serving());
        assert!(!quarantine.is_allowed());
        assert_eq!(quarantine.reason_code(), Some(PolicyReason::VulnSeverityExceeded));

        assert!(deny.blocks_serving());
        assert!(!deny.is_allowed());
        assert_eq!(deny.reason_code(), Some(PolicyReason::BlockedCoordinate));
        assert_eq!(deny.reason(), Some("coordinate blocked"));
    }

    #[test]
    fn should_map_every_reason_code_to_stable_string() {
        let cases = [
            (PolicyReason::BlockedCoordinate, "blocked-coordinate"),
            (PolicyReason::DisallowedLicense, "disallowed-license"),
            (PolicyReason::VulnSeverityExceeded, "vuln-severity-exceeded"),
            (PolicyReason::MissingSignature, "missing-signature"),
            (PolicyReason::FailingProvenance, "failing-provenance"),
            (PolicyReason::MissingScanReport, "missing-scan-report"),
            (PolicyReason::QuotaExceeded, "quota-exceeded"),
            (PolicyReason::ImmutableVersion, "immutable-version"),
        ];
        for (reason, expected) in cases {
            assert_eq!(reason.as_str(), expected, "as_str mismatch for {reason:?}");
            assert_eq!(reason.to_string(), expected, "Display mismatch for {reason:?}");
            let json = serde_json::to_string(&reason).unwrap();
            assert_eq!(json, format!("\"{expected}\""), "serde mismatch for {reason:?}");
        }
    }

    #[test]
    fn should_serialize_policy_decision_with_tagged_representation() {
        let deny = PolicyDecision::deny(PolicyReason::QuotaExceeded, "storage quota exceeded");
        let value: serde_json::Value = serde_json::to_value(&deny).unwrap();
        assert_eq!(value["decision"], "deny");
        assert_eq!(value["code"], "quota-exceeded");
        assert_eq!(value["reason"], "storage quota exceeded");

        let roundtripped: PolicyDecision = serde_json::from_value(value).unwrap();
        assert_eq!(roundtripped, deny);
    }

    #[test]
    fn should_roundtrip_sbom_format_serde() {
        assert_eq!(serde_json::to_string(&SbomFormat::CycloneDx).unwrap(), "\"cyclonedx\"");
        assert_eq!(serde_json::to_string(&SbomFormat::Spdx).unwrap(), "\"spdx\"");

        let cyclonedx: SbomFormat = serde_json::from_str("\"cyclonedx\"").unwrap();
        let spdx: SbomFormat = serde_json::from_str("\"spdx\"").unwrap();
        assert_eq!(cyclonedx, SbomFormat::CycloneDx);
        assert_eq!(spdx, SbomFormat::Spdx);

        assert_eq!(SbomFormat::CycloneDx.as_str(), "cyclonedx");
        assert_eq!(SbomFormat::Spdx.to_string(), "spdx");
    }

    #[test]
    fn should_pick_highest_severity_from_scan_report() {
        let report = ScanReport {
            scanner: "osv".to_string(),
            subject_digest: "0".repeat(64),
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-1".to_string(),
                    severity: VulnSeverity::Low,
                    package: None,
                    description: None,
                    fixed_version: None,
                },
                Vulnerability {
                    id: "CVE-2".to_string(),
                    severity: VulnSeverity::High,
                    package: Some("left-pad".to_string()),
                    description: None,
                    fixed_version: Some("1.3.1".to_string()),
                },
            ],
            completed: true,
        };
        assert_eq!(report.highest_severity(), Some(VulnSeverity::High));

        let clean = ScanReport {
            scanner: "osv".to_string(),
            subject_digest: "0".repeat(64),
            vulnerabilities: vec![],
            completed: true,
        };
        assert_eq!(clean.highest_severity(), None);
    }

    fn report_with(severity: VulnSeverity) -> ScanReport {
        ScanReport {
            scanner: "osv".to_string(),
            subject_digest: "0".repeat(64),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-1".to_string(),
                severity,
                package: None,
                description: None,
                fixed_version: None,
            }],
            completed: true,
        }
    }

    #[test]
    fn should_deny_when_a_finding_exceeds_the_max_allowed_severity() {
        let decision = evaluate_scan_report(&report_with(VulnSeverity::Critical), VulnSeverity::High);
        assert!(decision.blocks_serving());
        assert_eq!(decision.reason_code(), Some(PolicyReason::VulnSeverityExceeded));
    }

    #[test]
    fn should_allow_when_the_highest_finding_is_at_or_below_the_threshold() {
        // Equal to the threshold is tolerated.
        assert!(evaluate_scan_report(&report_with(VulnSeverity::High), VulnSeverity::High).is_allowed());
        // Below the threshold is tolerated.
        assert!(evaluate_scan_report(&report_with(VulnSeverity::Low), VulnSeverity::High).is_allowed());
    }

    #[test]
    fn should_allow_the_default_critical_threshold_even_with_a_critical_finding() {
        // The default `max_vuln_severity` (Critical) leaves the gate effectively off: nothing can
        // exceed the top of the scale, so an attached scanner never blocks until the bound is lowered.
        let decision = evaluate_scan_report(&report_with(VulnSeverity::Critical), VulnSeverity::Critical);
        assert!(decision.is_allowed());
        assert_eq!(decision.reason_code(), None);
    }

    #[test]
    fn should_allow_a_clean_report() {
        let clean = ScanReport {
            scanner: "osv".to_string(),
            subject_digest: "0".repeat(64),
            vulnerabilities: vec![],
            completed: true,
        };
        assert!(evaluate_scan_report(&clean, VulnSeverity::Low).is_allowed());
    }

    #[test]
    fn should_roundtrip_referrer_and_quarantine_serde() {
        let referrer = Referrer {
            subject_digest: "a".repeat(64),
            referrer_digest: "b".repeat(64),
            artifact_type: ReferrerType::ScanReport,
            media_type: "application/json".to_string(),
            created_at: None,
        };
        let value = serde_json::to_value(&referrer).unwrap();
        assert_eq!(value["artifact_type"], "scan-report");
        assert!(value.get("created_at").is_none(), "None timestamp should be skipped");
        let roundtripped: Referrer = serde_json::from_value(value).unwrap();
        assert_eq!(roundtripped, referrer);

        assert_eq!(
            serde_json::to_string(&QuarantineState::Quarantined).unwrap(),
            "\"quarantined\""
        );
        assert_eq!(
            serde_json::to_string(&AttestationFormat::InToto).unwrap(),
            "\"in-toto\""
        );
    }
}
