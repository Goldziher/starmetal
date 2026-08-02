//! Reusable port test doubles (fakes) for exercising the supply-chain gates.
//!
//! Gated behind the additive `test-support` feature so it never compiles into a production build.
//! These are *fakes for Starmetal's own ports* — not mocks of an external service — built entirely
//! from `starmetal-core`'s own types, so both `starmetal-service` unit tests and the `tests/integration`
//! HTTP end-to-end suite can share one implementation instead of each maintaining a private copy.
//!
//! Every double is infallible by construction (no `unwrap`/`expect`): a [`FakeScanner`] produces a
//! report whose `subject_digest` always matches the bytes it was handed, [`UnavailableScanner`] and
//! [`ErroringVerifier`] deterministically fail, and [`MutableScanner`] swaps its scripted findings
//! through a `Mutex` because [`Scanner::scan`] takes `&self`.

use async_trait::async_trait;

use crate::error::{Result, StarmetalError};
use crate::integrity::blake3_hex;
use crate::policy::VulnSeverity;
use crate::supply_chain::{
    PolicyDecision, ScanReport, ScanTarget, Scanner, ScannerCapabilities, VerificationTarget, Verifier, Vulnerability,
};

/// The advisory identifier stamped on every synthetic finding these fakes emit.
const TEST_VULNERABILITY_ID: &str = "CVE-TEST-1";

/// Build the single synthetic [`Vulnerability`] used by the severity-scripting constructors.
fn test_vulnerability(severity: VulnSeverity) -> Vulnerability {
    Vulnerability {
        id: TEST_VULNERABILITY_ID.to_string(),
        severity,
        package: None,
        description: None,
        fixed_version: None,
    }
}

/// A [`Scanner`] fake that returns a caller-scripted [`ScanReport`].
///
/// The scripted `vulnerabilities` and `completed` flag are fixed at construction, but the report's
/// `subject_digest` is computed from the bytes handed to each [`Scanner::scan`] call so it always
/// correlates with the artifact under test. Use [`FakeScanner::clean`] for a passing scan,
/// [`FakeScanner::vulnerable`] to script a finding of a chosen severity, [`FakeScanner::incomplete`]
/// to drive the "fail-closed on an inconclusive scan" path (`completed: false`), or
/// [`FakeScanner::new`] for full control over the findings list.
#[derive(Debug, Clone)]
pub struct FakeScanner {
    name: String,
    vulnerabilities: Vec<Vulnerability>,
    completed: bool,
}

impl FakeScanner {
    /// Construct a scanner that reports exactly `vulnerabilities` with the given `completed` flag.
    pub fn new(vulnerabilities: Vec<Vulnerability>, completed: bool) -> Self {
        Self {
            name: "fake".to_string(),
            vulnerabilities,
            completed,
        }
    }

    /// A scanner that always returns a completed, finding-free (clean) report.
    pub fn clean() -> Self {
        Self::new(Vec::new(), true)
    }

    /// A scanner that returns a completed report carrying a single finding of `severity`.
    pub fn vulnerable(severity: VulnSeverity) -> Self {
        Self::new(vec![test_vulnerability(severity)], true)
    }

    /// A scanner whose report is marked `completed: false`, modelling a partial or timed-out scan
    /// that the vulnerability gate must treat as inconclusive (quarantine, never clean).
    pub fn incomplete() -> Self {
        Self::new(Vec::new(), false)
    }

    /// Override the scanner name advertised through [`ScannerCapabilities::name`] and stamped on the
    /// report's `scanner` field. Defaults to `"fake"`.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

#[async_trait]
impl Scanner for FakeScanner {
    async fn scan(&self, target: ScanTarget<'_>) -> Result<ScanReport> {
        Ok(ScanReport {
            scanner: self.name.clone(),
            subject_digest: blake3_hex(target.content),
            vulnerabilities: self.vulnerabilities.clone(),
            completed: self.completed,
        })
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            name: self.name.clone(),
            version: "0".to_string(),
            ecosystems: Vec::new(),
            supports_vulnerabilities: true,
            produces_sbom: false,
            sbom_formats: Vec::new(),
        }
    }
}

/// A [`Scanner`] fake whose [`Scanner::scan`] always fails, proving the ingest/serve gate fails
/// closed when the scanner is unreachable (a transport failure is an error, never a passing scan).
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableScanner;

#[async_trait]
impl Scanner for UnavailableScanner {
    async fn scan(&self, _target: ScanTarget<'_>) -> Result<ScanReport> {
        Err(StarmetalError::Upstream("scanner unavailable".to_string()))
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            name: "unavailable".to_string(),
            version: "0".to_string(),
            ecosystems: Vec::new(),
            supports_vulnerabilities: true,
            produces_sbom: false,
            sbom_formats: Vec::new(),
        }
    }
}

/// A [`Scanner`] fake whose scripted report can be swapped between calls.
///
/// Models an advisory feed that discloses a new vulnerability after an artifact was first scanned:
/// publish while it reports clean, then [`MutableScanner::set`] a severity and re-run a
/// re-correlation sweep to observe the gate decision flip. Interior mutability uses a `Mutex`
/// because [`Scanner::scan`] takes `&self`; each `scan` computes `subject_digest` from the bytes it
/// is handed, so the swapped report still correlates with the artifact under test.
#[derive(Debug)]
pub struct MutableScanner {
    state: std::sync::Mutex<MutableScannerState>,
}

#[derive(Debug, Clone)]
struct MutableScannerState {
    vulnerabilities: Vec<Vulnerability>,
    completed: bool,
}

impl MutableScanner {
    /// Construct a scanner scripted to report a single finding of `severity`, or a clean report when
    /// `None`. The report is always marked `completed: true`.
    pub fn new(severity: Option<VulnSeverity>) -> Self {
        Self {
            state: std::sync::Mutex::new(MutableScannerState {
                vulnerabilities: severity
                    .map(|severity| vec![test_vulnerability(severity)])
                    .unwrap_or_default(),
                completed: true,
            }),
        }
    }

    /// A scanner initially scripted to report a completed, finding-free (clean) report.
    pub fn clean() -> Self {
        Self::new(None)
    }

    /// Swap the scripted finding to a single vulnerability of `severity`, or clear it (clean) when
    /// `None`, keeping `completed: true`. Takes effect on the next [`Scanner::scan`] call.
    pub fn set(&self, severity: Option<VulnSeverity>) {
        self.set_report(
            severity
                .map(|severity| vec![test_vulnerability(severity)])
                .unwrap_or_default(),
            true,
        );
    }

    /// Replace the entire scripted report (findings and `completed` flag) for full control over the
    /// next [`Scanner::scan`] outcome.
    pub fn set_report(&self, vulnerabilities: Vec<Vulnerability>, completed: bool) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.vulnerabilities = vulnerabilities;
        state.completed = completed;
    }
}

#[async_trait]
impl Scanner for MutableScanner {
    async fn scan(&self, target: ScanTarget<'_>) -> Result<ScanReport> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        Ok(ScanReport {
            scanner: "mutable".to_string(),
            subject_digest: blake3_hex(target.content),
            vulnerabilities: state.vulnerabilities,
            completed: state.completed,
        })
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            name: "mutable".to_string(),
            version: "0".to_string(),
            ecosystems: Vec::new(),
            supports_vulnerabilities: true,
            produces_sbom: false,
            sbom_formats: Vec::new(),
        }
    }
}

/// A [`Verifier`] fake that returns a fixed [`PolicyDecision`], for signature/provenance
/// port-delegation contract tests. Construct with the decision the gate should observe, e.g.
/// `StubVerifier::new(PolicyDecision::allow())`.
#[derive(Debug, Clone)]
pub struct StubVerifier {
    decision: PolicyDecision,
}

impl StubVerifier {
    /// Construct a verifier that always returns `decision`.
    pub fn new(decision: PolicyDecision) -> Self {
        Self { decision }
    }
}

#[async_trait]
impl Verifier for StubVerifier {
    async fn verify(&self, _target: &VerificationTarget<'_>) -> Result<PolicyDecision> {
        Ok(self.decision.clone())
    }
}

/// A [`Verifier`] fake whose [`Verifier::verify`] always fails with a storage-style error, proving
/// the gate fails closed when the verification backend is unreachable (an error is never treated as
/// a passing verification).
#[derive(Debug, Clone, Copy, Default)]
pub struct ErroringVerifier;

#[async_trait]
impl Verifier for ErroringVerifier {
    async fn verify(&self, _target: &VerificationTarget<'_>) -> Result<PolicyDecision> {
        Err(StarmetalError::Storage("verifier backend unavailable".to_string()))
    }
}
