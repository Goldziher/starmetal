//! [OSV.dev](https://osv.dev) query-API [`Scanner`] adapter.
//!
//! Queries the public (or a self-hosted) OSV `/v1/query` endpoint for a single package/version
//! coordinate and translates the response into the core [`ScanReport`]/[`Vulnerability`] shape.
//! This is a pure outbound HTTP client — it is not wired into the request pipeline yet.

use async_trait::async_trait;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::integrity;
use starmetal_core::package::Ecosystem;
use starmetal_core::policy::VulnSeverity;
use starmetal_core::supply_chain::{ScanReport, ScanTarget, Scanner, ScannerCapabilities, Vulnerability};

/// Default OSV.dev API base URL.
const DEFAULT_OSV_BASE_URL: &str = "https://api.osv.dev";

/// TCP connect timeout for OSV query requests.
const OSV_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Overall request timeout (connect + response) for OSV query requests.
const OSV_REQUEST_TIMEOUT_SECS: u64 = 60;

/// A [`Scanner`] backed by the OSV.dev query API.
pub struct OsvScanner {
    client: reqwest::Client,
    base_url: String,
}

impl OsvScanner {
    /// Create a scanner targeting the public OSV.dev API.
    pub fn new() -> Self {
        Self::with_endpoint(DEFAULT_OSV_BASE_URL)
    }

    /// Create a scanner targeting a custom OSV-compatible endpoint (e.g. a self-hosted mirror, or
    /// for tests).
    pub fn with_endpoint(base_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(OSV_CONNECT_TIMEOUT_SECS))
            .timeout(std::time::Duration::from_secs(OSV_REQUEST_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            base_url: base_url.into(),
        }
    }
}

impl Default for OsvScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a Starmetal [`Ecosystem`] to the ecosystem string OSV expects in query bodies.
fn osv_ecosystem(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::PyPI => "PyPI",
        Ecosystem::Npm => "npm",
        Ecosystem::Cargo => "crates.io",
        Ecosystem::Hex => "Hex",
        Ecosystem::Maven => "Maven",
        Ecosystem::RubyGems => "RubyGems",
        Ecosystem::NuGet => "NuGet",
        Ecosystem::Pub => "Pub",
        Ecosystem::Go => "Go",
        // OSV.dev has no registered "Zig" ecosystem (as of this writing). Unreachable in practice:
        // Zig is never routed through `CachingPackageService`/the scanner, so this exists purely
        // for match exhaustiveness, mirroring Go's read-only, no-publish scope.
        Ecosystem::Zig => "Zig",
        // OSV.dev DOES have a registered "Swift" ecosystem (as of this writing). Still unreachable
        // in practice: Swift, like Go and Zig, is never routed through
        // `CachingPackageService`/the scanner, so this exists purely for match exhaustiveness.
        Ecosystem::Swift => "Swift",
    }
}

/// Determine a vulnerability's severity from an OSV vuln entry.
///
/// Preference order: the scanner's own `database_specific.severity` rating, then any affected
/// entry's `ecosystem_specific.severity` rating, then a conservative default.
///
/// NOTE: full CVSS-vector base-score bucketing (parsing `severity[].score` vectors) is a
/// deliberate follow-up, not implemented here.
fn osv_severity(vuln: &serde_json::Value) -> VulnSeverity {
    if let Some(rating) = vuln["database_specific"]["severity"].as_str()
        && let Some(severity) = severity_from_rating(rating)
    {
        return severity;
    }

    if let Some(affected) = vuln["affected"].as_array() {
        for entry in affected {
            if let Some(rating) = entry["ecosystem_specific"]["severity"].as_str()
                && let Some(severity) = severity_from_rating(rating)
            {
                return severity;
            }
        }
    }

    // Conservative default: an unrated advisory must not read as Low.
    VulnSeverity::High
}

/// Map an OSV textual severity rating to [`VulnSeverity`], case-insensitively.
fn severity_from_rating(rating: &str) -> Option<VulnSeverity> {
    match rating.to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(VulnSeverity::Critical),
        "HIGH" => Some(VulnSeverity::High),
        "MODERATE" | "MEDIUM" => Some(VulnSeverity::Medium),
        "LOW" => Some(VulnSeverity::Low),
        _ => None,
    }
}

/// Find the first `fixed` version recorded in any `affected[].ranges[].events` entry.
fn find_fixed_version(vuln: &serde_json::Value) -> Option<String> {
    let affected = vuln["affected"].as_array()?;
    for entry in affected {
        let ranges = match entry["ranges"].as_array() {
            Some(ranges) => ranges,
            None => continue,
        };
        for range in ranges {
            let events = match range["events"].as_array() {
                Some(events) => events,
                None => continue,
            };
            for event in events {
                if let Some(fixed) = event["fixed"].as_str() {
                    return Some(fixed.to_string());
                }
            }
        }
    }
    None
}

/// Parse an OSV `/v1/query` response body into a [`ScanReport`].
///
/// Pure and deterministic: no I/O, so this is the unit-tested seam for the response mapping.
fn parse_osv_query(scanner: &str, subject_digest: &str, queried_package: &str, body: &serde_json::Value) -> ScanReport {
    let vulnerabilities = body["vulns"]
        .as_array()
        .map(|vulns| {
            vulns
                .iter()
                .filter_map(|vuln| {
                    let id = vuln["id"].as_str()?.to_string();
                    let description = vuln["summary"]
                        .as_str()
                        .or_else(|| vuln["details"].as_str())
                        .map(str::to_string);
                    Some(Vulnerability {
                        id,
                        severity: osv_severity(vuln),
                        package: Some(queried_package.to_string()),
                        description,
                        fixed_version: find_fixed_version(vuln),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    ScanReport {
        scanner: scanner.to_string(),
        subject_digest: subject_digest.to_string(),
        vulnerabilities,
        completed: true,
    }
}

#[async_trait]
impl Scanner for OsvScanner {
    async fn scan(&self, target: ScanTarget<'_>) -> Result<ScanReport> {
        let body = serde_json::json!({
            "version": target.artifact_id.version,
            "package": {
                "name": target.artifact_id.name.as_str(),
                "ecosystem": osv_ecosystem(target.artifact_id.ecosystem),
            }
        });

        let response = self
            .client
            .post(format!("{}/v1/query", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|err| StarmetalError::Upstream(err.to_string()))?;

        if !response.status().is_success() {
            return Err(StarmetalError::Upstream(format!(
                "OSV query returned HTTP {}",
                response.status()
            )));
        }

        let payload: serde_json::Value = response
            .json()
            .await
            .map_err(|err| StarmetalError::Upstream(err.to_string()))?;

        let subject_digest = integrity::blake3_hex(target.content);
        Ok(parse_osv_query(
            "osv",
            &subject_digest,
            target.artifact_id.name.as_str(),
            &payload,
        ))
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            name: "osv".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ecosystems: vec![
                Ecosystem::PyPI,
                Ecosystem::Npm,
                Ecosystem::Cargo,
                Ecosystem::Hex,
                Ecosystem::Maven,
                Ecosystem::RubyGems,
                Ecosystem::NuGet,
                Ecosystem::Pub,
            ],
            supports_vulnerabilities: true,
            produces_sbom: false,
            sbom_formats: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_vuln_with_high_severity_and_fixed_version() {
        let body = serde_json::json!({
            "vulns": [{
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Example vulnerability",
                "database_specific": { "severity": "HIGH" },
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            { "introduced": "0" },
                            { "fixed": "1.2.3" }
                        ]
                    }]
                }]
            }]
        });

        let report = parse_osv_query("osv", "digest123", "left-pad", &body);

        assert!(report.completed);
        assert_eq!(report.scanner, "osv");
        assert_eq!(report.subject_digest, "digest123");
        assert_eq!(report.vulnerabilities.len(), 1);
        let vuln = &report.vulnerabilities[0];
        assert_eq!(vuln.id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(vuln.severity, VulnSeverity::High);
        assert_eq!(vuln.fixed_version, Some("1.2.3".to_string()));
        assert_eq!(vuln.package, Some("left-pad".to_string()));
        assert_eq!(vuln.description, Some("Example vulnerability".to_string()));
    }

    #[test]
    fn should_map_moderate_severity_to_medium() {
        let body = serde_json::json!({
            "vulns": [{
                "id": "GHSA-moderate",
                "database_specific": { "severity": "MODERATE" }
            }]
        });
        let report = parse_osv_query("osv", "digest", "pkg", &body);
        assert_eq!(report.vulnerabilities[0].severity, VulnSeverity::Medium);
    }

    #[test]
    fn should_map_critical_severity() {
        let body = serde_json::json!({
            "vulns": [{
                "id": "GHSA-critical",
                "database_specific": { "severity": "CRITICAL" }
            }]
        });
        let report = parse_osv_query("osv", "digest", "pkg", &body);
        assert_eq!(report.vulnerabilities[0].severity, VulnSeverity::Critical);
    }

    #[test]
    fn should_default_to_high_when_no_severity_present() {
        let body = serde_json::json!({
            "vulns": [{
                "id": "GHSA-unrated"
            }]
        });
        let report = parse_osv_query("osv", "digest", "pkg", &body);
        assert_eq!(report.vulnerabilities[0].severity, VulnSeverity::High);
        assert_eq!(report.vulnerabilities[0].fixed_version, None);
    }

    #[test]
    fn should_return_empty_vulnerabilities_for_clean_responses() {
        let empty_object = serde_json::json!({});
        let empty_vulns = serde_json::json!({ "vulns": [] });

        for body in [&empty_object, &empty_vulns] {
            let report = parse_osv_query("osv", "digest", "pkg", body);
            assert!(report.vulnerabilities.is_empty());
            assert!(report.completed);
        }
    }

    #[test]
    fn should_map_every_ecosystem_to_its_osv_string() {
        let cases = [
            (Ecosystem::PyPI, "PyPI"),
            (Ecosystem::Npm, "npm"),
            (Ecosystem::Cargo, "crates.io"),
            (Ecosystem::Hex, "Hex"),
            (Ecosystem::Maven, "Maven"),
            (Ecosystem::RubyGems, "RubyGems"),
            (Ecosystem::NuGet, "NuGet"),
            (Ecosystem::Pub, "Pub"),
            (Ecosystem::Go, "Go"),
            (Ecosystem::Zig, "Zig"),
            (Ecosystem::Swift, "Swift"),
        ];
        for (ecosystem, expected) in cases {
            assert_eq!(osv_ecosystem(ecosystem), expected, "mismatch for {ecosystem:?}");
        }
    }

    #[test]
    fn should_construct_scanner_with_default_and_custom_endpoint() {
        let default_scanner = OsvScanner::new();
        assert_eq!(default_scanner.base_url, DEFAULT_OSV_BASE_URL);

        let custom_scanner = OsvScanner::with_endpoint("https://osv.example.internal");
        assert_eq!(custom_scanner.base_url, "https://osv.example.internal");

        let capabilities = default_scanner.capabilities();
        assert_eq!(capabilities.name, "osv");
        assert!(capabilities.supports_vulnerabilities);
        assert!(!capabilities.produces_sbom);
        assert_eq!(capabilities.ecosystems.len(), 8);
    }
}
