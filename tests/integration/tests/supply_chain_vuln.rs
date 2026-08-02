//! Integration tests for the vulnerability gate (ADR-0024) over the real HTTP publish (ingest) and
//! serve routes.
//!
//! Each test starts a real `TestServer`, wires `[supply_chain]` and `[policies].max_vuln_severity`
//! via `configure`, attaches a scanner fake via `TestServerBuilder::with_scanner`, and drives
//! artifacts through the PyPI legacy upload route (ingest) and/or the download route (serve) to
//! assert the gate blocks an over-threshold finding with `403 Forbidden`
//! (`crates/starmetal-service/src/service/mod.rs:491-534` `scan_artifacts_for_publish`,
//! `crates/starmetal-service/src/service/gate.rs:82-125` `enforce_serve_scan`; both raise an
//! unprefixed `PolicyViolation`, which `starmetal-adapters`' `map_public_error` falls back to
//! `403 Forbidden` for — see `crates/starmetal-adapters/src/lib.rs:82-100`) while a clean scan is
//! allowed through both paths.
//!
//! `enforce_serve_scan` persists its digest-keyed [`ScanReport`] under the *same* storage key
//! (`scan_report_key`, keyed purely by the artifact's blake3 content digest — see
//! `crates/starmetal-service/src/service/gate.rs:95-110`) that `scan_artifacts_for_publish` writes
//! on a successful publish (`crates/starmetal-service/src/service/mod.rs:1296-1303`). So once an
//! artifact has been published and scanned, a later plain `GET` of that *same, already-published*
//! artifact re-reads the cached report rather than re-scanning it — a later mutation of the scanner
//! (e.g. an advisory feed disclosing a new finding) has no effect on it without an explicit
//! `SupplyChainMaintenance::recorrelate` sweep, which this HTTP-only harness has no seam to trigger.
//! `should_block_republish_of_a_previously_clean_artifact_once_a_new_vulnerability_is_disclosed`
//! below verifies that cache boundary directly (the stale-clean artifact stays servable) while
//! proving the *ingest* gate re-scans fresh on every publish call, so a later disclosure genuinely
//! blocks a subsequent overwrite of a coordinate that previously published clean.

use reqwest::StatusCode;
use starmetal_core::policy::VulnSeverity;
use starmetal_core::test_support::{FakeScanner, MutableScanner};
use starmetal_integration_tests::{TestServer, enable_publishing, publish_pypi_legacy};

const PUBLISH_TOKEN: &str = "vuln-publish-token";

#[tokio::test]
async fn should_block_publish_of_over_threshold_vulnerability_with_403() {
    let server = TestServer::builder()
        .with_scanner(std::sync::Arc::new(FakeScanner::vulnerable(VulnSeverity::High)))
        .configure(|config| {
            config.supply_chain.enabled = true;
            config.policies.max_vuln_severity = VulnSeverity::Low;
            enable_publishing(config, PUBLISH_TOKEN);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        "vulnerable-widget",
        "1.0.0",
        "vulnerable-widget-1.0.0.tar.gz",
        b"artifact-bytes-with-a-high-severity-finding",
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a High-severity finding above the Low threshold must block the publish"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_allow_publish_of_clean_scan() {
    let server = TestServer::builder()
        .with_scanner(std::sync::Arc::new(FakeScanner::clean()))
        .configure(|config| {
            config.supply_chain.enabled = true;
            config.supply_chain.enforce_on_serve = true;
            config.policies.max_vuln_severity = VulnSeverity::Low;
            enable_publishing(config, PUBLISH_TOKEN);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();
    let name = "clean-widget";
    let version = "1.0.0";
    let filename = "clean-widget-1.0.0.tar.gz";

    let publish_response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        name,
        version,
        filename,
        b"clean-artifact-bytes",
    )
    .await;
    assert_eq!(
        publish_response.status(),
        StatusCode::OK,
        "a clean scan report must not block the publish"
    );

    let download_response = client
        .get(format!("{base_url}/pypi/packages/{name}/{version}/{filename}"))
        .send()
        .await
        .expect("download request failed");
    assert_eq!(
        download_response.status(),
        StatusCode::OK,
        "a clean scan report must not block serving the already-published artifact"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_block_republish_of_a_previously_clean_artifact_once_a_new_vulnerability_is_disclosed() {
    let scanner = std::sync::Arc::new(MutableScanner::clean());
    let scanner_handle = scanner.clone();
    let server = TestServer::builder()
        .with_scanner(scanner as std::sync::Arc<dyn starmetal_core::supply_chain::Scanner>)
        .configure(|config| {
            config.supply_chain.enabled = true;
            config.supply_chain.enforce_on_serve = true;
            config.policies.max_vuln_severity = VulnSeverity::Low;
            config.publishing.allow_overwrite = true;
            enable_publishing(config, PUBLISH_TOKEN);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();
    let name = "disclosed-widget";
    let version = "1.0.0";
    let filename = "disclosed-widget-1.0.0.tar.gz";

    let first_publish_response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        name,
        version,
        filename,
        b"artifact-bytes-clean-at-publish-time",
    )
    .await;
    assert_eq!(
        first_publish_response.status(),
        StatusCode::OK,
        "the artifact must publish successfully while the scanner reports clean"
    );

    // Simulate an advisory feed disclosing a new High-severity finding after the first publish.
    scanner_handle.set(Some(VulnSeverity::High));

    // `scan_artifacts_for_publish` (mod.rs:491-534) calls `scanner.scan` fresh on every publish
    // request — it never consults the digest-keyed cache `enforce_serve_scan` reads from — so this
    // overwrite of the same coordinate is scanned against the scanner's *current* state and is
    // blocked, even though its bytes previously scanned clean.
    let overwrite_response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        name,
        version,
        filename,
        b"artifact-bytes-clean-at-publish-time",
    )
    .await;
    assert_eq!(
        overwrite_response.status(),
        StatusCode::FORBIDDEN,
        "republishing the same coordinate must be blocked once a High-severity finding is disclosed"
    );

    // The artifact that was already published (and scanned) before the disclosure remains servable:
    // `enforce_serve_scan` (gate.rs:82-125) finds the previously-persisted clean report at this exact
    // content digest and serves it without re-scanning, since the blocked overwrite above never wrote
    // a new report over it.
    let download_response = client
        .get(format!("{base_url}/pypi/packages/{name}/{version}/{filename}"))
        .send()
        .await
        .expect("download request failed");
    assert_eq!(
        download_response.status(),
        StatusCode::OK,
        "the artifact scanned clean before the disclosure must remain servable from its cached report"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_fail_closed_on_incomplete_scan_at_publish() {
    let server = TestServer::builder()
        .with_scanner(std::sync::Arc::new(FakeScanner::incomplete()))
        .configure(|config| {
            config.supply_chain.enabled = true;
            enable_publishing(config, PUBLISH_TOKEN);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        "inconclusive-widget",
        "1.0.0",
        "inconclusive-widget-1.0.0.tar.gz",
        b"artifact-bytes-with-an-inconclusive-scan",
    )
    .await;

    // `evaluate_scan_report` treats `completed: false` as `PolicyDecision::quarantine(IncompleteScan,
    // ...)` (crates/starmetal-core/src/supply_chain.rs:354-360), which `blocks_serving()` reports as
    // blocking. With ingest quarantine off (the default here), `scan_artifacts_for_publish`
    // (crates/starmetal-service/src/service/mod.rs:510-517) returns a hard `PolicyViolation`, mapped
    // by `map_public_error`'s unprefixed-message fallback to 403 Forbidden
    // (crates/starmetal-adapters/src/lib.rs:88-100) rather than ever succeeding as 200. ~keep
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an inconclusive (incomplete) scan must fail closed, never pass as clean"
    );

    server.shutdown();
}
