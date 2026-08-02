//! Integration tests proving a real held quarantine record flows through the admin promote/reject
//! workflow over HTTP (ADR-0024), for both quarantine origins.
//!
//! Ingest origin (`config.supply_chain.ingest_quarantine`): `scan_artifacts_for_publish`
//! (`crates/starmetal-service/src/service/mod.rs:491-534`) returns `ScanGateOutcome::Held` for an
//! over-threshold finding, and `hold_ingest_publish`
//! (`crates/starmetal-service/src/service/mod.rs:1606-1669`) parks the uploaded bytes under
//! `_starmetal/held/` and returns `Ok(PublishResult)` rather than an error. Because `publish_package`
//! succeeds, the PyPI legacy upload route (`crates/starmetal-adapters/src/pypi/mod.rs:145-158`)
//! answers `200 OK` even though the publish was actually deferred, not applied — confirmed below
//! rather than assumed. `IngestQuarantine::promote_ingest`
//! (`crates/starmetal-service/src/service/mod.rs:1746-1778`) completes the deferred publish through
//! the real `publish_package` path on promotion, so the artifact becomes servable; `reject_ingest`
//! (`:1780-1796`) purges the held bytes/manifest instead, so the artifact is never published.
//!
//! Serve origin (`config.supply_chain.quarantine` + `enforce_on_serve`): `enforce_quarantine`
//! (`crates/starmetal-service/src/service/gate.rs:220-270`) records a hold for an artifact that
//! fails the vulnerability gate at read time and denies the read with an unprefixed
//! `PolicyViolation`, which `map_public_error`'s fallback maps to `403 Forbidden`
//! (`crates/starmetal-adapters/src/lib.rs:82-100`, exercised the same way in
//! `tests/integration/tests/supply_chain_vuln.rs`). A `Promoted` record releases the serve gate
//! (`gate.rs:236-238` returns `Ok(())`), so the artifact serves again after promotion.
//!
//! A serve-origin hold can only be produced over HTTP by an artifact whose *first-ever* scan
//! happens at serve time, through the pull-through proxy fetch path
//! (`fetch_and_cache_artifact`/`enforce_serve_scan`, `mod.rs:1150-1169`/`gate.rs:82-125`) rather
//! than a hosted publish: `enforce_serve_scan` unconditionally reuses whatever report is already
//! persisted at `scan_report_key(blake3)` (`gate.rs:95-110`), and `scan_artifacts_for_publish`
//! (`mod.rs:491-534`) *always* persists a passing scan's report at hosted-publish time whenever a
//! scanner is attached (`mod.rs:1296-1303`, unconditional on `enforce_on_serve`). So a
//! hosted-published artifact's report can never be invalidated by mutating a live scanner after
//! publish and re-reading — the only thing that rewrites an already-persisted report is
//! `SupplyChainMaintenance::recorrelate` (`gate.rs:363-401`), which is not reachable through any
//! `starmetal-server` HTTP route (only `starmetal-ops`'s own background maintenance loop calls it,
//! `crates/starmetal-ops/src/lib.rs:456`, which `TestServer` does not wire). The proxy path sidesteps
//! this entirely: a package never locally published has no persisted report at all, so its first
//! `GET` performs a genuine first-time scan.
//!
//! The admin routes themselves (`crates/starmetal-server/src/admin.rs:168-224`) list every held
//! record via `QuarantineReview::list_quarantine`, then route promote/reject to the ingest handle
//! when the digest's stored record has `origin == QuarantineOrigin::Ingest` and to the serve handle
//! otherwise (`:190-200`, `:212-222`, `is_ingest_hold` at `:359-365`).

use std::sync::Arc;

use reqwest::StatusCode;
use serde_json::Value;
use starmetal_core::policy::VulnSeverity;
use starmetal_core::test_support::FakeScanner;
use starmetal_integration_tests::{TestServer, enable_publishing, publish_pypi_legacy};

const PUBLISH_TOKEN: &str = "quarantine-publish-token";
const ADMIN_TOKEN: &str = "admin-token";

/// Enable admin API auth the same way every other admin test does
/// (`tests/integration/tests/admin.rs`).
fn enable_admin(config: &mut starmetal_core::config::Config) {
    config.admin.enabled = true;
    config.admin.tokens.push(ADMIN_TOKEN.to_string());
}

/// `GET /admin/api/v1/quarantine` as the admin bearer, decoded as a JSON array.
async fn list_quarantine(client: &reqwest::Client, base: &str) -> Vec<Value> {
    client
        .get(format!("{base}/admin/api/v1/quarantine"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .expect("quarantine list request failed")
        .json::<Value>()
        .await
        .expect("quarantine list should be JSON")
        .as_array()
        .expect("quarantine list should be a JSON array")
        .clone()
}

#[tokio::test]
async fn should_hold_then_promote_an_ingest_quarantined_artifact() {
    let server = TestServer::builder()
        .with_scanner(Arc::new(FakeScanner::vulnerable(VulnSeverity::High)))
        .configure(|config| {
            config.supply_chain.enabled = true;
            config.supply_chain.ingest_quarantine = true;
            config.policies.max_vuln_severity = VulnSeverity::Low;
            enable_publishing(config, PUBLISH_TOKEN);
            enable_admin(config);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base = server.base_url();
    let name = "held-widget";
    let version = "1.0.0";
    let filename = "held-widget-1.0.0.tar.gz";

    // `hold_ingest_publish` returns `Ok(PublishResult)` (mod.rs:1662-1668) rather than an error, so
    // the upload route reports success even though the publish was actually parked for review. ~keep
    let publish_response = publish_pypi_legacy(
        &client,
        &base,
        PUBLISH_TOKEN,
        name,
        version,
        filename,
        b"artifact-bytes-with-a-high-severity-finding-ingest",
    )
    .await;
    assert_eq!(
        publish_response.status(),
        StatusCode::OK,
        "an ingest-quarantined publish reports 200 OK, not an error, per hold_ingest_publish's Ok result"
    );

    let records = list_quarantine(&client, &base).await;
    assert_eq!(records.len(), 1, "exactly one artifact must be held: {records:?}");
    let record = &records[0];
    assert_eq!(record["origin"], "ingest");
    assert_eq!(record["state"], "quarantined");
    let digest = record["subject_digest"]
        .as_str()
        .expect("subject_digest should be a string")
        .to_string();

    let promote_response = client
        .post(format!("{base}/admin/api/v1/quarantine/{digest}/promote"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .expect("promote request failed");
    assert_eq!(promote_response.status(), StatusCode::OK);
    let promoted: Value = promote_response.json().await.expect("promote response should be JSON");
    assert_eq!(promoted["state"], "promoted");
    assert_eq!(promoted["subject_digest"], digest);

    // Promotion completes the deferred publish through the real `publish_package` path
    // (mod.rs:1763), so the artifact is now actually published and servable.
    let download_response = client
        .get(format!("{base}/pypi/packages/{name}/{version}/{filename}"))
        .send()
        .await
        .expect("download request failed");
    assert_eq!(
        download_response.status(),
        StatusCode::OK,
        "promoting an ingest hold must complete the deferred publish, making the artifact servable"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_hold_then_reject_an_ingest_quarantined_artifact() {
    let server = TestServer::builder()
        .with_scanner(Arc::new(FakeScanner::vulnerable(VulnSeverity::High)))
        .configure(|config| {
            config.supply_chain.enabled = true;
            config.supply_chain.ingest_quarantine = true;
            config.policies.max_vuln_severity = VulnSeverity::Low;
            enable_publishing(config, PUBLISH_TOKEN);
            enable_admin(config);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base = server.base_url();
    let name = "rejected-widget";
    let version = "1.0.0";
    let filename = "rejected-widget-1.0.0.tar.gz";

    let publish_response = publish_pypi_legacy(
        &client,
        &base,
        PUBLISH_TOKEN,
        name,
        version,
        filename,
        b"artifact-bytes-with-a-high-severity-finding-reject",
    )
    .await;
    assert_eq!(publish_response.status(), StatusCode::OK);

    let records = list_quarantine(&client, &base).await;
    assert_eq!(records.len(), 1, "exactly one artifact must be held: {records:?}");
    let record = &records[0];
    assert_eq!(record["origin"], "ingest");
    assert_eq!(record["state"], "quarantined");
    let digest = record["subject_digest"]
        .as_str()
        .expect("subject_digest should be a string")
        .to_string();

    let reject_response = client
        .post(format!("{base}/admin/api/v1/quarantine/{digest}/reject"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .expect("reject request failed");
    assert_eq!(reject_response.status(), StatusCode::OK);
    let rejected: Value = reject_response.json().await.expect("reject response should be JSON");
    assert_eq!(rejected["state"], "rejected");
    assert_eq!(rejected["subject_digest"], digest);

    // `reject_ingest` purges the parked bytes/manifest instead of publishing (mod.rs:1780-1796), so
    // the artifact was never actually published and remains unservable.
    let download_response = client
        .get(format!("{base}/pypi/packages/{name}/{version}/{filename}"))
        .send()
        .await
        .expect("download request failed");
    assert_eq!(
        download_response.status(),
        StatusCode::NOT_FOUND,
        "rejecting an ingest hold must never publish the artifact"
    );

    server.shutdown();
}

/// Requires live network access to the real `https://pypi.org` upstream (matching the convention of
/// every other real-upstream test in this crate, e.g. `tests/integration/tests/pypi_pip.rs`), so it
/// is `#[ignore]`d like its siblings and run with `cargo test -- --ignored`.
///
/// A hosted publish cannot produce a serve-origin hold over HTTP (see the module doc comment), so
/// this drives the pull-through proxy path instead: `six==1.16.0` is a long-stable, immutable PyPI
/// release that was never published to this server, so its very first `GET` is a genuine
/// first-ever scan (no cached report exists yet) rather than a cache hit.
#[tokio::test]
#[ignore]
async fn should_hold_on_first_serve_of_a_blocking_proxied_artifact() {
    let server = TestServer::builder()
        .with_scanner(Arc::new(FakeScanner::vulnerable(VulnSeverity::High)))
        .configure(|config| {
            config.supply_chain.enabled = true;
            config.supply_chain.quarantine = true;
            config.supply_chain.enforce_on_serve = true;
            config.policies.max_vuln_severity = VulnSeverity::Low;
            enable_admin(config);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base = server.base_url();
    let name = "six";
    let version = "1.16.0";
    let filename = "six-1.16.0-py2.py3-none-any.whl";

    // The artifact was never published locally, so this is a pull-through fetch from the real
    // upstream: `enforce_serve_scan` finds no persisted report for this digest and scans fresh,
    // observing the scripted High-severity finding immediately.
    let blocked_response = client
        .get(format!("{base}/pypi/packages/{name}/{version}/{filename}"))
        .send()
        .await
        .expect("download request failed");
    assert_eq!(
        blocked_response.status(),
        StatusCode::FORBIDDEN,
        "a first-time scan exceeding the Low threshold must block the proxied serve"
    );

    let records = list_quarantine(&client, &base).await;
    assert_eq!(records.len(), 1, "exactly one artifact must be held: {records:?}");
    let record = &records[0];
    assert_eq!(record["origin"], "serve");
    assert_eq!(record["state"], "quarantined");
    let digest = record["subject_digest"]
        .as_str()
        .expect("subject_digest should be a string")
        .to_string();

    let promote_response = client
        .post(format!("{base}/admin/api/v1/quarantine/{digest}/promote"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .expect("promote request failed");
    assert_eq!(promote_response.status(), StatusCode::OK);
    let promoted: Value = promote_response.json().await.expect("promote response should be JSON");
    assert_eq!(promoted["state"], "promoted");
    assert_eq!(promoted["subject_digest"], digest);

    // A promoted serve-origin record releases the gate (`enforce_quarantine` returns `Ok(())` for
    // `QuarantineState::Promoted`, gate.rs:236-238), so the artifact serves again. ~keep
    let released_response = client
        .get(format!("{base}/pypi/packages/{name}/{version}/{filename}"))
        .send()
        .await
        .expect("download request failed");
    assert_eq!(
        released_response.status(),
        StatusCode::OK,
        "promoting a serve-origin hold must release the artifact for serving"
    );

    server.shutdown();
}
