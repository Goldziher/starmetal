//! Integration tests for the publish quota gate (ADR-0021) over the real HTTP publish route.
//!
//! Each test starts a real `TestServer`, wires `[supply_chain.quota]` via `configure`, enables
//! publishing, and drives artifacts through the PyPI legacy upload route to assert the quota gate
//! denies an over-limit publish with `413 Payload Too Large` (`PolicyReason::QuotaExceeded` mapped
//! by `starmetal-adapters`) while an in-limit publish still succeeds with `200 OK`.
//!
//! The reserve-rollback-on-storage-failure path (a reservation made then rolled back when the
//! storage write itself fails) has no seam here: the HTTP harness always uses in-memory storage
//! with no fault injection, so that path is covered at the service layer instead, in
//! `crates/starmetal-service/src/service/quota.rs`. ~keep

use reqwest::StatusCode;
use starmetal_core::config::QuotaLimits;
use starmetal_integration_tests::{TestServer, enable_publishing, publish_pypi_legacy};

const PUBLISH_TOKEN: &str = "quota-publish-token";

#[tokio::test]
async fn should_reject_publish_exceeding_max_versions_with_413() {
    let server = TestServer::builder()
        .configure(|config| {
            config.supply_chain.quota.enabled = true;
            config.supply_chain.quota.default_limits = Some(QuotaLimits {
                max_versions: Some(1),
                max_bytes: None,
            });
            enable_publishing(config, PUBLISH_TOKEN);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let first = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        "widget",
        "1.0.0",
        "widget-1.0.0.tar.gz",
        b"first-version-bytes",
    )
    .await;
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "first version should publish within the 1-version quota"
    );

    let second = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        "widget",
        "2.0.0",
        "widget-2.0.0.tar.gz",
        b"second-version-bytes",
    )
    .await;
    assert_eq!(
        second.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "second version should be denied: it would push the coordinate past max_versions=1"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_reject_publish_exceeding_max_bytes_with_413() {
    let server = TestServer::builder()
        .configure(|config| {
            config.supply_chain.quota.enabled = true;
            config.supply_chain.quota.default_limits = Some(QuotaLimits {
                max_versions: None,
                max_bytes: Some(64),
            });
            enable_publishing(config, PUBLISH_TOKEN);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let small_bytes = vec![0u8; 32];
    let first = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        "gadget",
        "1.0.0",
        "gadget-1.0.0.tar.gz",
        &small_bytes,
    )
    .await;
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "a 32-byte artifact should fit within the 64-byte quota"
    );

    let large_bytes = vec![0u8; 128];
    let second = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        "gadget",
        "2.0.0",
        "gadget-2.0.0.tar.gz",
        &large_bytes,
    )
    .await;
    assert_eq!(
        second.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "cumulative bytes (32 + 128 = 160) should exceed the 64-byte quota"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_allow_publish_within_quota() {
    let server = TestServer::builder()
        .configure(|config| {
            config.supply_chain.quota.enabled = true;
            config.supply_chain.quota.default_limits = Some(QuotaLimits {
                max_versions: Some(5),
                max_bytes: Some(1_000_000),
            });
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
        "sprocket",
        "1.0.0",
        "sprocket-1.0.0.tar.gz",
        b"well-within-the-configured-quota",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "publishing a single small version should succeed when the quota gate is enabled but not exceeded"
    );

    server.shutdown();
}
