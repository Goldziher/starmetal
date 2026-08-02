//! Deterministic, offline proof that adapter mounting is driven by the resolved
//! repository set (ADR-0019), not hardcoded paths.
//!
//! The discriminator is a method-mismatch request against a known route: a
//! mounted path returns a non-404 status (405 Method Not Allowed) before any
//! upstream call, while an unmounted path returns 404. No network is used.

use reqwest::StatusCode;
use starmetal_core::config::RepositoryConfig;
use starmetal_core::package::Ecosystem;
use starmetal_core::repository::RepositoryKind;
use starmetal_integration_tests::TestServer;

/// `POST /simple/` hits the PyPI simple-index route (a GET route), so a mounted
/// path yields a non-404 method error and an unmounted path yields 404 — without
/// contacting any upstream.
async fn mounted(base_url: &str, mount: &str) -> bool {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/{mount}/simple/"))
        .send()
        .await
        .expect("request failed");
    response.status() != StatusCode::NOT_FOUND
}

#[tokio::test]
async fn default_config_derives_proxy_per_ecosystem_at_its_name() {
    let server = TestServer::start().await;
    let base = server.base_url();

    // Derived proxy repositories mount at the ecosystem name.
    assert!(mounted(&base, "pypi").await, "pypi proxy should be mounted at /pypi");
    // A path with no repository is not mounted.
    assert!(
        !mounted(&base, "does-not-exist").await,
        "unknown path must not be mounted"
    );

    server.shutdown();
}

#[tokio::test]
async fn explicit_repositories_override_derivation_and_mount_at_custom_name() {
    let server = TestServer::start_with_config(|config| {
        config.repositories = vec![RepositoryConfig {
            name: "python".to_string(),
            kind: RepositoryKind::Proxy,
            ecosystem: Ecosystem::PyPI,
            members: Vec::new(),
        }];
    })
    .await;
    let base = server.base_url();

    // The explicit repository mounts at its custom name.
    assert!(mounted(&base, "python").await, "custom proxy should mount at /python");
    // The default `/pypi` derivation is overridden by the explicit list.
    assert!(
        !mounted(&base, "pypi").await,
        "explicit repositories replace derived ones, so /pypi is not mounted"
    );

    server.shutdown();
}
