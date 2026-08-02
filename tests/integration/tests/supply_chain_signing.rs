//! Integration tests for the signature/provenance gate (ADR-0024) over the real HTTP publish
//! (ingest) and serve routes.
//!
//! Each test starts a real `TestServer` and drives an artifact through the PyPI legacy upload
//! route (ingest) and/or the download route (serve). Two seams are exercised:
//!
//! - `TestServerBuilder::with_verifier` attaches an external [`Verifier`] fake that *replaces* the
//!   built-in signature/provenance gate on every ingest and serve
//!   (`crates/starmetal-service/src/service/gate.rs:136-169` `enforce_verification`), letting a
//!   test drive a deterministic `Allow`/`Deny`/error outcome without needing signed fixtures. A
//!   blocking decision surfaces as an unprefixed `PolicyViolation`, which
//!   `starmetal-adapters::map_public_error`'s fallback maps to `403 Forbidden`
//!   (`crates/starmetal-adapters/src/lib.rs:97-100,133-163`); a verifier I/O error propagates as
//!   the underlying `StarmetalError` (here `StarmetalError::Storage`, mapped to `500 Internal
//!   Server Error` by the same function, `crates/starmetal-adapters/src/lib.rs:109-112`) rather
//!   than ever being treated as a passing verification ("fail closed").
//! - `TestServerBuilder::with_signing_key` wires the *built-in* own-graph signature gate
//!   (`config.signing` + `config.supply_chain.require_signature`), proving the production
//!   sign-on-publish / verify-on-read path accepts an artifact it signed itself, end to end.

use std::sync::Arc;

use reqwest::StatusCode;
use starmetal_core::supply_chain::{PolicyDecision, PolicyReason};
use starmetal_core::test_support::{ErroringVerifier, StubVerifier};
use starmetal_integration_tests::{TestServer, TestSigningKey, enable_publishing, publish_pypi_legacy};

const PUBLISH_TOKEN: &str = "signing-publish-token";

#[tokio::test]
async fn should_reject_publish_when_verifier_denies_with_403() {
    let server = TestServer::builder()
        .with_verifier(Arc::new(StubVerifier::new(PolicyDecision::deny(
            PolicyReason::MissingSignature,
            "no signature",
        ))))
        .configure(|config| enable_publishing(config, PUBLISH_TOKEN))
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        "denied-widget",
        "1.0.0",
        "denied-widget-1.0.0.tar.gz",
        b"artifact-bytes-rejected-by-a-denying-verifier",
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a denying external verifier must block the publish through the ingest gate"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_allow_publish_and_serve_when_verifier_allows() {
    let server = TestServer::builder()
        .with_verifier(Arc::new(StubVerifier::new(PolicyDecision::allow())))
        .configure(|config| enable_publishing(config, PUBLISH_TOKEN))
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();
    let name = "allowed-widget";
    let version = "1.0.0";
    let filename = "allowed-widget-1.0.0.tar.gz";

    let publish_response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        name,
        version,
        filename,
        b"artifact-bytes-allowed-by-a-permissive-verifier",
    )
    .await;
    assert_eq!(
        publish_response.status(),
        StatusCode::OK,
        "an allowing external verifier must not block the publish"
    );

    let download_response = client
        .get(format!("{base_url}/pypi/packages/{name}/{version}/{filename}"))
        .send()
        .await
        .expect("download request failed");
    assert_eq!(
        download_response.status(),
        StatusCode::OK,
        "an allowing external verifier must not block serving the published artifact"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_fail_closed_when_verifier_errors() {
    let server = TestServer::builder()
        .with_verifier(Arc::new(ErroringVerifier))
        .configure(|config| enable_publishing(config, PUBLISH_TOKEN))
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        "erroring-widget",
        "1.0.0",
        "erroring-widget-1.0.0.tar.gz",
        b"artifact-bytes-hitting-an-erroring-verifier",
    )
    .await;

    // `ErroringVerifier::verify` always returns `Err(StarmetalError::Storage(..))`
    // (crates/starmetal-core/src/test_support.rs:244-248). `enforce_verification` propagates it
    // via `?` rather than converting it to a `PolicyDecision`
    // (crates/starmetal-service/src/service/gate.rs:143-149), so the publish never reaches a
    // `PolicyViolation`; `map_public_error` maps `StarmetalError::Storage` to `500 Internal Server
    // Error` (crates/starmetal-adapters/src/lib.rs:109-112). The load-bearing assertion is simply
    // that it is NOT 200: a verifier I/O error must never be treated as a passing verification. ~keep
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "a verifier I/O error must fail closed, never pass the publish through"
    );
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a verifier I/O error surfaces as the underlying StarmetalError::Storage mapping"
    );

    server.shutdown();
}

// A serve-side "verifier denies" test is intentionally omitted here: `with_verifier` replaces the
// built-in gate on *both* ingest and serve unconditionally
// (crates/starmetal-service/src/service/gate.rs:143-149), so a `StubVerifier` scripted to deny
// also blocks the publish itself — there is no way to get a denying-verifier server to hold an
// already-published artifact to attempt a serve against, and the harness offers no seam to swap a
// verifier's decision between the publish and the download request on one running server (unlike
// `MutableScanner` for the vulnerability gate). `should_reject_publish_when_verifier_denies_with_403`
// above already proves the deny path fires through the same `enforce_verification` call the serve
// path shares, so the serve-side wiring is exercised by construction, not omitted from coverage.

#[tokio::test]
async fn should_publish_and_serve_a_self_signed_artifact_end_to_end() {
    let server = TestServer::builder()
        .with_signing_key(TestSigningKey::generate())
        .configure(|config| {
            config.supply_chain.require_signature = true;
            enable_publishing(config, PUBLISH_TOKEN);
        })
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();
    let name = "self-signed-widget";
    let version = "1.0.0";
    let filename = "self-signed-widget-1.0.0.tar.gz";

    let publish_response = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        name,
        version,
        filename,
        b"artifact-bytes-signed-by-the-built-in-signing-service",
    )
    .await;
    assert_eq!(
        publish_response.status(),
        StatusCode::OK,
        "the built-in signing service must sign the artifact at publish time, satisfying \
         require_signature at ingest"
    );

    let download_response = client
        .get(format!("{base_url}/pypi/packages/{name}/{version}/{filename}"))
        .send()
        .await
        .expect("download request failed");
    assert_eq!(
        download_response.status(),
        StatusCode::OK,
        "verify-on-read must accept the artifact's own valid signature when serving it back"
    );

    server.shutdown();
}
