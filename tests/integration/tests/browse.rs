//! Integration coverage for the content browse endpoint (`GET /api/v1/components`, ADR-0022).
//!
//! The scoped in-query filtering is proven at the store layer (metadata `browse` testcontainers
//! tests) and the authorizer layer (authz unit tests); here we cover the HTTP endpoint's
//! authentication and its 404-when-content-model-absent behavior.

use reqwest::StatusCode;
use starmetal_integration_tests::TestServer;

#[tokio::test]
async fn browse_reports_disabled_when_the_content_model_is_absent() {
    // Default config attaches no content model, so the endpoint reports it disabled (404) rather
    // than a server error — auth is off, so the request reaches the handler.
    let server = TestServer::start().await;

    let response = reqwest::get(format!("{}/api/v1/components", server.base_url()))
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    server.shutdown();
}

#[tokio::test]
async fn browse_requires_a_bearer_token_when_auth_is_enabled() {
    let server = TestServer::start_with_config(|config| {
        config.auth.enabled = true;
        config.auth.tokens.push("read-token".to_string());
    })
    .await;
    let client = reqwest::Client::new();
    let base = server.base_url();

    // The global read gate refuses an unauthenticated request before the handler runs.
    let response = client
        .get(format!("{base}/api/v1/components"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A wrong token is likewise rejected by the gate.
    let response = client
        .get(format!("{base}/api/v1/components"))
        .bearer_auth("wrong-token")
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A valid flat token clears the gate; with no content model attached the handler then reports
    // browse disabled (404), proving the token reaches it.
    let response = client
        .get(format!("{base}/api/v1/components"))
        .bearer_auth("read-token")
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    server.shutdown();
}
