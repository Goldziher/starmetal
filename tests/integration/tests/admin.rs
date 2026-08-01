use reqwest::StatusCode;
use serde_json::Value;
use starmetal_integration_tests::TestServer;

#[tokio::test]
async fn admin_api_is_not_mounted_when_disabled() {
    let server = TestServer::start().await;

    let response = reqwest::get(format!("{}/admin/api/v1/status", server.base_url()))
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    server.shutdown();
}

#[tokio::test]
async fn admin_api_requires_admin_bearer_token() {
    let server = TestServer::start_with_admin().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/admin/api/v1/status", server.base_url()))
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = client
        .get(format!("{}/admin/api/v1/status", server.base_url()))
        .bearer_auth("wrong-token")
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = client
        .get(format!("{}/admin/api/v1/status", server.base_url()))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("status should be JSON");
    assert_eq!(body["admin_enabled"], true);
    assert_eq!(body["storage_backend"], "fs");
    assert!(body["registries"].as_array().expect("registries array").len() >= 8);

    server.shutdown();
}

#[tokio::test]
async fn admin_token_passes_global_read_auth_for_admin_routes() {
    let server = TestServer::start_with_admin_and_read_auth().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/admin/api/v1/status", server.base_url()))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), StatusCode::OK);
    server.shutdown();
}

#[tokio::test]
async fn admin_api_returns_config_packages_and_metrics_json() {
    let server = TestServer::start_with_admin().await;
    let client = reqwest::Client::new();
    let base = server.base_url();

    let config: Value = client
        .get(format!("{base}/admin/api/v1/config"))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("config request failed")
        .json()
        .await
        .expect("config should be JSON");
    assert_eq!(config["admin"]["tokens"][0], "<redacted>");

    let packages: Value = client
        .get(format!("{base}/admin/api/v1/packages?ecosystem=npm"))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("packages request failed")
        .json()
        .await
        .expect("packages should be JSON");
    assert_eq!(packages.as_array().expect("packages array").len(), 0);

    let metrics: Value = client
        .get(format!("{base}/admin/api/v1/metrics"))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("metrics request failed")
        .json()
        .await
        .expect("metrics should be JSON");
    assert!(metrics["ecosystems"].is_object());

    server.shutdown();
}

#[tokio::test]
async fn admin_quarantine_endpoints_enforce_auth_and_report_disabled_without_a_scanner() {
    let server = TestServer::start_with_admin().await;
    let client = reqwest::Client::new();
    let base = server.base_url();
    let digest = "0".repeat(64);

    // Listing requires the admin bearer token.
    let response = client
        .get(format!("{base}/admin/api/v1/quarantine"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With no scanner attached nothing can be held, so the list is empty rather than a 404.
    let held: Value = client
        .get(format!("{base}/admin/api/v1/quarantine"))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("request failed")
        .json()
        .await
        .expect("quarantine list should be JSON");
    assert_eq!(held.as_array().expect("quarantine array").len(), 0);

    // Promote/reject report the workflow disabled (404) when no scanner is attached.
    let response = client
        .post(format!("{base}/admin/api/v1/quarantine/{digest}/promote"))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    server.shutdown();
}

#[tokio::test]
async fn admin_gc_and_retention_endpoints_enforce_auth_and_report_disabled_without_metadata() {
    let server = TestServer::start_with_admin().await;
    let client = reqwest::Client::new();
    let base = server.base_url();

    // Triggering requires the admin bearer token.
    let response = client
        .post(format!("{base}/admin/api/v1/gc"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = client
        .post(format!("{base}/admin/api/v1/retention"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With no content model attached (metadata disabled) there is nothing to sweep, so both
    // trigger endpoints report the workflow disabled (404) rather than a server error.
    let response = client
        .post(format!("{base}/admin/api/v1/gc"))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = client
        .post(format!("{base}/admin/api/v1/retention"))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    server.shutdown();
}

#[tokio::test]
async fn admin_quarantine_promote_rejects_a_path_traversal_shaped_digest() {
    let server = TestServer::start_with_admin().await;
    let client = reqwest::Client::new();
    let base = server.base_url();

    // `Path<String>` percent-decodes the segment, so this arrives at the handler as `../../config`.
    // It must be rejected as a malformed digest (400) before it ever reaches storage-key building,
    // not treated as an unknown record (404) or fail with a server error (500).
    let response = client
        .post(format!("{base}/admin/api/v1/quarantine/..%2f..%2fconfig/promote"))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    server.shutdown();
}
