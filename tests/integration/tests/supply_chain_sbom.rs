//! Integration tests for SBOM generation and retrieval (ADR-0024) over the real HTTP admin API.
//!
//! Each test starts a real `TestServer` with `[supply_chain.sbom]` enabled (via `configure`), plus
//! publishing and the admin API, publishes an artifact through the real PyPI legacy upload route,
//! and drives the admin SBOM endpoints (`GET /admin/api/v1/sbom` and
//! `GET /admin/api/v1/sbom/document`) to assert both the listing and the actual generated document
//! bytes are retrievable in both CycloneDX and SPDX formats — not just the disabled/bad-format
//! error paths already covered in `admin.rs`.

use reqwest::StatusCode;
use serde_json::Value;
use starmetal_integration_tests::{TestServer, enable_publishing, publish_pypi_legacy};

const PUBLISH_TOKEN: &str = "sbom-publish-token";
const PACKAGE_NAME: &str = "widget";
const PACKAGE_VERSION: &str = "1.0.0";
const PACKAGE_FILENAME: &str = "widget-1.0.0.tar.gz";
const PACKAGE_BYTES: &[u8] = b"widget-source-distribution-bytes";

fn enable_sbom_publishing_and_admin(config: &mut starmetal_core::config::Config) {
    config.supply_chain.sbom.enabled = true;
    config.admin.enabled = true;
    config.admin.tokens.push("admin-token".to_string());
    enable_publishing(config, PUBLISH_TOKEN);
}

#[tokio::test]
async fn should_generate_and_list_sboms_after_publish() {
    let server = TestServer::builder()
        .configure(enable_sbom_publishing_and_admin)
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let publish = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        PACKAGE_NAME,
        PACKAGE_VERSION,
        PACKAGE_FILENAME,
        PACKAGE_BYTES,
    )
    .await;
    assert_eq!(publish.status(), StatusCode::OK, "publish should succeed");

    let response = client
        .get(format!(
            "{base_url}/admin/api/v1/sbom?ecosystem=pypi&name={PACKAGE_NAME}&version={PACKAGE_VERSION}&filename={PACKAGE_FILENAME}"
        ))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("sbom list request failed");
    assert_eq!(response.status(), StatusCode::OK);

    let records: Vec<Value> = response.json().await.expect("sbom list should be JSON");
    let formats: Vec<&str> = records
        .iter()
        .map(|record| record["format"].as_str().expect("format should be a string"))
        .collect();
    assert!(
        formats.contains(&"cyclonedx"),
        "expected a cyclonedx record, got {formats:?}"
    );
    assert!(formats.contains(&"spdx"), "expected an spdx record, got {formats:?}");
    assert_eq!(
        records.len(),
        2,
        "expected exactly one record per format, got {records:?}"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_retrieve_cyclonedx_document_body() {
    let server = TestServer::builder()
        .configure(enable_sbom_publishing_and_admin)
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let publish = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        PACKAGE_NAME,
        PACKAGE_VERSION,
        PACKAGE_FILENAME,
        PACKAGE_BYTES,
    )
    .await;
    assert_eq!(publish.status(), StatusCode::OK, "publish should succeed");

    let response = client
        .get(format!(
            "{base_url}/admin/api/v1/sbom/document?ecosystem=pypi&name={PACKAGE_NAME}&version={PACKAGE_VERSION}&filename={PACKAGE_FILENAME}&format=cyclonedx"
        ))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("sbom document request failed");
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .expect("content-type header should be present")
        .to_str()
        .expect("content-type should be valid ASCII");
    assert!(
        content_type.contains("application/vnd.cyclonedx+json"),
        "unexpected content-type: {content_type}"
    );

    let body = response.bytes().await.expect("sbom document body should be readable");
    let document: Value = serde_json::from_slice(&body).expect("cyclonedx document should be JSON");
    assert_eq!(document["bomFormat"], "CycloneDX");
    assert_eq!(document["metadata"]["component"]["name"], PACKAGE_NAME);
    assert_eq!(document["metadata"]["component"]["version"], PACKAGE_VERSION);

    server.shutdown();
}

#[tokio::test]
async fn should_retrieve_spdx_document_body() {
    let server = TestServer::builder()
        .configure(enable_sbom_publishing_and_admin)
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let publish = publish_pypi_legacy(
        &client,
        &base_url,
        PUBLISH_TOKEN,
        PACKAGE_NAME,
        PACKAGE_VERSION,
        PACKAGE_FILENAME,
        PACKAGE_BYTES,
    )
    .await;
    assert_eq!(publish.status(), StatusCode::OK, "publish should succeed");

    let response = client
        .get(format!(
            "{base_url}/admin/api/v1/sbom/document?ecosystem=pypi&name={PACKAGE_NAME}&version={PACKAGE_VERSION}&filename={PACKAGE_FILENAME}&format=spdx"
        ))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("sbom document request failed");
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .expect("content-type header should be present")
        .to_str()
        .expect("content-type should be valid ASCII");
    assert!(
        content_type.contains("application/spdx+json"),
        "unexpected content-type: {content_type}"
    );

    let body = response.bytes().await.expect("sbom document body should be readable");
    let document: Value = serde_json::from_slice(&body).expect("spdx document should be JSON");
    assert_eq!(document["spdxVersion"], "SPDX-2.3");
    assert_eq!(document["packages"][0]["name"], PACKAGE_NAME);
    assert_eq!(document["packages"][0]["versionInfo"], PACKAGE_VERSION);

    server.shutdown();
}

#[tokio::test]
async fn should_404_for_unknown_artifact_document() {
    let server = TestServer::builder()
        .configure(enable_sbom_publishing_and_admin)
        .start()
        .await;
    let client = reqwest::Client::new();
    let base_url = server.base_url();

    let response = client
        .get(format!(
            "{base_url}/admin/api/v1/sbom/document?ecosystem=pypi&name=never-published&version=9.9.9&filename=never-published-9.9.9.tar.gz&format=cyclonedx"
        ))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("sbom document request failed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    server.shutdown();
}
