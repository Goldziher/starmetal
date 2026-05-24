use tokio::process::Command;

use depot_integration_tests::TestServer;

#[tokio::test]
#[ignore] // requires network
async fn cargo_config_json() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/cargo/config.json", server.base_url()))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("invalid JSON");
    assert!(
        body["dl"].as_str().is_some(),
        "expected dl field in config.json"
    );
    assert!(
        body["dl"].as_str().unwrap().contains("/cargo/crates/"),
        "dl should contain /cargo/crates/, got: {}",
        body["dl"]
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn cargo_sparse_index_lookup() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/cargo/on/ce/once_cell", server.base_url()))
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        response.status(),
        200,
        "expected 200 for once_cell index lookup"
    );

    let body = response.text().await.expect("failed to read body");
    assert!(!body.is_empty(), "expected non-empty ndjson body");

    // Each line should be valid JSON with name=once_cell
    for line in body.lines() {
        if line.is_empty() {
            continue;
        }
        let entry: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|err| panic!("invalid JSON in ndjson line: {err}\nline: {line}"));
        assert_eq!(
            entry["name"], "once_cell",
            "expected name=once_cell in index entry"
        );
    }

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn cargo_crate_download() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/cargo/crates/once_cell/1.19.0/download",
            server.base_url()
        ))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 200, "expected 200 for crate download");

    let bytes = response.bytes().await.expect("failed to read bytes");
    assert!(!bytes.is_empty(), "expected non-empty crate archive bytes");

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn cargo_nonexistent_crate_returns_404() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/cargo/th/is/this-crate-does-not-exist-depot-test",
            server.base_url()
        ))
        .send()
        .await
        .expect("request failed");

    assert!(
        response.status() == 404 || response.status() == 502,
        "expected 404 or 502 for nonexistent crate, got {}",
        response.status()
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn cargo_short_crate_name_index() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/cargo/2/cc", server.base_url()))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 200, "expected 200 for cc index lookup");

    let body = response.text().await.expect("failed to read body");
    assert!(!body.is_empty(), "expected non-empty ndjson body");

    // Verify at least one line has name=cc
    let first_line = body.lines().next().expect("expected at least one line");
    let entry: serde_json::Value =
        serde_json::from_str(first_line).expect("invalid JSON in first line");
    assert_eq!(entry["name"], "cc", "expected name=cc in index entry");

    server.shutdown();
}

/// Create a temp Cargo project that depends on a crate from our registry,
/// then run `cargo fetch` to verify the full sparse index + download flow.
async fn cargo_fetch_from_depot(
    base_url: &str,
    crate_name: &str,
    version: &str,
) -> (std::process::Output, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cargo_home = tempfile::tempdir().expect("cargo home tempdir");

    // Write a minimal Cargo.toml pointing to our depot as a registry
    let cargo_toml = format!(
        r#"[package]
name = "depot-test-project"
version = "0.0.0"
edition = "2021"

[dependencies]
{crate_name} = {{ version = "={version}", registry = "depot" }}
"#
    );
    std::fs::write(tmp.path().join("Cargo.toml"), cargo_toml).unwrap();
    std::fs::create_dir_all(tmp.path().join("src")).unwrap();
    std::fs::write(tmp.path().join("src/lib.rs"), "").unwrap();

    // Write .cargo/config.toml for the custom registry
    let cargo_dir = tmp.path().join(".cargo");
    std::fs::create_dir_all(&cargo_dir).unwrap();
    let config_toml = format!(
        r#"[registries.depot]
index = "sparse+{base_url}/cargo/"
"#
    );
    std::fs::write(cargo_dir.join("config.toml"), config_toml).unwrap();

    let output = Command::new("cargo")
        .args(["fetch"])
        .current_dir(tmp.path())
        .env("CARGO_HOME", cargo_home.path())
        .env("CARGO_HTTP_TIMEOUT", "60")
        .output()
        .await
        .expect("failed to run cargo fetch");

    (output, tmp)
}

#[tokio::test]
#[ignore] // requires network + cargo
async fn cargo_fetch_crate_via_sparse_index() {
    let server = TestServer::start().await;

    let (output, _tmp) = cargo_fetch_from_depot(&server.base_url(), "once_cell", "1.19.0").await;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "cargo fetch failed.\nstdout: {stdout}\nstderr: {stderr}"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + cargo
async fn cargo_fetch_cached_on_second_request() {
    let server = TestServer::start().await;

    let (out1, _tmp1) = cargo_fetch_from_depot(&server.base_url(), "once_cell", "1.19.0").await;
    assert!(out1.status.success(), "first cargo fetch failed");

    let (out2, _tmp2) = cargo_fetch_from_depot(&server.base_url(), "once_cell", "1.19.0").await;
    assert!(out2.status.success(), "second cargo fetch (cached) failed");

    server.shutdown();
}
