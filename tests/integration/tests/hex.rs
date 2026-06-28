use tokio::process::Command;

use starmetal_integration_tests::TestServer;

async fn ensure_mix_hex_package(hex_home: &std::path::Path, mix_home: &std::path::Path) {
    let install = Command::new("mix")
        .args(["local.hex", "--force"])
        .env("HEX_HOME", hex_home)
        .env("MIX_HOME", mix_home)
        .output()
        .await
        .expect("failed to run mix local.hex");
    assert!(
        install.status.success(),
        "failed to install Hex into temporary MIX_HOME with `mix local.hex --force`.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );

    let output = Command::new("mix")
        .args(["help", "hex.package"])
        .env("HEX_HOME", hex_home)
        .env("MIX_HOME", mix_home)
        .output()
        .await
        .expect("failed to run mix");
    assert!(
        output.status.success(),
        "mix hex.package task not found — install Hex with `mix local.hex --force` before running Hex E2E tests.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore] // requires network
async fn hex_package_metadata_returns_json() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/hex/api/packages/jason", server.base_url()))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("invalid JSON response");
    assert_eq!(body["name"], "jason");
    assert!(
        body["releases"].is_array(),
        "expected releases array in response"
    );
    assert!(
        !body["releases"].as_array().unwrap().is_empty(),
        "expected at least one release"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn hex_tarball_download() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/hex/tarballs/jason-1.4.1.tar",
            server.base_url()
        ))
        .send()
        .await
        .expect("request failed");

    let status = response.status();
    let bytes = response.bytes().await.expect("failed to read body");

    assert_eq!(
        status,
        200,
        "expected 200 for tarball download, body: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert!(!bytes.is_empty(), "expected non-empty tarball body");

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn hex_nonexistent_package_returns_404() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/hex/api/packages/this-does-not-exist-starmetal-test",
            server.base_url()
        ))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 404);

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn hex_package_has_license_info() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/hex/api/packages/jason", server.base_url()))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("invalid JSON response");
    let meta = &body["meta"];
    assert!(
        meta["licenses"].is_array(),
        "expected meta.licenses array in response"
    );
    assert!(
        !meta["licenses"].as_array().unwrap().is_empty(),
        "expected at least one license"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn hex_cached_on_second_request() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();

    let response1 = client
        .get(format!("{}/hex/api/packages/jason", server.base_url()))
        .send()
        .await
        .expect("first request failed");
    assert_eq!(response1.status(), 200);

    let response2 = client
        .get(format!("{}/hex/api/packages/jason", server.base_url()))
        .send()
        .await
        .expect("second request failed");
    assert_eq!(response2.status(), 200);

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + mix
async fn mix_hex_package_fetch() {
    let server = TestServer::start().await;
    let hex_mirror = format!("{}/hex", server.base_url());

    let tmp = tempfile::tempdir().expect("tempdir");
    let hex_home = tempfile::tempdir().expect("hex home tempdir");
    let mix_home = tempfile::tempdir().expect("mix home tempdir");
    ensure_mix_hex_package(hex_home.path(), mix_home.path()).await;
    let output_path = tmp.path().join("jason-1.4.1.tar");

    let output = Command::new("mix")
        .args([
            "hex.package",
            "fetch",
            "jason",
            "1.4.1",
            "--output",
            &output_path.to_string_lossy(),
        ])
        .env("HEX_MIRROR", &hex_mirror)
        .env("HEX_HOME", hex_home.path())
        .env("MIX_HOME", mix_home.path())
        .output()
        .await
        .expect("failed to run mix");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "mix hex.package fetch failed.\nstdout: {stdout}\nstderr: {stderr}"
    );

    assert!(
        output_path.exists(),
        "tarball not written to {output_path:?}"
    );
    let size = std::fs::metadata(&output_path).unwrap().len();
    assert!(size > 0, "tarball is empty");

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + mix
async fn mix_hex_package_fetch_cached() {
    let server = TestServer::start().await;
    let hex_mirror = format!("{}/hex", server.base_url());

    let tmp1 = tempfile::tempdir().expect("tempdir");
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let hex_home1 = tempfile::tempdir().expect("hex home tempdir");
    let hex_home2 = tempfile::tempdir().expect("hex home tempdir");
    let mix_home1 = tempfile::tempdir().expect("mix home tempdir");
    let mix_home2 = tempfile::tempdir().expect("mix home tempdir");
    ensure_mix_hex_package(hex_home1.path(), mix_home1.path()).await;
    ensure_mix_hex_package(hex_home2.path(), mix_home2.path()).await;

    // First fetch
    let out1 = Command::new("mix")
        .args([
            "hex.package",
            "fetch",
            "jason",
            "1.4.1",
            "--output",
            &tmp1.path().join("jason.tar").to_string_lossy(),
        ])
        .env("HEX_MIRROR", &hex_mirror)
        .env("HEX_HOME", hex_home1.path())
        .env("MIX_HOME", mix_home1.path())
        .output()
        .await
        .expect("failed to run mix");
    assert!(out1.status.success(), "first mix fetch failed");

    // Second fetch — hits starmetal cache
    let out2 = Command::new("mix")
        .args([
            "hex.package",
            "fetch",
            "jason",
            "1.4.1",
            "--output",
            &tmp2.path().join("jason.tar").to_string_lossy(),
        ])
        .env("HEX_MIRROR", &hex_mirror)
        .env("HEX_HOME", hex_home2.path())
        .env("MIX_HOME", mix_home2.path())
        .output()
        .await
        .expect("failed to run mix");
    assert!(out2.status.success(), "second mix fetch (cached) failed");

    assert!(tmp2.path().join("jason.tar").exists());

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + mix
async fn mix_hex_package_fetch_nonexistent_fails() {
    let server = TestServer::start().await;
    let hex_mirror = format!("{}/hex", server.base_url());

    let tmp = tempfile::tempdir().expect("tempdir");
    let hex_home = tempfile::tempdir().expect("hex home tempdir");
    let mix_home = tempfile::tempdir().expect("mix home tempdir");
    ensure_mix_hex_package(hex_home.path(), mix_home.path()).await;

    let output = Command::new("mix")
        .args([
            "hex.package",
            "fetch",
            "this-package-does-not-exist-starmetal-test",
            "0.0.1",
            "--output",
            &tmp.path().join("out.tar").to_string_lossy(),
        ])
        .env("HEX_MIRROR", &hex_mirror)
        .env("HEX_HOME", hex_home.path())
        .env("MIX_HOME", mix_home.path())
        .output()
        .await
        .expect("failed to run mix");

    assert!(
        !output.status.success(),
        "mix should fail for nonexistent package"
    );

    server.shutdown();
}
