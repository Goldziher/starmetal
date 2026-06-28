use tokio::process::Command;

use starmetal_integration_tests::TestServer;

/// Check that pip is available, skip test if not.
async fn require_pip() -> String {
    for cmd in &["pip3", "pip"] {
        if let Ok(output) = Command::new(cmd).arg("--version").output().await
            && output.status.success()
        {
            return cmd.to_string();
        }
    }
    panic!("pip not found — install Python to run integration tests");
}

/// Helper: run pip install into a temp dir via --target.
///
/// Uses `tokio::process::Command` so the async runtime can serve HTTP
/// requests from the starmetal server while pip is running.
async fn pip_install(
    pip: &str,
    index_url: &str,
    package: &str,
    target: &std::path::Path,
    cache_dir: &std::path::Path,
) -> std::process::Output {
    Command::new(pip)
        .args([
            "install",
            "--index-url",
            index_url,
            "--trusted-host",
            "127.0.0.1",
            "--target",
            target.to_string_lossy().as_ref(),
            "--no-cache-dir",
            "--no-deps",
            "--timeout",
            "120",
            package,
        ])
        .env("PIP_CACHE_DIR", cache_dir)
        .output()
        .await
        .expect("failed to run pip")
}

#[tokio::test]
#[ignore] // requires network + pip
async fn pip_install_small_package() {
    let pip = require_pip().await;
    let server = TestServer::start().await;
    let index_url = server.pypi_index_url();

    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let cache = tempfile::tempdir().expect("failed to create cache tempdir");

    // Install `six` — small, pure-python, no native deps
    let output = pip_install(&pip, &index_url, "six==1.16.0", tmp.path(), cache.path()).await;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let command = format!(
        "{pip} install --index-url {index_url} --trusted-host 127.0.0.1 --target {} --no-cache-dir --no-deps --timeout 120 six==1.16.0",
        tmp.path().display()
    );

    assert!(
        output.status.success(),
        "pip install failed: {command}\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Verify the package was actually installed
    assert!(
        tmp.path().join("six.py").exists(),
        "six.py not found in install target. Contents: {:?}",
        std::fs::read_dir(tmp.path()).map(|d| d
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect::<Vec<_>>())
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + pip
async fn pip_install_cached_on_second_request() {
    let pip = require_pip().await;
    let server = TestServer::start().await;
    let index_url = server.pypi_index_url();

    let tmp1 = tempfile::tempdir().expect("tempdir");
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let cache1 = tempfile::tempdir().expect("cache tempdir");
    let cache2 = tempfile::tempdir().expect("cache tempdir");

    // First install — fetches from upstream
    let out1 = pip_install(&pip, &index_url, "six==1.16.0", tmp1.path(), cache1.path()).await;
    assert!(out1.status.success(), "first pip install failed");

    // Second install — should hit starmetal's cache (we can't easily prove this
    // from pip's output alone, but we verify it still works, which confirms
    // the cached data is valid and serveable)
    let out2 = pip_install(&pip, &index_url, "six==1.16.0", tmp2.path(), cache2.path()).await;
    assert!(out2.status.success(), "second pip install (cached) failed");

    assert!(tmp2.path().join("six.py").exists());

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + pip
async fn pip_install_nonexistent_package_fails() {
    let pip = require_pip().await;
    let server = TestServer::start().await;
    let index_url = server.pypi_index_url();

    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = tempfile::tempdir().expect("cache tempdir");

    let output = pip_install(
        &pip,
        &index_url,
        "this-package-does-not-exist-starmetal-test",
        tmp.path(),
        cache.path(),
    )
    .await;

    // pip should fail because the package doesn't exist
    assert!(
        !output.status.success(),
        "pip install should have failed for nonexistent package"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn http_simple_index_returns_html() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/pypi/simple/", server.base_url()))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("missing content-type")
        .to_str()
        .expect("non-ascii content-type");
    assert!(
        content_type.contains("text/html"),
        "expected HTML, got {content_type}"
    );

    let body = response.text().await.expect("failed to read body");
    assert!(body.contains("<!DOCTYPE html>"));

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn http_project_detail_returns_files() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/pypi/simple/six/", server.base_url()))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 200);

    let body = response.text().await.expect("failed to read body");
    // Should contain links to six's files
    assert!(
        body.contains("six-"),
        "expected file links in response: {}",
        &body[..200.min(body.len())]
    );
    assert!(body.contains("#sha256="), "expected sha256 hashes in links");
    assert!(
        body.contains("/pypi/packages/"),
        "expected local download URLs"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn http_json_content_negotiation() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/pypi/simple/six/", server.base_url()))
        .header("Accept", "application/vnd.pypi.simple.v1+json")
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("missing content-type")
        .to_str()
        .expect("non-ascii content-type");
    assert!(
        content_type.contains("application/vnd.pypi.simple.v1+json"),
        "expected PEP 691 JSON content type, got {content_type}"
    );

    let body: serde_json::Value = response.json().await.expect("invalid JSON response");
    assert_eq!(body["name"], "six");
    assert!(
        body["files"].is_array(),
        "expected files array in JSON response"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn http_nonexistent_package_returns_404() {
    let server = TestServer::start().await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/pypi/simple/this-package-does-not-exist-starmetal-test/",
            server.base_url()
        ))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status(), 404);

    server.shutdown();
}
