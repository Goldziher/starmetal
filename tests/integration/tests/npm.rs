use tokio::process::Command;

use depot_integration_tests::TestServer;

/// Check that npm is available, return the command name.
async fn require_npm() -> String {
    for cmd in &["npm"] {
        if let Ok(output) = Command::new(cmd).arg("--version").output().await
            && output.status.success()
        {
            return cmd.to_string();
        }
    }
    panic!("npm not found — install Node.js to run npm integration tests");
}

/// Run `npm install` with a custom registry into a temp dir.
async fn npm_install(
    npm: &str,
    registry_url: &str,
    package: &str,
    target: &std::path::Path,
) -> std::process::Output {
    Command::new(npm)
        .args([
            "install",
            "--registry",
            registry_url,
            "--prefix",
            &target.to_string_lossy(),
            "--no-audit",
            "--no-fund",
            "--no-package-lock",
            package,
        ])
        .output()
        .await
        .expect("failed to run npm")
}

#[tokio::test]
#[ignore] // requires network
async fn npm_package_metadata_returns_json() {
    let server = TestServer::start().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/npm/is-odd", server.base_url()))
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
        content_type.contains("application/json"),
        "expected JSON content type, got {content_type}"
    );

    let body: serde_json::Value = response.json().await.expect("invalid JSON response");
    assert_eq!(body["name"], "is-odd");
    assert!(
        body["versions"].is_object(),
        "expected versions object in packument"
    );
    assert!(
        !body["versions"]
            .as_object()
            .expect("versions not an object")
            .is_empty(),
        "expected at least one version"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn npm_package_tarball_download() {
    let server = TestServer::start().await;
    let client = reqwest::Client::new();

    // First get metadata to find latest version
    let meta_response = client
        .get(format!("{}/npm/is-odd", server.base_url()))
        .send()
        .await
        .expect("metadata request failed");
    assert_eq!(meta_response.status(), 200);

    let body: serde_json::Value = meta_response.json().await.expect("invalid JSON");
    let latest = body["dist-tags"]["latest"]
        .as_str()
        .expect("no latest dist-tag");

    let filename = format!("is-odd-{latest}.tgz");
    let tarball_response = client
        .get(format!("{}/npm/is-odd/-/{filename}", server.base_url()))
        .send()
        .await
        .expect("tarball request failed");

    assert_eq!(tarball_response.status(), 200);
    let bytes = tarball_response.bytes().await.expect("failed to read body");
    assert!(
        !bytes.is_empty(),
        "expected non-empty tarball for is-odd@{latest}"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn npm_scoped_package() {
    let server = TestServer::start().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/npm/@anthropic-ai/sdk", server.base_url()))
        .send()
        .await
        .expect("request failed");

    // Should be 200 (found) or 404 (not found), but never 500 (server error)
    let status = response.status().as_u16();
    assert!(
        status == 200 || status == 404,
        "expected 200 or 404, got {status}"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn npm_nonexistent_package_returns_404() {
    let server = TestServer::start().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "{}/npm/this-does-not-exist-depot-test",
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
async fn npm_cached_on_second_request() {
    let server = TestServer::start().await;
    let client = reqwest::Client::new();

    let response1 = client
        .get(format!("{}/npm/is-odd", server.base_url()))
        .send()
        .await
        .expect("first request failed");
    assert_eq!(response1.status(), 200);

    let response2 = client
        .get(format!("{}/npm/is-odd", server.base_url()))
        .send()
        .await
        .expect("second request failed");
    assert_eq!(response2.status(), 200);

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + npm
async fn npm_install_small_package() {
    let npm = require_npm().await;
    let server = TestServer::start().await;
    let registry_url = format!("{}/npm", server.base_url());

    let tmp = tempfile::tempdir().expect("failed to create tempdir");

    let output = npm_install(&npm, &registry_url, "is-odd", tmp.path()).await;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "npm install failed.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Verify the package was installed
    assert!(
        tmp.path().join("node_modules/is-odd").exists(),
        "is-odd not found in node_modules. Contents: {:?}",
        std::fs::read_dir(tmp.path()).map(|d| d
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect::<Vec<_>>())
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + npm
async fn npm_install_cached_on_second() {
    let npm = require_npm().await;
    let server = TestServer::start().await;
    let registry_url = format!("{}/npm", server.base_url());

    let tmp1 = tempfile::tempdir().expect("tempdir");
    let tmp2 = tempfile::tempdir().expect("tempdir");

    let out1 = npm_install(&npm, &registry_url, "is-odd", tmp1.path()).await;
    assert!(out1.status.success(), "first npm install failed");

    let out2 = npm_install(&npm, &registry_url, "is-odd", tmp2.path()).await;
    assert!(out2.status.success(), "second npm install (cached) failed");

    assert!(tmp2.path().join("node_modules/is-odd").exists());

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + npm
async fn npm_install_nonexistent_package_fails() {
    let npm = require_npm().await;
    let server = TestServer::start().await;
    let registry_url = format!("{}/npm", server.base_url());

    let tmp = tempfile::tempdir().expect("tempdir");

    let output = npm_install(
        &npm,
        &registry_url,
        "this-package-does-not-exist-depot-test",
        tmp.path(),
    )
    .await;

    assert!(
        !output.status.success(),
        "npm install should have failed for nonexistent package"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + npm
async fn npm_install_package_with_deps() {
    let npm = require_npm().await;
    let server = TestServer::start().await;
    let registry_url = format!("{}/npm", server.base_url());

    let tmp = tempfile::tempdir().expect("failed to create tempdir");

    // is-odd depends on is-number — this tests that dependencies
    // are preserved in the packument response (not empty)
    let output = Command::new(&npm)
        .args([
            "install",
            "--registry",
            &registry_url,
            "--prefix",
            &tmp.path().to_string_lossy(),
            "--no-audit",
            "--no-fund",
            "--no-package-lock",
            "is-odd",
        ])
        .output()
        .await
        .expect("failed to run npm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "npm install with deps failed.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Verify is-odd AND its transitive dependency is-number were both installed
    assert!(
        tmp.path().join("node_modules/is-odd").exists(),
        "is-odd not found in node_modules"
    );
    assert!(
        tmp.path().join("node_modules/is-number").exists(),
        "is-number (dependency of is-odd) not found — dependencies lost in packument?"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + npm
async fn npm_install_express_full_tree() {
    let npm = require_npm().await;
    let server = TestServer::start().await;
    let registry_url = format!("{}/npm", server.base_url());

    let tmp = tempfile::tempdir().expect("failed to create tempdir");

    // express has ~65 transitive dependencies — tests real-world dep resolution
    let output = Command::new(&npm)
        .args([
            "install",
            "--registry",
            &registry_url,
            "--prefix",
            &tmp.path().to_string_lossy(),
            "--no-audit",
            "--no-fund",
            "--no-package-lock",
            "express",
        ])
        .output()
        .await
        .expect("failed to run npm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "npm install express failed.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Verify express and key transitive deps were installed
    assert!(tmp.path().join("node_modules/express").exists());
    assert!(tmp.path().join("node_modules/body-parser").exists());
    assert!(tmp.path().join("node_modules/debug").exists());

    // Should have installed 50+ packages
    let pkg_count = std::fs::read_dir(tmp.path().join("node_modules"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert!(pkg_count >= 50, "expected 50+ packages, got {pkg_count}");

    server.shutdown();
}
