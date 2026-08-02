//! Swift Package Registry (SE-0292) proxy tests: fast offline HTTP-level checks of the mounted
//! routes, and a live `#[ignore]`d end-to-end run of the real `swift` toolchain against Starmetal.
//!
//! Both build a fixture git repository with the `git` CLI and map its registry identifier
//! (`test.fixture`) to the fixture's `file://` URL via `swift.package_overrides` -- no network
//! access, mirroring `zig.rs`/`go.rs`.

use std::path::Path;
use std::process::Command as StdCommand;

use sha2::{Digest, Sha256};
use starmetal_integration_tests::TestServer;
use tokio::process::Command;

fn git(dir: &Path, args: &[&str]) -> String {
    let output = StdCommand::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.test")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.test")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git CLI is available");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("git output is utf-8")
}

fn write_file(dir: &Path, relative: &str, contents: &str) {
    let path = dir.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(path, contents).expect("write fixture file");
}

/// A `test.fixture`-shaped Swift package fixture with one tagged release, `1.0.0`.
struct Fixture {
    _root: tempfile::TempDir,
    url: String,
}

fn build_fixture() -> Fixture {
    let root = tempfile::tempdir().expect("tempdir");
    let work = root.path().join("upstream");
    std::fs::create_dir_all(&work).expect("create work dir");

    git(&work, &["init", "-b", "main"]);
    write_file(
        &work,
        "Package.swift",
        "// swift-tools-version:5.9\nimport PackageDescription\n\nlet package = Package(\n    name: \"fixture\",\n    \
         products: [\n        .library(name: \"fixture\", targets: [\"fixture\"])\n    ],\n    targets: [\n        \
         .target(name: \"fixture\", path: \"Sources/fixture\")\n    ]\n)\n",
    );
    write_file(
        &work,
        "Sources/fixture/fixture.swift",
        "public struct Fixture {\n    public init() {}\n    public func hello() -> String { \"hello\" }\n}\n",
    );
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-m", "release 1.0.0"]);
    git(&work, &["tag", "1.0.0"]);

    let url = format!("file://{}", work.display());
    Fixture { _root: root, url }
}

async fn start_server_with_fixture(fixture: &Fixture) -> TestServer {
    let git_url = fixture.url.clone();
    TestServer::start_with_config(move |config| {
        config.swift.enabled = true;
        config
            .swift
            .package_overrides
            .insert("test.fixture".to_string(), git_url);
    })
    .await
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[tokio::test]
async fn swift_proxy_lists_the_tagged_release() {
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/test/fixture", server.swift_proxy_url()))
        .send()
        .await
        .expect("list releases request");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        response
            .headers()
            .get("content-version")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );

    let body: serde_json::Value = response.json().await.expect("list releases body");
    let releases = body["releases"].as_object().expect("releases object");
    assert_eq!(releases.len(), 1);
    assert_eq!(
        releases["1.0.0"]["url"].as_str(),
        Some(format!("{}/test/fixture/1.0.0", server.swift_proxy_url()).as_str())
    );

    server.shutdown();
}

#[tokio::test]
async fn swift_proxy_serves_release_metadata_with_a_checksum_matching_the_zip() {
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let metadata_response = client
        .get(format!("{}/test/fixture/1.0.0", server.swift_proxy_url()))
        .send()
        .await
        .expect("release metadata request");
    assert_eq!(metadata_response.status(), 200);
    assert_eq!(
        metadata_response
            .headers()
            .get("content-version")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let metadata: serde_json::Value = metadata_response.json().await.expect("release metadata body");
    assert_eq!(metadata["id"], "test.fixture");
    assert_eq!(metadata["version"], "1.0.0");
    let resources = metadata["resources"].as_array().expect("resources array");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["name"], "source-archive");
    assert_eq!(resources[0]["type"], "application/zip");
    let claimed_checksum = resources[0]["checksum"].as_str().expect("checksum string").to_string();

    let zip_response = client
        .get(format!("{}/test/fixture/1.0.0.zip", server.swift_proxy_url()))
        .send()
        .await
        .expect("archive request");
    assert_eq!(zip_response.status(), 200);
    let zip_bytes = zip_response.bytes().await.expect("archive body");
    assert_eq!(claimed_checksum, sha256_hex(&zip_bytes));

    server.shutdown();
}

#[tokio::test]
async fn swift_proxy_serves_the_manifest_with_text_x_swift_content_type() {
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/test/fixture/1.0.0/Package.swift", server.swift_proxy_url()))
        .send()
        .await
        .expect("manifest request");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/x-swift")
    );
    let body = response.text().await.expect("manifest body");
    assert!(body.contains("swift-tools-version"));

    server.shutdown();
}

#[tokio::test]
async fn swift_proxy_serves_the_source_archive_with_correct_headers() {
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/test/fixture/1.0.0.zip", server.swift_proxy_url()))
        .send()
        .await
        .expect("archive request");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/zip")
    );
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok()),
        Some("attachment; filename=\"fixture-1.0.0.zip\"")
    );
    let digest_header = response
        .headers()
        .get("digest")
        .and_then(|value| value.to_str().ok())
        .expect("digest header")
        .to_string();
    assert!(digest_header.starts_with("sha-256="));

    let bytes = response.bytes().await.expect("archive body");
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).expect("valid zip archive");
    let mut names: Vec<String> = (0..archive.len())
        .map(|index| archive.by_index(index).expect("zip entry").name().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["fixture/Package.swift", "fixture/Sources/fixture/fixture.swift"],
        "every entry is prefixed with the package name, matching `swift package archive-source`'s layout"
    );

    server.shutdown();
}

#[tokio::test]
async fn swift_proxy_reports_404_for_an_unknown_version() {
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/test/fixture/9.9.9", server.swift_proxy_url()))
        .send()
        .await
        .expect("release metadata request");
    assert_eq!(response.status(), 404);

    server.shutdown();
}

#[tokio::test]
async fn swift_proxy_reports_502_when_the_archive_exceeds_max_archive_bytes() {
    let fixture = build_fixture();
    let git_url = fixture.url.clone();
    let server = TestServer::start_with_config(move |config| {
        config.swift.enabled = true;
        config
            .swift
            .package_overrides
            .insert("test.fixture".to_string(), git_url);
        // Smaller than any real archive, so the fixture's archive always exceeds it.
        config.swift.max_archive_bytes = 1;
    })
    .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/test/fixture/1.0.0.zip", server.swift_proxy_url()))
        .send()
        .await
        .expect("archive request");
    assert_eq!(response.status(), 502);

    server.shutdown();
}

async fn require_swift() -> String {
    if let Ok(output) = Command::new("swift").arg("--version").output().await
        && output.status.success()
    {
        return "swift".to_string();
    }
    panic!("swift not found — install the Swift toolchain to run Swift E2E tests");
}

/// Configure `project` to speak to `registry_url` as its default (unscoped) registry, isolated
/// from the developer's real `~/Library/org.swift.swiftpm` state via `--cache-path`/
/// `--security-path` (confirmed empirically to redirect the registry download cache and the
/// trust-on-first-use fingerprint store respectively; the project-local `registries.json` itself
/// always lives under `<package-path>/.swiftpm/configuration`, so no `--config-path` override is
/// needed for that part). This is what keeps the test independent and idempotent across repeated
/// local runs (ADR-agnostic test-hygiene requirement): without it, SwiftPM's per-user fingerprint
/// pin for `test.fixture` would persist across runs and reject a later run's differently-timed
/// commit (the archive's bytes are not reproducible run-to-run, since `starmetal-git` pins entry
/// mtimes to the commit time, and each fixture build creates a fresh commit).
async fn configure_registry(swift: &str, project: &Path, cache_path: &Path, security_path: &Path, registry_url: &str) {
    let output = Command::new(swift)
        .args(["package-registry", "set", "--allow-insecure-http"])
        .arg("--cache-path")
        .arg(cache_path)
        .arg("--security-path")
        .arg(security_path)
        .arg(registry_url)
        .current_dir(project)
        .output()
        .await
        .expect("failed to run swift package-registry set");
    assert!(
        output.status.success(),
        "swift package-registry set failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore]
async fn swift_package_resolve_downloads_and_builds_against_starmetal() {
    let swift = require_swift().await;
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;

    let project = tempfile::tempdir().expect("project tempdir");
    write_file(
        project.path(),
        "Package.swift",
        "// swift-tools-version:5.9\nimport PackageDescription\n\nlet package = Package(\n    name: \"consumer\",\n    \
         dependencies: [\n        .package(id: \"test.fixture\", from: \"1.0.0\")\n    ],\n    targets: [\n        \
         .executableTarget(name: \"consumer\", dependencies: [.product(name: \"fixture\", package: \
         \"test.fixture\")])\n    ]\n)\n",
    );
    write_file(
        project.path(),
        "Sources/consumer/main.swift",
        "import fixture\nprint(Fixture().hello())\n",
    );

    let cache_path = tempfile::tempdir().expect("swiftpm cache tempdir");
    let security_path = tempfile::tempdir().expect("swiftpm security tempdir");
    configure_registry(
        &swift,
        project.path(),
        cache_path.path(),
        security_path.path(),
        &server.swift_proxy_url(),
    )
    .await;

    let resolve = Command::new(&swift)
        .arg("package")
        .arg("resolve")
        .arg("--cache-path")
        .arg(cache_path.path())
        .arg("--security-path")
        .arg(security_path.path())
        .current_dir(project.path())
        .output()
        .await
        .expect("failed to run swift package resolve");
    let resolve_stdout = String::from_utf8_lossy(&resolve.stdout);
    let resolve_stderr = String::from_utf8_lossy(&resolve.stderr);
    assert!(
        resolve.status.success(),
        "swift package resolve failed:\nstdout: {resolve_stdout}\nstderr: {resolve_stderr}"
    );

    let resolved_manifest =
        std::fs::read_to_string(project.path().join("Package.resolved")).expect("Package.resolved was written");
    assert!(
        resolved_manifest.contains("test.fixture"),
        "expected test.fixture to be a resolved dependency: {resolved_manifest}"
    );

    let build = Command::new(&swift)
        .arg("build")
        .arg("--cache-path")
        .arg(cache_path.path())
        .arg("--security-path")
        .arg(security_path.path())
        .current_dir(project.path())
        .output()
        .await
        .expect("failed to run swift build");
    assert!(
        build.status.success(),
        "swift build failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    server.shutdown();
}
