//! Go module proxy (GOPROXY) tests: a fast offline HTTP-level check of the mounted routes, and a
//! live `#[ignore]`d end-to-end run of the real `go` toolchain against Starmetal.
//!
//! Both build a fixture git repository with the `git` CLI and map its module path to the fixture's
//! `file://` URL via `go.module_overrides` — no network access, and no vanity-import resolution is
//! needed (out of scope for this increment; see `starmetal_adapters::go`).

use std::path::Path;
use std::process::Command as StdCommand;

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

/// A `github.com/starmetal/example`-shaped module fixture with one tagged release, `v1.0.0`.
struct Fixture {
    _root: tempfile::TempDir,
    url: String,
}

fn build_fixture() -> Fixture {
    let root = tempfile::tempdir().expect("tempdir");
    let work = root.path().join("upstream");
    std::fs::create_dir_all(&work).expect("create work dir");

    git(&work, &["init", "-b", "main"]);
    write_file(&work, "go.mod", "module example.com/mod\n\ngo 1.21\n");
    write_file(
        &work,
        "greet.go",
        "package mod\n\n// Greet returns a fixed greeting.\nfunc Greet() string { return \"hello\" }\n",
    );
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-m", "release 1.0.0"]);
    git(&work, &["tag", "v1.0.0"]);

    let url = format!("file://{}", work.display());
    Fixture { _root: root, url }
}

async fn start_server_with_fixture(fixture: &Fixture) -> TestServer {
    let git_url = fixture.url.clone();
    TestServer::start_with_config(move |config| {
        config.go.enabled = true;
        config
            .go
            .module_overrides
            .insert("example.com/mod".to_string(), git_url);
    })
    .await
}

#[tokio::test]
async fn go_proxy_serves_list_info_mod_and_zip() {
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();
    let base = server.go_proxy_url();

    let list = client
        .get(format!("{base}/example.com/mod/@v/list"))
        .send()
        .await
        .expect("list request");
    assert_eq!(list.status(), 200);
    assert_eq!(list.text().await.expect("list body"), "v1.0.0\n");

    let info = client
        .get(format!("{base}/example.com/mod/@v/v1.0.0.info"))
        .send()
        .await
        .expect("info request");
    assert_eq!(info.status(), 200);
    let info_json: serde_json::Value = info.json().await.expect("info body is JSON");
    assert_eq!(info_json["Version"], "v1.0.0");
    assert!(info_json["Time"].as_str().is_some_and(|t| t.ends_with('Z')));

    let go_mod = client
        .get(format!("{base}/example.com/mod/@v/v1.0.0.mod"))
        .send()
        .await
        .expect("mod request");
    assert_eq!(go_mod.status(), 200);
    assert_eq!(
        go_mod.text().await.expect("mod body"),
        "module example.com/mod\n\ngo 1.21\n"
    );

    let latest = client
        .get(format!("{base}/example.com/mod/@latest"))
        .send()
        .await
        .expect("latest request");
    assert_eq!(latest.status(), 200);
    let latest_json: serde_json::Value = latest.json().await.expect("latest body is JSON");
    assert_eq!(latest_json["Version"], "v1.0.0");

    let zip = client
        .get(format!("{base}/example.com/mod/@v/v1.0.0.zip"))
        .send()
        .await
        .expect("zip request");
    assert_eq!(zip.status(), 200);
    let zip_bytes = zip.bytes().await.expect("zip body");
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes.to_vec())).expect("valid module zip");
    let names: Vec<String> = (0..archive.len())
        .map(|index| archive.by_index(index).expect("entry").name().to_string())
        .collect();
    assert_eq!(
        names,
        vec!["example.com/mod@v1.0.0/go.mod", "example.com/mod@v1.0.0/greet.go"]
    );

    server.shutdown();
}

#[tokio::test]
async fn go_proxy_reports_404_for_an_unknown_version() {
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/example.com/mod/@v/v9.9.9.info", server.go_proxy_url()))
        .send()
        .await
        .expect("info request");
    assert_eq!(response.status(), 404);

    server.shutdown();
}

async fn require_go() -> String {
    if let Ok(output) = Command::new("go").arg("version").output().await
        && output.status.success()
    {
        return "go".to_string();
    }
    panic!("go not found — install the Go toolchain to run Go E2E tests");
}

#[tokio::test]
#[ignore]
async fn go_get_resolves_and_downloads_a_module_through_starmetal() {
    let go = require_go().await;
    let fixture = build_fixture();
    let server = start_server_with_fixture(&fixture).await;

    let project = tempfile::tempdir().expect("project tempdir");
    std::fs::write(project.path().join("go.mod"), "module scratch\n\ngo 1.21\n").expect("write scratch go.mod");
    let gomodcache = tempfile::tempdir().expect("GOMODCACHE tempdir");
    let gopath = tempfile::tempdir().expect("GOPATH tempdir");
    let goenv = tempfile::tempdir().expect("GOENV tempdir");

    // `go mod download` (rather than `go get`) guarantees the module is fetched and extracted into
    // GOMODCACHE regardless of whether anything in `scratch` actually imports it yet.
    let output = Command::new(&go)
        .args(["mod", "download", "example.com/mod@v1.0.0"])
        .current_dir(project.path())
        .env("GOPROXY", server.go_proxy_url())
        .env("GOSUMDB", "off")
        .env("GOMODCACHE", gomodcache.path())
        .env("GOPATH", gopath.path())
        .env("GOENV", goenv.path().join("env"))
        .env("GOFLAGS", "-mod=mod")
        .output()
        .await
        .expect("failed to run go mod download");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let command = format!(
        "GOPROXY={} GOSUMDB=off GOMODCACHE={} go mod download example.com/mod@v1.0.0",
        server.go_proxy_url(),
        gomodcache.path().display()
    );
    assert!(
        output.status.success(),
        "go mod download failed: {command}\nstdout: {stdout}\nstderr: {stderr}"
    );

    let extracted = gomodcache.path().join("example.com/mod@v1.0.0");
    assert!(
        extracted.join("go.mod").exists(),
        "expected the module cache to contain the extracted module at {}",
        extracted.display()
    );
    assert!(
        extracted.join("greet.go").exists(),
        "expected the module cache to contain greet.go at {}",
        extracted.display()
    );

    server.shutdown();
}
