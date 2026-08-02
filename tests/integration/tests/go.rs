//! Go module proxy (GOPROXY) tests: a fast offline HTTP-level check of the mounted routes, and a
//! live `#[ignore]`d end-to-end run of the real `go` toolchain against Starmetal.
//!
//! Both build a fixture git repository with the `git` CLI and map its module path to the fixture's
//! `file://` URL via `go.module_overrides` — no network access, and no vanity-import resolution is
//! needed (out of scope for this increment; see `starmetal_adapters::go`).

use starmetal_integration_tests::{GitFixture, TestServer, go_module_fixture, require_go};
use tokio::process::Command;

async fn start_server_with_fixture(fixture: &GitFixture) -> TestServer {
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
    let fixture = go_module_fixture();
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
    let fixture = go_module_fixture();
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

#[tokio::test]
#[ignore]
async fn go_get_resolves_and_downloads_a_module_through_starmetal() {
    let go = require_go().await;
    let fixture = go_module_fixture();
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
