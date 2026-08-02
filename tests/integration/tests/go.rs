//! Go module proxy (GOPROXY) tests: a fast offline HTTP-level check of the mounted routes, and a
//! live `#[ignore]`d end-to-end run of the real `go` toolchain against Starmetal.
//!
//! Both build a fixture git repository with the `git` CLI and map its module path to the fixture's
//! `file://` URL via `go.module_overrides` — no network access, and no vanity-import resolution is
//! needed (out of scope for this increment; see `starmetal_adapters::go`).

use starmetal_integration_tests::{
    FIXTURE_COMMIT_DATE, GitFixture, GitFixtureBuilder, TestServer, go_module_fixture, require_go,
};
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

/// A two-release fixture for `example.com/mod`: `v1.0.0` and `v1.1.0`, each returning a distinct
/// string from `Greet`, so a test can tell which version's content it actually received.
fn two_version_module_fixture() -> GitFixture {
    GitFixtureBuilder::new()
        .file("go.mod", "module example.com/mod\n\ngo 1.21\n")
        .file(
            "greet.go",
            "package mod\n\n// Greet returns a fixed greeting.\nfunc Greet() string { return \"hello\" }\n",
        )
        .tag("v1.0.0")
        .commit()
        .file(
            "greet.go",
            "package mod\n\n// Greet returns a fixed greeting.\nfunc Greet() string { return \"hello v2\" }\n",
        )
        .tag("v1.1.0")
        .build()
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
async fn go_proxy_list_returns_every_tagged_version_ascending() {
    let fixture = two_version_module_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let list = client
        .get(format!("{}/example.com/mod/@v/list", server.go_proxy_url()))
        .send()
        .await
        .expect("list request");
    assert_eq!(list.status(), 200);
    assert_eq!(list.text().await.expect("list body"), "v1.0.0\nv1.1.0\n");

    server.shutdown();
}

#[tokio::test]
async fn go_proxy_latest_resolves_to_the_highest_semver_version() {
    let fixture = two_version_module_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let latest = client
        .get(format!("{}/example.com/mod/@latest", server.go_proxy_url()))
        .send()
        .await
        .expect("latest request");
    assert_eq!(latest.status(), 200);
    let latest_json: serde_json::Value = latest.json().await.expect("latest body is JSON");
    assert_eq!(latest_json["Version"], "v1.1.0");

    // Confirm @latest actually served v1.1.0's own content, not v1.0.0's.
    let go_mod = client
        .get(format!("{}/example.com/mod/@v/v1.1.0.zip", server.go_proxy_url()))
        .send()
        .await
        .expect("zip request");
    let zip_bytes = go_mod.bytes().await.expect("zip body");
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes.to_vec())).expect("valid module zip");
    let mut greet_go = archive
        .by_name("example.com/mod@v1.1.0/greet.go")
        .expect("greet.go entry");
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut greet_go, &mut contents).expect("read greet.go");
    assert!(
        contents.contains("hello v2"),
        "expected v1.1.0's own content: {contents}"
    );

    server.shutdown();
}

#[tokio::test]
async fn go_proxy_info_time_reflects_the_fixed_committer_date() {
    let fixture = go_module_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let info = client
        .get(format!("{}/example.com/mod/@v/v1.0.0.info", server.go_proxy_url()))
        .send()
        .await
        .expect("info request");
    assert_eq!(info.status(), 200);
    let info_json: serde_json::Value = info.json().await.expect("info body is JSON");
    assert_eq!(info_json["Time"], FIXTURE_COMMIT_DATE);

    server.shutdown();
}

#[tokio::test]
async fn go_proxy_module_zip_excludes_vendor_and_nested_go_mod_and_synthesizes_root_go_mod() {
    // No root go.mod in this fixture -- exercises synthesis -- plus a vendor/ tree and a nested
    // module (its own go.mod) that must both be excluded from the served module zip.
    let fixture = GitFixtureBuilder::new()
        .file("main.go", "package mod\n\nfunc Main() {}\n")
        .file("vendor/modules.txt", "ignored\n")
        .file("vendor/github.com/x/y/y.go", "ignored\n")
        .file("sub/go.mod", "module example.com/mod/sub\n")
        .file("sub/sub.go", "ignored\n")
        .tag("v1.0.0")
        .build();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let zip = client
        .get(format!("{}/example.com/mod/@v/v1.0.0.zip", server.go_proxy_url()))
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
        vec!["example.com/mod@v1.0.0/go.mod", "example.com/mod@v1.0.0/main.go"],
        "vendor/ and the nested sub/go.mod module must be excluded"
    );

    let mut go_mod = archive
        .by_name("example.com/mod@v1.0.0/go.mod")
        .expect("synthesized go.mod entry");
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut go_mod, &mut contents).expect("read go.mod");
    assert_eq!(contents, "module example.com/mod\n");

    server.shutdown();
}

#[tokio::test]
async fn go_proxy_reports_400_for_a_module_with_an_unrecognized_host() {
    // Unlike Swift's `package_overrides` (no fallback -> absent means 404 PackageNotFound), Go
    // falls back to a well-known-host mapping (github.com/gitlab.com/bitbucket.org/golang.org/x)
    // before giving up, so a module absent from `module_overrides` on an unrecognized host is a
    // client error (400 Adapter), not a 404 -- there is no host-shaped input at all to resolve. ~keep
    let fixture = go_module_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/unknown.example/mod/@v/list", server.go_proxy_url()))
        .send()
        .await
        .expect("list request");
    assert_eq!(response.status(), 400);

    server.shutdown();
}

#[tokio::test]
async fn go_proxy_reports_502_when_the_zip_exceeds_max_zip_bytes() {
    let fixture = go_module_fixture();
    let git_url = fixture.url.clone();
    let server = TestServer::start_with_config(move |config| {
        config.go.enabled = true;
        config
            .go
            .module_overrides
            .insert("example.com/mod".to_string(), git_url);
        // Smaller than any real module zip, so the fixture's archive always exceeds it.
        config.go.max_zip_bytes = 1;
    })
    .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/example.com/mod/@v/v1.0.0.zip", server.go_proxy_url()))
        .send()
        .await
        .expect("zip request");
    assert_eq!(response.status(), 502);

    server.shutdown();
}

#[tokio::test]
async fn go_proxy_module_zip_and_info_time_are_stable_across_a_server_restart() {
    let fixture = go_module_fixture();
    let client = reqwest::Client::new();

    let server = start_server_with_fixture(&fixture).await;
    let first_zip = client
        .get(format!("{}/example.com/mod/@v/v1.0.0.zip", server.go_proxy_url()))
        .send()
        .await
        .expect("zip request")
        .bytes()
        .await
        .expect("zip body");
    let first_info: serde_json::Value = client
        .get(format!("{}/example.com/mod/@v/v1.0.0.info", server.go_proxy_url()))
        .send()
        .await
        .expect("info request")
        .json()
        .await
        .expect("info body is JSON");
    server.shutdown();

    // A fresh server, same fixture: the git-mirror cache and everything downstream of it are
    // rebuilt from scratch, so byte-identical output here is the fixed commit dates paying off.
    let server = start_server_with_fixture(&fixture).await;
    let second_zip = client
        .get(format!("{}/example.com/mod/@v/v1.0.0.zip", server.go_proxy_url()))
        .send()
        .await
        .expect("zip request")
        .bytes()
        .await
        .expect("zip body");
    let second_info: serde_json::Value = client
        .get(format!("{}/example.com/mod/@v/v1.0.0.info", server.go_proxy_url()))
        .send()
        .await
        .expect("info request")
        .json()
        .await
        .expect("info body is JSON");
    server.shutdown();

    assert_eq!(
        first_zip, second_zip,
        "the module zip must be byte-identical across a restart"
    );
    assert_eq!(
        first_info["Time"], second_info["Time"],
        "the .info Time must be identical across a restart"
    );
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
