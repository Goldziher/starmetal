//! Zig tarball proxy tests: a fast offline HTTP-level check of the mounted route, and a live
//! `#[ignore]`d end-to-end run of the real `zig` toolchain against Starmetal.
//!
//! Both build a fixture git repository with the `git` CLI and map its repository path to the
//! fixture's `file://` URL via `zig.repo_overrides` -- no network access, mirroring `go.rs`.

use std::io::Read;

use starmetal_integration_tests::{GitFixture, GitFixtureBuilder, TestServer, require_zig, zig_package_fixture};
use tokio::process::Command;

async fn start_server_with_fixture(fixture: &GitFixture) -> TestServer {
    let git_url = fixture.url.clone();
    TestServer::start_with_config(move |config| {
        config.zig.enabled = true;
        config.zig.repo_overrides.insert("example.com/pkg".to_string(), git_url);
    })
    .await
}

fn tar_gz_entry_names(bytes: &[u8]) -> Vec<String> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut names: Vec<String> = archive
        .entries()
        .expect("tar entries")
        .map(|entry| {
            entry
                .expect("tar entry")
                .path()
                .expect("entry path")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn zig_proxy_serves_the_tarball_for_a_tagged_ref() {
    let fixture = zig_package_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/example.com/pkg/v1.0.0.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/gzip")
    );

    let bytes = response.bytes().await.expect("tarball body");
    let names = tar_gz_entry_names(&bytes);
    assert_eq!(
        names,
        vec!["build.zig", "build.zig.zon", "src/main.zig"],
        "entries sit at the tree root, with no top-level directory prefix"
    );

    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);
    let mut found_zon = false;
    for entry in archive.entries().expect("tar entries") {
        let mut entry = entry.expect("tar entry");
        if entry.path().expect("entry path").to_string_lossy() == "build.zig.zon" {
            let mut contents = String::new();
            entry.read_to_string(&mut contents).expect("read build.zig.zon");
            assert!(contents.contains(".version = \"1.0.0\""));
            found_zon = true;
        }
    }
    assert!(found_zon, "build.zig.zon entry was present and readable");

    server.shutdown();
}

#[tokio::test]
async fn zig_proxy_reports_404_for_an_unknown_ref() {
    let fixture = zig_package_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/example.com/pkg/v9.9.9.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request");
    assert_eq!(response.status(), 404);

    server.shutdown();
}

#[tokio::test]
async fn zig_proxy_serves_distinct_content_for_each_of_two_tagged_refs() {
    let fixture = GitFixtureBuilder::new()
        .file(
            "build.zig.zon",
            ".{\n    .name = .fixture,\n    .version = \"1.0.0\",\n}\n",
        )
        .tag("v1.0.0")
        .commit()
        .file(
            "build.zig.zon",
            ".{\n    .name = .fixture,\n    .version = \"2.0.0\",\n}\n",
        )
        .tag("v2.0.0")
        .build();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let v1_bytes = client
        .get(format!("{}/example.com/pkg/v1.0.0.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("v1.0.0 tarball request")
        .bytes()
        .await
        .expect("v1.0.0 tarball body");
    let v2_bytes = client
        .get(format!("{}/example.com/pkg/v2.0.0.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("v2.0.0 tarball request")
        .bytes()
        .await
        .expect("v2.0.0 tarball body");
    assert_ne!(
        v1_bytes, v2_bytes,
        "each tagged ref must serve its own commit's content"
    );

    let read_zon = |bytes: &[u8]| -> String {
        let decoder = flate2::read::GzDecoder::new(bytes);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().expect("tar entries") {
            let mut entry = entry.expect("tar entry");
            if entry.path().expect("entry path").to_string_lossy() == "build.zig.zon" {
                let mut contents = String::new();
                entry.read_to_string(&mut contents).expect("read build.zig.zon");
                return contents;
            }
        }
        panic!("build.zig.zon entry not found");
    };
    assert!(read_zon(&v1_bytes).contains(".version = \"1.0.0\""));
    assert!(read_zon(&v2_bytes).contains(".version = \"2.0.0\""));

    server.shutdown();
}

#[tokio::test]
async fn zig_proxy_rejects_an_untagged_branch_ref() {
    // "main" is a real ref (the fixture's default branch) but not a tag -- only tagged refs are
    // in scope, so this must 404 exactly like a wholly unknown ref.
    let fixture = zig_package_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/example.com/pkg/main.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request");
    assert_eq!(response.status(), 404);

    server.shutdown();
}

#[tokio::test]
async fn zig_proxy_rejects_a_traversal_shaped_ref() {
    let fixture = zig_package_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    // The ref is `..` (filename `...tar.gz` minus the `.tar.gz` suffix): traversal-shaped, but
    // resolved the same way as any other ref -- against the repository's tag names -- so it 404s
    // rather than escaping the repository.
    let response = client
        .get(format!("{}/example.com/pkg/...tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request");
    assert_eq!(response.status(), 404);

    server.shutdown();
}

#[tokio::test]
async fn zig_proxy_reports_400_for_a_disallowed_host_not_in_overrides() {
    // Unlike Swift's `package_overrides` (no fallback -> absent means 404 PackageNotFound), Zig
    // falls back to a well-known-host mapping (github.com/gitlab.com/bitbucket.org) before giving
    // up, so a repository path on an unrecognized host absent from `repo_overrides` is a client
    // error (400 Adapter), not a 404. ~keep
    let fixture = zig_package_fixture();
    let server = start_server_with_fixture(&fixture).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/unknown.example/pkg/v1.0.0.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request");
    assert_eq!(response.status(), 400);

    server.shutdown();
}

#[tokio::test]
async fn zig_proxy_repo_overrides_longest_prefix_wins_over_a_shorter_match() {
    let exact_fixture = GitFixtureBuilder::new()
        .file("MARKER.txt", "exact-override\n")
        .tag("v1.0.0")
        .build();
    let prefix_fixture = GitFixtureBuilder::new()
        .file("MARKER.txt", "prefix-override\n")
        .tag("v1.0.0")
        .build();
    let exact_url = exact_fixture.url.clone();
    let prefix_url = prefix_fixture.url.clone();
    let server = TestServer::start_with_config(move |config| {
        config.zig.enabled = true;
        // The shorter, prefix-matching override is registered first; the longer, exact override
        // for the full repo path must still win.
        config.zig.repo_overrides.insert("example.com".to_string(), prefix_url);
        config
            .zig
            .repo_overrides
            .insert("example.com/pkg".to_string(), exact_url);
    })
    .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/example.com/pkg/v1.0.0.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request");
    assert_eq!(response.status(), 200);
    let bytes = response.bytes().await.expect("tarball body");
    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);
    let mut marker = String::new();
    for entry in archive.entries().expect("tar entries") {
        let mut entry = entry.expect("tar entry");
        if entry.path().expect("entry path").to_string_lossy() == "MARKER.txt" {
            entry.read_to_string(&mut marker).expect("read MARKER.txt");
        }
    }
    assert_eq!(marker, "exact-override\n", "the longer, exact override must win");

    server.shutdown();
}

#[tokio::test]
async fn zig_proxy_tarball_is_stable_across_a_server_restart() {
    let fixture = zig_package_fixture();
    let client = reqwest::Client::new();

    let server = start_server_with_fixture(&fixture).await;
    let first = client
        .get(format!("{}/example.com/pkg/v1.0.0.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request")
        .bytes()
        .await
        .expect("tarball body");
    server.shutdown();

    // A fresh server, same fixture: the git-mirror cache is rebuilt from scratch, so a
    // byte-identical tarball here is the fixed commit dates paying off.
    let server = start_server_with_fixture(&fixture).await;
    let second = client
        .get(format!("{}/example.com/pkg/v1.0.0.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request")
        .bytes()
        .await
        .expect("tarball body");
    server.shutdown();

    assert_eq!(first, second, "the tarball must be byte-identical across a restart");
}

#[tokio::test]
async fn zig_proxy_reports_502_when_the_archive_exceeds_max_archive_bytes() {
    let fixture = zig_package_fixture();
    let git_url = fixture.url.clone();
    let server = TestServer::start_with_config(move |config| {
        config.zig.enabled = true;
        config.zig.repo_overrides.insert("example.com/pkg".to_string(), git_url);
        // Smaller than any real tarball, so the fixture's archive always exceeds it.
        config.zig.max_archive_bytes = 1;
    })
    .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/example.com/pkg/v1.0.0.tar.gz", server.zig_proxy_url()))
        .send()
        .await
        .expect("tarball request");
    assert_eq!(response.status(), 502);

    server.shutdown();
}

#[tokio::test]
#[ignore]
async fn zig_fetch_downloads_and_hashes_a_tarball_through_starmetal() {
    let zig = require_zig().await;
    let fixture = zig_package_fixture();
    let server = start_server_with_fixture(&fixture).await;

    // `zig fetch` (without `--save`) requires being run inside a project that already has a
    // `build.zig` -- it looks for one in the current directory or a parent -- so build a minimal
    // consumer project with `zig init`, mirroring how `go.rs` runs `go mod download` from inside a
    // scratch module.
    let project = tempfile::tempdir().expect("project tempdir");
    let init = Command::new(&zig)
        .arg("init")
        .current_dir(project.path())
        .output()
        .await
        .expect("failed to run zig init");
    assert!(
        init.status.success(),
        "zig init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let global_cache = tempfile::tempdir().expect("ZIG_GLOBAL_CACHE_DIR tempdir");
    let tarball_url = format!("{}/example.com/pkg/v1.0.0.tar.gz", server.zig_proxy_url());

    let output = Command::new(&zig)
        .args(["fetch", &tarball_url])
        .current_dir(project.path())
        .env("ZIG_GLOBAL_CACHE_DIR", global_cache.path())
        .output()
        .await
        .expect("failed to run zig fetch");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let command = format!(
        "ZIG_GLOBAL_CACHE_DIR={} zig fetch {tarball_url}",
        global_cache.path().display()
    );
    assert!(
        output.status.success(),
        "zig fetch failed: {command}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let hash = stdout.trim();
    assert!(
        !hash.is_empty(),
        "expected zig fetch to print a package hash to stdout: {command}\nstderr: {stderr}"
    );

    server.shutdown();
}
