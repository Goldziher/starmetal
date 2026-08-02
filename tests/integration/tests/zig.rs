//! Zig tarball proxy tests: a fast offline HTTP-level check of the mounted route, and a live
//! `#[ignore]`d end-to-end run of the real `zig` toolchain against Starmetal.
//!
//! Both build a fixture git repository with the `git` CLI and map its repository path to the
//! fixture's `file://` URL via `zig.repo_overrides` -- no network access, mirroring `go.rs`.

use std::io::Read;
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

/// An `example.com/pkg`-shaped Zig package fixture with one tagged release, `v1.0.0`.
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
        "build.zig.zon",
        ".{\n    .name = .fixture,\n    .version = \"1.0.0\",\n    .fingerprint = 0x5e540eeeedcbb0d,\n    \
         .paths = .{\"\"},\n}\n",
    );
    write_file(
        &work,
        "build.zig",
        "const std = @import(\"std\");\npub fn build(b: *std.Build) void {\n    _ = b;\n}\n",
    );
    write_file(&work, "src/main.zig", "pub fn main() void {}\n");
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-m", "release 1.0.0"]);
    git(&work, &["tag", "v1.0.0"]);

    let url = format!("file://{}", work.display());
    Fixture { _root: root, url }
}

async fn start_server_with_fixture(fixture: &Fixture) -> TestServer {
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
    let fixture = build_fixture();
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
    let fixture = build_fixture();
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
async fn zig_proxy_reports_502_when_the_archive_exceeds_max_archive_bytes() {
    let fixture = build_fixture();
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

async fn require_zig() -> String {
    if let Ok(output) = Command::new("zig").arg("version").output().await
        && output.status.success()
    {
        return "zig".to_string();
    }
    panic!("zig not found — install the Zig toolchain to run Zig E2E tests");
}

#[tokio::test]
#[ignore]
async fn zig_fetch_downloads_and_hashes_a_tarball_through_starmetal() {
    let zig = require_zig().await;
    let fixture = build_fixture();
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
