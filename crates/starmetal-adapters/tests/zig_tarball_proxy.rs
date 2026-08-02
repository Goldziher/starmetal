//! Offline tests for the Zig tarball proxy adapter against a real fixture git repository, built
//! with the `git` CLI (no network access), mirroring the pattern `go_module_proxy.rs` uses.
#![cfg(feature = "zig")]

use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use flate2::read::GzDecoder;
use starmetal_adapters::zig::upstream::{archive_tar_gz, ensure_mirror, list_refs, resolve_repo_url};
use starmetal_git::{GitRefKind, GixMirror};
use tar::Archive;

struct Fixture {
    _root: tempfile::TempDir,
    url: String,
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
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

/// A Zig package repository with a root `build.zig`/`build.zig.zon`/`src/main.zig`, one tag, and a
/// branch — so tests can assert only the tag resolves.
fn build_fixture() -> Fixture {
    let root = tempfile::tempdir().expect("tempdir");
    let work = root.path().join("upstream");
    std::fs::create_dir_all(&work).expect("create work dir");

    git(&work, &["init", "-b", "main"]);
    write_file(
        &work,
        "build.zig.zon",
        ".{\n    .name = .fixture,\n    .version = \"1.0.0\",\n    .fingerprint = 0x5e540eeeedcbb0d,\n    .paths = .{\"\"},\n}\n",
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

fn cache_root() -> tempfile::TempDir {
    tempfile::tempdir().expect("cache tempdir")
}

fn tar_gz_entry_names(bytes: &[u8]) -> Vec<String> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = Archive::new(decoder);
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

#[test]
fn resolves_well_known_hosts_and_overrides() {
    let overrides = std::collections::HashMap::new();
    assert_eq!(
        resolve_repo_url("github.com/foo/bar", &overrides).unwrap(),
        "https://github.com/foo/bar"
    );
}

#[tokio::test]
async fn only_the_tagged_ref_resolves_not_the_branch() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    ensure_mirror(&mirror, &fixture.url).await.expect("mirror");

    let refs = list_refs(&mirror, &fixture.url).await.expect("list refs");
    assert!(refs.iter().any(|r| r.kind == GitRefKind::Tag && r.name == "v1.0.0"));
    assert!(refs.iter().any(|r| r.kind == GitRefKind::Branch && r.name == "main"));
}

#[tokio::test]
async fn tarball_is_root_level_with_no_prefix_and_decompresses() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    ensure_mirror(&mirror, &fixture.url).await.expect("mirror");

    let bytes = archive_tar_gz(&mirror, &fixture.url, "v1.0.0")
        .await
        .expect("tar.gz archive");
    let names = tar_gz_entry_names(&bytes);
    assert_eq!(
        names,
        vec!["build.zig", "build.zig.zon", "src/main.zig"],
        "entries sit at the tree root, with no top-level directory prefix"
    );

    let decoder = GzDecoder::new(&bytes[..]);
    let mut archive = Archive::new(decoder);
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
}

#[tokio::test]
async fn archive_construction_is_deterministic_for_a_fixed_commit() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    ensure_mirror(&mirror, &fixture.url).await.expect("mirror");

    let first = archive_tar_gz(&mirror, &fixture.url, "v1.0.0")
        .await
        .expect("first archive");
    let second = archive_tar_gz(&mirror, &fixture.url, "v1.0.0")
        .await
        .expect("second archive");
    assert_eq!(first, second, "tarball construction is byte-stable for the same commit");
}
