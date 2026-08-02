//! Offline integration tests for the gitoxide-backed [`GixMirror`].
//!
//! Each test builds a throwaway git repository in a tempdir with the `git` CLI, serves it over a
//! `file://` URL, and exercises the mirror end to end. No network access is involved.

#![cfg(feature = "gix-backend")]

use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use starmetal_git::{ArchiveFormat, GitMirror, GitRefKind, GixMirror};

/// A fixture upstream repository and the commit oids of its two tagged releases.
struct Fixture {
    _root: tempfile::TempDir,
    url: String,
    v1_0_0: String,
    v1_1_0: String,
    v1_0_0_time: i64,
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

/// Build a two-release fixture: v1.0.0 (README + src/lib.rs) then v1.1.0 (adds go.mod, edits README).
fn build_fixture() -> Fixture {
    let root = tempfile::tempdir().expect("tempdir");
    let work = root.path().join("upstream");
    std::fs::create_dir_all(&work).expect("create work dir");

    git(&work, &["init", "-b", "main"]);

    write_file(&work, "README", "readme v1\n");
    write_file(&work, "src/lib.rs", "pub fn version() -> &'static str { \"1.0.0\" }\n");
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-m", "release 1.0.0"]);
    git(&work, &["tag", "v1.0.0"]);
    let v1_0_0 = git(&work, &["rev-parse", "HEAD"]).trim().to_owned();
    let v1_0_0_time: i64 = git(&work, &["log", "-1", "--format=%ct"])
        .trim()
        .parse()
        .expect("commit time is a unix timestamp");

    write_file(&work, "README", "readme v1.1\n");
    write_file(&work, "go.mod", "module example.com/foo\n\ngo 1.21\n");
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-m", "release 1.1.0"]);
    git(&work, &["tag", "v1.1.0"]);
    let v1_1_0 = git(&work, &["rev-parse", "HEAD"]).trim().to_owned();

    let url = format!("file://{}", work.display());
    Fixture {
        _root: root,
        url,
        v1_0_0,
        v1_1_0,
        v1_0_0_time,
    }
}

fn cache_root() -> tempfile::TempDir {
    tempfile::tempdir().expect("cache tempdir")
}

#[tokio::test]
async fn ensure_mirror_is_idempotent_and_refetches_when_stale() {
    let fixture = build_fixture();
    let cache = cache_root();
    // A zero interval forces the refresh (open-existing + fetch) path on every call.
    let mirror = GixMirror::new(cache.path(), Duration::ZERO);

    mirror.ensure_mirror(&fixture.url).await.expect("first mirror succeeds");
    mirror
        .ensure_mirror(&fixture.url)
        .await
        .expect("second mirror refreshes without error");
}

#[tokio::test]
async fn list_refs_returns_tags_and_branch_with_correct_kinds() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    mirror.ensure_mirror(&fixture.url).await.expect("mirror");

    let refs = mirror.list_refs(&fixture.url).await.expect("list refs");

    let tag_1_0 = refs.iter().find(|r| r.name == "v1.0.0").expect("v1.0.0 present");
    let tag_1_1 = refs.iter().find(|r| r.name == "v1.1.0").expect("v1.1.0 present");
    let branch = refs.iter().find(|r| r.name == "main").expect("main branch present");

    assert_eq!(tag_1_0.kind, GitRefKind::Tag);
    assert_eq!(tag_1_1.kind, GitRefKind::Tag);
    assert_eq!(branch.kind, GitRefKind::Branch);

    // Lightweight tags point straight at the tagged commit.
    assert_eq!(tag_1_0.target, fixture.v1_0_0);
    assert_eq!(tag_1_1.target, fixture.v1_1_0);
    assert_eq!(branch.target, fixture.v1_1_0);
}

#[tokio::test]
async fn resolve_returns_commit_for_tag_and_none_for_missing() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    mirror.ensure_mirror(&fixture.url).await.expect("mirror");

    let resolved = mirror.resolve(&fixture.url, "v1.0.0").await.expect("resolve tag");
    assert_eq!(resolved, Some(fixture.v1_0_0.clone()));

    let missing = mirror
        .resolve(&fixture.url, "nonexistent")
        .await
        .expect("resolve missing");
    assert_eq!(missing, None);
}

#[tokio::test]
async fn commit_time_returns_the_tagged_commit_time_and_none_for_missing() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    mirror.ensure_mirror(&fixture.url).await.expect("mirror");

    let time = mirror
        .commit_time(&fixture.url, "v1.0.0")
        .await
        .expect("commit time for tag")
        .expect("v1.0.0 has a commit time");
    assert_eq!(time, fixture.v1_0_0_time);

    let missing = mirror
        .commit_time(&fixture.url, "nonexistent")
        .await
        .expect("commit time for missing ref");
    assert_eq!(missing, None);
}

#[tokio::test]
async fn read_blob_returns_file_bytes_and_none_for_missing_path() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    mirror.ensure_mirror(&fixture.url).await.expect("mirror");

    let go_mod = mirror
        .read_blob(&fixture.url, "v1.1.0", "go.mod")
        .await
        .expect("read go.mod")
        .expect("go.mod exists at v1.1.0");
    assert_eq!(&go_mod[..], b"module example.com/foo\n\ngo 1.21\n");

    // go.mod does not exist at the earlier release.
    let absent = mirror
        .read_blob(&fixture.url, "v1.0.0", "go.mod")
        .await
        .expect("read go.mod at v1.0.0");
    assert_eq!(absent, None);

    let missing = mirror
        .read_blob(&fixture.url, "v1.1.0", "does/not/exist.txt")
        .await
        .expect("read missing path");
    assert_eq!(missing, None);
}

fn tar_gz_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = Vec::new();
    for entry in archive.entries().expect("tar entries") {
        let mut entry = entry.expect("tar entry");
        let path = entry.path().expect("entry path").to_string_lossy().into_owned();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).expect("read entry");
        entries.push((path, data));
    }
    entries
}

fn zip_entry_names(bytes: &[u8]) -> zip::ZipArchive<std::io::Cursor<Vec<u8>>> {
    zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).expect("valid zip archive")
}

#[tokio::test]
async fn archive_tar_gz_reflects_the_requested_ref() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    mirror.ensure_mirror(&fixture.url).await.expect("mirror");

    let archive = mirror
        .archive(&fixture.url, "v1.0.0", ArchiveFormat::TarGz)
        .await
        .expect("tar.gz archive");
    assert!(!archive.is_empty(), "archive is non-empty");

    let entries = tar_gz_entries(&archive);
    let names: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.iter().any(|n| n.ends_with("README")), "README present: {names:?}");
    assert!(
        names.iter().any(|n| n.ends_with("src/lib.rs")),
        "src/lib.rs present: {names:?}"
    );
    // go.mod was added in v1.1.0, so the v1.0.0 archive must not contain it.
    assert!(
        !names.iter().any(|n| n.ends_with("go.mod")),
        "go.mod absent from v1.0.0 archive: {names:?}"
    );

    let readme = entries
        .iter()
        .find(|(name, _)| name.ends_with("README"))
        .expect("README entry");
    assert_eq!(readme.1, b"readme v1\n");

    // Archiving the same commit again is byte-identical (entry mtimes are pinned to the commit time).
    let again = mirror
        .archive(&fixture.url, "v1.0.0", ArchiveFormat::TarGz)
        .await
        .expect("second tar.gz archive");
    assert_eq!(archive, again, "archive of a fixed commit is deterministic");
}

#[tokio::test]
async fn archive_zip_reflects_the_requested_ref() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    mirror.ensure_mirror(&fixture.url).await.expect("mirror");

    let archive = mirror
        .archive(&fixture.url, "v1.1.0", ArchiveFormat::Zip)
        .await
        .expect("zip archive");
    assert!(!archive.is_empty(), "archive is non-empty");

    let mut zip = zip_entry_names(&archive);
    let mut go_mod_name = None;
    for index in 0..zip.len() {
        let file = zip.by_index(index).expect("zip entry");
        if file.name().ends_with("go.mod") {
            go_mod_name = Some(file.name().to_owned());
        }
    }
    let go_mod_name = go_mod_name.expect("go.mod present in v1.1.0 zip archive");

    let mut go_mod = zip.by_name(&go_mod_name).expect("open go.mod in zip");
    let mut contents = String::new();
    go_mod.read_to_string(&mut contents).expect("read go.mod from zip");
    assert_eq!(contents, "module example.com/foo\n\ngo 1.21\n");
}

#[tokio::test]
async fn ttl_skips_refetch_within_the_refresh_interval() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));

    mirror.ensure_mirror(&fixture.url).await.expect("first mirror");
    let first = mirror.last_fetched(&fixture.url).expect("stamp after first fetch");

    // Within the interval the second call must be a no-op: the fetch stamp is left untouched.
    mirror.ensure_mirror(&fixture.url).await.expect("second mirror");
    let second = mirror.last_fetched(&fixture.url).expect("stamp after second call");

    assert_eq!(first, second, "TTL-fresh mirror was not re-fetched");
}
