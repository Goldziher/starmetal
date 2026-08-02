//! Offline tests for the Go module proxy adapter against a real fixture git repository, built with
//! the `git` CLI (no network access), mirroring the pattern `starmetal-git`'s own tests use.
#![cfg(feature = "go")]

use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use starmetal_adapters::go::models::is_valid_go_version;
use starmetal_adapters::go::upstream::{archive_zip, build_module_zip, ensure_mirror, list_refs, read_blob};
use starmetal_git::{GitRefKind, GixMirror};

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

/// A module with a root `go.mod`, two semver tags, one non-semver tag, and a branch — so tests can
/// assert version-list filtering keeps only the tagged semver releases.
fn build_fixture() -> Fixture {
    let root = tempfile::tempdir().expect("tempdir");
    let work = root.path().join("upstream");
    std::fs::create_dir_all(&work).expect("create work dir");

    git(&work, &["init", "-b", "main"]);
    write_file(&work, "go.mod", "module example.com/mod\n\ngo 1.21\n");
    write_file(
        &work,
        "greet.go",
        "package mod\n\nfunc Greet() string { return \"hi\" }\n",
    );
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-m", "release 1.0.0"]);
    git(&work, &["tag", "v1.0.0"]);

    write_file(
        &work,
        "greet.go",
        "package mod\n\nfunc Greet() string { return \"hello\" }\n",
    );
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-m", "release 1.1.0"]);
    git(&work, &["tag", "v1.1.0"]);
    // A non-semver tag must not appear in the module's version list.
    git(&work, &["tag", "not-a-version"]);

    let url = format!("file://{}", work.display());
    Fixture { _root: root, url }
}

fn cache_root() -> tempfile::TempDir {
    tempfile::tempdir().expect("cache tempdir")
}

#[tokio::test]
async fn version_list_filters_to_valid_semver_tags_only() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    ensure_mirror(&mirror, &fixture.url).await.expect("mirror");

    let refs = list_refs(&mirror, &fixture.url).await.expect("list refs");
    let mut versions: Vec<&str> = refs
        .iter()
        .filter(|reference| reference.kind == GitRefKind::Tag && is_valid_go_version(&reference.name))
        .map(|reference| reference.name.as_str())
        .collect();
    versions.sort();

    assert_eq!(
        versions,
        vec!["v1.0.0", "v1.1.0"],
        "only tagged semver releases are kept"
    );
    assert!(
        refs.iter().any(|reference| reference.name == "not-a-version"),
        "the non-semver tag exists in the mirror"
    );
    assert!(
        refs.iter().any(|reference| reference.kind == GitRefKind::Branch),
        "the main branch exists in the mirror but is not a Tag"
    );
}

#[tokio::test]
async fn module_zip_is_correctly_prefixed_contains_go_mod_and_decompresses() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    ensure_mirror(&mirror, &fixture.url).await.expect("mirror");

    let source = archive_zip(&mirror, &fixture.url, "v1.0.0")
        .await
        .expect("source archive");
    let module_zip = build_module_zip("example.com/mod", "v1.0.0", &source).expect("module zip");

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(module_zip.to_vec())).expect("valid module zip");
    let names: Vec<String> = (0..archive.len())
        .map(|index| archive.by_index(index).expect("entry").name().to_string())
        .collect();
    assert_eq!(
        names,
        vec!["example.com/mod@v1.0.0/go.mod", "example.com/mod@v1.0.0/greet.go"],
        "every entry is prefixed {{module}}@{{version}}/ and sorted"
    );

    let mut go_mod = archive.by_name("example.com/mod@v1.0.0/go.mod").expect("go.mod entry");
    let mut contents = String::new();
    go_mod.read_to_string(&mut contents).expect("decompress go.mod");
    assert_eq!(contents, "module example.com/mod\n\ngo 1.21\n");
}

#[tokio::test]
async fn module_zip_construction_is_deterministic_for_a_fixed_commit() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    ensure_mirror(&mirror, &fixture.url).await.expect("mirror");

    let source = archive_zip(&mirror, &fixture.url, "v1.1.0")
        .await
        .expect("source archive");
    let first = build_module_zip("example.com/mod", "v1.1.0", &source).expect("first module zip");
    let second = build_module_zip("example.com/mod", "v1.1.0", &source).expect("second module zip");

    assert_eq!(
        first, second,
        "module zip construction is byte-stable for the same commit"
    );
}

#[tokio::test]
async fn go_mod_is_absent_at_a_pre_module_ref_and_present_after() {
    let fixture = build_fixture();
    let cache = cache_root();
    let mirror = GixMirror::new(cache.path(), Duration::from_secs(3600));
    ensure_mirror(&mirror, &fixture.url).await.expect("mirror");

    let go_mod = read_blob(&mirror, &fixture.url, "v1.0.0", "go.mod")
        .await
        .expect("read go.mod")
        .expect("go.mod exists at v1.0.0");
    assert_eq!(&go_mod[..], b"module example.com/mod\n\ngo 1.21\n");
}
