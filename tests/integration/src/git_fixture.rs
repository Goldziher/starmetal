//! Deterministic git fixture builder shared by the Go, Zig, and Swift ecosystem tests.
//!
//! Each of those ecosystems maps a module/package identifier to a `file://` git repository via a
//! config override (`go.module_overrides`, `zig.repo_overrides`, `swift.package_overrides`), so
//! their integration tests all build a small fixture git repo with the `git` CLI. This module
//! centralizes that scaffolding and, critically, pins both the author and committer *dates* (not
//! just identity) so commit SHAs -- and anything derived from them, like the Go proxy's `.info`
//! `Time` field -- are reproducible across runs and machines.

use std::path::Path;
use std::process::Command as StdCommand;

/// Fixed author/committer timestamp applied to every fixture commit, so commit SHAs (and anything
/// derived from them, such as a served module's mtime) are reproducible across runs and machines.
///
/// Public so tests that assert on a derived timestamp (e.g. the Go proxy's `.info` `Time` field)
/// can compare against this constant instead of duplicating the literal.
pub const FIXTURE_COMMIT_DATE: &str = "2020-01-01T00:00:00Z";

/// Fixture git identity applied to every commit. The value is arbitrary but must stay constant so
/// commit SHAs remain stable across test runs.
const FIXTURE_AUTHOR_NAME: &str = "Fixture";
const FIXTURE_AUTHOR_EMAIL: &str = "fixture@example.test";

/// Default commit message used by every fixture built through [`GitFixtureBuilder`], matching the
/// message the Go, Zig, and Swift fixtures used before this module existed.
const DEFAULT_COMMIT_MESSAGE: &str = "release 1.0.0";

/// A fixture git repository with one or more tagged commits, hosted at a `file://` URL.
///
/// The backing [`tempfile::TempDir`] is kept alive for as long as the fixture is in scope --
/// dropping the fixture removes the directory, so callers must hold on to it for the lifetime of
/// the test server that reads through it.
pub struct GitFixture {
    _root: tempfile::TempDir,
    pub url: String,
}

/// One finalized commit round staged via [`GitFixtureBuilder::commit`]: the files added at that
/// point (on top of everything already written by prior rounds) plus the tags applied to it once
/// committed.
struct PendingCommit {
    files: Vec<(String, String)>,
    tags: Vec<String>,
    message: String,
}

/// Builds a [`GitFixture`]: a temporary git repository with the given working-tree files
/// committed and tagged, deterministic across runs (fixed author/committer identity *and* fixed
/// author/committer dates -- see [`FIXTURE_COMMIT_DATE`]).
///
/// By default `.file()`/`.tag()` stage a single commit, finalized by `.build()` -- matching every
/// fixture in this module before multi-version coverage was added. Call `.commit()` between
/// `.file()`/`.tag()` groups to produce a fixture with more than one tagged release, each with
/// genuinely distinct content (e.g. for testing that a version listing returns every tag, or that
/// `@latest` picks the highest semver one) while every commit's date stays fixed.
#[derive(Default)]
pub struct GitFixtureBuilder {
    /// Files staged for the commit currently being built up via `.file()`.
    files: Vec<(String, String)>,
    /// Tags staged for the commit currently being built up via `.tag()`.
    tags: Vec<String>,
    /// Already-finalized commit rounds, applied to the repository in order by `.build()`.
    commits: Vec<PendingCommit>,
}

impl GitFixtureBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a working-tree file at `relative_path` (created under the fixture's repo root) with
    /// the given `contents`, staged for the commit currently being built up. Parent directories
    /// are created as needed.
    pub fn file(mut self, relative_path: impl Into<String>, contents: impl Into<String>) -> Self {
        self.files.push((relative_path.into(), contents.into()));
        self
    }

    /// Tags the commit currently being built up with `name`. May be called more than once to
    /// apply multiple tags to the same commit.
    pub fn tag(mut self, name: impl Into<String>) -> Self {
        self.tags.push(name.into());
        self
    }

    /// Finalizes the files and tags staged so far into a discrete commit round, so subsequent
    /// `.file()`/`.tag()` calls stage a *new* commit on top of it. The final round need not call
    /// `.commit()` explicitly -- `.build()` flushes it automatically.
    pub fn commit(mut self) -> Self {
        let round = self.commits.len() + 1;
        self.commits.push(PendingCommit {
            files: std::mem::take(&mut self.files),
            tags: std::mem::take(&mut self.tags),
            message: format!("{DEFAULT_COMMIT_MESSAGE} (round {round})"),
        });
        self
    }

    /// Initializes a `main`-branch repo, then applies every finalized commit round (flushing any
    /// still-staged files/tags as the final round first) with a fixed identity and date, and
    /// returns the resulting [`GitFixture`].
    pub fn build(self) -> GitFixture {
        let mut builder = self;
        if !builder.files.is_empty() || !builder.tags.is_empty() || builder.commits.is_empty() {
            builder = builder.commit();
        }

        let root = tempfile::tempdir().expect("tempdir");
        let work = root.path().join("upstream");
        std::fs::create_dir_all(&work).expect("create work dir");

        git(&work, &["init", "-b", "main"]);
        for round in &builder.commits {
            for (relative_path, contents) in &round.files {
                write_file(&work, relative_path, contents);
            }
            git(&work, &["add", "-A"]);
            git(&work, &["commit", "-m", &round.message]);
            for tag in &round.tags {
                git(&work, &["tag", tag]);
            }
        }

        let url = format!("file://{}", work.display());
        GitFixture { _root: root, url }
    }
}

/// An `example.com/mod`-shaped Go module fixture with one tagged release, `v1.0.0`.
pub fn go_module_fixture() -> GitFixture {
    GitFixtureBuilder::new()
        .file("go.mod", "module example.com/mod\n\ngo 1.21\n")
        .file(
            "greet.go",
            "package mod\n\n// Greet returns a fixed greeting.\nfunc Greet() string { return \"hello\" }\n",
        )
        .tag("v1.0.0")
        .build()
}

/// An `example.com/pkg`-shaped Zig package fixture with one tagged release, `v1.0.0`.
pub fn zig_package_fixture() -> GitFixture {
    GitFixtureBuilder::new()
        .file(
            "build.zig.zon",
            ".{\n    .name = .fixture,\n    .version = \"1.0.0\",\n    .fingerprint = 0x5e540eeeedcbb0d,\n    \
             .paths = .{\"\"},\n}\n",
        )
        .file(
            "build.zig",
            "const std = @import(\"std\");\npub fn build(b: *std.Build) void {\n    _ = b;\n}\n",
        )
        .file("src/main.zig", "pub fn main() void {}\n")
        .tag("v1.0.0")
        .build()
}

/// A `test.fixture`-shaped Swift package fixture with one tagged release, `1.0.0`.
pub fn swift_package_fixture() -> GitFixture {
    GitFixtureBuilder::new()
        .file(
            "Package.swift",
            "// swift-tools-version:5.9\nimport PackageDescription\n\nlet package = Package(\n    name: \"fixture\",\n    \
             products: [\n        .library(name: \"fixture\", targets: [\"fixture\"])\n    ],\n    targets: [\n        \
             .target(name: \"fixture\", path: \"Sources/fixture\")\n    ]\n)\n",
        )
        .file(
            "Sources/fixture/fixture.swift",
            "public struct Fixture {\n    public init() {}\n    public func hello() -> String { \"hello\" }\n}\n",
        )
        .tag("1.0.0")
        .build()
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = StdCommand::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", FIXTURE_AUTHOR_NAME)
        .env("GIT_AUTHOR_EMAIL", FIXTURE_AUTHOR_EMAIL)
        .env("GIT_AUTHOR_DATE", FIXTURE_COMMIT_DATE)
        .env("GIT_COMMITTER_NAME", FIXTURE_AUTHOR_NAME)
        .env("GIT_COMMITTER_EMAIL", FIXTURE_AUTHOR_EMAIL)
        .env("GIT_COMMITTER_DATE", FIXTURE_COMMIT_DATE)
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

/// Probes for `binary`'s presence by running it with `probe_arg` (e.g. `"version"` or
/// `"--version"`), panicking with an install hint naming `toolchain_name` if it's missing or not
/// runnable. Returns `binary` unchanged, for use as a `Command::new` argument at the call site.
pub async fn require_tool(binary: &str, probe_arg: &str, toolchain_name: &str) -> String {
    if let Ok(output) = tokio::process::Command::new(binary).arg(probe_arg).output().await
        && output.status.success()
    {
        return binary.to_string();
    }
    panic!("{binary} not found — install the {toolchain_name} toolchain to run {toolchain_name} E2E tests");
}

/// Probes for the `go` toolchain, matching `go.rs`'s original `require_go`.
pub async fn require_go() -> String {
    require_tool("go", "version", "Go").await
}

/// Probes for the `zig` toolchain, matching `zig.rs`'s original `require_zig`.
pub async fn require_zig() -> String {
    require_tool("zig", "version", "Zig").await
}

/// Probes for the `swift` toolchain, matching `swift.rs`'s original `require_swift`.
pub async fn require_swift() -> String {
    require_tool("swift", "--version", "Swift").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_stages_a_second_tagged_release_with_distinct_content_on_top_of_the_first() {
        let fixture = GitFixtureBuilder::new()
            .file("VERSION", "1.0.0\n")
            .tag("v1.0.0")
            .commit()
            .file("VERSION", "2.0.0\n")
            .tag("v2.0.0")
            .build();

        let path = fixture.url.strip_prefix("file://").expect("file:// URL");
        let tags = StdCommand::new("git")
            .args(["tag", "--list"])
            .current_dir(path)
            .output()
            .expect("git tag --list");
        let mut tag_names: Vec<String> = String::from_utf8(tags.stdout)
            .expect("utf-8 tag list")
            .lines()
            .map(str::to_string)
            .collect();
        tag_names.sort();
        assert_eq!(tag_names, vec!["v1.0.0", "v2.0.0"]);

        let version_at_v1 = git(Path::new(path), &["show", "v1.0.0:VERSION"]);
        assert_eq!(version_at_v1, "1.0.0\n");
        let version_at_v2 = git(Path::new(path), &["show", "v2.0.0:VERSION"]);
        assert_eq!(version_at_v2, "2.0.0\n");
    }
}
