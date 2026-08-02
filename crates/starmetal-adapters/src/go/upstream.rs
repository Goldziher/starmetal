//! Module path -> git URL mapping and Go module zip construction (ADR-0023).
//!
//! This is the seam between the GOPROXY protocol handlers in [`super`] and the
//! [`starmetal_git::GitMirror`] port: it never touches a git library directly, only the port
//! trait, so the concrete gitoxide backend stays confined to `starmetal-git`.
//!
//! # Module -> git URL mapping (scope)
//!
//! Only a fixed set of well-known hosts is mapped automatically, by taking the module path's first
//! three (or, for `golang.org/x/...`, mapped) path segments as the repository root:
//!
//! - `github.com/<user>/<repo>` -> `https://github.com/<user>/<repo>`
//! - `gitlab.com/<user>/<repo>` -> `https://gitlab.com/<user>/<repo>`
//! - `bitbucket.org/<user>/<repo>` -> `https://bitbucket.org/<user>/<repo>`
//! - `golang.org/x/<name>` -> `https://go.googlesource.com/<name>`
//!
//! Anything else must be listed in `go.module_overrides` (operator-trusted config, checked first
//! and matched by longest path-segment prefix). **Out of scope for this increment:** vanity import
//! (`<meta name="go-import">`) resolution, nested/subdirectory modules (a module path with more
//! segments than its repository root), and major-version subdirectories (`/v2`).
use std::collections::HashMap;

use bytes::Bytes;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_git::GitMirror;

use super::models::escape_module_path;

/// Well-known git hosts mapped to `https://<host>/<user>/<repo>` without an explicit override.
const DIRECT_GIT_HOSTS: [&str; 3] = ["github.com", "gitlab.com", "bitbucket.org"];

/// Resolve a (already-unescaped) module path to the git remote URL it is mirrored from.
///
/// Checks `overrides` first (longest module-path-segment-prefix match), then the built-in
/// well-known-host mapping documented on the module.
pub fn module_to_git_url(module_path: &str, overrides: &HashMap<String, String>) -> Result<String> {
    if let Some(url) = resolve_override(module_path, overrides) {
        return Ok(url.to_string());
    }

    let mut segments = module_path.split('/');
    let host = segments
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| StarmetalError::Adapter("empty Go module path".to_string()))?;

    if host == "golang.org" {
        let rest: Vec<&str> = segments.collect();
        if let [sub, name] = rest.as_slice()
            && *sub == "x"
        {
            return Ok(format!("https://go.googlesource.com/{name}"));
        }
        return Err(StarmetalError::Adapter(format!(
            "unsupported golang.org module path '{module_path}'; only golang.org/x/<name> is mapped \
             automatically"
        )));
    }

    if DIRECT_GIT_HOSTS.contains(&host) {
        let rest: Vec<&str> = segments.collect();
        return match rest.as_slice() {
            [user, repo] => Ok(format!("https://{host}/{user}/{repo}")),
            _ => Err(StarmetalError::Adapter(format!(
                "unsupported module path '{module_path}': nested/subdirectory Go modules are not \
                 supported in this increment; the module path must be exactly '{host}/<user>/<repo>'"
            ))),
        };
    }

    Err(StarmetalError::Adapter(format!(
        "unsupported Go module host in '{module_path}'; add an entry to go.module_overrides or use \
         github.com, gitlab.com, bitbucket.org, or golang.org/x"
    )))
}

/// Longest module-path-segment-prefix match against `overrides`.
fn resolve_override<'a>(module_path: &str, overrides: &'a HashMap<String, String>) -> Option<&'a str> {
    if let Some(url) = overrides.get(module_path) {
        return Some(url.as_str());
    }
    let mut candidate = module_path;
    while let Some(index) = candidate.rfind('/') {
        candidate = &candidate[..index];
        if let Some(url) = overrides.get(candidate) {
            return Some(url.as_str());
        }
    }
    None
}

/// Ensure `git_url` is mirrored and fresh, mapping the port's error at this crate's boundary.
pub async fn ensure_mirror(mirror: &dyn GitMirror, git_url: &str) -> Result<()> {
    mirror
        .ensure_mirror(git_url)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// List the mirror's tags/branches, mapping the port's error at this crate's boundary.
pub async fn list_refs(mirror: &dyn GitMirror, git_url: &str) -> Result<Vec<starmetal_git::GitRef>> {
    mirror
        .list_refs(git_url)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// Resolve `reference` to a commit oid, mapping the port's error at this crate's boundary.
pub async fn resolve(mirror: &dyn GitMirror, git_url: &str, reference: &str) -> Result<Option<String>> {
    mirror
        .resolve(git_url, reference)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// Read a blob at `reference`, mapping the port's error at this crate's boundary.
pub async fn read_blob(mirror: &dyn GitMirror, git_url: &str, reference: &str, path: &str) -> Result<Option<Bytes>> {
    mirror
        .read_blob(git_url, reference, path)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// Read a commit's Unix-seconds timestamp, mapping the port's error at this crate's boundary.
pub async fn commit_time(mirror: &dyn GitMirror, git_url: &str, reference: &str) -> Result<Option<i64>> {
    mirror
        .commit_time(git_url, reference)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// Produce a source-tree archive at `reference`, mapping the port's error at this crate's boundary.
pub async fn archive_zip(mirror: &dyn GitMirror, git_url: &str, reference: &str) -> Result<Bytes> {
    mirror
        .archive(git_url, reference, starmetal_git::ArchiveFormat::Zip)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

/// Build a `golang.org/x/mod/zip`-shaped module archive from the tree archive `starmetal-git`
/// produced for `reference`.
///
/// Every entry is re-prefixed `{escaped_module}@{version}/...` (the escaped form, per the GOPROXY
/// protocol's zip file-name rule). Coverage of `golang.org/x/mod/zip`'s exclusion rules is partial
/// and documented at the call site (see the `go` module's doc comment): nested modules (any
/// subdirectory that has its own `go.mod`) and `vendor/` trees are excluded; other exclusions
/// (build-tag-based file filtering, submodules, size/name-length limits) are not implemented. Entry
/// order is sorted by path for determinism, independent of the source archive's own ordering.
pub fn build_module_zip(module_path: &str, version: &str, source_zip: &[u8]) -> Result<Bytes> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(source_zip))
        .map_err(|err| StarmetalError::Upstream(format!("invalid source tree archive: {err}")))?;

    let mut nested_module_dirs: Vec<String> = Vec::new();
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|err| StarmetalError::Upstream(format!("invalid source tree archive entry: {err}")))?;
        if let Some(dir) = file.name().strip_suffix("/go.mod") {
            nested_module_dirs.push(format!("{dir}/"));
        }
    }

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for index in 0..archive.len() {
        use std::io::Read as _;

        let mut file = archive
            .by_index(index)
            .map_err(|err| StarmetalError::Upstream(format!("invalid source tree archive entry: {err}")))?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        if is_vendor_path(&name) || nested_module_dirs.iter().any(|dir| name.starts_with(dir.as_str())) {
            continue;
        }
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|err| StarmetalError::Upstream(format!("failed to read tree archive entry: {err}")))?;
        entries.push((name, data));
    }

    if !entries.iter().any(|(name, _)| name == "go.mod") {
        entries.push(("go.mod".to_string(), format!("module {module_path}\n").into_bytes()));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let escaped_module = escape_module_path(module_path);
    let mut output = std::io::Cursor::new(Vec::new());
    {
        use std::io::Write as _;

        let mut writer = zip::ZipWriter::new(&mut output);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        for (name, data) in entries {
            let entry_name = format!("{escaped_module}@{version}/{name}");
            writer
                .start_file(entry_name, options)
                .map_err(|err| StarmetalError::Upstream(format!("failed to write module zip entry: {err}")))?;
            writer
                .write_all(&data)
                .map_err(|err| StarmetalError::Upstream(format!("failed to write module zip entry: {err}")))?;
        }
        writer
            .finish()
            .map_err(|err| StarmetalError::Upstream(format!("failed to finalize module zip: {err}")))?;
    }
    Ok(Bytes::from(output.into_inner()))
}

/// Whether `path` (root-relative, `/`-separated) falls under a `vendor/` directory at any depth.
fn is_vendor_path(path: &str) -> bool {
    path.split('/').next_back().is_some() && path.split('/').any(|segment| segment == "vendor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_github_gitlab_bitbucket_directly() {
        let overrides = HashMap::new();
        assert_eq!(
            module_to_git_url("github.com/foo/bar", &overrides).unwrap(),
            "https://github.com/foo/bar"
        );
        assert_eq!(
            module_to_git_url("gitlab.com/foo/bar", &overrides).unwrap(),
            "https://gitlab.com/foo/bar"
        );
        assert_eq!(
            module_to_git_url("bitbucket.org/foo/bar", &overrides).unwrap(),
            "https://bitbucket.org/foo/bar"
        );
    }

    #[test]
    fn maps_golang_org_x_to_googlesource() {
        let overrides = HashMap::new();
        assert_eq!(
            module_to_git_url("golang.org/x/mod", &overrides).unwrap(),
            "https://go.googlesource.com/mod"
        );
    }

    #[test]
    fn rejects_nested_module_paths_on_known_hosts() {
        let overrides = HashMap::new();
        let err = module_to_git_url("github.com/foo/bar/subpkg", &overrides).unwrap_err();
        assert!(err.to_string().contains("nested/subdirectory"));
    }

    #[test]
    fn rejects_unknown_hosts_without_an_override() {
        let overrides = HashMap::new();
        let err = module_to_git_url("example.com/mod", &overrides).unwrap_err();
        assert!(err.to_string().contains("unsupported Go module host"));
    }

    #[test]
    fn exact_override_wins_over_host_mapping() {
        let mut overrides = HashMap::new();
        overrides.insert("example.com/mod".to_string(), "file:///tmp/fixture.git".to_string());
        assert_eq!(
            module_to_git_url("example.com/mod", &overrides).unwrap(),
            "file:///tmp/fixture.git"
        );
    }

    #[test]
    fn prefix_override_matches_a_module_under_it() {
        let mut overrides = HashMap::new();
        overrides.insert("example.com".to_string(), "file:///tmp/fixture.git".to_string());
        assert_eq!(
            module_to_git_url("example.com/mod/sub", &overrides).unwrap(),
            "file:///tmp/fixture.git"
        );
    }

    fn read_source_zip(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            use std::io::Write as _;
            let mut writer = zip::ZipWriter::new(&mut buffer);
            let options = zip::write::SimpleFileOptions::default();
            for (name, contents) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(contents.as_bytes()).unwrap();
            }
            writer.finish().unwrap();
        }
        buffer.into_inner()
    }

    fn zip_entry_names(bytes: &[u8]) -> Vec<String> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
        (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect()
    }

    #[test]
    fn prefixes_every_entry_with_module_at_version() {
        let source = read_source_zip(&[("go.mod", "module example.com/mod\n"), ("main.go", "package main\n")]);
        let module_zip = build_module_zip("example.com/mod", "v1.0.0", &source).unwrap();
        let names = zip_entry_names(&module_zip);
        assert_eq!(
            names,
            vec!["example.com/mod@v1.0.0/go.mod", "example.com/mod@v1.0.0/main.go"]
        );
    }

    #[test]
    fn escapes_uppercase_in_the_module_zip_prefix() {
        let source = read_source_zip(&[("go.mod", "module github.com/Foo/Bar\n")]);
        let module_zip = build_module_zip("github.com/Foo/Bar", "v1.0.0", &source).unwrap();
        let names = zip_entry_names(&module_zip);
        assert_eq!(names, vec!["github.com/!foo/!bar@v1.0.0/go.mod"]);
    }

    #[test]
    fn synthesizes_go_mod_when_absent() {
        let source = read_source_zip(&[("main.go", "package main\n")]);
        let module_zip = build_module_zip("example.com/mod", "v1.0.0", &source).unwrap();
        let names = zip_entry_names(&module_zip);
        assert_eq!(
            names,
            vec!["example.com/mod@v1.0.0/go.mod", "example.com/mod@v1.0.0/main.go"]
        );

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(module_zip)).unwrap();
        let mut go_mod = archive.by_name("example.com/mod@v1.0.0/go.mod").unwrap();
        let mut contents = String::new();
        std::io::Read::read_to_string(&mut go_mod, &mut contents).unwrap();
        assert_eq!(contents, "module example.com/mod\n");
    }

    #[test]
    fn excludes_vendor_and_nested_module_trees() {
        let source = read_source_zip(&[
            ("go.mod", "module example.com/mod\n"),
            ("main.go", "package main\n"),
            ("vendor/modules.txt", "ignored\n"),
            ("vendor/github.com/x/y/y.go", "ignored\n"),
            ("sub/go.mod", "module example.com/mod/sub\n"),
            ("sub/sub.go", "ignored\n"),
        ]);
        let module_zip = build_module_zip("example.com/mod", "v1.0.0", &source).unwrap();
        let names = zip_entry_names(&module_zip);
        assert_eq!(
            names,
            vec!["example.com/mod@v1.0.0/go.mod", "example.com/mod@v1.0.0/main.go"]
        );
    }

    #[test]
    fn module_zip_construction_is_deterministic() {
        let source = read_source_zip(&[("b.go", "package main\n"), ("a.go", "package main\n")]);
        let first = build_module_zip("example.com/mod", "v1.0.0", &source).unwrap();
        let second = build_module_zip("example.com/mod", "v1.0.0", &source).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            zip_entry_names(&first),
            vec![
                "example.com/mod@v1.0.0/a.go",
                "example.com/mod@v1.0.0/b.go",
                "example.com/mod@v1.0.0/go.mod",
            ]
        );
    }
}
