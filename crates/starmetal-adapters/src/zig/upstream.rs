//! Repository-path -> git URL mapping for the Zig tarball proxy (ADR-0023).
//!
//! This is the seam between the route handlers in [`super`] and the
//! [`starmetal_git::GitMirror`] port: it never touches a git library directly, only the port
//! trait, so the concrete gitoxide backend stays confined to `starmetal-git`.
//!
//! # Repository path -> git URL mapping (scope)
//!
//! Mirrors the Go module proxy's mapping (see `starmetal_adapters::go::upstream`), but simpler:
//! the URL scheme's `{host}/{user}/{repo}` segment IS already a literal git remote coordinate, so
//! there is no escaping and no module-path-specific host table (e.g. Go's `golang.org/x`) to
//! reproduce.
//!
//! - `github.com/<user>/<repo>` -> `https://github.com/<user>/<repo>`
//! - `gitlab.com/<user>/<repo>` -> `https://gitlab.com/<user>/<repo>`
//! - `bitbucket.org/<user>/<repo>` -> `https://bitbucket.org/<user>/<repo>`
//!
//! Anything else must be listed in `zig.repo_overrides` (operator-trusted config, checked first
//! and matched by longest path-segment prefix) — the seam for private git hosts and offline
//! testing.

use std::collections::HashMap;

use bytes::Bytes;
use starmetal_core::error::{Result, StarmetalError};
use starmetal_git::GitMirror;

/// Well-known git hosts mapped to `https://<host>/<user>/<repo>` without an explicit override.
const DIRECT_GIT_HOSTS: [&str; 3] = ["github.com", "gitlab.com", "bitbucket.org"];

/// Resolve a repository path (`{host}/{user}/{repo}`) to the git remote URL it is mirrored from.
///
/// Checks `overrides` first (longest path-segment-prefix match), then the built-in
/// well-known-host mapping documented on the module.
pub fn resolve_repo_url(repo_path: &str, overrides: &HashMap<String, String>) -> Result<String> {
    if let Some(url) = resolve_override(repo_path, overrides) {
        return Ok(url.to_string());
    }

    let mut segments = repo_path.split('/');
    let host = segments
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| StarmetalError::Adapter("empty Zig repository path".to_string()))?;

    if DIRECT_GIT_HOSTS.contains(&host) {
        let rest: Vec<&str> = segments.collect();
        return match rest.as_slice() {
            [user, repo] => Ok(format!("https://{host}/{user}/{repo}")),
            _ => Err(StarmetalError::Adapter(format!(
                "unsupported Zig repository path '{repo_path}': nested paths/multi-package repos are \
                 not supported in this increment; the path must be exactly '{host}/<user>/<repo>'"
            ))),
        };
    }

    Err(StarmetalError::Adapter(format!(
        "unsupported Zig repository host in '{repo_path}'; add an entry to zig.repo_overrides or use \
         github.com, gitlab.com, or bitbucket.org"
    )))
}

/// Longest path-segment-prefix match against `overrides`.
fn resolve_override<'a>(repo_path: &str, overrides: &'a HashMap<String, String>) -> Option<&'a str> {
    if let Some(url) = overrides.get(repo_path) {
        return Some(url.as_str());
    }
    let mut candidate = repo_path;
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

/// Produce a gzip-compressed tar archive of the tree at `reference`, mapping the port's error at
/// this crate's boundary.
///
/// `starmetal-git`'s archive has no top-level directory prefix (`tree_prefix: None`), which is the
/// layout `zig fetch` 0.16 accepts directly — confirmed empirically against the real toolchain (see
/// the `zig` module's doc comment) — so no re-prefixing is done here, unlike the Go module proxy's
/// zip, which must re-prefix every entry to satisfy `golang.org/x/mod/zip`'s format.
pub async fn archive_tar_gz(mirror: &dyn GitMirror, git_url: &str, reference: &str) -> Result<Bytes> {
    mirror
        .archive(git_url, reference, starmetal_git::ArchiveFormat::TarGz)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_github_gitlab_bitbucket_directly() {
        let overrides = HashMap::new();
        assert_eq!(
            resolve_repo_url("github.com/foo/bar", &overrides).unwrap(),
            "https://github.com/foo/bar"
        );
        assert_eq!(
            resolve_repo_url("gitlab.com/foo/bar", &overrides).unwrap(),
            "https://gitlab.com/foo/bar"
        );
        assert_eq!(
            resolve_repo_url("bitbucket.org/foo/bar", &overrides).unwrap(),
            "https://bitbucket.org/foo/bar"
        );
    }

    #[test]
    fn rejects_nested_paths_on_known_hosts() {
        let overrides = HashMap::new();
        let err = resolve_repo_url("github.com/foo/bar/subpkg", &overrides).unwrap_err();
        assert!(err.to_string().contains("nested paths"));
    }

    #[test]
    fn rejects_unknown_hosts_without_an_override() {
        let overrides = HashMap::new();
        let err = resolve_repo_url("example.com/pkg", &overrides).unwrap_err();
        assert!(err.to_string().contains("unsupported Zig repository host"));
    }

    #[test]
    fn exact_override_wins_over_host_mapping() {
        let mut overrides = HashMap::new();
        overrides.insert("example.com/pkg".to_string(), "file:///tmp/fixture.git".to_string());
        assert_eq!(
            resolve_repo_url("example.com/pkg", &overrides).unwrap(),
            "file:///tmp/fixture.git"
        );
    }

    #[test]
    fn prefix_override_matches_a_path_under_it() {
        let mut overrides = HashMap::new();
        overrides.insert("example.com".to_string(), "file:///tmp/fixture.git".to_string());
        assert_eq!(
            resolve_repo_url("example.com/pkg/sub", &overrides).unwrap(),
            "file:///tmp/fixture.git"
        );
    }
}
