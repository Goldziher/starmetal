//! URL scheme for the Zig source-tarball proxy (ADR-0023).
//!
//! Zig has no package-index protocol: `zig fetch <url>` downloads a tarball (or git bundle) of a
//! package's source and hashes it client-side. This adapter exposes one clean URL scheme,
//! `GET /{host}/{user}/{repo}/{ref}.tar.gz`, so there is no protocol-specific document shape (an
//! `.info`/`.mod` file, a packument, an index entry) to model here — only the path split.

/// Split a mounted-adapter-relative path (`{host}/{user}/{repo}/{ref}.tar.gz`) into the repository
/// path and the requested ref.
///
/// The ref is always the final path segment, stripped of its `.tar.gz` suffix. Unlike a GOPROXY
/// path, this scheme has no internal marker (like Go's `/@v/`) separating the coordinate from the
/// operation — a plain rightmost-`/` split is unambiguous because the scheme has exactly one
/// operation (fetch the tarball at a ref). Returns `None` when `path` has no `/`, or its final
/// segment does not end in `.tar.gz`, or either half would be empty.
pub fn split_zig_path(path: &str) -> Option<(&str, &str)> {
    let (repo_path, filename) = path.rsplit_once('/')?;
    let reference = filename.strip_suffix(".tar.gz")?;
    if repo_path.is_empty() || reference.is_empty() {
        return None;
    }
    Some((repo_path, reference))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_repo_path_and_ref_from_a_tar_gz_suffix() {
        assert_eq!(
            split_zig_path("github.com/foo/bar/v1.0.0.tar.gz"),
            Some(("github.com/foo/bar", "v1.0.0"))
        );
    }

    #[test]
    fn splits_an_overridden_shorter_repo_path() {
        assert_eq!(
            split_zig_path("example.com/pkg/main.tar.gz"),
            Some(("example.com/pkg", "main"))
        );
    }

    #[test]
    fn rejects_a_path_with_no_slash() {
        assert_eq!(split_zig_path("v1.0.0.tar.gz"), None);
    }

    #[test]
    fn rejects_a_missing_tar_gz_suffix() {
        assert_eq!(split_zig_path("github.com/foo/bar/v1.0.0.zip"), None);
        assert_eq!(split_zig_path("github.com/foo/bar/v1.0.0"), None);
    }

    #[test]
    fn rejects_an_empty_ref() {
        assert_eq!(split_zig_path("github.com/foo/bar/.tar.gz"), None);
    }
}
