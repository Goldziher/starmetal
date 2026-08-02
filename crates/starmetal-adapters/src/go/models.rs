//! Protocol types for the Go module proxy (GOPROXY) HTTP surface.
//!
//! See <https://go.dev/ref/mod#goproxy-protocol> and `golang.org/x/mod/module` for the escaping
//! rules this module implements a minimal, spec-following subset of.

use serde::Serialize;
use starmetal_core::error::{Result, StarmetalError};

/// The JSON body served at `<module>/@v/<version>.info` and `<module>/@latest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GoModuleInfo {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Time")]
    pub time: String,
}

/// The suffix of a GOPROXY request path once the module path has been split off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoproxyRequest {
    /// `<module>/@v/list`
    List,
    /// `<module>/@v/<version>.info`
    Info(String),
    /// `<module>/@v/<version>.mod`
    Mod(String),
    /// `<module>/@v/<version>.zip`
    Zip(String),
    /// `<module>/@latest`
    Latest,
}

/// Split a GOPROXY catch-all path (everything after the mount prefix, still escaped) into the
/// escaped module path and the requested operation.
///
/// A module path element never contains `@` (see `module.CheckPath`), so the rightmost `/@v/` is
/// unambiguous. Returns `None` when `path` matches neither the `/@v/...` nor the `/@latest` shape.
pub fn split_goproxy_path(path: &str) -> Option<(&str, GoproxyRequest)> {
    const AT_V: &str = "/@v/";
    if let Some(index) = path.rfind(AT_V) {
        let module = &path[..index];
        let file = &path[index + AT_V.len()..];
        return parse_at_v_file(file).map(|request| (module, request));
    }
    path.strip_suffix("/@latest")
        .map(|module| (module, GoproxyRequest::Latest))
}

fn parse_at_v_file(file: &str) -> Option<GoproxyRequest> {
    if file == "list" {
        return Some(GoproxyRequest::List);
    }
    if let Some(version) = file.strip_suffix(".info") {
        return Some(GoproxyRequest::Info(version.to_string()));
    }
    if let Some(version) = file.strip_suffix(".mod") {
        return Some(GoproxyRequest::Mod(version.to_string()));
    }
    let version = file.strip_suffix(".zip")?;
    Some(GoproxyRequest::Zip(version.to_string()))
}

/// Escape a module path for the GOPROXY protocol: each uppercase ASCII letter becomes `!` followed
/// by its lowercase form (`module.EscapePath`), so the path is safe on case-insensitive filesystems
/// and unambiguous to unescape.
pub fn escape_module_path(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for ch in path.chars() {
        if ch.is_ascii_uppercase() {
            escaped.push('!');
            escaped.push(ch.to_ascii_lowercase());
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

/// Reverse [`escape_module_path`]. Rejects an unescaped uppercase letter or a dangling/invalid `!`
/// escape, matching `module.UnescapePath`'s validation.
pub fn unescape_module_path(escaped: &str) -> Result<String> {
    let mut unescaped = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(ch) = chars.next() {
        if ch == '!' {
            match chars.next() {
                Some(next) if next.is_ascii_lowercase() => unescaped.push(next.to_ascii_uppercase()),
                _ => {
                    return Err(StarmetalError::Adapter(format!(
                        "invalid Go module path escape in '{escaped}'"
                    )));
                }
            }
        } else if ch.is_ascii_uppercase() {
            return Err(StarmetalError::Adapter(format!(
                "unescaped uppercase letter in Go module path '{escaped}'"
            )));
        } else {
            unescaped.push(ch);
        }
    }
    Ok(unescaped)
}

/// Whether `tag` is a Go-proxy-valid semantic version tag: a mandatory `v` prefix followed by a
/// valid semver (`vX.Y.Z[-prerelease][+build]`).
pub fn is_valid_go_version(tag: &str) -> bool {
    tag.strip_prefix('v')
        .is_some_and(|rest| semver::Version::parse(rest).is_ok())
}

/// Compare two `v`-prefixed semver tags for ascending order.
pub fn compare_go_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |tag: &str| semver::Version::parse(tag.trim_start_matches('v')).ok();
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ => a.cmp(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_uppercase_letters_with_bang_lowercase() {
        assert_eq!(escape_module_path("github.com/Foo/Bar"), "github.com/!foo/!bar");
        assert_eq!(escape_module_path("example.com/mod"), "example.com/mod");
    }

    #[test]
    fn unescape_round_trips_escape() {
        let original = "github.com/Foo/Bar";
        let escaped = escape_module_path(original);
        assert_eq!(unescape_module_path(&escaped).unwrap(), original);
    }

    #[test]
    fn unescape_rejects_unescaped_uppercase() {
        let err = unescape_module_path("github.com/Foo").unwrap_err();
        assert!(err.to_string().contains("unescaped uppercase"));
    }

    #[test]
    fn unescape_rejects_dangling_bang() {
        let err = unescape_module_path("github.com/foo!").unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn splits_list_info_mod_zip_and_latest() {
        assert_eq!(
            split_goproxy_path("example.com/mod/@v/list"),
            Some(("example.com/mod", GoproxyRequest::List))
        );
        assert_eq!(
            split_goproxy_path("example.com/mod/@v/v1.0.0.info"),
            Some(("example.com/mod", GoproxyRequest::Info("v1.0.0".to_string())))
        );
        assert_eq!(
            split_goproxy_path("example.com/mod/@v/v1.0.0.mod"),
            Some(("example.com/mod", GoproxyRequest::Mod("v1.0.0".to_string())))
        );
        assert_eq!(
            split_goproxy_path("example.com/mod/@v/v1.0.0.zip"),
            Some(("example.com/mod", GoproxyRequest::Zip("v1.0.0".to_string())))
        );
        assert_eq!(
            split_goproxy_path("example.com/mod/@latest"),
            Some(("example.com/mod", GoproxyRequest::Latest))
        );
    }

    #[test]
    fn split_rejects_unknown_suffix() {
        assert_eq!(split_goproxy_path("example.com/mod/@v/v1.0.0.ziphash"), None);
        assert_eq!(split_goproxy_path("example.com/mod"), None);
    }

    #[test]
    fn validates_semver_tags_only() {
        assert!(is_valid_go_version("v1.0.0"));
        assert!(is_valid_go_version("v1.2.3-beta.1"));
        assert!(is_valid_go_version("v1.2.3+build.7"));
        assert!(!is_valid_go_version("1.0.0"));
        assert!(!is_valid_go_version("v1.0"));
        assert!(!is_valid_go_version("latest"));
        assert!(!is_valid_go_version("main"));
    }

    #[test]
    fn compares_versions_ascending() {
        let mut versions = vec!["v1.10.0".to_string(), "v1.2.0".to_string(), "v1.1.0".to_string()];
        versions.sort_by(|a, b| compare_go_versions(a, b));
        assert_eq!(versions, vec!["v1.1.0", "v1.2.0", "v1.10.0"]);
    }
}
