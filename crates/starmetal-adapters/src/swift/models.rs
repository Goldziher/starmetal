//! Protocol types for the Swift Package Registry (SE-0292) HTTP surface.
//!
//! See the [registry specification](https://github.com/swiftlang/swift-package-manager/blob/main/Documentation/PackageRegistry/Registry.md)
//! for the JSON shapes this module implements a minimal, read-only subset of.

use std::collections::BTreeMap;

use serde::Serialize;

/// The JSON body served at `GET /{scope}/{name}` (list package releases).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleasesResponse {
    pub releases: BTreeMap<String, ReleaseLink>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseLink {
    pub url: String,
}

/// The JSON body served at `GET /{scope}/{name}/{version}` (release metadata).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseMetadata {
    pub id: String,
    pub version: String,
    pub resources: Vec<ReleaseResource>,
    /// Always an empty object in this increment: SE-0292's `metadata` object (author, description,
    /// repository URLs, ...) is not synthesized from the git mirror.
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseResource {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub checksum: String,
}

/// The requested operation once `{scope}/{name}` has been split off a Swift registry path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwiftRequest {
    /// `GET /{scope}/{name}/{version}` -- release metadata.
    Metadata(String),
    /// `GET /{scope}/{name}/{version}.zip` -- source archive.
    Archive(String),
    /// `GET /{scope}/{name}/{version}/Package.swift` -- manifest.
    Manifest(String),
}

/// Parse the path segment(s) following `/{scope}/{name}/` into the requested operation.
///
/// `tail` is either a single segment (`{version}` or `{version}.zip`) or `{version}/Package.swift`
/// -- a registry version never itself contains a `/`, so splitting on the (at most one) remaining
/// `/` is unambiguous.
pub fn parse_swift_request(tail: &str) -> Option<SwiftRequest> {
    if let Some(version) = tail.strip_suffix("/Package.swift") {
        return (!version.is_empty()).then(|| SwiftRequest::Manifest(version.to_string()));
    }
    if tail.contains('/') {
        // No other multi-segment shape is recognized.
        return None;
    }
    if let Some(version) = tail.strip_suffix(".zip") {
        return (!version.is_empty()).then(|| SwiftRequest::Archive(version.to_string()));
    }
    (!tail.is_empty()).then(|| SwiftRequest::Metadata(tail.to_string()))
}

/// Registry identifier for a `(scope, name)` pair, per SE-0292's `{scope}.{name}` convention.
pub fn registry_identifier(scope: &str, name: &str) -> String {
    format!("{scope}.{name}")
}

/// Normalize a git tag to the semver it names, accepting both `1.2.3` and `v1.2.3` tag spellings.
///
/// Returns `None` when `tag` is not a valid semantic version either way.
pub fn normalize_version_tag(tag: &str) -> Option<String> {
    let candidate = tag.strip_prefix('v').unwrap_or(tag);
    semver::Version::parse(candidate)
        .ok()
        .map(|version| version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_metadata_archive_and_manifest_requests() {
        assert_eq!(
            parse_swift_request("1.0.0"),
            Some(SwiftRequest::Metadata("1.0.0".to_string()))
        );
        assert_eq!(
            parse_swift_request("1.0.0.zip"),
            Some(SwiftRequest::Archive("1.0.0".to_string()))
        );
        assert_eq!(
            parse_swift_request("1.0.0/Package.swift"),
            Some(SwiftRequest::Manifest("1.0.0".to_string()))
        );
    }

    #[test]
    fn rejects_empty_or_unrecognized_tails() {
        assert_eq!(parse_swift_request(""), None);
        assert_eq!(parse_swift_request(".zip"), None);
        assert_eq!(parse_swift_request("/Package.swift"), None);
        assert_eq!(parse_swift_request("1.0.0/other"), None);
    }

    #[test]
    fn builds_the_scope_dot_name_registry_identifier() {
        assert_eq!(registry_identifier("test", "fixture"), "test.fixture");
    }

    #[test]
    fn normalizes_bare_and_v_prefixed_semver_tags() {
        assert_eq!(normalize_version_tag("1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(normalize_version_tag("v1.2.3"), Some("1.2.3".to_string()));
    }

    #[test]
    fn rejects_non_semver_tags() {
        assert_eq!(normalize_version_tag("latest"), None);
        assert_eq!(normalize_version_tag("main"), None);
        assert_eq!(normalize_version_tag("v1.2"), None);
    }
}
