//! npm registry API type conversions.
//!
//! Works with raw `serde_json::Value` to handle the wide variety of field shapes
//! across npm packages without strict deserialization failures.

use ahash::AHashMap;
use depot_core::package::{ArtifactDigest, PackageName, VersionInfo, VersionMetadata};

/// Extract version info from a raw packument JSON.
pub fn extract_version_infos(packument: &serde_json::Value) -> Vec<VersionInfo> {
    let Some(versions) = packument["versions"].as_object() else {
        return Vec::new();
    };
    let mut infos: Vec<VersionInfo> = versions
        .keys()
        .map(|v| VersionInfo {
            version: v.clone(),
            yanked: false,
        })
        .collect();
    infos.sort_by(|a, b| a.version.cmp(&b.version));
    infos
}

/// Extract `VersionMetadata` for a specific version from a raw packument.
pub fn extract_version_metadata(
    name: &PackageName,
    version: &str,
    packument: &serde_json::Value,
) -> Option<VersionMetadata> {
    let ver = packument["versions"].get(version)?;
    let dist = &ver["dist"];

    let filename = format!("{}-{version}.tgz", name.as_str());

    let mut upstream_hashes = AHashMap::new();
    if let Some(shasum) = dist["shasum"].as_str() {
        upstream_hashes.insert("sha1".to_string(), shasum.to_string());
    }
    if let Some(integrity) = dist["integrity"].as_str() {
        upstream_hashes.insert("integrity".to_string(), integrity.to_string());
    }

    let artifact = ArtifactDigest {
        filename,
        blake3: String::new(),
        size: 0,
        upstream_hashes,
    };

    // License can be a string or absent; old packages use "licenses" (array)
    let license = ver["license"].as_str().map(|s| s.to_string()).or_else(|| {
        ver["licenses"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|l| l["type"].as_str().or(l.as_str()))
            .map(|s| s.to_string())
    });

    Some(VersionMetadata {
        name: name.clone(),
        version: version.to_string(),
        artifacts: vec![artifact],
        license,
        yanked: false,
    })
}

/// Rewrite tarball URLs in a raw packument JSON to point through depot.
///
/// Mutates `versions.*.dist.tarball` in place, preserving every other field
/// exactly as received from upstream.
pub fn rewrite_packument_tarball_urls(packument: &mut serde_json::Value, base_url: &str) {
    let pkg_name = packument["name"].as_str().unwrap_or("unknown").to_string();
    if let Some(versions) = packument["versions"].as_object_mut() {
        for (ver_str, ver_obj) in versions.iter_mut() {
            let tarball_filename = format!("{pkg_name}-{ver_str}.tgz");
            let new_url = format!("{base_url}/npm/{pkg_name}/-/{tarball_filename}");
            ver_obj["dist"]["tarball"] = serde_json::Value::String(new_url);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packument() -> serde_json::Value {
        serde_json::json!({
            "name": "is-odd",
            "description": "Is a number odd?",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "is-odd",
                    "version": "1.0.0",
                    "description": "Is a number odd?",
                    "license": "MIT",
                    "dependencies": { "is-number": "^4.0.0" },
                    "dist": {
                        "tarball": "https://registry.npmjs.org/is-odd/-/is-odd-1.0.0.tgz",
                        "shasum": "abc123",
                        "integrity": "sha512-xyz789"
                    }
                },
                "2.0.0": {
                    "name": "is-odd",
                    "version": "2.0.0",
                    "license": "MIT",
                    "dependencies": { "is-number": "^6.0.0" },
                    "dist": {
                        "tarball": "https://registry.npmjs.org/is-odd/-/is-odd-2.0.0.tgz",
                        "shasum": "def456"
                    }
                }
            }
        })
    }

    #[test]
    fn should_extract_version_infos() {
        let packument = sample_packument();
        let infos = extract_version_infos(&packument);

        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].version, "1.0.0");
        assert_eq!(infos[1].version, "2.0.0");
        assert!(!infos[0].yanked);
    }

    #[test]
    fn should_extract_version_metadata() {
        let packument = sample_packument();
        let name = PackageName::new("is-odd");

        let meta = extract_version_metadata(&name, "1.0.0", &packument).unwrap();
        assert_eq!(meta.version, "1.0.0");
        assert_eq!(meta.license.as_deref(), Some("MIT"));
        assert_eq!(meta.artifacts[0].filename, "is-odd-1.0.0.tgz");
        assert_eq!(
            meta.artifacts[0].upstream_hashes.get("sha1").unwrap(),
            "abc123"
        );
        assert_eq!(
            meta.artifacts[0].upstream_hashes.get("integrity").unwrap(),
            "sha512-xyz789"
        );
    }

    #[test]
    fn should_rewrite_tarball_urls() {
        let mut packument = sample_packument();
        rewrite_packument_tarball_urls(&mut packument, "http://localhost:8080");

        assert_eq!(
            packument["versions"]["1.0.0"]["dist"]["tarball"],
            "http://localhost:8080/npm/is-odd/-/is-odd-1.0.0.tgz"
        );
        assert_eq!(
            packument["versions"]["2.0.0"]["dist"]["tarball"],
            "http://localhost:8080/npm/is-odd/-/is-odd-2.0.0.tgz"
        );
        // Other fields preserved
        assert_eq!(packument["dist-tags"]["latest"], "2.0.0");
        assert_eq!(
            packument["versions"]["1.0.0"]["dependencies"]["is-number"],
            "^4.0.0"
        );
    }

    #[test]
    fn should_handle_empty_packument() {
        let packument = serde_json::json!({"name": "empty", "versions": {}});
        let infos = extract_version_infos(&packument);
        assert!(infos.is_empty());
    }

    #[test]
    fn should_handle_old_licenses_array_format() {
        let packument = serde_json::json!({
            "name": "old-pkg",
            "versions": {
                "0.1.0": {
                    "name": "old-pkg",
                    "version": "0.1.0",
                    "licenses": [{"type": "BSD", "url": "..."}],
                    "dist": { "tarball": "...", "shasum": "abc" }
                }
            }
        });
        let name = PackageName::new("old-pkg");
        let meta = extract_version_metadata(&name, "0.1.0", &packument).unwrap();
        assert_eq!(meta.license.as_deref(), Some("BSD"));
    }
}
