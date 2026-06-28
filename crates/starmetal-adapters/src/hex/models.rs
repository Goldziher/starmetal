//! Hex.pm API type conversions between core registry types and adapter responses.

use ahash::AHashMap;
use starmetal_core::package::{ArtifactDigest, PackageName, VersionInfo, VersionMetadata};
use starmetal_core::registry::hex::{HexPackage, HexRelease, HexRetirement};

/// Convert a `HexPackage` response into a list of `VersionInfo`.
///
/// Each release maps to one version. A release is considered yanked
/// when it carries a retirement annotation.
pub fn hex_package_to_version_infos(pkg: &HexPackage) -> Vec<VersionInfo> {
    pkg.releases
        .iter()
        .map(|release| VersionInfo {
            version: release.version.clone(),
            yanked: release.is_retired(),
        })
        .collect()
}

/// Build `VersionMetadata` for a specific version from a Hex package response.
///
/// Returns `None` when the requested version is not present in the releases list.
/// The Hex JSON API does not include per-release checksums, so `upstream_hashes`
/// is left empty. The tarball filename follows the `{name}-{version}.tar` convention.
pub fn hex_release_to_metadata(
    name: &PackageName,
    pkg: &HexPackage,
    version: &str,
) -> Option<VersionMetadata> {
    let release = pkg.releases.iter().find(|r| r.version == version)?;

    let filename = format!("{}-{version}.tar", name.as_str());
    let upstream_hashes: AHashMap<String, String> = AHashMap::new();

    let license = pkg.meta.as_ref().and_then(|meta| {
        if meta.licenses.is_empty() {
            None
        } else {
            Some(meta.licenses.join(" OR "))
        }
    });

    Some(VersionMetadata {
        name: name.clone(),
        version: version.to_string(),
        artifacts: vec![ArtifactDigest {
            filename,
            blake3: String::new(),
            size: 0,
            upstream_hashes,
        }],
        license,
        yanked: release.is_retired(),
    })
}

/// Reconstruct a `HexPackage` response with release URLs rewritten to point
/// through starmetal's local tarball endpoint (`/hex/tarballs/{name}-{version}.tar`).
pub fn build_package_response(
    name: &PackageName,
    original: &HexPackage,
    metadata_list: &[VersionMetadata],
) -> HexPackage {
    let releases: Vec<HexRelease> = original
        .releases
        .iter()
        .map(|release| {
            let url = format!("/hex/tarballs/{}-{}.tar", name.as_str(), release.version);
            let retirement = metadata_list
                .iter()
                .find(|m| m.version == release.version)
                .and_then(|m| {
                    if m.yanked {
                        Some(HexRetirement {
                            reason: "retired".to_string(),
                            message: None,
                        })
                    } else {
                        None
                    }
                })
                .or_else(|| release.retirement.clone());
            HexRelease {
                version: release.version.clone(),
                url,
                has_docs: release.has_docs,
                inserted_at: release.inserted_at.clone(),
                updated_at: release.updated_at.clone(),
                retirement,
            }
        })
        .collect();

    HexPackage {
        name: name.as_str().to_string(),
        url: original.url.clone(),
        html_url: original.html_url.clone(),
        docs_html_url: original.docs_html_url.clone(),
        meta: original.meta.clone(),
        releases,
        inserted_at: original.inserted_at.clone(),
        updated_at: original.updated_at.clone(),
    }
}

/// Build a `HexPackage` response directly from a cached upstream package,
/// rewriting release URLs to point through starmetal's local tarball endpoint
/// (`/hex/tarballs/{name}-{version}.tar`). This avoids the N+1 pattern of
/// fetching per-version metadata individually.
pub fn build_package_response_from_cached(name: &PackageName, original: &HexPackage) -> HexPackage {
    let releases: Vec<HexRelease> = original
        .releases
        .iter()
        .map(|release| {
            let url = format!("/hex/tarballs/{}-{}.tar", name.as_str(), release.version);
            HexRelease {
                version: release.version.clone(),
                url,
                has_docs: release.has_docs,
                inserted_at: release.inserted_at.clone(),
                updated_at: release.updated_at.clone(),
                retirement: release.retirement.clone(),
            }
        })
        .collect();

    HexPackage {
        name: name.as_str().to_string(),
        url: original.url.clone(),
        html_url: original.html_url.clone(),
        docs_html_url: original.docs_html_url.clone(),
        meta: original.meta.clone(),
        releases,
        inserted_at: original.inserted_at.clone(),
        updated_at: original.updated_at.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starmetal_core::registry::hex::HexMeta;

    fn sample_package() -> HexPackage {
        HexPackage {
            name: "jason".to_string(),
            url: Some("https://hex.pm/api/packages/jason".to_string()),
            html_url: Some("https://hex.pm/packages/jason".to_string()),
            docs_html_url: Some("https://hexdocs.pm/jason".to_string()),
            meta: Some(HexMeta {
                description: Some("A JSON parser".to_string()),
                licenses: vec!["Apache-2.0".to_string()],
                links: None,
                maintainers: vec![],
            }),
            releases: vec![
                HexRelease {
                    version: "1.4.1".to_string(),
                    url: "https://hex.pm/api/packages/jason/releases/1.4.1".to_string(),
                    has_docs: true,
                    inserted_at: None,
                    updated_at: None,
                    retirement: None,
                },
                HexRelease {
                    version: "1.3.0".to_string(),
                    url: "https://hex.pm/api/packages/jason/releases/1.3.0".to_string(),
                    has_docs: true,
                    inserted_at: None,
                    updated_at: None,
                    retirement: Some(HexRetirement {
                        reason: "security".to_string(),
                        message: Some("CVE-XXXX".to_string()),
                    }),
                },
            ],
            inserted_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn test_hex_package_to_version_infos() {
        let pkg = sample_package();
        let infos = hex_package_to_version_infos(&pkg);

        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].version, "1.4.1");
        assert!(!infos[0].yanked);
        assert_eq!(infos[1].version, "1.3.0");
        assert!(infos[1].yanked);
    }

    #[test]
    fn test_hex_release_to_metadata_found() {
        let pkg = sample_package();
        let name = PackageName::new("jason");
        let meta = hex_release_to_metadata(&name, &pkg, "1.4.1");

        assert!(meta.is_some());
        let meta = meta.unwrap();
        assert_eq!(meta.version, "1.4.1");
        assert_eq!(meta.artifacts.len(), 1);
        assert_eq!(meta.artifacts[0].filename, "jason-1.4.1.tar");
        assert!(meta.artifacts[0].upstream_hashes.is_empty());
        assert_eq!(meta.artifacts[0].blake3, "");
        assert_eq!(meta.artifacts[0].size, 0);
        assert_eq!(meta.license, Some("Apache-2.0".to_string()));
        assert!(!meta.yanked);
    }

    #[test]
    fn test_hex_release_to_metadata_retired() {
        let pkg = sample_package();
        let name = PackageName::new("jason");
        let meta = hex_release_to_metadata(&name, &pkg, "1.3.0");

        assert!(meta.is_some());
        let meta = meta.unwrap();
        assert!(meta.yanked);
    }

    #[test]
    fn test_hex_release_to_metadata_not_found() {
        let pkg = sample_package();
        let name = PackageName::new("jason");
        let meta = hex_release_to_metadata(&name, &pkg, "99.99.99");

        assert!(meta.is_none());
    }

    #[test]
    fn test_hex_release_to_metadata_no_licenses() {
        let mut pkg = sample_package();
        pkg.meta = Some(HexMeta {
            description: None,
            licenses: vec![],
            links: None,
            maintainers: vec![],
        });
        let name = PackageName::new("jason");
        let meta = hex_release_to_metadata(&name, &pkg, "1.4.1").unwrap();
        assert_eq!(meta.license, None);
    }

    #[test]
    fn test_hex_release_to_metadata_multiple_licenses() {
        let mut pkg = sample_package();
        pkg.meta = Some(HexMeta {
            description: None,
            licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            links: None,
            maintainers: vec![],
        });
        let name = PackageName::new("jason");
        let meta = hex_release_to_metadata(&name, &pkg, "1.4.1").unwrap();
        assert_eq!(meta.license, Some("MIT OR Apache-2.0".to_string()));
    }

    #[test]
    fn test_build_package_response_rewrites_urls() {
        let pkg = sample_package();
        let name = PackageName::new("jason");
        let metadata_list = vec![
            hex_release_to_metadata(&name, &pkg, "1.4.1").unwrap(),
            hex_release_to_metadata(&name, &pkg, "1.3.0").unwrap(),
        ];

        let response = build_package_response(&name, &pkg, &metadata_list);

        assert_eq!(response.name, "jason");
        assert_eq!(response.releases.len(), 2);
        assert_eq!(response.releases[0].url, "/hex/tarballs/jason-1.4.1.tar");
        assert_eq!(response.releases[1].url, "/hex/tarballs/jason-1.3.0.tar");
        // Meta should be preserved
        assert!(response.meta.is_some());
        assert_eq!(response.meta.as_ref().unwrap().licenses, vec!["Apache-2.0"]);
    }

    #[test]
    fn test_build_package_response_preserves_retirement() {
        let pkg = sample_package();
        let name = PackageName::new("jason");
        let metadata_list = vec![
            hex_release_to_metadata(&name, &pkg, "1.4.1").unwrap(),
            hex_release_to_metadata(&name, &pkg, "1.3.0").unwrap(),
        ];

        let response = build_package_response(&name, &pkg, &metadata_list);

        assert!(response.releases[0].retirement.is_none());
        assert!(response.releases[1].retirement.is_some());
    }
}
