//! SBOM document generation in CycloneDX and SPDX (ADR-0024).
//!
//! Pure, framework-free generators: an [`SbomSubject`] (a published package version and its file
//! hashes) compiles to a [`serde_json::Value`] document in either [`SbomFormat`]. The caller stamps
//! the document with an RFC 3339 timestamp so generation stays deterministic and unit-testable (no
//! clock dependency lives here). The service layer stores the rendered bytes as a coordinate-keyed
//! sidecar and links them to the subject via a [`Sbom`](crate::supply_chain::Sbom) record.
//!
//! Documents describe the subject's **primary component** — identity ([purl]), declared license, and
//! content hashes — plus any supplied [`SbomDependency`] entries. Both generators accept a dependency
//! list; per-ecosystem enumeration of a package's declared dependencies from its protocol metadata is
//! a separate concern and left to the caller.
//!
//! [purl]: https://github.com/package-url/purl-spec

use serde_json::{Value, json};

use crate::package::Ecosystem;
use crate::supply_chain::SbomFormat;

/// The [purl](https://github.com/package-url/purl-spec) type string for an ecosystem.
pub fn purl_type(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::PyPI => "pypi",
        Ecosystem::Npm => "npm",
        Ecosystem::Cargo => "cargo",
        Ecosystem::Hex => "hex",
        Ecosystem::Maven => "maven",
        Ecosystem::RubyGems => "gem",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Pub => "pub",
    }
}

/// Build a package URL (`pkg:<type>/[<namespace>/]<name>[@<version>]`) for a coordinate.
///
/// npm scoped names (`@scope/name`) split into a `namespace` (the scope) and `name` per the purl
/// spec. Every component is percent-encoded so a scope's `@`, or any other reserved character, is
/// escaped — e.g. `@angular/core@12.3.1` becomes `pkg:npm/%40angular/core@12.3.1`.
pub fn purl(ecosystem: Ecosystem, name: &str, version: Option<&str>) -> String {
    let mut purl = format!("pkg:{}", purl_type(ecosystem));

    // npm scopes become the purl namespace; other ecosystems have no namespace component here.
    let (namespace, bare_name) = match name.split_once('/') {
        Some((scope, rest)) if ecosystem == Ecosystem::Npm && scope.starts_with('@') => (Some(scope), rest),
        _ => (None, name),
    };
    if let Some(namespace) = namespace {
        purl.push('/');
        purl.push_str(&encode_purl_segment(namespace));
    }
    purl.push('/');
    purl.push_str(&encode_purl_segment(bare_name));

    if let Some(version) = version {
        purl.push('@');
        purl.push_str(&encode_purl_segment(version));
    }
    purl
}

/// Percent-encode one purl component, leaving only the RFC 3986 unreserved set (`A-Za-z0-9-._~`)
/// unescaped — the canonical purl encoding.
fn encode_purl_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// The IANA media type of an SBOM document in the given format.
pub fn media_type(format: SbomFormat) -> &'static str {
    match format {
        SbomFormat::CycloneDx => "application/vnd.cyclonedx+json",
        SbomFormat::Spdx => "application/spdx+json",
    }
}

/// One algorithm-tagged content hash of the subject.
///
/// `algorithm` is the CycloneDX spelling (`BLAKE3`, `SHA-256`, `SHA-512`, `SHA-1`, `MD5`); the SPDX
/// generator maps it to the SPDX spelling and drops any algorithm SPDX does not define.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomHash {
    /// CycloneDX algorithm label.
    pub algorithm: String,
    /// Lowercase hex digest.
    pub value: String,
}

/// A dependency of the subject, as much as is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomDependency {
    /// The dependency's ecosystem.
    pub ecosystem: Ecosystem,
    /// The dependency's package name.
    pub name: String,
    /// The resolved version, when known.
    pub version: Option<String>,
}

/// The subject an SBOM describes: a published package version and its content hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomSubject {
    /// The subject's ecosystem.
    pub ecosystem: Ecosystem,
    /// The package name.
    pub name: String,
    /// The version string.
    pub version: String,
    /// The declared license expression, when known.
    pub license: Option<String>,
    /// Content hashes of the subject artifact.
    pub hashes: Vec<SbomHash>,
    /// Declared dependencies, when the caller supplies them.
    pub dependencies: Vec<SbomDependency>,
}

/// Render an SBOM document for `subject` in `format`, stamped with the RFC 3339 `created_at`.
pub fn generate(subject: &SbomSubject, format: SbomFormat, created_at: &str) -> Value {
    match format {
        SbomFormat::CycloneDx => cyclonedx(subject, created_at),
        SbomFormat::Spdx => spdx(subject, created_at),
    }
}

fn cyclonedx(subject: &SbomSubject, created_at: &str) -> Value {
    let component_purl = purl(subject.ecosystem, &subject.name, Some(&subject.version));

    let mut component = json!({
        "type": "library",
        "bom-ref": component_purl,
        "name": subject.name,
        "version": subject.version,
        "purl": component_purl,
    });
    if let Some(license) = &subject.license {
        component["licenses"] = json!([{ "license": { "name": license } }]);
    }
    let hashes: Vec<Value> = subject
        .hashes
        .iter()
        .map(|hash| json!({ "alg": hash.algorithm, "content": hash.value }))
        .collect();
    if !hashes.is_empty() {
        component["hashes"] = Value::Array(hashes);
    }

    let dependencies: Vec<Value> = subject
        .dependencies
        .iter()
        .map(|dependency| {
            let dependency_purl = purl(dependency.ecosystem, &dependency.name, dependency.version.as_deref());
            let mut value = json!({
                "type": "library",
                "bom-ref": dependency_purl,
                "name": dependency.name,
                "purl": dependency_purl,
            });
            if let Some(version) = &dependency.version {
                value["version"] = json!(version);
            }
            value
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": created_at,
            "tools": [{ "vendor": "Starmetal", "name": "starmetal" }],
            "component": component,
        },
        "components": dependencies,
    })
}

fn spdx(subject: &SbomSubject, created_at: &str) -> Value {
    let primary_id = spdx_id("Package", &format!("{}-{}", subject.name, subject.version));

    let mut packages = vec![spdx_primary_package(subject, &primary_id)];
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": primary_id,
    })];

    for dependency in &subject.dependencies {
        let (package, dependency_id) = spdx_dependency_package(dependency);
        packages.push(package);
        relationships.push(json!({
            "spdxElementId": primary_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": dependency_id,
        }));
    }

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{}-{}", subject.name, subject.version),
        "documentNamespace": spdx_document_namespace(subject),
        "creationInfo": {
            "created": created_at,
            "creators": ["Tool: starmetal"],
        },
        "packages": packages,
        "relationships": relationships,
    })
}

/// The SPDX package entry describing the subject artifact, with its checksums and purl.
fn spdx_primary_package(subject: &SbomSubject, primary_id: &str) -> Value {
    let checksums: Vec<Value> = subject
        .hashes
        .iter()
        .filter_map(|hash| {
            spdx_algorithm(&hash.algorithm)
                .map(|algorithm| json!({ "algorithm": algorithm, "checksumValue": hash.value }))
        })
        .collect();

    let mut package = json!({
        "SPDXID": primary_id,
        "name": subject.name,
        "versionInfo": subject.version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "copyrightText": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": subject.license.clone().unwrap_or_else(|| "NOASSERTION".to_string()),
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl(subject.ecosystem, &subject.name, Some(&subject.version)),
        }],
    });
    if !checksums.is_empty() {
        package["checksums"] = Value::Array(checksums);
    }
    package
}

/// An SPDX package entry for a dependency, plus its generated SPDXID (for the relationship edge).
fn spdx_dependency_package(dependency: &SbomDependency) -> (Value, String) {
    let dependency_id = spdx_id(
        "Package",
        &format!(
            "{}-{}",
            dependency.name,
            dependency.version.as_deref().unwrap_or("unknown")
        ),
    );
    let package = json!({
        "SPDXID": dependency_id,
        "name": dependency.name,
        "versionInfo": dependency.version.clone().unwrap_or_else(|| "NOASSERTION".to_string()),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "copyrightText": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl(dependency.ecosystem, &dependency.name, dependency.version.as_deref()),
        }],
    });
    (package, dependency_id)
}

/// The SPDX document namespace: unique per coordinate, and per artifact bytes when a BLAKE3 hash is
/// present, so a republished version with different bytes never reuses the same namespace.
fn spdx_document_namespace(subject: &SbomSubject) -> String {
    let digest = subject
        .hashes
        .iter()
        .find(|hash| hash.algorithm == "BLAKE3")
        .map(|hash| hash.value.as_str())
        .unwrap_or("nodigest");
    format!(
        "urn:starmetal:sbom:{}:{}:{}:{digest}",
        purl_type(subject.ecosystem),
        subject.name,
        subject.version
    )
}

/// Map a CycloneDX algorithm label to its SPDX spelling, or `None` if SPDX does not define it.
fn spdx_algorithm(algorithm: &str) -> Option<&'static str> {
    match algorithm {
        "BLAKE3" => Some("BLAKE3"),
        "SHA-256" => Some("SHA256"),
        "SHA-512" => Some("SHA512"),
        "SHA-1" => Some("SHA1"),
        "MD5" => Some("MD5"),
        _ => None,
    }
}

/// Build a valid SPDXID (`SPDXRef-<prefix>-<sanitized>`); characters outside `[A-Za-z0-9.-]` become
/// `-` so the identifier always satisfies the SPDX grammar.
fn spdx_id(prefix: &str, raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '.' || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect();
    format!("SPDXRef-{prefix}-{sanitized}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> SbomSubject {
        SbomSubject {
            ecosystem: Ecosystem::Npm,
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            license: Some("MIT".to_string()),
            hashes: vec![
                SbomHash {
                    algorithm: "BLAKE3".to_string(),
                    value: "abc123".to_string(),
                },
                SbomHash {
                    algorithm: "SHA-256".to_string(),
                    value: "def456".to_string(),
                },
            ],
            dependencies: vec![SbomDependency {
                ecosystem: Ecosystem::Npm,
                name: "line-numbers".to_string(),
                version: Some("0.1.0".to_string()),
            }],
        }
    }

    #[test]
    fn purl_encodes_the_coordinate() {
        assert_eq!(purl(Ecosystem::Cargo, "serde", Some("1.0.0")), "pkg:cargo/serde@1.0.0");
        assert_eq!(purl(Ecosystem::RubyGems, "rails", None), "pkg:gem/rails");
    }

    #[test]
    fn purl_splits_and_percent_encodes_an_npm_scope() {
        // The scope becomes the purl namespace; its `@` is percent-encoded (canonical purl form).
        assert_eq!(
            purl(Ecosystem::Npm, "@angular/core", Some("12.3.1")),
            "pkg:npm/%40angular/core@12.3.1"
        );
        // A slash in a non-npm name is not a scope, so it is encoded within the single name segment.
        assert_eq!(
            purl(Ecosystem::Cargo, "weird/name", Some("1.0")),
            "pkg:cargo/weird%2Fname@1.0"
        );
    }

    #[test]
    fn spdx_document_namespace_includes_the_subject_digest() {
        let document = generate(&subject(), SbomFormat::Spdx, "t");
        assert_eq!(
            document["documentNamespace"],
            "urn:starmetal:sbom:npm:left-pad:1.3.0:abc123"
        );
    }

    #[test]
    fn cyclonedx_describes_the_primary_component_with_hashes_and_license() {
        let document = generate(&subject(), SbomFormat::CycloneDx, "2026-08-01T00:00:00Z");
        assert_eq!(document["bomFormat"], "CycloneDX");
        assert_eq!(document["specVersion"], "1.5");
        assert_eq!(document["metadata"]["timestamp"], "2026-08-01T00:00:00Z");

        let component = &document["metadata"]["component"];
        assert_eq!(component["name"], "left-pad");
        assert_eq!(component["version"], "1.3.0");
        assert_eq!(component["purl"], "pkg:npm/left-pad@1.3.0");
        assert_eq!(component["licenses"][0]["license"]["name"], "MIT");
        assert_eq!(component["hashes"][0]["alg"], "BLAKE3");
        assert_eq!(component["hashes"][0]["content"], "abc123");
        assert_eq!(component["hashes"][1]["alg"], "SHA-256");

        assert_eq!(document["components"][0]["name"], "line-numbers");
        assert_eq!(document["components"][0]["purl"], "pkg:npm/line-numbers@0.1.0");
    }

    #[test]
    fn spdx_describes_the_package_and_dependency_relationship() {
        let document = generate(&subject(), SbomFormat::Spdx, "2026-08-01T00:00:00Z");
        assert_eq!(document["spdxVersion"], "SPDX-2.3");
        assert_eq!(document["dataLicense"], "CC0-1.0");
        assert_eq!(document["SPDXID"], "SPDXRef-DOCUMENT");
        assert_eq!(document["creationInfo"]["created"], "2026-08-01T00:00:00Z");

        let primary = &document["packages"][0];
        assert_eq!(primary["SPDXID"], "SPDXRef-Package-left-pad-1.3.0");
        assert_eq!(primary["name"], "left-pad");
        assert_eq!(primary["versionInfo"], "1.3.0");
        assert_eq!(primary["licenseDeclared"], "MIT");
        // BLAKE3 + SHA-256 map to SPDX spellings; unknown algorithms would be dropped.
        assert_eq!(primary["checksums"][0]["algorithm"], "BLAKE3");
        assert_eq!(primary["checksums"][1]["algorithm"], "SHA256");
        assert_eq!(primary["externalRefs"][0]["referenceLocator"], "pkg:npm/left-pad@1.3.0");

        assert_eq!(document["relationships"][0]["relationshipType"], "DESCRIBES");
        assert_eq!(
            document["relationships"][0]["relatedSpdxElement"],
            "SPDXRef-Package-left-pad-1.3.0"
        );
        assert_eq!(document["relationships"][1]["relationshipType"], "DEPENDS_ON");
        assert_eq!(document["packages"][1]["name"], "line-numbers");
    }

    #[test]
    fn spdx_id_sanitizes_illegal_characters() {
        assert_eq!(spdx_id("Package", "@scope/pkg-1.0"), "SPDXRef-Package--scope-pkg-1.0");
    }

    #[test]
    fn missing_license_and_dependencies_still_produce_valid_documents() {
        let bare = SbomSubject {
            ecosystem: Ecosystem::PyPI,
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            license: None,
            hashes: vec![SbomHash {
                algorithm: "BLAKE3".to_string(),
                value: "aaa".to_string(),
            }],
            dependencies: Vec::new(),
        };
        let cyclonedx = generate(&bare, SbomFormat::CycloneDx, "t");
        assert!(cyclonedx["metadata"]["component"].get("licenses").is_none());
        assert_eq!(cyclonedx["components"].as_array().expect("array").len(), 0);

        let spdx = generate(&bare, SbomFormat::Spdx, "t");
        assert_eq!(spdx["packages"][0]["licenseDeclared"], "NOASSERTION");
        assert_eq!(spdx["packages"].as_array().expect("array").len(), 1);
        assert_eq!(spdx["relationships"].as_array().expect("array").len(), 1);
    }
}
