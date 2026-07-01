use std::borrow::Cow;
use std::str::FromStr;

use ahash::AHashMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Result, StarmetalError};
use crate::publishing::ProtocolMetadata;

const RESERVED_STORAGE_PREFIX: &str = "_starmetal";

/// Supported package ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    PyPI,
    Npm,
    Cargo,
    Hex,
    Maven,
    RubyGems,
    NuGet,
    Pub,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PyPI => write!(f, "pypi"),
            Self::Npm => write!(f, "npm"),
            Self::Cargo => write!(f, "cargo"),
            Self::Hex => write!(f, "hex"),
            Self::Maven => write!(f, "maven"),
            Self::RubyGems => write!(f, "rubygems"),
            Self::NuGet => write!(f, "nuget"),
            Self::Pub => write!(f, "pub"),
        }
    }
}

impl FromStr for Ecosystem {
    type Err = StarmetalError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "pypi" => Ok(Self::PyPI),
            "npm" => Ok(Self::Npm),
            "cargo" | "crates" => Ok(Self::Cargo),
            "hex" => Ok(Self::Hex),
            "maven" => Ok(Self::Maven),
            "rubygems" | "gem" | "gems" => Ok(Self::RubyGems),
            "nuget" => Ok(Self::NuGet),
            "pub" | "pubdev" | "pub.dev" => Ok(Self::Pub),
            _ => Err(StarmetalError::Config(format!("unknown ecosystem: {s}"))),
        }
    }
}

/// A normalized package name.
///
/// Canonicalizes names across ecosystems:
/// - PyPI: PEP 503 — lowercase, replace runs of `.`/`-`/`_` with single `-`
/// - npm: lowercase (preserving scope `@scope/name`)
/// - Cargo/Hex/RubyGems/NuGet/pub.dev: lowercase
/// - Maven: preserve `group_id:artifact_id`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PackageName(String);

impl PackageName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate_for_storage(&self) -> Result<()> {
        let _ = self.storage_segment()?;
        Ok(())
    }

    pub fn storage_segment(&self) -> Result<String> {
        if self.0 == RESERVED_STORAGE_PREFIX || self.0.starts_with("_starmetal/") {
            return Err(StarmetalError::Config(
                "package names must not use the reserved _starmetal prefix".to_string(),
            ));
        }
        validate_package_name_for_storage(&self.0)?;
        Ok(encode_storage_segment(&self.0))
    }

    /// Normalize for a specific ecosystem, returning `Cow::Borrowed` when no
    /// transformation is needed (zero-alloc fast path).
    pub fn normalized(&self, ecosystem: Ecosystem) -> Cow<'_, str> {
        match ecosystem {
            Ecosystem::PyPI => {
                if self.0.bytes().all(|b| b.is_ascii_lowercase())
                    && memchr::memchr3(b'.', b'-', b'_', self.0.as_bytes()).is_none()
                {
                    Cow::Borrowed(&self.0)
                } else {
                    Cow::Owned(normalize_pypi(&self.0))
                }
            }
            Ecosystem::Npm => normalize_npm(&self.0),
            Ecosystem::Maven => Cow::Borrowed(&self.0),
            Ecosystem::Cargo
            | Ecosystem::Hex
            | Ecosystem::RubyGems
            | Ecosystem::NuGet
            | Ecosystem::Pub => {
                if self
                    .0
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || !b.is_ascii_alphabetic())
                {
                    Cow::Borrowed(&self.0)
                } else {
                    Cow::Owned(self.0.to_ascii_lowercase())
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct StorageKey(String);

impl StorageKey {
    pub fn from_segments(segments: &[&str]) -> Result<Self> {
        if segments.is_empty() {
            return Err(StarmetalError::Config(
                "storage key requires at least one segment".to_string(),
            ));
        }
        for segment in segments {
            validate_storage_segment("storage key segment", segment)?;
        }
        Ok(Self(segments.join("/")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn validate_storage_segment(label: &str, segment: &str) -> Result<()> {
    if segment.trim().is_empty() {
        return Err(StarmetalError::Config(format!("{label} must not be empty")));
    }
    if segment == "." || segment == ".." {
        return Err(StarmetalError::Config(format!(
            "{label} must not be a relative path segment"
        )));
    }
    if segment.contains('/') || segment.contains('\\') {
        return Err(StarmetalError::Config(format!(
            "{label} must not contain path separators"
        )));
    }
    if segment.starts_with('/') || segment.starts_with('\\') {
        return Err(StarmetalError::Config(format!(
            "{label} must not be an absolute path"
        )));
    }
    if segment.bytes().any(|byte| byte == 0) {
        return Err(StarmetalError::Config(format!(
            "{label} must not contain NUL"
        )));
    }
    Ok(())
}

pub fn decode_storage_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// PEP 503: lowercase, replace runs of `.`, `-`, `_` with a single `-`.
fn normalize_pypi(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    // Fast path: check if any separator chars exist using memchr
    if memchr::memchr3(b'.', b'-', b'_', lower.as_bytes()).is_none() {
        return lower;
    }
    let mut result = String::with_capacity(lower.len());
    let mut prev_sep = false;
    for c in lower.chars() {
        if c == '.' || c == '-' || c == '_' {
            if !prev_sep {
                result.push('-');
                prev_sep = true;
            }
        } else {
            result.push(c);
            prev_sep = false;
        }
    }
    // Trim trailing separator
    while result.ends_with('-') {
        result.pop();
    }
    result
}

/// npm: lowercase, but preserve `@scope/` prefix.
fn normalize_npm(name: &str) -> Cow<'_, str> {
    if name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || !b.is_ascii_alphabetic())
    {
        return Cow::Borrowed(name);
    }
    Cow::Owned(name.to_ascii_lowercase())
}

impl std::fmt::Display for PackageName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Uniquely identifies an artifact in storage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactId {
    pub ecosystem: Ecosystem,
    pub name: PackageName,
    pub version: String,
    pub filename: String,
}

impl ArtifactId {
    /// Storage key: `<ecosystem>/<name>/<version>/<filename>`
    pub fn storage_key(&self) -> String {
        let eco = self.ecosystem.to_string();
        let name = self.name.as_str();
        // Pre-calculate capacity: eco + / + name + / + version + / + filename
        let cap = eco.len() + 1 + name.len() + 1 + self.version.len() + 1 + self.filename.len();
        let mut key = String::with_capacity(cap);
        key.push_str(&eco);
        key.push('/');
        key.push_str(name);
        key.push('/');
        key.push_str(&self.version);
        key.push('/');
        key.push_str(&self.filename);
        key
    }

    pub fn validated_storage_key(&self) -> Result<StorageKey> {
        let name = self.name.storage_segment()?;
        let ecosystem = self.ecosystem.to_string();
        StorageKey::from_segments(&[&ecosystem, &name, &self.version, &self.filename])
    }
}

fn validate_package_name_for_storage(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(StarmetalError::Config(
            "package name must not be empty".to_string(),
        ));
    }
    if name == "." || name == ".." {
        return Err(StarmetalError::Config(
            "package name must not be a relative path segment".to_string(),
        ));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(StarmetalError::Config(
            "package name must not be an absolute path".to_string(),
        ));
    }
    if name.bytes().any(|byte| byte == 0) {
        return Err(StarmetalError::Config(
            "package name must not contain NUL".to_string(),
        ));
    }
    Ok(())
}

fn encode_storage_segment(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'@' | b':' => {
                output.push(char::from(byte))
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(&mut output, "%{byte:02X}");
            }
        }
    }
    output
}

/// Metadata for a specific package version.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VersionMetadata {
    pub name: PackageName,
    pub version: String,
    pub artifacts: Vec<ArtifactDigest>,
    pub license: Option<String>,
    pub yanked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_metadata: Option<ProtocolMetadata>,
}

/// Summary info for a version (used in listings).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VersionInfo {
    pub version: String,
    pub yanked: bool,
}

/// Digest of a single artifact file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactDigest {
    pub filename: String,
    pub blake3: String,
    pub size: u64,
    /// Hashes from the upstream registry (e.g., `{"sha256": "abc..."}`).
    #[serde(default)]
    #[schemars(with = "std::collections::HashMap<String, String>")]
    pub upstream_hashes: AHashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixtures(path: &str) -> Vec<serde_json::Value> {
        let full = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testing_data")
            .join(path);
        let content = std::fs::read_to_string(&full).unwrap();
        serde_json::from_str(&content).unwrap()
    }

    #[test]
    fn normalization_fixtures() {
        let fixtures = load_fixtures("package/01_pypi_normalization.json");
        for fix in &fixtures {
            let name = fix["input"]["name"].as_str().unwrap();
            let eco_str = fix["input"]["ecosystem"].as_str().unwrap();
            let expected = fix["expected"]["normalized"].as_str().unwrap();

            let eco: Ecosystem = eco_str.parse().unwrap();
            let pkg = PackageName::new(name);
            let normalized = pkg.normalized(eco);
            assert_eq!(
                normalized.as_ref(),
                expected,
                "fixture '{}': normalized({name}, {eco}) = {normalized}, expected {expected}",
                fix["name"].as_str().unwrap_or("?")
            );
        }
    }

    #[test]
    fn storage_key_fixtures() {
        let fixtures = load_fixtures("package/02_storage_keys.json");
        for fix in &fixtures {
            let eco_str = fix["input"]["ecosystem"].as_str().unwrap();
            let name = fix["input"]["name"].as_str().unwrap();
            let version = fix["input"]["version"].as_str().unwrap();
            let filename = fix["input"]["filename"].as_str().unwrap();
            let expected = fix["expected"]["key"].as_str().unwrap();

            let eco: Ecosystem = eco_str.parse().unwrap();
            let artifact = ArtifactId {
                ecosystem: eco,
                name: PackageName::new(name),
                version: version.to_string(),
                filename: filename.to_string(),
            };
            assert_eq!(
                artifact.storage_key(),
                expected,
                "fixture '{}'",
                fix["name"].as_str().unwrap_or("?")
            );
        }
    }

    #[test]
    fn ecosystem_from_str() {
        assert_eq!("pypi".parse::<Ecosystem>().unwrap(), Ecosystem::PyPI);
        assert_eq!("npm".parse::<Ecosystem>().unwrap(), Ecosystem::Npm);
        assert_eq!("cargo".parse::<Ecosystem>().unwrap(), Ecosystem::Cargo);
        assert_eq!("crates".parse::<Ecosystem>().unwrap(), Ecosystem::Cargo);
        assert_eq!("hex".parse::<Ecosystem>().unwrap(), Ecosystem::Hex);
        assert_eq!("PYPI".parse::<Ecosystem>().unwrap(), Ecosystem::PyPI);
        assert!("unknown".parse::<Ecosystem>().is_err());
    }

    #[test]
    fn ecosystem_parsing_fixtures() {
        let fixtures = load_fixtures("package/03_ecosystem_parsing.json");
        for fix in &fixtures {
            let input = fix["input"]["value"].as_str().unwrap();
            let error = fix["error"].as_str();

            let result = input.parse::<Ecosystem>();
            match error {
                Some(expected_err) => {
                    let err = result.expect_err(&format!(
                        "fixture '{}': expected error for input '{input}'",
                        fix["name"].as_str().unwrap_or("?")
                    ));
                    assert!(
                        err.to_string().contains(expected_err),
                        "fixture '{}': error '{err}' should contain '{expected_err}'",
                        fix["name"].as_str().unwrap_or("?")
                    );
                }
                None => {
                    let eco = result.unwrap_or_else(|e| {
                        panic!(
                            "fixture '{}': unexpected error for input '{input}': {e}",
                            fix["name"].as_str().unwrap_or("?")
                        )
                    });
                    let expected = fix["expected"]["ecosystem"].as_str().unwrap();
                    assert_eq!(
                        eco.to_string(),
                        expected,
                        "fixture '{}': parse('{input}') = {eco}, expected {expected}",
                        fix["name"].as_str().unwrap_or("?")
                    );
                }
            }
        }
    }

    #[test]
    fn pypi_normalization_pep503() {
        // PEP 503 specific: runs of separators collapse to single hyphen
        let pkg = PackageName::new("My..Cool--Package__Name");
        assert_eq!(
            pkg.normalized(Ecosystem::PyPI).as_ref(),
            "my-cool-package-name"
        );
    }

    #[test]
    fn normalized_cow_borrows_when_unchanged() {
        let pkg = PackageName::new("serde_json");
        let cow = pkg.normalized(Ecosystem::Cargo);
        assert!(
            matches!(cow, Cow::Borrowed(_)),
            "should borrow when already lowercase"
        );
    }

    #[test]
    fn storage_key_rejects_traversal_segments() {
        let artifact = ArtifactId {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("requests"),
            version: "..".to_string(),
            filename: "requests.tar.gz".to_string(),
        };

        let err = artifact.validated_storage_key().unwrap_err().to_string();
        assert!(err.contains("relative path segment"));
    }

    #[test]
    fn storage_key_rejects_filename_with_separator() {
        let artifact = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("is-odd"),
            version: "3.0.1".to_string(),
            filename: "../is-odd.tgz".to_string(),
        };

        let err = artifact.validated_storage_key().unwrap_err().to_string();
        assert!(err.contains("path separators"));
    }

    #[test]
    fn storage_key_rejects_reserved_public_package_name() {
        let artifact = ArtifactId {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("_starmetal"),
            version: "1.0.0".to_string(),
            filename: "pkg.crate".to_string(),
        };

        let err = artifact.validated_storage_key().unwrap_err().to_string();
        assert!(err.contains("reserved _starmetal prefix"));
    }

    #[test]
    fn storage_key_encodes_scoped_npm_package_name() {
        let artifact = ArtifactId {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("@scope/name"),
            version: "1.0.0".to_string(),
            filename: "name-1.0.0.tgz".to_string(),
        };

        assert_eq!(
            artifact.validated_storage_key().unwrap().as_str(),
            "npm/@scope%2Fname/1.0.0/name-1.0.0.tgz"
        );
    }
}
