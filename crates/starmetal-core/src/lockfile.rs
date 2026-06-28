use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Result, StarmetalError};
use crate::integrity;
use crate::package::Ecosystem;

/// The starmetal lock file — ecosystem-agnostic, blake3-verified.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LockFile {
    pub metadata: LockMetadata,
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LockMetadata {
    pub schema_version: u32,
    pub generated_at: String,
    pub starmetal_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LockedPackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub artifacts: Vec<LockedArtifact>,
    pub resolved_from: String,
    #[serde(default)]
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LockedArtifact {
    pub filename: String,
    pub blake3: String,
    pub size: u64,
}

impl LockFile {
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| StarmetalError::Lockfile(e.to_string()))
    }

    pub fn from_toml(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }

    /// Find a locked package by ecosystem and name.
    pub fn find_package(&self, ecosystem: Ecosystem, name: &str) -> Option<&LockedPackage> {
        self.packages
            .iter()
            .find(|p| p.ecosystem == ecosystem && p.name == name)
    }

    /// Verify an artifact's data against the lock file's stored blake3 hash.
    pub fn verify_artifact(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        filename: &str,
        data: &[u8],
    ) -> Result<()> {
        let pkg =
            self.find_package(ecosystem, name)
                .ok_or_else(|| StarmetalError::PackageNotFound {
                    ecosystem: ecosystem.to_string(),
                    name: name.to_string(),
                })?;

        let artifact = pkg
            .artifacts
            .iter()
            .find(|a| a.filename == filename)
            .ok_or_else(|| StarmetalError::ArtifactNotFound(filename.to_string()))?;

        let actual = integrity::blake3_hex(data);
        if actual == artifact.blake3 {
            Ok(())
        } else {
            Err(StarmetalError::IntegrityError {
                expected: artifact.blake3.clone(),
                actual,
            })
        }
    }
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
    fn fixture_driven_roundtrip() {
        let fixtures = load_fixtures("lockfile/01_roundtrip.json");
        for fix in &fixtures {
            let toml_input = fix["input"]["toml"].as_str().unwrap();
            let name = fix["name"].as_str().unwrap_or("?");

            if fix["error"].is_string() {
                // Should fail to parse
                assert!(
                    LockFile::from_toml(toml_input).is_err(),
                    "fixture '{name}' should fail"
                );
                continue;
            }

            let lock = LockFile::from_toml(toml_input)
                .unwrap_or_else(|e| panic!("fixture '{name}' parse failed: {e}"));

            assert_eq!(
                lock.metadata.schema_version,
                fix["expected"]["schema_version"].as_u64().unwrap() as u32,
                "fixture '{name}' schema_version"
            );

            if let Some(count) = fix["expected"]["package_count"].as_u64() {
                assert_eq!(
                    lock.packages.len(),
                    count as usize,
                    "fixture '{name}' package_count"
                );
            }

            if let Some(expected_name) = fix["expected"]["first_package_name"].as_str() {
                assert_eq!(
                    lock.packages[0].name, expected_name,
                    "fixture '{name}' first package name"
                );
            }

            // Roundtrip: serialize and re-parse
            let serialized = lock.to_toml().unwrap();
            let reparsed = LockFile::from_toml(&serialized)
                .unwrap_or_else(|e| panic!("fixture '{name}' roundtrip failed: {e}"));
            assert_eq!(lock.packages.len(), reparsed.packages.len());
        }
    }

    #[test]
    fn find_package_by_ecosystem() {
        let lock = LockFile {
            metadata: LockMetadata {
                schema_version: 1,
                generated_at: "2026-01-01T00:00:00Z".into(),
                starmetal_version: "0.1.0".into(),
            },
            packages: vec![
                LockedPackage {
                    ecosystem: Ecosystem::PyPI,
                    name: "requests".into(),
                    version: "2.31.0".into(),
                    artifacts: vec![],
                    resolved_from: "https://pypi.org".into(),
                    pinned: false,
                },
                LockedPackage {
                    ecosystem: Ecosystem::Npm,
                    name: "lodash".into(),
                    version: "4.17.21".into(),
                    artifacts: vec![],
                    resolved_from: "https://registry.npmjs.org".into(),
                    pinned: false,
                },
            ],
        };

        assert!(lock.find_package(Ecosystem::PyPI, "requests").is_some());
        assert!(lock.find_package(Ecosystem::Npm, "lodash").is_some());
        assert!(lock.find_package(Ecosystem::PyPI, "lodash").is_none());
        assert!(lock.find_package(Ecosystem::Cargo, "serde").is_none());
    }

    #[test]
    fn verify_artifact_integrity() {
        let data = b"package contents";
        let hash = crate::integrity::blake3_hex(data);

        let lock = LockFile {
            metadata: LockMetadata {
                schema_version: 1,
                generated_at: "2026-01-01T00:00:00Z".into(),
                starmetal_version: "0.1.0".into(),
            },
            packages: vec![LockedPackage {
                ecosystem: Ecosystem::PyPI,
                name: "requests".into(),
                version: "2.31.0".into(),
                artifacts: vec![LockedArtifact {
                    filename: "requests-2.31.0.tar.gz".into(),
                    blake3: hash.clone(),
                    size: data.len() as u64,
                }],
                resolved_from: "https://pypi.org".into(),
                pinned: false,
            }],
        };

        // Valid data passes
        assert!(
            lock.verify_artifact(Ecosystem::PyPI, "requests", "requests-2.31.0.tar.gz", data)
                .is_ok()
        );

        // Tampered data fails
        assert!(
            lock.verify_artifact(
                Ecosystem::PyPI,
                "requests",
                "requests-2.31.0.tar.gz",
                b"tampered"
            )
            .is_err()
        );

        // Missing package fails
        assert!(
            lock.verify_artifact(Ecosystem::Npm, "lodash", "lodash.tgz", data)
                .is_err()
        );
    }
}
