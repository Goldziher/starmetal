use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Result, StarmetalError};
use crate::package::VersionMetadata;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum VulnSeverity {
    Low,
    Medium,
    High,
    #[default]
    Critical,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PolicyConfig {
    #[serde(default)]
    pub block_unlicensed: bool,
    #[serde(default)]
    pub max_vuln_severity: VulnSeverity,
    #[serde(default)]
    pub allowed_licenses: Vec<String>,
    #[serde(default)]
    pub blocked_packages: Vec<String>,
}

impl PolicyConfig {
    /// Check a package version against configured policies.
    pub fn check(&self, metadata: &VersionMetadata) -> Result<()> {
        if self
            .blocked_packages
            .iter()
            .any(|b| b == metadata.name.as_str())
        {
            return Err(StarmetalError::PolicyViolation(format!(
                "package {} is blocked",
                metadata.name
            )));
        }

        if self.block_unlicensed && metadata.license.is_none() {
            return Err(StarmetalError::PolicyViolation(format!(
                "package {} has no license",
                metadata.name
            )));
        }

        if !self.allowed_licenses.is_empty()
            && let Some(license) = &metadata.license
            && !self.allowed_licenses.iter().any(|a| a == license)
        {
            return Err(StarmetalError::PolicyViolation(format!(
                "package {} has license {license}, which is not in allowed list",
                metadata.name
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::AHashMap;

    use crate::package::{ArtifactDigest, PackageName};

    fn load_fixtures() -> Vec<serde_json::Value> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testing_data/policy/01_policy_checks.json");
        let content = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(&content).unwrap()
    }

    fn build_policy(fix: &serde_json::Value) -> PolicyConfig {
        let p = &fix["input"]["policy"];
        PolicyConfig {
            block_unlicensed: p["block_unlicensed"].as_bool().unwrap_or(false),
            max_vuln_severity: p["max_vuln_severity"]
                .as_str()
                .map(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap())
                .unwrap_or_default(),
            allowed_licenses: p["allowed_licenses"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            blocked_packages: p["blocked_packages"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn build_metadata(fix: &serde_json::Value) -> VersionMetadata {
        let pkg = &fix["input"]["package"];
        VersionMetadata {
            name: PackageName::new(pkg["name"].as_str().unwrap()),
            version: pkg["version"].as_str().unwrap().to_string(),
            license: pkg["license"].as_str().map(String::from),
            yanked: pkg["yanked"].as_bool().unwrap_or(false),
            artifacts: vec![ArtifactDigest {
                filename: "dummy.tar.gz".into(),
                blake3: "0".repeat(64),
                size: 0,
                upstream_hashes: AHashMap::new(),
            }],
        }
    }

    #[test]
    fn fixture_driven_policy_checks() {
        let fixtures = load_fixtures();
        for fix in &fixtures {
            let name = fix["name"].as_str().unwrap_or("?");
            let policy = build_policy(fix);
            let metadata = build_metadata(fix);
            let result = policy.check(&metadata);
            let expected_allowed = fix["expected"]["allowed"].as_bool().unwrap();

            if expected_allowed {
                assert!(
                    result.is_ok(),
                    "fixture '{name}' should pass but got: {result:?}"
                );
            } else {
                let err = result.unwrap_err();
                let err_msg = err.to_string();
                let expected_err = fix["error"].as_str().unwrap();
                assert!(
                    err_msg.contains(expected_err),
                    "fixture '{name}': error '{err_msg}' should contain '{expected_err}'"
                );
            }
        }
    }
}
