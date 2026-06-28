use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// npm registry packument — full package metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NpmPackument {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: HashMap<String, String>,
    pub versions: HashMap<String, NpmVersion>,
    #[serde(default)]
    pub time: HashMap<String, String>,
    #[serde(default)]
    pub readme: Option<String>,
}

/// A single version within a packument.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NpmVersion {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    pub dev_dependencies: HashMap<String, String>,
    pub dist: NpmDist,
}

/// Distribution metadata for an npm version.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NpmDist {
    pub tarball: String,
    pub shasum: String,
    #[serde(default)]
    pub integrity: Option<String>,
    #[serde(rename = "fileCount")]
    pub file_count: Option<u64>,
    #[serde(rename = "unpackedSize")]
    pub unpacked_size: Option<u64>,
}
