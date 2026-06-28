use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Dart Hosted Pub package response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PubPackage {
    pub name: String,
    #[serde(default)]
    pub latest: Option<PubVersion>,
    pub versions: Vec<PubVersion>,
}

/// A package version in a Hosted Pub repository response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PubVersion {
    pub version: String,
    pub pubspec: Pubspec,
    #[serde(rename = "archive_url")]
    pub archive_url: String,
    #[serde(default)]
    pub archive_sha256: Option<String>,
    #[serde(default)]
    pub published: Option<String>,
}

/// Pubspec subset relevant to package resolution.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Pubspec {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub environment: HashMap<String, String>,
    #[serde(default)]
    pub dependencies: HashMap<String, serde_json::Value>,
    #[serde(rename = "dev_dependencies", default)]
    pub dev_dependencies: HashMap<String, serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}
