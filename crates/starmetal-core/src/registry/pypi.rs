use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PEP 691 Simple Repository API — project detail response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PypiProject {
    pub meta: PypiMeta,
    pub name: String,
    #[serde(default)]
    pub versions: Vec<String>,
    pub files: Vec<PypiFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PypiMeta {
    #[serde(rename = "api-version")]
    pub api_version: String,
}

/// A single distribution file in a PyPI project listing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PypiFile {
    pub filename: String,
    pub url: String,
    pub hashes: HashMap<String, String>,
    #[serde(rename = "requires-python")]
    pub requires_python: Option<String>,
    #[serde(default)]
    pub yanked: PypiYanked,
    pub size: Option<u64>,
    #[serde(rename = "upload-time")]
    pub upload_time: Option<String>,
    #[serde(rename = "dist-info-metadata", default)]
    pub dist_info_metadata: Option<serde_json::Value>,
    #[serde(rename = "gpg-sig", default)]
    pub gpg_sig: Option<bool>,
}

/// Yanked can be `false`, `true`, or a reason string.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PypiYanked {
    Bool(bool),
    Reason(String),
}

impl Default for PypiYanked {
    fn default() -> Self {
        Self::Bool(false)
    }
}

impl PypiYanked {
    pub fn is_yanked(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Reason(_) => true,
        }
    }
}

/// PEP 691 project index (list of all projects).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PypiIndex {
    pub meta: PypiMeta,
    pub projects: Vec<PypiIndexProject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PypiIndexProject {
    pub name: String,
}
