use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Hex.pm HTTP API package response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HexPackage {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
    #[serde(default)]
    pub docs_html_url: Option<String>,
    #[serde(default)]
    pub meta: Option<HexMeta>,
    pub releases: Vec<HexRelease>,
    #[serde(default)]
    pub inserted_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HexMeta {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub licenses: Vec<String>,
    #[serde(default)]
    pub links: Option<serde_json::Value>,
    #[serde(default)]
    pub maintainers: Vec<String>,
}

/// A single release in a Hex package.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HexRelease {
    pub version: String,
    pub url: String,
    #[serde(default)]
    pub has_docs: bool,
    #[serde(default)]
    pub inserted_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub retirement: Option<HexRetirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HexRetirement {
    pub reason: String,
    #[serde(default)]
    pub message: Option<String>,
}

impl HexRelease {
    pub fn is_retired(&self) -> bool {
        self.retirement.is_some()
    }
}
