use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// NuGet V3 service index response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetServiceIndex {
    pub version: String,
    pub resources: Vec<NugetServiceResource>,
}

/// A resource advertised by the NuGet V3 service index.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetServiceResource {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    pub resource_type: String,
    #[serde(default)]
    pub comment: Option<String>,
}

/// NuGet PackageBaseAddress version listing response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetPackageVersions {
    pub versions: Vec<String>,
}

/// NuGet registration index response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetRegistrationIndex {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@context", default)]
    pub context: Option<serde_json::Value>,
    pub count: u64,
    pub items: Vec<NugetRegistrationPage>,
}

/// A page in a NuGet registration index.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetRegistrationPage {
    #[serde(rename = "@id")]
    pub id: String,
    pub count: u64,
    pub lower: String,
    pub upper: String,
    #[serde(default)]
    pub items: Vec<NugetRegistrationLeaf>,
}

/// A leaf entry in NuGet registration metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetRegistrationLeaf {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "catalogEntry")]
    pub catalog_entry: NugetCatalogEntry,
    #[serde(rename = "packageContent")]
    pub package_content: String,
    #[serde(default)]
    pub registration: Option<String>,
}

/// NuGet catalog entry subset used by registration metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetCatalogEntry {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "type", default)]
    pub entry_type: Option<String>,
    #[serde(rename = "id")]
    pub id_field: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub authors: Option<String>,
    #[serde(default)]
    pub listed: Option<bool>,
    #[serde(rename = "licenseExpression", default)]
    pub license_expression: Option<String>,
    #[serde(rename = "projectUrl", default)]
    pub project_url: Option<String>,
    #[serde(rename = "dependencyGroups", default)]
    pub dependency_groups: Vec<NugetDependencyGroup>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A NuGet dependency group inside registration metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetDependencyGroup {
    #[serde(rename = "targetFramework", default)]
    pub target_framework: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<NugetDependency>,
}

/// A NuGet package dependency.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NugetDependency {
    pub id: String,
    #[serde(default)]
    pub range: Option<String>,
    #[serde(default)]
    pub registration: Option<String>,
}
