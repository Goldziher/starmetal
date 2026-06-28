use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single version entry in a Cargo sparse index file.
/// Index files contain one JSON object per line (newline-delimited).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CargoIndexEntry {
    pub name: String,
    pub vers: String,
    pub deps: Vec<CargoDep>,
    pub cksum: String,
    #[serde(default)]
    pub features: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub features2: Option<HashMap<String, Vec<String>>>,
    pub yanked: bool,
    #[serde(default)]
    pub links: Option<String>,
    #[serde(default)]
    pub v: Option<u32>,
    #[serde(default)]
    pub rust_version: Option<String>,
}

/// A dependency in a Cargo index entry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CargoDep {
    pub name: String,
    pub req: String,
    pub features: Vec<String>,
    pub optional: bool,
    pub default_features: bool,
    pub target: Option<String>,
    pub kind: CargoDepKind,
    #[serde(default)]
    pub registry: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CargoDepKind {
    Normal,
    Dev,
    Build,
}

/// Cargo registry config.json at the index root.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CargoConfig {
    pub dl: String,
    #[serde(default)]
    pub api: Option<String>,
    #[serde(rename = "auth-required", default)]
    pub auth_required: bool,
}

/// Compute the sparse index path for a crate name.
pub fn sparse_index_path(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_index_paths() {
        assert_eq!(sparse_index_path("a"), "1/a");
        assert_eq!(sparse_index_path("ab"), "2/ab");
        assert_eq!(sparse_index_path("abc"), "3/a/abc");
        assert_eq!(sparse_index_path("cargo"), "ca/rg/cargo");
        assert_eq!(sparse_index_path("serde_json"), "se/rd/serde_json");
        assert_eq!(sparse_index_path("Serde"), "se/rd/serde");
    }
}
