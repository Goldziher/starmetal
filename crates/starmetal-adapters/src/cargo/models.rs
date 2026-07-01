//! Cargo sparse index types, conversions, and serialization helpers.

use ahash::AHashMap;
use starmetal_core::package::{ArtifactDigest, PackageName, VersionInfo, VersionMetadata};
use starmetal_core::registry::cargo::{CargoConfig, CargoIndexEntry};

/// Convert a slice of index entries into version info summaries.
pub fn cargo_entries_to_version_infos(entries: &[CargoIndexEntry]) -> Vec<VersionInfo> {
    entries
        .iter()
        .map(|entry| VersionInfo {
            version: entry.vers.clone(),
            yanked: entry.yanked,
        })
        .collect()
}

/// Convert a single index entry into full version metadata.
pub fn cargo_entry_to_metadata(name: &PackageName, entry: &CargoIndexEntry) -> VersionMetadata {
    let filename = format!("{}-{}.crate", name.as_str(), entry.vers);
    let mut upstream_hashes = AHashMap::new();
    upstream_hashes.insert("sha256".to_string(), entry.cksum.clone());

    let artifact = ArtifactDigest {
        filename,
        blake3: String::new(),
        size: 0,
        upstream_hashes,
    };

    VersionMetadata {
        name: name.clone(),
        version: entry.vers.clone(),
        artifacts: vec![artifact],
        license: None,
        yanked: entry.yanked,
        listed: None,
        protocol_metadata: Some(starmetal_core::publishing::ProtocolMetadata::Cargo {
            index_entry: serde_json::to_value(entry).unwrap_or(serde_json::Value::Null),
        }),
    }
}

/// Serialize index entries to newline-delimited JSON (one JSON object per line).
pub fn entries_to_ndjson(entries: &[CargoIndexEntry]) -> String {
    let mut result = String::new();
    for entry in entries {
        if let Ok(line) = serde_json::to_string(entry) {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&line);
        }
    }
    result
}

/// Build the config.json response for the Cargo sparse index root.
pub fn build_config_json(dl_base: &str) -> CargoConfig {
    CargoConfig {
        dl: dl_base.to_string(),
        api: None,
        auth_required: false,
    }
}

pub fn build_config_json_with_api(dl_base: &str, api_base: Option<String>) -> CargoConfig {
    CargoConfig {
        dl: dl_base.to_string(),
        api: api_base,
        auth_required: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starmetal_core::registry::cargo::CargoDep;
    use std::collections::HashMap;

    fn sample_entry(version: &str, yanked: bool) -> CargoIndexEntry {
        CargoIndexEntry {
            name: "serde".to_string(),
            vers: version.to_string(),
            deps: vec![],
            cksum: "abc123".to_string(),
            features: HashMap::new(),
            features2: None,
            yanked,
            links: None,
            v: Some(2),
            rust_version: None,
        }
    }

    fn entry_with_deps() -> CargoIndexEntry {
        CargoIndexEntry {
            name: "my-crate".to_string(),
            vers: "0.1.0".to_string(),
            deps: vec![CargoDep {
                name: "serde".to_string(),
                req: "^1.0".to_string(),
                features: vec!["derive".to_string()],
                optional: false,
                default_features: true,
                target: None,
                kind: starmetal_core::registry::cargo::CargoDepKind::Normal,
                registry: None,
                package: None,
            }],
            cksum: "deadbeef".to_string(),
            features: HashMap::from([("default".to_string(), vec![])]),
            features2: None,
            yanked: false,
            links: None,
            v: Some(2),
            rust_version: Some("1.70".to_string()),
        }
    }

    #[test]
    fn should_convert_entries_to_version_infos() {
        let entries = vec![
            sample_entry("1.0.0", false),
            sample_entry("1.1.0", true),
            sample_entry("2.0.0", false),
        ];
        let infos = cargo_entries_to_version_infos(&entries);
        assert_eq!(infos.len(), 3);
        assert_eq!(infos[0].version, "1.0.0");
        assert!(!infos[0].yanked);
        assert_eq!(infos[1].version, "1.1.0");
        assert!(infos[1].yanked);
        assert_eq!(infos[2].version, "2.0.0");
        assert!(!infos[2].yanked);
    }

    #[test]
    fn should_convert_entry_to_metadata() {
        let entry = sample_entry("1.0.0", false);
        let name = PackageName::new("serde");
        let meta = cargo_entry_to_metadata(&name, &entry);

        assert_eq!(meta.name.as_str(), "serde");
        assert_eq!(meta.version, "1.0.0");
        assert!(!meta.yanked);
        assert_eq!(meta.artifacts.len(), 1);
        assert_eq!(meta.artifacts[0].filename, "serde-1.0.0.crate");
        assert_eq!(
            meta.artifacts[0].upstream_hashes.get("sha256"),
            Some(&"abc123".to_string())
        );
        assert!(meta.artifacts[0].blake3.is_empty());
        assert_eq!(meta.artifacts[0].size, 0);
        assert!(meta.license.is_none());
    }

    #[test]
    fn should_serialize_entries_to_ndjson() {
        let entries = vec![sample_entry("1.0.0", false), sample_entry("2.0.0", true)];
        let ndjson = entries_to_ndjson(&entries);
        let lines: Vec<&str> = ndjson.split('\n').collect();

        assert_eq!(lines.len(), 2);
        let parsed_first: serde_json::Value =
            serde_json::from_str(lines[0]).expect("valid JSON on line 1");
        assert_eq!(parsed_first["vers"], "1.0.0");
        assert_eq!(parsed_first["yanked"], false);

        let parsed_second: serde_json::Value =
            serde_json::from_str(lines[1]).expect("valid JSON on line 2");
        assert_eq!(parsed_second["vers"], "2.0.0");
        assert_eq!(parsed_second["yanked"], true);
    }

    #[test]
    fn should_build_config_json() {
        let config = build_config_json("https://starmetal.example.com/cargo/crates");
        assert_eq!(config.dl, "https://starmetal.example.com/cargo/crates");
        assert!(config.api.is_none());
        assert!(!config.auth_required);
    }

    #[test]
    fn should_handle_empty_entries() {
        let entries: Vec<CargoIndexEntry> = vec![];
        assert!(cargo_entries_to_version_infos(&entries).is_empty());
        assert!(entries_to_ndjson(&entries).is_empty());
    }

    #[test]
    fn should_preserve_deps_and_features_in_ndjson() {
        let entry = entry_with_deps();
        let ndjson = entries_to_ndjson(&[entry]);
        let parsed: serde_json::Value = serde_json::from_str(&ndjson).expect("valid JSON");
        assert_eq!(parsed["deps"][0]["name"], "serde");
        assert_eq!(parsed["deps"][0]["req"], "^1.0");
        assert!(parsed["features"]["default"].is_array());
        assert_eq!(parsed["rust_version"], "1.70");
    }
}
