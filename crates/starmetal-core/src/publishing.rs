use ahash::AHashMap;
use bytes::Bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::package::{ArtifactDigest, Ecosystem, PackageName, VersionMetadata};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum PublishMode {
    #[default]
    Local,
    LocalAndForward,
    ForwardOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TokenScope {
    Read,
    Publish,
    Yank,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PublishTokenConfig {
    pub token: String,
    #[serde(default)]
    pub scopes: Vec<TokenScope>,
    #[serde(default)]
    pub ecosystems: Vec<Ecosystem>,
    #[serde(default)]
    pub packages: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PublishedArtifact {
    pub filename: String,
    pub data: Bytes,
    pub upstream_hashes: AHashMap<String, String>,
}

impl PublishedArtifact {
    pub fn digest(&self, blake3: String) -> ArtifactDigest {
        ArtifactDigest {
            filename: self.filename.clone(),
            blake3,
            size: self.data.len() as u64,
            upstream_hashes: self.upstream_hashes.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PublishRequest {
    pub ecosystem: Ecosystem,
    pub name: PackageName,
    pub version: String,
    pub license: Option<String>,
    pub yanked: bool,
    pub listed: bool,
    pub artifacts: Vec<PublishedArtifact>,
    pub protocol_metadata: ProtocolMetadata,
    pub allow_overwrite: bool,
    pub allow_shadowing: bool,
    /// Descriptive repository attribution for the published component (ADR-0020). `None` leaves the
    /// component unattributed (persisted as the empty string). Adapters pass `None` today; named
    /// repositories arrive with facets in a later stage.
    pub repository: Option<String>,
}

impl PublishRequest {
    pub fn metadata(&self, artifacts: Vec<ArtifactDigest>) -> VersionMetadata {
        VersionMetadata {
            name: self.name.clone(),
            version: self.version.clone(),
            artifacts,
            license: self.license.clone(),
            yanked: self.yanked,
            listed: Some(self.listed),
            protocol_metadata: Some(self.protocol_metadata.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PublishRecord {
    pub ecosystem: Ecosystem,
    pub name: PackageName,
    pub version: String,
    pub artifacts: Vec<ArtifactDigest>,
    pub source: PublishSource,
    pub protocol_metadata: ProtocolMetadata,
    pub published_at_unix_seconds: u64,
    pub yanked: bool,
    pub listed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PublishSource {
    Local,
    UpstreamCache,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "data", rename_all = "kebab-case")]
pub enum ProtocolMetadata {
    #[default]
    Generic,
    PyPI {
        fields: serde_json::Value,
    },
    Npm {
        packument: serde_json::Value,
    },
    Cargo {
        index_entry: serde_json::Value,
    },
    Hex {
        package: serde_json::Value,
    },
    Maven {
        path: String,
    },
    RubyGems {
        metadata: serde_json::Value,
    },
    NuGet {
        nuspec: serde_json::Value,
    },
    Pub {
        pubspec: serde_json::Value,
    },
    /// Go modules (ADR-0023) are resolved read-only from an upstream git repository — there is no
    /// hosted publish workflow yet, so this variant exists for match exhaustiveness and carries the
    /// synthesized or repository `go.mod` text.
    Go {
        go_mod: String,
    },
}

impl ProtocolMetadata {
    pub fn default_for(ecosystem: Ecosystem) -> Self {
        match ecosystem {
            Ecosystem::PyPI => Self::PyPI {
                fields: serde_json::Value::Null,
            },
            Ecosystem::Npm => Self::Npm {
                packument: serde_json::Value::Null,
            },
            Ecosystem::Cargo => Self::Cargo {
                index_entry: serde_json::Value::Null,
            },
            Ecosystem::Hex => Self::Hex {
                package: serde_json::Value::Null,
            },
            Ecosystem::Maven => Self::Maven { path: String::new() },
            Ecosystem::RubyGems => Self::RubyGems {
                metadata: serde_json::Value::Null,
            },
            Ecosystem::NuGet => Self::NuGet {
                nuspec: serde_json::Value::Null,
            },
            Ecosystem::Pub => Self::Pub {
                pubspec: serde_json::Value::Null,
            },
            Ecosystem::Go => Self::Go { go_mod: String::new() },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PublishResult {
    pub ecosystem: Ecosystem,
    pub name: PackageName,
    pub version: String,
    pub artifacts: Vec<ArtifactDigest>,
    pub mode: PublishMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct YankRequest {
    pub ecosystem: Ecosystem,
    pub name: PackageName,
    pub version: String,
    pub yanked: bool,
}
