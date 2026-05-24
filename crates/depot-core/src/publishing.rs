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

impl PublishTokenConfig {
    pub fn allows(&self, scope: TokenScope, ecosystem: Ecosystem, package: &PackageName) -> bool {
        let scope_allowed =
            self.scopes.contains(&TokenScope::Admin) || self.scopes.contains(&scope);
        let ecosystem_allowed = self.ecosystems.is_empty() || self.ecosystems.contains(&ecosystem);
        let package_allowed =
            self.packages.is_empty() || self.packages.iter().any(|name| name == package.as_str());
        scope_allowed && ecosystem_allowed && package_allowed
    }
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
    pub artifacts: Vec<PublishedArtifact>,
    pub allow_overwrite: bool,
    pub allow_shadowing: bool,
}

impl PublishRequest {
    pub fn metadata(&self, artifacts: Vec<ArtifactDigest>) -> VersionMetadata {
        VersionMetadata {
            name: self.name.clone(),
            version: self.version.clone(),
            artifacts,
            license: self.license.clone(),
            yanked: self.yanked,
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
