use serde::{Deserialize, Serialize};
use starmetal_core::package::{Ecosystem, PackageName};

/// Where a dependency sits in a manifest (affects grouping and update policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepType {
    /// A normal runtime/production dependency.
    Runtime,
    /// A development-only dependency (e.g. Cargo `dev-dependencies`).
    Dev,
    /// A build-time dependency (e.g. Cargo `build-dependencies`).
    Build,
    /// A peer dependency (npm).
    Peer,
    /// An optional dependency.
    Optional,
}

impl std::fmt::Display for DepType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Runtime => "runtime",
            Self::Dev => "dev",
            Self::Build => "build",
            Self::Peer => "peer",
            Self::Optional => "optional",
        };
        formatter.write_str(text)
    }
}

/// A single dependency extracted from a manifest file.
///
/// `current_value` is the raw constraint text as it appears in the manifest
/// (for example `1.2.3`, `^1.2`, or `>=1,<2`). The engine never compares these
/// values as strings — all ordering goes through a [`crate::ports::Versioning`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// Normalized package name.
    pub name: PackageName,
    /// Ecosystem the package belongs to (drives datasource selection).
    pub ecosystem: Ecosystem,
    /// Raw constraint text as written in the manifest.
    pub current_value: String,
    /// Manifest section the dependency was found in.
    pub dep_type: DepType,
    /// Repository-relative path of the manifest file.
    pub file_path: String,
    /// Name of the versioning scheme that governs `current_value`.
    pub versioning: String,
}

/// A manifest file and the dependencies parsed from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageFile {
    /// Repository-relative path of the manifest.
    pub path: String,
    /// Name of the manager that parsed the file.
    pub manager: String,
    /// Dependencies discovered in the file.
    pub dependencies: Vec<Dependency>,
}
