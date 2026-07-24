use serde::{Deserialize, Serialize};

use crate::dependency::Dependency;

/// Classification of the semantic distance between the current and target version.
///
/// The upgrade variants are ordered from least to most impactful, so `Ord`/`max` picks the
/// most significant upgrade in a group. `Rollback` is a downgrade rather than an upgrade, so
/// it deliberately sorts *below* every upgrade variant and never dominates a group's ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateType {
    /// A downgrade to a lower version (e.g. off a yanked release). Sorts lowest.
    Rollback,
    /// Pin a floating range to an exact version without changing the target.
    Pin,
    /// Move a digest reference (e.g. a container image digest).
    Digest,
    /// A patch-level bump (`x.y.Z`).
    Patch,
    /// A minor-level bump (`x.Y.z`).
    Minor,
    /// A major-level bump (`X.y.z`).
    Major,
}

impl std::fmt::Display for UpdateType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Pin => "pin",
            Self::Digest => "digest",
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
            Self::Rollback => "rollback",
        };
        formatter.write_str(text)
    }
}

/// How to rewrite a dependency's constraint when a newer version is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RangeStrategy {
    /// Let the versioning scheme choose a sensible default (bump or replace).
    #[default]
    Auto,
    /// Replace any range with the exact target version.
    Pin,
    /// Raise the lower bound of a range to the target, keeping the range shape.
    Bump,
    /// Replace the constraint only when the target falls outside the current range.
    Replace,
    /// Widen the range to include the target without dropping the old lower bound.
    Widen,
}

/// A concrete proposed update for a single dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyUpdate {
    /// The dependency being updated.
    pub dependency: Dependency,
    /// The classification of the update.
    pub update_type: UpdateType,
    /// The new constraint text to write into the manifest.
    pub new_value: String,
    /// The concrete target version the update resolves to.
    pub new_version: String,
}
