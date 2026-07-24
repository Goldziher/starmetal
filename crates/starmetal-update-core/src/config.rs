use serde::{Deserialize, Serialize};

use crate::update::RangeStrategy;

/// Configuration governing how the update engine proposes changes.
///
/// This is intentionally minimal for the initial engine; richer Renovate-style
/// `packageRules`, schedules, and grouping are layered on in later phases.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateConfig {
    /// How to rewrite constraints when a newer version is found.
    pub range_strategy: RangeStrategy,
    /// Package names to skip entirely.
    pub ignore: Vec<String>,
    /// Whether pre-release versions are eligible update targets.
    pub allow_prerelease: bool,
}

impl UpdateConfig {
    /// Whether the given package name is on the ignore list.
    pub fn is_ignored(&self, name: &str) -> bool {
        self.ignore.iter().any(|ignored| ignored == name)
    }
}
