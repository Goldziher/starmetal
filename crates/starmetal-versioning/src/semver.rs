use std::cmp::Ordering;

use semver::{Comparator, Op, Version, VersionReq};
use starmetal_update_core::ports::Versioning;
use starmetal_update_core::update::{RangeStrategy, UpdateType};

/// Cargo-style semantic-versioning scheme (semver 2.0 with Cargo range operators).
#[derive(Debug, Clone, Copy, Default)]
pub struct SemverVersioning;

impl SemverVersioning {
    /// Create a new semver versioning scheme.
    pub fn new() -> Self {
        Self
    }
}

/// Build a concrete lower-bound [`Version`] from a range comparator.
fn comparator_lower_bound(comparator: &Comparator) -> Version {
    Version {
        major: comparator.major,
        minor: comparator.minor.unwrap_or(0),
        patch: comparator.patch.unwrap_or(0),
        pre: comparator.pre.clone(),
        build: semver::BuildMetadata::EMPTY,
    }
}

/// Whether a comparator establishes an inclusive lower bound on satisfying versions.
///
/// `Op::Greater` (`>x`) is excluded: it is exclusive, so its stated version is not itself
/// permitted and would be a wrong lower bound.
fn is_lower_bound(op: Op) -> bool {
    matches!(op, Op::Exact | Op::GreaterEq | Op::Tilde | Op::Caret | Op::Wildcard)
}

/// Classify an upgrade from `current` to a strictly-greater `candidate`.
///
/// Honors Cargo's 0.x caret semantics: `^0.y.z` locks the minor and `^0.0.z` locks the
/// patch, so a change in the left-most non-zero component is a breaking (major-equivalent)
/// bump even though the numeric major stays `0`.
fn classify_bump(current: &Version, candidate: &Version) -> UpdateType {
    if candidate.major != current.major {
        UpdateType::Major
    } else if current.major == 0 {
        if candidate.minor != current.minor || current.minor == 0 {
            UpdateType::Major
        } else {
            UpdateType::Patch
        }
    } else if candidate.minor != current.minor {
        UpdateType::Minor
    } else {
        UpdateType::Patch
    }
}

/// Extract a leading Cargo range operator, returning `(prefix, rest)`.
fn split_operator(value: &str) -> (&str, &str) {
    let trimmed = value.trim();
    for prefix in ["^", "~", "="] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return (prefix, rest.trim());
        }
    }
    ("", trimmed)
}

impl Versioning for SemverVersioning {
    fn scheme(&self) -> &'static str {
        "semver"
    }

    fn is_valid(&self, version: &str) -> bool {
        Version::parse(version).is_ok()
    }

    fn is_stable(&self, version: &str) -> bool {
        Version::parse(version).map(|v| v.pre.is_empty()).unwrap_or(false)
    }

    fn compare(&self, left: &str, right: &str) -> Option<Ordering> {
        let left = Version::parse(left).ok()?;
        let right = Version::parse(right).ok()?;
        Some(left.cmp(&right))
    }

    fn matches(&self, version: &str, constraint: &str) -> bool {
        let Ok(version) = Version::parse(version) else {
            return false;
        };
        VersionReq::parse(constraint)
            .map(|req| req.matches(&version))
            .unwrap_or(false)
    }

    fn min_version(&self, constraint: &str) -> Option<String> {
        let req = VersionReq::parse(constraint).ok()?;
        req.comparators
            .iter()
            .filter(|comparator| is_lower_bound(comparator.op))
            .map(comparator_lower_bound)
            .max()
            .map(|version| version.to_string())
    }

    fn diff(&self, current: &str, candidate: &str) -> Option<UpdateType> {
        let current = Version::parse(current).ok()?;
        let candidate = Version::parse(candidate).ok()?;
        match candidate.cmp(&current) {
            Ordering::Less => Some(UpdateType::Rollback),
            Ordering::Equal => None,
            Ordering::Greater => Some(classify_bump(&current, &candidate)),
        }
    }

    fn get_new_value(&self, current_value: &str, strategy: RangeStrategy, target: &str) -> Option<String> {
        // Only rewrite toward a valid concrete target.
        if Version::parse(target).is_err() {
            return None;
        }

        if strategy == RangeStrategy::Pin {
            return Some(format!("={target}"));
        }

        let already_satisfied = self.matches(target, current_value);

        // Replace only rewrites when the target is not already permitted.
        if strategy == RangeStrategy::Replace && already_satisfied {
            return None;
        }

        // Widen keeps the existing lower bound and extends the upper bound to admit the
        // target, rather than moving the constraint onto it.
        if strategy == RangeStrategy::Widen {
            if already_satisfied {
                return None;
            }
            return self.widen(current_value, target);
        }

        // Multi-comparator ranges (e.g. ">=1, <2") cannot have a single operator moved onto
        // the target; if the target is already inside the range there is nothing to do,
        // otherwise widen the range to include it. ~keep
        if current_value.contains(',') {
            if already_satisfied {
                return None;
            }
            return self.widen(current_value, target);
        }

        // Wildcard forms (`*`, `1.*`) have no operator to preserve and are left untouched.
        if current_value.contains('*') {
            return None;
        }

        let (prefix, rest) = split_operator(current_value);
        // The remainder after any operator must itself be a plain version core.
        if rest.is_empty() || rest.starts_with(['>', '<']) {
            return None;
        }
        match prefix {
            "^" | "~" | "=" => Some(format!("{prefix}{target}")),
            "" => Some(target.to_string()),
            _ => None,
        }
    }
}

impl SemverVersioning {
    /// Widen a constraint to admit `target` while preserving its existing lower bound.
    ///
    /// Produces `>=<lower>, <<target_major + 1>.0.0`, which keeps every currently-allowed
    /// version and additionally admits `target`. Returns `None` when no inclusive lower
    /// bound can be derived from `current_value`.
    fn widen(&self, current_value: &str, target: &str) -> Option<String> {
        let lower = self.min_version(current_value)?;
        let target_major = Version::parse(target).ok()?.major;
        Some(format!(">={lower}, <{}.0.0", target_major + 1))
    }
}
