//! Versioning-scheme implementations for the Starmetal dependency-update engine.
//!
//! Each scheme implements [`starmetal_update_core::ports::Versioning`] and is a pure,
//! I/O-free transform. Schemes are compile-time optional behind Cargo features.

use std::sync::Arc;

use starmetal_core::package::Ecosystem;
use starmetal_update_core::ports::Versioning;

#[cfg(feature = "semver")]
mod semver;

#[cfg(feature = "semver")]
pub use crate::semver::SemverVersioning;

/// Return the default versioning scheme for an ecosystem, when one is compiled in.
pub fn for_ecosystem(ecosystem: Ecosystem) -> Option<Arc<dyn Versioning>> {
    match ecosystem {
        #[cfg(feature = "semver")]
        Ecosystem::Cargo => Some(Arc::new(SemverVersioning::new())),
        _ => None,
    }
}

/// Return every compiled-in versioning scheme.
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn all() -> Vec<Arc<dyn Versioning>> {
    let mut schemes: Vec<Arc<dyn Versioning>> = Vec::new();
    #[cfg(feature = "semver")]
    schemes.push(Arc::new(SemverVersioning::new()));
    schemes
}

/// Return a versioning scheme by its identifier, when compiled in.
pub fn by_scheme(scheme: &str) -> Option<Arc<dyn Versioning>> {
    match scheme {
        #[cfg(feature = "semver")]
        "semver" => Some(Arc::new(SemverVersioning::new())),
        _ => None,
    }
}

#[cfg(all(test, feature = "semver"))]
mod tests {
    use std::cmp::Ordering;

    use starmetal_update_core::ports::Versioning;
    use starmetal_update_core::update::{RangeStrategy, UpdateType};

    use super::SemverVersioning;

    fn scheme() -> SemverVersioning {
        SemverVersioning::new()
    }

    #[test]
    fn is_valid_and_stable() {
        let scheme = scheme();
        assert!(scheme.is_valid("1.2.3"));
        assert!(!scheme.is_valid("not-a-version"));
        assert!(scheme.is_stable("1.2.3"));
        assert!(!scheme.is_stable("1.2.3-rc.1"));
        assert!(!scheme.is_stable("garbage"));
    }

    #[test]
    fn compare_orders_versions() {
        let scheme = scheme();
        assert_eq!(scheme.compare("1.2.3", "1.2.4"), Some(Ordering::Less));
        assert_eq!(scheme.compare("2.0.0", "1.9.9"), Some(Ordering::Greater));
        assert_eq!(scheme.compare("1.0.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(scheme.compare("bad", "1.0.0"), None);
    }

    #[test]
    fn matches_cargo_default_caret() {
        let scheme = scheme();
        // Bare "1.2.3" is caret semantics in Cargo.
        assert!(scheme.matches("1.9.0", "1.2.3"));
        assert!(!scheme.matches("2.0.0", "1.2.3"));
        assert!(scheme.matches("1.2.5", "~1.2.3"));
        assert!(!scheme.matches("1.3.0", "~1.2.3"));
    }

    #[test]
    fn min_version_reads_lower_bound() {
        let scheme = scheme();
        assert_eq!(scheme.min_version("^1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(scheme.min_version("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(scheme.min_version("=1.4.0").as_deref(), Some("1.4.0"));
        assert_eq!(scheme.min_version("~1.2").as_deref(), Some("1.2.0"));
        assert_eq!(scheme.min_version(">=1.5, <2").as_deref(), Some("1.5.0"));
    }

    #[test]
    fn diff_classifies_updates() {
        let scheme = scheme();
        assert_eq!(scheme.diff("1.2.3", "2.0.0"), Some(UpdateType::Major));
        assert_eq!(scheme.diff("1.2.3", "1.3.0"), Some(UpdateType::Minor));
        assert_eq!(scheme.diff("1.2.3", "1.2.4"), Some(UpdateType::Patch));
        assert_eq!(scheme.diff("1.2.3", "1.2.3"), None);
        assert_eq!(scheme.diff("1.2.3", "1.2.2"), Some(UpdateType::Rollback));
    }

    #[test]
    fn get_new_value_preserves_operator() {
        let scheme = scheme();
        assert_eq!(
            scheme.get_new_value("^1.2.3", RangeStrategy::Auto, "1.5.0").as_deref(),
            Some("^1.5.0")
        );
        assert_eq!(
            scheme.get_new_value("1.2.3", RangeStrategy::Auto, "1.5.0").as_deref(),
            Some("1.5.0")
        );
        assert_eq!(
            scheme.get_new_value("~1.2", RangeStrategy::Auto, "1.5.0").as_deref(),
            Some("~1.5.0")
        );
        assert_eq!(
            scheme.get_new_value("=1.2.3", RangeStrategy::Auto, "1.5.0").as_deref(),
            Some("=1.5.0")
        );
    }

    #[test]
    fn get_new_value_pin_forces_exact() {
        let scheme = scheme();
        assert_eq!(
            scheme.get_new_value("^1.2.3", RangeStrategy::Pin, "1.5.0").as_deref(),
            Some("=1.5.0")
        );
    }

    #[test]
    fn get_new_value_rejects_unsupported() {
        let scheme = scheme();
        // Multi-comparator ranges are not rewritten (except Pin).
        assert_eq!(scheme.get_new_value(">=1.2, <2", RangeStrategy::Auto, "1.5.0"), None);
        // Invalid target is never written.
        assert_eq!(
            scheme.get_new_value("^1.2.3", RangeStrategy::Auto, "not-a-version"),
            None
        );
    }

    #[test]
    fn get_new_value_output_is_valid_and_on_target() {
        let scheme = scheme();
        // The load-bearing invariant: a rewritten value must satisfy the target.
        for current in ["^1.2.3", "1.2.3", "~1.2", "=1.0.0"] {
            let target = "1.5.7";
            let new_value = scheme
                .get_new_value(current, RangeStrategy::Auto, target)
                .expect("rewrite should succeed");
            assert!(
                scheme.matches(target, &new_value),
                "new value {new_value} for {current} must match target {target}"
            );
        }
    }

    #[test]
    fn diff_honors_zerover_caret_semantics() {
        let scheme = scheme();
        // 0.1.2 -> 0.2.0 is breaking under ^0.1.2 (minor is the locked component).
        assert_eq!(scheme.diff("0.1.2", "0.2.0"), Some(UpdateType::Major));
        // 0.1.2 -> 0.1.3 is a compatible patch.
        assert_eq!(scheme.diff("0.1.2", "0.1.3"), Some(UpdateType::Patch));
        // Any 0.0.z bump is breaking.
        assert_eq!(scheme.diff("0.0.1", "0.0.2"), Some(UpdateType::Major));
        // 1.x still classifies normally.
        assert_eq!(scheme.diff("1.2.3", "1.3.0"), Some(UpdateType::Minor));
    }

    #[test]
    fn min_version_excludes_exclusive_greater() {
        let scheme = scheme();
        // ">1.2.3" is exclusive, so it has no representable inclusive lower bound.
        assert_eq!(scheme.min_version(">1.2.3"), None);
        // ">=1.2.3" does.
        assert_eq!(scheme.min_version(">=1.2.3").as_deref(), Some("1.2.3"));
    }

    #[test]
    fn replace_strategy_skips_when_already_compatible() {
        let scheme = scheme();
        // 1.5.0 already satisfies ^1.2.3 -> no rewrite under Replace.
        assert_eq!(scheme.get_new_value("^1.2.3", RangeStrategy::Replace, "1.5.0"), None);
        // 2.0.0 falls outside -> rewrite.
        assert_eq!(
            scheme
                .get_new_value("^1.2.3", RangeStrategy::Replace, "2.0.0")
                .as_deref(),
            Some("^2.0.0")
        );
    }

    #[test]
    fn widen_keeps_lower_bound_and_admits_target() {
        let scheme = scheme();
        let widened = scheme
            .get_new_value("^1.2.3", RangeStrategy::Widen, "3.0.0")
            .expect("widen should produce a range");
        assert_eq!(widened, ">=1.2.3, <4.0.0");
        assert!(scheme.matches("3.0.0", &widened));
        assert!(scheme.matches("1.2.3", &widened));
        // Already-compatible target needs no widening.
        assert_eq!(scheme.get_new_value("^1.2.3", RangeStrategy::Widen, "1.9.0"), None);
    }

    #[test]
    fn multi_comparator_widens_to_include_target() {
        let scheme = scheme();
        // In-range target: nothing to do.
        assert_eq!(scheme.get_new_value(">=1.0, <2.0", RangeStrategy::Auto, "1.5.0"), None);
        // Out-of-range target: widen the upper bound.
        let widened = scheme
            .get_new_value(">=1.0, <2.0", RangeStrategy::Auto, "2.5.0")
            .expect("out-of-range target should widen");
        assert_eq!(widened, ">=1.0.0, <3.0.0");
        assert!(scheme.matches("2.5.0", &widened));
    }

    #[test]
    fn wildcard_current_value_is_not_rewritten() {
        let scheme = scheme();
        assert_eq!(scheme.get_new_value("1.*", RangeStrategy::Auto, "2.5.0"), None);
        assert_eq!(scheme.get_new_value("*", RangeStrategy::Auto, "2.5.0"), None);
    }
}
