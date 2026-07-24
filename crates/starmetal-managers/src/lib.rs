//! Manifest managers for the Starmetal dependency-update engine.
//!
//! Each manager implements [`starmetal_update_core::ports::Manager`]: it detects the
//! manifest files it understands, extracts the dependencies declared in them, and applies
//! surgical, formatting-preserving edits when a dependency's constraint should be updated.
//! Managers are pure text transforms — they never perform registry lookups or forge/git
//! operations, and every manager is gated behind its own feature flag.
//!
//! # Examples
//!
//! ```
//! let managers = starmetal_managers::all();
//! assert!(managers.iter().any(|manager| manager.name() == "cargo"));
//! ```

#[cfg(feature = "cargo")]
mod cargo;

#[cfg(feature = "cargo")]
pub use cargo::CargoManager;

use std::sync::Arc;

use starmetal_update_core::ports::Manager;

/// Returns every manager compiled into this build, selected by active feature flags.
///
/// # Examples
///
/// ```
/// let managers = starmetal_managers::all();
/// assert!(!managers.is_empty());
/// ```
#[must_use]
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn all() -> Vec<Arc<dyn Manager>> {
    let mut managers: Vec<Arc<dyn Manager>> = Vec::new();

    #[cfg(feature = "cargo")]
    managers.push(Arc::new(CargoManager::new()));

    managers
}
