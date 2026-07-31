//! Scheduled garbage-collection sweep (ADR-0020 Stage 2d) over a [`ContentStore`].
//!
//! ## Two-phase semantics
//!
//! A single sweep drives the mark -> soft-delete -> compact lifecycle in one pass, but reclaiming
//! bytes is inherently a **two-sweep** process unless `grace` is zero:
//!
//! 1. This sweep lists every currently unreferenced blob, marks it, and soft-deletes it with a
//!    `grace_expires_at` of `now() + config.grace`.
//! 2. [`ContentStore::compact`] only hard-deletes blobs whose grace window has already elapsed.
//!    A blob freshly soft-deleted in *this* sweep therefore is not reclaimed by *this* sweep's
//!    `compact()` call — it needs a **later** sweep (run after the grace window elapses) to be
//!    physically removed.
//!
//! With `grace == Duration::ZERO` the window has already elapsed by the time `compact()` runs, so
//! a single sweep both soft-deletes and reclaims. This module contains only the pure sweep logic
//! and its config/report types — no scheduler or timer; callers decide when and how often to run
//! it.

use std::time::Duration;

use starmetal_core::content::{BlobDigest, ContentStore};
use starmetal_core::error::Result;

/// Hours in the default grace window.
const DEFAULT_GRACE_HOURS: u64 = 24;

/// Seconds in an hour, used to convert [`DEFAULT_GRACE_HOURS`] into a [`Duration`].
const SECONDS_PER_HOUR: u64 = 60 * 60;

/// Default grace window before a soft-deleted blob becomes eligible for [`compact`](ContentStore::compact).
const DEFAULT_GRACE: Duration = Duration::from_secs(DEFAULT_GRACE_HOURS * SECONDS_PER_HOUR);

/// Configuration for a single [`run_gc_sweep`] call.
#[derive(Debug, Clone)]
pub struct GcConfig {
    /// Grace window applied to every blob soft-deleted by this sweep before it becomes eligible
    /// for hard deletion by a later sweep's [`ContentStore::compact`] call.
    pub grace: Duration,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self { grace: DEFAULT_GRACE }
    }
}

/// The outcome of one [`run_gc_sweep`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    /// Number of blobs marked as garbage-collection candidates this sweep.
    pub marked: usize,
    /// Number of blobs soft-deleted this sweep (equal to `marked`; kept as a separate field so
    /// the report reads as a lifecycle trace rather than a single count).
    pub soft_deleted: usize,
    /// Digests hard-deleted (bytes and metadata reclaimed) by this sweep's [`ContentStore::compact`]
    /// call. See the module docs: this is typically empty unless a *previous* sweep's grace
    /// window has since elapsed, or `grace` is zero.
    pub reclaimed: Vec<BlobDigest>,
}

/// Run one garbage-collection sweep over `store`.
///
/// Lists every currently unreferenced blob, marks and soft-deletes each with `config.grace`, then
/// compacts (hard-deletes) whatever is already past its grace window — see the module docs for why
/// that is usually a different set of blobs than the ones just soft-deleted.
///
/// # Errors
///
/// Returns an error if any underlying [`ContentStore`] call fails.
pub async fn run_gc_sweep(store: &dyn ContentStore, config: &GcConfig) -> Result<GcReport> {
    let candidates = store.list_unreferenced_blobs().await?;

    let mut marked = 0usize;
    let mut soft_deleted = 0usize;
    for digest in &candidates {
        store.mark_unreferenced(digest).await?;
        marked += 1;
        store.soft_delete(digest, config.grace).await?;
        soft_deleted += 1;
    }

    let reclaimed = store.compact().await?;

    Ok(GcReport {
        marked,
        soft_deleted,
        reclaimed,
    })
}
