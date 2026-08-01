//! Publish quota reserve/reconcile (ADR-0021).
//!
//! A process-local, in-memory ledger enforcing a per-`(ecosystem, namespace)` ceiling on published
//! version count and cumulative artifact bytes. This is a first increment: the ledger is not
//! persisted and not shared across replicas, and it is not coupled to the Postgres metadata store.
//!
//! Concurrency safety: [`CachingPackageService::reserve_quota`] performs its "would this exceed the
//! ceiling" check and, if not, its increment of `reserved` usage inside a single critical section
//! guarded by one `std::sync::Mutex` — the check and the mutation never straddle a lock release, so
//! two concurrent publishes racing the same `(ecosystem, namespace)` coordinate cannot both observe
//! room for a delta that only fits once (no double-spend). The lock is held only for in-memory
//! arithmetic, never across an `.await`.
//!
//! A [`QuotaReservationGuard`] ties one reservation to its publish's lifetime: [`Drop`] releases the
//! reservation (moving the delta back out of `reserved`) unless the caller has already
//! [`QuotaReservationGuard::reconcile`]d it into committed usage. This covers every exit path of
//! `publish_package` — the transactional block's success, its rollback branch, and any early-return
//! error in between — without each branch needing to remember to clean up.

use std::sync::Mutex;

use ahash::AHashMap;
use starmetal_core::config::{QuotaConfig, QuotaLimits};
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::Ecosystem;
use starmetal_core::supply_chain::PolicyReason;

use super::CachingPackageService;

/// Ledger key: the `(ecosystem, namespace)` coordinate a quota ceiling applies to. `namespace` is
/// the component's grouping (npm scope, Maven group id; see
/// [`starmetal_core::package::PackageName::publish_namespace`]) — `None` for ecosystems with no
/// namespace concept.
pub(in crate::service) type QuotaKey = (Ecosystem, Option<String>);

/// Committed and in-flight-reserved usage for one [`QuotaKey`].
#[derive(Debug, Default, Clone, Copy)]
pub(in crate::service) struct QuotaUsage {
    committed_versions: u64,
    committed_bytes: u64,
    reserved_versions: u64,
    reserved_bytes: u64,
}

/// The in-memory ledger: one entry per coordinate that has ever reserved or committed usage.
pub(in crate::service) type QuotaLedger = Mutex<AHashMap<QuotaKey, QuotaUsage>>;

/// RAII guard for one in-flight quota reservation (ADR-0021).
///
/// [`Drop`] releases the reservation — subtracting this guard's delta back out of `reserved` — unless
/// [`Self::reconcile`] was called first. This means a reservation is only ever leaked if the process
/// itself is killed mid-publish (out of scope for a process-local ledger); every normal exit path,
/// including a `?`-propagated error and the transactional block's rollback branch, releases it.
pub(in crate::service) struct QuotaReservationGuard<'a> {
    ledger: &'a QuotaLedger,
    key: QuotaKey,
    versions: u64,
    bytes: u64,
    reconciled: bool,
}

impl QuotaReservationGuard<'_> {
    /// Move this reservation's delta from `reserved` into `committed` usage (the publish succeeded).
    /// Consumes the guard so it cannot be reconciled twice; `Drop` still runs afterward but becomes a
    /// no-op once `reconciled` is set.
    pub(in crate::service) fn reconcile(mut self) {
        self.reconciled = true;
        let mut ledger = self.ledger.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(usage) = ledger.get_mut(&self.key) {
            usage.reserved_versions = usage.reserved_versions.saturating_sub(self.versions);
            usage.reserved_bytes = usage.reserved_bytes.saturating_sub(self.bytes);
            usage.committed_versions = usage.committed_versions.saturating_add(self.versions);
            usage.committed_bytes = usage.committed_bytes.saturating_add(self.bytes);
        }
    }
}

impl Drop for QuotaReservationGuard<'_> {
    fn drop(&mut self) {
        if self.reconciled {
            return;
        }
        let mut ledger = self.ledger.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(usage) = ledger.get_mut(&self.key) {
            usage.reserved_versions = usage.reserved_versions.saturating_sub(self.versions);
            usage.reserved_bytes = usage.reserved_bytes.saturating_sub(self.bytes);
        }
    }
}

impl CachingPackageService {
    /// Resolve the effective [`QuotaLimits`] for `ecosystem`: a `per_ecosystem` entry takes
    /// precedence, falling back to `default_limits`, else `None` (unlimited).
    fn quota_limits_for(quota: &QuotaConfig, ecosystem: Ecosystem) -> Option<&QuotaLimits> {
        quota
            .per_ecosystem
            .get(&ecosystem.to_string())
            .or(quota.default_limits.as_ref())
    }

    /// Reserve `add_versions`/`add_bytes` against the quota ceiling for `(ecosystem, namespace)`
    /// ahead of a publish's transactional writes (ADR-0021).
    ///
    /// Returns `Ok(None)` — and takes no lock — when quota enforcement is disabled, unconfigured for
    /// this ecosystem, or unlimited in both dimensions, so the publish path is byte-for-byte inert in
    /// that case. Otherwise the check-then-increment runs inside one critical section: denies with
    /// [`StarmetalError::PolicyViolation`] (carrying the [`PolicyReason::QuotaExceeded`] code) when
    /// the reservation would push either dimension over its ceiling, recording no reservation in that
    /// case; else increments `reserved` usage and returns a guard scoped to this reservation.
    ///
    /// # Errors
    ///
    /// Returns [`StarmetalError::PolicyViolation`] when the reservation would exceed a configured
    /// ceiling.
    pub(in crate::service) fn reserve_quota(
        &self,
        ecosystem: Ecosystem,
        namespace: Option<String>,
        add_versions: u64,
        add_bytes: u64,
    ) -> Result<Option<QuotaReservationGuard<'_>>> {
        let Some(quota) = &self.quota else {
            return Ok(None);
        };
        if !quota.enabled {
            return Ok(None);
        }
        let Some(limits) = Self::quota_limits_for(quota, ecosystem) else {
            return Ok(None);
        };
        if limits.max_versions.is_none() && limits.max_bytes.is_none() {
            return Ok(None);
        }

        let key: QuotaKey = (ecosystem, namespace);
        let mut ledger = self
            .quota_ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let usage = ledger.entry(key.clone()).or_default();

        if let Some(max_versions) = limits.max_versions {
            let projected = usage
                .committed_versions
                .saturating_add(usage.reserved_versions)
                .saturating_add(add_versions);
            if projected > max_versions {
                return Err(quota_exceeded_error(format!(
                    "publishing would push {ecosystem} past its configured version quota of \
                     {max_versions} ({} committed, {} reserved, {add_versions} requested)",
                    usage.committed_versions, usage.reserved_versions
                )));
            }
        }
        if let Some(max_bytes) = limits.max_bytes {
            let projected = usage
                .committed_bytes
                .saturating_add(usage.reserved_bytes)
                .saturating_add(add_bytes);
            if projected > max_bytes {
                return Err(quota_exceeded_error(format!(
                    "publishing would push {ecosystem} past its configured byte quota of {max_bytes} \
                     ({} committed, {} reserved, {add_bytes} requested)",
                    usage.committed_bytes, usage.reserved_bytes
                )));
            }
        }

        usage.reserved_versions = usage.reserved_versions.saturating_add(add_versions);
        usage.reserved_bytes = usage.reserved_bytes.saturating_add(add_bytes);

        Ok(Some(QuotaReservationGuard {
            ledger: &self.quota_ledger,
            key,
            versions: add_versions,
            bytes: add_bytes,
            reconciled: false,
        }))
    }
}

/// Build the `PolicyViolation` for a denied reservation, prefixed with the stable
/// [`PolicyReason::QuotaExceeded`] code, matching the `<code>: <prose>` convention the other
/// supply-chain gates use (see `gate::apply_verification`).
fn quota_exceeded_error(prose: String) -> StarmetalError {
    StarmetalError::PolicyViolation(format!("{}: {prose}", PolicyReason::QuotaExceeded.as_str()))
}
