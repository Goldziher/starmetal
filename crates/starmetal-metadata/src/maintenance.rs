//! Scheduled metadata maintenance (ADR-0020 Stages 2c/2d): composes the retention engine and the
//! garbage-collection sweep over a shared [`PostgresContentStore`] into the core
//! [`ContentMaintenance`] port, so a runtime scheduler can drive both lifecycles with a single
//! handle.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use starmetal_core::content::{ContentMaintenance, GcReport, RetentionOutcome, RetentionPolicy};
use starmetal_core::error::Result;
use starmetal_core::package::{Ecosystem, PackageName};

use crate::gc::{GcConfig, run_gc_sweep};
use crate::generated::queries;
use crate::store::{PostgresContentStore, db_error};

/// Composes the retention engine (Stage 2c) and the GC sweep (Stage 2d) over a shared content
/// store into one [`ContentMaintenance`] handle.
///
/// Retention is resolved per component family with precedence
/// `per_repository` > `per_ecosystem` > global `retention` (ADR-0020): each family's `repository`
/// attribution is consulted first, then its ecosystem, then the global fallback.
pub struct MetadataMaintenance {
    store: Arc<PostgresContentStore>,
    /// Grace window applied to every blob newly soft-deleted by a GC sweep, mirroring
    /// [`crate::gc::GcConfig::grace`].
    grace: Duration,
    /// The global fallback retention policy, applied to a family when neither `per_repository` nor
    /// `per_ecosystem` matches it. An empty policy (`rules` is empty) is a no-op.
    retention: RetentionPolicy,
    /// Retention policies keyed by canonical ecosystem name; a family whose ecosystem matches uses
    /// this in preference to the global `retention`.
    per_ecosystem: HashMap<String, RetentionPolicy>,
    /// Retention policies keyed by repository attribution string; a family whose repository matches
    /// uses this in preference to both `per_ecosystem` and the global `retention`.
    per_repository: HashMap<String, RetentionPolicy>,
}

impl MetadataMaintenance {
    /// Build a maintenance handle over a shared content store, the GC grace window, the global
    /// retention policy, and the per-ecosystem and per-repository retention overrides applied on
    /// each sweep (precedence: per-repository > per-ecosystem > global).
    pub fn new(
        store: Arc<PostgresContentStore>,
        grace: Duration,
        retention: RetentionPolicy,
        per_ecosystem: HashMap<String, RetentionPolicy>,
        per_repository: HashMap<String, RetentionPolicy>,
    ) -> Self {
        Self {
            store,
            grace,
            retention,
            per_ecosystem,
            per_repository,
        }
    }

    /// Resolve the retention policy for a component family, applying precedence
    /// per-repository > per-ecosystem > global.
    fn resolve_policy(&self, ecosystem: &str, repository: &str) -> &RetentionPolicy {
        self.per_repository
            .get(repository)
            .or_else(|| self.per_ecosystem.get(ecosystem))
            .unwrap_or(&self.retention)
    }
}

#[async_trait]
impl ContentMaintenance for MetadataMaintenance {
    async fn gc_sweep(&self) -> Result<GcReport> {
        run_gc_sweep(&*self.store, &GcConfig { grace: self.grace }).await
    }

    async fn retention_sweep(&self) -> Result<RetentionOutcome> {
        // With no global policy and no per-ecosystem/per-repository overrides, every family resolves
        // to an empty policy that selects nothing, so skip the family listing entirely.
        if self.retention.rules.is_empty() && self.per_ecosystem.is_empty() && self.per_repository.is_empty() {
            return Ok(RetentionOutcome { deleted: Vec::new() });
        }

        let families = {
            let conn = self.store.conn().await?;
            queries::list_component_families(&*conn).await.map_err(db_error)?
        };

        let mut deleted = Vec::new();
        for family in families {
            // Resolve before parsing so the per-ecosystem lookup uses the raw canonical string the
            // family carries (config keys are validated to be canonical ecosystem names).
            let policy = self.resolve_policy(&family.ecosystem, &family.repository);
            if policy.rules.is_empty() {
                continue;
            }
            let Ok(ecosystem) = family.ecosystem.parse::<Ecosystem>() else {
                tracing::warn!(
                    ecosystem = %family.ecosystem,
                    name = %family.name,
                    "skipping retention sweep for a component family with an unparseable ecosystem"
                );
                continue;
            };
            let namespace = if family.namespace.is_empty() {
                None
            } else {
                Some(family.namespace.as_str())
            };
            let name = PackageName::new(family.name);
            let outcome = self.store.apply_retention(policy, ecosystem, namespace, &name).await?;
            deleted.extend(outcome.deleted);
        }

        Ok(RetentionOutcome { deleted })
    }
}
