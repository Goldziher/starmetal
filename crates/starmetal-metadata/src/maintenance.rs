//! Scheduled metadata maintenance (ADR-0020 Stages 2c/2d): composes the retention engine and the
//! garbage-collection sweep over a shared [`PostgresContentStore`] into the core
//! [`ContentMaintenance`] port, so a runtime scheduler can drive both lifecycles with a single
//! handle.

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
pub struct MetadataMaintenance {
    store: Arc<PostgresContentStore>,
    /// Grace window applied to every blob newly soft-deleted by a GC sweep, mirroring
    /// [`crate::gc::GcConfig::grace`].
    grace: Duration,
    /// The retention policy applied to every known component family on each retention sweep. An
    /// empty policy (`rules` is empty) is a no-op.
    retention: RetentionPolicy,
}

impl MetadataMaintenance {
    /// Build a maintenance handle over a shared content store, the GC grace window, and the
    /// retention policy to apply on each sweep.
    pub fn new(store: Arc<PostgresContentStore>, grace: Duration, retention: RetentionPolicy) -> Self {
        Self {
            store,
            grace,
            retention,
        }
    }
}

#[async_trait]
impl ContentMaintenance for MetadataMaintenance {
    async fn gc_sweep(&self) -> Result<GcReport> {
        run_gc_sweep(&*self.store, &GcConfig { grace: self.grace }).await
    }

    async fn retention_sweep(&self) -> Result<RetentionOutcome> {
        // An empty policy selects nothing in every family, so skip the family listing entirely.
        if self.retention.rules.is_empty() {
            return Ok(RetentionOutcome { deleted: Vec::new() });
        }

        let families = {
            let conn = self.store.conn().await?;
            queries::list_component_families(&*conn).await.map_err(db_error)?
        };

        let mut deleted = Vec::new();
        for family in families {
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
            let outcome = self
                .store
                .apply_retention(&self.retention, ecosystem, namespace, &name)
                .await?;
            deleted.extend(outcome.deleted);
        }

        Ok(RetentionOutcome { deleted })
    }
}
