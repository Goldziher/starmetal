//! Retention engine (ADR-0020 Stage 2c): deletes component rows selected by a
//! [`RetentionPolicy`], letting reference-counted garbage collection reclaim any blobs that
//! become unreferenced as a result.
//!
//! ## Deletion model
//!
//! Retention is evaluated per `(ecosystem, namespace, name)` component family. Each
//! [`RetentionRule`] in the policy is evaluated **independently** against the full set of
//! versions for that family, and *selects the versions it wants deleted* (not the versions to
//! keep). [`apply_retention`](PostgresContentStore::apply_retention) deletes the **union** of
//! every rule's selection — a version survives only when *no* rule selects it. Adding more rules
//! to a policy can therefore only delete more versions, never fewer; there is no rule-priority or
//! "first match wins" semantics, and rules do not interact.
//!
//! Deleting a component row cascades (`ON DELETE CASCADE`) to its assets and `asset_blobs` rows,
//! dropping the references those assets held on their blobs. This module does not reclaim blob
//! bytes itself — a blob left unreferenced by a deletion becomes a candidate for the
//! reference-counted garbage-collection sweep in [`crate::gc`].
//!
//! ## Prerelease detection
//!
//! [`RetentionRule::IsPrerelease`] uses a simple, ecosystem-agnostic heuristic: a version string
//! is treated as a prerelease if it contains a `-` character, following the semver convention of
//! `<version-core>-<pre-release>`. This crate deliberately does not depend on
//! `starmetal-versioning` for this: that crate's prerelease detection
//! (`SemverVersioning::is_stable`) is wired up per-ecosystem via `for_ecosystem`, which today only
//! resolves for `Ecosystem::Cargo` — every other ecosystem gets `None` and the check would
//! silently do nothing. The heuristic here applies uniformly across every ecosystem instead.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use regex::Regex;
use starmetal_core::content::{RetentionPolicy, RetentionRule};
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::{Ecosystem, PackageName};

use crate::generated::queries;
use crate::store::{PostgresContentStore, db_error};

/// The character that separates a version core from its pre-release identifier, per the semver
/// convention this crate's prerelease heuristic relies on (see the module docs).
const PRERELEASE_SEPARATOR: char = '-';

/// The outcome of applying a [`RetentionPolicy`]: the versions it deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionOutcome {
    /// Version strings that were deleted, in no particular order.
    pub deleted: Vec<String>,
}

/// One component-version row loaded for retention evaluation.
struct VersionRow {
    id: i64,
    version: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_downloaded_at: Option<DateTime<Utc>>,
}

impl PostgresContentStore {
    /// Apply `policy` to every version of the `(ecosystem, namespace, name)` component family,
    /// deleting the union of what each rule in the policy selects for deletion.
    ///
    /// See the module docs for the deletion model and the [`RetentionRule::IsPrerelease`]
    /// heuristic. `namespace` is `None` for ecosystems with no namespace concept, matching
    /// [`starmetal_core::content::Component::namespace`]. Returns the version strings that were
    /// deleted.
    ///
    /// # Errors
    ///
    /// Returns [`StarmetalError::Storage`] on a database failure, or [`StarmetalError::Config`]
    /// if a [`RetentionRule::MatchesRegex`] pattern fails to compile.
    pub async fn apply_retention(
        &self,
        policy: &RetentionPolicy,
        ecosystem: Ecosystem,
        namespace: Option<&str>,
        name: &PackageName,
    ) -> Result<RetentionOutcome> {
        let conn = self.conn().await?;
        let namespace = namespace.unwrap_or("");
        let rows = queries::list_component_versions(&*conn, &ecosystem.to_string(), namespace, name.as_str())
            .await
            .map_err(db_error)?;

        let versions: Vec<VersionRow> = rows
            .into_iter()
            .map(|row| VersionRow {
                id: row.id,
                version: row.version,
                created_at: row.created_at,
                updated_at: row.updated_at,
                last_downloaded_at: row.last_downloaded_at,
            })
            .collect();

        let mut selected_ids: HashSet<i64> = HashSet::new();
        for rule in &policy.rules {
            for id in select_for_deletion(rule, &versions)? {
                selected_ids.insert(id);
            }
        }

        let mut deleted = Vec::with_capacity(selected_ids.len());
        for row in &versions {
            if selected_ids.contains(&row.id) {
                queries::delete_component(&*conn, row.id).await.map_err(db_error)?;
                deleted.push(row.version.clone());
            }
        }

        Ok(RetentionOutcome { deleted })
    }
}

/// Evaluate a single [`RetentionRule`] against the loaded versions, returning the component ids
/// it selects for deletion.
fn select_for_deletion(rule: &RetentionRule, versions: &[VersionRow]) -> Result<Vec<i64>> {
    match rule {
        RetentionRule::KeepLatest { count } => {
            let mut by_recency: Vec<&VersionRow> = versions.iter().collect();
            by_recency.sort_by_key(|row| std::cmp::Reverse(row.created_at));
            Ok(by_recency.into_iter().skip(*count).map(|row| row.id).collect())
        }
        RetentionRule::IsPrerelease { prerelease } => Ok(versions
            .iter()
            .filter(|row| is_prerelease(&row.version) == *prerelease)
            .map(|row| row.id)
            .collect()),
        RetentionRule::MatchesRegex { pattern } => {
            let regex = Regex::new(pattern)
                .map_err(|error| StarmetalError::Config(format!("invalid retention regex {pattern:?}: {error}")))?;
            Ok(versions
                .iter()
                .filter(|row| regex.is_match(&row.version))
                .map(|row| row.id)
                .collect())
        }
        RetentionRule::LastUpdated { within_days } => {
            let cutoff = Utc::now() - chrono::Duration::days(i64::from(*within_days));
            Ok(versions
                .iter()
                .filter(|row| row.updated_at < cutoff)
                .map(|row| row.id)
                .collect())
        }
        RetentionRule::LastDownloaded { within_days } => {
            let cutoff = Utc::now() - chrono::Duration::days(i64::from(*within_days));
            Ok(versions
                .iter()
                .filter(|row| {
                    row.last_downloaded_at
                        .is_none_or(|downloaded_at| downloaded_at < cutoff)
                })
                .map(|row| row.id)
                .collect())
        }
    }
}

/// Ecosystem-agnostic prerelease heuristic (see module docs): a version is a prerelease when it
/// contains a [`PRERELEASE_SEPARATOR`].
fn is_prerelease(version: &str) -> bool {
    version.contains(PRERELEASE_SEPARATOR)
}
