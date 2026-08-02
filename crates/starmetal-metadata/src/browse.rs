//! [`ContentBrowse`] over Postgres: list components through a pushed-down [`QueryPredicate`]
//! (ADR-0022 selector push-down).
//!
//! The predicate is compiled to a parameterized `WHERE` by [`crate::predicate_sql`] and executed as
//! a single dynamic query, so authorization filtering happens in the database rather than in memory.

use async_trait::async_trait;
use starmetal_core::authz::QueryPredicate;
use starmetal_core::content::{BrowsePage, Component, ContentBrowse};
use starmetal_core::error::Result;
use starmetal_core::package::{Ecosystem, PackageName};
use tokio_postgres::Row;
use tokio_postgres::types::ToSql;

use crate::predicate_sql::compile;
use crate::store::{PostgresContentStore, db_error};

#[async_trait]
impl ContentBrowse for PostgresContentStore {
    async fn browse_components(&self, predicate: &QueryPredicate, page: BrowsePage) -> Result<Vec<Component>> {
        let compiled = compile(predicate);
        let limit = i64::from(page.limit);
        let offset = i64::from(page.offset);
        // LIMIT/OFFSET placeholders continue numbering after the predicate's parameters.
        let limit_placeholder = compiled.params.len() + 1;
        let offset_placeholder = compiled.params.len() + 2;
        let sql = format!(
            "SELECT ecosystem, namespace, name, version, repository, attributes FROM components WHERE {} \
             ORDER BY ecosystem, namespace, name, version LIMIT ${limit_placeholder} OFFSET ${offset_placeholder}",
            compiled.sql,
        );

        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(compiled.params.len() + 2);
        for value in &compiled.params {
            params.push(value);
        }
        params.push(&limit);
        params.push(&offset);

        let conn = self.conn().await?;
        let rows = conn.query(&sql, &params).await.map_err(db_error)?;
        rows.iter().map(component_from_row).collect()
    }
}

fn component_from_row(row: &Row) -> Result<Component> {
    let ecosystem: String = row.get("ecosystem");
    let namespace: String = row.get("namespace");
    let name: String = row.get("name");
    let version: String = row.get("version");
    let repository: String = row.get("repository");
    let attributes: serde_json::Value = row.get("attributes");

    Ok(Component {
        namespace: if namespace.is_empty() { None } else { Some(namespace) },
        name: PackageName::new(name),
        version,
        ecosystem: ecosystem.parse::<Ecosystem>()?,
        repository,
        attributes,
    })
}
