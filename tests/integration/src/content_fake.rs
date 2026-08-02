//! An in-memory [`ContentBrowse`] fake for exercising the ADR-0022 browse route and its
//! authorization predicate push-down over HTTP without a Postgres content store (the real
//! store, and its own testcontainer coverage, land in milestone M5).
//!
//! It holds a fixed component set and filters it through the *real*
//! [`QueryPredicate::evaluate`](starmetal_core::authz::QueryPredicate::evaluate) that an
//! [`Authorizer`](starmetal_core::authz::Authorizer) decision carries — so the pushed-down
//! authorization filter is exercised end to end and the fake never re-implements predicate
//! matching — then paginates deterministically.

use async_trait::async_trait;
use starmetal_core::authz::{ContentContext, Coordinate, QueryPredicate};
use starmetal_core::content::{BrowsePage, Component, ContentBrowse};
use starmetal_core::error::Result;

/// A [`ContentBrowse`] backed by an in-memory component list.
#[derive(Debug, Clone, Default)]
pub struct ContentBrowseFake {
    components: Vec<Component>,
}

impl ContentBrowseFake {
    /// Build a fake seeded with `components`, returned in the given order before pagination.
    pub fn new(components: Vec<Component>) -> Self {
        Self { components }
    }
}

#[async_trait]
impl ContentBrowse for ContentBrowseFake {
    async fn browse_components(&self, predicate: &QueryPredicate, page: BrowsePage) -> Result<Vec<Component>> {
        let matched = self.components.iter().filter(|component| {
            let coordinate = Coordinate {
                ecosystem: component.ecosystem,
                name: component.name.clone(),
                version: Some(component.version.clone()),
            };
            let path = format!("{}/{}", component.name.as_str(), component.version);
            let context = ContentContext {
                ecosystem: component.ecosystem,
                path: &path,
                coordinate: Some(&coordinate),
            };
            predicate.evaluate(&context)
        });
        Ok(matched
            .skip(page.offset as usize)
            .take(page.limit as usize)
            .cloned()
            .collect())
    }
}
