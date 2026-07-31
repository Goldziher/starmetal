//! Postgres-backed content model and reference-counted garbage collection
//! (ADR-0020) for Starmetal.
//!
//! SQL is the source of truth: `sql/schema.sql` plus `sql/queries/*.sql` are
//! compiled to typed tokio-postgres access code by `scythe` (see `scythe.toml`)
//! into [`generated::queries`]. [`PostgresContentStore`] wraps those queriers and
//! a [`starmetal_core::ports::StoragePort`] to implement
//! [`starmetal_core::content::ContentStore`].

pub mod generated;
mod pool;
mod store;

pub use pool::{DbPool, create_pool};
pub use store::{PostgresContentStore, SCHEMA_SQL};
