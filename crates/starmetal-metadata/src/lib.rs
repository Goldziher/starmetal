//! Postgres-backed content model and reference-counted garbage collection
//! (ADR-0020) for Starmetal.
//!
//! SQL is the source of truth: `sql/schema.sql` plus `sql/queries/*.sql` are
//! compiled to typed tokio-postgres access code by `scythe` (see `scythe.toml`)
//! into [`generated::queries`]. [`PostgresContentStore`] wraps those queriers and
//! a [`starmetal_core::ports::StoragePort`] to implement
//! [`starmetal_core::content::ContentStore`].

pub mod gc;
pub mod generated;
pub mod maintenance;
mod pool;
pub mod retention;
mod store;

pub use gc::{GcConfig, run_gc_sweep};
pub use maintenance::MetadataMaintenance;
pub use pool::{DbPool, create_pool};
pub use starmetal_core::content::{GcReport, RetentionOutcome};
pub use store::{PostgresContentStore, SCHEMA_SQL};
