//! Framework-free domain types and port traits for the Starmetal dependency-update engine.
//!
//! This crate mirrors `starmetal-core`'s role for the update engine: it defines the
//! shared vocabulary (dependencies, updates, configuration) and the port traits
//! ([`ports::Manager`], [`ports::Versioning`], [`ports::Datasource`], [`ports::Forge`])
//! that adapter crates implement. It must stay free of framework and I/O dependencies.

pub mod config;
pub mod dependency;
pub mod error;
pub mod ports;
pub mod update;

pub use config::UpdateConfig;
pub use dependency::{DepType, Dependency, PackageFile};
pub use error::{Result, UpdateError};
pub use ports::{
    Datasource, FileEdit, Forge, Manager, PullRequestOutcome, PullRequestRequest, Release, RepoRef, Versioning,
};
pub use update::{DependencyUpdate, RangeStrategy, UpdateType};
