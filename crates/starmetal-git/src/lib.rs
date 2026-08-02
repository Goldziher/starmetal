//! Git-as-a-dependency-source foundation for Starmetal (ADR-0023).
//!
//! This crate defines the inbound [`GitMirror`] port — mirror an upstream git repository, keep it
//! fresh, resolve refs, read blobs, and produce source archives — and a `gix`-backed implementation
//! behind the `gix-backend` feature. All git-library access is quarantined here, exactly as ADR-0017
//! quarantines the outbound forge client: the framework-free core and the update crates never see a
//! git dependency.
//!
//! # Scope
//!
//! This is the mirror-and-read substrate only. The Go, Swift, and Zig ecosystem adapters that consume
//! it — translating tags into module zips, source archives, and tarballs — are later increments and
//! are intentionally absent here. Nothing in the crate is wired into the server yet.
//!
//! # Feature flags
//!
//! - `gix-backend` (off by default): compiles [`GixMirror`] and pulls in the `gix` git dependency.
//!   With the feature off, only the port trait and its plain types are available, so the workspace
//!   builds without any git library.
//!
//! # Example port
//!
//! The seam carries only `String`, [`bytes::Bytes`], and small owned structs — never a `gix` type —
//! so downstream adapters depend on [`GitMirror`], not on the implementation.

#![forbid(unsafe_code)]

mod error;
mod port;

#[cfg(feature = "gix-backend")]
mod gix_backend;

pub use error::{GitMirrorError, Result};
pub use port::{ArchiveFormat, GitMirror, GitRef, GitRefKind};

#[cfg(feature = "gix-backend")]
pub use gix_backend::GixMirror;
