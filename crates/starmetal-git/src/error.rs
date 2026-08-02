//! Error type for the git-mirror port.
//!
//! External git-library and I/O errors are converted into [`GitMirrorError`] at the crate boundary so
//! no `gix` type ever leaks across the [`GitMirror`](crate::GitMirror) port.

#[cfg(feature = "gix-backend")]
use std::fmt::Display;

/// Errors produced while mirroring or reading from an upstream git repository.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GitMirrorError {
    /// A local filesystem operation on the mirror cache failed.
    #[error("mirror I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// An underlying git operation (clone, fetch, ref resolution, object read, archive) failed.
    ///
    /// The source error is flattened to a string so the concrete `gix` error types stay confined to
    /// the implementation and never appear in this crate's public API.
    #[error("git operation failed: {0}")]
    Git(String),

    /// A blocking mirror task could not be joined (for example, it panicked).
    #[error("mirror task failed: {0}")]
    Task(String),
}

#[cfg(feature = "gix-backend")]
impl GitMirrorError {
    /// Wrap a git-library error as a [`GitMirrorError::Git`] at the boundary.
    pub(crate) fn git(source: impl Display) -> Self {
        Self::Git(source.to_string())
    }

    /// Wrap a task-join failure as a [`GitMirrorError::Task`].
    pub(crate) fn task(source: impl Display) -> Self {
        Self::Task(source.to_string())
    }
}

/// Convenience result alias for git-mirror operations.
pub type Result<T> = std::result::Result<T, GitMirrorError>;
