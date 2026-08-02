//! The [`GitMirror`] port and its plain data types.
//!
//! Every type crossing this port is a `String`, [`Bytes`], or a small owned struct/enum — no
//! git-library type is exposed — so downstream ecosystem adapters (Go, Swift, Zig; later increments)
//! depend only on this seam, never on `gix`.

use bytes::Bytes;

use crate::error::Result;

/// The kind of a git reference returned by [`GitMirror::list_refs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitRefKind {
    /// A tag under `refs/tags/` (annotated or lightweight).
    Tag,
    /// A branch under `refs/heads/`.
    Branch,
}

/// A single git reference: its short name, kind, and the hex object id it points at.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitRef {
    /// The short reference name, for example `v1.0.0` or `main`.
    pub name: String,
    /// Whether this reference is a tag or a branch.
    pub kind: GitRefKind,
    /// The hex-encoded object id the reference points at (a commit for branches; a commit or tag
    /// object for tags).
    pub target: String,
}

/// The source-archive container format produced by [`GitMirror::archive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveFormat {
    /// A gzip-compressed tar archive (`.tar.gz`).
    TarGz,
    /// A zip archive (`.zip`).
    Zip,
}

/// Mirrors upstream git repositories to a local cache and reads artifacts from them.
///
/// This is the inbound git-source port of ADR-0023: it lets Starmetal treat git as an upstream
/// package source (mirror, refresh, resolve, read, archive) without any adapter touching a git
/// library directly. Implementations quarantine all git access behind this trait.
#[async_trait::async_trait]
pub trait GitMirror: Send + Sync {
    /// Ensure a fresh local mirror of `remote_url` exists.
    ///
    /// Bare-clones the remote on first call; on later calls it refreshes the mirror by fetching, but
    /// only when the existing mirror is older than the configured refresh interval (TTL-gated, like
    /// the other upstream caches). Calling it repeatedly is safe and idempotent.
    async fn ensure_mirror(&self, remote_url: &str) -> Result<()>;

    /// Enumerate the mirror's tags and branches.
    async fn list_refs(&self, remote_url: &str) -> Result<Vec<GitRef>>;

    /// Resolve a reference (tag, branch, short or full name, or hex oid) to a commit oid.
    ///
    /// Returns `Ok(None)` when the reference does not exist in the mirror.
    async fn resolve(&self, remote_url: &str, reference: &str) -> Result<Option<String>>;

    /// Read the bytes of a single file at `path` as of `reference`.
    ///
    /// Returns `Ok(None)` when the path is absent at that reference or does not name a regular file
    /// (for example, it names a directory).
    async fn read_blob(&self, remote_url: &str, reference: &str, path: &str) -> Result<Option<Bytes>>;

    /// Produce a source archive of the tree at `reference` in the requested `format`.
    ///
    /// The archive is the basis for ecosystem artifacts (Go module zip, Swift source archive, Zig
    /// tarball). Entry modification times are pinned to the commit time so repeated calls for the same
    /// commit are byte-stable.
    async fn archive(&self, remote_url: &str, reference: &str, format: ArchiveFormat) -> Result<Bytes>;
}
