//! A [`GitMirror`] implementation backed by [`gix`] (gitoxide, pure-Rust — no libgit2).
//!
//! All git access lives in this module. Every git call is synchronous (gitoxide's
//! `blocking-network-client`), so the async port methods run each operation inside
//! [`tokio::task::spawn_blocking`] to keep the async paths non-blocking.
//!
//! # Storage
//!
//! Each remote is mirrored as a bare repository under a configurable cache root, named by a Blake3
//! digest of its URL, alongside a `.stamp` marker file whose modification time records the last fetch
//! for TTL gating. The cache is a rebuildable local tier; there is no object-store snapshot or archive
//! content-addressing in this increment.
//!
//! # Archive determinism
//!
//! Archives pin every entry's modification time to the commit time and use a fixed compression level,
//! so repeated calls for the same commit produce byte-stable output (git tree traversal is already
//! deterministic).

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

use bytes::Bytes;

use crate::error::{GitMirrorError, Result};
use crate::port::{ArchiveFormat, GitMirror, GitRef, GitRefKind};

/// Fixed deflate level (0-9) for archive output; a constant keeps archives byte-stable per commit.
const ARCHIVE_COMPRESSION_LEVEL: u8 = 6;

/// Refspecs that mirror all upstream branches and tags into matching local refs.
const MIRROR_REFSPECS: [&str; 2] = ["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"];

/// A gitoxide-backed [`GitMirror`] over a local bare-repository cache.
#[derive(Debug, Clone)]
pub struct GixMirror {
    cache_root: PathBuf,
    refresh_interval: Duration,
}

impl GixMirror {
    /// Create a mirror that stores bare repositories under `cache_root` and refreshes an existing
    /// mirror only once it is older than `refresh_interval`.
    pub fn new(cache_root: impl Into<PathBuf>, refresh_interval: Duration) -> Self {
        Self {
            cache_root: cache_root.into(),
            refresh_interval,
        }
    }

    /// The last time `remote_url` was fetched, if it has ever been mirrored.
    ///
    /// Exposed for callers (and tests) that need to reason about mirror freshness without triggering a
    /// fetch.
    pub fn last_fetched(&self, remote_url: &str) -> Option<SystemTime> {
        std::fs::metadata(self.stamp_path(remote_url))
            .and_then(|metadata| metadata.modified())
            .ok()
    }

    fn slug(remote_url: &str) -> String {
        blake3::hash(remote_url.as_bytes()).to_hex().to_string()
    }

    fn mirror_dir(&self, remote_url: &str) -> PathBuf {
        self.cache_root.join(format!("{}.git", Self::slug(remote_url)))
    }

    fn stamp_path(&self, remote_url: &str) -> PathBuf {
        self.cache_root.join(format!("{}.stamp", Self::slug(remote_url)))
    }
}

#[async_trait::async_trait]
impl GitMirror for GixMirror {
    async fn ensure_mirror(&self, remote_url: &str) -> Result<()> {
        let repo_dir = self.mirror_dir(remote_url);
        let stamp = self.stamp_path(remote_url);
        let url = remote_url.to_owned();
        let interval = self.refresh_interval;
        run_blocking(move || ensure_blocking(&repo_dir, &stamp, &url, interval)).await
    }

    async fn list_refs(&self, remote_url: &str) -> Result<Vec<GitRef>> {
        let repo_dir = self.mirror_dir(remote_url);
        run_blocking(move || list_refs_blocking(&repo_dir)).await
    }

    async fn resolve(&self, remote_url: &str, reference: &str) -> Result<Option<String>> {
        let repo_dir = self.mirror_dir(remote_url);
        let reference = reference.to_owned();
        run_blocking(move || resolve_blocking(&repo_dir, &reference)).await
    }

    async fn read_blob(&self, remote_url: &str, reference: &str, path: &str) -> Result<Option<Bytes>> {
        let repo_dir = self.mirror_dir(remote_url);
        let reference = reference.to_owned();
        let path = path.to_owned();
        let bytes = run_blocking(move || read_blob_blocking(&repo_dir, &reference, &path)).await?;
        Ok(bytes.map(Bytes::from))
    }

    async fn archive(&self, remote_url: &str, reference: &str, format: ArchiveFormat) -> Result<Bytes> {
        let repo_dir = self.mirror_dir(remote_url);
        let reference = reference.to_owned();
        let bytes = run_blocking(move || archive_blocking(&repo_dir, &reference, format)).await?;
        Ok(Bytes::from(bytes))
    }
}

/// Run a blocking mirror operation off the async runtime and flatten the join failure.
async fn run_blocking<T, F>(operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(GitMirrorError::task)?
}

fn ensure_blocking(repo_dir: &Path, stamp: &Path, remote_url: &str, interval: Duration) -> Result<()> {
    if repo_dir.exists() && is_fresh(stamp, interval) {
        return Ok(());
    }
    if let Some(parent) = repo_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let repository = if repo_dir.exists() {
        gix::open(repo_dir).map_err(GitMirrorError::git)?
    } else {
        gix::init_bare(repo_dir).map_err(GitMirrorError::git)?
    };
    fetch_all(&repository, remote_url)?;
    // Truncating the stamp advances its modification time to now, recording this fetch for TTL gating.
    std::fs::write(stamp, b"")?;
    Ok(())
}

/// A mirror is fresh when its stamp exists and is younger than the refresh interval.
fn is_fresh(stamp: &Path, interval: Duration) -> bool {
    std::fs::metadata(stamp)
        .and_then(|metadata| metadata.modified())
        .map(|modified| modified.elapsed().map(|age| age < interval).unwrap_or(false))
        .unwrap_or(false)
}

fn fetch_all(repository: &gix::Repository, remote_url: &str) -> Result<()> {
    let should_interrupt = AtomicBool::new(false);
    let remote = repository
        .remote_at(remote_url)
        .map_err(GitMirrorError::git)?
        .with_refspecs(MIRROR_REFSPECS, gix::remote::Direction::Fetch)
        .map_err(GitMirrorError::git)?
        .with_fetch_tags(gix::remote::fetch::Tags::All);
    let connection = remote
        .connect(gix::remote::Direction::Fetch)
        .map_err(GitMirrorError::git)?;
    let prepared = connection
        .prepare_fetch(gix::progress::Discard, gix::remote::ref_map::Options::default())
        .map_err(GitMirrorError::git)?;
    prepared
        .receive(gix::progress::Discard, &should_interrupt)
        .map_err(GitMirrorError::git)?;
    Ok(())
}

fn open_mirror(repo_dir: &Path) -> Result<gix::Repository> {
    gix::open(repo_dir).map_err(GitMirrorError::git)
}

fn list_refs_blocking(repo_dir: &Path) -> Result<Vec<GitRef>> {
    let repository = open_mirror(repo_dir)?;
    let platform = repository.references().map_err(GitMirrorError::git)?;
    let mut refs = Vec::new();
    collect_refs(
        platform.tags().map_err(GitMirrorError::git)?,
        GitRefKind::Tag,
        &mut refs,
    )?;
    collect_refs(
        platform.local_branches().map_err(GitMirrorError::git)?,
        GitRefKind::Branch,
        &mut refs,
    )?;
    Ok(refs)
}

fn collect_refs(iter: gix::reference::iter::Iter<'_, '_>, kind: GitRefKind, refs: &mut Vec<GitRef>) -> Result<()> {
    for reference in iter {
        let reference = reference.map_err(GitMirrorError::git)?;
        refs.push(GitRef {
            name: reference.name().shorten().to_string(),
            kind,
            target: reference.id().detach().to_hex().to_string(),
        });
    }
    Ok(())
}

fn resolve_blocking(repo_dir: &Path, reference: &str) -> Result<Option<String>> {
    let repository = open_mirror(repo_dir)?;
    match resolve_commit(&repository, reference)? {
        Some(commit) => Ok(Some(commit.id.to_hex().to_string())),
        None => Ok(None),
    }
}

fn read_blob_blocking(repo_dir: &Path, reference: &str, path: &str) -> Result<Option<Vec<u8>>> {
    let repository = open_mirror(repo_dir)?;
    let commit = match resolve_commit(&repository, reference)? {
        Some(object) => object.into_commit(),
        None => return Ok(None),
    };
    let tree = commit.tree().map_err(GitMirrorError::git)?;
    let entry = match tree.lookup_entry_by_path(path).map_err(GitMirrorError::git)? {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let object = entry.object().map_err(GitMirrorError::git)?;
    if object.kind != gix::object::Kind::Blob {
        return Ok(None);
    }
    // `object.data` holds the decoded blob bytes; clone them out since the object owns a cache slot.
    Ok(Some(object.data.clone()))
}

fn archive_blocking(repo_dir: &Path, reference: &str, format: ArchiveFormat) -> Result<Vec<u8>> {
    let repository = open_mirror(repo_dir)?;
    let commit = match resolve_commit(&repository, reference)? {
        Some(object) => object.into_commit(),
        None => return Err(GitMirrorError::Git(format!("reference not found: {reference}"))),
    };
    let tree_id = commit.tree_id().map_err(GitMirrorError::git)?.detach();
    let modification_time = commit.time().map_err(GitMirrorError::git)?.seconds;
    let (stream, _index) = repository.worktree_stream(tree_id).map_err(GitMirrorError::git)?;

    let options = gix_archive::Options {
        format: archive_format(format),
        tree_prefix: None,
        modification_time,
    };
    let should_interrupt = AtomicBool::new(false);
    let mut out = std::io::Cursor::new(Vec::new());
    repository
        .worktree_archive(stream, &mut out, gix::progress::Discard, &should_interrupt, options)
        .map_err(GitMirrorError::git)?;
    Ok(out.into_inner())
}

fn archive_format(format: ArchiveFormat) -> gix_archive::Format {
    let compression_level = Some(ARCHIVE_COMPRESSION_LEVEL);
    match format {
        ArchiveFormat::TarGz => gix_archive::Format::TarGz { compression_level },
        ArchiveFormat::Zip => gix_archive::Format::Zip { compression_level },
    }
}

/// Resolve `reference` (tag, branch, name, or oid) to its commit object, or `None` if it is unknown.
fn resolve_commit<'repo>(repository: &'repo gix::Repository, reference: &str) -> Result<Option<gix::Object<'repo>>> {
    let id = match repository.rev_parse_single(reference) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };
    let commit = repository
        .find_object(id)
        .map_err(GitMirrorError::git)?
        .peel_to_kind(gix::object::Kind::Commit)
        .map_err(GitMirrorError::git)?;
    Ok(Some(commit))
}
