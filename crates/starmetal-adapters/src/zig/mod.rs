//! Zig source-tarball proxy (ADR-0023).
//!
//! `zig fetch <url>` has no package-index protocol to speak: it downloads a tarball (or git
//! bundle) of a package's source and hashes it client-side. Like the Go module proxy, this
//! ecosystem's git remote is derived per-request rather than configured as a single upstream host,
//! so this adapter reads straight from the [`starmetal_git::GitMirror`] port — never through
//! `PackageService` — mirroring `starmetal_adapters::go`'s architecture.
//!
//! # Routes
//!
//! Mounted at the repository's own name (`/zig` by default):
//!
//! - `GET /{host}/{user}/{repo}/{ref}.tar.gz`
//!
//! `{host}/{user}/{repo}` resolves to a git remote the same way the Go module proxy resolves a
//! module path (see [`upstream`]), and `{ref}` must name one of that repository's tags.
//!
//! # Tarball layout
//!
//! The archive `starmetal-git` produces has no top-level directory prefix (every entry sits at the
//! tree root). This is served as-is: empirical testing against the real `zig` 0.16 toolchain
//! (`zig fetch --debug-hash <url>`) confirmed it accepts a root-level tarball directly — `zig fetch`
//! only strips a *single* leading directory component when the tarball root itself contains
//! exactly one entry, and treats a tarball with several root-level entries (as this one always has:
//! at minimum `build.zig.zon` and `build.zig`) as already-flat. No re-prefixing step is needed,
//! unlike the Go module proxy's zip construction (which must re-prefix every entry to satisfy
//! `golang.org/x/mod/zip`'s format).
//!
//! # Scope
//!
//! In scope: a tagged ref of a repository whose package sources live at that repository's root,
//! served as a plain gzip-compressed tarball.
//!
//! Out of scope for this increment:
//!
//! - `git+https`/`git+http` direct fetch (Zig's other supported URL form) — only the tarball form
//!   is served.
//! - `build.zig.zon` dependency-graph resolution or transitive fetch of a package's own
//!   dependencies.
//! - Server-side package-hash verification — `zig fetch` computes and verifies the hash itself,
//!   client-side, exactly as it would for any other tarball URL.
//! - Multi-package repositories (a repository whose Zig package does not live at its root).
//! - Untagged refs (arbitrary branches or commits) — only tags are resolved (see
//!   [`ensure_known_tag`]).

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use starmetal_core::config::Config;
use starmetal_core::error::StarmetalError;
use starmetal_git::{GitMirror, GitRefKind};

use self::models::split_zig_path;
use self::upstream::{archive_tar_gz, ensure_mirror, list_refs, resolve_repo_url};

/// State a caller must expose to mount the Zig tarball proxy router.
pub trait HasZigState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn git_mirror(&self) -> &Arc<dyn GitMirror>;
}

/// Build the Zig tarball proxy router. A single catch-all route because the repository path's
/// segment count is unbounded (an override may map an arbitrarily deep path); [`split_zig_path`]
/// does the actual routing inside [`dispatch`].
pub fn router<S: HasZigState>() -> Router<S> {
    Router::new().route("/{*rest}", get(dispatch::<S>))
}

async fn dispatch<S: HasZigState>(
    State(state): State<S>,
    Path(rest): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let (repo_path, reference) =
        split_zig_path(&rest).ok_or_else(|| (StatusCode::NOT_FOUND, "unrecognized zig tarball path".to_string()))?;
    let git_url = resolve_repo_url(repo_path, &state.config().zig.repo_overrides).map_err(|err| map_error(&err))?;
    let mirror = state.git_mirror().as_ref();
    ensure_mirror(mirror, &git_url).await.map_err(|err| map_error(&err))?;
    ensure_known_tag(mirror, repo_path, &git_url, reference).await?;

    let archive = archive_tar_gz(mirror, &git_url, reference)
        .await
        .map_err(|err| map_error(&err))?;
    let max_bytes = state.config().zig.max_archive_bytes;
    if archive.len() as u64 > max_bytes {
        return Err(map_error(&StarmetalError::Upstream(format!(
            "zig archive for '{repo_path}@{reference}' ({} bytes) exceeded configured max_archive_bytes \
             ({max_bytes})",
            archive.len()
        ))));
    }

    Ok(([(header::CONTENT_TYPE, "application/gzip")], Body::from(archive)).into_response())
}

/// Reject a ref that is not one of the repository's tags before doing any further (potentially
/// expensive) work for it — only tagged refs are in scope for this increment.
async fn ensure_known_tag(
    mirror: &dyn GitMirror,
    repo_path: &str,
    git_url: &str,
    reference: &str,
) -> Result<(), (StatusCode, String)> {
    let refs = list_refs(mirror, git_url).await.map_err(|err| map_error(&err))?;
    if refs
        .iter()
        .any(|candidate| candidate.kind == GitRefKind::Tag && candidate.name == reference)
    {
        Ok(())
    } else {
        Err(map_error(&StarmetalError::VersionNotFound {
            ecosystem: "zig".to_string(),
            name: repo_path.to_string(),
            version: reference.to_string(),
        }))
    }
}

fn map_error(err: &StarmetalError) -> (StatusCode, String) {
    tracing::warn!(error = %err, "Zig tarball proxy request failed");
    crate::map_public_error(err)
}
