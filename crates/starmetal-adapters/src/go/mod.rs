//! Go module proxy (GOPROXY protocol) adapter (ADR-0023).
//!
//! Serves `go get`/`go mod download` against an upstream git repository's tags, translating git
//! refs and trees into the [GOPROXY HTTP protocol](https://go.dev/ref/mod#goproxy-protocol) through
//! the [`starmetal_git::GitMirror`] port — never through `PackageService`. Go's proxy shape (a
//! synthesized version list, `.info`/`.mod` documents, and an on-the-fly module zip) doesn't map
//! onto `PackageService`'s fetch/verify/cache pipeline the other eight adapters share, so this
//! adapter reads straight from the git mirror (itself a local, TTL-refreshed cache) instead.
//!
//! # Routes
//!
//! Mounted at the repository's own name (`/go` by default), matching every other adapter:
//!
//! - `GET /{module}/@v/list`
//! - `GET /{module}/@v/{version}.info`
//! - `GET /{module}/@v/{version}.mod`
//! - `GET /{module}/@v/{version}.zip`
//! - `GET /{module}/@latest`
//!
//! `{module}` is the GOPROXY-escaped module path (uppercase letters as `!lowercase`, per
//! `module.EscapePath`); axum's catch-all route captures the whole remaining path and
//! [`models::split_goproxy_path`] locates the rightmost `/@v/` (a module path element never
//! contains `@`, so this is unambiguous).
//!
//! # Scope
//!
//! In scope: tagged semantic-version releases of a module whose root is the mapped repository's
//! root, with `go.mod` at that root (or synthesized as `module <path>\n` when absent, per Go's rule
//! for pre-module repositories).
//!
//! Out of scope for this increment (see [`upstream`] for the module -> git URL mapping and
//! [`upstream::build_module_zip`] for the zip-construction coverage):
//!
//! - Pseudo-versions (untagged commits) and the `+incompatible` suffix.
//! - Nested/subdirectory modules and major-version subdirectories (`/v2`).
//! - Vanity import (`<meta name="go-import">`) resolution.
//! - The checksum database (`GONOSUMDB`/`sumdb`) and `.info`/`.mod`/`.zip` hash endpoints.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use starmetal_core::config::Config;
use starmetal_core::error::StarmetalError;
use starmetal_git::{GitMirror, GitRefKind};

use self::models::{
    GoModuleInfo, GoproxyRequest, compare_go_versions, is_valid_go_version, split_goproxy_path, unescape_module_path,
};
use self::upstream::{
    archive_zip, build_module_zip, commit_time, ensure_mirror, list_refs, module_to_git_url, read_blob,
};

/// State a caller must expose to mount the Go module proxy router.
pub trait HasGoState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn git_mirror(&self) -> &Arc<dyn GitMirror>;
}

/// Build the GOPROXY router. A single catch-all route because the module path's segment count is
/// unbounded; [`models::split_goproxy_path`] does the actual routing inside [`dispatch`].
pub fn router<S: HasGoState>() -> Router<S> {
    Router::new().route("/{*rest}", get(dispatch::<S>))
}

async fn dispatch<S: HasGoState>(
    State(state): State<S>,
    Path(rest): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let (escaped_module, request) =
        split_goproxy_path(&rest).ok_or_else(|| (StatusCode::NOT_FOUND, "unrecognized GOPROXY path".to_string()))?;
    let module_path = unescape_module_path(escaped_module).map_err(|err| map_error(&err))?;
    let git_url =
        module_to_git_url(&module_path, &state.config().go.module_overrides).map_err(|err| map_error(&err))?;
    let mirror = state.git_mirror().as_ref();
    ensure_mirror(mirror, &git_url).await.map_err(|err| map_error(&err))?;

    match request {
        GoproxyRequest::List => list(mirror, &git_url).await,
        GoproxyRequest::Info(version) => info(mirror, &module_path, &git_url, &version).await,
        GoproxyRequest::Mod(version) => go_mod(mirror, &module_path, &git_url, &version).await,
        GoproxyRequest::Zip(version) => zip(mirror, &module_path, &git_url, &version).await,
        GoproxyRequest::Latest => latest(mirror, &module_path, &git_url).await,
    }
}

/// The module's tagged semver versions, ascending, from the mirror's tag refs.
async fn valid_versions(mirror: &dyn GitMirror, git_url: &str) -> Result<Vec<String>, StarmetalError> {
    let refs = list_refs(mirror, git_url)
        .await
        .map_err(|err| StarmetalError::Upstream(err.to_string()))?;
    let mut versions: Vec<String> = refs
        .into_iter()
        .filter(|reference| reference.kind == GitRefKind::Tag && is_valid_go_version(&reference.name))
        .map(|reference| reference.name)
        .collect();
    versions.sort_by(|a, b| compare_go_versions(a, b));
    Ok(versions)
}

async fn list(mirror: &dyn GitMirror, git_url: &str) -> Result<Response, (StatusCode, String)> {
    let versions = valid_versions(mirror, git_url).await.map_err(|err| map_error(&err))?;
    let body = if versions.is_empty() {
        String::new()
    } else {
        format!("{}\n", versions.join("\n"))
    };
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response())
}

/// Build the `.info` document for `version`, verifying it is one of the module's tagged semver
/// releases and resolving its commit time. Shared by the `.info` and `@latest` handlers.
async fn module_info(
    mirror: &dyn GitMirror,
    module_path: &str,
    git_url: &str,
    version: &str,
) -> Result<GoModuleInfo, (StatusCode, String)> {
    if !is_valid_go_version(version) {
        return Err(not_found(module_path, version));
    }
    let versions = valid_versions(mirror, git_url).await.map_err(|err| map_error(&err))?;
    if !versions.iter().any(|candidate| candidate == version) {
        return Err(not_found(module_path, version));
    }
    let seconds = commit_time(mirror, git_url, version)
        .await
        .map_err(|err| map_error(&err))?
        .ok_or_else(|| not_found(module_path, version))?;
    Ok(GoModuleInfo {
        version: version.to_string(),
        time: format_rfc3339(seconds),
    })
}

async fn info(
    mirror: &dyn GitMirror,
    module_path: &str,
    git_url: &str,
    version: &str,
) -> Result<Response, (StatusCode, String)> {
    let info = module_info(mirror, module_path, git_url, version).await?;
    json_response(&info)
}

async fn latest(mirror: &dyn GitMirror, module_path: &str, git_url: &str) -> Result<Response, (StatusCode, String)> {
    let versions = valid_versions(mirror, git_url).await.map_err(|err| map_error(&err))?;
    let version = versions.last().cloned().ok_or_else(|| {
        map_error(&StarmetalError::PackageNotFound {
            ecosystem: "go".to_string(),
            name: module_path.to_string(),
        })
    })?;
    let info = module_info(mirror, module_path, git_url, &version).await?;
    json_response(&info)
}

async fn go_mod(
    mirror: &dyn GitMirror,
    module_path: &str,
    git_url: &str,
    version: &str,
) -> Result<Response, (StatusCode, String)> {
    ensure_known_version(mirror, module_path, git_url, version).await?;
    let contents = match read_blob(mirror, git_url, version, "go.mod")
        .await
        .map_err(|err| map_error(&err))?
    {
        Some(bytes) => bytes,
        // Go's rule for a repository with no go.mod: synthesize a minimal one naming the module.
        None => Bytes::from(format!("module {module_path}\n")),
    };
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        Body::from(contents),
    )
        .into_response())
}

async fn zip(
    mirror: &dyn GitMirror,
    module_path: &str,
    git_url: &str,
    version: &str,
) -> Result<Response, (StatusCode, String)> {
    ensure_known_version(mirror, module_path, git_url, version).await?;
    let source = archive_zip(mirror, git_url, version)
        .await
        .map_err(|err| map_error(&err))?;
    let module_zip = build_module_zip(module_path, version, &source).map_err(|err| map_error(&err))?;
    Ok(([(header::CONTENT_TYPE, "application/zip")], Body::from(module_zip)).into_response())
}

/// Reject a version that is not a valid, tagged semver release of the module before doing any
/// further (potentially expensive) work for it.
async fn ensure_known_version(
    mirror: &dyn GitMirror,
    module_path: &str,
    git_url: &str,
    version: &str,
) -> Result<(), (StatusCode, String)> {
    if !is_valid_go_version(version) {
        return Err(not_found(module_path, version));
    }
    let versions = valid_versions(mirror, git_url).await.map_err(|err| map_error(&err))?;
    if versions.iter().any(|candidate| candidate == version) {
        Ok(())
    } else {
        Err(not_found(module_path, version))
    }
}

fn not_found(module_path: &str, version: &str) -> (StatusCode, String) {
    map_error(&StarmetalError::VersionNotFound {
        ecosystem: "go".to_string(),
        name: module_path.to_string(),
        version: version.to_string(),
    })
}

fn json_response(info: &GoModuleInfo) -> Result<Response, (StatusCode, String)> {
    let body = serde_json::to_vec(info).map_err(|err| map_error(&StarmetalError::from(err)))?;
    Ok(([(header::CONTENT_TYPE, "application/json")], Body::from(body)).into_response())
}

/// Format a Unix-seconds timestamp as RFC 3339 (`2023-01-02T03:04:05Z`), as Go's `@v/*.info`
/// document requires for its `Time` field.
fn format_rfc3339(seconds: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
        .map(|datetime| datetime.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn map_error(err: &StarmetalError) -> (StatusCode, String) {
    tracing::warn!(error = %err, "Go module proxy request failed");
    crate::map_public_error(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_seconds_as_rfc3339() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
