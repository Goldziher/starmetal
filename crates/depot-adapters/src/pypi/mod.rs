//! PyPI protocol adapter implementing PEP 503/691 Simple Repository API.
//!
//! Provides an axum router that translates PEP 503 HTTP requests into
//! `PackageService` trait calls, and an upstream client for fetching
//! packages from pypi.org or any PEP 691-compatible registry.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::PackageService;

use self::upstream::PypiUpstreamClient;

/// Trait for extracting PyPI-specific state from application state.
///
/// The server crate implements this on its `AppState` to bridge the adapter
/// to the service layer and upstream client without creating a circular dependency.
pub trait HasPypiState: Clone + Send + Sync + 'static {
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn pypi_upstream(&self) -> &Arc<PypiUpstreamClient>;
}

/// Build the PyPI adapter router.
///
/// Mount this under `/pypi` in the top-level application router.
pub fn router<S: HasPypiState>() -> Router<S> {
    Router::new()
        .route("/simple/", get(simple_index::<S>))
        .route("/simple/{project}/", get(simple_project::<S>))
        .route("/simple/{project}", get(redirect_with_slash))
        .route(
            "/packages/{name}/{version}/{filename}",
            get(download_artifact::<S>),
        )
}

/// GET /simple/{project} (without trailing slash) -- redirect to canonical URL.
///
/// pip may request `/simple/requests` without a trailing slash. PEP 503 requires
/// the canonical form to have a trailing slash, so we issue a permanent redirect.
async fn redirect_with_slash(Path(project): Path<String>) -> impl IntoResponse {
    axum::response::Redirect::permanent(&format!("/pypi/simple/{project}/"))
}

/// GET /simple/ -- list all cached PyPI packages.
async fn simple_index<S: HasPypiState>(
    State(state): State<S>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let packages = state
        .package_service()
        .list_packages(Ecosystem::PyPI)
        .await
        .map_err(|err| map_error(&err))?;

    let format =
        models::negotiate_format(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));

    match format {
        models::PypiFormat::Html => {
            let html = models::render_index_html(&packages);
            Ok(([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response())
        }
        models::PypiFormat::Json => {
            let index = models::build_json_index(&packages);
            let body = serde_json::to_string(&index)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            Ok((
                [(header::CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")],
                body,
            )
                .into_response())
        }
    }
}

/// GET /simple/{project}/ -- list all files for a project.
///
/// Triggers the caching lifecycle through `PackageService`, then serves
/// the full upstream project (preserving requires-python, yanked reasons, etc.)
/// with file URLs rewritten to point through this depot instance.
async fn simple_project<S: HasPypiState>(
    State(state): State<S>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let name = PackageName::new(project);
    let name = PackageName::new(name.normalized(Ecosystem::PyPI).into_owned());
    let service = state.package_service();

    // Storage is the source of truth — check there first
    let mut project: depot_core::registry::pypi::PypiProject = if let Some(raw) = service
        .get_raw_upstream(Ecosystem::PyPI, &name)
        .await
        .map_err(|err| map_error(&err))?
    {
        serde_json::from_slice(&raw)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        // Cache miss — fetch from upstream
        let _versions = service
            .list_versions(Ecosystem::PyPI, &name)
            .await
            .map_err(|err| map_error(&err))?;

        let upstream_project = state
            .pypi_upstream()
            .get_cached_project(&name)
            .await
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "project not cached after upstream fetch".to_string(),
                )
            })?;

        // Persist to storage — this is now depot's data
        if let Ok(raw) = serde_json::to_vec(&upstream_project) {
            let _ = service
                .put_raw_upstream(Ecosystem::PyPI, &name, bytes::Bytes::from(raw))
                .await;
        }

        upstream_project
    };

    // Rewrite file URLs to point through depot
    models::rewrite_project_file_urls(&mut project);

    let format =
        models::negotiate_format(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()));

    match format {
        models::PypiFormat::Html => {
            let html = models::render_project_html_from_upstream(&project);
            Ok(([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response())
        }
        models::PypiFormat::Json => {
            let body = serde_json::to_string(&project)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            Ok((
                [(header::CONTENT_TYPE, "application/vnd.pypi.simple.v1+json")],
                body,
            )
                .into_response())
        }
    }
}

/// GET /packages/{name}/{version}/{filename} -- download an artifact.
async fn download_artifact<S: HasPypiState>(
    State(state): State<S>,
    Path((name, version, filename)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let pkg_name = PackageName::new(name);
    let pkg_name = PackageName::new(pkg_name.normalized(Ecosystem::PyPI).into_owned());

    let artifact_id = ArtifactId {
        ecosystem: Ecosystem::PyPI,
        name: pkg_name,
        version,
        filename: filename.clone(),
    };

    let data = state
        .package_service()
        .get_artifact(&artifact_id)
        .await
        .map_err(|err| map_error(&err))?;

    let disposition = format!("attachment; filename=\"{filename}\"");
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        data,
    ))
}

/// Map `DepotError` variants to appropriate HTTP status codes.
fn map_error(err: &DepotError) -> (StatusCode, String) {
    match err {
        DepotError::PackageNotFound { .. }
        | DepotError::VersionNotFound { .. }
        | DepotError::ArtifactNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        DepotError::PolicyViolation(_) => (StatusCode::FORBIDDEN, err.to_string()),
        DepotError::Upstream(_) => (StatusCode::BAD_GATEWAY, err.to_string()),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}
