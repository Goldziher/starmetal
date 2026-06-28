//! PyPI protocol adapter implementing PEP 503/691 Simple Repository API.
//!
//! Provides an axum router that translates PEP 503 HTTP requests into
//! `PackageService` trait calls, and an upstream client for fetching
//! packages from pypi.org or any PEP 691-compatible registry.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use sha2::Digest;
use starmetal_core::config::Config;
use starmetal_core::error::StarmetalError;
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName, VersionMetadata};
use starmetal_core::ports::{PackageService, PublishingService};
use starmetal_core::publishing::{PublishRequest, PublishedArtifact, TokenScope};

use self::upstream::PypiUpstreamClient;

/// Trait for extracting PyPI-specific state from application state.
///
/// The server crate implements this on its `AppState` to bridge the adapter
/// to the service layer and upstream client without creating a circular dependency.
pub trait HasPypiState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
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
        .route("/legacy/", post(legacy_upload::<S>))
        .route(
            "/packages/{name}/{version}/{filename}",
            get(download_artifact::<S>),
        )
}

async fn legacy_upload<S: HasPypiState>(
    State(state): State<S>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_write_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "missing publishing token".to_string(),
        )
    })?;
    let mut name = None;
    let mut version = None;
    let mut license = None;
    let mut file = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?
    {
        let field_name = field.name().unwrap_or_default().to_string();
        if field_name == "content" {
            let filename = field
                .file_name()
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        "missing upload filename".to_string(),
                    )
                })?
                .to_string();
            let data = field
                .bytes()
                .await
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            file = Some((filename, data));
            continue;
        }

        let value = field
            .text()
            .await
            .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
        match field_name.as_str() {
            "name" => name = Some(value),
            "version" => version = Some(value),
            "license" => license = Some(value),
            _ => {}
        }
    }

    let name = PackageName::new(
        name.ok_or_else(|| (StatusCode::BAD_REQUEST, "missing package name".to_string()))?,
    );
    let name = PackageName::new(name.normalized(Ecosystem::PyPI).into_owned());
    authorize_publish(&state, &token, &name)?;
    let version = version.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing package version".to_string(),
        )
    })?;
    let (filename, data) = file.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing upload content".to_string(),
        )
    })?;
    let sha256 = hex::encode(sha2::Sha256::digest(&data));
    let mut upstream_hashes = ahash::AHashMap::new();
    upstream_hashes.insert("sha256".to_string(), sha256);

    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: name.clone(),
            version: version.clone(),
            license,
            yanked: false,
            artifacts: vec![PublishedArtifact {
                filename,
                data,
                upstream_hashes,
            }],
            allow_overwrite: state.config().publishing.allow_overwrite,
            allow_shadowing: state.config().publishing.allow_shadowing,
        })
        .await
        .map_err(|err| map_error(&err))?;

    Ok((
        StatusCode::OK,
        format!("uploaded {} {version}", name.as_str()),
    ))
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
/// with file URLs rewritten to point through this starmetal instance.
async fn simple_project<S: HasPypiState>(
    State(state): State<S>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let name = PackageName::new(project);
    let name = PackageName::new(name.normalized(Ecosystem::PyPI).into_owned());
    let service = state.package_service();

    // Storage is the source of truth — check there first
    let mut project: starmetal_core::registry::pypi::PypiProject = if let Some(raw) = service
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
            .unwrap_or(build_local_project(service.as_ref(), &name).await?);

        // Persist to storage — this is now starmetal's data
        if let Ok(raw) = serde_json::to_vec(&upstream_project) {
            let _ = service
                .put_raw_upstream(Ecosystem::PyPI, &name, bytes::Bytes::from(raw))
                .await;
        }

        upstream_project
    };

    // Rewrite file URLs to point through starmetal
    validate_project_metadata(service.as_ref(), &name, &project)
        .await
        .map_err(|err| map_error(&err))?;
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

async fn build_local_project(
    service: &dyn PackageService,
    name: &PackageName,
) -> Result<starmetal_core::registry::pypi::PypiProject, (StatusCode, String)> {
    let versions = service
        .list_versions(Ecosystem::PyPI, name)
        .await
        .map_err(|err| map_error(&err))?;
    let mut files = Vec::new();
    for version in &versions {
        let metadata = service
            .get_version_metadata(Ecosystem::PyPI, name, &version.version)
            .await
            .map_err(|err| map_error(&err))?;
        files.extend(pypi_files_from_metadata(&metadata));
    }
    Ok(starmetal_core::registry::pypi::PypiProject {
        meta: starmetal_core::registry::pypi::PypiMeta {
            api_version: "1.0".to_string(),
        },
        name: name.as_str().to_string(),
        versions: versions
            .into_iter()
            .map(|version| version.version)
            .collect(),
        files,
    })
}

fn pypi_files_from_metadata(
    metadata: &VersionMetadata,
) -> Vec<starmetal_core::registry::pypi::PypiFile> {
    metadata
        .artifacts
        .iter()
        .map(|artifact| starmetal_core::registry::pypi::PypiFile {
            filename: artifact.filename.clone(),
            url: format!(
                "/pypi/packages/{}/{}/{}",
                metadata.name.as_str(),
                metadata.version,
                artifact.filename
            ),
            hashes: artifact.upstream_hashes.clone().into_iter().collect(),
            requires_python: None,
            yanked: starmetal_core::registry::pypi::PypiYanked::Bool(metadata.yanked),
            size: Some(artifact.size),
            upload_time: None,
            dist_info_metadata: None,
            gpg_sig: None,
        })
        .collect()
}

async fn validate_project_metadata(
    service: &dyn PackageService,
    name: &PackageName,
    project: &starmetal_core::registry::pypi::PypiProject,
) -> Result<(), StarmetalError> {
    for version in models::pypi_project_to_version_infos(project) {
        if let Some(metadata) =
            models::pypi_files_to_metadata(name, &version.version, &project.files)
        {
            service.validate_metadata(&metadata).await?;
        }
    }
    Ok(())
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

/// Map `StarmetalError` variants to appropriate HTTP status codes.
fn map_error(err: &StarmetalError) -> (StatusCode, String) {
    tracing::warn!(error = %err, "PyPI adapter request failed");
    crate::map_public_error(err)
}

fn authorize_publish<S: HasPypiState>(
    state: &S,
    token: &str,
    name: &PackageName,
) -> Result<(), (StatusCode, String)> {
    if !state.config().publishing.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            "publishing is not enabled".to_string(),
        ));
    }
    if state
        .config()
        .authorize_publish_token(token, TokenScope::Publish, Ecosystem::PyPI, name)
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "publishing token is not authorized for this package".to_string(),
        ))
    }
}

fn extract_write_token(headers: &HeaderMap) -> Option<String> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    if let Some(token) = authorization.strip_prefix("Bearer ") {
        return Some(token.to_string());
    }
    let encoded = authorization.strip_prefix("Basic ")?;
    let decoded = BASE64_STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_username, password) = decoded.split_once(':')?;
    Some(password.to_string())
}
