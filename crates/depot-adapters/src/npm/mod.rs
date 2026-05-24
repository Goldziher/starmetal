//! npm registry protocol adapter.
//!
//! Provides an axum router that translates npm registry API requests into
//! `PackageService` trait calls, and an upstream client for fetching
//! packages from registry.npmjs.org or any npm-compatible registry.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use depot_core::config::Config;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::{PackageService, PublishingService};
use depot_core::publishing::{PublishRequest, PublishedArtifact, TokenScope};

use self::upstream::NpmUpstreamClient;

/// Trait for extracting npm-specific state from application state.
///
/// The server crate implements this on its `AppState` to bridge the adapter
/// to the service layer and upstream client without creating a circular dependency.
pub trait HasNpmState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
    fn npm_upstream(&self) -> &Arc<NpmUpstreamClient>;
}

/// Build the npm adapter router.
///
/// Mount this under `/npm` in the top-level application router.
pub fn router<S: HasNpmState>() -> Router<S> {
    Router::new()
        .route(
            "/{package}",
            get(package_metadata::<S>).put(publish_package::<S>),
        )
        .route(
            "/@{scope}/{name}",
            get(scoped_package_metadata::<S>).put(publish_scoped_package::<S>),
        )
        .route("/{package}/-/{filename}", get(download_tarball::<S>))
        .route(
            "/@{scope}/{name}/-/{filename}",
            get(download_scoped_tarball::<S>),
        )
}

async fn publish_package<S: HasNpmState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path(package): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let name = PackageName::new(package);
    publish_packument(state, &headers, name, payload).await
}

async fn publish_scoped_package<S: HasNpmState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path((scope, name)): Path<(String, String)>,
    Json(payload): Json<serde_json::Value>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let full_name = PackageName::new(format!("@{scope}/{name}"));
    publish_packument(state, &headers, full_name, payload).await
}

async fn publish_packument<S: HasNpmState>(
    state: S,
    headers: &HeaderMap,
    name: PackageName,
    payload: serde_json::Value,
) -> Result<axum::response::Response, (StatusCode, String)> {
    authorize_publish(&state, headers, &name)?;
    let version = payload["dist-tags"]["latest"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            payload["versions"]
                .as_object()
                .and_then(|versions| versions.keys().next().cloned())
        })
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing npm version".to_string()))?;
    let version_payload = payload["versions"].get(&version).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing npm version metadata".to_string(),
        )
    })?;
    let (filename, data) = attachment(&payload).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing npm tarball attachment".to_string(),
        )
    })?;

    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::Npm,
            name: name.clone(),
            version: version.clone(),
            license: version_payload["license"].as_str().map(str::to_string),
            yanked: false,
            artifacts: vec![PublishedArtifact {
                filename,
                data,
                upstream_hashes: Default::default(),
            }],
            allow_overwrite: state.config().publishing.allow_overwrite,
            allow_shadowing: state.config().publishing.allow_shadowing,
        })
        .await
        .map_err(|err| map_error(&err))?;

    Ok((
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&serde_json::json!({
            "ok": true,
            "id": name.as_str(),
            "rev": format!("depot-{version}")
        }))
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
    )
        .into_response())
}

/// GET /{package} -- return packument JSON for an unscoped package.
async fn package_metadata<S: HasNpmState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path(package): Path<String>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let name = PackageName::new(package);
    let host = extract_host(&headers);
    serve_packument(state, &name, &host).await
}

/// GET /@{scope}/{name} -- return packument JSON for a scoped package.
async fn scoped_package_metadata<S: HasNpmState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path((scope, name)): Path<(String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let full_name = PackageName::new(format!("@{scope}/{name}"));
    let host = extract_host(&headers);
    serve_packument(state, &full_name, &host).await
}

fn extract_host(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string()
}

/// Shared logic for serving packument responses.
///
/// Checks depot's storage first. On miss, fetches from upstream, stores the
/// raw packument in storage, then serves it. The upstream client's memory
/// cache is an optimization — storage is the source of truth.
async fn serve_packument<S: HasNpmState>(
    state: S,
    name: &PackageName,
    host: &str,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let service = state.package_service();

    // Try storage first — depot owns this data once fetched
    let mut packument: serde_json::Value = if let Some(raw) = service
        .get_raw_upstream(Ecosystem::Npm, name)
        .await
        .map_err(|err| map_error(&err))?
    {
        serde_json::from_slice(&raw)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        // Cache miss — fetch from upstream
        let _versions = service
            .list_versions(Ecosystem::Npm, name)
            .await
            .map_err(|err| map_error(&err))?;

        let upstream_packument = state
            .npm_upstream()
            .get_cached_packument(name)
            .await
            .unwrap_or(build_local_packument(service.as_ref(), name, host).await?);

        // Persist to storage — this is now depot's data
        let raw = serde_json::to_vec(&upstream_packument)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let _ = service
            .put_raw_upstream(Ecosystem::Npm, name, bytes::Bytes::from(raw))
            .await;

        upstream_packument
    };

    // Rewrite tarball URLs to point through depot
    validate_packument_metadata(service.as_ref(), name, &packument)
        .await
        .map_err(|err| map_error(&err))?;
    let base_url = format!("http://{host}");
    models::rewrite_packument_tarball_urls(&mut packument, &base_url);

    let body = serde_json::to_string(&packument)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

async fn build_local_packument(
    service: &dyn PackageService,
    name: &PackageName,
    host: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let versions = service
        .list_versions(Ecosystem::Npm, name)
        .await
        .map_err(|err| map_error(&err))?;
    let mut version_map = serde_json::Map::new();
    for version in &versions {
        let metadata = service
            .get_version_metadata(Ecosystem::Npm, name, &version.version)
            .await
            .map_err(|err| map_error(&err))?;
        let Some(artifact) = metadata.artifacts.first() else {
            continue;
        };
        version_map.insert(
            version.version.clone(),
            serde_json::json!({
                "name": name.as_str(),
                "version": version.version,
                "license": metadata.license,
                "dist": {
                    "tarball": format!("http://{host}/npm/{}/-/{}", name.as_str(), artifact.filename),
                }
            }),
        );
    }
    let latest = versions.last().map(|version| version.version.clone());
    Ok(serde_json::json!({
        "_id": name.as_str(),
        "name": name.as_str(),
        "dist-tags": latest.map(|version| serde_json::json!({ "latest": version })).unwrap_or_else(|| serde_json::json!({})),
        "versions": version_map,
    }))
}

async fn validate_packument_metadata(
    service: &dyn PackageService,
    name: &PackageName,
    packument: &serde_json::Value,
) -> Result<(), DepotError> {
    for version in models::extract_version_infos(packument) {
        if let Some(metadata) = models::extract_version_metadata(name, &version.version, packument)
        {
            service.validate_metadata(&metadata).await?;
        }
    }
    Ok(())
}

/// GET /{package}/-/{filename} -- download an unscoped package tarball.
async fn download_tarball<S: HasNpmState>(
    State(state): State<S>,
    Path((package, filename)): Path<(String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let name = PackageName::new(package);
    serve_tarball(state, &name, &filename).await
}

/// GET /@{scope}/{name}/-/{filename} -- download a scoped package tarball.
async fn download_scoped_tarball<S: HasNpmState>(
    State(state): State<S>,
    Path((scope, name, filename)): Path<(String, String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let full_name = PackageName::new(format!("@{scope}/{name}"));
    serve_tarball(state, &full_name, &filename).await
}

/// Shared logic for serving tarball downloads.
async fn serve_tarball<S: HasNpmState>(
    state: S,
    name: &PackageName,
    filename: &str,
) -> Result<axum::response::Response, (StatusCode, String)> {
    // Extract version from filename: {name}-{version}.tgz
    let version = extract_version_from_filename(name.as_str(), filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "invalid filename format".to_string(),
        )
    })?;

    let artifact_id = ArtifactId {
        ecosystem: Ecosystem::Npm,
        name: name.clone(),
        version,
        filename: filename.to_string(),
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
    )
        .into_response())
}

/// Extract version string from an npm tarball filename.
///
/// Expected format: `{name}-{version}.tgz` where name may contain `@scope/`.
fn extract_version_from_filename(name: &str, filename: &str) -> Option<String> {
    let stripped = filename.strip_suffix(".tgz")?;
    let package_basename = name.rsplit_once('/').map_or(name, |(_, basename)| basename);
    let prefix = format!("{package_basename}-");
    let version = stripped.strip_prefix(&prefix)?;
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

fn attachment(payload: &serde_json::Value) -> Option<(String, bytes::Bytes)> {
    let (filename, attachment) = payload["_attachments"].as_object()?.iter().next()?;
    let encoded = attachment["data"].as_str()?;
    let decoded = BASE64_STANDARD.decode(encoded).ok()?;
    Some((filename.clone(), bytes::Bytes::from(decoded)))
}

fn authorize_publish<S: HasNpmState>(
    state: &S,
    headers: &HeaderMap,
    name: &PackageName,
) -> Result<(), (StatusCode, String)> {
    if !state.config().publishing.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            "publishing is not enabled".to_string(),
        ));
    }
    let token = extract_write_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "missing publishing token".to_string(),
        )
    })?;
    if state
        .config()
        .authorize_publish_token(&token, TokenScope::Publish, Ecosystem::Npm, name)
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
    authorization.strip_prefix("npm ").map(str::to_string)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_extract_version_from_simple_filename() {
        assert_eq!(
            extract_version_from_filename("is-odd", "is-odd-3.0.1.tgz"),
            Some("3.0.1".to_string())
        );
    }

    #[test]
    fn should_extract_version_from_scoped_filename() {
        assert_eq!(
            extract_version_from_filename("@scope/pkg", "pkg-1.2.3.tgz"),
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn should_return_none_for_invalid_filename() {
        assert_eq!(
            extract_version_from_filename("is-odd", "not-a-match.tgz"),
            None
        );
        assert_eq!(extract_version_from_filename("is-odd", "is-odd-.tgz"), None);
        assert_eq!(
            extract_version_from_filename("is-odd", "is-odd-1.0.0.tar.gz"),
            None
        );
    }
}
