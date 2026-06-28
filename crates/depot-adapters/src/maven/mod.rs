//! Maven Central-compatible artifact serving adapter.

pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, put};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use depot_core::config::Config;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::{PackageService, PublishingService};
use depot_core::publishing::{PublishRequest, PublishedArtifact, TokenScope};
use sha1::Digest as _;

use self::upstream::MavenUpstreamClient;

pub trait HasMavenState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
    fn maven_upstream(&self) -> &Arc<MavenUpstreamClient>;
}

pub fn router<S: HasMavenState>() -> Router<S> {
    Router::new()
        .route("/{*path}", get(get_path::<S>))
        .route("/{*path}", head(head_path::<S>))
        .route("/{*path}", put(put_path::<S>))
}

async fn get_path<S: HasMavenState>(
    State(state): State<S>,
    Path(path): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    serve_path(state, path, Method::GET).await
}

async fn head_path<S: HasMavenState>(
    State(state): State<S>,
    Path(path): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    serve_path(state, path, Method::HEAD).await
}

async fn put_path<S: HasMavenState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path(path): Path<String>,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    if let Some((artifact_path, _algorithm)) = checksum_request(&path) {
        authorize_publish(&state, &headers, artifact_path)?;
        return Ok(StatusCode::CREATED.into_response());
    }

    if path.ends_with("maven-metadata.xml") {
        let package_name = PackageName::new(path.trim_end_matches("/maven-metadata.xml"));
        authorize_publish_for_package(&state, &headers, &package_name)?;
        state
            .package_service()
            .put_raw_upstream(Ecosystem::Maven, &package_name, body)
            .await
            .map_err(|err| map_error(&err))?;
        return Ok(StatusCode::CREATED.into_response());
    }

    let artifact_id = artifact_id_from_path(&path).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid Maven path: {path}"),
        )
    })?;
    authorize_publish_for_package(&state, &headers, &artifact_id.name)?;
    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::Maven,
            name: artifact_id.name,
            version: artifact_id.version,
            license: None,
            yanked: false,
            artifacts: vec![PublishedArtifact {
                filename: artifact_id.filename,
                data: body,
                upstream_hashes: Default::default(),
            }],
            allow_overwrite: true,
            allow_shadowing: state.config().publishing.allow_shadowing,
        })
        .await
        .map_err(|err| map_error(&err))?;

    Ok(StatusCode::CREATED.into_response())
}

async fn serve_path<S: HasMavenState>(
    state: S,
    path: String,
    method: Method,
) -> Result<Response, (StatusCode, String)> {
    if path.ends_with("maven-metadata.xml") {
        return serve_raw_xml(state, path, method).await;
    }

    if let Some((artifact_path, algorithm)) = checksum_request(&path) {
        let data = artifact_bytes(state, artifact_path).await?;
        let digest = match algorithm {
            "sha1" => hex::encode(sha1::Sha1::digest(&data)),
            "sha256" => hex::encode(sha2::Sha256::digest(&data)),
            _ => unreachable!("checksum_request only returns supported algorithms"),
        };
        return Ok(text_response(method, digest));
    }

    let data = artifact_bytes(state, &path).await?;
    Ok(binary_response(method, content_type(&path), data))
}

async fn serve_raw_xml<S: HasMavenState>(
    state: S,
    path: String,
    method: Method,
) -> Result<Response, (StatusCode, String)> {
    let package_name = PackageName::new(path.trim_end_matches("/maven-metadata.xml"));
    let service = state.package_service();
    let data = if let Some(cached) = service
        .get_raw_upstream(Ecosystem::Maven, &package_name)
        .await
        .map_err(|err| map_error(&err))?
    {
        cached
    } else {
        let fetched = state
            .maven_upstream()
            .fetch_path(&path)
            .await
            .map_err(|err| map_error(&err))?;
        service
            .put_raw_upstream(Ecosystem::Maven, &package_name, fetched.clone())
            .await
            .map_err(|err| map_error(&err))?;
        fetched
    };

    Ok(binary_response(method, "application/xml", data))
}

async fn artifact_bytes<S: HasMavenState>(
    state: S,
    path: &str,
) -> Result<bytes::Bytes, (StatusCode, String)> {
    let artifact_id = artifact_id_from_path(path).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid Maven path: {path}"),
        )
    })?;
    state
        .package_service()
        .get_artifact(&artifact_id)
        .await
        .map_err(|err| map_error(&err))
}

fn artifact_id_from_path(path: &str) -> Option<ArtifactId> {
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() < 4 {
        return None;
    }
    let filename = parts.last()?.to_string();
    let version = parts.get(parts.len() - 2)?.to_string();
    let artifact = parts.get(parts.len() - 3)?;
    let group = parts[..parts.len() - 3].join(".");
    Some(ArtifactId {
        ecosystem: Ecosystem::Maven,
        name: PackageName::new(format!("{group}:{artifact}")),
        version,
        filename,
    })
}

fn checksum_request(path: &str) -> Option<(&str, &str)> {
    path.strip_suffix(".sha256")
        .map(|artifact_path| (artifact_path, "sha256"))
        .or_else(|| {
            path.strip_suffix(".sha1")
                .map(|artifact_path| (artifact_path, "sha1"))
        })
}

fn content_type(path: &str) -> &'static str {
    if path.ends_with(".pom") {
        "application/xml"
    } else {
        "application/octet-stream"
    }
}

fn authorize_publish<S: HasMavenState>(
    state: &S,
    headers: &HeaderMap,
    path: &str,
) -> Result<(), (StatusCode, String)> {
    let artifact_id = artifact_id_from_path(path).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid Maven path: {path}"),
        )
    })?;
    authorize_publish_for_package(state, headers, &artifact_id.name)
}

fn authorize_publish_for_package<S: HasMavenState>(
    state: &S,
    headers: &HeaderMap,
    package_name: &PackageName,
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

    if state.config().authorize_publish_token(
        &token,
        TokenScope::Publish,
        Ecosystem::Maven,
        package_name,
    ) {
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

fn binary_response(method: Method, content_type: &'static str, data: bytes::Bytes) -> Response {
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(data)
    };
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

fn text_response(method: Method, body: String) -> Response {
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(body)
    };
    ([(header::CONTENT_TYPE, "text/plain")], body).into_response()
}

fn map_error(err: &DepotError) -> (StatusCode, String) {
    tracing::warn!(error = %err, "Maven adapter request failed");
    crate::map_public_error(err)
}
