//! Hosted Pub Repository v2 adapter.

pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::PackageService;

use self::upstream::PubUpstreamClient;

pub trait HasPubState: Clone + Send + Sync + 'static {
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn pub_upstream(&self) -> &Arc<PubUpstreamClient>;
}

pub fn router<S: HasPubState>() -> Router<S> {
    Router::new()
        .route("/api/packages/{name}", get(package::<S>))
        .route("/api/packages/{name}/versions/{version}", get(version::<S>))
        .route("/api/archives/{filename}", get(archive::<S>))
}

async fn package<S: HasPubState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let name = PackageName::new(name.to_ascii_lowercase());
    let service = state.package_service();
    let mut package: serde_json::Value = if let Some(raw) = service
        .get_raw_upstream(Ecosystem::Pub, &name)
        .await
        .map_err(|err| map_error(&err))?
    {
        serde_json::from_slice(&raw)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        let fetched = state
            .pub_upstream()
            .fetch_package_json(&name)
            .await
            .map_err(|err| map_error(&err))?;
        service
            .put_raw_upstream(
                Ecosystem::Pub,
                &name,
                bytes::Bytes::from(serde_json::to_vec(&fetched).unwrap_or_default()),
            )
            .await
            .map_err(|err| map_error(&err))?;
        fetched
    };
    validate_package(service.as_ref(), &name, &package)
        .await
        .map_err(|err| map_error(&err))?;
    rewrite_archive_urls(&mut package, &host_base(&headers));
    Ok(json_response(package))
}

async fn version<S: HasPubState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path((name, version)): Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    let name = PackageName::new(name.to_ascii_lowercase());
    let metadata = state
        .package_service()
        .get_version_metadata(Ecosystem::Pub, &name, &version)
        .await
        .map_err(|err| map_error(&err))?;
    let archive_url = format!(
        "{}/pub/api/archives/{}-{version}.tar.gz",
        host_base(&headers),
        name.as_str()
    );
    Ok(json_response(serde_json::json!({
        "version": metadata.version,
        "archive_url": archive_url,
        "archive_sha256": metadata.artifacts.first().and_then(|artifact| artifact.upstream_hashes.get("sha256"))
    })))
}

async fn archive<S: HasPubState>(
    State(state): State<S>,
    Path(filename): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let (name, version) = parse_archive_filename(&filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid archive filename: {filename}"),
        )
    })?;
    let data = state
        .package_service()
        .get_artifact(&ArtifactId {
            ecosystem: Ecosystem::Pub,
            name: PackageName::new(name),
            version: version.to_string(),
            filename,
        })
        .await
        .map_err(|err| map_error(&err))?;
    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        Body::from(data),
    )
        .into_response())
}

async fn validate_package(
    service: &dyn PackageService,
    name: &PackageName,
    package: &serde_json::Value,
) -> Result<(), DepotError> {
    for version in package["versions"].as_array().into_iter().flatten() {
        let Some(version_text) = version["version"].as_str() else {
            continue;
        };
        let metadata = upstream::metadata_from_version(name, version_text, version);
        service.validate_metadata(&metadata).await?;
    }
    Ok(())
}

fn rewrite_archive_urls(package: &mut serde_json::Value, base_url: &str) {
    let name = package["name"].as_str().unwrap_or_default().to_string();
    for version in package["versions"].as_array_mut().into_iter().flatten() {
        if let Some(version_text) = version["version"].as_str() {
            version["archive_url"] = serde_json::Value::String(format!(
                "{base_url}/pub/api/archives/{name}-{version_text}.tar.gz"
            ));
        }
    }
}

fn parse_archive_filename(filename: &str) -> Option<(&str, &str)> {
    let stem = filename.strip_suffix(".tar.gz")?;
    for idx in (1..stem.len()).rev() {
        if stem.as_bytes()[idx] == b'-'
            && stem
                .as_bytes()
                .get(idx + 1)
                .is_some_and(|byte| byte.is_ascii_digit())
        {
            return Some((&stem[..idx], &stem[idx + 1..]));
        }
    }
    None
}

fn host_base(headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost:8080");
    format!("http://{host}")
}

fn json_response(value: serde_json::Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

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
