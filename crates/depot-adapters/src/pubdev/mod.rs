//! Hosted Pub Repository v2 adapter.

pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use depot_core::config::Config;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::{PackageService, PublishingService};
use depot_core::publishing::{PublishRequest, PublishedArtifact, TokenScope};
use sha2::Digest;

use self::upstream::PubUpstreamClient;
use crate::archive;

pub trait HasPubState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
    fn pub_upstream(&self) -> &Arc<PubUpstreamClient>;
}

pub fn router<S: HasPubState>() -> Router<S> {
    Router::new()
        .route("/api/packages/{name}", get(package::<S>))
        .route("/api/packages/{name}/versions/{version}", get(version::<S>))
        .route("/api/archives/{filename}", get(archive::<S>))
        .route("/api/packages/versions/new", post(publish_archive::<S>))
}

async fn publish_archive<S: HasPubState>(
    State(state): State<S>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let metadata = archive::parse_pub_archive(&body).map_err(|err| map_error(&err))?;
    let name = PackageName::new(metadata.name.to_ascii_lowercase());
    authorize_publish(&state, &headers, &name)?;
    let filename = format!("{}-{}.tar.gz", name.as_str(), metadata.version);
    let sha256 = hex::encode(sha2::Sha256::digest(&body));
    let mut upstream_hashes = ahash::AHashMap::new();
    upstream_hashes.insert("sha256".to_string(), sha256);
    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::Pub,
            name: name.clone(),
            version: metadata.version.clone(),
            license: None,
            yanked: false,
            artifacts: vec![PublishedArtifact {
                filename,
                data: body,
                upstream_hashes,
            }],
            allow_overwrite: state.config().publishing.allow_overwrite,
            allow_shadowing: state.config().publishing.allow_shadowing,
        })
        .await
        .map_err(|err| map_error(&err))?;
    Ok(json_response(serde_json::json!({
        "success": {"message": format!("Uploaded {} {}", name.as_str(), metadata.version)}
    })))
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
        let fetched = match state.pub_upstream().fetch_package_json(&name).await {
            Ok(fetched) => fetched,
            Err(_) => build_local_package(service.as_ref(), &name, &host_base(&headers))
                .await
                .map_err(|err| map_error(&err))?,
        };
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

async fn build_local_package(
    service: &dyn PackageService,
    name: &PackageName,
    base_url: &str,
) -> Result<serde_json::Value, DepotError> {
    let versions = service.list_versions(Ecosystem::Pub, name).await?;
    let mut version_values = Vec::new();
    for version in versions {
        let metadata = service
            .get_version_metadata(Ecosystem::Pub, name, &version.version)
            .await?;
        let archive_sha256 = metadata
            .artifacts
            .first()
            .and_then(|artifact| artifact.upstream_hashes.get("sha256"))
            .cloned();
        version_values.push(serde_json::json!({
            "version": metadata.version,
            "archive_url": format!("{base_url}/pub/api/archives/{}-{}.tar.gz", name.as_str(), metadata.version),
            "archive_sha256": archive_sha256,
            "pubspec": {
                "name": name.as_str(),
                "version": metadata.version
            }
        }));
    }
    let latest = version_values.last().cloned().unwrap_or_else(|| {
        serde_json::json!({
            "version": "",
            "archive_url": "",
            "archive_sha256": null,
            "pubspec": {}
        })
    });
    Ok(serde_json::json!({
        "name": name.as_str(),
        "latest": latest,
        "versions": version_values
    }))
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
        DepotError::Adapter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        DepotError::Publish(_) => (StatusCode::CONFLICT, err.to_string()),
        DepotError::Upstream(_) => (StatusCode::BAD_GATEWAY, err.to_string()),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

fn authorize_publish<S: HasPubState>(
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
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "missing publishing token".to_string(),
            )
        })?;
    if state
        .config()
        .authorize_publish_token(token, TokenScope::Publish, Ecosystem::Pub, name)
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "publishing token is not authorized for this package".to_string(),
        ))
    }
}
