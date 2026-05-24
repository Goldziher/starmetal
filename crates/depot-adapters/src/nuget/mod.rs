//! NuGet V3 restore adapter.

pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use base64::Engine;
use depot_core::config::Config;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::{PackageService, PublishingService};
use depot_core::publishing::{PublishRequest, PublishedArtifact, TokenScope};
use sha2::Digest;

use self::upstream::NuGetUpstreamClient;
use crate::archive;

pub trait HasNuGetState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
    fn nuget_upstream(&self) -> &Arc<NuGetUpstreamClient>;
}

pub fn router<S: HasNuGetState>() -> Router<S> {
    Router::new()
        .route("/v3/index.json", get(service_index::<S>))
        .route(
            "/api/v2/package",
            put(publish_package::<S>).post(publish_package::<S>),
        )
        .route("/v3-flatcontainer/{id}/index.json", get(versions::<S>))
        .route(
            "/v3-flatcontainer/{id}/{version}/{filename}",
            get(package_file::<S>),
        )
        .route("/v3/registration/{id}/index.json", get(registration::<S>))
}

async fn service_index<S: HasNuGetState>(
    State(_state): State<S>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost:8080");
    let body = serde_json::json!({
        "version": "3.0.0",
        "resources": resources(host, _state.config().publishing.enabled)
    });
    Ok(json_response(body))
}

fn resources(host: &str, publishing_enabled: bool) -> Vec<serde_json::Value> {
    let mut resources = vec![
        serde_json::json!({
            "@id": format!("http://{host}/nuget/v3-flatcontainer/"),
            "@type": "PackageBaseAddress/3.0.0",
            "comment": "Depot NuGet package base address"
        }),
        serde_json::json!({
            "@id": format!("http://{host}/nuget/v3/registration/"),
            "@type": "RegistrationsBaseUrl/3.6.0",
            "comment": "Depot NuGet registration base"
        }),
    ];
    if publishing_enabled {
        resources.push(serde_json::json!({
            "@id": format!("http://{host}/nuget/api/v2/package"),
            "@type": "PackagePublish/2.0.0",
            "comment": "Depot NuGet package publish endpoint"
        }));
    }
    resources
}

async fn publish_package<S: HasNuGetState>(
    State(state): State<S>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let metadata = archive::parse_nuget(&body).map_err(|err| map_error(&err))?;
    let name = PackageName::new(metadata.name);
    authorize_publish(&state, &headers, &name)?;
    let package_filename = format!("{}.{}.nupkg", name.as_str(), metadata.version);
    let nuspec_filename = format!("{}.nuspec", name.as_str());
    let sha512 = base64::prelude::BASE64_STANDARD.encode(sha2::Sha512::digest(&body));
    let mut upstream_hashes = ahash::AHashMap::new();
    upstream_hashes.insert("sha512".to_string(), sha512);
    let mut artifacts = vec![PublishedArtifact {
        filename: package_filename,
        data: body,
        upstream_hashes,
    }];
    if let Some(nuspec) = metadata.nuspec {
        artifacts.push(PublishedArtifact {
            filename: nuspec_filename,
            data: nuspec,
            upstream_hashes: Default::default(),
        });
    }
    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::NuGet,
            name,
            version: metadata.version,
            license: metadata.license,
            yanked: false,
            artifacts,
            allow_overwrite: state.config().publishing.allow_overwrite,
            allow_shadowing: state.config().publishing.allow_shadowing,
        })
        .await
        .map_err(|err| map_error(&err))?;
    Ok(StatusCode::CREATED.into_response())
}

async fn versions<S: HasNuGetState>(
    State(state): State<S>,
    Path(id): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let name = PackageName::new(id.to_ascii_lowercase());
    let versions = state
        .package_service()
        .list_versions(Ecosystem::NuGet, &name)
        .await
        .map_err(|err| map_error(&err))?;
    Ok(json_response(serde_json::json!({
        "versions": versions.into_iter().map(|version| version.version).collect::<Vec<_>>()
    })))
}

async fn registration<S: HasNuGetState>(
    State(state): State<S>,
    Path(id): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let name = PackageName::new(id.to_ascii_lowercase());
    let versions = state
        .package_service()
        .list_versions(Ecosystem::NuGet, &name)
        .await
        .map_err(|err| map_error(&err))?;
    Ok(json_response(upstream::registration_json(&name, versions)))
}

async fn package_file<S: HasNuGetState>(
    State(state): State<S>,
    Path((id, version, filename)): Path<(String, String, String)>,
) -> Result<Response, (StatusCode, String)> {
    let name = PackageName::new(id.to_ascii_lowercase());
    if filename.ends_with(".sha512") {
        let base = filename.trim_end_matches(".sha512");
        let data = get_artifact(state, &name, &version, base.to_string()).await?;
        let digest = sha2::Sha512::digest(&data);
        let encoded = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, digest);
        return Ok(([(header::CONTENT_TYPE, "text/plain")], encoded).into_response());
    }

    let content_type = if filename.ends_with(".nuspec") {
        "application/xml"
    } else {
        "application/octet-stream"
    };
    let data = get_artifact(state, &name, &version, filename).await?;
    Ok(([(header::CONTENT_TYPE, content_type)], Body::from(data)).into_response())
}

async fn get_artifact<S: HasNuGetState>(
    state: S,
    name: &PackageName,
    version: &str,
    filename: String,
) -> Result<bytes::Bytes, (StatusCode, String)> {
    state
        .package_service()
        .get_artifact(&ArtifactId {
            ecosystem: Ecosystem::NuGet,
            name: name.clone(),
            version: version.to_string(),
            filename,
        })
        .await
        .map_err(|err| map_error(&err))
}

fn json_response(value: serde_json::Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

fn authorize_publish<S: HasNuGetState>(
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
        .get("x-nuget-apikey")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "missing publishing token".to_string(),
            )
        })?;
    if state
        .config()
        .authorize_publish_token(token, TokenScope::Publish, Ecosystem::NuGet, name)
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "publishing token is not authorized for this package".to_string(),
        ))
    }
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
