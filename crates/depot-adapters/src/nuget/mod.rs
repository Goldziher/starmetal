//! NuGet V3 restore adapter.

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
use sha2::Digest;

use self::upstream::NuGetUpstreamClient;

pub trait HasNuGetState: Clone + Send + Sync + 'static {
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn nuget_upstream(&self) -> &Arc<NuGetUpstreamClient>;
}

pub fn router<S: HasNuGetState>() -> Router<S> {
    Router::new()
        .route("/v3/index.json", get(service_index::<S>))
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
        "resources": [
            {
                "@id": format!("http://{host}/nuget/v3-flatcontainer/"),
                "@type": "PackageBaseAddress/3.0.0",
                "comment": "Depot NuGet package base address"
            },
            {
                "@id": format!("http://{host}/nuget/v3/registration/"),
                "@type": "RegistrationsBaseUrl/3.6.0",
                "comment": "Depot NuGet registration base"
            }
        ]
    });
    Ok(json_response(body))
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
