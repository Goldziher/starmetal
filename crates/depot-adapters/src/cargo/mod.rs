//! Cargo sparse index registry adapter.
//!
//! Provides an axum router that serves the Cargo sparse index protocol
//! (RFC 2789) and crate downloads, translating requests into `PackageService`
//! trait calls. Includes an upstream client for fetching from index.crates.io.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::PackageService;

use self::upstream::CargoUpstreamClient;

/// Trait for extracting Cargo-specific state from the application state.
///
/// The Cargo adapter needs direct access to the upstream client in addition
/// to PackageService, because the sparse index response must include dependency
/// and feature data that is not captured in VersionMetadata.
pub trait HasCargoState: Clone + Send + Sync + 'static {
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn cargo_upstream(&self) -> &Arc<CargoUpstreamClient>;
}

/// Build the Cargo adapter router.
///
/// Mount this under `/cargo` in the top-level application router.
pub fn router<S: HasCargoState>() -> Router<S> {
    Router::new()
        .route("/config.json", get(config_json))
        .route("/1/{name}", get(sparse_index::<S>))
        .route("/2/{name}", get(sparse_index::<S>))
        .route("/3/{first}/{name}", get(sparse_index_3::<S>))
        .route("/{first}/{second}/{name}", get(sparse_index_long::<S>))
        .route(
            "/crates/{name}/{version}/download",
            get(download_crate::<S>),
        )
}

/// GET /config.json -- return the Cargo sparse index configuration.
async fn config_json(headers: HeaderMap) -> Result<Response, (StatusCode, String)> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");

    let dl_base = format!("http://{host}/cargo/crates/{{crate}}/{{version}}/download");
    let config = models::build_config_json(&dl_base);
    let body = serde_json::to_string(&config)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}

/// Handler for 1-2 character crate names: /1/{name} and /2/{name}
async fn sparse_index<S: HasCargoState>(
    State(state): State<S>,
    Path(name): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    serve_index(state, name).await
}

/// Handler for 3-character crate names: /3/{first}/{name}
async fn sparse_index_3<S: HasCargoState>(
    State(state): State<S>,
    Path((_first, name)): Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    serve_index(state, name).await
}

/// Handler for 4+ character crate names: /{first}/{second}/{name}
async fn sparse_index_long<S: HasCargoState>(
    State(state): State<S>,
    Path((_first, _second, name)): Path<(String, String, String)>,
) -> Result<Response, (StatusCode, String)> {
    serve_index(state, name).await
}

/// Shared logic for all sparse index routes.
///
/// Triggers the caching lifecycle through PackageService, then serves the
/// raw ndjson index data from the upstream client cache.
async fn serve_index<S: HasCargoState>(
    state: S,
    name: String,
) -> Result<Response, (StatusCode, String)> {
    let package_name = PackageName::new(&name);
    let service = state.package_service();

    // Storage is the source of truth
    let body = if let Some(raw) = service
        .get_raw_upstream(Ecosystem::Cargo, &package_name)
        .await
        .map_err(|err| map_error(&err))?
    {
        String::from_utf8(raw.to_vec())
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        // Cache miss — fetch from upstream
        let _versions = service
            .list_versions(Ecosystem::Cargo, &package_name)
            .await
            .map_err(|err| map_error(&err))?;

        let entries = state
            .cargo_upstream()
            .get_cached_entries(&package_name)
            .await
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "index entries not cached after upstream fetch".to_string(),
                )
            })?;

        let ndjson = models::entries_to_ndjson(&entries);

        // Persist to storage
        let _ = service
            .put_raw_upstream(
                Ecosystem::Cargo,
                &package_name,
                bytes::Bytes::from(ndjson.clone()),
            )
            .await;

        ndjson
    };

    Ok(([(axum::http::header::CONTENT_TYPE, "text/plain")], body).into_response())
}

/// GET /crates/{name}/{version}/download -- download a crate archive.
async fn download_crate<S: HasCargoState>(
    State(state): State<S>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    let filename = format!("{name}-{version}.crate");
    let artifact_id = ArtifactId {
        ecosystem: Ecosystem::Cargo,
        name: PackageName::new(&name),
        version: version.clone(),
        filename,
    };

    let data = state
        .package_service()
        .get_artifact(&artifact_id)
        .await
        .map_err(|err| map_error(&err))?;

    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/x-tar".to_string(),
        )],
        data,
    )
        .into_response())
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
