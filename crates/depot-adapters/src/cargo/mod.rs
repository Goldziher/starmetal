//! Cargo sparse index registry adapter.
//!
//! Provides an axum router that serves the Cargo sparse index protocol
//! (RFC 2789) and crate downloads, translating requests into `PackageService`
//! trait calls. Includes an upstream client for fetching from index.crates.io.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use depot_core::config::Config;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::{PackageService, PublishingService};
use depot_core::publishing::{PublishRequest, PublishedArtifact, TokenScope};
use depot_core::registry::cargo::CargoIndexEntry;
use sha2::Digest;

use self::upstream::CargoUpstreamClient;

/// Trait for extracting Cargo-specific state from the application state.
///
/// The Cargo adapter needs direct access to the upstream client in addition
/// to PackageService, because the sparse index response must include dependency
/// and feature data that is not captured in VersionMetadata.
pub trait HasCargoState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
    fn cargo_upstream(&self) -> &Arc<CargoUpstreamClient>;
}

/// Build the Cargo adapter router.
///
/// Mount this under `/cargo` in the top-level application router.
pub fn router<S: HasCargoState>() -> Router<S> {
    Router::new()
        .route("/config.json", get(config_json::<S>))
        .route("/api/v1/crates/new", put(publish_crate::<S>))
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
async fn config_json<S: HasCargoState>(
    State(state): State<S>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let base_url = crate::public_base_url(state.config(), &headers);

    let dl_base = format!("{base_url}/cargo/crates/{{crate}}/{{version}}/download");
    let config = if state.config().publishing.enabled {
        models::build_config_json_with_api(&dl_base, Some(format!("{base_url}/cargo")))
    } else {
        models::build_config_json(&dl_base)
    };
    let body = serde_json::to_string(&config)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}

async fn publish_crate<S: HasCargoState>(
    State(state): State<S>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let (metadata, crate_bytes) = parse_publish_body(&body)?;
    let name = metadata["name"]
        .as_str()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing crate name".to_string()))?;
    let version = metadata["vers"]
        .as_str()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing crate version".to_string()))?;
    let package_name = PackageName::new(name.to_ascii_lowercase());
    authorize_publish(&state, &headers, &package_name)?;
    let sha256 = hex::encode(sha2::Sha256::digest(&crate_bytes));
    let filename = format!("{}-{version}.crate", package_name.as_str());
    let mut upstream_hashes = ahash::AHashMap::new();
    upstream_hashes.insert("sha256".to_string(), sha256.clone());

    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::Cargo,
            name: package_name.clone(),
            version: version.to_string(),
            license: metadata["license"].as_str().map(str::to_string),
            yanked: false,
            artifacts: vec![PublishedArtifact {
                filename,
                data: crate_bytes,
                upstream_hashes,
            }],
            allow_overwrite: state.config().publishing.allow_overwrite,
            allow_shadowing: state.config().publishing.allow_shadowing,
        })
        .await
        .map_err(|err| map_error(&err))?;

    let entry = cargo_entry_from_publish_metadata(&metadata, &sha256)?;
    store_cargo_index_entry(state.package_service().as_ref(), &package_name, entry).await?;

    Ok(json_response(serde_json::json!({
        "ok": true,
        "warnings": {
            "invalid_categories": [],
            "invalid_badges": [],
            "other": []
        }
    })))
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
            .unwrap_or(Vec::new());

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

    validate_index_metadata(service.as_ref(), &package_name, &body)
        .await
        .map_err(|err| map_error(&err))?;
    Ok(([(axum::http::header::CONTENT_TYPE, "text/plain")], body).into_response())
}

fn parse_publish_body(body: &Bytes) -> Result<(serde_json::Value, Bytes), (StatusCode, String)> {
    let metadata_len = read_u32(body, 0)? as usize;
    let metadata_start = 4;
    let metadata_end = metadata_start + metadata_len;
    if body.len() < metadata_end + 4 {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid cargo publish body".to_string(),
        ));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&body[metadata_start..metadata_end])
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    let crate_len = read_u32(body, metadata_end)? as usize;
    let crate_start = metadata_end + 4;
    let crate_end = crate_start + crate_len;
    if body.len() < crate_end {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid cargo crate length".to_string(),
        ));
    }
    Ok((metadata, body.slice(crate_start..crate_end)))
}

fn read_u32(body: &Bytes, offset: usize) -> Result<u32, (StatusCode, String)> {
    let bytes = body.get(offset..offset + 4).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "invalid cargo publish body".to_string(),
        )
    })?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])))
}

fn cargo_entry_from_publish_metadata(
    metadata: &serde_json::Value,
    sha256: &str,
) -> Result<CargoIndexEntry, (StatusCode, String)> {
    let mut entry = metadata.clone();
    entry["cksum"] = serde_json::Value::String(sha256.to_string());
    entry["yanked"] = serde_json::Value::Bool(false);
    if entry.get("features").is_none() {
        entry["features"] = serde_json::json!({});
    }
    serde_json::from_value(entry).map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

async fn store_cargo_index_entry(
    service: &dyn PackageService,
    package_name: &PackageName,
    entry: CargoIndexEntry,
) -> Result<(), (StatusCode, String)> {
    let mut entries = if let Some(raw) = service
        .get_raw_upstream(Ecosystem::Cargo, package_name)
        .await
        .map_err(|err| map_error(&err))?
    {
        String::from_utf8(raw.to_vec())
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str::<CargoIndexEntry>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        Vec::new()
    };
    entries.retain(|existing| existing.vers != entry.vers);
    entries.push(entry);
    let body = models::entries_to_ndjson(&entries);
    service
        .put_raw_upstream(Ecosystem::Cargo, package_name, bytes::Bytes::from(body))
        .await
        .map_err(|err| map_error(&err))
}

fn authorize_publish<S: HasCargoState>(
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
        .authorize_publish_token(token, TokenScope::Publish, Ecosystem::Cargo, name)
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "publishing token is not authorized for this package".to_string(),
        ))
    }
}

fn json_response(value: serde_json::Value) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

async fn validate_index_metadata(
    service: &dyn PackageService,
    package_name: &PackageName,
    body: &str,
) -> Result<(), DepotError> {
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let entry: depot_core::registry::cargo::CargoIndexEntry = serde_json::from_str(line)
            .map_err(|err| DepotError::Storage(format!("invalid cached cargo index: {err}")))?;
        let metadata = models::cargo_entry_to_metadata(package_name, &entry);
        service.validate_metadata(&metadata).await?;
    }
    Ok(())
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
    tracing::warn!(error = %err, "Cargo adapter request failed");
    crate::map_public_error(err)
}
