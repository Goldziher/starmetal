use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Serialize;

use crate::state::AppState;
use starmetal_core::package::{Ecosystem, PackageName};

#[derive(Debug, Serialize)]
struct AdminStatus {
    version: &'static str,
    storage_backend: String,
    auth_enabled: bool,
    admin_enabled: bool,
    publishing_enabled: bool,
    registries: Vec<RegistryStatus>,
}

#[derive(Debug, Serialize)]
struct RegistryStatus {
    ecosystem: &'static str,
    configured: bool,
    enabled: bool,
    compiled: bool,
    url: Option<String>,
    artifact_url: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct PackageQuery {
    ecosystem: Ecosystem,
}

#[derive(Debug, serde::Deserialize)]
struct VersionsQuery {
    ecosystem: Ecosystem,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct MetadataQuery {
    ecosystem: Ecosystem,
    name: String,
    version: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/status", get(status))
        .route("/config", get(config))
        .route("/registries", get(registries))
        .route("/packages", get(packages))
        .route("/versions", get(versions))
        .route("/metadata", get(metadata))
        .route("/metrics", get(metrics))
}

async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers)?;
    Ok(Json(AdminStatus {
        version: env!("CARGO_PKG_VERSION"),
        storage_backend: state.config.storage.backend.clone(),
        auth_enabled: state.config.auth.enabled,
        admin_enabled: state.config.admin.enabled,
        publishing_enabled: state.config.publishing.enabled,
        registries: registry_statuses(&state),
    }))
}

async fn config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers)?;
    Ok(Json(state.config.redacted_value()))
}

async fn registries(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers)?;
    Ok(Json(registry_statuses(&state)))
}

async fn packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PackageQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers)?;
    let packages = state
        .package_service
        .list_packages(query.ecosystem)
        .await
        .map_err(map_admin_error)?;
    let mut names = packages
        .into_iter()
        .map(|package| package.as_str().to_string())
        .collect::<Vec<_>>();
    names.sort();
    Ok(Json(names))
}

async fn versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VersionsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers)?;
    let name = PackageName::new(query.name);
    let versions = state
        .package_service
        .list_versions(query.ecosystem, &name)
        .await
        .map_err(map_admin_error)?;
    Ok(Json(versions))
}

async fn metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MetadataQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers)?;
    let name = PackageName::new(query.name);
    let metadata = state
        .package_service
        .get_version_metadata(query.ecosystem, &name, &query.version)
        .await
        .map_err(map_admin_error)?;
    Ok(Json(metadata))
}

async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers)?;
    Ok(Json(state.statistics_service.statistics()))
}

fn authorize_admin(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if !state.config.admin.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            "admin API is not enabled".to_string(),
        ));
    }

    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    if let Some(token) = token
        && state.config.authorize_admin_token(token)
    {
        return Ok(());
    }

    Err((
        StatusCode::UNAUTHORIZED,
        "missing or invalid admin bearer token".to_string(),
    ))
}

fn map_admin_error(err: starmetal_core::error::StarmetalError) -> (StatusCode, String) {
    tracing::warn!(error = %err, "admin API request failed");
    match err {
        starmetal_core::error::StarmetalError::PackageNotFound { .. }
        | starmetal_core::error::StarmetalError::VersionNotFound { .. }
        | starmetal_core::error::StarmetalError::ArtifactNotFound(_) => {
            (StatusCode::NOT_FOUND, err.to_string())
        }
        starmetal_core::error::StarmetalError::PolicyViolation(_) => {
            (StatusCode::FORBIDDEN, err.to_string())
        }
        starmetal_core::error::StarmetalError::Adapter(_) => {
            (StatusCode::BAD_REQUEST, err.to_string())
        }
        starmetal_core::error::StarmetalError::Publish(_) => {
            (StatusCode::CONFLICT, err.to_string())
        }
        starmetal_core::error::StarmetalError::Upstream(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream registry request failed".to_string(),
        ),
        starmetal_core::error::StarmetalError::Config(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server configuration error".to_string(),
        ),
        starmetal_core::error::StarmetalError::Storage(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage operation failed".to_string(),
        ),
        starmetal_core::error::StarmetalError::IntegrityError { .. } => (
            StatusCode::BAD_GATEWAY,
            "upstream artifact integrity check failed".to_string(),
        ),
        starmetal_core::error::StarmetalError::SchemaValidation(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream registry response failed validation".to_string(),
        ),
        starmetal_core::error::StarmetalError::Lockfile(_)
        | starmetal_core::error::StarmetalError::ConfigNotFound(_)
        | starmetal_core::error::StarmetalError::Io(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal starmetal error".to_string(),
        ),
        starmetal_core::error::StarmetalError::Toml(_)
        | starmetal_core::error::StarmetalError::Json(_) => (
            StatusCode::BAD_REQUEST,
            "invalid request or registry payload".to_string(),
        ),
    }
}

fn registry_statuses(state: &AppState) -> Vec<RegistryStatus> {
    registry_specs()
        .into_iter()
        .map(|(ecosystem, key, compiled)| {
            let upstream = state.config.upstream.get(key);
            RegistryStatus {
                ecosystem,
                configured: upstream.is_some(),
                enabled: upstream.map(|config| config.enabled).unwrap_or(false),
                compiled,
                url: upstream.map(|config| config.url.clone()),
                artifact_url: upstream.and_then(|config| config.artifact_url.clone()),
            }
        })
        .collect()
}

fn registry_specs() -> Vec<(&'static str, &'static str, bool)> {
    vec![
        ("pypi", "pypi", cfg!(feature = "pypi")),
        ("npm", "npm", cfg!(feature = "npm")),
        ("cargo", "cargo", cfg!(feature = "cargo-registry")),
        ("hex", "hex", cfg!(feature = "hex")),
        ("maven", "maven", cfg!(feature = "maven")),
        ("rubygems", "rubygems", cfg!(feature = "rubygems")),
        ("nuget", "nuget", cfg!(feature = "nuget")),
        ("pub", "pub", cfg!(feature = "pub")),
    ]
}
