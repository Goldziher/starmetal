use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde::Serialize;

use crate::state::AppState;
use starmetal_authz::default_namespace;
use starmetal_core::authz::{Action, Authorizer, Resource};
use starmetal_core::content::ContentMaintenance;
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName};
use starmetal_core::supply_chain::{IngestQuarantine, QuarantineOrigin, QuarantineReview, SbomFormat, SbomIndex};

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

#[derive(Debug, serde::Deserialize)]
struct SbomQuery {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    filename: String,
}

#[derive(Debug, serde::Deserialize)]
struct SbomDocumentQuery {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    filename: String,
    format: SbomFormat,
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
        .route("/quarantine", get(quarantine_list))
        .route("/quarantine/{digest}/promote", post(quarantine_promote))
        .route("/quarantine/{digest}/reject", post(quarantine_reject))
        .route("/gc", post(trigger_gc))
        .route("/retention", post(trigger_retention))
        .route("/sbom", get(sbom_list))
        .route("/sbom/document", get(sbom_document))
}

async fn status(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    Ok(Json(AdminStatus {
        version: env!("CARGO_PKG_VERSION"),
        storage_backend: state.config.storage.backend.clone(),
        auth_enabled: state.config.auth.enabled,
        admin_enabled: state.config.admin.enabled,
        publishing_enabled: state.config.publishing.enabled,
        registries: registry_statuses(&state),
    }))
}

async fn config(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    Ok(Json(state.config.redacted_value()))
}

async fn registries(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    Ok(Json(registry_statuses(&state)))
}

async fn packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PackageQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
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
    authorize_admin(&state, &headers).await?;
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
    authorize_admin(&state, &headers).await?;
    let name = PackageName::new(query.name);
    let metadata = state
        .package_service
        .get_version_metadata(query.ecosystem, &name, &query.version)
        .await
        .map_err(map_admin_error)?;
    Ok(Json(metadata))
}

async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    Ok(Json(state.statistics_service.statistics()))
}

async fn quarantine_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    // Absent handle (no scanner attached) means nothing can be quarantined: an empty list, not 404.
    let records = match &state.quarantine {
        Some(quarantine) => quarantine.list_quarantine().await.map_err(map_admin_error)?,
        None => Vec::new(),
    };
    Ok(Json(records))
}

async fn quarantine_promote(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(digest): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    validate_quarantine_digest(&digest)?;
    // An ingest-origin hold promotes by completing the deferred publish (not merely flipping the
    // record state), so it routes to the ingest handle; serve-origin holds are unchanged.
    let record = if is_ingest_hold(&state, &digest).await? {
        ingest_quarantine_handle(&state)?
            .promote_ingest(&digest)
            .await
            .map_err(map_admin_error)?
    } else {
        quarantine_handle(&state)?
            .promote_quarantine(&digest)
            .await
            .map_err(map_admin_error)?
    };
    Ok(Json(record))
}

async fn quarantine_reject(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(digest): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    validate_quarantine_digest(&digest)?;
    // An ingest-origin hold rejects by purging the parked publish bytes; serve-origin is unchanged.
    let record = if is_ingest_hold(&state, &digest).await? {
        ingest_quarantine_handle(&state)?
            .reject_ingest(&digest)
            .await
            .map_err(map_admin_error)?
    } else {
        quarantine_handle(&state)?
            .reject_quarantine(&digest)
            .await
            .map_err(map_admin_error)?
    };
    Ok(Json(record))
}

async fn trigger_gc(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    let maintenance = content_maintenance_handle(&state)?;
    let report = maintenance.gc_sweep().await.map_err(map_admin_error)?;
    Ok(Json(report))
}

async fn trigger_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    let maintenance = content_maintenance_handle(&state)?;
    let report = maintenance.retention_sweep().await.map_err(map_admin_error)?;
    Ok(Json(report))
}

async fn sbom_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SbomQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    let artifact = validated_artifact(query.ecosystem, query.name, query.version, query.filename)?;
    let sbom = sbom_handle(&state)?;
    let records = sbom.list_sboms(&artifact).await.map_err(map_admin_error)?;
    Ok(Json(records))
}

async fn sbom_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SbomDocumentQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    authorize_admin(&state, &headers).await?;
    let artifact = validated_artifact(query.ecosystem, query.name, query.version, query.filename)?;
    let sbom = sbom_handle(&state)?;
    let document = sbom
        .get_sbom_document(&artifact, query.format)
        .await
        .map_err(map_admin_error)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "no SBOM document for this artifact and format".to_string(),
        ))?;
    Ok((
        [(header::CONTENT_TYPE, starmetal_core::sbom::media_type(query.format))],
        document,
    ))
}

/// The SBOM retrieval handle, or a 404 when SBOM generation is disabled (`supply_chain.sbom.enabled`
/// unset), mirroring the other optional-handle accessors.
fn sbom_handle(state: &AppState) -> Result<&std::sync::Arc<dyn SbomIndex>, (StatusCode, String)> {
    state
        .sbom
        .as_ref()
        .ok_or((StatusCode::NOT_FOUND, "SBOM generation is not enabled".to_string()))
}

/// Build an [`ArtifactId`] from query parameters and validate its coordinate, rejecting a malformed
/// coordinate (e.g. a path-traversal name/version/filename) as a 400 before any storage-key use.
fn validated_artifact(
    ecosystem: Ecosystem,
    name: String,
    version: String,
    filename: String,
) -> Result<ArtifactId, (StatusCode, String)> {
    let artifact = ArtifactId {
        ecosystem,
        name: PackageName::new(name),
        version,
        filename,
    };
    artifact
        .validated_storage_key()
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    Ok(artifact)
}

/// The metadata-maintenance handle, or a 404 when `metadata.enabled` is unset (the content model
/// is not attached and there is nothing to sweep).
fn content_maintenance_handle(
    state: &AppState,
) -> Result<&std::sync::Arc<dyn ContentMaintenance>, (StatusCode, String)> {
    state
        .content_maintenance
        .as_ref()
        .ok_or((StatusCode::NOT_FOUND, "metadata maintenance is not enabled".to_string()))
}

/// Reject a digest path parameter that is not a well-formed blake3 hex digest.
///
/// `Path<String>` percent-decodes the raw URL segment, so without this check a crafted value such as
/// `%2e%2e%2f` would decode to `../` and reach `quarantine_record_key` verbatim (CWE-22 path
/// traversal against the object store). Validating here, before the digest is used for anything,
/// stops that at the boundary; `transition_quarantine` in `starmetal-service` repeats the same check
/// as defense in depth.
fn validate_quarantine_digest(digest: &str) -> Result<(), (StatusCode, String)> {
    if starmetal_core::integrity::is_blake3_hex(digest) {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "invalid blake3 digest".to_string()))
    }
}

/// The quarantine review handle, or a 404 when `supply_chain.enabled` is unset (no scanner is
/// attached and the workflow is inactive).
fn quarantine_handle(state: &AppState) -> Result<&std::sync::Arc<dyn QuarantineReview>, (StatusCode, String)> {
    state.quarantine.as_ref().ok_or((
        StatusCode::NOT_FOUND,
        "supply-chain quarantine is not enabled".to_string(),
    ))
}

/// The ingest-time quarantine handle, or a 404 when no scanner is attached (the workflow is
/// inactive), mirroring [`quarantine_handle`].
fn ingest_quarantine_handle(state: &AppState) -> Result<&std::sync::Arc<dyn IngestQuarantine>, (StatusCode, String)> {
    state.ingest_quarantine.as_ref().ok_or((
        StatusCode::NOT_FOUND,
        "supply-chain quarantine is not enabled".to_string(),
    ))
}

/// Whether the quarantine record for `digest` is an ingest-origin hold, so the admin promote/reject
/// handlers can route it to the ingest workflow (which completes or purges a deferred publish)
/// rather than the serve workflow (which only flips record state). `false` when quarantine is
/// disabled or no such record exists — the serve path then reports not-found consistently.
async fn is_ingest_hold(state: &AppState, digest: &str) -> Result<bool, (StatusCode, String)> {
    let Some(quarantine) = &state.quarantine else {
        return Ok(false);
    };
    let records = quarantine.list_quarantine().await.map_err(map_admin_error)?;
    Ok(records
        .iter()
        .any(|record| record.subject_digest == digest && record.origin == QuarantineOrigin::Ingest))
}

async fn authorize_admin(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if !state.config.admin.enabled {
        return Err((StatusCode::NOT_FOUND, "admin API is not enabled".to_string()));
    }

    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    // Authenticate the bearer token to a principal, then require the config-plane `Admin` action
    // via the injected Authorizer (ADR-0022). The current config is namespace-less, so the request
    // targets the whole default namespace. Admin-migrated tokens carry a `RepositoryAdmin` grant;
    // flat and publish tokens do not, so they are denied here exactly as before. ~keep
    if let Some(token) = token
        && let Some(principal) = state.authorizer.authenticate(token)
    {
        let resource = Resource {
            namespace: default_namespace(),
            ecosystem: None,
            repository: None,
            coordinate: None,
        };
        if let Ok(decision) = state.authorizer.authorize(&principal, Action::Admin, &resource).await
            && decision.is_allowed()
        {
            // Audit every admin action (OWASP A09): rare and high-value, so logged at info. ~keep
            tracing::info!(target: "starmetal::audit", principal = %principal.id(), action = "admin", decision = "allow", "admin action authorized");
            return Ok(());
        }
        tracing::warn!(target: "starmetal::audit", principal = %principal.id(), action = "admin", decision = "deny", "admin action denied by authorizer");
    } else {
        tracing::warn!(target: "starmetal::audit", action = "admin", decision = "deny", "unauthenticated admin request");
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
        | starmetal_core::error::StarmetalError::ArtifactNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        starmetal_core::error::StarmetalError::PolicyViolation(_) => (StatusCode::FORBIDDEN, err.to_string()),
        starmetal_core::error::StarmetalError::Adapter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        starmetal_core::error::StarmetalError::Update(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "update operation failed".to_string())
        }
        starmetal_core::error::StarmetalError::Publish(_) => (StatusCode::CONFLICT, err.to_string()),
        starmetal_core::error::StarmetalError::Upstream(_) => {
            (StatusCode::BAD_GATEWAY, "upstream registry request failed".to_string())
        }
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
        starmetal_core::error::StarmetalError::Toml(_) | starmetal_core::error::StarmetalError::Json(_) => (
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
