//! Hex.pm registry protocol adapter.
//!
//! Provides an axum router that translates Hex HTTP API requests into
//! `PackageService` trait calls, and an upstream client for fetching
//! packages from hex.pm or any Hex-compatible registry.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::PackageService;

use self::upstream::HexUpstreamClient;

/// Trait for extracting Hex-specific state from application state.
///
/// The server crate implements this on its `AppState` to bridge the adapter
/// to the service layer and upstream client without creating a circular dependency.
pub trait HasHexState: Clone + Send + Sync + 'static {
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn hex_upstream(&self) -> &Arc<HexUpstreamClient>;
}

/// Build the Hex adapter router.
///
/// Mount this under `/hex` in the top-level application router.
pub fn router<S: HasHexState>() -> Router<S> {
    Router::new()
        .route("/api/packages/{name}", get(package_metadata::<S>))
        .route("/packages/{name}", get(registry_entry::<S>))
        .route("/tarballs/{tarball}", get(download_tarball::<S>))
}

/// GET /api/packages/{name} -- return Hex package metadata as JSON.
///
/// Triggers the caching lifecycle through `PackageService`, then builds
/// the response directly from the cached upstream `HexPackage` with
/// release URLs rewritten to point through depot.
async fn package_metadata<S: HasHexState>(
    State(state): State<S>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let name = PackageName::new(name);
    let service = state.package_service();

    // Storage is the source of truth
    let package: depot_core::registry::hex::HexPackage = if let Some(raw) = service
        .get_raw_upstream(Ecosystem::Hex, &name)
        .await
        .map_err(|err| map_error(&err))?
    {
        serde_json::from_slice(&raw)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        // Cache miss — fetch from upstream
        let _versions = service
            .list_versions(Ecosystem::Hex, &name)
            .await
            .map_err(|err| map_error(&err))?;

        let upstream_package = state
            .hex_upstream()
            .get_cached_package(&name)
            .await
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "package not cached after upstream fetch".to_string(),
                )
            })?;

        if let Ok(raw) = serde_json::to_vec(&upstream_package) {
            let _ = service
                .put_raw_upstream(Ecosystem::Hex, &name, bytes::Bytes::from(raw))
                .await;
        }

        upstream_package
    };

    // Build response with URLs rewritten to point through depot
    let response = models::build_package_response_from_cached(&name, &package);

    let body = serde_json::to_string(&response)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(([(header::CONTENT_TYPE, "application/json")], body))
}

/// GET /tarballs/{tarball} -- download a Hex tarball.
///
/// Parses `{tarball}` as `{name}-{version}.tar`, builds an `ArtifactId`,
/// and fetches the artifact bytes through `PackageService`.
async fn download_tarball<S: HasHexState>(
    State(state): State<S>,
    Path(tarball): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (name, version) = parse_tarball_name(&tarball).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid tarball name: {tarball}"),
        )
    })?;

    let artifact_id = ArtifactId {
        ecosystem: Ecosystem::Hex,
        name: PackageName::new(name),
        version: version.to_string(),
        filename: tarball.clone(),
    };

    let data = state
        .package_service()
        .get_artifact(&artifact_id)
        .await
        .map_err(|err| map_error(&err))?;

    let disposition = format!("attachment; filename=\"{tarball}\"");
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        data,
    ))
}

/// GET /packages/{name} -- serve protobuf registry entry for mix checksum verification.
///
/// Mix needs this endpoint to fetch checksums before installing tarballs. We proxy
/// the raw protobuf bytes from repo.hex.pm without parsing them.
async fn registry_entry<S: HasHexState>(
    State(state): State<S>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let bytes = state
        .hex_upstream()
        .fetch_registry_entry(&name)
        .await
        .map_err(|err| map_error(&err))?;

    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes))
}

/// Parse a Hex tarball filename into (name, version).
///
/// The format is `{name}-{version}.tar`. We strip the `.tar` suffix, then
/// scan from the END to find the last `-` followed by a digit. This correctly
/// handles hyphenated package names like `http-client-2.0.0.tar`.
fn parse_tarball_name(tarball: &str) -> Option<(&str, &str)> {
    let stem = tarball.strip_suffix(".tar")?;
    let bytes = stem.as_bytes();

    // Scan from end, find last hyphen followed by a digit
    for idx in (1..bytes.len()).rev() {
        if bytes[idx] == b'-' && bytes.get(idx + 1).is_some_and(|b| b.is_ascii_digit()) {
            return Some((&stem[..idx], &stem[idx + 1..]));
        }
    }
    None
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
    fn test_parse_tarball_name_simple() {
        assert_eq!(
            parse_tarball_name("jason-1.4.1.tar"),
            Some(("jason", "1.4.1"))
        );
    }

    #[test]
    fn test_parse_tarball_name_hyphenated_package() {
        assert_eq!(
            parse_tarball_name("plug-1.0.0.tar"),
            Some(("plug", "1.0.0"))
        );
    }

    #[test]
    fn test_parse_tarball_name_underscore() {
        assert_eq!(
            parse_tarball_name("my_package-2.0.0.tar"),
            Some(("my_package", "2.0.0"))
        );
    }

    #[test]
    fn test_parse_tarball_name_no_tar_suffix() {
        assert_eq!(parse_tarball_name("jason-1.4.1"), None);
    }

    #[test]
    fn test_parse_tarball_name_no_version() {
        assert_eq!(parse_tarball_name("jason.tar"), None);
    }

    #[test]
    fn test_parse_tarball_name_complex_version() {
        assert_eq!(
            parse_tarball_name("phoenix_html-4.1.1.tar"),
            Some(("phoenix_html", "4.1.1"))
        );
    }

    #[test]
    fn test_parse_tarball_name_hyphenated_multi_segment() {
        assert_eq!(
            parse_tarball_name("http-client-2.0.0.tar"),
            Some(("http-client", "2.0.0"))
        );
    }

    #[test]
    fn test_parse_tarball_name_underscore_hyphen_mix() {
        assert_eq!(
            parse_tarball_name("plug_cowboy-2.7.0.tar"),
            Some(("plug_cowboy", "2.7.0"))
        );
    }

    #[test]
    fn test_parse_tarball_name_digit_in_package_name() {
        assert_eq!(
            parse_tarball_name("db-2-pool-1.0.0.tar"),
            Some(("db-2-pool", "1.0.0"))
        );
    }
}
