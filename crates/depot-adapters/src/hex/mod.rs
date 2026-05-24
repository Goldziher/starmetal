//! Hex.pm registry protocol adapter.
//!
//! Provides an axum router that translates Hex HTTP API requests into
//! `PackageService` trait calls, and an upstream client for fetching
//! packages from hex.pm or any Hex-compatible registry.

pub mod models;
pub mod proto;
pub mod upstream;

use std::sync::Arc;

use ahash::AHashMap;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use depot_core::config::Config;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::{PackageService, PublishingService};
use depot_core::publishing::{PublishRequest, PublishedArtifact, TokenScope};
use depot_core::registry::hex::{HexMeta, HexPackage, HexRelease};
use prost::Message;
use sha2::Digest;

use self::upstream::HexUpstreamClient;
use crate::archive;

/// Trait for extracting Hex-specific state from application state.
///
/// The server crate implements this on its `AppState` to bridge the adapter
/// to the service layer and upstream client without creating a circular dependency.
pub trait HasHexState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
    fn hex_upstream(&self) -> &Arc<HexUpstreamClient>;
}

/// Build the Hex adapter router.
///
/// Mount this under `/hex` in the top-level application router.
pub fn router<S: HasHexState>() -> Router<S> {
    Router::new()
        .route("/api/packages/{name}", get(package_metadata::<S>))
        .route("/api/packages", post(publish_package::<S>))
        .route("/packages/{name}", get(registry_entry::<S>))
        .route("/tarballs/{tarball}", get(download_tarball::<S>))
}

async fn publish_package<S: HasHexState>(
    State(state): State<S>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let metadata = archive::parse_hex_tarball(&body).map_err(|err| map_error(&err))?;
    let name = PackageName::new(metadata.name.to_ascii_lowercase());
    authorize_publish(&state, &headers, &name)?;
    let filename = format!("{}-{}.tar", name.as_str(), metadata.version);
    let sha256 = hex::encode(sha2::Sha256::digest(&body));
    let mut upstream_hashes = AHashMap::new();
    upstream_hashes.insert("sha256".to_string(), sha256.clone());
    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::Hex,
            name: name.clone(),
            version: metadata.version.clone(),
            license: metadata.license.clone(),
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
    store_hex_metadata(
        state.package_service().as_ref(),
        &name,
        &metadata.version,
        metadata.license,
        &sha256,
    )
    .await?;
    Ok((StatusCode::CREATED, "created"))
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
            .unwrap_or(build_local_package(service.as_ref(), &name).await?);

        if let Ok(raw) = serde_json::to_vec(&upstream_package) {
            let _ = service
                .put_raw_upstream(Ecosystem::Hex, &name, bytes::Bytes::from(raw))
                .await;
        }

        upstream_package
    };

    // Build response with URLs rewritten to point through depot
    validate_package_metadata(service.as_ref(), &name, &package)
        .await
        .map_err(|err| map_error(&err))?;
    let response = models::build_package_response_from_cached(&name, &package);

    let body = serde_json::to_string(&response)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(([(header::CONTENT_TYPE, "application/json")], body))
}

async fn validate_package_metadata(
    service: &dyn PackageService,
    name: &PackageName,
    package: &depot_core::registry::hex::HexPackage,
) -> Result<(), DepotError> {
    for release in &package.releases {
        if let Some(metadata) = models::hex_release_to_metadata(name, package, &release.version) {
            service.validate_metadata(&metadata).await?;
        }
    }
    Ok(())
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
    let package_name = PackageName::new(name.clone());
    let service = state.package_service();
    let bytes = if let Some(cached) = service
        .get_raw_upstream(
            Ecosystem::Hex,
            &PackageName::new(format!("registry/{name}")),
        )
        .await
        .map_err(|err| map_error(&err))?
    {
        cached
    } else {
        let fetched = state
            .hex_upstream()
            .fetch_registry_entry(package_name.as_str())
            .await
            .map_err(|err| map_error(&err))?;
        service
            .put_raw_upstream(
                Ecosystem::Hex,
                &PackageName::new(format!("registry/{name}")),
                fetched.clone(),
            )
            .await
            .map_err(|err| map_error(&err))?;
        fetched
    };

    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes))
}

async fn build_local_package(
    service: &dyn PackageService,
    name: &PackageName,
) -> Result<HexPackage, (StatusCode, String)> {
    let versions = service
        .list_versions(Ecosystem::Hex, name)
        .await
        .map_err(|err| map_error(&err))?;
    Ok(HexPackage {
        name: name.as_str().to_string(),
        url: None,
        html_url: None,
        docs_html_url: None,
        meta: None,
        releases: versions
            .into_iter()
            .map(|version| HexRelease {
                version: version.version.clone(),
                url: format!("/hex/tarballs/{}-{}.tar", name.as_str(), version.version),
                has_docs: false,
                inserted_at: None,
                updated_at: None,
                retirement: None,
            })
            .collect(),
        inserted_at: None,
        updated_at: None,
    })
}

async fn store_hex_metadata(
    service: &dyn PackageService,
    name: &PackageName,
    version: &str,
    license: Option<String>,
    sha256: &str,
) -> Result<(), (StatusCode, String)> {
    let package = HexPackage {
        name: name.as_str().to_string(),
        url: None,
        html_url: None,
        docs_html_url: None,
        meta: license.map(|license| HexMeta {
            description: None,
            licenses: vec![license],
            links: None,
            maintainers: Vec::new(),
        }),
        releases: vec![HexRelease {
            version: version.to_string(),
            url: format!("/hex/tarballs/{}-{version}.tar", name.as_str()),
            has_docs: false,
            inserted_at: None,
            updated_at: None,
            retirement: None,
        }],
        inserted_at: None,
        updated_at: None,
    };
    service
        .put_raw_upstream(
            Ecosystem::Hex,
            name,
            Bytes::from(
                serde_json::to_vec(&package)
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            ),
        )
        .await
        .map_err(|err| map_error(&err))?;

    let checksum =
        hex::decode(sha256).map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let package_proto = proto::Package {
        name: name.as_str().to_string(),
        repository: "hexpm".to_string(),
        releases: vec![proto::Release {
            version: version.to_string(),
            inner_checksum: checksum.clone(),
            outer_checksum: Some(checksum),
        }],
    };
    let mut payload = Vec::new();
    package_proto
        .encode(&mut payload)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let signed = proto::Signed {
        payload,
        signature: None,
    };
    let mut signed_bytes = Vec::new();
    signed
        .encode(&mut signed_bytes)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    service
        .put_raw_upstream(
            Ecosystem::Hex,
            &PackageName::new(format!("registry/{}", name.as_str())),
            Bytes::from(signed_bytes),
        )
        .await
        .map_err(|err| map_error(&err))
}

fn authorize_publish<S: HasHexState>(
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
        .or_else(|| {
            headers
                .get("x-hex-api-key")
                .and_then(|value| value.to_str().ok())
        })
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "missing publishing token".to_string(),
            )
        })?;
    if state
        .config()
        .authorize_publish_token(token, TokenScope::Publish, Ecosystem::Hex, name)
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "publishing token is not authorized for this package".to_string(),
        ))
    }
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
        DepotError::Adapter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        DepotError::Publish(_) => (StatusCode::CONFLICT, err.to_string()),
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
