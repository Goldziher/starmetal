//! npm registry protocol adapter.
//!
//! Provides an axum router that translates npm registry API requests into
//! `PackageService` trait calls, and an upstream client for fetching
//! packages from registry.npmjs.org or any npm-compatible registry.

pub mod models;
pub mod upstream;

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use sha2::Digest;
use starmetal_core::config::Config;
use starmetal_core::error::StarmetalError;
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName};
use starmetal_core::ports::{PackageService, PublishingService};
use starmetal_core::publishing::{ProtocolMetadata, PublishRequest, PublishedArtifact, TokenScope};

use self::upstream::NpmUpstreamClient;

/// Trait for extracting npm-specific state from application state.
///
/// The server crate implements this on its `AppState` to bridge the adapter
/// to the service layer and upstream client without creating a circular dependency.
pub trait HasNpmState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
    fn npm_upstream(&self) -> &Arc<NpmUpstreamClient>;
}

/// Build the npm adapter router.
///
/// Mount this under `/npm` in the top-level application router.
pub fn router<S: HasNpmState>() -> Router<S> {
    Router::new()
        .route(
            "/{package}",
            get(package_metadata::<S>).put(publish_package::<S>),
        )
        .route(
            "/@{scope}/{name}",
            get(scoped_package_metadata::<S>).put(publish_scoped_package::<S>),
        )
        .route("/{package}/-/{filename}", get(download_tarball::<S>))
        .route(
            "/@{scope}/{name}/-/{filename}",
            get(download_scoped_tarball::<S>),
        )
}

async fn publish_package<S: HasNpmState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path(package): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let name = PackageName::new(package);
    publish_packument(state, &headers, name, payload).await
}

async fn publish_scoped_package<S: HasNpmState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path((scope, name)): Path<(String, String)>,
    Json(payload): Json<serde_json::Value>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let full_name = PackageName::new(format!("@{scope}/{name}"));
    publish_packument(state, &headers, full_name, payload).await
}

async fn publish_packument<S: HasNpmState>(
    state: S,
    headers: &HeaderMap,
    name: PackageName,
    payload: serde_json::Value,
) -> Result<axum::response::Response, (StatusCode, String)> {
    authorize_publish(&state, headers, &name)?;
    if !payload.is_object() {
        return Err((
            StatusCode::BAD_REQUEST,
            "npm publish payload must be an object".to_string(),
        ));
    }
    let versions = payload["versions"].as_object().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing npm versions object".to_string(),
        )
    })?;
    let latest = match payload.get("dist-tags") {
        Some(tags) => {
            let tags = tags.as_object().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "npm dist-tags must be an object".to_string(),
                )
            })?;
            match tags.get("latest") {
                Some(value) => Some(value.as_str().ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        "npm dist-tags.latest must be a string".to_string(),
                    )
                })?),
                None => None,
            }
        }
        None => None,
    };
    let version = latest
        .map(str::to_string)
        .or_else(|| versions.keys().next().cloned())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing npm version".to_string()))?;
    let version_payload = versions.get(&version).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing npm version metadata".to_string(),
        )
    })?;
    let (filename, data) = attachment(&payload).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing npm tarball attachment".to_string(),
        )
    })?;
    let upstream_hashes = validated_npm_dist_hashes(&data, version_payload)?;

    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::Npm,
            name: name.clone(),
            version: version.clone(),
            license: version_payload["license"].as_str().map(str::to_string),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename,
                data,
                upstream_hashes,
            }],
            protocol_metadata: ProtocolMetadata::Npm {
                packument: version_payload.clone(),
            },
            allow_overwrite: state.config().publishing.allow_overwrite,
            allow_shadowing: state.config().publishing.allow_shadowing,
        })
        .await
        .map_err(|err| map_error(&err))?;
    let sanitized_packument = sanitized_published_packument(payload, &version);
    state
        .package_service()
        .put_raw_upstream(
            Ecosystem::Npm,
            &name,
            bytes::Bytes::from(
                serde_json::to_vec(&sanitized_packument)
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            ),
        )
        .await
        .map_err(|err| map_error(&err))?;

    Ok((
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&serde_json::json!({
            "ok": true,
            "id": name.as_str(),
            "rev": format!("starmetal-{version}")
        }))
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
    )
        .into_response())
}

fn sanitized_published_packument(
    mut payload: serde_json::Value,
    latest_version: &str,
) -> serde_json::Value {
    if let Some(object) = payload.as_object_mut() {
        object.remove("_attachments");
        let dist_tags = object
            .entry("dist-tags".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if let Some(tags) = dist_tags.as_object_mut() {
            tags.entry("latest".to_string())
                .or_insert_with(|| serde_json::Value::String(latest_version.to_string()));
        } else {
            *dist_tags = serde_json::json!({ "latest": latest_version });
        }
    }
    payload
}

fn validated_npm_dist_hashes(
    data: &bytes::Bytes,
    version_payload: &serde_json::Value,
) -> Result<ahash::AHashMap<String, String>, (StatusCode, String)> {
    let mut upstream_hashes = ahash::AHashMap::new();
    if let Some(shasum) = version_payload["dist"]["shasum"].as_str() {
        let actual = hex::encode(sha1::Sha1::digest(data));
        if !actual.eq_ignore_ascii_case(shasum) {
            return Err((
                StatusCode::BAD_REQUEST,
                "npm dist.shasum does not match uploaded tarball".to_string(),
            ));
        }
        upstream_hashes.insert("sha1".to_string(), shasum.to_string());
    }
    if let Some(integrity) = version_payload["dist"]["integrity"].as_str() {
        verify_npm_integrity(data, integrity)?;
        upstream_hashes.insert("integrity".to_string(), integrity.to_string());
    }
    Ok(upstream_hashes)
}

fn verify_npm_integrity(data: &bytes::Bytes, integrity: &str) -> Result<(), (StatusCode, String)> {
    let mut saw_supported_hash = false;
    for token in integrity.split_whitespace() {
        let hash_token = token.split_once('?').map_or(token, |(hash, _options)| hash);
        let Some((algorithm, expected)) = hash_token.split_once('-') else {
            continue;
        };
        let actual = match algorithm {
            "sha512" => BASE64_STANDARD.encode(sha2::Sha512::digest(data)),
            "sha384" => BASE64_STANDARD.encode(sha2::Sha384::digest(data)),
            "sha256" => BASE64_STANDARD.encode(sha2::Sha256::digest(data)),
            "sha1" => BASE64_STANDARD.encode(sha1::Sha1::digest(data)),
            _ => continue,
        };
        saw_supported_hash = true;
        if actual == expected {
            return Ok(());
        }
    }
    let message = if saw_supported_hash {
        "npm dist.integrity does not match uploaded tarball"
    } else {
        "npm dist.integrity does not contain a supported hash"
    };
    Err((StatusCode::BAD_REQUEST, message.to_string()))
}

/// GET /{package} -- return packument JSON for an unscoped package.
async fn package_metadata<S: HasNpmState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path(package): Path<String>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let name = PackageName::new(package);
    let base_url = crate::public_base_url(state.config(), &headers);
    serve_packument(state, &name, &base_url).await
}

/// GET /@{scope}/{name} -- return packument JSON for a scoped package.
async fn scoped_package_metadata<S: HasNpmState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path((scope, name)): Path<(String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let full_name = PackageName::new(format!("@{scope}/{name}"));
    let base_url = crate::public_base_url(state.config(), &headers);
    serve_packument(state, &full_name, &base_url).await
}

/// Shared logic for serving packument responses.
///
/// Checks starmetal's storage first. On miss, fetches from upstream, stores the
/// raw packument in storage, then serves it. The upstream client's memory
/// cache is an optimization — storage is the source of truth.
async fn serve_packument<S: HasNpmState>(
    state: S,
    name: &PackageName,
    base_url: &str,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let service = state.package_service();

    // Try storage first — starmetal owns this data once fetched
    let mut packument: serde_json::Value = if let Some(raw) = service
        .get_raw_upstream(Ecosystem::Npm, name)
        .await
        .map_err(|err| map_error(&err))?
    {
        serde_json::from_slice(&raw)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        // Cache miss — fetch from upstream
        let _versions = service
            .list_versions(Ecosystem::Npm, name)
            .await
            .map_err(|err| map_error(&err))?;

        let upstream_packument = state
            .npm_upstream()
            .get_cached_packument(name)
            .await
            .unwrap_or(build_local_packument(service.as_ref(), name, base_url).await?);

        // Persist to storage — this is now starmetal's data
        let raw = serde_json::to_vec(&upstream_packument)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let _ = service
            .put_raw_upstream(Ecosystem::Npm, name, bytes::Bytes::from(raw))
            .await;

        upstream_packument
    };

    // Rewrite tarball URLs to point through starmetal
    validate_packument_metadata(service.as_ref(), name, &packument)
        .await
        .map_err(|err| map_error(&err))?;
    models::rewrite_packument_tarball_urls(&mut packument, base_url);

    let body = serde_json::to_string(&packument)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

async fn build_local_packument(
    service: &dyn PackageService,
    name: &PackageName,
    base_url: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let versions = service
        .list_versions(Ecosystem::Npm, name)
        .await
        .map_err(|err| map_error(&err))?;
    let mut version_map = serde_json::Map::new();
    for version in &versions {
        let metadata = service
            .get_version_metadata(Ecosystem::Npm, name, &version.version)
            .await
            .map_err(|err| map_error(&err))?;
        let Some(artifact) = metadata.artifacts.first() else {
            continue;
        };
        let mut version_payload = metadata
            .protocol_metadata
            .as_ref()
            .and_then(|metadata| match metadata {
                ProtocolMetadata::Npm { packument } => packument.as_object().cloned(),
                _ => None,
            })
            .unwrap_or_default();
        version_payload
            .entry("name".to_string())
            .or_insert_with(|| serde_json::Value::String(name.as_str().to_string()));
        version_payload
            .entry("version".to_string())
            .or_insert_with(|| serde_json::Value::String(version.version.clone()));
        if let Some(license) = &metadata.license {
            version_payload
                .entry("license".to_string())
                .or_insert_with(|| serde_json::Value::String(license.clone()));
        }
        let dist = version_payload
            .entry("dist".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if !dist.is_object() {
            *dist = serde_json::json!({});
        }
        dist["tarball"] = serde_json::Value::String(format!(
            "{base_url}/npm/{}/-/{}",
            name.as_str(),
            artifact.filename
        ));
        if let Some(shasum) = artifact.upstream_hashes.get("sha1") {
            dist["shasum"] = serde_json::Value::String(shasum.clone());
        }
        if let Some(integrity) = artifact.upstream_hashes.get("integrity") {
            dist["integrity"] = serde_json::Value::String(integrity.clone());
        }
        version_map.insert(
            version.version.clone(),
            serde_json::Value::Object(version_payload),
        );
    }
    let latest = versions.last().map(|version| version.version.clone());
    Ok(serde_json::json!({
        "_id": name.as_str(),
        "name": name.as_str(),
        "dist-tags": latest.map(|version| serde_json::json!({ "latest": version })).unwrap_or_else(|| serde_json::json!({})),
        "versions": version_map,
    }))
}

async fn validate_packument_metadata(
    service: &dyn PackageService,
    name: &PackageName,
    packument: &serde_json::Value,
) -> Result<(), StarmetalError> {
    for version in models::extract_version_infos(packument) {
        if let Some(metadata) = models::extract_version_metadata(name, &version.version, packument)
        {
            service.validate_metadata(&metadata).await?;
        }
    }
    Ok(())
}

/// GET /{package}/-/{filename} -- download an unscoped package tarball.
async fn download_tarball<S: HasNpmState>(
    State(state): State<S>,
    Path((package, filename)): Path<(String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let name = PackageName::new(package);
    serve_tarball(state, &name, &filename).await
}

/// GET /@{scope}/{name}/-/{filename} -- download a scoped package tarball.
async fn download_scoped_tarball<S: HasNpmState>(
    State(state): State<S>,
    Path((scope, name, filename)): Path<(String, String, String)>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let full_name = PackageName::new(format!("@{scope}/{name}"));
    serve_tarball(state, &full_name, &filename).await
}

/// Shared logic for serving tarball downloads.
async fn serve_tarball<S: HasNpmState>(
    state: S,
    name: &PackageName,
    filename: &str,
) -> Result<axum::response::Response, (StatusCode, String)> {
    // Extract version from filename: {name}-{version}.tgz
    let version = extract_version_from_filename(name.as_str(), filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "invalid filename format".to_string(),
        )
    })?;

    let artifact_id = ArtifactId {
        ecosystem: Ecosystem::Npm,
        name: name.clone(),
        version,
        filename: filename.to_string(),
    };

    let data = state
        .package_service()
        .get_artifact(&artifact_id)
        .await
        .map_err(|err| map_error(&err))?;

    let disposition = format!("attachment; filename=\"{filename}\"");
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        data,
    )
        .into_response())
}

/// Extract version string from an npm tarball filename.
///
/// Expected format: `{name}-{version}.tgz` where name may contain `@scope/`.
fn extract_version_from_filename(name: &str, filename: &str) -> Option<String> {
    let stripped = filename.strip_suffix(".tgz")?;
    let package_basename = name.rsplit_once('/').map_or(name, |(_, basename)| basename);
    let prefix = format!("{package_basename}-");
    let version = stripped.strip_prefix(&prefix)?;
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

fn attachment(payload: &serde_json::Value) -> Option<(String, bytes::Bytes)> {
    let (filename, attachment) = payload["_attachments"].as_object()?.iter().next()?;
    let encoded = attachment["data"].as_str()?;
    let decoded = BASE64_STANDARD.decode(encoded).ok()?;
    Some((filename.clone(), bytes::Bytes::from(decoded)))
}

fn authorize_publish<S: HasNpmState>(
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
    let token = extract_write_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "missing publishing token".to_string(),
        )
    })?;
    if state
        .config()
        .authorize_publish_token(&token, TokenScope::Publish, Ecosystem::Npm, name)
    {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "publishing token is not authorized for this package".to_string(),
        ))
    }
}

fn extract_write_token(headers: &HeaderMap) -> Option<String> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    if let Some(token) = authorization.strip_prefix("Bearer ") {
        return Some(token.to_string());
    }
    authorization.strip_prefix("npm ").map(str::to_string)
}

/// Map `StarmetalError` variants to appropriate HTTP status codes.
fn map_error(err: &StarmetalError) -> (StatusCode, String) {
    tracing::warn!(error = %err, "npm adapter request failed");
    crate::map_public_error(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_extract_version_from_simple_filename() {
        assert_eq!(
            extract_version_from_filename("is-odd", "is-odd-3.0.1.tgz"),
            Some("3.0.1".to_string())
        );
    }

    #[test]
    fn should_extract_version_from_scoped_filename() {
        assert_eq!(
            extract_version_from_filename("@scope/pkg", "pkg-1.2.3.tgz"),
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn should_return_none_for_invalid_filename() {
        assert_eq!(
            extract_version_from_filename("is-odd", "not-a-match.tgz"),
            None
        );
        assert_eq!(extract_version_from_filename("is-odd", "is-odd-.tgz"), None);
        assert_eq!(
            extract_version_from_filename("is-odd", "is-odd-1.0.0.tar.gz"),
            None
        );
    }

    #[test]
    fn should_sanitize_malformed_dist_tags_without_panicking() {
        let payload = serde_json::json!({
            "name": "demo",
            "dist-tags": "bad",
            "_attachments": {
                "demo-1.0.0.tgz": { "data": "ZmFrZQ==" }
            }
        });

        let sanitized = sanitized_published_packument(payload, "1.0.0");

        assert!(sanitized.get("_attachments").is_none());
        assert_eq!(sanitized["dist-tags"]["latest"], "1.0.0");
    }

    #[test]
    fn should_reject_mismatched_npm_shasum() {
        let data = bytes::Bytes::from_static(b"package");
        let metadata = serde_json::json!({
            "dist": {
                "shasum": "0000000000000000000000000000000000000000"
            }
        });

        let err = validated_npm_dist_hashes(&data, &metadata).unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "npm dist.shasum does not match uploaded tarball");
    }

    #[test]
    fn should_accept_matching_npm_integrity() {
        let data = bytes::Bytes::from_static(b"package");
        let integrity = format!(
            "sha512-{}",
            BASE64_STANDARD.encode(sha2::Sha512::digest(&data))
        );
        let metadata = serde_json::json!({
            "dist": {
                "integrity": integrity
            }
        });

        let hashes = validated_npm_dist_hashes(&data, &metadata).unwrap();

        assert_eq!(
            hashes.get("integrity").map(String::as_str),
            metadata["dist"]["integrity"].as_str()
        );
    }
}
