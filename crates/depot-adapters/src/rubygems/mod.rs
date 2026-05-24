//! RubyGems Compact Index adapter.

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

use self::upstream::RubyGemsUpstreamClient;
use crate::archive;

pub trait HasRubyGemsState: Clone + Send + Sync + 'static {
    fn config(&self) -> &Arc<Config>;
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn publishing_service(&self) -> &Arc<dyn PublishingService>;
    fn rubygems_upstream(&self) -> &Arc<RubyGemsUpstreamClient>;
}

pub fn router<S: HasRubyGemsState>() -> Router<S> {
    Router::new()
        .route("/versions", get(versions::<S>))
        .route("/info/{gem}", get(info::<S>))
        .route("/gems/{filename}", get(gem::<S>))
        .route("/api/v1/gems", post(publish_gem::<S>))
}

async fn publish_gem<S: HasRubyGemsState>(
    State(state): State<S>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let metadata = archive::parse_rubygem(&body).map_err(|err| map_error(&err))?;
    let name = PackageName::new(metadata.name.to_ascii_lowercase());
    authorize_publish(&state, &headers, &name)?;
    let filename = format!("{}-{}.gem", name.as_str(), metadata.version);
    let sha256 = hex::encode(sha2::Sha256::digest(&body));
    let mut upstream_hashes = ahash::AHashMap::new();
    upstream_hashes.insert("sha256".to_string(), sha256.clone());
    state
        .publishing_service()
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::RubyGems,
            name: name.clone(),
            version: metadata.version.clone(),
            license: metadata.license,
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
    update_compact_index(
        state.package_service().as_ref(),
        &name,
        &metadata.version,
        &sha256,
    )
    .await?;
    Ok((StatusCode::CREATED, "created").into_response())
}

async fn versions<S: HasRubyGemsState>(
    State(state): State<S>,
) -> Result<Response, (StatusCode, String)> {
    let key = PackageName::new("_versions");
    serve_raw(state, key, "versions").await
}

async fn info<S: HasRubyGemsState>(
    State(state): State<S>,
    Path(gem): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let key = PackageName::new(format!("info/{gem}"));
    serve_raw(state, key, &format!("info/{gem}")).await
}

async fn serve_raw<S: HasRubyGemsState>(
    state: S,
    key: PackageName,
    path: &str,
) -> Result<Response, (StatusCode, String)> {
    let service = state.package_service();
    let data = if let Some(cached) = service
        .get_raw_upstream(Ecosystem::RubyGems, &key)
        .await
        .map_err(|err| map_error(&err))?
    {
        cached
    } else {
        let fetched = state
            .rubygems_upstream()
            .fetch_path(path)
            .await
            .map_err(|err| map_error(&err))?;
        service
            .put_raw_upstream(Ecosystem::RubyGems, &key, fetched.clone())
            .await
            .map_err(|err| map_error(&err))?;
        fetched
    };
    Ok(([(header::CONTENT_TYPE, "text/plain")], Body::from(data)).into_response())
}

async fn gem<S: HasRubyGemsState>(
    State(state): State<S>,
    Path(filename): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let (name, version) = parse_gem_filename(&filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid gem filename: {filename}"),
        )
    })?;
    let artifact_id = ArtifactId {
        ecosystem: Ecosystem::RubyGems,
        name: PackageName::new(name),
        version: version.to_string(),
        filename,
    };
    let data = state
        .package_service()
        .get_artifact(&artifact_id)
        .await
        .map_err(|err| map_error(&err))?;
    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        Body::from(data),
    )
        .into_response())
}

fn parse_gem_filename(filename: &str) -> Option<(&str, &str)> {
    let stem = filename.strip_suffix(".gem")?;
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

async fn update_compact_index(
    service: &dyn PackageService,
    name: &PackageName,
    version: &str,
    sha256: &str,
) -> Result<(), (StatusCode, String)> {
    let versions_key = PackageName::new("_versions");
    let mut versions = service
        .get_raw_upstream(Ecosystem::RubyGems, &versions_key)
        .await
        .map_err(|err| map_error(&err))?
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_else(|| "---\n".to_string());
    let versions_line = format!("{} {version}", name.as_str());
    if !versions.lines().any(|line| line == versions_line) {
        versions.push_str(&versions_line);
        versions.push('\n');
    }
    service
        .put_raw_upstream(Ecosystem::RubyGems, &versions_key, Bytes::from(versions))
        .await
        .map_err(|err| map_error(&err))?;

    let info_key = PackageName::new(format!("info/{}", name.as_str()));
    let mut info = service
        .get_raw_upstream(Ecosystem::RubyGems, &info_key)
        .await
        .map_err(|err| map_error(&err))?
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_else(|| "---\n".to_string());
    let info_line = format!("{version} checksum:sha256={sha256}");
    if !info.lines().any(|line| line == info_line) {
        info.push_str(&info_line);
        info.push('\n');
    }
    service
        .put_raw_upstream(Ecosystem::RubyGems, &info_key, Bytes::from(info))
        .await
        .map_err(|err| map_error(&err))
}

fn authorize_publish<S: HasRubyGemsState>(
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
        .map(|value| value.strip_prefix("Bearer ").unwrap_or(value))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "missing publishing token".to_string(),
            )
        })?;
    if state
        .config()
        .authorize_publish_token(token, TokenScope::Publish, Ecosystem::RubyGems, name)
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
