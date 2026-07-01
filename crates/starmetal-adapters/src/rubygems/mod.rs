//! RubyGems Compact Index adapter.

pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use sha2::Digest;
use starmetal_core::config::Config;
use starmetal_core::error::StarmetalError;
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName};
use starmetal_core::ports::{PackageService, PublishingService};
use starmetal_core::publishing::{ProtocolMetadata, PublishRequest, PublishedArtifact, TokenScope};

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
            license: metadata.license.clone(),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename,
                data: body,
                upstream_hashes,
            }],
            protocol_metadata: ProtocolMetadata::RubyGems {
                metadata: serde_json::json!({
                    "name": metadata.name,
                    "version": metadata.version,
                    "license": metadata.license,
                }),
            },
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
    let info_key = PackageName::new(format!("info/{}", name.as_str()));
    let mut info = service
        .get_raw_upstream(Ecosystem::RubyGems, &info_key)
        .await
        .map_err(|err| map_error(&err))?
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_else(|| "---\n".to_string());
    upsert_compact_index_line(
        &mut info,
        &format!("{version} "),
        &format!("{version} |checksum:{sha256}"),
    );
    let info_checksum = hex::encode(sha2::Sha256::digest(info.as_bytes()));
    service
        .put_raw_upstream(Ecosystem::RubyGems, &info_key, Bytes::from(info))
        .await
        .map_err(|err| map_error(&err))?;

    let versions_key = PackageName::new("_versions");
    let mut versions = service
        .get_raw_upstream(Ecosystem::RubyGems, &versions_key)
        .await
        .map_err(|err| map_error(&err))?
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_else(|| "---\n".to_string());
    upsert_versions_line(&mut versions, name.as_str(), version, &info_checksum);
    service
        .put_raw_upstream(Ecosystem::RubyGems, &versions_key, Bytes::from(versions))
        .await
        .map_err(|err| map_error(&err))
}

fn upsert_versions_line(body: &mut String, name: &str, version: &str, checksum: &str) {
    let line_prefix = format!("{name} ");
    let mut versions = body
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix(&line_prefix)?;
            rest.split_whitespace().next()
        })
        .map(|tokens| {
            tokens
                .split(',')
                .filter(|token| !token.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !versions.iter().any(|existing| existing == version) {
        versions.push(version.to_string());
    }
    let line = format!("{name} {} {checksum}", versions.join(","));
    upsert_compact_index_line(body, &line_prefix, &line);
}

fn upsert_compact_index_line(body: &mut String, line_prefix: &str, line: &str) {
    let mut replaced = false;
    let mut updated = String::new();
    for existing in body.lines() {
        if existing.starts_with(line_prefix) {
            if !replaced {
                updated.push_str(line);
                updated.push('\n');
                replaced = true;
            }
        } else {
            updated.push_str(existing);
            updated.push('\n');
        }
    }
    if !replaced {
        updated.push_str(line);
        updated.push('\n');
    }
    *body = updated;
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

fn map_error(err: &StarmetalError) -> (StatusCode, String) {
    tracing::warn!(error = %err, "RubyGems adapter request failed");
    crate::map_public_error(err)
}
