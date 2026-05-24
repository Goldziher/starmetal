//! RubyGems Compact Index adapter.

pub mod upstream;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use depot_core::error::DepotError;
use depot_core::package::{ArtifactId, Ecosystem, PackageName};
use depot_core::ports::PackageService;

use self::upstream::RubyGemsUpstreamClient;

pub trait HasRubyGemsState: Clone + Send + Sync + 'static {
    fn package_service(&self) -> &Arc<dyn PackageService>;
    fn rubygems_upstream(&self) -> &Arc<RubyGemsUpstreamClient>;
}

pub fn router<S: HasRubyGemsState>() -> Router<S> {
    Router::new()
        .route("/versions", get(versions::<S>))
        .route("/info/{gem}", get(info::<S>))
        .route("/gems/{filename}", get(gem::<S>))
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
