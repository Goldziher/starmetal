use axum::http::{HeaderMap, StatusCode, header};
use depot_core::config::Config;
use depot_core::error::DepotError;

mod upstream_http;

#[cfg(feature = "pypi")]
pub mod pypi;

#[cfg(feature = "npm")]
pub mod npm;

#[cfg(any(
    feature = "hex",
    feature = "rubygems",
    feature = "nuget",
    feature = "pub"
))]
mod archive;

#[cfg(feature = "cargo-registry")]
pub mod cargo;

#[cfg(feature = "hex")]
pub mod hex;

#[cfg(feature = "maven")]
pub mod maven;

#[cfg(feature = "rubygems")]
pub mod rubygems;

#[cfg(feature = "nuget")]
pub mod nuget;

#[cfg(feature = "pub")]
pub mod pubdev;

#[allow(dead_code)]
pub(crate) fn public_base_url(config: &Config, headers: &HeaderMap) -> String {
    config.server.public_base_url.clone().unwrap_or_else(|| {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("localhost:8080");
        format!("http://{host}")
    })
}

#[allow(dead_code)]
pub(crate) fn map_public_error(err: &DepotError) -> (StatusCode, String) {
    match err {
        DepotError::PackageNotFound { .. }
        | DepotError::VersionNotFound { .. }
        | DepotError::ArtifactNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        DepotError::PolicyViolation(_) => (StatusCode::FORBIDDEN, err.to_string()),
        DepotError::Adapter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        DepotError::Publish(_) => (StatusCode::CONFLICT, err.to_string()),
        DepotError::Upstream(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream registry request failed".to_string(),
        ),
        DepotError::Config(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server configuration error".to_string(),
        ),
        DepotError::Storage(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage operation failed".to_string(),
        ),
        DepotError::IntegrityError { .. } => (
            StatusCode::BAD_GATEWAY,
            "upstream artifact integrity check failed".to_string(),
        ),
        DepotError::SchemaValidation(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream registry response failed validation".to_string(),
        ),
        DepotError::Lockfile(_) | DepotError::ConfigNotFound(_) | DepotError::Io(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal depot error".to_string(),
        ),
        DepotError::Toml(_) | DepotError::Json(_) => (
            StatusCode::BAD_REQUEST,
            "invalid request or registry payload".to_string(),
        ),
    }
}
