use axum::http::{HeaderMap, StatusCode, header};
use starmetal_core::config::Config;
use starmetal_core::error::StarmetalError;

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
pub(crate) fn map_public_error(err: &StarmetalError) -> (StatusCode, String) {
    match err {
        StarmetalError::PackageNotFound { .. }
        | StarmetalError::VersionNotFound { .. }
        | StarmetalError::ArtifactNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        StarmetalError::PolicyViolation(_) => (StatusCode::FORBIDDEN, err.to_string()),
        StarmetalError::Adapter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        StarmetalError::Publish(_) => (StatusCode::CONFLICT, err.to_string()),
        StarmetalError::Upstream(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream registry request failed".to_string(),
        ),
        StarmetalError::Config(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server configuration error".to_string(),
        ),
        StarmetalError::Storage(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage operation failed".to_string(),
        ),
        StarmetalError::IntegrityError { .. } => (
            StatusCode::BAD_GATEWAY,
            "upstream artifact integrity check failed".to_string(),
        ),
        StarmetalError::SchemaValidation(_) => (
            StatusCode::BAD_GATEWAY,
            "upstream registry response failed validation".to_string(),
        ),
        StarmetalError::Lockfile(_) | StarmetalError::ConfigNotFound(_) | StarmetalError::Io(_) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal starmetal error".to_string(),
            )
        }
        StarmetalError::Toml(_) | StarmetalError::Json(_) => (
            StatusCode::BAD_REQUEST,
            "invalid request or registry payload".to_string(),
        ),
    }
}
