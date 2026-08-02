use axum::http::{HeaderMap, StatusCode, header};
use starmetal_core::config::Config;
use starmetal_core::error::StarmetalError;
use starmetal_core::supply_chain::{PolicyHttpStatus, PolicyReason};

mod upstream_http;

#[cfg(feature = "pypi")]
pub mod pypi;

#[cfg(feature = "npm")]
pub mod npm;

#[cfg(any(feature = "hex", feature = "rubygems", feature = "nuget", feature = "pub"))]
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

#[cfg(feature = "scanner-osv")]
pub mod scanner;

/// The outcome of a publish authorization check (ADR-0022), which each adapter maps to HTTP.
///
/// `Unauthenticated` means no bearer credential was presented (→ 401). A credential that is
/// present but unrecognized, or recognized but not granted `Add` on the target, is `Forbidden`
/// (→ 403) — preserving the pre-ADR-0022 behavior where an unknown/insufficient publish token
/// returned 403, not 401.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishAuthorization {
    Allowed,
    Unauthenticated,
    Forbidden,
}

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

/// Convert a core-defined, framework-agnostic [`PolicyHttpStatus`] into this adapter's axum
/// `StatusCode`. This is the only place the axum status type and the core status vocabulary meet.
fn to_status_code(status: PolicyHttpStatus) -> StatusCode {
    match status {
        PolicyHttpStatus::Forbidden => StatusCode::FORBIDDEN,
        PolicyHttpStatus::Conflict => StatusCode::CONFLICT,
        PolicyHttpStatus::ContentTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
    }
}

/// The canonical, reason-aware `StarmetalError` → HTTP mapping (ADR-0024/0025 Stage N9).
///
/// Every protocol adapter (`map_public_error`, below) and the admin API (`map_admin_error` in
/// `starmetal-server`) share this single mapping so a given `PolicyReason` always surfaces as the
/// same HTTP status regardless of which surface denied the request. `PolicyViolation` messages are
/// formatted by the gates as `"<code>: <prose>"`; the code is resolved back to a [`PolicyReason`]
/// via [`PolicyReason::http_status_for_message`] and mapped to a status. A message with no
/// recognizable code prefix falls back to 403 Forbidden, matching the pre-N9 flat behavior.
///
/// Non-policy variants are unchanged from before N9: NotFound family → 404, Publish → 409,
/// Upstream/IntegrityError/SchemaValidation → 502, Adapter/Toml/Json → 400, everything else → 500.
pub fn map_public_error(err: &StarmetalError) -> (StatusCode, String) {
    match err {
        StarmetalError::PackageNotFound { .. }
        | StarmetalError::VersionNotFound { .. }
        | StarmetalError::ArtifactNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        StarmetalError::PolicyViolation(message) => (
            to_status_code(PolicyReason::http_status_for_message(message)),
            err.to_string(),
        ),
        StarmetalError::Adapter(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        StarmetalError::Update(_) => (StatusCode::INTERNAL_SERVER_ERROR, "update operation failed".to_string()),
        StarmetalError::Publish(_) => (StatusCode::CONFLICT, err.to_string()),
        StarmetalError::Upstream(_) => (StatusCode::BAD_GATEWAY, "upstream registry request failed".to_string()),
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
        StarmetalError::Lockfile(_) | StarmetalError::ConfigNotFound(_) | StarmetalError::Io(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal starmetal error".to_string(),
        ),
        StarmetalError::Toml(_) | StarmetalError::Json(_) => (
            StatusCode::BAD_REQUEST,
            "invalid request or registry payload".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_map_each_policy_reason_to_its_canonical_status_via_public_error() {
        let cases = [
            (PolicyReason::BlockedCoordinate, StatusCode::FORBIDDEN),
            (PolicyReason::DisallowedLicense, StatusCode::FORBIDDEN),
            (PolicyReason::VulnSeverityExceeded, StatusCode::FORBIDDEN),
            (PolicyReason::MissingSignature, StatusCode::FORBIDDEN),
            (PolicyReason::FailingProvenance, StatusCode::FORBIDDEN),
            (PolicyReason::MissingScanReport, StatusCode::FORBIDDEN),
            (PolicyReason::IncompleteScan, StatusCode::FORBIDDEN),
            (PolicyReason::QuotaExceeded, StatusCode::PAYLOAD_TOO_LARGE),
            (PolicyReason::ImmutableVersion, StatusCode::CONFLICT),
        ];
        for (reason, expected_status) in cases {
            let message = format!("{}: some prose", reason.as_str());
            let err = StarmetalError::PolicyViolation(message);
            let (status, _) = map_public_error(&err);
            assert_eq!(status, expected_status, "status mismatch for {reason:?}");
        }
    }

    #[test]
    fn should_fall_back_to_forbidden_for_an_unprefixed_policy_violation() {
        let err = StarmetalError::PolicyViolation("package foo is blocked".to_string());
        let (status, body) = map_public_error(&err);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("package foo is blocked"));
    }

    #[test]
    fn should_not_change_non_policy_error_mappings() {
        let cases = [
            (
                StarmetalError::PackageNotFound {
                    ecosystem: "pypi".to_string(),
                    name: "foo".to_string(),
                },
                StatusCode::NOT_FOUND,
            ),
            (
                StarmetalError::Publish("already published".to_string()),
                StatusCode::CONFLICT,
            ),
            (
                StarmetalError::Upstream("timed out".to_string()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                StarmetalError::Adapter("bad request shape".to_string()),
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (err, expected_status) in cases {
            let (status, _) = map_public_error(&err);
            assert_eq!(status, expected_status, "status mismatch for {err:?}");
        }
    }
}
