//! Offline static-JWKS OIDC bearer validator behind the core
//! [`Authenticator`](starmetal_core::authz::Authenticator) port (ADR-0022).
//!
//! [`OidcAuthenticator`] is a *second* identity backend proving the `Authenticator` port is a clean
//! seam: it verifies a compact JWS bearer against a **static** JWKS taken from configuration and maps
//! a configurable claim to a [`Principal`](starmetal_core::authz::Principal). It composes ahead of the
//! flat-token authorizer via
//! [`CompositeAuthenticator`](starmetal_core::authz::CompositeAuthenticator), so a JWT authenticates
//! here while an unchanged flat token still authenticates via the fallback.
//!
//! # Scope boundary
//!
//! This backend is deliberately **offline**: the JWKS is supplied inline or from a local file and is
//! parsed once at startup. There is intentionally **no** live-IdP integration — no JWKS-URL fetch, no
//! OIDC discovery, no token refresh, no network I/O of any kind. A live-IdP backend is a later stage;
//! this proves the port with a self-contained, fully testable validator.
//!
//! # Validation
//!
//! A token is accepted only when every check passes (any failure resolves to [`None`], never a panic):
//!
//! - the compact JWS has exactly three parts and a parseable header and payload;
//! - the header `alg` is one of the allowlisted asymmetric algorithms ([`RS256`](Algorithm::Rs256) or
//!   [`ES256`](Algorithm::Es256)); `alg: none`, any HMAC alg, and anything else are rejected;
//! - the selected JWK's type matches the algorithm (algorithm-confusion defense: an `HS256` token can
//!   never be verified against a public key, and an `RS256` header can never consume an EC key);
//! - the signature verifies over the `header.payload` signing input;
//! - `exp` is in the future (within `leeway_secs`), `iss` equals the configured issuer, and `aud`
//!   contains the configured audience;
//! - the configured `principal_claim` (default `sub`) is present and a non-empty string.

mod jwks;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Map, Value};
use starmetal_core::authz::{Authenticator, Principal, PrincipalId, PrincipalScope};
use starmetal_core::config::OidcConfig;

use crate::jwks::{Algorithm, JwkSet};

/// Errors raised while constructing an [`OidcAuthenticator`] from configuration.
///
/// Construction is the only fallible surface; token validation never errors (it returns [`None`]).
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// A required configuration value was missing or empty.
    #[error("oidc configuration error: {0}")]
    Config(String),
    /// The configured `jwks_file` could not be read.
    #[error("failed to read oidc.jwks_file {path}: {source}")]
    JwksFile {
        /// The path that failed to read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The JWKS document could not be parsed or held no usable RS256/ES256 key.
    #[error("invalid oidc JWKS: {0}")]
    Jwks(String),
}

/// A [`Principal`]-resolving OIDC bearer validator over a static JWKS (see [module docs](self)).
pub struct OidcAuthenticator {
    issuer: String,
    audience: String,
    principal_claim: String,
    leeway_secs: u64,
    keys: JwkSet,
}

impl std::fmt::Debug for OidcAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAuthenticator")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("principal_claim", &self.principal_claim)
            .field("leeway_secs", &self.leeway_secs)
            .field("keys", &self.keys.len())
            .finish()
    }
}

/// The JWT header fields this validator consults.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

impl OidcAuthenticator {
    /// Build a validator from the OIDC configuration section.
    ///
    /// Resolves the JWKS (inline [`jwks`](OidcConfig::jwks) preferred over
    /// [`jwks_file`](OidcConfig::jwks_file)), parses every RS256/ES256 key, and requires at least one.
    /// This is the crypto-side startup validation that complements
    /// [`OidcConfig::validate`](starmetal_core::config::OidcConfig::validate).
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] when the issuer or audience is empty, no JWKS source is set, the file is
    /// unreadable, or the JWKS parses to zero usable keys.
    pub fn from_config(config: &OidcConfig) -> Result<Self, OidcError> {
        if config.issuer.trim().is_empty() {
            return Err(OidcError::Config("oidc.issuer must not be empty".to_string()));
        }
        if config.audience.trim().is_empty() {
            return Err(OidcError::Config("oidc.audience must not be empty".to_string()));
        }

        let jwks_json = resolve_jwks_source(config)?;
        let keys = JwkSet::parse(&jwks_json).map_err(OidcError::Jwks)?;
        if keys.is_empty() {
            return Err(OidcError::Jwks("no supported (RS256/ES256) keys in JWKS".to_string()));
        }

        let principal_claim = if config.principal_claim.trim().is_empty() {
            "sub".to_string()
        } else {
            config.principal_claim.clone()
        };

        Ok(Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            principal_claim,
            leeway_secs: config.leeway_secs,
            keys,
        })
    }

    /// Build a validator and hand it back as an `Arc<dyn Authenticator>` ready to compose.
    ///
    /// # Errors
    ///
    /// Propagates every [`from_config`](OidcAuthenticator::from_config) error.
    pub fn into_authenticator(config: &OidcConfig) -> Result<Arc<dyn Authenticator>, OidcError> {
        Ok(Arc::new(Self::from_config(config)?))
    }

    /// Validate `token`, returning the resolved [`Principal`] or [`None`] on any failure.
    fn validate(&self, token: &str) -> Option<Principal> {
        let mut parts = token.split('.');
        let header_b64 = parts.next()?;
        let payload_b64 = parts.next()?;
        let signature_b64 = parts.next()?;
        if parts.next().is_some() {
            // More than three segments is not a compact JWS.
            return None;
        }

        let header: JwtHeader = serde_json::from_slice(&jwks::decode_b64url(header_b64)?).ok()?;
        let algorithm = Algorithm::from_header(&header.alg)?;
        let signature = jwks::decode_b64url(signature_b64)?;

        let key = self.keys.select(header.kid.as_deref())?;
        // Algorithm-confusion defense: the key type must match the header algorithm. A mismatch
        // (or the earlier rejection of non-asymmetric algs) means an attacker cannot coerce an HMAC
        // verification against public-key material, nor consume the wrong key kind.
        let signing_input = format!("{header_b64}.{payload_b64}");
        if key.verify(algorithm, signing_input.as_bytes(), &signature).is_none() {
            tracing::debug!(target: "starmetal::audit", "oidc token signature verification failed");
            return None;
        }

        let claims: Map<String, Value> = serde_json::from_slice(&jwks::decode_b64url(payload_b64)?).ok()?;
        self.validate_claims(&claims)?;

        let subject = claims.get(&self.principal_claim)?.as_str()?;
        let id = PrincipalId::new(subject).ok()?;
        Some(Principal::User {
            id,
            scope: PrincipalScope::System,
        })
    }

    /// Check the registered claims (`exp`, `iss`, `aud`). Returns [`None`] on any failure.
    fn validate_claims(&self, claims: &Map<String, Value>) -> Option<()> {
        let exp = claims.get("exp").and_then(json_number_to_i64)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
        if now > exp.saturating_add(self.leeway_secs as i64) {
            tracing::debug!(target: "starmetal::audit", "oidc token expired");
            return None;
        }

        let issuer = claims.get("iss").and_then(Value::as_str)?;
        if issuer != self.issuer {
            tracing::debug!(target: "starmetal::audit", "oidc token issuer mismatch");
            return None;
        }

        let audience_ok = match claims.get("aud")? {
            Value::String(single) => single == &self.audience,
            Value::Array(many) => many.iter().any(|value| value.as_str() == Some(self.audience.as_str())),
            _ => false,
        };
        if !audience_ok {
            tracing::debug!(target: "starmetal::audit", "oidc token audience mismatch");
            return None;
        }

        Some(())
    }
}

impl Authenticator for OidcAuthenticator {
    /// Resolve a JWT `credential` to its [`Principal`], or [`None`] if it is not a valid token.
    fn authenticate_bearer(&self, credential: &str) -> Option<Principal> {
        self.validate(credential)
    }
}

/// Extract a JSON number claim as an `i64`, tolerating integer or floating `NumericDate` encodings.
fn json_number_to_i64(value: &Value) -> Option<i64> {
    if let Some(integer) = value.as_i64() {
        return Some(integer);
    }
    value.as_f64().map(|float| float as i64)
}

/// Resolve the JWKS JSON from the inline value or the file path (inline wins).
fn resolve_jwks_source(config: &OidcConfig) -> Result<String, OidcError> {
    if let Some(inline) = &config.jwks
        && !inline.trim().is_empty()
    {
        return Ok(inline.clone());
    }
    if let Some(path) = &config.jwks_file {
        return std::fs::read_to_string(path).map_err(|source| OidcError::JwksFile {
            path: path.display().to_string(),
            source,
        });
    }
    Err(OidcError::Config(
        "oidc requires either oidc.jwks or oidc.jwks_file".to_string(),
    ))
}

#[cfg(test)]
mod tests;
