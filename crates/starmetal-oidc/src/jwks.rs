//! JWKS parsing and RS256/ES256 signature verification.
//!
//! Assembled from RustCrypto primitives (`rsa`, `p256`, `sha2`) rather than a batteries-included JWT
//! crate, so the dependency footprint stays within the crates the workspace already builds and avoids
//! pulling `ring`/`aws-lc` (keeping `cargo deny` licenses clean). Only the two common OIDC asymmetric
//! signing algorithms are supported; everything else is rejected.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::BigUint;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use serde::Deserialize;
use sha2::Sha256;
use signature::Verifier as _;

/// The allowlisted signing algorithms. `alg: none`, HMAC algorithms, and every other value are
/// rejected simply by not being representable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    Rs256,
    /// ECDSA using P-256 and SHA-256.
    Es256,
}

impl Algorithm {
    /// Parse the JWT header `alg` into a supported algorithm, or [`None`] for anything unsupported
    /// (including `none`, `HS256`, `RS384`, `ES384`, ...).
    pub fn from_header(alg: &str) -> Option<Self> {
        match alg {
            "RS256" => Some(Algorithm::Rs256),
            "ES256" => Some(Algorithm::Es256),
            _ => None,
        }
    }
}

/// A parsed public JWK: an RSA or P-256 verifying key, with its optional `kid`.
pub struct Jwk {
    kid: Option<String>,
    key: PublicKey,
}

/// The verifying-key material behind a [`Jwk`].
enum PublicKey {
    Rsa(Box<RsaPublicKey>),
    Ec(Box<p256::ecdsa::VerifyingKey>),
}

impl Jwk {
    /// Verify `signature` over `message` using this key, but only when `algorithm` matches the key
    /// type. A mismatch returns [`None`] — the algorithm-confusion defense.
    pub fn verify(&self, algorithm: Algorithm, message: &[u8], signature: &[u8]) -> Option<()> {
        match (algorithm, &self.key) {
            (Algorithm::Rs256, PublicKey::Rsa(public_key)) => {
                let verifying_key = RsaVerifyingKey::<Sha256>::new((**public_key).clone());
                let signature = RsaSignature::try_from(signature).ok()?;
                verifying_key.verify(message, &signature).ok()
            }
            (Algorithm::Es256, PublicKey::Ec(verifying_key)) => {
                let signature = p256::ecdsa::Signature::from_slice(signature).ok()?;
                verifying_key.verify(message, &signature).ok()
            }
            // RS256 header against an EC key (or vice versa): reject.
            _ => None,
        }
    }
}

/// A set of parsed JWKs, selectable by `kid`.
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a JWKS document, keeping only usable RS256/ES256 keys.
    ///
    /// # Errors
    ///
    /// Returns a message when the document is not valid JSON in the JWKS shape. A key whose type is
    /// unsupported is skipped; a key whose type is supported but whose parameters are malformed is an
    /// error, so a misconfigured intended key is surfaced rather than silently dropped.
    pub fn parse(json: &str) -> Result<Self, String> {
        let document: JwksDocument = serde_json::from_str(json).map_err(|error| error.to_string())?;
        let mut keys = Vec::new();
        for raw in document.keys {
            if let Some(jwk) = raw.into_jwk()? {
                keys.push(jwk);
            }
        }
        Ok(Self { keys })
    }

    /// The number of usable keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set holds no usable keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Select the key to verify with.
    ///
    /// When the token header carries a `kid`, the matching key is required (an unknown `kid` returns
    /// [`None`], so a rotated-out key cannot be silently accepted by another). When the header has no
    /// `kid`, a single-key set is used; an ambiguous multi-key set returns [`None`].
    pub fn select(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => self.keys.iter().find(|jwk| jwk.kid.as_deref() == Some(kid)),
            None => match self.keys.as_slice() {
                [single] => Some(single),
                _ => None,
            },
        }
    }
}

/// The raw JWKS document as it appears on the wire.
#[derive(Debug, Deserialize)]
struct JwksDocument {
    #[serde(default)]
    keys: Vec<RawJwk>,
}

/// A single raw JWK before conversion into typed key material.
#[derive(Debug, Deserialize)]
struct RawJwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

impl RawJwk {
    /// Convert into a typed [`Jwk`], returning `Ok(None)` for an unsupported key type and `Err` for a
    /// supported type with malformed parameters.
    fn into_jwk(self) -> Result<Option<Jwk>, String> {
        match self.kty.as_str() {
            "RSA" => {
                let n = decode_required(&self.n, "RSA JWK missing n")?;
                let e = decode_required(&self.e, "RSA JWK missing e")?;
                let public_key = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
                    .map_err(|error| format!("invalid RSA JWK: {error}"))?;
                Ok(Some(Jwk {
                    kid: self.kid,
                    key: PublicKey::Rsa(Box::new(public_key)),
                }))
            }
            "EC" => {
                if self.crv.as_deref() != Some("P-256") {
                    // Only P-256 (ES256) is supported; other curves are skipped.
                    return Ok(None);
                }
                let x = decode_required(&self.x, "EC JWK missing x")?;
                let y = decode_required(&self.y, "EC JWK missing y")?;
                if x.len() != 32 || y.len() != 32 {
                    return Err("EC P-256 JWK coordinates must be 32 bytes".to_string());
                }
                let point = p256::EncodedPoint::from_affine_coordinates(
                    p256::FieldBytes::from_slice(&x),
                    p256::FieldBytes::from_slice(&y),
                    false,
                );
                let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                    .map_err(|error| format!("invalid EC JWK: {error}"))?;
                Ok(Some(Jwk {
                    kid: self.kid,
                    key: PublicKey::Ec(Box::new(verifying_key)),
                }))
            }
            _ => Ok(None),
        }
    }
}

/// Decode a required base64url JWK parameter, mapping absence/failure to `message`.
fn decode_required(value: &Option<String>, message: &str) -> Result<Vec<u8>, String> {
    let encoded = value.as_deref().ok_or_else(|| message.to_string())?;
    decode_b64url(encoded).ok_or_else(|| message.to_string())
}

/// Decode a base64url (no padding) segment, returning [`None`] on any decode error.
pub fn decode_b64url(input: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(input).ok()
}
