//! Offline tests: every key is generated and every JWT signed in-process. No network, no fixtures.

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey as EcSigningKey;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::traits::PublicKeyParts as _;
use serde_json::{Value, json};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};
use starmetal_core::authz::{Authenticator, CompositeAuthenticator, Principal, PrincipalId, PrincipalScope};
use starmetal_core::config::OidcConfig;

use super::OidcAuthenticator;

const ISSUER: &str = "https://issuer.example.com";
const AUDIENCE: &str = "starmetal";

/// A cached 2048-bit RSA key so the several RSA tests share one (slow) key generation.
fn rsa_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key")
    })
}

fn ec_key() -> EcSigningKey {
    let mut rng = rand::thread_rng();
    EcSigningKey::random(&mut rng)
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn encode_segment(value: &Value) -> String {
    b64(serde_json::to_vec(value).expect("serialize segment"))
}

/// Build the RSA JWK (public parameters only) for the cached key, under `kid`.
fn rsa_jwk(kid: &str) -> Value {
    let public = rsa_key().to_public_key();
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "n": b64(public.n().to_bytes_be()),
        "e": b64(public.e().to_bytes_be()),
    })
}

/// Build the EC (P-256) JWK for `signing_key`, under `kid`.
fn ec_jwk(signing_key: &EcSigningKey, kid: &str) -> Value {
    let point = signing_key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "alg": "ES256",
        "x": b64(point.x().expect("x coordinate")),
        "y": b64(point.y().expect("y coordinate")),
    })
}

fn jwks_document(keys: Vec<Value>) -> String {
    json!({ "keys": keys }).to_string()
}

fn future_exp() -> i64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() as i64;
    now + 3600
}

fn default_claims() -> Value {
    json!({
        "sub": "alice",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": future_exp(),
    })
}

fn sign_rs256(header: &Value, claims: &Value) -> String {
    let signing_input = format!("{}.{}", encode_segment(header), encode_segment(claims));
    let signing_key = RsaSigningKey::<Sha256>::new(rsa_key().clone());
    let signature = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64(signature.to_bytes()))
}

fn sign_es256(signing_key: &EcSigningKey, header: &Value, claims: &Value) -> String {
    let signing_input = format!("{}.{}", encode_segment(header), encode_segment(claims));
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64(signature.to_bytes()))
}

fn config_with_jwks(jwks: String) -> OidcConfig {
    OidcConfig {
        enabled: true,
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        jwks: Some(jwks),
        jwks_file: None,
        principal_claim: "sub".to_string(),
        leeway_secs: 60,
    }
}

fn rsa_authenticator() -> OidcAuthenticator {
    OidcAuthenticator::from_config(&config_with_jwks(jwks_document(vec![rsa_jwk("rsa-1")]))).expect("valid config")
}

#[test]
fn valid_rs256_token_authenticates_to_subject() {
    let authenticator = rsa_authenticator();
    let token = sign_rs256(
        &json!({ "alg": "RS256", "kid": "rsa-1", "typ": "JWT" }),
        &default_claims(),
    );

    let principal = authenticator.authenticate_bearer(&token).expect("valid RS256 token");
    assert_eq!(
        principal,
        Principal::User {
            id: PrincipalId::new("alice").unwrap(),
            scope: PrincipalScope::System,
        }
    );
}

#[test]
fn valid_es256_token_authenticates_to_subject() {
    let signing_key = ec_key();
    let authenticator =
        OidcAuthenticator::from_config(&config_with_jwks(jwks_document(vec![ec_jwk(&signing_key, "ec-1")])))
            .expect("valid config");
    let token = sign_es256(
        &signing_key,
        &json!({ "alg": "ES256", "kid": "ec-1" }),
        &default_claims(),
    );

    let principal = authenticator.authenticate_bearer(&token).expect("valid ES256 token");
    assert_eq!(principal.id().as_str(), "alice");
}

#[test]
fn tampered_signature_is_rejected() {
    let authenticator = rsa_authenticator();
    let mut token = sign_rs256(&json!({ "alg": "RS256", "kid": "rsa-1" }), &default_claims());
    // Flip the final character of the signature segment.
    let last = token.pop().expect("non-empty token");
    token.push(if last == 'A' { 'B' } else { 'A' });

    assert!(authenticator.authenticate_bearer(&token).is_none());
}

#[test]
fn expired_token_is_rejected() {
    let authenticator = rsa_authenticator();
    let claims = json!({ "sub": "alice", "iss": ISSUER, "aud": AUDIENCE, "exp": 1_000 });
    let token = sign_rs256(&json!({ "alg": "RS256", "kid": "rsa-1" }), &claims);

    assert!(authenticator.authenticate_bearer(&token).is_none());
}

#[test]
fn wrong_issuer_is_rejected() {
    let authenticator = rsa_authenticator();
    let claims = json!({ "sub": "alice", "iss": "https://evil.example.com", "aud": AUDIENCE, "exp": future_exp() });
    let token = sign_rs256(&json!({ "alg": "RS256", "kid": "rsa-1" }), &claims);

    assert!(authenticator.authenticate_bearer(&token).is_none());
}

#[test]
fn wrong_audience_is_rejected() {
    let authenticator = rsa_authenticator();
    let claims = json!({ "sub": "alice", "iss": ISSUER, "aud": "someone-else", "exp": future_exp() });
    let token = sign_rs256(&json!({ "alg": "RS256", "kid": "rsa-1" }), &claims);

    assert!(authenticator.authenticate_bearer(&token).is_none());
}

#[test]
fn audience_array_containing_configured_value_is_accepted() {
    let authenticator = rsa_authenticator();
    let claims = json!({ "sub": "alice", "iss": ISSUER, "aud": ["other", AUDIENCE], "exp": future_exp() });
    let token = sign_rs256(&json!({ "alg": "RS256", "kid": "rsa-1" }), &claims);

    assert!(authenticator.authenticate_bearer(&token).is_some());
}

#[test]
fn alg_none_is_rejected() {
    let authenticator = rsa_authenticator();
    let header = encode_segment(&json!({ "alg": "none" }));
    let payload = encode_segment(&default_claims());
    let token = format!("{header}.{payload}.");

    assert!(authenticator.authenticate_bearer(&token).is_none());
}

#[test]
fn hs256_algorithm_confusion_is_rejected() {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let authenticator = rsa_authenticator();
    // The classic algorithm-confusion attack: forge an HS256 token whose HMAC secret is the RSA
    // public key material the server publishes. It must not validate against the RSA JWK.
    let public_bytes = rsa_key().to_public_key().n().to_bytes_be();
    let header = encode_segment(&json!({ "alg": "HS256", "kid": "rsa-1" }));
    let payload = encode_segment(&default_claims());
    let signing_input = format!("{header}.{payload}");

    let mut mac = HmacSha256::new_from_slice(&public_bytes).expect("hmac key");
    mac.update(signing_input.as_bytes());
    let token = format!("{signing_input}.{}", b64(mac.finalize().into_bytes()));

    assert!(
        authenticator.authenticate_bearer(&token).is_none(),
        "HS256 forged with the public key must not authenticate"
    );
}

#[test]
fn rs256_header_against_ec_key_is_rejected() {
    // A token claiming RS256 must not verify against an EC JWK even if that is the only key.
    let signing_key = ec_key();
    let authenticator =
        OidcAuthenticator::from_config(&config_with_jwks(jwks_document(vec![ec_jwk(&signing_key, "ec-1")])))
            .expect("valid config");
    // Sign a real ES256 signature but lie about the algorithm in the header.
    let token = sign_es256(
        &signing_key,
        &json!({ "alg": "RS256", "kid": "ec-1" }),
        &default_claims(),
    );

    assert!(authenticator.authenticate_bearer(&token).is_none());
}

#[test]
fn unknown_kid_is_rejected() {
    let authenticator = rsa_authenticator();
    let token = sign_rs256(&json!({ "alg": "RS256", "kid": "does-not-exist" }), &default_claims());

    assert!(authenticator.authenticate_bearer(&token).is_none());
}

#[test]
fn malformed_token_is_rejected() {
    let authenticator = rsa_authenticator();
    assert!(authenticator.authenticate_bearer("not-a-jwt").is_none());
    assert!(authenticator.authenticate_bearer("only.two").is_none());
    assert!(authenticator.authenticate_bearer("a.b.c.d").is_none());
    assert!(authenticator.authenticate_bearer("$$$.$$$.$$$").is_none());
}

#[test]
fn custom_principal_claim_maps_to_that_claim() {
    let mut config = config_with_jwks(jwks_document(vec![rsa_jwk("rsa-1")]));
    config.principal_claim = "email".to_string();
    let authenticator = OidcAuthenticator::from_config(&config).expect("valid config");

    let claims = json!({
        "sub": "alice",
        "email": "alice@example.com",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": future_exp(),
    });
    let token = sign_rs256(&json!({ "alg": "RS256", "kid": "rsa-1" }), &claims);

    let principal = authenticator.authenticate_bearer(&token).expect("valid token");
    assert_eq!(principal.id().as_str(), "alice@example.com");
}

/// A stub flat-token backend standing in for `LocalAuthorizer` in composition tests.
struct FlatTokenStub;

impl Authenticator for FlatTokenStub {
    fn authenticate_bearer(&self, credential: &str) -> Option<Principal> {
        (credential == "flat-secret").then(|| Principal::User {
            id: PrincipalId::new("legacy-bearer").unwrap(),
            scope: PrincipalScope::System,
        })
    }
}

#[test]
fn composed_with_flat_backend_preserves_both_paths() {
    let oidc: Arc<dyn Authenticator> = Arc::new(rsa_authenticator());
    let flat: Arc<dyn Authenticator> = Arc::new(FlatTokenStub);
    let composite = CompositeAuthenticator::new(vec![oidc, flat]);

    // A valid JWT authenticates via the OIDC backend.
    let token = sign_rs256(&json!({ "alg": "RS256", "kid": "rsa-1" }), &default_claims());
    assert_eq!(
        composite
            .authenticate_bearer(&token)
            .expect("jwt authenticates")
            .id()
            .as_str(),
        "alice"
    );

    // The existing flat token still authenticates via the fallback (behavior preserved).
    assert_eq!(
        composite
            .authenticate_bearer("flat-secret")
            .expect("flat token authenticates")
            .id()
            .as_str(),
        "legacy-bearer"
    );

    // A JWT-looking string that is neither a valid JWT nor a configured flat token stays unauthenticated.
    assert!(composite.authenticate_bearer("aaa.bbb.ccc").is_none());
}

#[test]
fn from_config_rejects_empty_issuer() {
    let mut config = config_with_jwks(jwks_document(vec![rsa_jwk("rsa-1")]));
    config.issuer = String::new();
    assert!(OidcAuthenticator::from_config(&config).is_err());
}

#[test]
fn from_config_rejects_empty_audience() {
    let mut config = config_with_jwks(jwks_document(vec![rsa_jwk("rsa-1")]));
    config.audience = String::new();
    assert!(OidcAuthenticator::from_config(&config).is_err());
}

#[test]
fn from_config_rejects_unparseable_jwks() {
    let config = config_with_jwks("{ not valid json".to_string());
    assert!(OidcAuthenticator::from_config(&config).is_err());
}

#[test]
fn from_config_rejects_jwks_without_supported_keys() {
    // A syntactically valid JWKS whose only key is an unsupported type yields zero usable keys.
    let jwks = json!({ "keys": [{ "kty": "oct", "k": "c2VjcmV0" }] }).to_string();
    let config = config_with_jwks(jwks);
    assert!(OidcAuthenticator::from_config(&config).is_err());
}
