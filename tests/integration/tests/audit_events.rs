//! Audit-event coverage (OWASP A09 / ADR-0022) plus OIDC HTTP wiring, both asserted through an
//! in-process capturing subscriber over the `starmetal::audit` tracing target.
//!
//! The read gate collapses "authenticated but unauthorized" and "unauthenticated" to the same 401
//! status, so the *audit event* is the only place the two differ: a denied request from an
//! authenticated principal carries `principal`, an unauthenticated one does not. That same signal
//! proves the OIDC `CompositeAuthenticator` is wired into the HTTP auth path (feature `oidc`): a
//! valid ES256 bearer authenticates to its subject — the resulting read/deny event carries
//! `principal = "alice"` — whereas an `alg:none` token fails authentication and carries no principal.
//!
//! The server runs on a spawned Tokio task, so a thread-local subscriber would miss its events. A
//! process-global default subscriber is installed once; audit tests serialize through an async mutex
//! (held across `.await`, hence a `tokio::sync::Mutex`, not a std one) and clear the shared buffer
//! before running.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use starmetal_core::publishing::{PublishTokenConfig, TokenScope};
use starmetal_integration_tests::TestServer;
use tracing::field::{Field, Visit};
use tracing::subscriber::set_global_default;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::Registry;

const AUDIT_TARGET: &str = "starmetal::audit";

/// Captured audit events, cleared at the start of each serialized audit test.
static BUFFER: Mutex<Vec<CapturedEvent>> = Mutex::new(Vec::new());
/// Ensures the global subscriber is installed exactly once for this test binary.
static INSTALLED: OnceLock<()> = OnceLock::new();

/// Serializes audit tests. An async mutex so its guard can be held across the request `.await`
/// without tripping `clippy::await_holding_lock`.
fn serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[derive(Debug, Clone)]
struct CapturedEvent {
    fields: HashMap<String, String>,
}

impl CapturedEvent {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    /// Whether this event's `action`/`decision` pair matches.
    fn is(&self, action: &str, decision: &str) -> bool {
        self.field("action") == Some(action) && self.field("decision") == Some(decision)
    }
}

#[derive(Default)]
struct FieldVisitor(HashMap<String, String>);

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `%principal.id()` records via the Display shim, whose Debug is the Display output, so this
        // yields the bare principal id (e.g. "alice") rather than a quoted string. ~keep
        self.0.insert(field.name().to_string(), format!("{value:?}"));
    }
}

struct AuditLayer;

impl<S: tracing::Subscriber> Layer<S> for AuditLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
        if event.metadata().target() != AUDIT_TARGET {
            return;
        }
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        BUFFER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(CapturedEvent { fields: visitor.0 });
    }
}

/// Acquire the serial guard, install the global subscriber once, and clear the shared buffer. The
/// returned guard must be held for the test's duration.
async fn begin_audit_capture() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = serial().lock().await;
    INSTALLED.get_or_init(|| {
        let subscriber = Registry::default().with(AuditLayer);
        set_global_default(subscriber).expect("install global audit subscriber");
    });
    BUFFER.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    guard
}

/// A snapshot of the events captured so far.
fn captured() -> Vec<CapturedEvent> {
    BUFFER.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

// `/api/v1/components` is behind the global read gate but attaches no content model here, so the read
// middleware's audit event fires before the handler's 404 — a fully local route with no upstream.
const READ_ROUTE: &str = "/api/v1/components";

#[tokio::test]
async fn read_denied_for_an_authenticated_principal_emits_an_audit_event_with_the_principal() {
    let _guard = begin_audit_capture().await;
    // A publish-only token authenticates but carries no Read grant, so the read gate denies it.
    let server = TestServer::builder()
        .configure(|config| {
            config.auth.enabled = true;
            config.publishing.enabled = true;
            config.publishing.tokens.push(PublishTokenConfig {
                token: "publish-only".to_string(),
                scopes: vec![TokenScope::Publish],
                ecosystems: Vec::new(),
                packages: Vec::new(),
            });
        })
        .start()
        .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}{READ_ROUTE}", server.base_url()))
        .bearer_auth("publish-only")
        .send()
        .await
        .expect("read request");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let events = captured();
    let denied = events
        .iter()
        .find(|event| event.is("read", "deny"))
        .expect("a read/deny audit event");
    assert!(
        denied.field("principal").is_some(),
        "an authenticated-but-denied read must record the principal, got: {denied:?}"
    );

    server.shutdown();
}

#[tokio::test]
async fn unauthenticated_read_emits_an_audit_event_without_a_principal() {
    let _guard = begin_audit_capture().await;
    let server = TestServer::builder()
        .configure(|config| {
            config.auth.enabled = true;
            config.auth.tokens.push("read-token".to_string());
        })
        .start()
        .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}{READ_ROUTE}", server.base_url()))
        .send()
        .await
        .expect("read request");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let events = captured();
    let denied = events
        .iter()
        .find(|event| event.is("read", "deny"))
        .expect("a read/deny audit event");
    assert_eq!(
        denied.field("principal"),
        None,
        "an unauthenticated read must not record a principal, got: {denied:?}"
    );

    server.shutdown();
}

#[tokio::test]
async fn authorized_read_emits_an_allow_audit_event_with_the_principal() {
    let _guard = begin_audit_capture().await;
    let server = TestServer::builder()
        .configure(|config| {
            config.auth.enabled = true;
            config.auth.tokens.push("read-token".to_string());
        })
        .start()
        .await;
    let client = reqwest::Client::new();

    // The flat token clears the read gate (its allow event fires); the handler then 404s for the
    // absent content model, which is irrelevant to the audit assertion.
    let _response = client
        .get(format!("{}{READ_ROUTE}", server.base_url()))
        .bearer_auth("read-token")
        .send()
        .await
        .expect("read request");

    let events = captured();
    let allowed = events
        .iter()
        .find(|event| event.is("read", "allow"))
        .expect("a read/allow audit event");
    assert!(
        allowed.field("principal").is_some(),
        "an authorized read must record the principal, got: {allowed:?}"
    );

    server.shutdown();
}

#[tokio::test]
async fn authorized_admin_action_emits_an_allow_audit_event() {
    let _guard = begin_audit_capture().await;
    let server = TestServer::start_with_admin().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/admin/api/v1/status", server.base_url()))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("admin request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let events = captured();
    let admin_allow = events
        .iter()
        .find(|event| event.is("admin", "allow"))
        .expect("an admin/allow audit event");
    assert!(
        admin_allow.field("principal").is_some(),
        "an authorized admin action must record the principal, got: {admin_allow:?}"
    );

    server.shutdown();
}

#[cfg(feature = "oidc")]
mod oidc {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use serde_json::{Value, json};
    use starmetal_integration_tests::TestServer;

    use super::{READ_ROUTE, begin_audit_capture, captured};

    const ISSUER: &str = "https://issuer.test";
    const AUDIENCE: &str = "starmetal";
    const KID: &str = "ec-1";

    fn b64(bytes: impl AsRef<[u8]>) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn segment(value: &Value) -> String {
        b64(serde_json::to_vec(value).expect("serialize JWT segment"))
    }

    /// A fixed throwaway ES256 signing key. The 32-byte scalar is a constant (a test key needs no
    /// randomness, only a valid scalar), sidestepping any RNG dependency.
    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar")
    }

    /// The inline JWKS document for `signing_key`'s public key, under `KID`.
    fn jwks() -> String {
        let point = signing_key().verifying_key().to_encoded_point(false);
        json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": KID,
                "alg": "ES256",
                "x": b64(point.x().expect("x coordinate")),
                "y": b64(point.y().expect("y coordinate")),
            }]
        })
        .to_string()
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    fn claims(exp: i64) -> Value {
        json!({ "sub": "alice", "iss": ISSUER, "aud": AUDIENCE, "exp": exp })
    }

    fn sign_es256(header: &Value, claims: &Value) -> String {
        let input = format!("{}.{}", segment(header), segment(claims));
        let signature: Signature = signing_key().sign(input.as_bytes());
        format!("{input}.{}", b64(signature.to_bytes()))
    }

    fn es256_header() -> Value {
        json!({ "alg": "ES256", "kid": KID, "typ": "JWT" })
    }

    async fn oidc_server() -> TestServer {
        TestServer::builder()
            .configure(|config| {
                config.auth.enabled = true;
                config.oidc.enabled = true;
                config.oidc.issuer = ISSUER.to_string();
                config.oidc.audience = AUDIENCE.to_string();
                config.oidc.jwks = Some(jwks());
                config.oidc.principal_claim = "sub".to_string();
                config.oidc.leeway_secs = 60;
            })
            .start()
            .await
    }

    #[tokio::test]
    async fn valid_oidc_bearer_authenticates_to_its_subject_over_http() {
        let _guard = begin_audit_capture().await;
        let server = oidc_server().await;
        let client = reqwest::Client::new();
        let token = sign_es256(&es256_header(), &claims(now_secs() + 3600));

        // "alice" carries no authorizer grant, so the read gate denies with 401 — but the deny event
        // records the principal, proving the ES256 token was authenticated through the wired OIDC
        // CompositeAuthenticator (not merely rejected).
        let response = client
            .get(format!("{}{READ_ROUTE}", server.base_url()))
            .bearer_auth(&token)
            .send()
            .await
            .expect("read request");
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        let events = captured();
        let denied = events
            .iter()
            .find(|event| event.is("read", "deny"))
            .expect("a read/deny audit event");
        assert_eq!(
            denied.field("principal"),
            Some("alice"),
            "a valid OIDC bearer must authenticate to its subject, got: {denied:?}"
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn alg_none_bearer_fails_authentication_over_http() {
        let _guard = begin_audit_capture().await;
        let server = oidc_server().await;
        let client = reqwest::Client::new();
        // An unsigned `alg:none` token: rejected at authentication, so no principal is recorded.
        let header = json!({ "alg": "none", "typ": "JWT" });
        let token = format!("{}.{}.", segment(&header), segment(&claims(now_secs() + 3600)));

        let response = client
            .get(format!("{}{READ_ROUTE}", server.base_url()))
            .bearer_auth(&token)
            .send()
            .await
            .expect("read request");
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        let events = captured();
        let denied = events
            .iter()
            .find(|event| event.is("read", "deny"))
            .expect("a read/deny audit event");
        assert_eq!(
            denied.field("principal"),
            None,
            "an alg:none token must fail authentication and record no principal, got: {denied:?}"
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn expired_oidc_bearer_fails_authentication_over_http() {
        let _guard = begin_audit_capture().await;
        let server = oidc_server().await;
        let client = reqwest::Client::new();
        // Expired well beyond the 60s leeway.
        let token = sign_es256(&es256_header(), &claims(now_secs() - 3600));

        let response = client
            .get(format!("{}{READ_ROUTE}", server.base_url()))
            .bearer_auth(&token)
            .send()
            .await
            .expect("read request");
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        let events = captured();
        let denied = events
            .iter()
            .find(|event| event.is("read", "deny"))
            .expect("a read/deny audit event");
        assert_eq!(
            denied.field("principal"),
            None,
            "an expired token must fail authentication and record no principal, got: {denied:?}"
        );

        server.shutdown();
    }
}
