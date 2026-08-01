use axum::extract::Request;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use starmetal_authz::default_namespace;
use starmetal_core::authz::{Action, Authorizer, Resource};

use crate::state::AppState;

/// Gate every request behind the ADR-0022 [`Authorizer`](starmetal_core::authz::Authorizer).
///
/// Replaces the legacy `Config::authorize_bearer_token || authorize_admin_token` disjunction: the
/// bearer token is authenticated to a [`Principal`](starmetal_core::authz::Principal), then the
/// content-plane [`Action::Read`] is required against the whole default namespace (the config is
/// namespace-less today). This preserves the prior behavior exactly — flat-bearer grants carry
/// `RepositoryView[Browse, Read]` and admin grants imply content authority, so both authorize; a
/// publish-only token carries neither and is denied, as before. `authenticate` resolves a token to
/// one principal by precedence admin > publish > flat.
///
/// Every decision emits an audit event (OWASP A09): denials at `warn`, reads at `debug` to keep the
/// per-request hot path from flooding an operator's audit stream.
pub async fn require_bearer_token(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !state.config.auth.enabled {
        return next.run(request).await;
    }

    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    if let Some(token) = token
        && let Some(principal) = state.authorizer.authenticate(token)
    {
        let resource = Resource {
            namespace: default_namespace(),
            ecosystem: None,
            repository: None,
            coordinate: None,
        };
        if let Ok(decision) = state.authorizer.authorize(&principal, Action::Read, &resource).await
            && decision.is_allowed()
        {
            tracing::debug!(target: "starmetal::audit", principal = %principal.id(), action = "read", decision = "allow", "read authorized");
            return next.run(request).await;
        }
        tracing::warn!(target: "starmetal::audit", principal = %principal.id(), action = "read", decision = "deny", "read denied by authorizer");
    } else {
        tracing::warn!(target: "starmetal::audit", action = "read", decision = "deny", "unauthenticated read request");
    }

    (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
}
