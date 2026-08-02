//! Content listing endpoint with authorization push-down (ADR-0022).
//!
//! `GET /api/v1/components` authorizes the caller for [`Action::Browse`] and pushes the resulting
//! [`QueryPredicate`] into the metadata store, so a principal only ever lists the components its
//! grants cover — filtered in-query, never post-filtered. It authorizes `Browse` (not `Admin`) so a
//! scoped principal receives a scoped predicate; it is mounted outside the admin API for that
//! reason.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use starmetal_authz::default_namespace;
use starmetal_core::authz::{Action, Authorizer, QueryPredicate, Resource};
use starmetal_core::content::{BrowsePage, Component, ContentBrowse};
use starmetal_core::package::Ecosystem;

use crate::state::AppState;

/// Router for the content browse surface, mounted at `/api/v1`.
pub fn router() -> Router<AppState> {
    Router::new().route("/components", get(browse_components))
}

#[derive(Debug, Deserialize)]
struct BrowseQuery {
    /// Narrow the listing to a single ecosystem, combined with the authorization predicate.
    #[serde(default)]
    ecosystem: Option<Ecosystem>,
    /// Page size; clamped into `1..=BrowsePage::MAX_LIMIT`.
    #[serde(default)]
    limit: Option<u32>,
    /// Number of leading components to skip.
    #[serde(default)]
    offset: Option<u32>,
}

async fn browse_components(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BrowseQuery>,
) -> Response {
    let browse = match content_browse_handle(&state) {
        Ok(browse) => browse,
        Err(error) => return error.into_response(),
    };

    let predicate = match authorize_browse(&state, &headers).await {
        Ok(predicate) => predicate,
        Err(error) => return error.into_response(),
    };

    // Narrow to a single ecosystem when requested, keeping the authorization predicate intact.
    let predicate = match query.ecosystem {
        Some(ecosystem) => QueryPredicate::All(vec![predicate, QueryPredicate::Ecosystem(ecosystem)]),
        None => predicate,
    };

    let page = BrowsePage::new(
        query.limit.unwrap_or(BrowsePage::DEFAULT_LIMIT),
        query.offset.unwrap_or(0),
    );

    match browse.browse_components(&predicate, page).await {
        Ok(components) => Json::<Vec<Component>>(components).into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "content browse failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "content browse failed".to_string()).into_response()
        }
    }
}

/// The content browse handle, or a 404 when the content model is not attached (`metadata.enabled`
/// unset), mirroring the quarantine/maintenance handle accessors.
fn content_browse_handle(state: &AppState) -> Result<&Arc<dyn ContentBrowse>, (StatusCode, String)> {
    state
        .content_browse
        .as_ref()
        .ok_or((StatusCode::NOT_FOUND, "content browse is not enabled".to_string()))
}

/// Authorize the request for [`Action::Browse`] and return the pushed-down predicate.
///
/// When auth is disabled the server is open, so browsing is unconditional ([`QueryPredicate::Always`]).
/// Otherwise the bearer token is authenticated and authorized; an unconditional allow carries no
/// predicate and lists everything, a scoped allow carries the predicate to push down, and a denial
/// (or missing/invalid token) is refused.
async fn authorize_browse(state: &AppState, headers: &HeaderMap) -> Result<QueryPredicate, (StatusCode, String)> {
    if !state.config.auth.enabled {
        return Ok(QueryPredicate::Always);
    }

    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let unauthorized = || (StatusCode::UNAUTHORIZED, "missing or invalid bearer token".to_string());
    let token = token.ok_or_else(unauthorized)?;
    let principal = state
        .authenticator
        .authenticate_bearer(token)
        .ok_or_else(unauthorized)?;

    let resource = Resource {
        namespace: default_namespace(),
        ecosystem: None,
        repository: None,
        coordinate: None,
    };
    let decision = state
        .authorizer
        .authorize(&principal, Action::Browse, &resource)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "browse authorization failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "authorization failed".to_string())
        })?;

    if !decision.is_allowed() {
        tracing::warn!(target: "starmetal::audit", principal = %principal.id(), action = "browse", decision = "deny", "browse denied by authorizer");
        return Err((StatusCode::FORBIDDEN, "browse not permitted".to_string()));
    }

    // An unconditional allow (no predicate) lists everything; a scoped allow pushes its predicate.
    Ok(decision.predicate.unwrap_or(QueryPredicate::Always))
}
