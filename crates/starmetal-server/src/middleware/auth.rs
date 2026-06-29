use axum::extract::Request;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;

use crate::state::AppState;

pub async fn require_bearer_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !state.config.auth.enabled {
        return next.run(request).await;
    }

    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    if let Some(token) = token
        && (state.config.authorize_bearer_token(token) || state.config.authorize_admin_token(token))
    {
        return next.run(request).await;
    }

    (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
}
