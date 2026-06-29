use axum::Router;
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::header;
use axum::middleware;
use axum::routing::get;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::middleware::auth;
use crate::state::AppState;

/// Build the axum application with all middleware and adapter routes.
pub fn build_app(state: AppState) -> Router {
    #[allow(unused_mut)]
    let mut app = Router::new().route("/healthz", get(healthz));

    #[cfg(feature = "pypi")]
    {
        if state.config.upstream_enabled("pypi") {
            app = app.nest("/pypi", starmetal_adapters::pypi::router());
        }
    }

    #[cfg(feature = "npm")]
    {
        if state.config.upstream_enabled("npm") {
            app = app.nest("/npm", starmetal_adapters::npm::router());
        }
    }

    #[cfg(feature = "cargo-registry")]
    {
        if state.config.upstream_enabled("cargo") {
            app = app.nest("/cargo", starmetal_adapters::cargo::router());
        }
    }

    #[cfg(feature = "hex")]
    {
        if state.config.upstream_enabled("hex") {
            app = app.nest("/hex", starmetal_adapters::hex::router());
        }
    }

    #[cfg(feature = "maven")]
    {
        if state.config.upstream_enabled("maven") {
            app = app.nest("/maven", starmetal_adapters::maven::router());
        }
    }

    #[cfg(feature = "rubygems")]
    {
        if state.config.upstream_enabled("rubygems") {
            app = app.nest("/rubygems", starmetal_adapters::rubygems::router());
        }
    }

    #[cfg(feature = "nuget")]
    {
        if state.config.upstream_enabled("nuget") {
            app = app.nest("/nuget", starmetal_adapters::nuget::router());
        }
    }

    #[cfg(feature = "pub")]
    {
        if state.config.upstream_enabled("pub") {
            app = app.nest("/pub", starmetal_adapters::pubdev::router());
        }
    }

    if state.config.admin.enabled {
        app = app.nest("/admin/api/v1", crate::admin::router());
    }

    app.layer(CompressionLayer::new())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_bearer_token,
        ))
        .layer(cors_layer(&state))
        .layer(RequestBodyLimitLayer::new(
            state.config.server.max_upload_bytes as usize,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let origins = state
        .config
        .server
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect::<Vec<_>>();

    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::POST,
            Method::PUT,
            Method::DELETE,
        ])
        .allow_headers([header::ACCEPT, header::AUTHORIZATION, header::CONTENT_TYPE]);

    if origins.is_empty() {
        layer
    } else {
        layer.allow_origin(AllowOrigin::list(origins))
    }
}
