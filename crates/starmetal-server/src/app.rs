use axum::Router;
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::header;
use axum::middleware;
use axum::routing::get;
use starmetal_core::package::Ecosystem;
use starmetal_core::repository::RepositoryKind;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::middleware::auth;
use crate::state::AppState;

/// Build the axum application with all middleware and adapter routes.
pub fn build_app(state: AppState) -> Router {
    #[allow(unused_mut)]
    let mut app: Router<AppState> = Router::new().route("/healthz", get(healthz));

    // Mount one adapter per resolved repository (ADR-0019). The repository set is
    // derived from config: proxy repositories per enabled upstream by default, or
    // the explicit `[[repositories]]` list. Only the proxy kind is wired today.
    for repository in state.config.resolved_repositories() {
        if repository.kind == RepositoryKind::Proxy {
            app = mount_proxy(app, &repository.name, repository.ecosystem);
        }
    }

    if state.config.admin.enabled {
        app = app.nest("/admin/api/v1", crate::admin::router());
    }

    // Content listing with authorization push-down (ADR-0022), mounted outside the admin API since
    // it authorizes Browse rather than Admin. Reports 404 when the content model is not attached.
    app = app.nest("/api/v1", crate::browse::router());

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

/// Mount the proxy adapter for `ecosystem` under `/{name}`.
///
/// The `(kind, ecosystem)` dispatch is the recipe seam (ADR-0019): adding a
/// repository kind extends this match rather than the mount loop. Ecosystems
/// whose feature is not compiled fall through unmounted.
fn mount_proxy(app: Router<AppState>, name: &str, ecosystem: Ecosystem) -> Router<AppState> {
    let path = format!("/{name}");
    match ecosystem {
        #[cfg(feature = "pypi")]
        Ecosystem::PyPI => app.nest(&path, starmetal_adapters::pypi::router()),
        #[cfg(feature = "npm")]
        Ecosystem::Npm => app.nest(&path, starmetal_adapters::npm::router()),
        #[cfg(feature = "cargo-registry")]
        Ecosystem::Cargo => app.nest(&path, starmetal_adapters::cargo::router()),
        #[cfg(feature = "hex")]
        Ecosystem::Hex => app.nest(&path, starmetal_adapters::hex::router()),
        #[cfg(feature = "maven")]
        Ecosystem::Maven => app.nest(&path, starmetal_adapters::maven::router()),
        #[cfg(feature = "rubygems")]
        Ecosystem::RubyGems => app.nest(&path, starmetal_adapters::rubygems::router()),
        #[cfg(feature = "nuget")]
        Ecosystem::NuGet => app.nest(&path, starmetal_adapters::nuget::router()),
        #[cfg(feature = "pub")]
        Ecosystem::Pub => app.nest(&path, starmetal_adapters::pubdev::router()),
        // Ecosystems whose adapter feature is not compiled in are not mounted.
        #[allow(unreachable_patterns)]
        _ => app,
    }
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
