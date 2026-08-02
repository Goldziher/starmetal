use axum::Router;
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::header;
use axum::middleware;
use axum::routing::get;
use starmetal_core::package::Ecosystem;
use starmetal_core::repository::{RecipeKey, RepositoryKind};
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

    // Mount one adapter per resolved repository (ADR-0019). A `proxy` is driven by the recipe
    // registry: its `(ecosystem, kind)` recipe exposing a proxy facet drives the historical proxy
    // mount (behavior-identical to the pre-registry match), using the shared service. A `group` is
    // driven by its per-repository entry in `group_mounts`: the same ecosystem adapter is mounted
    // with a per-repository state whose service is the merged group service. `hosted` is rejected by
    // `validate_mvp`, so a validated deployment never resolves one here.
    for repository in state.config.resolved_repositories() {
        match repository.kind {
            RepositoryKind::Proxy => {
                let key = RecipeKey::new(repository.ecosystem, repository.kind);
                if state
                    .recipe_registry
                    .get(&key)
                    .is_some_and(|recipe| recipe.proxy_facet().is_some())
                {
                    app = mount_proxy(app, &repository.name, repository.ecosystem);
                }
            }
            RepositoryKind::Group => {
                if let Some(mount) = state.group_mounts.get(&repository.name) {
                    let group_state = state.for_group_mount(mount);
                    app = mount_group(app, &repository.name, repository.ecosystem, group_state);
                }
            }
            RepositoryKind::Hosted => {}
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

/// The axum router for `ecosystem`'s protocol adapter, or `None` when that adapter's feature is not
/// compiled in.
///
/// This is the recipe seam (ADR-0019): both proxy and group mounts resolve their adapter here, so
/// adding a repository kind reuses one dispatch. The returned router is unstated (`Router<AppState>`);
/// the caller decides whether to nest it against the shared state (proxy) or bake a per-repository
/// state into it (group).
fn ecosystem_router(ecosystem: Ecosystem) -> Option<Router<AppState>> {
    match ecosystem {
        #[cfg(feature = "pypi")]
        Ecosystem::PyPI => Some(starmetal_adapters::pypi::router()),
        #[cfg(feature = "npm")]
        Ecosystem::Npm => Some(starmetal_adapters::npm::router()),
        #[cfg(feature = "cargo-registry")]
        Ecosystem::Cargo => Some(starmetal_adapters::cargo::router()),
        #[cfg(feature = "hex")]
        Ecosystem::Hex => Some(starmetal_adapters::hex::router()),
        #[cfg(feature = "maven")]
        Ecosystem::Maven => Some(starmetal_adapters::maven::router()),
        #[cfg(feature = "rubygems")]
        Ecosystem::RubyGems => Some(starmetal_adapters::rubygems::router()),
        #[cfg(feature = "nuget")]
        Ecosystem::NuGet => Some(starmetal_adapters::nuget::router()),
        #[cfg(feature = "pub")]
        Ecosystem::Pub => Some(starmetal_adapters::pubdev::router()),
        // Ecosystems whose adapter feature is not compiled in are not mounted.
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

/// Mount the proxy adapter for `ecosystem` under `/{name}`, backed by the shared state applied to
/// the whole router tree. Ecosystems whose feature is not compiled fall through unmounted.
fn mount_proxy(app: Router<AppState>, name: &str, ecosystem: Ecosystem) -> Router<AppState> {
    match ecosystem_router(ecosystem) {
        Some(router) => app.nest(&format!("/{name}"), router),
        None => app,
    }
}

/// Mount the group adapter for `ecosystem` under `/{name}` (ADR-0019), backed by `group_state`.
///
/// `with_state` bakes the per-repository group state into the adapter subtree, so the group serves
/// its merged members while the outer tree's shared state (applied later) governs every proxy mount.
fn mount_group(app: Router<AppState>, name: &str, ecosystem: Ecosystem, group_state: AppState) -> Router<AppState> {
    match ecosystem_router(ecosystem) {
        Some(router) => app.nest(&format!("/{name}"), router.with_state(group_state)),
        None => app,
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
