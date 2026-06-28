use depot_ops::DepotRuntime;
use depot_server::app::build_app;

pub async fn run(runtime: DepotRuntime) -> depot_core::error::Result<()> {
    let bind = runtime.config.server.bind.clone();
    let app = build_app(runtime.app_state());
    let listener = tokio::net::TcpListener::bind(&bind).await.map_err(|err| {
        depot_core::error::DepotError::Config(format!("failed to bind {bind}: {err}"))
    })?;
    tracing::info!("starmetal listening on {}", bind);
    axum::serve(listener, app)
        .await
        .map_err(|err| depot_core::error::DepotError::Config(format!("server error: {err}")))
}
