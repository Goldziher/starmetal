use starmetal_ops::StarmetalRuntime;
use starmetal_server::app::build_app;

pub async fn run(runtime: StarmetalRuntime) -> starmetal_core::error::Result<()> {
    let bind = runtime.config.server.bind.clone();
    // Drive scheduled supply-chain re-correlation alongside the server; the sweep runs until the
    // process exits. A no-op unless a scanner is attached and an interval is configured.
    let _recorrelation = runtime.spawn_recorrelation_scheduler();
    let app = build_app(runtime.app_state());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|err| starmetal_core::error::StarmetalError::Config(format!("failed to bind {bind}: {err}")))?;
    tracing::info!("starmetal listening on {}", bind);
    axum::serve(listener, app)
        .await
        .map_err(|err| starmetal_core::error::StarmetalError::Config(format!("server error: {err}")))
}
