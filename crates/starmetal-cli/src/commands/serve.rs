use starmetal_ops::StarmetalRuntime;
use starmetal_server::app::build_app;

pub async fn run(runtime: StarmetalRuntime) -> starmetal_core::error::Result<()> {
    let bind = runtime.config.server.bind.clone();
    let app = build_app(runtime.app_state());
    let listener = tokio::net::TcpListener::bind(&bind).await.map_err(|err| {
        starmetal_core::error::StarmetalError::Config(format!("failed to bind {bind}: {err}"))
    })?;
    tracing::info!("starmetal listening on {}", bind);
    axum::serve(listener, app).await.map_err(|err| {
        starmetal_core::error::StarmetalError::Config(format!("server error: {err}"))
    })
}
