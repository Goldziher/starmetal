use std::net::SocketAddr;
use std::sync::Arc;

use ahash::AHashMap;
use depot_adapters::cargo::upstream::CargoUpstreamClient;
use depot_adapters::hex::upstream::HexUpstreamClient;
use depot_adapters::maven::upstream::MavenUpstreamClient;
use depot_adapters::npm::upstream::NpmUpstreamClient;
use depot_adapters::nuget::upstream::NuGetUpstreamClient;
use depot_adapters::pubdev::upstream::PubUpstreamClient;
use depot_adapters::pypi::upstream::PypiUpstreamClient;
use depot_adapters::rubygems::upstream::RubyGemsUpstreamClient;
use depot_core::config::Config;
use depot_core::package::Ecosystem;
use depot_core::policy::PolicyConfig;
use depot_core::ports::UpstreamClient;
use depot_server::state::{AppState, UpstreamClients};
use depot_service::CachingPackageService;
use depot_storage::OpenDalStorage;

/// A running depot test server with in-memory storage.
pub struct TestServer {
    pub addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    /// Start a depot server on a random port with memory storage.
    ///
    /// Reads optional env vars:
    /// - `DEPOT_TEST_UPSTREAM_PYPI_URL`: override PyPI upstream (default: https://pypi.org)
    /// - `DEPOT_TEST_UPSTREAM_NPM_URL`: override npm upstream (default: https://registry.npmjs.org)
    /// - `DEPOT_TEST_UPSTREAM_CARGO_INDEX_URL`: override Cargo index (default: https://index.crates.io)
    /// - `DEPOT_TEST_UPSTREAM_CARGO_DL_URL`: override Cargo download (default: https://static.crates.io/crates)
    /// - `DEPOT_TEST_UPSTREAM_HEX_URL`: override Hex upstream (default: https://hex.pm)
    /// - `DEPOT_TEST_UPSTREAM_HEX_REPO_URL`: override Hex repo (default: https://repo.hex.pm)
    pub async fn start() -> Self {
        let storage = OpenDalStorage::memory().expect("failed to create memory storage");
        let mut upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();

        // PyPI
        let pypi_url = std::env::var("DEPOT_TEST_UPSTREAM_PYPI_URL")
            .unwrap_or_else(|_| "https://pypi.org".into());
        let pypi_client = Arc::new(PypiUpstreamClient::new(pypi_url));
        upstream_clients.insert(Ecosystem::PyPI, pypi_client.clone());

        // npm
        let npm_url = std::env::var("DEPOT_TEST_UPSTREAM_NPM_URL")
            .unwrap_or_else(|_| "https://registry.npmjs.org".into());
        let npm_client = Arc::new(NpmUpstreamClient::new(npm_url));
        upstream_clients.insert(Ecosystem::Npm, npm_client.clone());

        // Cargo
        let cargo_index_url = std::env::var("DEPOT_TEST_UPSTREAM_CARGO_INDEX_URL")
            .unwrap_or_else(|_| "https://index.crates.io".into());
        let cargo_dl_url = std::env::var("DEPOT_TEST_UPSTREAM_CARGO_DL_URL")
            .unwrap_or_else(|_| "https://static.crates.io/crates".into());
        let cargo_client = Arc::new(CargoUpstreamClient::new(cargo_index_url, cargo_dl_url));
        upstream_clients.insert(Ecosystem::Cargo, cargo_client.clone());

        // Hex
        let hex_url = std::env::var("DEPOT_TEST_UPSTREAM_HEX_URL")
            .unwrap_or_else(|_| "https://hex.pm".into());
        let hex_repo_url = std::env::var("DEPOT_TEST_UPSTREAM_HEX_REPO_URL")
            .unwrap_or_else(|_| "https://repo.hex.pm".into());
        let hex_client = Arc::new(HexUpstreamClient::new(hex_url, hex_repo_url));
        upstream_clients.insert(Ecosystem::Hex, hex_client.clone());

        let maven_client = Arc::new(MavenUpstreamClient::new(
            "https://repo1.maven.org/maven2".into(),
        ));
        let rubygems_client = Arc::new(RubyGemsUpstreamClient::new("https://rubygems.org".into()));
        let nuget_client = Arc::new(NuGetUpstreamClient::new(
            "https://api.nuget.org/v3/index.json".into(),
        ));
        let pub_client = Arc::new(PubUpstreamClient::new("https://pub.dev".into()));

        let service = CachingPackageService::new(
            Arc::new(storage),
            upstream_clients,
            PolicyConfig::default(),
        );

        let config = Config::default();
        let upstreams = UpstreamClients {
            pypi_upstream: pypi_client,
            cargo_upstream: cargo_client,
            npm_upstream: npm_client,
            hex_upstream: hex_client,
            maven_upstream: maven_client,
            rubygems_upstream: rubygems_client,
            nuget_upstream: nuget_client,
            pub_upstream: pub_client,
        };
        let state = AppState::new(config, Arc::new(service), upstreams);
        let app = depot_server::app::build_app(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let addr = listener.local_addr().expect("failed to get local addr");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("server error");
        });

        Self {
            addr,
            shutdown: shutdown_tx,
        }
    }

    /// Base URL for this server (e.g. "http://127.0.0.1:12345")
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// PyPI simple index URL for pip --index-url
    pub fn pypi_index_url(&self) -> String {
        format!("{}/pypi/simple/", self.base_url())
    }

    /// Shutdown the server.
    pub fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}
