use std::net::SocketAddr;
use std::sync::Arc;

use ahash::AHashMap;
use starmetal_adapters::cargo::upstream::CargoUpstreamClient;
use starmetal_adapters::hex::upstream::HexUpstreamClient;
use starmetal_adapters::maven::upstream::MavenUpstreamClient;
use starmetal_adapters::npm::upstream::NpmUpstreamClient;
use starmetal_adapters::nuget::upstream::NuGetUpstreamClient;
use starmetal_adapters::pubdev::upstream::PubUpstreamClient;
use starmetal_adapters::pypi::upstream::PypiUpstreamClient;
use starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient;
use starmetal_core::config::Config;
use starmetal_core::package::Ecosystem;
use starmetal_core::policy::PolicyConfig;
use starmetal_core::ports::UpstreamClient;
use starmetal_core::repository::{HostedFacet, ProxyFacet, RecipeRegistry, RepositoryKind};
use starmetal_git::GixMirror;
use starmetal_server::state::{AppState, UpstreamClients};
use starmetal_service::{CachingPackageService, ProxyRecipe};
use starmetal_storage::OpenDalStorage;

/// A running starmetal test server with in-memory storage.
pub struct TestServer {
    pub addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    // Kept alive for the server's lifetime: the Go module proxy's git-mirror cache lives here.
    _go_mirror_cache: tempfile::TempDir,
    // Kept alive for the server's lifetime: the Zig tarball proxy's git-mirror cache lives here.
    _zig_mirror_cache: tempfile::TempDir,
    // Kept alive for the server's lifetime: the Swift Package Registry proxy's git-mirror cache
    // lives here.
    _swift_mirror_cache: tempfile::TempDir,
}

impl TestServer {
    /// Start a starmetal server on a random port with memory storage.
    ///
    /// Reads optional env vars:
    /// - `STARMETAL_TEST_UPSTREAM_PYPI_URL`: override PyPI upstream (default: https://pypi.org)
    /// - `STARMETAL_TEST_UPSTREAM_NPM_URL`: override npm upstream (default: https://registry.npmjs.org)
    /// - `STARMETAL_TEST_UPSTREAM_CARGO_INDEX_URL`: override Cargo index (default: https://index.crates.io)
    /// - `STARMETAL_TEST_UPSTREAM_CARGO_DL_URL`: override Cargo download (default: https://static.crates.io/crates)
    /// - `STARMETAL_TEST_UPSTREAM_HEX_URL`: override Hex upstream (default: https://hex.pm)
    /// - `STARMETAL_TEST_UPSTREAM_HEX_REPO_URL`: override Hex repo (default: https://repo.hex.pm)
    /// - `STARMETAL_TEST_UPSTREAM_MAVEN_URL`: override Maven upstream (default: https://repo1.maven.org/maven2)
    /// - `STARMETAL_TEST_UPSTREAM_RUBYGEMS_URL`: override RubyGems upstream (default: https://rubygems.org)
    /// - `STARMETAL_TEST_UPSTREAM_NUGET_URL`: override NuGet upstream (default: https://api.nuget.org/v3/index.json)
    /// - `STARMETAL_TEST_UPSTREAM_PUB_URL`: override pub.dev upstream (default: https://pub.dev)
    pub async fn start() -> Self {
        Self::start_with_all_enabled_and_config(false, |_| {}).await
    }

    /// Start a starmetal server with all configured registry routes enabled.
    pub async fn start_all_enabled() -> Self {
        Self::start_with_all_enabled_and_config(true, |_| {}).await
    }

    /// Start a starmetal server applying `configure` to the default config.
    ///
    /// All upstream clients are registered and memory storage is used; the
    /// closure customizes the config (e.g. `repositories`) before `build_app`.
    pub async fn start_with_config(configure: impl FnOnce(&mut Config)) -> Self {
        Self::start_with_all_enabled_and_config(false, configure).await
    }

    /// Start a starmetal server with the admin API enabled.
    pub async fn start_with_admin() -> Self {
        Self::start_with_all_enabled_and_config(false, |config| {
            config.admin.enabled = true;
            config.admin.tokens.push("admin-token".to_string());
        })
        .await
    }

    /// Start a starmetal server with read auth and admin API enabled.
    pub async fn start_with_admin_and_read_auth() -> Self {
        Self::start_with_all_enabled_and_config(false, |config| {
            config.auth.enabled = true;
            config.auth.tokens.push("read-token".to_string());
            config.admin.enabled = true;
            config.admin.tokens.push("admin-token".to_string());
        })
        .await
    }

    async fn start_with_all_enabled_and_config(enable_all: bool, configure: impl FnOnce(&mut Config)) -> Self {
        let storage = OpenDalStorage::memory().expect("failed to create memory storage");
        let mut upstream_clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();

        let pypi_url = std::env::var("STARMETAL_TEST_UPSTREAM_PYPI_URL").unwrap_or_else(|_| "https://pypi.org".into());
        let pypi_client = Arc::new(PypiUpstreamClient::new(pypi_url));
        upstream_clients.insert(Ecosystem::PyPI, pypi_client.clone());

        let npm_url =
            std::env::var("STARMETAL_TEST_UPSTREAM_NPM_URL").unwrap_or_else(|_| "https://registry.npmjs.org".into());
        let npm_client = Arc::new(NpmUpstreamClient::new(npm_url));
        upstream_clients.insert(Ecosystem::Npm, npm_client.clone());

        let cargo_index_url = std::env::var("STARMETAL_TEST_UPSTREAM_CARGO_INDEX_URL")
            .unwrap_or_else(|_| "https://index.crates.io".into());
        let cargo_dl_url = std::env::var("STARMETAL_TEST_UPSTREAM_CARGO_DL_URL")
            .unwrap_or_else(|_| "https://static.crates.io/crates".into());
        let cargo_client = Arc::new(CargoUpstreamClient::new(cargo_index_url, cargo_dl_url));
        upstream_clients.insert(Ecosystem::Cargo, cargo_client.clone());

        let hex_url = std::env::var("STARMETAL_TEST_UPSTREAM_HEX_URL").unwrap_or_else(|_| "https://hex.pm".into());
        let hex_repo_url =
            std::env::var("STARMETAL_TEST_UPSTREAM_HEX_REPO_URL").unwrap_or_else(|_| "https://repo.hex.pm".into());
        let hex_client = Arc::new(HexUpstreamClient::new(hex_url, hex_repo_url));
        upstream_clients.insert(Ecosystem::Hex, hex_client.clone());

        let maven_url = std::env::var("STARMETAL_TEST_UPSTREAM_MAVEN_URL")
            .unwrap_or_else(|_| "https://repo1.maven.org/maven2".into());
        let maven_client = Arc::new(MavenUpstreamClient::new(maven_url));
        upstream_clients.insert(Ecosystem::Maven, maven_client.clone());

        let rubygems_url =
            std::env::var("STARMETAL_TEST_UPSTREAM_RUBYGEMS_URL").unwrap_or_else(|_| "https://rubygems.org".into());
        let rubygems_client = Arc::new(RubyGemsUpstreamClient::new(rubygems_url));
        upstream_clients.insert(Ecosystem::RubyGems, rubygems_client.clone());

        let nuget_url = std::env::var("STARMETAL_TEST_UPSTREAM_NUGET_URL")
            .unwrap_or_else(|_| "https://api.nuget.org/v3/index.json".into());
        let nuget_client = Arc::new(NuGetUpstreamClient::new(nuget_url));
        upstream_clients.insert(Ecosystem::NuGet, nuget_client.clone());

        let pub_url = std::env::var("STARMETAL_TEST_UPSTREAM_PUB_URL").unwrap_or_else(|_| "https://pub.dev".into());
        let pub_client = Arc::new(PubUpstreamClient::new(pub_url));
        upstream_clients.insert(Ecosystem::Pub, pub_client.clone());

        // Go is never registered into `upstream_clients`/`CachingPackageService` (ADR-0023): the
        // GOPROXY adapter reads through this mirror handle directly.
        let go_mirror_cache = tempfile::tempdir().expect("go mirror cache tempdir");
        let go_mirror: Arc<dyn starmetal_git::GitMirror> = Arc::new(GixMirror::new(
            go_mirror_cache.path(),
            std::time::Duration::from_secs(300),
        ));

        // Zig, like Go, is never registered into `upstream_clients`/`CachingPackageService`
        // (ADR-0023): the tarball proxy reads through this mirror handle directly.
        let zig_mirror_cache = tempfile::tempdir().expect("zig mirror cache tempdir");
        let zig_mirror: Arc<dyn starmetal_git::GitMirror> = Arc::new(GixMirror::new(
            zig_mirror_cache.path(),
            std::time::Duration::from_secs(300),
        ));

        // Swift, like Go and Zig, is never registered into `upstream_clients`/
        // `CachingPackageService` (ADR-0023): the registry proxy reads through this mirror handle
        // directly.
        let swift_mirror_cache = tempfile::tempdir().expect("swift mirror cache tempdir");
        let swift_mirror: Arc<dyn starmetal_git::GitMirror> = Arc::new(GixMirror::new(
            swift_mirror_cache.path(),
            std::time::Duration::from_secs(300),
        ));
        let swift_archive_cache = Arc::new(starmetal_adapters::swift::upstream::SwiftArchiveCache::new());

        let service = Arc::new(CachingPackageService::new(
            Arc::new(storage),
            upstream_clients,
            PolicyConfig::default(),
        ));

        let mut config = Config::default();
        if enable_all {
            for name in ["pypi", "npm", "cargo", "hex", "maven", "rubygems", "nuget", "pub"] {
                config
                    .upstream
                    .get_mut(name)
                    .unwrap_or_else(|| panic!("default upstream missing: {name}"))
                    .enabled = true;
            }
            config.go.enabled = true;
            config.zig.enabled = true;
            config.swift.enabled = true;
        }
        configure(&mut config);
        let upstreams = UpstreamClients {
            pypi_upstream: pypi_client,
            cargo_upstream: cargo_client,
            npm_upstream: npm_client,
            hex_upstream: hex_client,
            maven_upstream: maven_client,
            rubygems_upstream: rubygems_client,
            nuget_upstream: nuget_client,
            pub_upstream: pub_client,
            go_mirror,
            zig_mirror,
            swift_mirror,
            swift_archive_cache,
        };
        // Populate the facet recipe registry the same way the runtime does, so `build_app`'s
        // registry-driven mounting produces the historical proxy routes (ADR-0019). Go, Zig, and
        // Swift have no ProxyFacet recipe (ADR-0023) — `build_app` mounts each unconditionally
        // instead.
        let mut recipe_registry = RecipeRegistry::new();
        for repository in config.resolved_repositories() {
            if repository.kind == RepositoryKind::Proxy
                && repository.ecosystem != Ecosystem::Go
                && repository.ecosystem != Ecosystem::Zig
                && repository.ecosystem != Ecosystem::Swift
            {
                recipe_registry.register(Arc::new(ProxyRecipe::new(
                    repository.ecosystem,
                    service.clone() as Arc<dyn ProxyFacet>,
                    service.clone() as Arc<dyn HostedFacet>,
                )));
            }
        }
        let state = AppState::new(config, service.clone(), service.clone(), service, upstreams)
            .with_recipe_registry(Arc::new(recipe_registry));
        let app = starmetal_server::app::build_app(state);

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
            _go_mirror_cache: go_mirror_cache,
            _zig_mirror_cache: zig_mirror_cache,
            _swift_mirror_cache: swift_mirror_cache,
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

    /// npm registry URL for npm --registry.
    pub fn npm_registry_url(&self) -> String {
        format!("{}/npm", self.base_url())
    }

    /// Cargo sparse registry URL for .cargo/config.toml.
    pub fn cargo_sparse_url(&self) -> String {
        format!("{}/cargo/", self.base_url())
    }

    /// Hex mirror URL for HEX_MIRROR.
    pub fn hex_mirror_url(&self) -> String {
        format!("{}/hex", self.base_url())
    }

    /// Maven repository URL for settings.xml mirrors.
    pub fn maven_url(&self) -> String {
        format!("{}/maven", self.base_url())
    }

    /// RubyGems source URL for Gemfile source.
    pub fn rubygems_url(&self) -> String {
        format!("{}/rubygems", self.base_url())
    }

    /// NuGet V3 service index URL for nuget.config.
    pub fn nuget_index_url(&self) -> String {
        format!("{}/nuget/v3/index.json", self.base_url())
    }

    /// Hosted pub repository base URL for PUB_HOSTED_URL.
    pub fn pub_hosted_url(&self) -> String {
        format!("{}/pub", self.base_url())
    }

    /// Go module proxy URL for `GOPROXY`.
    pub fn go_proxy_url(&self) -> String {
        format!("{}/go", self.base_url())
    }

    /// Zig tarball proxy base URL, mounted at `/zig`.
    pub fn zig_proxy_url(&self) -> String {
        format!("{}/zig", self.base_url())
    }

    /// Swift Package Registry proxy base URL, mounted at `/swift`.
    pub fn swift_proxy_url(&self) -> String {
        format!("{}/swift", self.base_url())
    }

    /// Shutdown the server.
    pub fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}
