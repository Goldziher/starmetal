use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

mod git_fixture;

pub use git_fixture::{
    FIXTURE_COMMIT_DATE, GitFixture, GitFixtureBuilder, go_module_fixture, require_go, require_swift, require_tool,
    require_zig, swift_package_fixture, zig_package_fixture,
};

use ahash::AHashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pkcs8::EncodePrivateKey;
use starmetal_adapters::cargo::upstream::CargoUpstreamClient;
use starmetal_adapters::hex::upstream::HexUpstreamClient;
use starmetal_adapters::maven::upstream::MavenUpstreamClient;
use starmetal_adapters::npm::upstream::NpmUpstreamClient;
use starmetal_adapters::nuget::upstream::NuGetUpstreamClient;
use starmetal_adapters::pubdev::upstream::PubUpstreamClient;
use starmetal_adapters::pypi::upstream::PypiUpstreamClient;
use starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient;
#[cfg(feature = "oidc")]
use starmetal_core::authz::{Authenticator, CompositeAuthenticator};
use starmetal_core::config::Config;
use starmetal_core::package::Ecosystem;
use starmetal_core::ports::{PackageService, UpstreamClient};
use starmetal_core::repository::{HostedFacet, ProxyFacet, RecipeRegistry, RepositoryKind};
use starmetal_core::signing::{SigningAlgorithm, SigningConfig, SigningKeyConfig, SigningKeyStatus, SigningMode};
use starmetal_core::supply_chain::{IngestQuarantine, QuarantineReview, SbomIndex, Scanner};
use starmetal_git::GixMirror;
use starmetal_server::state::{AppState, GroupMount, UpstreamClients};
use starmetal_service::{CachingPackageService, GroupPackageService, ProxyRecipe, SigningService};
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
    // Kept alive for the server's lifetime when `TestServerBuilder::with_signing_key` was used: the
    // 0600 temp PEM file `config.signing` points at, plus the public material for asserting on
    // emitted DSSE signatures. ~keep
    signing_key: Option<TestSigningKey>,
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
        Self::builder().start().await
    }

    /// Start a starmetal server with all configured registry routes enabled.
    pub async fn start_all_enabled() -> Self {
        Self::builder().enable_all(true).start().await
    }

    /// Start a starmetal server applying `configure` to the default config.
    ///
    /// All upstream clients are registered and memory storage is used; the
    /// closure customizes the config (e.g. `repositories`) before `build_app`.
    pub async fn start_with_config(configure: impl FnOnce(&mut Config) + 'static) -> Self {
        Self::builder().configure(configure).start().await
    }

    /// Start a starmetal server with the admin API enabled.
    pub async fn start_with_admin() -> Self {
        Self::builder()
            .configure(|config| {
                config.admin.enabled = true;
                config.admin.tokens.push("admin-token".to_string());
            })
            .start()
            .await
    }

    /// Start a starmetal server with read auth and admin API enabled.
    pub async fn start_with_admin_and_read_auth() -> Self {
        Self::builder()
            .configure(|config| {
                config.auth.enabled = true;
                config.auth.tokens.push("read-token".to_string());
                config.admin.enabled = true;
                config.admin.tokens.push("admin-token".to_string());
            })
            .start()
            .await
    }

    /// Start building a server with capabilities production wires but the constructors above leave
    /// unset by default: a vulnerability scanner, publish signing, group repository members, and (with
    /// the `oidc` feature) an OIDC identity backend. See [`TestServerBuilder`].
    pub fn builder() -> TestServerBuilder {
        TestServerBuilder::new()
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

    /// The signing key injected via [`TestServerBuilder::with_signing_key`], or `None` if the server
    /// was started without one. Exposes the public material so a test can verify emitted DSSE
    /// signatures.
    pub fn signing_key(&self) -> Option<&TestSigningKey> {
        self.signing_key.as_ref()
    }

    /// Shutdown the server.
    pub fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

/// Builds a [`TestServer`], optionally wiring the supply-chain, signing, group, and (with the `oidc`
/// feature) OIDC handles that `starmetal-ops` assembles in production but a bare server leaves at
/// `None`. Every capability is off by default, so `TestServer::start()` and friends remain
/// byte-identical to a builder with nothing attached.
pub struct TestServerBuilder {
    enable_all: bool,
    configure: Box<dyn FnOnce(&mut Config)>,
    scanner: Option<Arc<dyn Scanner>>,
    signing_key: Option<TestSigningKey>,
    group_members: HashMap<String, Vec<Arc<dyn PackageService>>>,
}

impl TestServerBuilder {
    fn new() -> Self {
        Self {
            enable_all: false,
            configure: Box::new(|_| {}),
            scanner: None,
            signing_key: None,
            group_members: HashMap::new(),
        }
    }

    /// Enable all configured registry routes (mirrors `TestServer::start_all_enabled`).
    pub fn enable_all(mut self, enable_all: bool) -> Self {
        self.enable_all = enable_all;
        self
    }

    /// Customize the config before the server is built. Replaces any closure set by a previous call.
    pub fn configure(mut self, configure: impl FnOnce(&mut Config) + 'static) -> Self {
        self.configure = Box::new(configure);
        self
    }

    /// Attach a vulnerability scanner (ADR-0024), mirroring `starmetal-ops`'s `attach_scanner`. Only
    /// takes effect when the resulting config also has `supply_chain.enabled` set (via `configure`) —
    /// the same condition production gates on — in which case `enforce_scan_on_serve`,
    /// `with_quarantine`, and `with_ingest_quarantine` are driven by `config.supply_chain`, and the
    /// admin quarantine/ingest-quarantine handles are attached to `AppState`.
    pub fn with_scanner(mut self, scanner: Arc<dyn Scanner>) -> Self {
        self.scanner = Some(scanner);
        self
    }

    /// Inject a publish signing key (ADR-0004/ADR-0024), wiring `config.signing` so the real
    /// `SigningService::from_config` path loads it (private-key-permission check included). Applied
    /// before the `configure` closure runs, so a test can further customize `config.signing` (e.g.
    /// add a second key, or flip the mode) on top of the default `SignAndVerify` wiring this installs.
    pub fn with_signing_key(mut self, signing_key: TestSigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Override the backing member services for one declared `group` repository (looked up by name
    /// against `config.repositories` at start time), instead of every member defaulting to the single
    /// shared caching service (what production does, since every proxy of one ecosystem shares it —
    /// see `starmetal-ops`). Needed to reproduce physically-distinct members for union/first-match
    /// assertions against genuinely different backing data.
    pub fn with_group_members(
        mut self,
        repository_name: impl Into<String>,
        members: Vec<Arc<dyn PackageService>>,
    ) -> Self {
        self.group_members.insert(repository_name.into(), members);
        self
    }

    /// Build and start the server.
    pub async fn start(self) -> TestServer {
        let TestServerBuilder {
            enable_all,
            configure,
            scanner,
            signing_key,
            mut group_members,
        } = self;

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
        if let Some(signing_key) = &signing_key {
            signing_key.apply_to(&mut config.signing);
        }
        configure(&mut config);

        #[cfg(not(feature = "oidc"))]
        assert!(
            !config.oidc.enabled,
            "config.oidc.enabled requires building starmetal-integration-tests with the `oidc` feature"
        );

        // Assemble the caching service exactly like `starmetal-ops` does (crates/starmetal-ops/src/
        // lib.rs ~:264-307): signing first, then the scanner/serve/quarantine gates, then SBOM,
        // quota, and the signature/provenance requirement gates — all BEFORE the single `Arc::new`
        // below, so every AppState handle derived from `service` observes the same instance the
        // gates were applied to. ~keep
        let signing = SigningService::from_config(&config.signing).expect("signing config should be valid");
        let mut service_builder = CachingPackageService::new_with_signing(
            Arc::new(storage),
            upstream_clients,
            config.policies.clone(),
            signing,
        );

        // Mirrors `attach_scanner`'s gate (starmetal-ops ~:171-190): a scanner only takes effect when
        // `supply_chain.enabled`, matching production exactly rather than always attaching whatever
        // `with_scanner` was handed.
        let scanner_attached = scanner.is_some() && config.supply_chain.enabled;
        if let Some(scanner) = scanner
            && config.supply_chain.enabled
        {
            service_builder = service_builder
                .with_scanner(scanner)
                .enforce_scan_on_serve(config.supply_chain.enforce_on_serve)
                .with_quarantine(config.supply_chain.quarantine)
                .with_ingest_quarantine(config.supply_chain.ingest_quarantine);
        }
        // SBOM generation is independent of the scanner (starmetal-ops ~:278-282).
        if config.supply_chain.sbom.enabled {
            service_builder = service_builder.with_sbom_formats(config.supply_chain.sbom.formats.clone());
        }
        // Publish quota gate (ADR-0021, starmetal-ops ~:286-290): independent of the scanner and of
        // signing.
        if config.supply_chain.quota.enabled {
            service_builder = service_builder.with_quota(config.supply_chain.quota.clone());
        }
        // Signature/provenance gate (ADR-0024, starmetal-ops ~:294-306): requiring either without
        // `[signing]` configured is a startup misconfiguration in production; mirror that here as a
        // panic rather than silently ignoring it.
        if config.supply_chain.require_signature || config.supply_chain.require_provenance {
            assert!(
                config.signing.enabled,
                "supply_chain.require_signature/require_provenance require [signing] to be enabled"
            );
            service_builder = service_builder
                .require_signature(config.supply_chain.require_signature)
                .require_provenance(config.supply_chain.require_provenance)
                .emit_provenance(config.supply_chain.require_provenance);
        }
        let service = Arc::new(service_builder);

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

        // Group backing services (ADR-0019, starmetal-ops ~:331-355): one read-only
        // `GroupPackageService` per declared group. A member defaults to cloning the shared caching
        // service (production behavior, since every proxy of one ecosystem shares it) unless the
        // harness seeded physically-distinct members via `with_group_members`.
        let mut group_mounts: HashMap<String, GroupMount> = HashMap::new();
        for repository in config.resolved_repositories() {
            if repository.kind != RepositoryKind::Group {
                continue;
            }
            let members: Vec<Arc<dyn PackageService>> = group_members.remove(&repository.name).unwrap_or_else(|| {
                repository
                    .members
                    .iter()
                    .map(|_member| service.clone() as Arc<dyn PackageService>)
                    .collect()
            });
            let group = Arc::new(GroupPackageService::new(repository.ecosystem, members));
            group_mounts.insert(
                repository.name.clone(),
                GroupMount {
                    package_service: group.clone(),
                    publishing_service: group.clone(),
                    statistics_service: group,
                },
            );
        }

        // Expose the supply-chain handles (ADR-0024) only when a scanner is actually attached, so a
        // server built without one carries neither — matching `starmetal-ops` ~:357-380.
        let quarantine: Option<Arc<dyn QuarantineReview>> =
            scanner_attached.then(|| service.clone() as Arc<dyn QuarantineReview>);
        let ingest_quarantine: Option<Arc<dyn IngestQuarantine>> =
            scanner_attached.then(|| service.clone() as Arc<dyn IngestQuarantine>);
        // SBOM retrieval is exposed whenever SBOM generation is enabled — independent of the scanner.
        let sbom: Option<Arc<dyn SbomIndex>> = config
            .supply_chain
            .sbom
            .enabled
            .then(|| service.clone() as Arc<dyn SbomIndex>);

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

        let state = AppState::new(config, service.clone(), service.clone(), service, upstreams)
            .with_recipe_registry(Arc::new(recipe_registry))
            .with_group_mounts(Arc::new(group_mounts))
            .with_quarantine(quarantine)
            .with_ingest_quarantine(ingest_quarantine)
            .with_sbom(sbom);
        // Postgres-backed content store (ADR-0020): deferred to milestone M5, so `with_content_store`
        // is never wired here and `content_maintenance`/`content_browse` stay at the `AppState`
        // default of `None`.

        // Compose the OIDC backend ahead of the flat-token authenticator (ADR-0022), mirroring
        // `starmetal-ops`'s `app_state` (~:545-555), using the inline `config.oidc.jwks` only — no
        // file or network I/O.
        #[cfg(feature = "oidc")]
        let state = {
            if state.config.oidc.enabled {
                let oidc = starmetal_oidc::OidcAuthenticator::into_authenticator(&state.config.oidc)
                    .expect("oidc config should be valid for TestServer");
                let flat_tokens: Arc<dyn Authenticator> = state.authorizer.clone();
                let composite = Arc::new(CompositeAuthenticator::new(vec![oidc, flat_tokens]));
                state.with_authenticator(composite)
            } else {
                state
            }
        };

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

        TestServer {
            addr,
            shutdown: shutdown_tx,
            _go_mirror_cache: go_mirror_cache,
            _zig_mirror_cache: zig_mirror_cache,
            _swift_mirror_cache: swift_mirror_cache,
            signing_key,
        }
    }
}

/// A test-only ed25519 signing key (ADR-0004/ADR-0024 `[signing]`), generated fresh per instance and
/// staged as a `0600` PKCS#8 PEM file so it loads through the real `SigningService::from_config` path
/// — including its private-key-permission check — exactly as a production key would.
///
/// `TestServerBuilder::with_signing_key` injects this into `config.signing`, enabling `[signing]` in
/// `SignAndVerify` mode with the key allowed for every ecosystem/package (empty allow-lists). The
/// backing temp file is kept alive on `TestServer` for the server's lifetime.
pub struct TestSigningKey {
    private_key_file: tempfile::NamedTempFile,
    key_id: String,
    verifying_key: VerifyingKey,
}

impl TestSigningKey {
    /// Generate a fresh keypair under the default key id `"test-key"`.
    pub fn generate() -> Self {
        Self::with_id("test-key")
    }

    /// Generate a fresh keypair under a caller-chosen key id — useful when a test wires more than one
    /// signing key (e.g. to exercise key rotation).
    pub fn with_id(key_id: impl Into<String>) -> Self {
        let secret = generate_ed25519_secret();
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let pem = signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("encode ed25519 signing key as PKCS#8 PEM");

        let private_key_file = tempfile::NamedTempFile::new().expect("create temp signing key file");
        std::fs::write(private_key_file.path(), pem.as_bytes()).expect("write temp signing key file");
        #[cfg(unix)]
        std::fs::set_permissions(private_key_file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("restrict temp signing key file permissions");

        Self {
            private_key_file,
            key_id: key_id.into(),
            verifying_key,
        }
    }

    /// The public verifying key, for asserting on emitted DSSE signatures.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// The signing key's configured id (`SignatureStatement::key_id` / `DsseSignature::key_id`).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Enable `[signing]` in `SignAndVerify` mode with this key, allowed for every ecosystem/package.
    fn apply_to(&self, signing: &mut SigningConfig) {
        signing.enabled = true;
        signing.mode = SigningMode::SignAndVerify;
        signing.verify_on_read = true;
        signing.keys.push(SigningKeyConfig {
            id: self.key_id.clone(),
            algorithm: SigningAlgorithm::Ed25519,
            private_key_file: Some(self.private_key_file.path().to_path_buf()),
            public_key_file: None,
            private_key_password_env: None,
            certificate_file: None,
            certificate_chain_file: None,
            ecosystems: Vec::new(),
            packages: Vec::new(),
            status: SigningKeyStatus::Active,
        });
    }
}

/// Derive a fresh 32-byte ed25519 seed from a monotonic counter mixed with the current time via
/// blake3, so repeated `TestSigningKey` construction within one process yields distinct keys without
/// pulling in a CSPRNG dependency — ed25519 needs no cryptographic-quality randomness here, only a
/// valid 32-byte scalar seed for a throwaway test key.
fn generate_ed25519_secret() -> [u8; 32] {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let seed = format!("starmetal-test-signing-key-{count}-{nanos}");
    *blake3::hash(seed.as_bytes()).as_bytes()
}
