use std::sync::Arc;

use ahash::AHashMap;
use depot_core::config::Config;
use depot_core::package::Ecosystem;
use depot_core::ports::UpstreamClient;
use depot_server::app::build_app;
use depot_server::state::{AppState, UpstreamClients};
use depot_service::CachingPackageService;
use depot_storage::OpenDalStorage;

pub fn run(config: Config) {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        config.validate_mvp().unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });

        let storage = build_storage(&config);
        let mut clients: AHashMap<Ecosystem, Arc<dyn UpstreamClient>> = AHashMap::new();

        #[cfg(feature = "pypi")]
        let pypi_upstream = register_pypi_upstream(&config, &mut clients);
        #[cfg(feature = "cargo-registry")]
        let cargo_upstream = register_cargo_upstream(&config, &mut clients);
        #[cfg(feature = "npm")]
        let npm_upstream = register_npm_upstream(&config, &mut clients);
        #[cfg(feature = "hex")]
        let hex_upstream = register_hex_upstream(&config, &mut clients);
        #[cfg(feature = "maven")]
        let maven_upstream = register_maven_upstream(&config, &mut clients);
        #[cfg(feature = "rubygems")]
        let rubygems_upstream = register_rubygems_upstream(&config, &mut clients);
        #[cfg(feature = "nuget")]
        let nuget_upstream = register_nuget_upstream(&config, &mut clients);
        #[cfg(feature = "pub")]
        let pub_upstream = register_pub_upstream(&config, &mut clients);

        let service = Arc::new(CachingPackageService::new(
            Arc::new(storage),
            clients,
            config.policies.clone(),
        ));

        let upstreams = UpstreamClients {
            #[cfg(feature = "pypi")]
            pypi_upstream,
            #[cfg(feature = "cargo-registry")]
            cargo_upstream,
            #[cfg(feature = "npm")]
            npm_upstream,
            #[cfg(feature = "hex")]
            hex_upstream,
            #[cfg(feature = "maven")]
            maven_upstream,
            #[cfg(feature = "rubygems")]
            rubygems_upstream,
            #[cfg(feature = "nuget")]
            nuget_upstream,
            #[cfg(feature = "pub")]
            pub_upstream,
        };
        let state = AppState::new(config.clone(), service.clone(), service, upstreams);
        let app = build_app(state);

        let listener = tokio::net::TcpListener::bind(&config.server.bind)
            .await
            .unwrap_or_else(|e| {
                eprintln!("error: failed to bind to {}: {e}", config.server.bind);
                std::process::exit(1);
            });

        tracing::info!("depot listening on {}", config.server.bind);
        axum::serve(listener, app).await.expect("server error");
    });
}

#[cfg(feature = "maven")]
fn register_maven_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<depot_adapters::maven::upstream::MavenUpstreamClient> {
    let upstream_config = config
        .upstream
        .get("maven")
        .expect("default maven upstream");
    let client = Arc::new(depot_adapters::maven::upstream::MavenUpstreamClient::new(
        upstream_config.url.clone(),
    ));
    if upstream_config.enabled {
        clients.insert(Ecosystem::Maven, client.clone());
        tracing::info!("Maven upstream enabled: {}", upstream_config.url);
    }
    client
}

#[cfg(feature = "rubygems")]
fn register_rubygems_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<depot_adapters::rubygems::upstream::RubyGemsUpstreamClient> {
    let upstream_config = config
        .upstream
        .get("rubygems")
        .expect("default rubygems upstream");
    let client = Arc::new(
        depot_adapters::rubygems::upstream::RubyGemsUpstreamClient::new(
            upstream_config
                .artifact_url
                .clone()
                .unwrap_or_else(|| upstream_config.url.clone()),
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::RubyGems, client.clone());
        tracing::info!("RubyGems upstream enabled: {}", upstream_config.url);
    }
    client
}

#[cfg(feature = "nuget")]
fn register_nuget_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<depot_adapters::nuget::upstream::NuGetUpstreamClient> {
    let upstream_config = config
        .upstream
        .get("nuget")
        .expect("default nuget upstream");
    let client = Arc::new(depot_adapters::nuget::upstream::NuGetUpstreamClient::new(
        upstream_config.url.clone(),
    ));
    if upstream_config.enabled {
        clients.insert(Ecosystem::NuGet, client.clone());
        tracing::info!("NuGet upstream enabled: {}", upstream_config.url);
    }
    client
}

#[cfg(feature = "pub")]
fn register_pub_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<depot_adapters::pubdev::upstream::PubUpstreamClient> {
    let upstream_config = config.upstream.get("pub").expect("default pub upstream");
    let client = Arc::new(depot_adapters::pubdev::upstream::PubUpstreamClient::new(
        upstream_config.url.clone(),
    ));
    if upstream_config.enabled {
        clients.insert(Ecosystem::Pub, client.clone());
        tracing::info!("pub.dev upstream enabled: {}", upstream_config.url);
    }
    client
}

fn build_storage(config: &Config) -> OpenDalStorage {
    OpenDalStorage::from_config(&config.storage).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    })
}

#[cfg(feature = "pypi")]
fn register_pypi_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<depot_adapters::pypi::upstream::PypiUpstreamClient> {
    if let Some(pypi_config) = config.upstream.get("pypi") {
        if !pypi_config.enabled {
            return Arc::new(depot_adapters::pypi::upstream::PypiUpstreamClient::new(
                pypi_config.url.clone(),
            ));
        }
        let client = Arc::new(depot_adapters::pypi::upstream::PypiUpstreamClient::new(
            pypi_config.url.clone(),
        ));
        clients.insert(Ecosystem::PyPI, client.clone());
        tracing::info!("PyPI upstream enabled: {}", pypi_config.url);
        client
    } else {
        Arc::new(depot_adapters::pypi::upstream::PypiUpstreamClient::new(
            "https://pypi.org".to_string(),
        ))
    }
}

#[cfg(feature = "npm")]
fn register_npm_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<depot_adapters::npm::upstream::NpmUpstreamClient> {
    if let Some(npm_config) = config.upstream.get("npm") {
        if !npm_config.enabled {
            return Arc::new(depot_adapters::npm::upstream::NpmUpstreamClient::new(
                npm_config.url.clone(),
            ));
        }
        let client = Arc::new(depot_adapters::npm::upstream::NpmUpstreamClient::new(
            npm_config.url.clone(),
        ));
        clients.insert(Ecosystem::Npm, client.clone());
        tracing::info!("npm upstream enabled: {}", npm_config.url);
        client
    } else {
        Arc::new(depot_adapters::npm::upstream::NpmUpstreamClient::new(
            "https://registry.npmjs.org".to_string(),
        ))
    }
}

#[cfg(feature = "cargo-registry")]
fn register_cargo_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<depot_adapters::cargo::upstream::CargoUpstreamClient> {
    if let Some(cargo_config) = config.upstream.get("cargo") {
        let artifact_url = cargo_config
            .artifact_url
            .clone()
            .unwrap_or_else(|| "https://static.crates.io/crates".to_string());
        if !cargo_config.enabled {
            return Arc::new(depot_adapters::cargo::upstream::CargoUpstreamClient::new(
                cargo_config.url.clone(),
                artifact_url,
            ));
        }
        let client = Arc::new(depot_adapters::cargo::upstream::CargoUpstreamClient::new(
            cargo_config.url.clone(),
            artifact_url,
        ));
        clients.insert(Ecosystem::Cargo, client.clone());
        tracing::info!("Cargo upstream enabled: {}", cargo_config.url);
        client
    } else {
        Arc::new(depot_adapters::cargo::upstream::CargoUpstreamClient::new(
            "https://index.crates.io".to_string(),
            "https://static.crates.io/crates".to_string(),
        ))
    }
}

#[cfg(feature = "hex")]
fn register_hex_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<depot_adapters::hex::upstream::HexUpstreamClient> {
    if let Some(hex_config) = config.upstream.get("hex") {
        let artifact_url = hex_config
            .artifact_url
            .clone()
            .unwrap_or_else(|| "https://repo.hex.pm".to_string());
        if !hex_config.enabled {
            return Arc::new(depot_adapters::hex::upstream::HexUpstreamClient::new(
                hex_config.url.clone(),
                artifact_url,
            ));
        }
        let client = Arc::new(depot_adapters::hex::upstream::HexUpstreamClient::new(
            hex_config.url.clone(),
            artifact_url,
        ));
        clients.insert(Ecosystem::Hex, client.clone());
        tracing::info!("Hex upstream enabled: {}", hex_config.url);
        client
    } else {
        Arc::new(depot_adapters::hex::upstream::HexUpstreamClient::new(
            "https://hex.pm".to_string(),
            "https://repo.hex.pm".to_string(),
        ))
    }
}
