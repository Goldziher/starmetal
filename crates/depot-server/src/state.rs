use std::sync::Arc;

use depot_core::config::Config;
use depot_core::ports::PackageService;

/// Shared application state, passed to all handlers via axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub package_service: Arc<dyn PackageService>,
    pub upstreams: UpstreamClients,
}

/// Feature-gated upstream clients used by protocol adapters.
#[derive(Clone)]
pub struct UpstreamClients {
    #[cfg(feature = "pypi")]
    pub pypi_upstream: Arc<depot_adapters::pypi::upstream::PypiUpstreamClient>,
    #[cfg(feature = "cargo-registry")]
    pub cargo_upstream: Arc<depot_adapters::cargo::upstream::CargoUpstreamClient>,
    #[cfg(feature = "npm")]
    pub npm_upstream: Arc<depot_adapters::npm::upstream::NpmUpstreamClient>,
    #[cfg(feature = "hex")]
    pub hex_upstream: Arc<depot_adapters::hex::upstream::HexUpstreamClient>,
    #[cfg(feature = "maven")]
    pub maven_upstream: Arc<depot_adapters::maven::upstream::MavenUpstreamClient>,
    #[cfg(feature = "rubygems")]
    pub rubygems_upstream: Arc<depot_adapters::rubygems::upstream::RubyGemsUpstreamClient>,
    #[cfg(feature = "nuget")]
    pub nuget_upstream: Arc<depot_adapters::nuget::upstream::NuGetUpstreamClient>,
    #[cfg(feature = "pub")]
    pub pub_upstream: Arc<depot_adapters::pubdev::upstream::PubUpstreamClient>,
}

impl AppState {
    pub fn new(
        config: Config,
        package_service: Arc<dyn PackageService>,
        upstreams: UpstreamClients,
    ) -> Self {
        Self {
            config: Arc::new(config),
            package_service,
            upstreams,
        }
    }
}

#[cfg(feature = "pypi")]
impl depot_adapters::pypi::HasPypiState for AppState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn pypi_upstream(&self) -> &Arc<depot_adapters::pypi::upstream::PypiUpstreamClient> {
        &self.upstreams.pypi_upstream
    }
}

#[cfg(feature = "npm")]
impl depot_adapters::npm::HasNpmState for AppState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn npm_upstream(&self) -> &Arc<depot_adapters::npm::upstream::NpmUpstreamClient> {
        &self.upstreams.npm_upstream
    }
}

#[cfg(feature = "cargo-registry")]
impl depot_adapters::cargo::HasCargoState for AppState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn cargo_upstream(&self) -> &Arc<depot_adapters::cargo::upstream::CargoUpstreamClient> {
        &self.upstreams.cargo_upstream
    }
}

#[cfg(feature = "hex")]
impl depot_adapters::hex::HasHexState for AppState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn hex_upstream(&self) -> &Arc<depot_adapters::hex::upstream::HexUpstreamClient> {
        &self.upstreams.hex_upstream
    }
}

#[cfg(feature = "maven")]
impl depot_adapters::maven::HasMavenState for AppState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn maven_upstream(&self) -> &Arc<depot_adapters::maven::upstream::MavenUpstreamClient> {
        &self.upstreams.maven_upstream
    }
}

#[cfg(feature = "rubygems")]
impl depot_adapters::rubygems::HasRubyGemsState for AppState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn rubygems_upstream(
        &self,
    ) -> &Arc<depot_adapters::rubygems::upstream::RubyGemsUpstreamClient> {
        &self.upstreams.rubygems_upstream
    }
}

#[cfg(feature = "nuget")]
impl depot_adapters::nuget::HasNuGetState for AppState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn nuget_upstream(&self) -> &Arc<depot_adapters::nuget::upstream::NuGetUpstreamClient> {
        &self.upstreams.nuget_upstream
    }
}

#[cfg(feature = "pub")]
impl depot_adapters::pubdev::HasPubState for AppState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn pub_upstream(&self) -> &Arc<depot_adapters::pubdev::upstream::PubUpstreamClient> {
        &self.upstreams.pub_upstream
    }
}
