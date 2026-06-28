use std::sync::Arc;

use starmetal_core::config::Config;
use starmetal_core::ports::{PackageService, PublishingService};

/// Shared application state, passed to all handlers via axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub package_service: Arc<dyn PackageService>,
    pub publishing_service: Arc<dyn PublishingService>,
    pub upstreams: UpstreamClients,
}

/// Feature-gated upstream clients used by protocol adapters.
#[derive(Clone)]
pub struct UpstreamClients {
    #[cfg(feature = "pypi")]
    pub pypi_upstream: Arc<starmetal_adapters::pypi::upstream::PypiUpstreamClient>,
    #[cfg(feature = "cargo-registry")]
    pub cargo_upstream: Arc<starmetal_adapters::cargo::upstream::CargoUpstreamClient>,
    #[cfg(feature = "npm")]
    pub npm_upstream: Arc<starmetal_adapters::npm::upstream::NpmUpstreamClient>,
    #[cfg(feature = "hex")]
    pub hex_upstream: Arc<starmetal_adapters::hex::upstream::HexUpstreamClient>,
    #[cfg(feature = "maven")]
    pub maven_upstream: Arc<starmetal_adapters::maven::upstream::MavenUpstreamClient>,
    #[cfg(feature = "rubygems")]
    pub rubygems_upstream: Arc<starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient>,
    #[cfg(feature = "nuget")]
    pub nuget_upstream: Arc<starmetal_adapters::nuget::upstream::NuGetUpstreamClient>,
    #[cfg(feature = "pub")]
    pub pub_upstream: Arc<starmetal_adapters::pubdev::upstream::PubUpstreamClient>,
}

impl AppState {
    pub fn new(
        config: Config,
        package_service: Arc<dyn PackageService>,
        publishing_service: Arc<dyn PublishingService>,
        upstreams: UpstreamClients,
    ) -> Self {
        Self {
            config: Arc::new(config),
            package_service,
            publishing_service,
            upstreams,
        }
    }
}

#[cfg(feature = "pypi")]
impl starmetal_adapters::pypi::HasPypiState for AppState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn pypi_upstream(&self) -> &Arc<starmetal_adapters::pypi::upstream::PypiUpstreamClient> {
        &self.upstreams.pypi_upstream
    }
}

#[cfg(feature = "npm")]
impl starmetal_adapters::npm::HasNpmState for AppState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn npm_upstream(&self) -> &Arc<starmetal_adapters::npm::upstream::NpmUpstreamClient> {
        &self.upstreams.npm_upstream
    }
}

#[cfg(feature = "cargo-registry")]
impl starmetal_adapters::cargo::HasCargoState for AppState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn cargo_upstream(&self) -> &Arc<starmetal_adapters::cargo::upstream::CargoUpstreamClient> {
        &self.upstreams.cargo_upstream
    }
}

#[cfg(feature = "hex")]
impl starmetal_adapters::hex::HasHexState for AppState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn hex_upstream(&self) -> &Arc<starmetal_adapters::hex::upstream::HexUpstreamClient> {
        &self.upstreams.hex_upstream
    }
}

#[cfg(feature = "maven")]
impl starmetal_adapters::maven::HasMavenState for AppState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn maven_upstream(&self) -> &Arc<starmetal_adapters::maven::upstream::MavenUpstreamClient> {
        &self.upstreams.maven_upstream
    }
}

#[cfg(feature = "rubygems")]
impl starmetal_adapters::rubygems::HasRubyGemsState for AppState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn rubygems_upstream(
        &self,
    ) -> &Arc<starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient> {
        &self.upstreams.rubygems_upstream
    }
}

#[cfg(feature = "nuget")]
impl starmetal_adapters::nuget::HasNuGetState for AppState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn nuget_upstream(&self) -> &Arc<starmetal_adapters::nuget::upstream::NuGetUpstreamClient> {
        &self.upstreams.nuget_upstream
    }
}

#[cfg(feature = "pub")]
impl starmetal_adapters::pubdev::HasPubState for AppState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn pub_upstream(&self) -> &Arc<starmetal_adapters::pubdev::upstream::PubUpstreamClient> {
        &self.upstreams.pub_upstream
    }
}
