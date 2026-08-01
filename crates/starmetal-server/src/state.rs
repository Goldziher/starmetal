use std::sync::Arc;

use starmetal_adapters::PublishAuthorization;
use starmetal_authz::{LocalAuthorizer, default_namespace};
use starmetal_core::authz::{Action, Authenticator, Coordinate, Resource};
use starmetal_core::config::Config;
use starmetal_core::content::{ContentBrowse, ContentMaintenance};
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::ports::{PackageService, PublishingService, StatisticsService};
use starmetal_core::supply_chain::{IngestQuarantine, QuarantineReview, SbomIndex};

/// Shared application state, passed to all handlers via axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub package_service: Arc<dyn PackageService>,
    pub publishing_service: Arc<dyn PublishingService>,
    pub statistics_service: Arc<dyn StatisticsService>,
    /// Access-control seam (ADR-0022). Migrated from the config's flat token sections; it both
    /// authenticates bearer tokens to principals and implements the core `Authorizer` port. Stored
    /// concretely because authentication is not part of the port and there is one local
    /// implementation today; consulted at the admin API now and the publish/read paths as later
    /// stages consume it.
    pub authorizer: Arc<LocalAuthorizer>,
    pub upstreams: UpstreamClients,
    /// Quarantine review workflow (ADR-0024), `Some` only when a scanner is attached. Backs the admin
    /// promote/reject/list endpoints; `None` leaves those endpoints reporting quarantine disabled.
    pub quarantine: Option<Arc<dyn QuarantineReview>>,
    /// Ingest-time quarantine workflow (ADR-0024), `Some` under the same condition as
    /// [`AppState::quarantine`] (a scanner is attached). The admin promote/reject handlers route
    /// ingest-origin holds here to complete or purge the deferred publish; `None` leaves them on the
    /// serve-only path.
    pub ingest_quarantine: Option<Arc<dyn IngestQuarantine>>,
    /// Scheduled metadata maintenance (ADR-0020 Stages 2c/2d), `Some` only when the content model
    /// is attached (`metadata.enabled`). Backs the admin `/gc` and `/retention` trigger endpoints;
    /// `None` leaves those endpoints reporting metadata maintenance disabled.
    pub content_maintenance: Option<Arc<dyn ContentMaintenance>>,
    /// Read-only content browse handle (ADR-0022 selector push-down), `Some` only when the content
    /// model is attached (`metadata.enabled`). Backs the `/api/v1/components` listing endpoint,
    /// which pushes an authorizer predicate into the store; `None` makes that endpoint report
    /// content browse disabled.
    pub content_browse: Option<Arc<dyn ContentBrowse>>,
    /// SBOM retrieval handle (ADR-0024), `Some` when `supply_chain.sbom.enabled`. Backs the admin
    /// SBOM list/fetch endpoints; `None` makes them report SBOM generation disabled.
    pub sbom: Option<Arc<dyn SbomIndex>>,
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
        statistics_service: Arc<dyn StatisticsService>,
        upstreams: UpstreamClients,
    ) -> Self {
        // Migrate the flat token config into the grant model once, at assembly time.
        let authorizer = Arc::new(LocalAuthorizer::from_config(&config));
        Self {
            config: Arc::new(config),
            package_service,
            publishing_service,
            statistics_service,
            authorizer,
            upstreams,
            quarantine: None,
            ingest_quarantine: None,
            content_maintenance: None,
            content_browse: None,
            sbom: None,
        }
    }

    /// Attach the quarantine review handle (ADR-0024) built by the runtime. Absent by default so the
    /// admin promote/reject/list endpoints report quarantine disabled unless a scanner is attached.
    pub fn with_quarantine(mut self, quarantine: Option<Arc<dyn QuarantineReview>>) -> Self {
        self.quarantine = quarantine;
        self
    }

    /// Attach the ingest-time quarantine handle (ADR-0024) built by the runtime. Absent by default
    /// so the admin promote/reject handlers stay on the serve-only path unless a scanner is attached.
    pub fn with_ingest_quarantine(mut self, ingest_quarantine: Option<Arc<dyn IngestQuarantine>>) -> Self {
        self.ingest_quarantine = ingest_quarantine;
        self
    }

    /// Attach the metadata-maintenance handle (ADR-0020 Stages 2c/2d) built by the runtime. Absent
    /// by default so the admin `/gc` and `/retention` endpoints report maintenance disabled unless
    /// the content model is attached.
    pub fn with_content_maintenance(mut self, content_maintenance: Option<Arc<dyn ContentMaintenance>>) -> Self {
        self.content_maintenance = content_maintenance;
        self
    }

    /// Attach the read-only content browse handle (ADR-0022) built by the runtime. Absent by default
    /// so the `/api/v1/components` endpoint reports content browse disabled unless the content model
    /// is attached.
    pub fn with_content_browse(mut self, content_browse: Option<Arc<dyn ContentBrowse>>) -> Self {
        self.content_browse = content_browse;
        self
    }

    /// Attach the SBOM retrieval handle (ADR-0024) built by the runtime. Absent by default so the
    /// admin SBOM endpoints report SBOM generation disabled unless it is enabled in config.
    pub fn with_sbom(mut self, sbom: Option<Arc<dyn SbomIndex>>) -> Self {
        self.sbom = sbom;
        self
    }
}

/// Resolve a publish authorization check (`Action::Add`) through the ADR-0022
/// Authenticator/Authorizer seam, shared by every `Has*State::authorize_publish` impl below.
///
/// A missing credential is `Unauthenticated`. A present-but-unrecognized token is `Forbidden` —
/// not `Unauthenticated` — matching the pre-ADR-0022 behavior where an unknown/insufficient
/// publish token returned 403.
///
/// Unused (and `#[allow(dead_code)]`) when no adapter feature is enabled, since every call site
/// lives in a `#[cfg(feature = "...")]`-gated `Has*State` impl below.
#[allow(dead_code)]
fn resolve_publish_authorization(
    authorizer: &LocalAuthorizer,
    credential: Option<&str>,
    ecosystem: Ecosystem,
    name: &PackageName,
) -> PublishAuthorization {
    let Some(token) = credential else {
        return PublishAuthorization::Unauthenticated;
    };
    let Some(principal) = authorizer.authenticate_bearer(token) else {
        return PublishAuthorization::Forbidden;
    };
    let resource = Resource {
        namespace: default_namespace(),
        ecosystem: Some(ecosystem),
        repository: Some(name.clone()),
        coordinate: Some(Coordinate {
            ecosystem,
            name: name.clone(),
            version: None,
        }),
    };
    if authorizer
        .authorize_sync(&principal, Action::Add, &resource)
        .is_allowed()
    {
        PublishAuthorization::Allowed
    } else {
        PublishAuthorization::Forbidden
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

    fn authorize_publish(
        &self,
        credential: Option<&str>,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> PublishAuthorization {
        resolve_publish_authorization(&self.authorizer, credential, ecosystem, name)
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

    fn authorize_publish(
        &self,
        credential: Option<&str>,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> PublishAuthorization {
        resolve_publish_authorization(&self.authorizer, credential, ecosystem, name)
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

    fn authorize_publish(
        &self,
        credential: Option<&str>,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> PublishAuthorization {
        resolve_publish_authorization(&self.authorizer, credential, ecosystem, name)
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

    fn authorize_publish(
        &self,
        credential: Option<&str>,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> PublishAuthorization {
        resolve_publish_authorization(&self.authorizer, credential, ecosystem, name)
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

    fn authorize_publish(
        &self,
        credential: Option<&str>,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> PublishAuthorization {
        resolve_publish_authorization(&self.authorizer, credential, ecosystem, name)
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

    fn rubygems_upstream(&self) -> &Arc<starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient> {
        &self.upstreams.rubygems_upstream
    }

    fn authorize_publish(
        &self,
        credential: Option<&str>,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> PublishAuthorization {
        resolve_publish_authorization(&self.authorizer, credential, ecosystem, name)
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

    fn authorize_publish(
        &self,
        credential: Option<&str>,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> PublishAuthorization {
        resolve_publish_authorization(&self.authorizer, credential, ecosystem, name)
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

    fn authorize_publish(
        &self,
        credential: Option<&str>,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> PublishAuthorization {
        resolve_publish_authorization(&self.authorizer, credential, ecosystem, name)
    }
}

#[cfg(test)]
mod tests {
    use starmetal_core::config::{Config, PublishingConfig};
    use starmetal_core::publishing::{PublishTokenConfig, TokenScope};

    use super::*;

    /// A `LocalAuthorizer` built from a publish token scoped to exactly one ecosystem + package.
    fn authorizer_with_scoped_publish_token() -> LocalAuthorizer {
        let config = Config {
            publishing: PublishingConfig {
                enabled: true,
                tokens: vec![PublishTokenConfig {
                    token: "scoped-secret".to_string(),
                    scopes: vec![TokenScope::Publish],
                    ecosystems: vec![Ecosystem::Npm],
                    packages: vec!["left-pad".to_string()],
                }],
                ..PublishingConfig::default()
            },
            ..Config::default()
        };
        LocalAuthorizer::from_config(&config)
    }

    #[test]
    fn resolve_publish_authorization_allows_in_scope_credential() {
        let authorizer = authorizer_with_scoped_publish_token();
        let decision = resolve_publish_authorization(
            &authorizer,
            Some("scoped-secret"),
            Ecosystem::Npm,
            &PackageName::new("left-pad"),
        );
        assert_eq!(decision, PublishAuthorization::Allowed);
    }

    #[test]
    fn resolve_publish_authorization_denies_wrong_package() {
        let authorizer = authorizer_with_scoped_publish_token();
        let decision = resolve_publish_authorization(
            &authorizer,
            Some("scoped-secret"),
            Ecosystem::Npm,
            &PackageName::new("other-package"),
        );
        assert_eq!(decision, PublishAuthorization::Forbidden);
    }

    #[test]
    fn resolve_publish_authorization_denies_wrong_ecosystem() {
        let authorizer = authorizer_with_scoped_publish_token();
        let decision = resolve_publish_authorization(
            &authorizer,
            Some("scoped-secret"),
            Ecosystem::PyPI,
            &PackageName::new("left-pad"),
        );
        assert_eq!(decision, PublishAuthorization::Forbidden);
    }

    #[test]
    fn resolve_publish_authorization_denies_unknown_token() {
        let authorizer = authorizer_with_scoped_publish_token();
        let decision = resolve_publish_authorization(
            &authorizer,
            Some("not-configured"),
            Ecosystem::Npm,
            &PackageName::new("left-pad"),
        );
        assert_eq!(decision, PublishAuthorization::Forbidden);
    }

    #[test]
    fn resolve_publish_authorization_is_unauthenticated_without_credential() {
        let authorizer = authorizer_with_scoped_publish_token();
        let decision = resolve_publish_authorization(&authorizer, None, Ecosystem::Npm, &PackageName::new("left-pad"));
        assert_eq!(decision, PublishAuthorization::Unauthenticated);
    }
}
