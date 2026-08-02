use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahash::AHashMap;
use bytes::Bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use starmetal_core::authz::{Authenticator, CompositeAuthenticator};
use starmetal_core::config::{Config, DEFAULT_MAX_UPSTREAM_BYTES, UpstreamConfig};
use starmetal_core::content::{ContentBrowse, ContentMaintenance};
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::package::{ArtifactId, Ecosystem, PackageName, VersionMetadata};
use starmetal_core::ports::{PackageService, PublishingService, StatisticsService, StoragePort, UpstreamClient};
use starmetal_core::publishing::{ProtocolMetadata, PublishRequest, PublishedArtifact, YankRequest};
use starmetal_core::repository::{HostedFacet, ProxyFacet, RecipeRegistry, RepositoryKind};
use starmetal_core::supply_chain::{IngestQuarantine, QuarantineReview, SbomIndex, SupplyChainMaintenance};
use starmetal_server::state::{AppState, GroupMount, UpstreamClients};
use starmetal_service::{CachingPackageService, GroupPackageService, ProxyRecipe, SigningService};
use starmetal_storage::OpenDalStorage;

#[derive(Debug, Clone, Default)]
pub struct ConfigLoadOptions {
    pub path: Option<PathBuf>,
    pub no_config: bool,
    pub overrides: ConfigOverrides,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigOverrides {
    pub bind: Option<String>,
    pub storage_backend: Option<String>,
    pub storage_options: Vec<(String, String)>,
    pub upstreams: Vec<UpstreamOverride>,
}

#[derive(Debug, Clone)]
pub struct UpstreamOverride {
    pub name: String,
    pub enabled: Option<bool>,
    pub url: Option<String>,
    pub artifact_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegistryStatus {
    pub ecosystem: Ecosystem,
    pub configured: bool,
    pub enabled: bool,
    pub compiled: bool,
    pub url: Option<String>,
    pub artifact_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeStatus {
    pub bind: String,
    pub storage_backend: String,
    pub registries: Vec<RegistryStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactFetchResult {
    pub artifact: ArtifactId,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CacheDeleteResult {
    pub deleted_keys: Vec<String>,
}

#[derive(Clone)]
pub struct StarmetalRuntime {
    pub config: Config,
    pub storage: Arc<dyn StoragePort>,
    pub package_service: Arc<dyn PackageService>,
    pub publishing_service: Arc<dyn PublishingService>,
    pub statistics_service: Arc<dyn StatisticsService>,
    /// Facet recipes keyed by `(ecosystem, kind)` (ADR-0019). Built at assembly with one proxy
    /// recipe per resolved proxy repository, exposing the shared caching service as its proxy and
    /// hosted facets. Consulted by `build_app` to drive per-repository mounting.
    pub recipe_registry: Arc<RecipeRegistry>,
    /// Per-repository backing services for declared `group` repositories (ADR-0019), keyed by
    /// repository name. Empty when no group is declared; consumed by `app_state` so `build_app`
    /// mounts each group's ecosystem adapter with its merged group service.
    pub group_mounts: Arc<HashMap<String, GroupMount>>,
    pub upstreams: UpstreamClients,
    /// Handle for scheduled supply-chain re-correlation (ADR-0024). `Some` only when a scanner is
    /// attached (`supply_chain.enabled` under the scanner feature); drives the background sweep.
    pub maintenance: Option<Arc<dyn SupplyChainMaintenance>>,
    /// Handle for the quarantine review workflow (ADR-0024). `Some` exactly when
    /// `supply_chain.enabled` is set — the same condition under which `attach_scanner` attaches a
    /// scanner to the service — so this is `Some` iff a scanner is actually attached. Backs the admin
    /// promote/reject/list endpoints.
    pub quarantine: Option<Arc<dyn QuarantineReview>>,
    /// Handle for the ingest-time quarantine workflow (ADR-0024). `Some` under the same condition as
    /// [`quarantine`] (a scanner is attached); backs the admin promote/reject handlers when a held
    /// digest is ingest-origin, completing or purging the deferred publish.
    pub ingest_quarantine: Option<Arc<dyn IngestQuarantine>>,
    /// Handle for scheduled metadata maintenance (ADR-0020 Stages 2c/2d): the retention and
    /// garbage-collection sweeps. `Some` only when the content model is attached (`metadata.enabled`
    /// under the `metadata` feature); drives the background sweeps and backs the admin
    /// `/gc` and `/retention` endpoints.
    pub content_maintenance: Option<Arc<dyn ContentMaintenance>>,
    /// Read-only content browse handle (ADR-0022 selector push-down). `Some` under the same
    /// condition as [`content_maintenance`] (the content model is attached); backs the
    /// `/api/v1/components` listing endpoint, which pushes an authorizer predicate into the store.
    pub content_browse: Option<Arc<dyn ContentBrowse>>,
    /// SBOM retrieval handle (ADR-0024). `Some` when `supply_chain.sbom.enabled`; backs the admin
    /// SBOM list/fetch endpoints. Independent of the scanner.
    pub sbom: Option<Arc<dyn SbomIndex>>,
    /// Extra identity backend composed ahead of the flat-token authenticator (ADR-0022). `Some` only
    /// when `[oidc]` is enabled and the crate is built with the `oidc` feature; `app_state` fronts the
    /// flat-token authenticator with it via `CompositeAuthenticator`, leaving authorization unchanged.
    pub oidc_authenticator: Option<Arc<dyn Authenticator>>,
}

/// Attach a Postgres-backed content store (ADR-0020) to the service when `metadata.enabled`, so
/// publishes dual-write the content model against the same object store used for flat artifacts.
/// A disabled or absent config leaves the service untouched (the `None` content-store path) and
/// yields no maintenance handle.
///
/// Returns the (possibly wrapped) service alongside a maintenance handle over the *same* store, so
/// the scheduled GC (Stage 2d) and retention (Stage 2c) sweeps operate on the store publishes
/// actually write to.
#[cfg(feature = "metadata")]
async fn attach_content_store(
    service: CachingPackageService,
    config: &Config,
    storage: Arc<dyn StoragePort>,
) -> Result<(
    CachingPackageService,
    Option<Arc<dyn ContentMaintenance>>,
    Option<Arc<dyn ContentBrowse>>,
)> {
    use starmetal_core::content::ContentStore;
    use starmetal_metadata::{MetadataMaintenance, PostgresContentStore, create_pool};

    if !config.metadata.enabled {
        return Ok((service, None, None));
    }
    let database_url = config.metadata.database_url.as_deref().ok_or_else(|| {
        StarmetalError::Config("metadata.enabled requires metadata.database_url to be set".to_string())
    })?;
    let pool = create_pool(database_url).await?;
    let content_store = Arc::new(PostgresContentStore::new(pool, storage));
    if config.metadata.apply_schema {
        content_store.apply_schema().await?;
    }
    let maintenance = Arc::new(MetadataMaintenance::new(
        content_store.clone(),
        std::time::Duration::from_secs(config.metadata.gc_grace_secs),
        config.metadata.retention.clone(),
        config.metadata.retention_per_ecosystem.clone(),
        config.metadata.retention_per_repository.clone(),
    )) as Arc<dyn ContentMaintenance>;
    let browse = content_store.clone() as Arc<dyn ContentBrowse>;
    let service = service.with_content_store(content_store as Arc<dyn ContentStore>);
    Ok((service, Some(maintenance), Some(browse)))
}

/// Attach a vulnerability scanner (ADR-0024) to the service when `supply_chain.enabled`, so publishes
/// are gated at ingest. A disabled config leaves the service untouched (the `None` scanner path).
#[cfg(feature = "scanner-osv")]
fn attach_scanner(service: CachingPackageService, config: &Config) -> CachingPackageService {
    use starmetal_adapters::scanner::OsvScanner;
    use starmetal_core::config::ScannerKind;

    if !config.supply_chain.enabled {
        return service;
    }
    let scanner = match config.supply_chain.scanner {
        ScannerKind::Osv => match &config.supply_chain.osv_endpoint {
            Some(endpoint) => OsvScanner::with_endpoint(endpoint.clone()),
            None => OsvScanner::new(),
        },
    };
    service
        .with_scanner(Arc::new(scanner))
        .enforce_scan_on_serve(config.supply_chain.enforce_on_serve)
        .with_quarantine(config.supply_chain.quarantine)
        .with_ingest_quarantine(config.supply_chain.ingest_quarantine)
}

/// Build the static-JWKS OIDC authenticator (ADR-0022) when `[oidc]` is enabled.
///
/// The validator crate carries the JWT/JWKS crypto, so it is compiled only under the `oidc` feature;
/// an enabled `[oidc]` section without that feature is a startup misconfiguration, surfaced as a
/// config error rather than silently ignored. Returns `Ok(None)` when OIDC is disabled.
#[cfg(feature = "oidc")]
fn build_oidc_authenticator(config: &Config) -> Result<Option<Arc<dyn Authenticator>>> {
    if !config.oidc.enabled {
        return Ok(None);
    }
    let authenticator = starmetal_oidc::OidcAuthenticator::into_authenticator(&config.oidc)
        .map_err(|error| StarmetalError::Config(error.to_string()))?;
    Ok(Some(authenticator))
}

#[cfg(not(feature = "oidc"))]
fn build_oidc_authenticator(config: &Config) -> Result<Option<Arc<dyn Authenticator>>> {
    if config.oidc.enabled {
        return Err(StarmetalError::Config(
            "oidc.enabled requires building with the `oidc` feature".to_string(),
        ));
    }
    Ok(None)
}

impl StarmetalRuntime {
    pub async fn new(options: ConfigLoadOptions) -> Result<Self> {
        let config = load_config(options)?;
        config.validate_mvp()?;
        Self::from_config(config).await
    }

    pub async fn from_config(config: Config) -> Result<Self> {
        let oidc_authenticator = build_oidc_authenticator(&config)?;
        let storage = Arc::new(OpenDalStorage::from_config(&config.storage)?);
        #[allow(unused_mut)]
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

        let signing = SigningService::from_config(&config.signing)?;
        let service =
            CachingPackageService::new_with_signing(storage.clone(), clients, config.policies.clone(), signing);
        #[cfg(feature = "metadata")]
        let (service, content_maintenance, content_browse) =
            attach_content_store(service, &config, storage.clone()).await?;
        #[cfg(not(feature = "metadata"))]
        let content_maintenance: Option<Arc<dyn ContentMaintenance>> = None;
        #[cfg(not(feature = "metadata"))]
        let content_browse: Option<Arc<dyn ContentBrowse>> = None;
        #[cfg(feature = "scanner-osv")]
        let service = attach_scanner(service, &config);
        // SBOM generation is independent of the scanner (pure generation from the publish request),
        // so it attaches unconditionally when enabled — no scanner feature required.
        let service = if config.supply_chain.sbom.enabled {
            service.with_sbom_formats(config.supply_chain.sbom.formats.clone())
        } else {
            service
        };
        // Publish quota gate (ADR-0021): a process-local in-memory ledger enforcing a per-ecosystem/
        // namespace ceiling on published version count and bytes. Independent of the scanner and of
        // signing — no build feature is required.
        let service = if config.supply_chain.quota.enabled {
            service.with_quota(config.supply_chain.quota.clone())
        } else {
            service
        };
        // Signature/provenance gate (ADR-0024): enable the built-in own-graph verification and (for
        // provenance) attestation emission on publish/cache-fill. Requiring either without
        // `[signing]` configured is a startup misconfiguration.
        let service = if config.supply_chain.require_signature || config.supply_chain.require_provenance {
            if !config.signing.enabled {
                return Err(StarmetalError::Config(
                    "supply_chain.require_signature/require_provenance require [signing] to be enabled".to_string(),
                ));
            }
            service
                .require_signature(config.supply_chain.require_signature)
                .require_provenance(config.supply_chain.require_provenance)
                .emit_provenance(config.supply_chain.require_provenance)
        } else {
            service
        };
        let service = Arc::new(service);

        // Facet recipe registry (ADR-0019): register one proxy recipe per resolved proxy repository,
        // exposing the shared caching service as both its proxy and hosted facet. Only proxy kinds
        // are wired end-to-end (validate_mvp rejects others), so only proxy recipes are registered.
        let mut recipe_registry = RecipeRegistry::new();
        for repository in config.resolved_repositories() {
            if repository.kind == RepositoryKind::Proxy {
                recipe_registry.register(Arc::new(ProxyRecipe::new(
                    repository.ecosystem,
                    service.clone() as Arc<dyn ProxyFacet>,
                    service.clone() as Arc<dyn HostedFacet>,
                )));
            }
        }
        let recipe_registry = Arc::new(recipe_registry);

        // Group backing services (ADR-0019): build one read-only GroupPackageService per declared
        // group, keyed by repository name for `build_app`'s per-repository mount. Every proxy of one
        // ecosystem shares the single caching service today, so a group's same-ecosystem members all
        // resolve to that shared service — the group is a read-only virtual view over its members.
        let mut group_mounts: HashMap<String, GroupMount> = HashMap::new();
        for repository in config.resolved_repositories() {
            if repository.kind != RepositoryKind::Group {
                continue;
            }
            let members: Vec<Arc<dyn PackageService>> = repository
                .members
                .iter()
                .map(|_member| service.clone() as Arc<dyn PackageService>)
                .collect();
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
        let group_mounts = Arc::new(group_mounts);

        // Expose the supply-chain handles (re-correlation + quarantine review) only when a scanner is
        // actually attached, so a build without the scanner feature (or with supply-chain disabled)
        // carries neither.
        #[cfg(feature = "scanner-osv")]
        let maintenance: Option<Arc<dyn SupplyChainMaintenance>> = config
            .supply_chain
            .enabled
            .then(|| service.clone() as Arc<dyn SupplyChainMaintenance>);
        #[cfg(feature = "scanner-osv")]
        let quarantine: Option<Arc<dyn QuarantineReview>> = config
            .supply_chain
            .enabled
            .then(|| service.clone() as Arc<dyn QuarantineReview>);
        #[cfg(feature = "scanner-osv")]
        let ingest_quarantine: Option<Arc<dyn IngestQuarantine>> = config
            .supply_chain
            .enabled
            .then(|| service.clone() as Arc<dyn IngestQuarantine>);
        #[cfg(not(feature = "scanner-osv"))]
        let maintenance: Option<Arc<dyn SupplyChainMaintenance>> = None;
        #[cfg(not(feature = "scanner-osv"))]
        let quarantine: Option<Arc<dyn QuarantineReview>> = None;
        #[cfg(not(feature = "scanner-osv"))]
        let ingest_quarantine: Option<Arc<dyn IngestQuarantine>> = None;

        // SBOM retrieval is exposed whenever SBOM generation is enabled — independent of the scanner.
        let sbom: Option<Arc<dyn SbomIndex>> = config
            .supply_chain
            .sbom
            .enabled
            .then(|| service.clone() as Arc<dyn SbomIndex>);

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

        Ok(Self {
            config,
            storage,
            package_service: service.clone(),
            publishing_service: service.clone(),
            statistics_service: service,
            recipe_registry,
            group_mounts,
            upstreams,
            maintenance,
            quarantine,
            ingest_quarantine,
            content_maintenance,
            content_browse,
            sbom,
            oidc_authenticator,
        })
    }

    /// Spawn the scheduled supply-chain re-correlation sweep (ADR-0024) when configured.
    ///
    /// Returns `None` (spawning nothing) unless a scanner is attached and
    /// `supply_chain.recorrelation_interval_secs` is non-zero. The returned task re-scans every
    /// stored scan report on each interval and logs the sweep outcome; it runs until the process
    /// exits (or the caller aborts the handle). The first sweep runs one interval after start, not
    /// immediately, so startup stays cheap.
    pub fn spawn_recorrelation_scheduler(&self) -> Option<tokio::task::JoinHandle<()>> {
        let interval_secs = self.config.supply_chain.recorrelation_interval_secs;
        if interval_secs == 0 {
            return None;
        }
        let maintenance = self.maintenance.clone()?;
        let period = std::time::Duration::from_secs(interval_secs);
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires immediately; consume it so the first real sweep waits one period.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match maintenance.recorrelate().await {
                    Ok(report) => tracing::info!(
                        scanned = report.scanned,
                        updated = report.updated,
                        failed = report.failed,
                        newly_blocking = report.newly_blocking.len(),
                        "supply-chain re-correlation sweep complete"
                    ),
                    Err(error) => tracing::warn!(%error, "supply-chain re-correlation sweep failed"),
                }
            }
        }))
    }

    /// Spawn the scheduled garbage-collection sweep (ADR-0020 Stage 2d) when configured.
    ///
    /// Returns `None` unless the content model is attached (`metadata.enabled` under the
    /// `metadata` feature) and `metadata.gc_interval_secs` is non-zero. Mirrors
    /// [`Self::spawn_recorrelation_scheduler`]: the first sweep runs one interval after start.
    pub fn spawn_gc_scheduler(&self) -> Option<tokio::task::JoinHandle<()>> {
        let interval_secs = self.config.metadata.gc_interval_secs;
        if interval_secs == 0 {
            return None;
        }
        let maintenance = self.content_maintenance.clone()?;
        let period = std::time::Duration::from_secs(interval_secs);
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires immediately; consume it so the first real sweep waits one period.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match maintenance.gc_sweep().await {
                    Ok(report) => tracing::info!(
                        marked = report.marked,
                        soft_deleted = report.soft_deleted,
                        reclaimed = report.reclaimed.len(),
                        "garbage-collection sweep complete"
                    ),
                    Err(error) => tracing::warn!(%error, "garbage-collection sweep failed"),
                }
            }
        }))
    }

    /// Spawn the scheduled retention sweep (ADR-0020 Stage 2c) when configured.
    ///
    /// Returns `None` unless the content model is attached (`metadata.enabled` under the
    /// `metadata` feature) and `metadata.retention_interval_secs` is non-zero. Mirrors
    /// [`Self::spawn_recorrelation_scheduler`]: the first sweep runs one interval after start.
    pub fn spawn_retention_scheduler(&self) -> Option<tokio::task::JoinHandle<()>> {
        let interval_secs = self.config.metadata.retention_interval_secs;
        if interval_secs == 0 {
            return None;
        }
        let maintenance = self.content_maintenance.clone()?;
        let period = std::time::Duration::from_secs(interval_secs);
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires immediately; consume it so the first real sweep waits one period.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match maintenance.retention_sweep().await {
                    Ok(report) => tracing::info!(deleted = report.deleted.len(), "retention sweep complete"),
                    Err(error) => tracing::warn!(%error, "retention sweep failed"),
                }
            }
        }))
    }

    pub fn app_state(&self) -> AppState {
        let state = AppState::new(
            self.config.clone(),
            self.package_service.clone(),
            self.publishing_service.clone(),
            self.statistics_service.clone(),
            self.upstreams.clone(),
        )
        .with_recipe_registry(self.recipe_registry.clone())
        .with_group_mounts(self.group_mounts.clone())
        .with_quarantine(self.quarantine.clone())
        .with_ingest_quarantine(self.ingest_quarantine.clone())
        .with_content_maintenance(self.content_maintenance.clone())
        .with_content_browse(self.content_browse.clone())
        .with_sbom(self.sbom.clone());

        // Compose the OIDC backend ahead of the flat-token authenticator (ADR-0022) when configured.
        // Ordering is precedence: a JWT authenticates via OIDC, an unchanged flat token falls through
        // to the local authorizer. Authorization (grant evaluation) stays on the concrete authorizer.
        match &self.oidc_authenticator {
            Some(oidc) => {
                let flat_tokens: Arc<dyn Authenticator> = state.authorizer.clone();
                let composite = Arc::new(CompositeAuthenticator::new(vec![oidc.clone(), flat_tokens]));
                state.with_authenticator(composite)
            }
            None => state,
        }
    }

    pub fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            bind: self.config.server.bind.clone(),
            storage_backend: self.config.storage.backend.clone(),
            registries: registry_statuses(&self.config),
        }
    }

    pub async fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<PackageRef>> {
        let mut packages = self.package_service.list_packages(ecosystem).await?;
        packages.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(packages
            .into_iter()
            .map(|name| PackageRef {
                ecosystem,
                name: name.as_str().to_string(),
            })
            .collect())
    }

    pub async fn versions(
        &self,
        ecosystem: Ecosystem,
        name: &str,
    ) -> Result<Vec<starmetal_core::package::VersionInfo>> {
        let name = normalize_name(ecosystem, name);
        self.package_service.list_versions(ecosystem, &name).await
    }

    pub async fn metadata(&self, ecosystem: Ecosystem, name: &str, version: &str) -> Result<VersionMetadata> {
        let name = normalize_name(ecosystem, name);
        self.package_service
            .get_version_metadata(ecosystem, &name, version)
            .await
    }

    pub async fn fetch_artifact(&self, artifact: ArtifactId) -> Result<(ArtifactId, Bytes)> {
        let data = self.package_service.get_artifact(&artifact).await?;
        Ok((artifact, data))
    }

    pub async fn set_yanked(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        yanked: bool,
    ) -> Result<VersionMetadata> {
        self.publishing_service
            .set_yanked(YankRequest {
                ecosystem,
                name: normalize_name(ecosystem, name),
                version: version.to_string(),
                yanked,
            })
            .await
    }

    pub async fn publish_artifact(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        filename: String,
        data: Bytes,
        license: Option<String>,
    ) -> Result<starmetal_core::publishing::PublishResult> {
        if !self.config.publishing.enabled {
            return Err(StarmetalError::Config(
                "publishing is disabled in the effective config".to_string(),
            ));
        }
        self.publishing_service
            .publish_package(PublishRequest {
                ecosystem,
                name: normalize_name(ecosystem, name),
                version: version.to_string(),
                license,
                yanked: false,
                listed: true,
                artifacts: vec![PublishedArtifact {
                    filename,
                    data,
                    upstream_hashes: Default::default(),
                }],
                protocol_metadata: ProtocolMetadata::default_for(ecosystem),
                allow_overwrite: self.config.publishing.allow_overwrite,
                allow_shadowing: self.config.publishing.allow_shadowing,
                repository: None,
            })
            .await
    }

    /// Compose the dependency-update engine over this runtime's package service.
    ///
    /// The engine's datasource is the runtime `PackageService`, so update lookups
    /// reuse the proxy cache, integrity verification, and policy enforcement.
    #[cfg(feature = "update")]
    pub fn update_engine(&self, config: starmetal_update_core::UpdateConfig) -> starmetal_updater::UpdateEngine {
        let datasource = std::sync::Arc::new(starmetal_updater::PackageServiceDatasource::new(
            self.package_service.clone(),
        ));
        starmetal_updater::UpdateEngine::new(
            starmetal_managers::all(),
            starmetal_versioning::all(),
            datasource,
            config,
        )
    }

    pub async fn delete_cached_artifact(&self, artifact: &ArtifactId) -> Result<CacheDeleteResult> {
        let key = artifact.validated_storage_key()?.into_string();
        let sidecar = format!("{key}.blake3");
        let mut deleted_keys = Vec::new();
        for candidate in [&key, &sidecar] {
            if self.storage.exists(candidate).await? {
                self.storage.delete(candidate).await?;
                deleted_keys.push(candidate.to_string());
            }
        }
        Ok(CacheDeleteResult { deleted_keys })
    }
}

pub fn load_config(options: ConfigLoadOptions) -> Result<Config> {
    let mut config = if options.no_config {
        Config::default()
    } else if let Some(path) = &options.path {
        Config::load_from(path)?
    } else {
        Config::load()?
    };
    apply_overrides(&mut config, options.overrides);
    Ok(config)
}

pub fn write_minimal_config(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(StarmetalError::Config(format!(
            "config file already exists: {}",
            path.display()
        )));
    }
    std::fs::write(path, minimal_config())?;
    Ok(())
}

pub fn minimal_config() -> &'static str {
    r#"# Starmetal configuration

[server]
bind = "127.0.0.1:8080"
max_upload_bytes = 536870912

[storage]
backend = "fs"

[storage.options]
root = "./starmetal-data"

[auth]
enabled = false
tokens = []

[publishing]
enabled = false
"#
}

fn apply_overrides(config: &mut Config, overrides: ConfigOverrides) {
    if let Some(bind) = overrides.bind {
        config.server.bind = bind;
    }
    if let Some(backend) = overrides.storage_backend {
        config.storage.backend = backend;
    }
    for (key, value) in overrides.storage_options {
        config.storage.options.insert(key, value);
    }
    for upstream in overrides.upstreams {
        let entry = config.upstream.entry(upstream.name).or_insert_with(|| UpstreamConfig {
            enabled: true,
            url: String::new(),
            artifact_url: None,
            allow_insecure: false,
            allow_private_network: false,
            max_response_bytes: DEFAULT_MAX_UPSTREAM_BYTES,
        });
        if let Some(enabled) = upstream.enabled {
            entry.enabled = enabled;
        }
        if let Some(url) = upstream.url {
            entry.url = url;
        }
        if upstream.artifact_url.is_some() {
            entry.artifact_url = upstream.artifact_url;
        }
    }
}

fn normalize_name(ecosystem: Ecosystem, name: &str) -> PackageName {
    let raw = PackageName::new(name);
    PackageName::new(raw.normalized(ecosystem).into_owned())
}

fn registry_statuses(config: &Config) -> Vec<RegistryStatus> {
    [
        (Ecosystem::PyPI, "pypi", cfg!(feature = "pypi")),
        (Ecosystem::Npm, "npm", cfg!(feature = "npm")),
        (Ecosystem::Cargo, "cargo", cfg!(feature = "cargo-registry")),
        (Ecosystem::Hex, "hex", cfg!(feature = "hex")),
        (Ecosystem::Maven, "maven", cfg!(feature = "maven")),
        (Ecosystem::RubyGems, "rubygems", cfg!(feature = "rubygems")),
        (Ecosystem::NuGet, "nuget", cfg!(feature = "nuget")),
        (Ecosystem::Pub, "pub", cfg!(feature = "pub")),
    ]
    .into_iter()
    .map(|(ecosystem, key, compiled)| {
        let upstream = config.upstream.get(key);
        RegistryStatus {
            ecosystem,
            configured: upstream.is_some(),
            enabled: upstream.map(|upstream| upstream.enabled).unwrap_or(false),
            compiled,
            url: upstream.map(|upstream| upstream.url.clone()),
            artifact_url: upstream.and_then(|upstream| upstream.artifact_url.clone()),
        }
    })
    .collect()
}

#[cfg(feature = "maven")]
fn register_maven_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::maven::upstream::MavenUpstreamClient> {
    let upstream_config = config.upstream.get("maven").expect("default maven upstream");
    let client = Arc::new(
        starmetal_adapters::maven::upstream::MavenUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Maven, client.clone());
    }
    client
}

#[cfg(feature = "rubygems")]
fn register_rubygems_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient> {
    let upstream_config = config.upstream.get("rubygems").expect("default rubygems upstream");
    let client = Arc::new(
        starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient::with_max_response_bytes(
            upstream_config
                .artifact_url
                .clone()
                .unwrap_or_else(|| upstream_config.url.clone()),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::RubyGems, client.clone());
    }
    client
}

#[cfg(feature = "nuget")]
fn register_nuget_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::nuget::upstream::NuGetUpstreamClient> {
    let upstream_config = config.upstream.get("nuget").expect("default nuget upstream");
    let client = Arc::new(
        starmetal_adapters::nuget::upstream::NuGetUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::NuGet, client.clone());
    }
    client
}

#[cfg(feature = "pub")]
fn register_pub_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::pubdev::upstream::PubUpstreamClient> {
    let upstream_config = config.upstream.get("pub").expect("default pub upstream");
    let client = Arc::new(
        starmetal_adapters::pubdev::upstream::PubUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Pub, client.clone());
    }
    client
}

#[cfg(feature = "pypi")]
fn register_pypi_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::pypi::upstream::PypiUpstreamClient> {
    let upstream_config = config.upstream.get("pypi").expect("default pypi upstream");
    let client = Arc::new(
        starmetal_adapters::pypi::upstream::PypiUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::PyPI, client.clone());
    }
    client
}

#[cfg(feature = "npm")]
fn register_npm_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::npm::upstream::NpmUpstreamClient> {
    let upstream_config = config.upstream.get("npm").expect("default npm upstream");
    let client = Arc::new(
        starmetal_adapters::npm::upstream::NpmUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Npm, client.clone());
    }
    client
}

#[cfg(feature = "cargo-registry")]
fn register_cargo_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::cargo::upstream::CargoUpstreamClient> {
    let upstream_config = config.upstream.get("cargo").expect("default cargo upstream");
    let artifact_url = upstream_config
        .artifact_url
        .clone()
        .unwrap_or_else(|| "https://static.crates.io/crates".to_string());
    let client = Arc::new(
        starmetal_adapters::cargo::upstream::CargoUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            artifact_url,
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Cargo, client.clone());
    }
    client
}

#[cfg(feature = "hex")]
fn register_hex_upstream(
    config: &Config,
    clients: &mut AHashMap<Ecosystem, Arc<dyn UpstreamClient>>,
) -> Arc<starmetal_adapters::hex::upstream::HexUpstreamClient> {
    let upstream_config = config.upstream.get("hex").expect("default hex upstream");
    let artifact_url = upstream_config
        .artifact_url
        .clone()
        .unwrap_or_else(|| "https://repo.hex.pm".to_string());
    let client = Arc::new(
        starmetal_adapters::hex::upstream::HexUpstreamClient::with_max_response_bytes(
            upstream_config.url.clone(),
            artifact_url,
            upstream_config.max_response_bytes,
        ),
    );
    if upstream_config.enabled {
        clients.insert(Ecosystem::Hex, client.clone());
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_config_uses_defaults_and_overrides() {
        let config = load_config(ConfigLoadOptions {
            no_config: true,
            overrides: ConfigOverrides {
                bind: Some("127.0.0.1:9999".to_string()),
                storage_backend: Some("memory".to_string()),
                storage_options: vec![("root".to_string(), "/tmp/ignored".to_string())],
                upstreams: vec![UpstreamOverride {
                    name: "pypi".to_string(),
                    enabled: Some(false),
                    url: Some("https://example.test".to_string()),
                    artifact_url: None,
                }],
            },
            path: None,
        })
        .expect("config should load");
        assert_eq!(config.server.bind, "127.0.0.1:9999");
        assert_eq!(config.storage.backend, "memory");
        assert!(!config.upstream["pypi"].enabled);
        assert_eq!(config.upstream["pypi"].url, "https://example.test");
    }

    #[test]
    fn config_init_refuses_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("starmetal.toml");
        std::fs::write(&path, "exists").expect("write");
        let err = write_minimal_config(&path).expect_err("existing config should fail");
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn require_signature_without_signing_is_a_startup_error() {
        let mut config = Config::default();
        config.storage.backend = "memory".to_string();
        for upstream in config.upstream.values_mut() {
            upstream.enabled = false;
        }
        config.supply_chain.require_signature = true; // but [signing] stays disabled

        let error = StarmetalRuntime::from_config(config)
            .await
            .err()
            .expect("requiring signatures without signing must fail closed at startup");
        assert!(error.to_string().contains("signing"));
    }

    #[tokio::test]
    async fn publish_artifact_stores_metadata() {
        let mut config = Config::default();
        config.storage.backend = "memory".to_string();
        config.publishing.enabled = true;
        for upstream in config.upstream.values_mut() {
            upstream.enabled = false;
        }
        let runtime = StarmetalRuntime::from_config(config)
            .await
            .expect("runtime should build");
        runtime
            .publish_artifact(
                Ecosystem::Npm,
                "sample",
                "1.0.0",
                "sample-1.0.0.tgz".to_string(),
                Bytes::from_static(b"artifact"),
                Some("MIT".to_string()),
            )
            .await
            .expect("publish should succeed");
        let metadata = runtime
            .metadata(Ecosystem::Npm, "sample", "1.0.0")
            .await
            .expect("metadata should load");
        assert_eq!(metadata.artifacts[0].filename, "sample-1.0.0.tgz");
    }

    #[tokio::test]
    async fn gc_and_retention_schedulers_are_none_without_a_content_maintenance_handle() {
        // The default config disables the content model (`metadata.enabled = false`), so no
        // maintenance handle is attached regardless of the interval fields, and both schedulers
        // must report `None` rather than spawning a task with nothing to drive.
        let mut config = Config::default();
        config.storage.backend = "memory".to_string();
        for upstream in config.upstream.values_mut() {
            upstream.enabled = false;
        }
        config.metadata.gc_interval_secs = 60;
        config.metadata.retention_interval_secs = 60;
        let runtime = StarmetalRuntime::from_config(config)
            .await
            .expect("runtime should build");

        assert!(
            runtime.content_maintenance.is_none(),
            "no content-store handle without metadata.enabled"
        );
        assert!(
            runtime.spawn_gc_scheduler().is_none(),
            "GC scheduler must not spawn without a maintenance handle"
        );
        assert!(
            runtime.spawn_retention_scheduler().is_none(),
            "retention scheduler must not spawn without a maintenance handle"
        );
    }

    #[tokio::test]
    async fn gc_and_retention_schedulers_are_none_when_interval_is_zero() {
        // Even with `metadata.enabled` (and thus a maintenance handle) reachable in principle, a
        // zero interval must disable each scheduler independently of the handle's presence.
        let mut config = Config::default();
        config.storage.backend = "memory".to_string();
        for upstream in config.upstream.values_mut() {
            upstream.enabled = false;
        }
        config.metadata.gc_interval_secs = 0;
        config.metadata.retention_interval_secs = 0;
        let runtime = StarmetalRuntime::from_config(config)
            .await
            .expect("runtime should build");

        assert!(
            runtime.spawn_gc_scheduler().is_none(),
            "zero GC interval disables the scheduler"
        );
        assert!(
            runtime.spawn_retention_scheduler().is_none(),
            "zero retention interval disables the scheduler"
        );
    }
}
