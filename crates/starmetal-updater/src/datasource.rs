use std::sync::Arc;

use async_trait::async_trait;
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::ports::PackageService;
use starmetal_update_core::error::Result;
use starmetal_update_core::ports::{Datasource, Release};

/// A [`Datasource`] backed by the registry [`PackageService`].
///
/// Version lookups performed during an update run therefore reuse the proxy's
/// pull-through cache, blake3 integrity verification, and policy enforcement,
/// rather than querying upstream registries directly. This is the integration
/// point that ties the update engine to the registry proxy.
pub struct PackageServiceDatasource {
    service: Arc<dyn PackageService>,
}

impl PackageServiceDatasource {
    /// Wrap a package service as an update datasource.
    pub fn new(service: Arc<dyn PackageService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Datasource for PackageServiceDatasource {
    async fn get_releases(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<Vec<Release>> {
        let versions = self.service.list_versions(ecosystem, name).await?;
        Ok(versions
            .into_iter()
            .map(|info| Release {
                version: info.version,
                yanked: info.yanked,
                timestamp: None,
            })
            .collect())
    }
}
