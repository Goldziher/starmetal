use async_trait::async_trait;
use bytes::Bytes;
use opendal::Operator;

use starmetal_core::config::StorageConfig;
use starmetal_core::error::Result;
use starmetal_core::error::StarmetalError;
use starmetal_core::ports::StoragePort;

/// Storage backend backed by OpenDAL.
pub struct OpenDalStorage {
    operator: Operator,
}

impl OpenDalStorage {
    pub fn new(operator: Operator) -> Self {
        Self { operator }
    }

    pub fn from_config(config: &StorageConfig) -> Result<Self> {
        let mut options = config.opendal_options();
        if config.backend == "fs" {
            options
                .entry("root".to_string())
                .or_insert_with(|| "./starmetal-data".to_string());
        }

        Operator::via_iter(&config.backend, options)
            .map(Self::new)
            .map_err(|err| {
                StarmetalError::Storage(format!(
                    "failed to initialize OpenDAL backend '{}': {err}",
                    config.backend
                ))
            })
    }

    /// Create a filesystem-backed storage rooted at the given path.
    ///
    /// Creates the directory if it does not already exist.
    #[cfg(feature = "backend-fs")]
    pub fn filesystem(root: &std::path::Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        let builder = opendal::services::Fs::default().root(&root.to_string_lossy());
        let operator = Operator::new(builder)
            .map_err(|e| StarmetalError::Storage(e.to_string()))?
            .finish();
        Ok(Self::new(operator))
    }

    /// Create an in-memory storage backend (useful for testing).
    #[cfg(feature = "backend-memory")]
    pub fn memory() -> Result<Self> {
        let builder = opendal::services::Memory::default();
        let operator = Operator::new(builder)
            .map_err(|e| StarmetalError::Storage(e.to_string()))?
            .finish();
        Ok(Self::new(operator))
    }
}

#[async_trait]
impl StoragePort for OpenDalStorage {
    async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        match self.operator.read(key).await {
            Ok(data) => Ok(Some(data.to_bytes())),
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StarmetalError::Storage(e.to_string())),
        }
    }

    async fn put(&self, key: &str, data: Bytes) -> Result<()> {
        self.operator
            .write(key, data)
            .await
            .map(|_| ())
            .map_err(|e| StarmetalError::Storage(e.to_string()))
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.operator
            .exists(key)
            .await
            .map_err(|e| StarmetalError::Storage(e.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.operator
            .delete(key)
            .await
            .map_err(|e| StarmetalError::Storage(e.to_string()))
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let entries = self
            .operator
            .list(prefix)
            .await
            .map_err(|e| StarmetalError::Storage(e.to_string()))?;

        Ok(entries.into_iter().map(|e| e.path().to_string()).collect())
    }
}
