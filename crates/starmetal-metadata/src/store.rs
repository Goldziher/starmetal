//! Postgres-backed [`ContentStore`]: the content-addressed metadata spine and
//! reference-counted garbage collection of ADR-0020, over the generated
//! tokio-postgres queriers and a low-level [`StoragePort`] byte driver.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bb8::PooledConnection;
use bb8_postgres::PostgresConnectionManager;
use bytes::Bytes;
use starmetal_core::content::{Asset, AssetRef, Blob, BlobDigest, Component, ContentStore};
use starmetal_core::error::{Result, StarmetalError};
use starmetal_core::ports::StoragePort;
use tokio_postgres::{GenericClient, NoTls};

use crate::generated::queries;
use crate::pool::DbPool;

/// The content-model schema, applied verbatim to provision a database.
pub const SCHEMA_SQL: &str = include_str!("../sql/schema.sql");

pub(crate) type Conn<'a> = PooledConnection<'a, PostgresConnectionManager<NoTls>>;

/// A [`ContentStore`] backed by Postgres (metadata + reference table) over a
/// [`StoragePort`] (blob bytes).
///
/// Blobs are content-addressed by their Blake3 digest; identical bytes across
/// ecosystems and versions share one stored object. The `asset -> blob` reference
/// table drives reference-counted GC.
pub struct PostgresContentStore {
    pool: DbPool,
    storage: Arc<dyn StoragePort>,
}

impl PostgresContentStore {
    /// Build a store over a pool and a byte-storage driver.
    pub fn new(pool: DbPool, storage: Arc<dyn StoragePort>) -> Self {
        Self { pool, storage }
    }

    /// Apply [`SCHEMA_SQL`] to provision a fresh database.
    ///
    /// # Errors
    ///
    /// Returns [`StarmetalError::Storage`] if the schema cannot be applied.
    pub async fn apply_schema(&self) -> Result<()> {
        let conn = self.conn().await?;
        conn.batch_execute(SCHEMA_SQL).await.map_err(db_error)?;
        Ok(())
    }

    pub(crate) async fn conn(&self) -> Result<Conn<'_>> {
        self.pool
            .get()
            .await
            .map_err(|error| StarmetalError::Storage(format!("database pool checkout failed: {error}")))
    }

    async fn resolve_asset_id(&self, client: &(impl GenericClient + Sync), asset: &AssetRef) -> Result<i64> {
        let component = &asset.component_ref;
        queries::get_asset_id_by_ref(
            client,
            &component.ecosystem.to_string(),
            namespace(&component.namespace),
            component.name.as_str(),
            &component.version,
            &asset.path,
        )
        .await
        .map_err(db_error)?
        .map(|row| row.id)
        .ok_or_else(|| StarmetalError::Storage(format!("asset not found: {}", asset.path)))
    }
}

#[async_trait]
impl ContentStore for PostgresContentStore {
    async fn get_or_insert_blob(&self, blob: &Blob, data: Bytes) -> Result<Blob> {
        // Enforce the content-address invariant at the write boundary: the storage key *is* the
        // Blake3 digest, so a caller claiming a digest that doesn't match its bytes is rejected
        // here, before any DB call and regardless of dedup (a lying caller is rejected even when
        // the blob already exists).
        starmetal_core::integrity::verify_or_err(&data, blob.digest.as_str())?;

        let conn = self.conn().await?;
        let upstream_hashes = serde_json::to_value(&blob.upstream_hashes)
            .map_err(|error| StarmetalError::Storage(format!("serialize upstream_hashes: {error}")))?;
        let inserted = queries::insert_blob_if_absent(
            &*conn,
            blob.digest.as_str(),
            blob.size as i64,
            blob.content_type.as_deref(),
            &upstream_hashes,
        )
        .await
        .map_err(db_error)?;

        // Only a freshly inserted row writes bytes — identical digests dedup.
        if inserted.is_some() {
            self.storage.put(blob.digest.as_str(), data).await?;
        }

        self.get_blob(&blob.digest)
            .await?
            .ok_or_else(|| StarmetalError::Storage("blob missing immediately after insert".to_string()))
    }

    async fn get_blob(&self, digest: &BlobDigest) -> Result<Option<Blob>> {
        let conn = self.conn().await?;
        let row = queries::get_blob(&*conn, digest.as_str()).await.map_err(db_error)?;
        row.map(blob_from_row).transpose()
    }

    async fn read_blob(&self, digest: &BlobDigest) -> Result<Option<Bytes>> {
        // A known blob row gates the read, so a stray/foreign object under this key is never
        // served as a blob.
        if self.get_blob(digest).await?.is_none() {
            return Ok(None);
        }
        let Some(bytes) = self.storage.get(digest.as_str()).await? else {
            return Ok(None);
        };
        starmetal_core::integrity::verify_or_err(&bytes, digest.as_str())?;
        Ok(Some(bytes))
    }

    async fn upsert_component(&self, component: &Component) -> Result<()> {
        let conn = self.conn().await?;
        queries::upsert_component(
            &*conn,
            &component.ecosystem.to_string(),
            namespace(&component.namespace),
            component.name.as_str(),
            &component.version,
            &component.repository,
            &component.attributes,
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn upsert_asset(&self, asset: &Asset) -> Result<()> {
        let conn = self.conn().await?;
        let component = &asset.component_ref;
        let component_id = queries::get_component_id(
            &*conn,
            &component.ecosystem.to_string(),
            namespace(&component.namespace),
            component.name.as_str(),
            &component.version,
        )
        .await
        .map_err(db_error)?
        .map(|row| row.id)
        .ok_or_else(|| StarmetalError::Storage(format!("component not found for asset {}", asset.path)))?;

        queries::upsert_asset(
            &*conn,
            component_id,
            &asset.path,
            asset.content_type.as_deref(),
            &asset.attributes,
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn add_reference(&self, asset: &AssetRef, digest: &BlobDigest) -> Result<()> {
        let conn = self.conn().await?;
        let asset_id = self.resolve_asset_id(&*conn, asset).await?;
        queries::add_reference(&*conn, asset_id, digest.as_str())
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn remove_reference(&self, asset: &AssetRef, digest: &BlobDigest) -> Result<()> {
        let conn = self.conn().await?;
        let asset_id = self.resolve_asset_id(&*conn, asset).await?;
        queries::remove_reference(&*conn, asset_id, digest.as_str())
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn is_referenced(&self, digest: &BlobDigest) -> Result<bool> {
        let conn = self.conn().await?;
        let row = queries::is_blob_referenced(&*conn, digest.as_str())
            .await
            .map_err(db_error)?;
        Ok(row.referenced)
    }

    async fn list_unreferenced_blobs(&self) -> Result<Vec<BlobDigest>> {
        let conn = self.conn().await?;
        let rows = queries::list_unreferenced_blobs(&*conn).await.map_err(db_error)?;
        Ok(rows.into_iter().map(|row| BlobDigest::new(row.digest)).collect())
    }

    async fn mark_unreferenced(&self, digest: &BlobDigest) -> Result<()> {
        let conn = self.conn().await?;
        queries::mark_blob_unreferenced(&*conn, digest.as_str())
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn soft_delete(&self, digest: &BlobDigest, grace: Duration) -> Result<()> {
        let conn = self.conn().await?;
        let grace = chrono::Duration::from_std(grace)
            .map_err(|error| StarmetalError::Storage(format!("invalid grace window: {error}")))?;
        let expires_at = chrono::Utc::now() + grace;
        queries::soft_delete_blob(&*conn, digest.as_str(), &expires_at)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn undelete(&self, digest: &BlobDigest) -> Result<()> {
        let conn = self.conn().await?;
        queries::undelete_blob(&*conn, digest.as_str())
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn compact(&self) -> Result<Vec<BlobDigest>> {
        let conn = self.conn().await?;
        // Compare against the caller's clock (the same clock `soft_delete` stamped
        // `grace_expires_at` with) so the grace decision never straddles a client/server
        // clock skew — otherwise a zero-grace blob can be missed when the DB clock lags.
        let now = chrono::Utc::now();
        let expired = queries::list_expired_soft_deleted(&*conn, &now)
            .await
            .map_err(db_error)?;
        let mut reclaimed = Vec::with_capacity(expired.len());
        for row in expired {
            // Delete bytes before the row so a storage failure leaves the row for
            // a later retry rather than orphaning bytes with no metadata.
            self.storage.delete(&row.digest).await?;
            queries::delete_blob(&*conn, &row.digest).await.map_err(db_error)?;
            reclaimed.push(BlobDigest::new(row.digest));
        }
        Ok(reclaimed)
    }
}

fn blob_from_row(row: queries::GetBlobRow) -> Result<Blob> {
    let upstream_hashes = serde_json::from_value(row.upstream_hashes)
        .map_err(|error| StarmetalError::Storage(format!("deserialize upstream_hashes: {error}")))?;
    Ok(Blob {
        digest: BlobDigest::new(row.digest),
        size: row.size as u64,
        upstream_hashes,
        content_type: row.content_type,
    })
}

/// Map the empty-string sentinel used for a namespace-less component.
fn namespace(namespace: &Option<String>) -> &str {
    namespace.as_deref().unwrap_or("")
}

pub(crate) fn db_error(error: tokio_postgres::Error) -> StarmetalError {
    StarmetalError::Storage(format!("database error: {error}"))
}
