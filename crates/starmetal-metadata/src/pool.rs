//! bb8-managed connection pool over tokio-postgres.

use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use starmetal_core::error::{Result, StarmetalError};
use tokio_postgres::NoTls;

/// The connection pool type used by [`crate::PostgresContentStore`].
pub type DbPool = Pool<PostgresConnectionManager<NoTls>>;

/// Build a connection pool from a `postgresql://` URL.
///
/// # Errors
///
/// Returns [`StarmetalError::Storage`] if the URL is invalid or the pool cannot
/// establish an initial connection.
pub async fn create_pool(database_url: &str) -> Result<DbPool> {
    let config = database_url
        .parse::<tokio_postgres::Config>()
        .map_err(|error| StarmetalError::Storage(format!("invalid database url: {error}")))?;
    let manager = PostgresConnectionManager::new(config, NoTls);
    Pool::builder()
        .build(manager)
        .await
        .map_err(|error| StarmetalError::Storage(format!("failed to build database pool: {error}")))
}
