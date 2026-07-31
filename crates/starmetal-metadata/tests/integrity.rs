//! Integration tests for the content-address integrity invariant on the `ContentStore` blob
//! path (ADR-0020 Stage 2b): `get_or_insert_blob` rejects a claimed digest that doesn't match its
//! bytes, and `read_blob` re-verifies bytes fetched from storage against their digest-key.
//! Against a real Postgres. Marked `#[ignore]` so the default `cargo test` stays offline; run
//! with `cargo test -p starmetal-metadata --test integrity -- --ignored` (needs Docker).

use std::sync::Arc;

use bytes::Bytes;
use starmetal_core::content::{Blob, BlobDigest, ContentStore};
use starmetal_core::error::StarmetalError;
use starmetal_core::integrity::blake3_hex;
use starmetal_core::ports::StoragePort;
use starmetal_metadata::{PostgresContentStore, create_pool};
use starmetal_storage::OpenDalStorage;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;

struct Fixture {
    _container: ContainerAsync<Postgres>,
    store: PostgresContentStore,
    storage: Arc<dyn StoragePort>,
}

async fn setup() -> Fixture {
    let container = Postgres::default().start().await.expect("start postgres container");
    let port = container.get_host_port_ipv4(5432).await.expect("map postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = create_pool(&url).await.expect("build pool");
    let storage: Arc<dyn StoragePort> = Arc::new(OpenDalStorage::memory().expect("memory storage"));
    let store = PostgresContentStore::new(pool, storage.clone());
    store.apply_schema().await.expect("apply schema");
    Fixture {
        _container: container,
        store,
        storage,
    }
}

fn blob_for(bytes: &Bytes) -> Blob {
    Blob {
        digest: BlobDigest::new(blake3_hex(bytes)),
        size: bytes.len() as u64,
        upstream_hashes: Default::default(),
        content_type: None,
    }
}

#[tokio::test]
#[ignore = "requires docker"]
async fn read_blob_returns_the_verified_bytes() {
    let fx = setup().await;
    let bytes = Bytes::from_static(b"integrity-verified-bytes");
    let blob = blob_for(&bytes);
    fx.store.get_or_insert_blob(&blob, bytes.clone()).await.unwrap();

    let read = fx.store.read_blob(&blob.digest).await.unwrap();
    assert_eq!(read, Some(bytes));
}

#[tokio::test]
#[ignore = "requires docker"]
async fn read_blob_detects_tampered_bytes() {
    let fx = setup().await;
    let bytes = Bytes::from_static(b"original-bytes");
    let blob = blob_for(&bytes);
    fx.store.get_or_insert_blob(&blob, bytes.clone()).await.unwrap();

    // Overwrite the storage object directly, bypassing the content store, to simulate on-disk
    // corruption or tampering under the digest key.
    fx.storage
        .put(blob.digest.as_str(), Bytes::from_static(b"tampered-bytes"))
        .await
        .unwrap();

    let error = fx.store.read_blob(&blob.digest).await.unwrap_err();
    assert!(
        matches!(error, StarmetalError::IntegrityError { .. }),
        "expected IntegrityError, got {error:?}"
    );
}

#[tokio::test]
#[ignore = "requires docker"]
async fn read_blob_is_none_for_an_unknown_digest() {
    let fx = setup().await;
    let unknown = BlobDigest::new(blake3_hex(b"never-inserted"));

    let read = fx.store.read_blob(&unknown).await.unwrap();
    assert_eq!(read, None);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn get_or_insert_blob_rejects_a_digest_that_does_not_match_its_bytes() {
    let fx = setup().await;
    let bytes = Bytes::from_static(b"actual-bytes");
    let lying_digest = BlobDigest::new(blake3_hex(b"a-different-payload"));
    let blob = Blob {
        digest: lying_digest.clone(),
        size: bytes.len() as u64,
        upstream_hashes: Default::default(),
        content_type: None,
    };

    let error = fx.store.get_or_insert_blob(&blob, bytes).await.unwrap_err();
    assert!(
        matches!(error, StarmetalError::IntegrityError { .. }),
        "expected IntegrityError, got {error:?}"
    );

    assert_eq!(
        fx.store.get_blob(&lying_digest).await.unwrap(),
        None,
        "nothing is persisted for a rejected insert"
    );
}
