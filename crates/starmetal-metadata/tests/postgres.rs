//! Integration tests for `PostgresContentStore` against a real Postgres
//! (ADR-0020). Marked `#[ignore]` so the default `cargo test` stays offline;
//! run with `cargo test -p starmetal-metadata -- --ignored` (needs Docker).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use starmetal_core::content::{Asset, AssetRef, Blob, BlobDigest, Component, ComponentRef, ContentStore};
use starmetal_core::package::{Ecosystem, PackageName};
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

fn blob(digest: &str, size: u64) -> Blob {
    Blob {
        digest: BlobDigest::new(digest),
        size,
        upstream_hashes: Default::default(),
        content_type: None,
    }
}

fn component(ecosystem: Ecosystem, name: &str, version: &str) -> Component {
    Component {
        namespace: None,
        name: PackageName::new(name),
        version: version.to_string(),
        ecosystem,
        repository: String::new(),
        attributes: serde_json::json!({}),
    }
}

fn component_ref(ecosystem: Ecosystem, name: &str, version: &str) -> ComponentRef {
    ComponentRef {
        ecosystem,
        namespace: None,
        name: PackageName::new(name),
        version: version.to_string(),
    }
}

fn asset(ecosystem: Ecosystem, name: &str, version: &str, path: &str) -> Asset {
    Asset {
        path: path.to_string(),
        component_ref: component_ref(ecosystem, name, version),
        content_type: None,
        attributes: serde_json::json!({}),
    }
}

fn asset_ref(ecosystem: Ecosystem, name: &str, version: &str, path: &str) -> AssetRef {
    AssetRef {
        component_ref: component_ref(ecosystem, name, version),
        path: path.to_string(),
    }
}

/// Register a component + asset and link it to a blob digest.
async fn link(fx: &Fixture, ecosystem: Ecosystem, name: &str, version: &str, path: &str, digest: &BlobDigest) {
    fx.store
        .upsert_component(&component(ecosystem, name, version))
        .await
        .unwrap();
    fx.store
        .upsert_asset(&asset(ecosystem, name, version, path))
        .await
        .unwrap();
    fx.store
        .add_reference(&asset_ref(ecosystem, name, version, path), digest)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires docker"]
async fn get_or_insert_blob_dedups_and_never_overwrites_bytes() {
    let fx = setup().await;
    let bytes = Bytes::from_static(b"first");
    let digest = starmetal_core::integrity::blake3_hex(&bytes);

    fx.store
        .get_or_insert_blob(&blob(&digest, bytes.len() as u64), bytes.clone())
        .await
        .unwrap();

    // Tamper with storage directly, bypassing the content store, to make a second dedup'd
    // call observable: since the digest already has a row, `get_or_insert_blob` must skip the
    // storage write entirely and leave the tampered bytes in place.
    fx.storage.put(&digest, Bytes::from_static(b"TAMPERED")).await.unwrap();

    // Same digest and matching bytes on a second call: the row already exists, so this dedups.
    let returned = fx
        .store
        .get_or_insert_blob(&blob(&digest, bytes.len() as u64), bytes.clone())
        .await
        .unwrap();

    assert_eq!(returned.digest.as_str(), digest);
    let stored = fx.storage.get(&digest).await.unwrap().expect("bytes present");
    assert_eq!(
        &stored[..],
        b"TAMPERED",
        "dedup must not overwrite storage on a second insert of the same digest"
    );

    let unreferenced = fx.store.list_unreferenced_blobs().await.unwrap();
    assert_eq!(unreferenced.len(), 1, "exactly one blob row exists");
    assert_eq!(unreferenced[0].as_str(), digest);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn identical_bytes_across_ecosystems_share_one_blob() {
    let fx = setup().await;
    let bytes = Bytes::from_static(b"abc");
    let digest = BlobDigest::new(starmetal_core::integrity::blake3_hex(&bytes));
    fx.store
        .get_or_insert_blob(&blob(digest.as_str(), bytes.len() as u64), bytes)
        .await
        .unwrap();

    link(&fx, Ecosystem::PyPI, "pkg", "1.0.0", "pkg-1.0.0.tar.gz", &digest).await;
    link(&fx, Ecosystem::Npm, "pkg", "1.0.0", "pkg-1.0.0.tgz", &digest).await;

    assert!(fx.store.is_referenced(&digest).await.unwrap());
    assert!(
        fx.store.list_unreferenced_blobs().await.unwrap().is_empty(),
        "a referenced blob is never a GC candidate"
    );
}

#[tokio::test]
#[ignore = "requires docker"]
async fn reference_counting_detects_the_last_reference() {
    let fx = setup().await;
    let bytes = Bytes::from_static(b"x");
    let digest = BlobDigest::new(starmetal_core::integrity::blake3_hex(&bytes));
    fx.store
        .get_or_insert_blob(&blob(digest.as_str(), bytes.len() as u64), bytes)
        .await
        .unwrap();

    link(&fx, Ecosystem::Cargo, "cr", "1.0.0", "one.txt", &digest).await;
    link(&fx, Ecosystem::Cargo, "cr", "1.0.0", "two.txt", &digest).await;

    fx.store
        .remove_reference(&asset_ref(Ecosystem::Cargo, "cr", "1.0.0", "one.txt"), &digest)
        .await
        .unwrap();
    assert!(
        fx.store.is_referenced(&digest).await.unwrap(),
        "still referenced by two.txt"
    );

    fx.store
        .remove_reference(&asset_ref(Ecosystem::Cargo, "cr", "1.0.0", "two.txt"), &digest)
        .await
        .unwrap();
    assert!(
        !fx.store.is_referenced(&digest).await.unwrap(),
        "last reference removed"
    );

    let unreferenced = fx.store.list_unreferenced_blobs().await.unwrap();
    assert_eq!(unreferenced, vec![digest]);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn gc_honors_grace_window_then_compacts() {
    let fx = setup().await;
    let bytes = Bytes::from_static(b"z");
    let digest = BlobDigest::new(starmetal_core::integrity::blake3_hex(&bytes));
    fx.store
        .get_or_insert_blob(&blob(digest.as_str(), bytes.len() as u64), bytes)
        .await
        .unwrap();

    // Marked + soft-deleted with a long grace: nothing is reclaimed yet.
    fx.store.mark_unreferenced(&digest).await.unwrap();
    fx.store.soft_delete(&digest, Duration::from_secs(3600)).await.unwrap();
    assert!(fx.store.compact().await.unwrap().is_empty(), "grace not elapsed");
    assert!(
        fx.storage.get(digest.as_str()).await.unwrap().is_some(),
        "bytes survive during the grace window"
    );

    // Undelete cancels the pending reclaim.
    fx.store.undelete(&digest).await.unwrap();
    assert!(fx.store.compact().await.unwrap().is_empty());

    // Zero grace makes it immediately eligible; a small pause covers clock skew.
    fx.store.soft_delete(&digest, Duration::ZERO).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let reclaimed = fx.store.compact().await.unwrap();
    assert_eq!(reclaimed, vec![digest.clone()], "expired blob is reclaimed");
    assert!(
        fx.store.get_blob(&digest).await.unwrap().is_none(),
        "metadata row is gone"
    );
    assert!(
        fx.storage.get(digest.as_str()).await.unwrap().is_none(),
        "blob bytes are gone"
    );
}
