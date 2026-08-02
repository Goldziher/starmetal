//! Integration tests for the scheduled GC sweep (`starmetal_metadata::gc::run_gc_sweep`,
//! ADR-0020 Stage 2d) against a real Postgres. Marked `#[ignore]` so the default `cargo test`
//! stays offline; run with `cargo test -p starmetal-metadata -- --ignored` (needs Docker).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use starmetal_core::content::{Asset, AssetRef, Blob, BlobDigest, Component, ComponentRef, ContentStore};
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::ports::StoragePort;
use starmetal_metadata::{GcConfig, PostgresContentStore, create_pool, run_gc_sweep};
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

async fn insert_blob(fx: &Fixture, bytes: &[u8]) -> BlobDigest {
    let digest = BlobDigest::new(starmetal_core::integrity::blake3_hex(bytes));
    let blob = Blob {
        digest: digest.clone(),
        size: bytes.len() as u64,
        upstream_hashes: Default::default(),
        content_type: None,
    };
    fx.store
        .get_or_insert_blob(&blob, Bytes::copy_from_slice(bytes))
        .await
        .unwrap();
    digest
}

/// Register a component + asset and link it to `digest`, so the blob has a live reference.
async fn reference_blob(fx: &Fixture, ecosystem: Ecosystem, name: &str, version: &str, digest: &BlobDigest) {
    fx.store
        .upsert_component(&component(ecosystem, name, version))
        .await
        .unwrap();
    let path = format!("{name}-{version}.tar.gz");
    fx.store
        .upsert_asset(&asset(ecosystem, name, version, &path))
        .await
        .unwrap();
    fx.store
        .add_reference(&asset_ref(ecosystem, name, version, &path), digest)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires docker"]
async fn zero_grace_reclaims_an_unreferenced_blob_in_one_sweep() {
    let fx = setup().await;
    let digest = insert_blob(&fx, b"unreferenced").await;

    let config = GcConfig { grace: Duration::ZERO };
    let report = run_gc_sweep(&fx.store, &config).await.unwrap();

    assert_eq!(report.marked, 1);
    assert_eq!(report.soft_deleted, 1);
    assert_eq!(report.reclaimed, vec![digest.clone()]);

    assert!(
        fx.store.get_blob(&digest).await.unwrap().is_none(),
        "metadata row is gone from the content store"
    );
    assert!(
        fx.storage.get(digest.as_str()).await.unwrap().is_none(),
        "bytes are gone from the underlying StoragePort"
    );
}

#[tokio::test]
#[ignore = "requires docker"]
async fn a_referenced_blob_is_never_touched() {
    let fx = setup().await;
    let digest = insert_blob(&fx, b"referenced").await;
    reference_blob(&fx, Ecosystem::PyPI, "pkg", "1.0.0", &digest).await;

    let config = GcConfig { grace: Duration::ZERO };
    let report = run_gc_sweep(&fx.store, &config).await.unwrap();

    assert_eq!(report.marked, 0);
    assert_eq!(report.soft_deleted, 0);
    assert!(report.reclaimed.is_empty());

    assert!(
        fx.store.get_blob(&digest).await.unwrap().is_some(),
        "referenced blob's metadata survives"
    );
    assert!(
        fx.storage.get(digest.as_str()).await.unwrap().is_some(),
        "referenced blob's bytes survive"
    );
}

#[tokio::test]
#[ignore = "requires docker"]
async fn long_grace_soft_deletes_first_then_reclaims_nothing_on_either_sweep() {
    let fx = setup().await;
    let digest = insert_blob(&fx, b"long-grace").await;

    let long_grace = GcConfig {
        grace: Duration::from_secs(3600),
    };

    let first = run_gc_sweep(&fx.store, &long_grace).await.unwrap();
    assert_eq!(first.marked, 1);
    assert_eq!(first.soft_deleted, 1);
    assert!(first.reclaimed.is_empty(), "grace has not elapsed yet");
    assert!(
        fx.storage.get(digest.as_str()).await.unwrap().is_some(),
        "bytes survive the first sweep"
    );

    // A second sweep: the blob is already soft-deleted (and thus no longer unreferenced-and-active),
    // so it is not re-marked, and its grace window still has not elapsed.
    let second = run_gc_sweep(&fx.store, &long_grace).await.unwrap();
    assert_eq!(
        second.marked, 0,
        "already soft-deleted blobs are not re-listed as candidates"
    );
    assert!(second.reclaimed.is_empty(), "grace still has not elapsed");
    assert!(
        fx.storage.get(digest.as_str()).await.unwrap().is_some(),
        "bytes survive the second sweep too"
    );
}
