//! Integration tests proving cross-ecosystem blob deduplication (ADR-0020 Stage 2b) against a
//! real Postgres. Marked `#[ignore]` so the default `cargo test` stays offline; run with
//! `cargo test -p starmetal-metadata -- --ignored` (needs Docker).

use std::sync::Arc;

use bytes::Bytes;
use starmetal_core::content::{Asset, AssetRef, Blob, BlobDigest, Component, ComponentRef, ContentStore};
use starmetal_core::integrity::blake3_hex;
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
}

async fn setup() -> Fixture {
    let container = Postgres::default().start().await.expect("start postgres container");
    let port = container.get_host_port_ipv4(5432).await.expect("map postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = create_pool(&url).await.expect("build pool");
    let storage: Arc<dyn StoragePort> = Arc::new(OpenDalStorage::memory().expect("memory storage"));
    let store = PostgresContentStore::new(pool, storage);
    store.apply_schema().await.expect("apply schema");
    Fixture {
        _container: container,
        store,
    }
}

fn component(ecosystem: Ecosystem, name: &str, version: &str) -> Component {
    Component {
        namespace: None,
        name: PackageName::new(name),
        version: version.to_string(),
        ecosystem,
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

/// Register a component + asset for `ecosystem` and link it to the shared blob at `digest`,
/// without writing the blob bytes (the caller is expected to have already inserted the blob).
async fn link_to_shared_blob(fx: &Fixture, ecosystem: Ecosystem, name: &str, version: &str, digest: &BlobDigest) {
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
async fn identical_bytes_across_two_ecosystems_share_one_blob() {
    let fx = setup().await;
    let payload = Bytes::from_static(b"identical package bytes shared across ecosystems");
    let digest = BlobDigest::new(blake3_hex(&payload));
    let blob = Blob {
        digest: digest.clone(),
        size: payload.len() as u64,
        upstream_hashes: Default::default(),
        content_type: None,
    };

    let inserted_from_pypi = fx.store.get_or_insert_blob(&blob, payload.clone()).await.unwrap();
    let inserted_from_npm = fx.store.get_or_insert_blob(&blob, payload.clone()).await.unwrap();

    assert_eq!(
        inserted_from_pypi.digest, digest,
        "PyPI insert resolves to the shared digest"
    );
    assert_eq!(
        inserted_from_npm.digest, digest,
        "npm insert resolves to the same shared digest"
    );
    assert_eq!(
        inserted_from_pypi.size, inserted_from_npm.size,
        "both inserts report identical blob size"
    );

    link_to_shared_blob(&fx, Ecosystem::PyPI, "widget", "1.0.0", &digest).await;
    link_to_shared_blob(&fx, Ecosystem::Npm, "widget", "1.0.0", &digest).await;

    let fetched = fx.store.get_blob(&digest).await.unwrap();
    assert!(fetched.is_some(), "the shared blob is retrievable by digest");
    assert_eq!(fetched.unwrap().digest, digest);

    assert!(
        fx.store.is_referenced(&digest).await.unwrap(),
        "the shared blob is referenced by at least one asset"
    );
    let unreferenced = fx.store.list_unreferenced_blobs().await.unwrap();
    assert!(
        !unreferenced.contains(&digest),
        "a blob referenced from two ecosystems is not a GC candidate"
    );
}

#[tokio::test]
#[ignore = "requires docker"]
async fn shared_blob_survives_until_the_last_reference_is_removed() {
    let fx = setup().await;
    let payload = Bytes::from_static(b"cross-ecosystem shared bytes for reference counting");
    let digest = BlobDigest::new(blake3_hex(&payload));
    let blob = Blob {
        digest: digest.clone(),
        size: payload.len() as u64,
        upstream_hashes: Default::default(),
        content_type: None,
    };
    fx.store.get_or_insert_blob(&blob, payload.clone()).await.unwrap();
    fx.store.get_or_insert_blob(&blob, payload.clone()).await.unwrap();

    link_to_shared_blob(&fx, Ecosystem::PyPI, "gadget", "2.0.0", &digest).await;
    link_to_shared_blob(&fx, Ecosystem::Npm, "gadget", "2.0.0", &digest).await;

    let pypi_ref = asset_ref(Ecosystem::PyPI, "gadget", "2.0.0", "gadget-2.0.0.tar.gz");
    fx.store.remove_reference(&pypi_ref, &digest).await.unwrap();

    assert!(
        fx.store.is_referenced(&digest).await.unwrap(),
        "the npm reference alone keeps the blob alive after the PyPI reference is dropped"
    );
    let unreferenced_after_pypi_removed = fx.store.list_unreferenced_blobs().await.unwrap();
    assert!(
        !unreferenced_after_pypi_removed.contains(&digest),
        "still referenced by npm, so not yet a GC candidate"
    );

    let npm_ref = asset_ref(Ecosystem::Npm, "gadget", "2.0.0", "gadget-2.0.0.tar.gz");
    fx.store.remove_reference(&npm_ref, &digest).await.unwrap();

    assert!(
        !fx.store.is_referenced(&digest).await.unwrap(),
        "removing both ecosystems' references leaves the blob unreferenced"
    );
    let unreferenced_after_both_removed = fx.store.list_unreferenced_blobs().await.unwrap();
    assert!(
        unreferenced_after_both_removed.contains(&digest),
        "with no remaining references, the blob is now a GC candidate"
    );
}

#[tokio::test]
#[ignore = "requires docker"]
async fn distinct_bytes_produce_distinct_blobs() {
    let fx = setup().await;
    let pypi_payload = Bytes::from_static(b"pypi-only distinct payload bytes");
    let npm_payload = Bytes::from_static(b"npm-only distinct payload bytes, different content");

    let pypi_digest = BlobDigest::new(blake3_hex(&pypi_payload));
    let npm_digest = BlobDigest::new(blake3_hex(&npm_payload));
    assert_ne!(pypi_digest, npm_digest, "different bytes hash to different digests");

    let pypi_blob = Blob {
        digest: pypi_digest.clone(),
        size: pypi_payload.len() as u64,
        upstream_hashes: Default::default(),
        content_type: None,
    };
    let npm_blob = Blob {
        digest: npm_digest.clone(),
        size: npm_payload.len() as u64,
        upstream_hashes: Default::default(),
        content_type: None,
    };
    fx.store.get_or_insert_blob(&pypi_blob, pypi_payload).await.unwrap();
    fx.store.get_or_insert_blob(&npm_blob, npm_payload).await.unwrap();

    link_to_shared_blob(&fx, Ecosystem::PyPI, "solo", "1.0.0", &pypi_digest).await;
    link_to_shared_blob(&fx, Ecosystem::Npm, "solo", "1.0.0", &npm_digest).await;

    let fetched_pypi = fx.store.get_blob(&pypi_digest).await.unwrap();
    let fetched_npm = fx.store.get_blob(&npm_digest).await.unwrap();
    assert!(
        fetched_pypi.is_some(),
        "the PyPI-only blob is retrievable by its own digest"
    );
    assert!(
        fetched_npm.is_some(),
        "the npm-only blob is retrievable by its own digest"
    );
    assert_ne!(
        fetched_pypi.unwrap().digest,
        fetched_npm.unwrap().digest,
        "the two blobs remain distinct stored objects"
    );
}
