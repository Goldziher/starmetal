//! Integration tests for the retention engine (`PostgresContentStore::apply_retention`,
//! ADR-0020 Stage 2c) against a real Postgres. Marked `#[ignore]` so the default `cargo test`
//! stays offline; run with `cargo test -p starmetal-metadata -- --ignored` (needs Docker).

use std::sync::Arc;

use bytes::Bytes;
use starmetal_core::content::{
    Asset, AssetRef, Blob, BlobDigest, Component, ComponentRef, ContentStore, RetentionPolicy, RetentionRule,
};
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

/// Register a component + asset and link it to a fresh blob with unique bytes/digest.
///
/// `seed` only needs to be unique per call (it becomes the blob's bytes); the digest is always
/// the real Blake3 hash of those bytes, and is returned so callers can assert against it.
async fn seed_version(fx: &Fixture, ecosystem: Ecosystem, name: &str, version: &str, seed: &str) -> BlobDigest {
    let bytes = Bytes::from(seed.to_string());
    let digest = BlobDigest::new(starmetal_core::integrity::blake3_hex(&bytes));
    let blob = Blob {
        digest: digest.clone(),
        size: bytes.len() as u64,
        upstream_hashes: Default::default(),
        content_type: None,
    };
    fx.store.get_or_insert_blob(&blob, bytes).await.unwrap();

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
        .add_reference(&asset_ref(ecosystem, name, version, &path), &digest)
        .await
        .unwrap();
    digest
}

#[tokio::test]
#[ignore = "requires docker"]
async fn keep_latest_deletes_all_but_the_newest_versions() {
    let fx = setup().await;
    let ecosystem = Ecosystem::PyPI;
    let name = "widget";

    // Stagger creation so version 5 is the newest and version 1 the oldest.
    for index in 1..=5 {
        let digest = format!("{:064}", index);
        seed_version(&fx, ecosystem, name, &format!("1.0.{index}"), &digest).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let policy = RetentionPolicy {
        rules: vec![RetentionRule::KeepLatest { count: 2 }],
    };
    let outcome = fx
        .store
        .apply_retention(&policy, ecosystem, None, &PackageName::new(name))
        .await
        .unwrap();

    let mut deleted = outcome.deleted.clone();
    deleted.sort();
    assert_eq!(
        deleted,
        vec!["1.0.1", "1.0.2", "1.0.3"],
        "the 3 oldest versions are deleted"
    );

    let remaining = fx
        .store
        .apply_retention(&RetentionPolicy::default(), ecosystem, None, &PackageName::new(name))
        .await
        .unwrap();
    assert!(remaining.deleted.is_empty(), "an empty policy deletes nothing");
}

#[tokio::test]
#[ignore = "requires docker"]
async fn is_prerelease_true_deletes_only_prerelease_versions() {
    let fx = setup().await;
    let ecosystem = Ecosystem::Cargo;
    let name = "crate-a";

    seed_version(&fx, ecosystem, name, "1.0.0", &"a".repeat(64)).await;
    seed_version(&fx, ecosystem, name, "1.1.0-rc.1", &"b".repeat(64)).await;

    let policy = RetentionPolicy {
        rules: vec![RetentionRule::IsPrerelease { prerelease: true }],
    };
    let outcome = fx
        .store
        .apply_retention(&policy, ecosystem, None, &PackageName::new(name))
        .await
        .unwrap();

    assert_eq!(outcome.deleted, vec!["1.1.0-rc.1"]);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn deleting_a_version_drops_its_reference_and_frees_the_blob() {
    let fx = setup().await;
    let ecosystem = Ecosystem::Npm;
    let name = "pkg";
    let digest = seed_version(&fx, ecosystem, name, "2.0.0-beta.1", "c".repeat(64).as_str()).await;

    assert!(
        fx.store.list_unreferenced_blobs().await.unwrap().is_empty(),
        "blob is referenced before retention runs"
    );

    let policy = RetentionPolicy {
        rules: vec![RetentionRule::IsPrerelease { prerelease: true }],
    };
    let outcome = fx
        .store
        .apply_retention(&policy, ecosystem, None, &PackageName::new(name))
        .await
        .unwrap();
    assert_eq!(outcome.deleted, vec!["2.0.0-beta.1"]);

    let unreferenced = fx.store.list_unreferenced_blobs().await.unwrap();
    assert_eq!(
        unreferenced,
        vec![digest],
        "the blob only referenced by the deleted version is now a GC candidate"
    );
}
