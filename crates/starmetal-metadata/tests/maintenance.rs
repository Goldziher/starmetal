//! Integration tests for scheduled metadata maintenance (`starmetal_metadata::MetadataMaintenance`,
//! ADR-0020 Stages 2c/2d) against a real Postgres. Marked `#[ignore]` so the default `cargo test`
//! stays offline; run with `cargo test -p starmetal-metadata -- --ignored` (needs Docker).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use starmetal_core::content::{
    Asset, AssetRef, Blob, BlobDigest, Component, ComponentRef, ContentMaintenance, ContentStore, RetentionPolicy,
    RetentionRule,
};
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::ports::StoragePort;
use starmetal_metadata::{MetadataMaintenance, PostgresContentStore, create_pool, generated::queries};
use starmetal_storage::OpenDalStorage;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;

struct Fixture {
    _container: ContainerAsync<Postgres>,
    pool: starmetal_metadata::DbPool,
    store: Arc<PostgresContentStore>,
}

async fn setup() -> Fixture {
    let container = Postgres::default().start().await.expect("start postgres container");
    let port = container.get_host_port_ipv4(5432).await.expect("map postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = create_pool(&url).await.expect("build pool");
    let storage: Arc<dyn StoragePort> = Arc::new(OpenDalStorage::memory().expect("memory storage"));
    let store = Arc::new(PostgresContentStore::new(pool.clone(), storage));
    store.apply_schema().await.expect("apply schema");
    Fixture {
        _container: container,
        pool,
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

/// Register a component + asset and link it to a fresh blob with unique bytes/digest, returning
/// the digest so callers can assert against it.
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
async fn list_component_families_returns_each_distinct_family_once() {
    let fx = setup().await;

    // Three versions of one family, two of another.
    for index in 1..=3 {
        seed_version(
            &fx,
            Ecosystem::PyPI,
            "widget",
            &format!("1.0.{index}"),
            &format!("{:064}", index),
        )
        .await;
    }
    for index in 1..=2 {
        seed_version(
            &fx,
            Ecosystem::Npm,
            "gadget",
            &format!("2.0.{index}"),
            &format!("n{:063}", index),
        )
        .await;
    }

    let conn = fx.pool.get().await.expect("checkout connection");
    let mut families = queries::list_component_families(&*conn)
        .await
        .expect("list families")
        .into_iter()
        .map(|row| (row.ecosystem, row.namespace, row.name))
        .collect::<Vec<_>>();
    families.sort();

    assert_eq!(
        families,
        vec![
            ("npm".to_string(), String::new(), "gadget".to_string()),
            ("pypi".to_string(), String::new(), "widget".to_string()),
        ],
        "each distinct (ecosystem, namespace, name) family appears exactly once, \
         regardless of how many versions it has"
    );
}

#[tokio::test]
#[ignore = "requires docker"]
async fn retention_sweep_deletes_the_union_across_families() {
    let fx = setup().await;

    // Family A: 5 versions of a pypi package; KeepLatest{2} should delete the 3 oldest, keeping
    // the two seeded last (1.0.4, 1.0.5).
    let mut pypi_digests = Vec::new();
    for index in 1..=5 {
        let digest = seed_version(
            &fx,
            Ecosystem::PyPI,
            "widget",
            &format!("1.0.{index}"),
            &format!("{:064}", index),
        )
        .await;
        pypi_digests.push(digest);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let kept_pypi_digests = &pypi_digests[3..];

    // Family B: a stable and a prerelease npm version; IsPrerelease{true} should delete the beta.
    let kept_npm_digest = seed_version(&fx, Ecosystem::Npm, "gadget", "2.0.0", &"g".repeat(64)).await;
    seed_version(&fx, Ecosystem::Npm, "gadget", "2.0.0-beta.1", &"h".repeat(64)).await;

    let policy = RetentionPolicy {
        rules: vec![
            RetentionRule::KeepLatest { count: 2 },
            RetentionRule::IsPrerelease { prerelease: true },
        ],
    };
    let maintenance = MetadataMaintenance::new(fx.store.clone(), Duration::from_secs(3600), policy);

    let outcome = maintenance.retention_sweep().await.expect("retention sweep");
    let mut deleted = outcome.deleted.clone();
    deleted.sort();
    assert_eq!(
        deleted,
        vec!["1.0.1", "1.0.2", "1.0.3", "2.0.0-beta.1"],
        "the sweep deletes the union of every family's rule selection"
    );

    // Versions kept by the policy are untouched, and the blobs they still reference remain intact.
    for digest in kept_pypi_digests {
        assert!(
            fx.store.is_referenced(digest).await.unwrap(),
            "a surviving pypi version still references its blob"
        );
    }
    assert!(
        fx.store.is_referenced(&kept_npm_digest).await.unwrap(),
        "the surviving stable npm version still references its blob"
    );

    // A second sweep over the now-pruned families deletes nothing further.
    let second = maintenance.retention_sweep().await.expect("second retention sweep");
    assert!(second.deleted.is_empty(), "nothing left to select for deletion");
}

#[tokio::test]
#[ignore = "requires docker"]
async fn gc_sweep_after_retention_delete_reclaims_only_the_now_unreferenced_blob() {
    let fx = setup().await;
    let ecosystem = Ecosystem::Cargo;
    let name = "crate-a";

    let kept_digest = seed_version(&fx, ecosystem, name, "1.0.0", &"k".repeat(64)).await;
    let deleted_digest = seed_version(&fx, ecosystem, name, "1.1.0-rc.1", &"d".repeat(64)).await;

    let policy = RetentionPolicy {
        rules: vec![RetentionRule::IsPrerelease { prerelease: true }],
    };
    // Zero grace so the GC sweep both soft-deletes and reclaims in one pass.
    let maintenance = MetadataMaintenance::new(fx.store.clone(), Duration::ZERO, policy);

    let retention_outcome = maintenance.retention_sweep().await.expect("retention sweep");
    assert_eq!(retention_outcome.deleted, vec!["1.1.0-rc.1"]);

    let gc_report = maintenance.gc_sweep().await.expect("gc sweep");
    assert_eq!(gc_report.marked, 1);
    assert_eq!(gc_report.soft_deleted, 1);
    assert_eq!(
        gc_report.reclaimed,
        vec![deleted_digest.clone()],
        "only the blob orphaned by the retention delete is reclaimed"
    );

    assert!(
        fx.store.get_blob(&deleted_digest).await.unwrap().is_none(),
        "the reclaimed blob's metadata is gone"
    );
    assert!(
        fx.store.get_blob(&kept_digest).await.unwrap().is_some(),
        "the still-referenced blob survives GC"
    );
}
