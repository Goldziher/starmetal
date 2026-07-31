//! Integration tests proving the hosted publish path optionally dual-writes the ADR-0020 content
//! model (component -> asset -> blob) alongside flat storage, with cross-ecosystem blob dedup.
//!
//! The Postgres-backed tests are `#[ignore]` so the default `cargo test` stays offline; run with
//! `cargo test -p starmetal-service --test content_publish -- --ignored` (needs Docker).

use std::sync::Arc;

use ahash::AHashMap;
use bytes::Bytes;
use starmetal_core::content::{BlobDigest, ContentStore};
use starmetal_core::integrity::blake3_hex;
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::policy::PolicyConfig;
use starmetal_core::ports::PublishingService;
use starmetal_core::publishing::{ProtocolMetadata, PublishRequest, PublishedArtifact};
use starmetal_metadata::{PostgresContentStore, create_pool};
use starmetal_service::CachingPackageService;
use starmetal_storage::OpenDalStorage;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;

struct Fixture {
    _container: ContainerAsync<Postgres>,
    service: CachingPackageService,
}

async fn setup() -> Fixture {
    let container = Postgres::default().start().await.expect("start postgres container");
    let port = container.get_host_port_ipv4(5432).await.expect("map postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = create_pool(&url).await.expect("build pool");
    let blob_storage = Arc::new(OpenDalStorage::memory().expect("memory storage for blobs"));
    let content_store = PostgresContentStore::new(pool, blob_storage);
    content_store.apply_schema().await.expect("apply schema");

    let service_storage = Arc::new(OpenDalStorage::memory().expect("memory storage for flat writes"));
    let service = CachingPackageService::new(service_storage, AHashMap::new(), PolicyConfig::default())
        .with_content_store(Arc::new(content_store));

    Fixture {
        _container: container,
        service,
    }
}

fn publish_request(ecosystem: Ecosystem, name: &str, version: &str, filename: &str, data: Bytes) -> PublishRequest {
    PublishRequest {
        ecosystem,
        name: PackageName::new(name),
        version: version.to_string(),
        license: Some("MIT".to_string()),
        yanked: false,
        listed: true,
        artifacts: vec![PublishedArtifact {
            filename: filename.to_string(),
            data,
            upstream_hashes: AHashMap::new(),
        }],
        protocol_metadata: ProtocolMetadata::default_for(ecosystem),
        allow_overwrite: false,
        allow_shadowing: false,
    }
}

#[tokio::test]
#[ignore = "requires docker"]
async fn publish_dedups_identical_bytes_across_ecosystems() {
    let fx = setup().await;
    let payload = Bytes::from_static(b"identical package bytes shared across ecosystems");
    let digest = BlobDigest::new(blake3_hex(&payload));

    fx.service
        .publish_package(publish_request(
            Ecosystem::PyPI,
            "pkg",
            "1.0.0",
            "pkg-1.0.0.tar.gz",
            payload.clone(),
        ))
        .await
        .expect("pypi publish succeeds");

    fx.service
        .publish_package(publish_request(
            Ecosystem::Npm,
            "pkg",
            "1.0.0",
            "pkg-1.0.0.tgz",
            payload.clone(),
        ))
        .await
        .expect("npm publish succeeds");

    // Reach through the content store to assert the shared blob and reference state. The service
    // does not expose the content store, so we build a second handle against the same Postgres
    // schema to query it directly.
    let content_store = fx.content_store().await;

    let blob = content_store.get_blob(&digest).await.expect("get_blob succeeds");
    assert!(blob.is_some(), "the blob referenced by both publishes exists");
    assert_eq!(
        blob.unwrap().digest,
        digest,
        "the stored blob matches the expected digest"
    );

    assert!(
        content_store
            .is_referenced(&digest)
            .await
            .expect("is_referenced succeeds"),
        "the blob is referenced after both publishes"
    );

    let unreferenced = content_store
        .list_unreferenced_blobs()
        .await
        .expect("list_unreferenced_blobs succeeds");
    assert!(
        !unreferenced.contains(&digest),
        "a blob shared by two ecosystems is not a GC candidate"
    );
}

#[tokio::test]
#[ignore = "requires docker"]
async fn publish_records_a_reference_for_the_artifact_blob() {
    let fx = setup().await;
    let payload = Bytes::from_static(b"solo package bytes for reference recording");
    let digest = BlobDigest::new(blake3_hex(&payload));

    fx.service
        .publish_package(publish_request(
            Ecosystem::Cargo,
            "solo",
            "2.0.0",
            "solo-2.0.0.crate",
            payload,
        ))
        .await
        .expect("publish succeeds");

    let content_store = fx.content_store().await;
    let unreferenced = content_store
        .list_unreferenced_blobs()
        .await
        .expect("list_unreferenced_blobs succeeds");
    assert!(
        !unreferenced.contains(&digest),
        "the newly published artifact's blob is referenced, not a GC candidate"
    );
}

#[tokio::test]
async fn publish_without_a_content_store_still_succeeds() {
    let storage = Arc::new(OpenDalStorage::memory().expect("memory storage"));
    let service = CachingPackageService::new(storage, AHashMap::new(), PolicyConfig::default());
    let payload = Bytes::from_static(b"no content store attached");

    let result = service
        .publish_package(publish_request(
            Ecosystem::PyPI,
            "none-store",
            "1.0.0",
            "none-store-1.0.0.tar.gz",
            payload,
        ))
        .await
        .expect("publish succeeds without a content store");

    assert_eq!(result.version, "1.0.0");
}

impl Fixture {
    /// Build a second `PostgresContentStore` handle against the same Postgres container to assert
    /// content-model state independently of the service under test.
    async fn content_store(&self) -> PostgresContentStore {
        let port = self
            ._container
            .get_host_port_ipv4(5432)
            .await
            .expect("map postgres port");
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = create_pool(&url).await.expect("build pool");
        let storage = Arc::new(OpenDalStorage::memory().expect("memory storage"));
        PostgresContentStore::new(pool, storage)
    }
}
