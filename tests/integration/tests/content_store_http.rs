//! End-to-end coverage of the ADR-0020 content store over real HTTP, against a real Postgres
//! (testcontainers). The metadata crate's own suite tests the store directly; this proves the
//! *server* path: a publish dual-writes the content model, the browse route lists it, and the admin
//! GC/retention routes reach a real maintenance handle instead of reporting the workflow disabled.
//!
//! Behind the `metadata` feature and `#[ignore]`d (needs Docker), like the metadata crate's tests.
//! Run with `cargo test -p starmetal-integration-tests --features metadata -- --ignored`.
#![cfg(feature = "metadata")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::Value;
use starmetal_core::content::{ContentBrowse, ContentMaintenance, ContentStore, RetentionPolicy};
use starmetal_core::ports::StoragePort;
use starmetal_integration_tests::{TestServer, enable_publishing, publish_pypi_legacy};
use starmetal_metadata::{MetadataMaintenance, PostgresContentStore, create_pool};
use starmetal_storage::OpenDalStorage;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;

const PUBLISH_TOKEN: &str = "content-store-publish-token";
const ADMIN_TOKEN: &str = "admin-token";

/// A running Postgres content store, kept together with its container so both outlive the server.
struct StoreFixture {
    _container: ContainerAsync<Postgres>,
    store: Arc<PostgresContentStore>,
}

/// Start a Postgres testcontainer, build a schema-applied [`PostgresContentStore`] over in-memory
/// blob storage, mirroring the metadata crate's own test setup.
async fn start_store() -> StoreFixture {
    let container = Postgres::default().start().await.expect("start postgres container");
    let port = container.get_host_port_ipv4(5432).await.expect("map postgres port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = create_pool(&url).await.expect("build pool");
    let storage: Arc<dyn StoragePort> = Arc::new(OpenDalStorage::memory().expect("memory storage"));
    let store = Arc::new(PostgresContentStore::new(pool, storage));
    store.apply_schema().await.expect("apply schema");
    StoreFixture {
        _container: container,
        store,
    }
}

/// Derive the three content handles the harness seam wants from one store: the store the publishing
/// service dual-writes into, its browse view, and a maintenance wrapper (empty retention, zero grace).
fn handles(
    store: &Arc<PostgresContentStore>,
) -> (
    Arc<dyn ContentStore>,
    Arc<dyn ContentBrowse>,
    Arc<dyn ContentMaintenance>,
) {
    let maintenance = Arc::new(MetadataMaintenance::new(
        store.clone(),
        Duration::from_secs(0),
        RetentionPolicy::default(),
        HashMap::new(),
        HashMap::new(),
    ));
    (
        store.clone() as Arc<dyn ContentStore>,
        store.clone() as Arc<dyn ContentBrowse>,
        maintenance as Arc<dyn ContentMaintenance>,
    )
}

#[tokio::test]
#[ignore = "requires Docker (Postgres testcontainer)"]
async fn published_artifact_is_dual_written_and_listed_by_the_content_browse() {
    let fixture = start_store().await;
    let (store, browse, maintenance) = handles(&fixture.store);
    let server = TestServer::builder()
        .configure(|config| enable_publishing(config, PUBLISH_TOKEN))
        .with_content_store(store, browse, maintenance)
        .start()
        .await;
    let client = reqwest::Client::new();
    let base = server.base_url();

    let publish = publish_pypi_legacy(
        &client,
        &base,
        PUBLISH_TOKEN,
        "widget",
        "1.0.0",
        "widget-1.0.0.tar.gz",
        b"widget-payload",
    )
    .await;
    assert_eq!(
        publish.status(),
        StatusCode::OK,
        "publish should succeed and dual-write the content model"
    );

    // Auth is disabled, so browse is open (QueryPredicate::Always) and lists everything in the store.
    let response = client
        .get(format!("{base}/api/v1/components"))
        .send()
        .await
        .expect("browse request");
    assert_eq!(response.status(), StatusCode::OK);
    let components: Value = response.json().await.expect("components json");
    let names: Vec<&str> = components
        .as_array()
        .expect("components array")
        .iter()
        .filter_map(|component| component["name"].as_str())
        .collect();
    assert!(
        names.contains(&"widget"),
        "the published component must appear in the real store's browse listing, got: {names:?}"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker (Postgres testcontainer)"]
async fn admin_gc_and_retention_reach_the_real_maintenance_handle() {
    let fixture = start_store().await;
    let (store, browse, maintenance) = handles(&fixture.store);
    let server = TestServer::builder()
        .configure(|config| {
            config.admin.enabled = true;
            config.admin.tokens.push(ADMIN_TOKEN.to_string());
        })
        .with_content_store(store, browse, maintenance)
        .start()
        .await;
    let client = reqwest::Client::new();
    let base = server.base_url();

    // Without a store these report the workflow disabled (404, covered in admin.rs); with a real store
    // attached they run a sweep and return its report (200).
    for endpoint in ["gc", "retention"] {
        let response = client
            .post(format!("{base}/admin/api/v1/{endpoint}"))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .expect("sweep request");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{endpoint} must reach the real maintenance handle rather than report disabled"
        );
        let report: Value = response.json().await.expect("sweep report json");
        assert!(
            report.is_object(),
            "{endpoint} returns a sweep report object, got: {report}"
        );
    }

    server.shutdown();
}
