//! Integration tests for content browse with pushed-down predicates
//! (`PostgresContentStore as ContentBrowse`, ADR-0022) against a real Postgres. Marked `#[ignore]`
//! so the default `cargo test` stays offline; run with
//! `cargo test -p starmetal-metadata -- --ignored` (needs Docker).

use std::sync::Arc;

use starmetal_core::authz::{NamePattern, QueryPredicate};
use starmetal_core::content::{BrowsePage, Component, ContentBrowse, ContentStore};
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

async fn insert(store: &PostgresContentStore, ecosystem: Ecosystem, name: &str, version: &str) {
    store
        .upsert_component(&Component {
            namespace: None,
            name: PackageName::new(name),
            version: version.to_string(),
            ecosystem,
            attributes: serde_json::json!({}),
        })
        .await
        .expect("upsert component");
}

/// The `(ecosystem, name)` pairs of a browse result, for order-independent assertions.
fn coordinates(components: &[Component]) -> Vec<(Ecosystem, String)> {
    components
        .iter()
        .map(|component| (component.ecosystem, component.name.as_str().to_string()))
        .collect()
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn browse_always_lists_every_component() {
    let fx = setup().await;
    insert(&fx.store, Ecosystem::Npm, "left-pad", "1.0.0").await;
    insert(&fx.store, Ecosystem::Npm, "right-pad", "1.0.0").await;
    insert(&fx.store, Ecosystem::PyPI, "requests", "2.31.0").await;

    let all = fx
        .store
        .browse_components(&QueryPredicate::Always, BrowsePage::default())
        .await
        .expect("browse");
    assert_eq!(all.len(), 3, "Always lists every component");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn browse_never_lists_nothing() {
    let fx = setup().await;
    insert(&fx.store, Ecosystem::Npm, "left-pad", "1.0.0").await;

    let none = fx
        .store
        .browse_components(&QueryPredicate::Never, BrowsePage::default())
        .await
        .expect("browse");
    assert!(none.is_empty(), "Never lists nothing");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn browse_ecosystem_predicate_filters_in_query() {
    let fx = setup().await;
    insert(&fx.store, Ecosystem::Npm, "left-pad", "1.0.0").await;
    insert(&fx.store, Ecosystem::Npm, "right-pad", "1.0.0").await;
    insert(&fx.store, Ecosystem::PyPI, "requests", "2.31.0").await;

    let npm = fx
        .store
        .browse_components(&QueryPredicate::Ecosystem(Ecosystem::Npm), BrowsePage::default())
        .await
        .expect("browse");
    assert_eq!(
        coordinates(&npm),
        vec![
            (Ecosystem::Npm, "left-pad".to_string()),
            (Ecosystem::Npm, "right-pad".to_string()),
        ],
        "only npm components, ordered by name"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn browse_scoped_predicate_returns_only_the_matching_component() {
    let fx = setup().await;
    insert(&fx.store, Ecosystem::Npm, "left-pad", "1.0.0").await;
    insert(&fx.store, Ecosystem::Npm, "right-pad", "1.0.0").await;
    insert(&fx.store, Ecosystem::PyPI, "left-pad", "9.9.9").await;

    // The predicate an authorizer produces for a publish token scoped to npm/left-pad.
    let predicate = QueryPredicate::All(vec![
        QueryPredicate::Ecosystem(Ecosystem::Npm),
        QueryPredicate::CoordinateName(NamePattern::Exact("left-pad".to_string())),
    ]);
    let scoped = fx
        .store
        .browse_components(&predicate, BrowsePage::default())
        .await
        .expect("browse");
    assert_eq!(
        coordinates(&scoped),
        vec![(Ecosystem::Npm, "left-pad".to_string())],
        "the scoped predicate matches exactly its one repository"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn browse_name_prefix_treats_underscore_literally() {
    let fx = setup().await;
    insert(&fx.store, Ecosystem::Cargo, "a_b", "1.0.0").await;
    insert(&fx.store, Ecosystem::Cargo, "axb", "1.0.0").await;

    // `a_` must match the literal underscore, not the SQL LIKE single-char wildcard, so `axb` is
    // excluded — proving the compiler escapes LIKE metacharacters.
    let predicate = QueryPredicate::CoordinateName(NamePattern::Prefix("a_".to_string()));
    let matched = fx
        .store
        .browse_components(&predicate, BrowsePage::default())
        .await
        .expect("browse");
    assert_eq!(
        coordinates(&matched),
        vec![(Ecosystem::Cargo, "a_b".to_string())],
        "the underscore is escaped, so only a_b matches"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers Postgres)"]
async fn browse_paginates_with_limit_and_offset() {
    let fx = setup().await;
    for index in 0..5 {
        insert(&fx.store, Ecosystem::Npm, &format!("pkg-{index}"), "1.0.0").await;
    }

    let page = fx
        .store
        .browse_components(&QueryPredicate::Always, BrowsePage::new(2, 1))
        .await
        .expect("browse");
    assert_eq!(
        coordinates(&page),
        vec![
            (Ecosystem::Npm, "pkg-1".to_string()),
            (Ecosystem::Npm, "pkg-2".to_string()),
        ],
        "limit 2 offset 1 returns the second and third components by name"
    );
}
