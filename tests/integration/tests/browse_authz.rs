//! End-to-end proof that the ADR-0022 content-browse route (`GET /api/v1/components`) enforces the
//! authorizer's *pushed-down* predicate over real HTTP: an unscoped token lists every component,
//! while a token scoped to one ecosystem+package lists only the components its grant permits.
//!
//! The listing is served by an in-memory [`ContentBrowseFake`] seeded with a fixed component set and
//! filtered through the real `QueryPredicate` an [`Authorizer`] decision carries — so the filter is
//! the production authorization filter, not a test re-implementation. (The Postgres-backed store and
//! its own coverage land in milestone M5; this exercises the HTTP authorization path today.)

use std::sync::Arc;

use serde_json::Value;
use starmetal_core::content::Component;
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::publishing::{PublishTokenConfig, TokenScope};
use starmetal_integration_tests::{ContentBrowseFake, TestServer};

/// Three components across two ecosystems: `npm/left-pad`, `npm/right-pad`, `pypi/flask`.
fn seed_components() -> Vec<Component> {
    let component = |ecosystem: Ecosystem, name: &str| Component {
        namespace: None,
        name: PackageName::new(name),
        version: "1.0.0".to_string(),
        ecosystem,
        repository: String::new(),
        attributes: Value::Null,
    };
    vec![
        component(Ecosystem::Npm, "left-pad"),
        component(Ecosystem::Npm, "right-pad"),
        component(Ecosystem::PyPI, "flask"),
    ]
}

/// Collect the `name` field of every component in a `GET /api/v1/components` JSON array.
fn component_names(body: &Value) -> Vec<String> {
    body.as_array()
        .expect("components array")
        .iter()
        .filter_map(|component| component["name"].as_str().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn should_list_every_component_for_an_unscoped_read_token() {
    let server = TestServer::builder()
        .configure(|config| {
            config.auth.enabled = true;
            config.auth.tokens.push("read-token".to_string());
        })
        .with_content_browse(Arc::new(ContentBrowseFake::new(seed_components())))
        .start()
        .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/api/v1/components", server.base_url()))
        .bearer_auth("read-token")
        .send()
        .await
        .expect("browse request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "flat read token clears both gates"
    );

    let body: Value = response.json().await.expect("components json");
    let mut names = component_names(&body);
    names.sort();
    assert_eq!(
        names,
        vec!["flask".to_string(), "left-pad".to_string(), "right-pad".to_string()],
        "an unscoped RepositoryView grant carries QueryPredicate::Always and lists everything"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_filter_components_to_a_scoped_tokens_grant() {
    // A token scoped to exactly npm + left-pad. Its content grant confers Read/Browse only on that
    // coordinate, so the authorizer pushes down a predicate that admits only `npm/left-pad`.
    let server = TestServer::builder()
        .configure(|config| {
            config.auth.enabled = true;
            config.publishing.enabled = true;
            config.publishing.tokens.push(PublishTokenConfig {
                token: "scoped-token".to_string(),
                scopes: vec![TokenScope::Read],
                ecosystems: vec![Ecosystem::Npm],
                packages: vec!["left-pad".to_string()],
            });
        })
        .with_content_browse(Arc::new(ContentBrowseFake::new(seed_components())))
        .start()
        .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/api/v1/components", server.base_url()))
        .bearer_auth("scoped-token")
        .send()
        .await
        .expect("browse request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "scoped token clears the read gate"
    );

    let body: Value = response.json().await.expect("components json");
    let names = component_names(&body);
    assert_eq!(
        names,
        vec!["left-pad".to_string()],
        "the scoped grant's pushed-down predicate must exclude npm/right-pad and pypi/flask"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_reject_browse_without_a_token() {
    let server = TestServer::builder()
        .configure(|config| {
            config.auth.enabled = true;
            config.auth.tokens.push("read-token".to_string());
        })
        .with_content_browse(Arc::new(ContentBrowseFake::new(seed_components())))
        .start()
        .await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/api/v1/components", server.base_url()))
        .send()
        .await
        .expect("browse request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the global read gate refuses an unauthenticated browse"
    );

    server.shutdown();
}
