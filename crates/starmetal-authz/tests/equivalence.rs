//! Migration-equivalence tests (ADR-0022 Stage 3A): the `LocalAuthorizer` decisions must match the
//! legacy `Config::authorize_*` predicates they replace, so wiring the authorizer into the
//! enforcement seams preserves the behavior of existing flat/admin/publish tokens.

use starmetal_authz::{LocalAuthorizer, default_namespace};
use starmetal_core::authz::{Action, Authorizer, Coordinate, Resource};
use starmetal_core::config::Config;
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::publishing::{PublishTokenConfig, TokenScope};

/// A config exercising all three legacy token sections with distinct token strings.
fn config() -> Config {
    let mut config = Config::default();
    config.admin.enabled = true;
    config.admin.tokens = vec!["adm".to_string()];
    config.auth.enabled = true;
    config.auth.tokens = vec!["flat".to_string()];
    config.publishing.enabled = true;
    config.publishing.tokens = vec![PublishTokenConfig {
        token: "pub".to_string(),
        scopes: vec![TokenScope::Publish],
        ecosystems: vec![Ecosystem::Npm],
        packages: vec!["left-pad".to_string()],
    }];
    config
}

fn namespace_resource() -> Resource {
    Resource {
        namespace: default_namespace(),
        ecosystem: None,
        repository: None,
        coordinate: None,
    }
}

fn coordinate_resource(ecosystem: Ecosystem, name: &str) -> Resource {
    Resource {
        namespace: default_namespace(),
        ecosystem: Some(ecosystem),
        repository: Some(PackageName::new(name)),
        coordinate: Some(Coordinate {
            ecosystem,
            name: PackageName::new(name),
            version: None,
        }),
    }
}

async fn allows(authorizer: &LocalAuthorizer, token: &str, action: Action, resource: &Resource) -> bool {
    match authorizer.authenticate(token) {
        Some(principal) => authorizer
            .authorize(&principal, action, resource)
            .await
            .expect("decision is computable")
            .is_allowed(),
        None => false,
    }
}

#[tokio::test]
async fn admin_token_authorizes_admin_exactly_where_the_legacy_predicate_did() {
    let config = config();
    let authorizer = LocalAuthorizer::from_config(&config);
    let resource = namespace_resource();

    // The admin token clears the admin gate under both the legacy predicate and the authorizer.
    assert!(config.authorize_admin_token("adm"));
    assert!(allows(&authorizer, "adm", Action::Admin, &resource).await);

    // Flat and publish tokens never had admin-API access, and still do not.
    assert!(!config.authorize_admin_token("flat"));
    assert!(!allows(&authorizer, "flat", Action::Admin, &resource).await);
    assert!(!config.authorize_admin_token("pub"));
    assert!(!allows(&authorizer, "pub", Action::Admin, &resource).await);

    // An unknown token is denied by both.
    assert!(!config.authorize_admin_token("nope"));
    assert!(!allows(&authorizer, "nope", Action::Admin, &resource).await);
}

#[tokio::test]
async fn flat_bearer_token_still_reads_and_browses() {
    let config = config();
    let authorizer = LocalAuthorizer::from_config(&config);
    let resource = namespace_resource();

    // Legacy: the flat token was a valid read/proxy bearer token.
    assert!(config.authorize_bearer_token("flat"));
    assert!(allows(&authorizer, "flat", Action::Read, &resource).await);
    assert!(allows(&authorizer, "flat", Action::Browse, &resource).await);

    // It never granted write or admin authority, and still does not.
    assert!(!allows(&authorizer, "flat", Action::Add, &resource).await);
    assert!(!allows(&authorizer, "flat", Action::Delete, &resource).await);
    assert!(!allows(&authorizer, "flat", Action::Admin, &resource).await);
}

#[tokio::test]
async fn publish_token_authorizes_add_exactly_where_the_legacy_predicate_did() {
    let config = config();
    let authorizer = LocalAuthorizer::from_config(&config);

    let left_pad = PackageName::new("left-pad");
    let other = PackageName::new("other");

    // In scope: publish (Add) of the exact ecosystem+package the token names.
    assert!(config.authorize_publish_token("pub", TokenScope::Publish, Ecosystem::Npm, &left_pad));
    assert!(
        allows(
            &authorizer,
            "pub",
            Action::Add,
            &coordinate_resource(Ecosystem::Npm, "left-pad")
        )
        .await
    );

    // Out of scope: a different package, a different ecosystem, or a non-granted action.
    assert!(!config.authorize_publish_token("pub", TokenScope::Publish, Ecosystem::Npm, &other));
    assert!(
        !allows(
            &authorizer,
            "pub",
            Action::Add,
            &coordinate_resource(Ecosystem::Npm, "other")
        )
        .await
    );
    assert!(!config.authorize_publish_token("pub", TokenScope::Publish, Ecosystem::PyPI, &left_pad));
    assert!(
        !allows(
            &authorizer,
            "pub",
            Action::Add,
            &coordinate_resource(Ecosystem::PyPI, "left-pad")
        )
        .await
    );
    assert!(
        !allows(
            &authorizer,
            "pub",
            Action::Delete,
            &coordinate_resource(Ecosystem::Npm, "left-pad")
        )
        .await
    );
}

#[tokio::test]
async fn disabled_sections_deny_everything() {
    // A default config enables nothing: no token authenticates, mirroring the legacy predicates.
    let config = Config::default();
    let authorizer = LocalAuthorizer::from_config(&config);
    let resource = namespace_resource();

    assert!(!config.authorize_admin_token("adm"));
    assert!(!config.authorize_bearer_token("flat"));
    assert!(authorizer.authenticate("adm").is_none());
    assert!(!allows(&authorizer, "flat", Action::Read, &resource).await);
}
