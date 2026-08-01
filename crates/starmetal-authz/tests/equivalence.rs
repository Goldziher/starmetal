//! Config-migration behavior tests (ADR-0022 Stage 3A + N1): the `LocalAuthorizer` built by
//! `from_config` must grant exactly the access the legacy flat/admin/publish token sections did.
//! These originally cross-checked the `Config::authorize_*` predicates; those predicates were
//! removed once the read, publish, and admin paths all migrated onto the `Authorizer` port, so the
//! authorizer's decisions are now the sole specification and these tests lock them.

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
async fn admin_token_authorizes_only_the_admin_principal() {
    let authorizer = LocalAuthorizer::from_config(&config());
    let resource = namespace_resource();

    // The admin token clears the admin gate; flat and publish tokens never had admin-API access.
    assert!(allows(&authorizer, "adm", Action::Admin, &resource).await);
    assert!(!allows(&authorizer, "flat", Action::Admin, &resource).await);
    assert!(!allows(&authorizer, "pub", Action::Admin, &resource).await);

    // An unknown token authenticates to no principal and is denied.
    assert!(!allows(&authorizer, "nope", Action::Admin, &resource).await);
}

#[tokio::test]
async fn flat_bearer_token_reads_and_browses_but_never_writes() {
    let authorizer = LocalAuthorizer::from_config(&config());
    let resource = namespace_resource();

    // The read middleware (N1) requires the read action on the namespace resource; the flat token
    // must clear both read and browse, exactly as the legacy bearer gate allowed.
    assert!(allows(&authorizer, "flat", Action::Read, &resource).await);
    assert!(allows(&authorizer, "flat", Action::Browse, &resource).await);

    // It never granted write or admin authority, and still does not.
    assert!(!allows(&authorizer, "flat", Action::Add, &resource).await);
    assert!(!allows(&authorizer, "flat", Action::Delete, &resource).await);
    assert!(!allows(&authorizer, "flat", Action::Admin, &resource).await);
}

#[tokio::test]
async fn admin_token_also_clears_the_read_gate() {
    // The legacy read gate was `bearer || admin`; the admin principal must therefore still read.
    let authorizer = LocalAuthorizer::from_config(&config());
    assert!(allows(&authorizer, "adm", Action::Read, &namespace_resource()).await);

    // A publish-only token was in neither the bearer nor admin section, so it is denied read.
    assert!(!allows(&authorizer, "pub", Action::Read, &namespace_resource()).await);
}

#[tokio::test]
async fn publish_token_authorizes_add_only_within_scope() {
    let authorizer = LocalAuthorizer::from_config(&config());

    // In scope: publish (Add) of the exact ecosystem+package the token names.
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
    assert!(
        !allows(
            &authorizer,
            "pub",
            Action::Add,
            &coordinate_resource(Ecosystem::Npm, "other")
        )
        .await
    );
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
async fn a_default_config_denies_everything() {
    // A default config enables no token section: nothing authenticates, so every gate denies.
    let authorizer = LocalAuthorizer::from_config(&Config::default());
    assert!(authorizer.authenticate("adm").is_none());
    assert!(!allows(&authorizer, "flat", Action::Read, &namespace_resource()).await);
}
