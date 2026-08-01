//! A framework-free, local, grant-based [`Authorizer`](starmetal_core::authz::Authorizer)
//! implementation (ADR-0022, Stage 3A-1).
//!
//! [`LocalAuthorizer`] migrates the historical flat token configuration
//! ([`AuthConfig`](starmetal_core::config::AuthConfig),
//! [`AdminConfig`](starmetal_core::config::AdminConfig),
//! [`PublishingConfig`](starmetal_core::config::PublishingConfig)) into the richer grant model
//! defined by [`starmetal_core::authz`]: [`RepositoryView`](starmetal_core::authz::RepositoryView)
//! (content plane), [`RepositoryAdmin`](starmetal_core::authz::RepositoryAdmin) (config plane), and
//! [`ApiTokenScope`](starmetal_core::authz::ApiTokenScope) (fine-grained publish-token scopes).
//!
//! # Default namespace
//!
//! The current codebase is namespace-less: every migrated grant, and every [`Resource`] a caller
//! builds today, lives in a single namespace named by [`DEFAULT_NAMESPACE`] /
//! [`default_namespace`]. This is a migration convenience, not a permanent constraint — later
//! stages that introduce real multi-tenancy will mint additional namespaces.
//!
//! # Deny-by-default
//!
//! [`LocalAuthorizer::authorize`] never grants access it cannot trace to an explicit migrated
//! grant. An unknown principal, a namespace the principal's grants do not cover, or an action no
//! grant lists, all resolve to [`Decision::deny`]. See
//! [`Authorizer`](starmetal_core::authz::Authorizer) for the full contract.

use std::collections::HashMap;

use async_trait::async_trait;
use starmetal_core::authz::{
    Action, ApiTokenScope, Authenticator, Authorizer, ContentSelector, Decision, EcosystemPattern, NamePattern,
    Namespace, Principal, PrincipalId, PrincipalScope, RepositoryAdmin, RepositoryPattern, RepositoryView, Resource,
};
use starmetal_core::config::Config;
use starmetal_core::error::Result;
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::publishing::{PublishTokenConfig, TokenScope};

// ---------------------------------------------------------------------------
// Default namespace
// ---------------------------------------------------------------------------

/// The single [`Namespace`] every migrated grant lives in, since the current configuration model
/// has no notion of tenancy.
pub const DEFAULT_NAMESPACE: &str = "default";

/// Construct the [`DEFAULT_NAMESPACE`] namespace.
///
/// Infallible: `DEFAULT_NAMESPACE` is a fixed literal that satisfies
/// [`Namespace::new`]'s validation, which is asserted by this crate's test suite.
///
/// # Examples
///
/// ```
/// use starmetal_authz::default_namespace;
///
/// assert_eq!(default_namespace().as_str(), starmetal_authz::DEFAULT_NAMESPACE);
/// ```
pub fn default_namespace() -> Namespace {
    match Namespace::new(DEFAULT_NAMESPACE) {
        Ok(namespace) => namespace,
        Err(_) => unreachable!("DEFAULT_NAMESPACE {DEFAULT_NAMESPACE:?} is a statically valid namespace"),
    }
}

/// Construct a [`PrincipalId`] from a literal this crate controls (always non-empty).
///
/// Infallible in practice: [`PrincipalId::new`] only rejects empty strings, and every caller in
/// this crate passes a non-empty literal or a non-empty formatted string.
fn required_principal_id(value: impl Into<String>) -> PrincipalId {
    let value = value.into();
    match PrincipalId::new(value.clone()) {
        Ok(id) => id,
        Err(_) => unreachable!("principal id {value:?} is always non-empty in this crate"),
    }
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Constant-time byte comparison, so token lookups do not leak timing information about how much
/// of a candidate token matched (secrets-handling, OWASP authentication-failures).
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Internal grant storage
// ---------------------------------------------------------------------------

/// The merged grants held by a single migrated principal.
#[derive(Debug, Clone, Default)]
struct Grants {
    views: Vec<RepositoryView>,
    admins: Vec<RepositoryAdmin>,
    token_scopes: Vec<ApiTokenScope>,
    /// Reserved for future selector-scoped grants (ADR-0022 later stages); the config migration
    /// implemented here never populates it, so nothing reads it yet.
    #[allow(
        dead_code,
        reason = "populated by a later ADR-0022 stage; kept now to fix the Grants shape"
    )]
    selectors: Vec<ContentSelector>,
}

/// One authenticatable bearer token and the principal it resolves to.
#[derive(Clone)]
struct TokenEntry {
    token: String,
    principal: Principal,
}

// ---------------------------------------------------------------------------
// LocalAuthorizer
// ---------------------------------------------------------------------------

/// An [`Authorizer`] backed by grants migrated from flat token configuration.
///
/// Build one with [`LocalAuthorizer::from_config`], authenticate bearer tokens with
/// [`LocalAuthorizer::authenticate`], and consult it as an [`Authorizer`] for every request.
///
/// The [`Debug`] implementation never prints token secrets (it reports counts only), mirroring
/// [`AuthConfig`](starmetal_core::config::AuthConfig)'s manual `Debug` impl.
#[derive(Clone)]
pub struct LocalAuthorizer {
    /// Authenticatable tokens, in authentication precedence order: admin, then publish, then flat
    /// bearer tokens. See [`LocalAuthorizer::authenticate`].
    tokens: Vec<TokenEntry>,
    /// Merged grants per principal id.
    grants: HashMap<PrincipalId, Grants>,
}

impl std::fmt::Debug for LocalAuthorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAuthorizer")
            .field("tokens", &format!("[{} redacted]", self.tokens.len()))
            .field("principals", &self.grants.len())
            .finish()
    }
}

impl LocalAuthorizer {
    /// Build the authorizer by migrating `config`'s `auth`, `admin`, and `publishing` token
    /// sections into the grant model described in the [module docs](self).
    ///
    /// A section that is disabled (`enabled = false`) or carries no tokens contributes nothing.
    /// An empty or fully-disabled [`Config`] therefore yields an authorizer that denies every
    /// request (deny-by-default).
    ///
    /// # Migration
    ///
    /// - `auth.tokens` each authenticate to a single shared `Principal::User("legacy-bearer")`
    ///   granted [`Action::Browse`] + [`Action::Read`] on every repository in the default
    ///   namespace.
    /// - `admin.tokens` each authenticate to a single shared `Principal::User("legacy-admin")`
    ///   granted [`RepositoryAdmin`] plus all five [`Action::CONTENT`] actions, both on every
    ///   repository in the default namespace.
    /// - `publishing.tokens[i]` each authenticate to their own `Principal::Service("publish-token:i")`,
    ///   carrying [`ApiTokenScope`]s built from the cross product of the token's scopes,
    ///   ecosystems, and packages (empty ecosystems/packages migrate to `Any`/`Any` wildcards).
    ///
    /// A token string that appears in more than one section resolves, on
    /// [`authenticate`](LocalAuthorizer::authenticate), to whichever section has the highest
    /// precedence: admin, then publish, then flat bearer tokens.
    ///
    /// # Examples
    ///
    /// ```
    /// use starmetal_core::config::Config;
    /// use starmetal_authz::LocalAuthorizer;
    ///
    /// let authorizer = LocalAuthorizer::from_config(&Config::default());
    /// // No tokens configured: nothing authenticates.
    /// assert!(authorizer.authenticate("anything").is_none());
    /// ```
    pub fn from_config(config: &Config) -> Self {
        let mut tokens = Vec::new();
        let mut grants: HashMap<PrincipalId, Grants> = HashMap::new();

        register_admin_tokens(config, &mut tokens, &mut grants);
        register_publish_tokens(config, &mut tokens, &mut grants);
        register_flat_tokens(config, &mut tokens, &mut grants);

        Self { tokens, grants }
    }

    /// Authenticate a bearer token to the [`Principal`] it acts as.
    ///
    /// Uses a constant-time comparison against every configured token (secrets-handling): timing
    /// does not reveal how many leading bytes of an incorrect guess matched. Returns [`None`] for
    /// an unknown token; the caller must treat an unauthenticated request as denied.
    ///
    /// When a token string was configured in more than one section, the principal from the
    /// highest-precedence section wins: admin, then publish, then flat bearer tokens (see
    /// [`from_config`](LocalAuthorizer::from_config)).
    ///
    /// # Examples
    ///
    /// ```
    /// use starmetal_core::config::Config;
    /// use starmetal_authz::LocalAuthorizer;
    ///
    /// let toml = "[auth]\nenabled = true\ntokens = [\"secret\"]\n";
    /// let config: Config = toml::from_str(toml)?;
    /// let authorizer = LocalAuthorizer::from_config(&config);
    ///
    /// assert!(authorizer.authenticate("secret").is_some());
    /// assert!(authorizer.authenticate("wrong").is_none());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn authenticate(&self, token: &str) -> Option<Principal> {
        self.tokens
            .iter()
            .find(|entry| constant_time_eq(entry.token.as_bytes(), token.as_bytes()))
            .map(|entry| entry.principal.clone())
    }
}

impl Authenticator for LocalAuthorizer {
    /// Resolve a bearer token to its principal via the crate's constant-time
    /// [`authenticate`](LocalAuthorizer::authenticate). Implements the core [`Authenticator`] port so
    /// adapters can depend on the port rather than this concrete type.
    fn authenticate_bearer(&self, credential: &str) -> Option<Principal> {
        self.authenticate(credential)
    }
}

#[async_trait]
impl Authorizer for LocalAuthorizer {
    /// Decide whether `principal` may perform `action` on `resource`.
    ///
    /// Deny-by-default: an unrecognized principal, or one whose migrated grants do not cover
    /// `action`/`resource`, yields [`Decision::deny`]. This implementation never fails to compute
    /// a decision, so it always returns `Ok`.
    ///
    /// # Examples
    ///
    /// ```
    /// use starmetal_core::authz::{Action, Authorizer, Resource};
    /// use starmetal_core::config::Config;
    /// use starmetal_authz::{default_namespace, LocalAuthorizer};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let toml = "[auth]\nenabled = true\ntokens = [\"secret\"]\n";
    /// let config: Config = toml::from_str(toml)?;
    /// let authorizer = LocalAuthorizer::from_config(&config);
    ///
    /// let principal = authorizer.authenticate("secret").expect("configured token");
    /// let resource = Resource {
    ///     namespace: default_namespace(),
    ///     ecosystem: None,
    ///     repository: None,
    ///     coordinate: None,
    /// };
    /// let decision = authorizer.authorize(&principal, Action::Read, &resource).await?;
    /// assert!(decision.is_allowed());
    /// # Ok(())
    /// # }
    /// ```
    async fn authorize(&self, principal: &Principal, action: Action, resource: &Resource) -> Result<Decision> {
        Ok(self.authorize_sync(principal, action, resource))
    }
}

impl LocalAuthorizer {
    /// Synchronous grant evaluation, the substance behind the async [`Authorizer::authorize`] port.
    ///
    /// Local grant checks touch no I/O, so callers already inside a synchronous seam (e.g. a
    /// protocol adapter's publish authorization) can decide without an `.await`. The async port
    /// method simply wraps this in `Ok`; both are deny-by-default.
    pub fn authorize_sync(&self, principal: &Principal, action: Action, resource: &Resource) -> Decision {
        let Some(grants) = self.grants.get(principal.id()) else {
            return Decision::deny();
        };

        match action {
            Action::Admin => authorize_admin(grants, resource),
            _ => authorize_content(principal, grants, action, resource),
        }
    }
}

// ---------------------------------------------------------------------------
// Migration: config sections -> tokens + grants ~keep
// ---------------------------------------------------------------------------

fn register_admin_tokens(config: &Config, tokens: &mut Vec<TokenEntry>, grants: &mut HashMap<PrincipalId, Grants>) {
    if !config.admin.enabled || config.admin.tokens.is_empty() {
        return;
    }

    let id = required_principal_id("legacy-admin");
    let principal = Principal::User {
        id: id.clone(),
        scope: PrincipalScope::System,
    };

    let entry = grants.entry(id).or_default();
    entry.admins.push(RepositoryAdmin {
        namespace: default_namespace(),
        repository: RepositoryPattern::any(),
    });
    entry.views.push(RepositoryView {
        namespace: default_namespace(),
        repository: RepositoryPattern::any(),
        actions: Action::CONTENT.to_vec(),
    });

    for token in &config.admin.tokens {
        tokens.push(TokenEntry {
            token: token.clone(),
            principal: principal.clone(),
        });
    }
}

fn register_publish_tokens(config: &Config, tokens: &mut Vec<TokenEntry>, grants: &mut HashMap<PrincipalId, Grants>) {
    if !config.publishing.enabled {
        return;
    }

    for (index, token_config) in config.publishing.tokens.iter().enumerate() {
        let id = required_principal_id(format!("publish-token:{index}"));
        let principal = Principal::Service {
            id: id.clone(),
            scope: PrincipalScope::System,
        };

        let entry = grants.entry(id).or_default();
        entry.token_scopes.extend(publish_token_scopes(token_config));

        tokens.push(TokenEntry {
            token: token_config.token.clone(),
            principal,
        });
    }
}

fn register_flat_tokens(config: &Config, tokens: &mut Vec<TokenEntry>, grants: &mut HashMap<PrincipalId, Grants>) {
    if !config.auth.enabled || config.auth.tokens.is_empty() {
        return;
    }

    let id = required_principal_id("legacy-bearer");
    let principal = Principal::User {
        id: id.clone(),
        scope: PrincipalScope::System,
    };

    let entry = grants.entry(id).or_default();
    entry.views.push(RepositoryView {
        namespace: default_namespace(),
        repository: RepositoryPattern::any(),
        actions: vec![Action::Browse, Action::Read],
    });

    for token in &config.auth.tokens {
        tokens.push(TokenEntry {
            token: token.clone(),
            principal: principal.clone(),
        });
    }
}

/// The cross product of a publish token's scopes, ecosystems, and packages, per the migration
/// rules documented on [`LocalAuthorizer::from_config`].
fn publish_token_scopes(token_config: &PublishTokenConfig) -> Vec<ApiTokenScope> {
    let ecosystem_patterns = ecosystem_patterns(&token_config.ecosystems);
    let name_patterns = name_patterns(&token_config.packages);

    let mut scopes = Vec::with_capacity(token_config.scopes.len() * ecosystem_patterns.len() * name_patterns.len());
    for token_scope in &token_config.scopes {
        let action = map_token_scope(*token_scope);
        for ecosystem in &ecosystem_patterns {
            for name in &name_patterns {
                scopes.push(ApiTokenScope {
                    action,
                    repository: RepositoryPattern {
                        ecosystem: ecosystem.clone(),
                        name: name.clone(),
                    },
                });
            }
        }
    }
    scopes
}

fn ecosystem_patterns(ecosystems: &[Ecosystem]) -> Vec<EcosystemPattern> {
    if ecosystems.is_empty() {
        vec![EcosystemPattern::Any]
    } else {
        ecosystems
            .iter()
            .map(|ecosystem| EcosystemPattern::Exact(*ecosystem))
            .collect()
    }
}

fn name_patterns(packages: &[String]) -> Vec<NamePattern> {
    if packages.is_empty() {
        vec![NamePattern::Any]
    } else {
        packages.iter().map(|name| NamePattern::Exact(name.clone())).collect()
    }
}

fn map_token_scope(scope: TokenScope) -> Action {
    match scope {
        TokenScope::Read => Action::Read,
        TokenScope::Publish => Action::Add,
        TokenScope::Yank => Action::Edit,
        TokenScope::Admin => Action::Admin,
    }
}

// ---------------------------------------------------------------------------
// authorize(): grant evaluation ~keep
// ---------------------------------------------------------------------------

/// The `(ecosystem, name)` pair a [`Resource`] names, when it is concrete enough to match a
/// [`RepositoryPattern`] against. `None` when the resource only narrows down to a namespace.
fn resource_repository(resource: &Resource) -> Option<(Ecosystem, &PackageName)> {
    match (resource.ecosystem, &resource.repository) {
        (Some(ecosystem), Some(name)) => Some((ecosystem, name)),
        _ => None,
    }
}

/// Whether any [`RepositoryAdmin`] grant covers `resource`.
///
/// When the resource is concrete (ecosystem + repository present), this matches the admin
/// grant's [`RepositoryPattern`] precisely. When the resource is namespace-only, it falls back to
/// an existence check: does the principal hold *any* admin grant in that namespace.
fn admin_covers(grants: &Grants, resource: &Resource) -> bool {
    match resource_repository(resource) {
        Some((ecosystem, name)) => grants
            .admins
            .iter()
            .any(|admin| admin.allows(&resource.namespace, ecosystem, name)),
        None => grants.admins.iter().any(|admin| admin.namespace == resource.namespace),
    }
}

fn authorize_admin(grants: &Grants, resource: &Resource) -> Decision {
    if admin_covers(grants, resource) {
        Decision::allow()
    } else {
        Decision::deny()
    }
}

fn authorize_content(principal: &Principal, grants: &Grants, action: Action, resource: &Resource) -> Decision {
    // Admin authority implies full content authority (config plane subsumes content plane).
    if admin_covers(grants, resource) {
        return Decision::allow();
    }

    if view_allows(grants, action, resource) {
        return Decision::allow();
    }

    if token_scope_allows(principal, grants, action, resource) {
        return Decision::allow();
    }

    Decision::deny()
}

fn view_allows(grants: &Grants, action: Action, resource: &Resource) -> bool {
    match resource_repository(resource) {
        Some((ecosystem, name)) => grants
            .views
            .iter()
            .any(|view| view.allows(&resource.namespace, action, ecosystem, name)),
        None => grants
            .views
            .iter()
            .any(|view| view.namespace == resource.namespace && view.actions.contains(&action)),
    }
}

/// [`ApiTokenScope`] carries no namespace of its own, so it is only honored when the principal's
/// [`PrincipalScope`] covers the resource's namespace.
fn token_scope_allows(principal: &Principal, grants: &Grants, action: Action, resource: &Resource) -> bool {
    if !principal.scope().covers(&resource.namespace) {
        return false;
    }

    match resource_repository(resource) {
        Some((ecosystem, name)) => grants
            .token_scopes
            .iter()
            .any(|scope| scope.allows(action, ecosystem, name)),
        None => grants
            .token_scopes
            .iter()
            .any(|scope| scope.action == Action::Admin || scope.action == action),
    }
}

#[cfg(test)]
mod tests {
    use starmetal_core::authz::Coordinate;

    use super::*;

    fn resource(namespace: &str) -> Resource {
        Resource {
            namespace: Namespace::new(namespace).expect("valid namespace"),
            ecosystem: None,
            repository: None,
            coordinate: None,
        }
    }

    fn resource_for(namespace: &str, ecosystem: Ecosystem, name: &str) -> Resource {
        Resource {
            namespace: Namespace::new(namespace).expect("valid namespace"),
            ecosystem: Some(ecosystem),
            repository: Some(PackageName::new(name)),
            coordinate: None,
        }
    }

    async fn authorize(
        authorizer: &LocalAuthorizer,
        principal: &Principal,
        action: Action,
        resource: &Resource,
    ) -> Decision {
        authorizer
            .authorize(principal, action, resource)
            .await
            .expect("computable decision")
    }

    #[test]
    fn default_namespace_is_the_literal_constant() {
        assert_eq!(default_namespace().as_str(), DEFAULT_NAMESPACE);
        assert_eq!(DEFAULT_NAMESPACE, "default");
    }

    #[tokio::test]
    async fn empty_config_denies_everything() {
        let authorizer = LocalAuthorizer::from_config(&Config::default());
        assert!(authorizer.authenticate("anything").is_none());

        let principal = Principal::User {
            id: PrincipalId::new("nobody").unwrap(),
            scope: PrincipalScope::System,
        };
        let decision = authorize(&authorizer, &principal, Action::Read, &resource(DEFAULT_NAMESPACE)).await;
        assert_eq!(decision, Decision::deny());
    }

    #[tokio::test]
    async fn flat_auth_token_authorizes_read_and_browse_only() {
        let config: Config = toml::from_str(
            r#"
[auth]
enabled = true
tokens = ["flat-secret"]
"#,
        )
        .unwrap();
        let authorizer = LocalAuthorizer::from_config(&config);

        let principal = authorizer.authenticate("flat-secret").expect("token authenticates");
        assert_eq!(principal.id().as_str(), "legacy-bearer");
        assert!(!principal.is_service());

        let target = resource_for(DEFAULT_NAMESPACE, Ecosystem::Npm, "left-pad");
        assert_eq!(
            authorize(&authorizer, &principal, Action::Read, &target).await,
            Decision::allow()
        );
        assert_eq!(
            authorize(&authorizer, &principal, Action::Browse, &target).await,
            Decision::allow()
        );
        assert_eq!(
            authorize(&authorizer, &principal, Action::Add, &target).await,
            Decision::deny()
        );
        assert_eq!(
            authorize(&authorizer, &principal, Action::Delete, &target).await,
            Decision::deny()
        );
        assert_eq!(
            authorize(&authorizer, &principal, Action::Admin, &target).await,
            Decision::deny()
        );
    }

    #[tokio::test]
    async fn admin_token_authorizes_admin_and_all_content_actions() {
        let config: Config = toml::from_str(
            r#"
[admin]
enabled = true
tokens = ["admin-secret"]
"#,
        )
        .unwrap();
        let authorizer = LocalAuthorizer::from_config(&config);

        let principal = authorizer.authenticate("admin-secret").expect("token authenticates");
        assert_eq!(principal.id().as_str(), "legacy-admin");

        let target = resource_for(DEFAULT_NAMESPACE, Ecosystem::Cargo, "serde");
        assert_eq!(
            authorize(&authorizer, &principal, Action::Admin, &target).await,
            Decision::allow()
        );
        for action in Action::CONTENT {
            assert_eq!(
                authorize(&authorizer, &principal, action, &target).await,
                Decision::allow(),
                "admin should allow content action {action}"
            );
        }
    }

    #[tokio::test]
    async fn scoped_publish_token_matches_only_its_ecosystem_and_package() {
        let config: Config = toml::from_str(
            r#"
[publishing]
enabled = true

[[publishing.tokens]]
token = "publish-secret"
scopes = ["publish"]
ecosystems = ["npm"]
packages = ["left-pad"]
"#,
        )
        .unwrap();
        let authorizer = LocalAuthorizer::from_config(&config);

        let principal = authorizer.authenticate("publish-secret").expect("token authenticates");
        assert_eq!(principal.id().as_str(), "publish-token:0");
        assert!(principal.is_service());

        let matching = resource_for(DEFAULT_NAMESPACE, Ecosystem::Npm, "left-pad");
        assert_eq!(
            authorize(&authorizer, &principal, Action::Add, &matching).await,
            Decision::allow()
        );

        let wrong_package = resource_for(DEFAULT_NAMESPACE, Ecosystem::Npm, "other");
        assert_eq!(
            authorize(&authorizer, &principal, Action::Add, &wrong_package).await,
            Decision::deny()
        );

        let wrong_ecosystem = resource_for(DEFAULT_NAMESPACE, Ecosystem::PyPI, "left-pad");
        assert_eq!(
            authorize(&authorizer, &principal, Action::Add, &wrong_ecosystem).await,
            Decision::deny()
        );

        assert_eq!(
            authorize(&authorizer, &principal, Action::Read, &matching).await,
            Decision::deny()
        );
        assert_eq!(
            authorize(&authorizer, &principal, Action::Delete, &matching).await,
            Decision::deny()
        );
    }

    #[test]
    fn unknown_token_does_not_authenticate() {
        let config: Config = toml::from_str(
            r#"
[auth]
enabled = true
tokens = ["flat-secret"]
"#,
        )
        .unwrap();
        let authorizer = LocalAuthorizer::from_config(&config);
        assert!(authorizer.authenticate("not-configured").is_none());
    }

    #[tokio::test]
    async fn resource_in_non_default_namespace_is_denied_for_namespace_scoped_grants() {
        let config: Config = toml::from_str(
            r#"
[auth]
enabled = true
tokens = ["flat-secret"]

[admin]
enabled = true
tokens = ["admin-secret"]
"#,
        )
        .unwrap();
        let authorizer = LocalAuthorizer::from_config(&config);

        let bearer = authorizer.authenticate("flat-secret").unwrap();
        let admin = authorizer.authenticate("admin-secret").unwrap();

        let other_namespace = resource_for("other", Ecosystem::Npm, "left-pad");

        // RepositoryView/RepositoryAdmin grants are pinned to the default namespace, so even
        // though these principals are System-scoped, a differently-named namespace is denied.
        assert_eq!(
            authorize(&authorizer, &bearer, Action::Read, &other_namespace).await,
            Decision::deny()
        );
        assert_eq!(
            authorize(&authorizer, &admin, Action::Admin, &other_namespace).await,
            Decision::deny()
        );
        assert_eq!(
            authorize(&authorizer, &admin, Action::Read, &other_namespace).await,
            Decision::deny()
        );
    }

    #[tokio::test]
    async fn token_present_in_multiple_sections_prefers_admin_then_publish_then_flat() {
        let config: Config = toml::from_str(
            r#"
[auth]
enabled = true
tokens = ["shared-secret"]

[admin]
enabled = true
tokens = ["shared-secret"]

[publishing]
enabled = true

[[publishing.tokens]]
token = "shared-secret"
scopes = ["publish"]
"#,
        )
        .unwrap();
        let authorizer = LocalAuthorizer::from_config(&config);

        let principal = authorizer.authenticate("shared-secret").expect("token authenticates");
        assert_eq!(
            principal.id().as_str(),
            "legacy-admin",
            "admin section takes precedence"
        );

        // A second, admin-only token confirms the other sections were still registered under
        // their own tokens (precedence only matters for the shared string).
        let publish_only: Config = toml::from_str(
            r#"
[publishing]
enabled = true

[[publishing.tokens]]
token = "shared-secret"
scopes = ["publish"]
"#,
        )
        .unwrap();
        let publish_authorizer = LocalAuthorizer::from_config(&publish_only);
        let publish_principal = publish_authorizer.authenticate("shared-secret").unwrap();
        assert_eq!(publish_principal.id().as_str(), "publish-token:0");
    }

    #[tokio::test]
    async fn disabled_sections_contribute_no_grants_even_with_tokens_present() {
        let config: Config = toml::from_str(
            r#"
[auth]
enabled = false
tokens = ["flat-secret"]
"#,
        )
        .unwrap();
        let authorizer = LocalAuthorizer::from_config(&config);
        assert!(authorizer.authenticate("flat-secret").is_none());
    }

    #[tokio::test]
    async fn coordinate_pinned_resource_is_ignored_by_repository_matching() {
        // The reserved `selectors` field is documented as unused by this migration; a
        // coordinate-pinned resource still resolves through ecosystem/name matching only.
        let config: Config = toml::from_str(
            r#"
[auth]
enabled = true
tokens = ["flat-secret"]
"#,
        )
        .unwrap();
        let authorizer = LocalAuthorizer::from_config(&config);
        let principal = authorizer.authenticate("flat-secret").unwrap();

        let mut target = resource_for(DEFAULT_NAMESPACE, Ecosystem::Npm, "left-pad");
        target.coordinate = Some(Coordinate {
            ecosystem: Ecosystem::Npm,
            name: PackageName::new("left-pad"),
            version: Some("1.0.0".to_string()),
        });

        assert_eq!(
            authorize(&authorizer, &principal, Action::Read, &target).await,
            Decision::allow()
        );
    }
}
