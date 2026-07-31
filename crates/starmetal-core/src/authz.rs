//! Access control model: actions, principals, permission planes, and content selectors.
//!
//! This module defines the domain vocabulary for authorization per ADR-0022. It is
//! *definitions only*: the [`Authorizer`] port is consulted by adapters and services, but every
//! implementation (local tokens, OIDC/LDAP, forge-delegated) lives outside the domain, preserving
//! the framework-free core (hexagonal-boundaries).
//!
//! The model adopts Nexus's reference shape:
//!
//! - a **BREAD** [`Action`] set (`browse`, `read`, `edit`, `add`, `delete`) plus `admin`;
//! - [`Principal`]s that are either users or service/robot accounts, scoped to a [`Namespace`] or
//!   system-wide, plus scoped [`ApiToken`]s;
//! - three permission planes — content ([`RepositoryView`]), config ([`RepositoryAdmin`]), and
//!   selector-scoped ([`ContentSelector`]);
//! - [`ContentSelector`]s that both gate access *and* compile to a backend-agnostic
//!   [`QueryPredicate`] pushed into browse/search.
//!
//! This supersedes the flat bearer-token scheme in [`crate::publishing`]
//! ([`TokenScope`](crate::publishing::TokenScope) /
//! [`PublishTokenConfig`](crate::publishing::PublishTokenConfig)): the richer
//! [`ApiToken`]/[`ApiTokenScope`] types carry action, ecosystem, and repository scopes, and the flat
//! tokens migrate to a coarse [`RepositoryView`] grant.
//!
//! Authorization is **deny-by-default**: a request that is not explicitly granted is denied, and a
//! missing authorization is a denied request, not an allowed one (OWASP broken-access-control).

use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Result, StarmetalError};
use crate::package::{Ecosystem, PackageName};

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// The set of authorizable actions: the **BREAD** verbs plus `admin`.
///
/// Modelled as a typed enum rather than bare booleans (rust-conventions). The five BREAD verbs
/// (`browse`, `read`, `edit`, `add`, `delete`) act on the content plane; `admin` is the config
/// plane (see [`RepositoryAdmin`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// List/discover that a repository or coordinate exists (weakest content grant).
    Browse,
    /// Read/download artifact content and metadata.
    Read,
    /// Modify existing metadata (e.g. yank/unlist) without adding new versions.
    Edit,
    /// Publish new versions/artifacts.
    Add,
    /// Remove versions/artifacts.
    Delete,
    /// Manage repository configuration and grants (config plane).
    Admin,
}

impl Action {
    /// The five BREAD content-plane actions, in ascending order of privilege.
    ///
    /// Excludes [`Action::Admin`], which is the config plane.
    pub const CONTENT: [Action; 5] = [Action::Browse, Action::Read, Action::Edit, Action::Add, Action::Delete];

    /// The lowercase wire/serialization token for this action.
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Browse => "browse",
            Action::Read => "read",
            Action::Edit => "edit",
            Action::Add => "add",
            Action::Delete => "delete",
            Action::Admin => "admin",
        }
    }

    /// Whether this is a content-plane action (a BREAD verb, not `admin`).
    pub fn is_content(&self) -> bool {
        !matches!(self, Action::Admin)
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Action {
    type Err = StarmetalError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "browse" => Ok(Action::Browse),
            "read" => Ok(Action::Read),
            "edit" => Ok(Action::Edit),
            "add" => Ok(Action::Add),
            "delete" => Ok(Action::Delete),
            "admin" => Ok(Action::Admin),
            _ => Err(StarmetalError::Config(format!("unknown action: {s}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Namespace (tenancy boundary)
// ---------------------------------------------------------------------------

/// The tenancy boundary a repository (and its hosted packages) belongs to.
///
/// A namespace is the integration point an external forge/identity provider maps onto: identity can
/// be local or delegated by swapping the [`Authorizer`] implementation, but the namespace is the
/// stable unit of ownership either way.
///
/// Validated as a lowercase DNS-label-like string: non-empty, made only of ASCII lowercase
/// alphanumerics plus `.`, `-`, `_`, and never a path segment (`.`/`..`, separators, NUL) so it is
/// safe to embed in storage keys and URLs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Namespace(String);

impl Namespace {
    /// Construct and validate a namespace.
    ///
    /// # Errors
    ///
    /// Returns [`StarmetalError::Config`] if the value is empty, a relative path segment, or
    /// contains characters outside the `[a-z0-9._-]` allowlist.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(StarmetalError::Config("namespace must not be empty".to_string()));
        }
        if value == "." || value == ".." {
            return Err(StarmetalError::Config(
                "namespace must not be a relative path segment".to_string(),
            ));
        }
        for byte in value.bytes() {
            let allowed = byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_');
            if !allowed {
                return Err(StarmetalError::Config(format!(
                    "namespace must match [a-z0-9._-]: invalid value {value:?}"
                )));
            }
        }
        Ok(Self(value))
    }

    /// The namespace as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Principals & tokens
// ---------------------------------------------------------------------------

/// A stable identifier for a principal (username or service-account name).
///
/// Free-form beyond being non-empty; the [`Authorizer`] implementation owns the identity namespace
/// (local database, OIDC subject, forge login, ...).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Construct a principal id.
    ///
    /// # Errors
    ///
    /// Returns [`StarmetalError::Config`] if the id is empty.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(StarmetalError::Config("principal id must not be empty".to_string()));
        }
        Ok(Self(value))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The reach of a principal or token: bound to one [`Namespace`], or system-wide.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PrincipalScope {
    /// System-wide reach, not confined to a single namespace.
    System,
    /// Reach confined to a single namespace.
    Namespace(Namespace),
}

impl PrincipalScope {
    /// Whether this scope covers `namespace` (system-wide scopes cover every namespace).
    pub fn covers(&self, namespace: &Namespace) -> bool {
        match self {
            PrincipalScope::System => true,
            PrincipalScope::Namespace(scope) => scope == namespace,
        }
    }
}

/// An authenticated actor: a human user or a service/robot account.
///
/// Both variants carry a [`PrincipalId`] and a [`PrincipalScope`]; the distinction lets policy and
/// audit treat automation differently from people (e.g. tighter default grants for robots).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Principal {
    /// A human user account.
    User {
        /// Stable identity.
        id: PrincipalId,
        /// Namespace reach or system-wide.
        scope: PrincipalScope,
    },
    /// A service/robot (machine) account.
    Service {
        /// Stable identity.
        id: PrincipalId,
        /// Namespace reach or system-wide.
        scope: PrincipalScope,
    },
}

impl Principal {
    /// This principal's identity.
    pub fn id(&self) -> &PrincipalId {
        match self {
            Principal::User { id, .. } | Principal::Service { id, .. } => id,
        }
    }

    /// This principal's scope.
    pub fn scope(&self) -> &PrincipalScope {
        match self {
            Principal::User { scope, .. } | Principal::Service { scope, .. } => scope,
        }
    }

    /// Whether this is a service/robot account (as opposed to a human user).
    pub fn is_service(&self) -> bool {
        matches!(self, Principal::Service { .. })
    }
}

/// A single grant on an [`ApiToken`]: one [`Action`] over a [`RepositoryPattern`].
///
/// The pattern carries both the ecosystem and repository-name wildcards, so a scope expresses
/// "this action, on these ecosystems, on these repositories" — the action + ecosystem + repository
/// triple that supersedes the flat [`crate::publishing::TokenScope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApiTokenScope {
    /// The granted action.
    pub action: Action,
    /// The repositories (ecosystem + name) the action applies to.
    pub repository: RepositoryPattern,
}

impl ApiTokenScope {
    /// Whether this scope grants `action` on `ecosystem`/`name`.
    ///
    /// [`Action::Admin`] in a scope grants any action (admin implies the full BREAD set).
    pub fn allows(&self, action: Action, ecosystem: Ecosystem, name: &PackageName) -> bool {
        let action_allowed = self.action == Action::Admin || self.action == action;
        action_allowed && self.repository.matches(ecosystem, name)
    }
}

/// A scoped API token: an opaque secret bound to a subject and scope, carrying action + ecosystem +
/// repository grants.
///
/// This is the richer replacement for [`crate::publishing::PublishTokenConfig`]: rather than flat
/// `scopes`/`ecosystems`/`packages` lists, each [`ApiTokenScope`] pairs an [`Action`] with a
/// [`RepositoryPattern`]. Empty `scopes` grants nothing (deny-by-default).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiToken {
    /// The opaque bearer secret. Never logged (secrets-handling).
    pub token: String,
    /// The principal this token acts as.
    pub subject: PrincipalId,
    /// The namespace/system reach this token is confined to.
    pub scope: PrincipalScope,
    /// The action/repository grants carried by this token.
    #[serde(default)]
    pub scopes: Vec<ApiTokenScope>,
}

impl ApiToken {
    /// Whether this token grants `action` on `namespace`/`ecosystem`/`name`.
    ///
    /// Requires both that the token's [`PrincipalScope`] covers `namespace` and that some
    /// [`ApiTokenScope`] grants the action on the repository. With no scopes, denies (deny-by-default).
    pub fn allows(&self, namespace: &Namespace, action: Action, ecosystem: Ecosystem, name: &PackageName) -> bool {
        self.scope.covers(namespace) && self.scopes.iter().any(|scope| scope.allows(action, ecosystem, name))
    }
}

// ---------------------------------------------------------------------------
// Wildcard patterns
// ---------------------------------------------------------------------------

/// An ecosystem matcher: any ecosystem, or one exact [`Ecosystem`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "match", rename_all = "lowercase")]
pub enum EcosystemPattern {
    /// Matches every ecosystem.
    Any,
    /// Matches exactly one ecosystem.
    Exact(Ecosystem),
}

impl EcosystemPattern {
    /// Whether `ecosystem` satisfies this pattern.
    pub fn matches(&self, ecosystem: Ecosystem) -> bool {
        match self {
            EcosystemPattern::Any => true,
            EcosystemPattern::Exact(expected) => *expected == ecosystem,
        }
    }
}

/// A package-name matcher: any name, an exact name, or a literal prefix.
///
/// Matching compares raw name strings; callers that need canonical matching should
/// [`PackageName::normalized`](crate::package::PackageName::normalized) first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "match", content = "value", rename_all = "lowercase")]
pub enum NamePattern {
    /// Matches every name.
    Any,
    /// Matches one exact name.
    Exact(String),
    /// Matches any name starting with this literal prefix.
    Prefix(String),
}

impl NamePattern {
    /// Whether `name` satisfies this pattern.
    pub fn matches(&self, name: &PackageName) -> bool {
        match self {
            NamePattern::Any => true,
            NamePattern::Exact(expected) => name.as_str() == expected,
            NamePattern::Prefix(prefix) => name.as_str().starts_with(prefix.as_str()),
        }
    }
}

/// A repository matcher, wildcardable by ecosystem and name.
///
/// The shared shape behind [`RepositoryView`], [`RepositoryAdmin`], and [`ApiTokenScope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepositoryPattern {
    /// Which ecosystem(s) this pattern covers.
    pub ecosystem: EcosystemPattern,
    /// Which repository name(s) this pattern covers.
    pub name: NamePattern,
}

impl RepositoryPattern {
    /// A pattern matching every repository in every ecosystem.
    pub fn any() -> Self {
        Self {
            ecosystem: EcosystemPattern::Any,
            name: NamePattern::Any,
        }
    }

    /// Whether `ecosystem`/`name` satisfies this pattern.
    pub fn matches(&self, ecosystem: Ecosystem, name: &PackageName) -> bool {
        self.ecosystem.matches(ecosystem) && self.name.matches(name)
    }
}

// ---------------------------------------------------------------------------
// Permission planes
// ---------------------------------------------------------------------------

/// Content-plane grant: BREAD actions on repositories within a namespace.
///
/// Wildcardable by ecosystem and name via [`RepositoryPattern`]. `actions` should hold only content
/// verbs ([`Action::CONTENT`]); config-plane authority is expressed separately by
/// [`RepositoryAdmin`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepositoryView {
    /// The namespace this grant applies within.
    pub namespace: Namespace,
    /// The repositories the grant covers.
    pub repository: RepositoryPattern,
    /// The content actions granted.
    #[serde(default)]
    pub actions: Vec<Action>,
}

impl RepositoryView {
    /// Whether this grant allows `action` on `namespace`/`ecosystem`/`name`.
    ///
    /// The namespace must match exactly, the repository pattern must match, and `action` must be in
    /// the granted set.
    pub fn allows(&self, namespace: &Namespace, action: Action, ecosystem: Ecosystem, name: &PackageName) -> bool {
        &self.namespace == namespace && self.repository.matches(ecosystem, name) && self.actions.contains(&action)
    }
}

/// Config-plane grant: administrative authority over repositories within a namespace.
///
/// Carries the implicit [`Action::Admin`]; it manages repository configuration and grants rather
/// than content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepositoryAdmin {
    /// The namespace this grant applies within.
    pub namespace: Namespace,
    /// The repositories the admin authority covers.
    pub repository: RepositoryPattern,
}

impl RepositoryAdmin {
    /// Whether this grant confers admin over `namespace`/`ecosystem`/`name`.
    pub fn allows(&self, namespace: &Namespace, ecosystem: Ecosystem, name: &PackageName) -> bool {
        &self.namespace == namespace && self.repository.matches(ecosystem, name)
    }
}

// ---------------------------------------------------------------------------
// Content selectors & query predicates
// ---------------------------------------------------------------------------

/// A specific artifact coordinate: ecosystem + name, optionally pinned to a version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Coordinate {
    /// The ecosystem the coordinate belongs to.
    pub ecosystem: Ecosystem,
    /// The package name.
    pub name: PackageName,
    /// The version, when the coordinate is pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// The `(ecosystem, path, coordinate)` context a [`QueryPredicate`] is evaluated against.
///
/// `path` is the storage/route path of the asset under consideration; `coordinate` is present when
/// the asset resolves to a known package coordinate.
#[derive(Debug, Clone, Copy)]
pub struct ContentContext<'a> {
    /// The ecosystem of the asset being evaluated.
    pub ecosystem: Ecosystem,
    /// The asset's path.
    pub path: &'a str,
    /// The asset's coordinate, when known.
    pub coordinate: Option<&'a Coordinate>,
}

/// A backend-agnostic predicate over `(ecosystem, path, coordinate)`.
///
/// This is an abstract AST, *not* SQL: it can be evaluated in memory to gate a single asset
/// ([`QueryPredicate::evaluate`]) and later compiled to a store-specific `WHERE` clause (the
/// Postgres compilation lives in another crate, per ADR-0020). Kept small and serializable so it can
/// be persisted in configuration and handed across the [`Authorizer`] boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryPredicate {
    /// Always true (tautology). Matches everything.
    Always,
    /// Always false (contradiction). Matches nothing.
    Never,
    /// The asset's ecosystem equals this one.
    Ecosystem(Ecosystem),
    /// The asset's path starts with this literal prefix.
    PathPrefix(String),
    /// The asset's path equals this literal.
    PathEquals(String),
    /// The asset resolves to a coordinate whose name satisfies this pattern.
    CoordinateName(NamePattern),
    /// Conjunction: true iff every child is true (empty is vacuously true).
    All(Vec<QueryPredicate>),
    /// Disjunction: true iff any child is true (empty is vacuously false).
    Any(Vec<QueryPredicate>),
    /// Negation of the child predicate.
    Not(Box<QueryPredicate>),
}

impl QueryPredicate {
    /// Evaluate this predicate against a single asset's context (in-memory gating).
    ///
    /// The same predicate is what a store compiles into a pushed-down filter; evaluating it here and
    /// compiling it there are two views of one expression.
    pub fn evaluate(&self, context: &ContentContext<'_>) -> bool {
        match self {
            QueryPredicate::Always => true,
            QueryPredicate::Never => false,
            QueryPredicate::Ecosystem(ecosystem) => context.ecosystem == *ecosystem,
            QueryPredicate::PathPrefix(prefix) => context.path.starts_with(prefix.as_str()),
            QueryPredicate::PathEquals(path) => context.path == path,
            QueryPredicate::CoordinateName(pattern) => context
                .coordinate
                .is_some_and(|coordinate| pattern.matches(&coordinate.name)),
            QueryPredicate::All(children) => children.iter().all(|child| child.evaluate(context)),
            QueryPredicate::Any(children) => children.iter().any(|child| child.evaluate(context)),
            QueryPredicate::Not(child) => !child.evaluate(context),
        }
    }
}

/// A named expression over `(ecosystem, path, coordinate)` that both gates access and compiles to a
/// query filter.
///
/// The selector's [`QueryPredicate`] plays a dual role: [`ContentSelector::matches`] evaluates it to
/// gate a single asset, and [`ContentSelector::to_query_predicate`] hands it to the metadata store to
/// be pushed down into browse/search — so authorization filters what a principal can even list,
/// enforced in-query rather than per-asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ContentSelector {
    /// The selector's name (its handle in configuration and grants).
    pub name: String,
    /// The predicate that defines the selector's scope.
    pub predicate: QueryPredicate,
}

impl ContentSelector {
    /// Construct a selector from a name and predicate.
    pub fn new(name: impl Into<String>, predicate: QueryPredicate) -> Self {
        Self {
            name: name.into(),
            predicate,
        }
    }

    /// Borrow the selector's predicate.
    pub fn predicate(&self) -> &QueryPredicate {
        &self.predicate
    }

    /// Gate a single asset: whether it falls within this selector's scope.
    pub fn matches(&self, context: &ContentContext<'_>) -> bool {
        self.predicate.evaluate(context)
    }

    /// Compile to a query-filter predicate for push-down into the metadata store.
    pub fn to_query_predicate(&self) -> QueryPredicate {
        self.predicate.clone()
    }
}

// ---------------------------------------------------------------------------
// Authorizer port
// ---------------------------------------------------------------------------

/// The resource an authorization request is about.
///
/// A request always names a [`Namespace`]; `ecosystem`, `repository`, and `coordinate` narrow it
/// from a whole-namespace decision down to a single pinned artifact as they are supplied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Resource {
    /// The tenancy boundary the request is scoped to.
    pub namespace: Namespace,
    /// The ecosystem, when the request is ecosystem-specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<Ecosystem>,
    /// The repository name, when the request targets a specific repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<PackageName>,
    /// The exact coordinate, when the request targets a specific package/version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinate: Option<Coordinate>,
}

/// The outcome of an authorization check: a boolean decision plus an optional query predicate.
///
/// Per ADR-0022 the [`Authorizer`] returns *both* a boolean allow/deny and an optional
/// [`QueryPredicate`]. The predicate is present on `allow` decisions that are content-scoped: the
/// caller must push it into browse/search so listings are filtered in-query. An `allow` with no
/// predicate is unconditional; a `deny` never carries one.
///
/// [`Decision::default`] is [`Decision::deny`] — deny-by-default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Decision {
    /// Whether the action is permitted.
    pub allow: bool,
    /// A filter the caller must apply to browse/search results, when the grant is content-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<QueryPredicate>,
}

impl Decision {
    /// A denial (no predicate). This is the default outcome.
    pub fn deny() -> Self {
        Self {
            allow: false,
            predicate: None,
        }
    }

    /// An unconditional allow (no filtering required).
    pub fn allow() -> Self {
        Self {
            allow: true,
            predicate: None,
        }
    }

    /// An allow that requires the caller to apply `predicate` to browse/search results.
    pub fn allow_where(predicate: QueryPredicate) -> Self {
        Self {
            allow: true,
            predicate: Some(predicate),
        }
    }

    /// Whether the action is permitted.
    pub fn is_allowed(&self) -> bool {
        self.allow
    }
}

impl Default for Decision {
    fn default() -> Self {
        Self::deny()
    }
}

/// The injected access-control port.
///
/// Adapters and services consult this trait; implementations (local tokens, OIDC/LDAP,
/// forge-delegated) live outside the domain, keeping the core framework-free. The trait is
/// object-safe so it can be held as `Arc<dyn Authorizer>` and swapped per deployment.
///
/// Contract: [`authorize`](Authorizer::authorize) is **deny-by-default** — an implementation that
/// cannot find an explicit grant must return [`Decision::deny`], never allow. When it allows a
/// content-scoped request it should attach a [`QueryPredicate`] via [`Decision::allow_where`] so the
/// caller filters listings in-query.
#[async_trait::async_trait]
pub trait Authorizer: Send + Sync {
    /// Decide whether `principal` may perform `action` on `resource`.
    ///
    /// Returns a [`Decision`] carrying both the boolean outcome and an optional filter predicate.
    ///
    /// # Errors
    ///
    /// Returns an error only when the decision cannot be computed (e.g. an identity backend is
    /// unreachable). A computable "not permitted" is a successful [`Decision::deny`], not an error.
    async fn authorize(&self, principal: &Principal, action: Action, resource: &Resource) -> Result<Decision>;
}

/// The injected authentication port: resolve a bearer credential to the [`Principal`] it acts as.
///
/// Kept separate from [`Authorizer`] because authentication (who is this?) and authorization (may
/// they?) are distinct concerns with different backends: a request is first authenticated to a
/// principal, then that principal is authorized against a resource. Implementations (local tokens,
/// OIDC, forge-delegated) live outside the domain. The trait is object-safe so it can be held as
/// `Arc<dyn Authenticator>` and swapped per deployment.
///
/// Synchronous because local token verification needs no I/O; a future remote backend that must do
/// network introspection can wrap its own runtime or this port can gain an async sibling then
/// (kept minimal today, per YAGNI).
pub trait Authenticator: Send + Sync {
    /// Resolve a bearer `credential` to the [`Principal`] it authenticates as.
    ///
    /// Returns [`None`] for an unrecognized credential; callers must treat an unauthenticated
    /// request as denied. Implementations must compare secrets in constant time (secrets-handling).
    fn authenticate_bearer(&self, credential: &str) -> Option<Principal>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace(value: &str) -> Namespace {
        Namespace::new(value).expect("valid namespace")
    }

    #[test]
    fn action_display_and_from_str_round_trip() {
        let all = [
            Action::Browse,
            Action::Read,
            Action::Edit,
            Action::Add,
            Action::Delete,
            Action::Admin,
        ];
        for action in all {
            let rendered = action.to_string();
            let parsed = Action::from_str(&rendered).expect("round trip");
            assert_eq!(parsed, action, "round trip for {rendered}");
        }
    }

    #[test]
    fn action_from_str_is_case_insensitive() {
        assert_eq!(Action::from_str("ADD").unwrap(), Action::Add);
        assert_eq!(Action::from_str("Browse").unwrap(), Action::Browse);
    }

    #[test]
    fn action_from_str_rejects_unknown() {
        let err = Action::from_str("publish").unwrap_err().to_string();
        assert!(err.contains("unknown action: publish"), "got: {err}");
    }

    #[test]
    fn action_content_set_excludes_admin() {
        assert!(!Action::CONTENT.contains(&Action::Admin));
        assert!(Action::Add.is_content());
        assert!(!Action::Admin.is_content());
    }

    #[test]
    fn namespace_accepts_valid_values() {
        assert_eq!(Namespace::new("team-a").unwrap().as_str(), "team-a");
        assert_eq!(Namespace::new("acme.internal_1").unwrap().as_str(), "acme.internal_1");
    }

    #[test]
    fn namespace_rejects_empty() {
        assert!(Namespace::new("").is_err());
    }

    #[test]
    fn namespace_rejects_path_traversal() {
        assert!(Namespace::new("..").is_err());
        assert!(Namespace::new("a/b").is_err());
    }

    #[test]
    fn namespace_rejects_uppercase_and_symbols() {
        assert!(Namespace::new("TeamA").is_err());
        assert!(Namespace::new("team a").is_err());
        assert!(Namespace::new("team@a").is_err());
    }

    #[test]
    fn ecosystem_pattern_matches() {
        assert!(EcosystemPattern::Any.matches(Ecosystem::Npm));
        assert!(EcosystemPattern::Exact(Ecosystem::PyPI).matches(Ecosystem::PyPI));
        assert!(!EcosystemPattern::Exact(Ecosystem::PyPI).matches(Ecosystem::Npm));
    }

    #[test]
    fn name_pattern_matches() {
        let requests = PackageName::new("requests");
        assert!(NamePattern::Any.matches(&requests));
        assert!(NamePattern::Exact("requests".to_string()).matches(&requests));
        assert!(!NamePattern::Exact("flask".to_string()).matches(&requests));
        assert!(NamePattern::Prefix("req".to_string()).matches(&requests));
        assert!(!NamePattern::Prefix("flask".to_string()).matches(&requests));
    }

    #[test]
    fn repository_view_wildcard_matching() {
        let view = RepositoryView {
            namespace: namespace("team-a"),
            repository: RepositoryPattern {
                ecosystem: EcosystemPattern::Exact(Ecosystem::PyPI),
                name: NamePattern::Prefix("internal-".to_string()),
            },
            actions: vec![Action::Browse, Action::Read],
        };
        let internal = PackageName::new("internal-tool");
        let public = PackageName::new("requests");

        assert!(view.allows(&namespace("team-a"), Action::Read, Ecosystem::PyPI, &internal));
        // wrong namespace
        assert!(!view.allows(&namespace("team-b"), Action::Read, Ecosystem::PyPI, &internal));
        // wrong ecosystem
        assert!(!view.allows(&namespace("team-a"), Action::Read, Ecosystem::Npm, &internal));
        // name outside prefix
        assert!(!view.allows(&namespace("team-a"), Action::Read, Ecosystem::PyPI, &public));
        // action not granted
        assert!(!view.allows(&namespace("team-a"), Action::Add, Ecosystem::PyPI, &internal));
    }

    #[test]
    fn repository_admin_matching() {
        let admin = RepositoryAdmin {
            namespace: namespace("team-a"),
            repository: RepositoryPattern::any(),
        };
        let any_pkg = PackageName::new("whatever");
        assert!(admin.allows(&namespace("team-a"), Ecosystem::Cargo, &any_pkg));
        assert!(!admin.allows(&namespace("team-b"), Ecosystem::Cargo, &any_pkg));
    }

    #[test]
    fn api_token_scope_admin_grants_any_action() {
        let scope = ApiTokenScope {
            action: Action::Admin,
            repository: RepositoryPattern::any(),
        };
        let pkg = PackageName::new("serde");
        assert!(scope.allows(Action::Delete, Ecosystem::Cargo, &pkg));
        assert!(scope.allows(Action::Read, Ecosystem::Cargo, &pkg));
    }

    #[test]
    fn api_token_requires_scope_and_reach() {
        let token = ApiToken {
            token: "secret".to_string(),
            subject: PrincipalId::new("ci-bot").unwrap(),
            scope: PrincipalScope::Namespace(namespace("team-a")),
            scopes: vec![ApiTokenScope {
                action: Action::Add,
                repository: RepositoryPattern {
                    ecosystem: EcosystemPattern::Exact(Ecosystem::Npm),
                    name: NamePattern::Any,
                },
            }],
        };
        let pkg = PackageName::new("left-pad");

        assert!(token.allows(&namespace("team-a"), Action::Add, Ecosystem::Npm, &pkg));
        // outside the token's namespace reach
        assert!(!token.allows(&namespace("team-b"), Action::Add, Ecosystem::Npm, &pkg));
        // action not scoped
        assert!(!token.allows(&namespace("team-a"), Action::Delete, Ecosystem::Npm, &pkg));
    }

    #[test]
    fn empty_token_denies_by_default() {
        let token = ApiToken {
            token: "secret".to_string(),
            subject: PrincipalId::new("nobody").unwrap(),
            scope: PrincipalScope::System,
            scopes: vec![],
        };
        let pkg = PackageName::new("anything");
        assert!(!token.allows(&namespace("team-a"), Action::Read, Ecosystem::PyPI, &pkg));
    }

    #[test]
    fn query_predicate_evaluates_over_context() {
        let coordinate = Coordinate {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("internal-lib"),
            version: Some("1.0.0".to_string()),
        };
        let context = ContentContext {
            ecosystem: Ecosystem::PyPI,
            path: "pypi/internal-lib/1.0.0/internal_lib-1.0.0.tar.gz",
            coordinate: Some(&coordinate),
        };

        let predicate = QueryPredicate::All(vec![
            QueryPredicate::Ecosystem(Ecosystem::PyPI),
            QueryPredicate::PathPrefix("pypi/internal-".to_string()),
            QueryPredicate::CoordinateName(NamePattern::Prefix("internal-".to_string())),
        ]);
        assert!(predicate.evaluate(&context));

        let negated = QueryPredicate::Not(Box::new(QueryPredicate::Ecosystem(Ecosystem::Npm)));
        assert!(negated.evaluate(&context));

        assert!(QueryPredicate::Always.evaluate(&context));
        assert!(!QueryPredicate::Never.evaluate(&context));
        // empty All is vacuously true, empty Any is vacuously false
        assert!(QueryPredicate::All(vec![]).evaluate(&context));
        assert!(!QueryPredicate::Any(vec![]).evaluate(&context));
    }

    #[test]
    fn content_selector_gates_and_compiles_to_same_predicate() {
        let predicate = QueryPredicate::Ecosystem(Ecosystem::Cargo);
        let selector = ContentSelector::new("cargo-only", predicate.clone());

        let coordinate = Coordinate {
            ecosystem: Ecosystem::Cargo,
            name: PackageName::new("serde"),
            version: None,
        };
        let context = ContentContext {
            ecosystem: Ecosystem::Cargo,
            path: "cargo/serde/1.0.0/serde-1.0.0.crate",
            coordinate: Some(&coordinate),
        };

        assert!(selector.matches(&context));
        assert_eq!(selector.to_query_predicate(), predicate);
    }

    #[test]
    fn decision_defaults_to_deny() {
        assert_eq!(Decision::default(), Decision::deny());
        assert!(!Decision::default().is_allowed());
        assert!(Decision::allow().is_allowed());

        let filtered = Decision::allow_where(QueryPredicate::Always);
        assert!(filtered.is_allowed());
        assert_eq!(filtered.predicate, Some(QueryPredicate::Always));
    }

    #[test]
    fn principal_scope_covers_namespace() {
        assert!(PrincipalScope::System.covers(&namespace("anything")));
        assert!(PrincipalScope::Namespace(namespace("team-a")).covers(&namespace("team-a")));
        assert!(!PrincipalScope::Namespace(namespace("team-a")).covers(&namespace("team-b")));
    }

    #[test]
    fn principal_accessors() {
        let user = Principal::User {
            id: PrincipalId::new("alice").unwrap(),
            scope: PrincipalScope::System,
        };
        let service = Principal::Service {
            id: PrincipalId::new("ci-bot").unwrap(),
            scope: PrincipalScope::Namespace(namespace("team-a")),
        };
        assert_eq!(user.id().as_str(), "alice");
        assert!(!user.is_service());
        assert!(service.is_service());
        assert!(service.scope().covers(&namespace("team-a")));
    }
}
