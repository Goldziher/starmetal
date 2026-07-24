use std::cmp::Ordering;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use starmetal_core::package::{Ecosystem, PackageName};

use crate::dependency::Dependency;
use crate::error::Result;
use crate::update::{RangeStrategy, UpdateType};

/// A single release of a package as reported by a datasource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    /// The release version string (interpreted by a [`Versioning`]).
    pub version: String,
    /// Whether the release is yanked/withdrawn.
    pub yanked: bool,
    /// Release timestamp as RFC 3339, when the datasource provides one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Inbound port: detect, parse, and patch a class of manifest files.
///
/// Implementations are pure text transforms — they must not perform registry
/// lookups or forge/git operations.
pub trait Manager: Send + Sync {
    /// Stable identifier for the manager (e.g. `"cargo"`).
    fn name(&self) -> &'static str;

    /// Ecosystem the manager's dependencies belong to.
    fn ecosystem(&self) -> Ecosystem;

    /// Whether this manager handles the file at `path` (matched on basename/path).
    fn matches_file(&self, path: &str) -> bool;

    /// Parse `content` (the file at `path`) into its dependencies.
    fn extract(&self, path: &str, content: &str) -> Result<Vec<Dependency>>;

    /// Return `content` with `dependency`'s constraint replaced by `new_value`.
    ///
    /// Implementations perform a surgical edit that preserves formatting rather
    /// than reserializing the manifest. They must locate the dependency by its
    /// name and section (`dep_type`), never by matching the literal
    /// `current_value` text — two dependencies can share an identical constraint
    /// string in the same file, and matching on value would edit the wrong one.
    fn apply_update(&self, content: &str, dependency: &Dependency, new_value: &str) -> Result<String>;
}

/// Outbound port: version-scheme operations for one ecosystem's versions.
///
/// Implementations must be pure (no I/O). This is the single source of truth for
/// version ordering and constraint rewriting.
pub trait Versioning: Send + Sync {
    /// Stable identifier for the scheme (e.g. `"semver"`).
    fn scheme(&self) -> &'static str;

    /// Whether `version` is a valid concrete version in this scheme.
    fn is_valid(&self, version: &str) -> bool;

    /// Whether `version` is a stable (non-pre-release) version.
    fn is_stable(&self, version: &str) -> bool;

    /// Compare two concrete versions, or `None` if either is invalid.
    fn compare(&self, left: &str, right: &str) -> Option<Ordering>;

    /// Whether concrete `version` satisfies `constraint`.
    fn matches(&self, version: &str, constraint: &str) -> bool;

    /// The lowest concrete version a constraint permits, for "is newer" checks.
    ///
    /// For an exact version this is the version itself; for a range it is the
    /// range's lower bound. `None` if the constraint cannot be interpreted.
    fn min_version(&self, constraint: &str) -> Option<String>;

    /// Classify the difference between `current` and `candidate` concrete versions.
    fn diff(&self, current: &str, candidate: &str) -> Option<UpdateType>;

    /// Rewrite `current_value` so it targets `target` per `strategy`.
    ///
    /// Returns `None` when the new value cannot be represented in this scheme.
    fn get_new_value(&self, current_value: &str, strategy: RangeStrategy, target: &str) -> Option<String>;
}

/// Outbound port: available versions for a package.
///
/// The production implementation adapts the registry `PackageService`, so lookups
/// reuse the proxy's cache, integrity verification, and policy enforcement.
#[async_trait]
pub trait Datasource: Send + Sync {
    /// Return the known releases for `name` in `ecosystem`.
    async fn get_releases(&self, ecosystem: Ecosystem, name: &PackageName) -> Result<Vec<Release>>;
}

/// Identifies a repository on a forge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoRef {
    /// Owning user or organization.
    pub owner: String,
    /// Repository name.
    pub name: String,
    /// Base branch to target; `None` uses the repository default branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_branch: Option<String>,
}

impl RepoRef {
    /// Construct a validated repository reference.
    ///
    /// `owner` and `name` are the single boundary where a forge target is checked, so every
    /// [`Forge`] backend can trust them. They must be non-empty and contain none of the URL
    /// path/query metacharacters (`/ \ ? # % : whitespace`) that could smuggle path or query
    /// segments into a forge request.
    pub fn new(owner: impl Into<String>, name: impl Into<String>, base_branch: Option<String>) -> Result<Self> {
        let owner = owner.into();
        let name = name.into();
        validate_repo_segment("repository owner", &owner)?;
        validate_repo_segment("repository name", &name)?;
        Ok(Self {
            owner,
            name,
            base_branch,
        })
    }
}

/// Reject repository owner/name segments that are empty or contain URL metacharacters.
fn validate_repo_segment(label: &str, segment: &str) -> Result<()> {
    if segment.is_empty() {
        return Err(crate::error::UpdateError::Config(format!("{label} must not be empty")));
    }
    if segment
        .chars()
        .any(|character| character.is_whitespace() || matches!(character, '/' | '\\' | '?' | '#' | '%' | ':'))
    {
        return Err(crate::error::UpdateError::Config(format!(
            "{label} contains an invalid character: {segment:?}"
        )));
    }
    Ok(())
}

/// A single file edit to include in an update branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEdit {
    /// Repository-relative path of the file to write.
    pub path: String,
    /// Full new content of the file.
    pub new_content: String,
}

/// A request to publish an update branch and open (or update) a pull request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestRequest {
    /// Head branch to create/update.
    pub branch: String,
    /// Pull-request title.
    pub title: String,
    /// Pull-request body (markdown).
    pub body: String,
    /// Commit message for the branch commit.
    pub commit_message: String,
    /// File edits to apply on the branch.
    pub edits: Vec<FileEdit>,
}

/// Result of submitting a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequestOutcome {
    /// Pull-request number, when the forge assigns one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
    /// Web URL of the pull request.
    pub url: String,
    /// Whether this call created a new pull request (vs. updated an existing one).
    pub created: bool,
}

/// Outbound port: repository read and pull-request operations on a forge.
#[async_trait]
pub trait Forge: Send + Sync {
    /// List repository-relative paths of candidate manifest files.
    async fn list_files(&self, repo: &RepoRef) -> Result<Vec<String>>;

    /// Read a file's UTF-8 content at the base branch, or `None` if absent.
    async fn read_file(&self, repo: &RepoRef, path: &str) -> Result<Option<String>>;

    /// Create/update the head branch with the edits and open/update a pull request.
    async fn submit_pull_request(&self, repo: &RepoRef, request: &PullRequestRequest) -> Result<PullRequestOutcome>;
}

#[cfg(test)]
mod tests {
    use super::RepoRef;

    #[test]
    fn repo_ref_accepts_valid_owner_and_name() {
        let repo = RepoRef::new("octocat", "hello-world", None).expect("valid");
        assert_eq!(repo.owner, "octocat");
        assert_eq!(repo.name, "hello-world");
    }

    #[test]
    fn repo_ref_rejects_empty_and_metacharacters() {
        assert!(RepoRef::new("", "name", None).is_err());
        assert!(RepoRef::new("owner", "", None).is_err());
        assert!(RepoRef::new("owner", "na/me", None).is_err());
        assert!(RepoRef::new("ow ner", "name", None).is_err());
        assert!(RepoRef::new("owner", "na?me", None).is_err());
        assert!(RepoRef::new("owner", "na#me", None).is_err());
    }
}
