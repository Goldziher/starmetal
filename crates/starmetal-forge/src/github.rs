//! GitHub [`Forge`] backend built on [`octocrab`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use octocrab::models::pulls::PullRequest;
use octocrab::models::repos::{Content, Object};
use octocrab::params::State;
use octocrab::params::repos::Reference;
use secrecy::SecretString;
use starmetal_update_core::error::{Result, UpdateError};
use starmetal_update_core::ports::{FileEdit, Forge, PullRequestOutcome, PullRequestRequest, RepoRef};

/// Time-to-live for cached repository default-branch lookups.
const DEFAULT_BRANCH_CACHE_TTL: Duration = Duration::from_secs(300);

/// Key into the default-branch cache: `(owner, name)`.
type RepoKey = (String, String);

/// A small TTL cache of resolved repository default branches.
///
/// Deliberately free of any `octocrab`/HTTP dependency so its logic is unit-testable without
/// constructing a network client (which would require a Tokio runtime and a rustls crypto
/// provider).
#[derive(Debug)]
struct DefaultBranchCache {
    entries: Mutex<HashMap<RepoKey, (Instant, String)>>,
    ttl: Duration,
}

impl DefaultBranchCache {
    /// Create an empty cache with the given entry time-to-live.
    fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Return the cached branch for `key` if present and younger than the TTL.
    fn get(&self, key: &RepoKey) -> Option<String> {
        let entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.get(key).and_then(|(inserted, branch)| {
            if inserted.elapsed() < self.ttl {
                Some(branch.clone())
            } else {
                None
            }
        })
    }

    /// Store `branch` as the resolved default branch for `key`.
    fn put(&self, key: RepoKey, branch: String) {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.insert(key, (Instant::now(), branch));
    }
}

/// A [`Forge`] implementation that talks to GitHub (or GitHub Enterprise) via the REST API.
///
/// Credentials are handed to `octocrab` as a [`SecretString`] and are never logged; the
/// resulting client redacts the token in its own `Debug` output.
pub struct GithubForge {
    client: octocrab::Octocrab,
    /// Cache of resolved repository default branches, so repeated operations against the same
    /// repository (list files, read file, submit pull request) do not each pay for a
    /// `GET /repos/{owner}/{repo}` round trip just to resolve the default branch.
    default_branch_cache: DefaultBranchCache,
}

impl GithubForge {
    /// Build a client authenticated with a personal access token against `github.com`.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::Forge`] if the underlying HTTP client cannot be constructed.
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let token: SecretString = token.into().into();
        let client = octocrab::Octocrab::builder()
            .personal_token(token)
            .build()
            .map_err(to_forge_error)?;
        Ok(Self {
            client,
            default_branch_cache: DefaultBranchCache::new(DEFAULT_BRANCH_CACHE_TTL),
        })
    }

    /// Build a client authenticated with a personal access token against a GitHub Enterprise
    /// instance at `base_url` (e.g. `https://github.example.com/api/v3`).
    ///
    /// `base_url` is validated before use: it must be `https`, unless the host is
    /// `localhost`/`127.0.0.1` (allowed over `http` so tests and local mirrors work). This
    /// guards against SSRF via an attacker-controlled base URL, per ADR-0017's host-allowlisting
    /// requirement.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::Forge`] if `base_url` fails validation, is not a valid URI, or the
    /// client cannot be constructed.
    pub fn with_base_url(token: impl Into<String>, base_url: impl AsRef<str>) -> Result<Self> {
        let validated = validate_base_url(base_url.as_ref())?;
        let token: SecretString = token.into().into();
        let client = octocrab::Octocrab::builder()
            .base_uri(validated.as_str())
            .map_err(to_forge_error)?
            .personal_token(token)
            .build()
            .map_err(to_forge_error)?;
        Ok(Self {
            client,
            default_branch_cache: DefaultBranchCache::new(DEFAULT_BRANCH_CACHE_TTL),
        })
    }

    /// Resolve the branch operations should target: the explicit `base_branch`, or the
    /// repository's default branch (cached for [`DEFAULT_BRANCH_CACHE_TTL`]).
    #[tracing::instrument(skip(self))]
    async fn resolve_base_branch(&self, repo: &RepoRef) -> Result<String> {
        if let Some(branch) = &repo.base_branch {
            return Ok(branch.clone());
        }
        let key: RepoKey = (repo.owner.clone(), repo.name.clone());
        if let Some(branch) = self.default_branch_cache.get(&key) {
            return Ok(branch);
        }
        let repository = self
            .client
            .repos(&repo.owner, &repo.name)
            .get()
            .await
            .map_err(to_forge_error)?;
        let branch = repository
            .default_branch
            .ok_or_else(|| UpdateError::Forge(format!("{}/{} has no default branch", repo.owner, repo.name)))?;
        self.default_branch_cache.put(key, branch.clone());
        Ok(branch)
    }

    /// Fetch the commit SHA that `branch` currently points at.
    #[tracing::instrument(skip(self))]
    async fn branch_head_sha(&self, repo: &RepoRef, branch: &str) -> Result<String> {
        let reference = Reference::Branch(branch.to_string());
        let git_ref = self
            .client
            .repos(&repo.owner, &repo.name)
            .get_ref(&reference)
            .await
            .map_err(to_forge_error)?;
        match git_ref.object {
            Object::Commit { sha, .. } | Object::Tag { sha, .. } => Ok(sha),
            other => Err(UpdateError::Forge(format!(
                "unsupported git reference object for {branch}: {other:?}"
            ))),
        }
    }

    /// Fetch a file's blob SHA and decoded UTF-8 content at `path` on `branch`.
    ///
    /// Returns `Ok(None)` when the file does not exist on that branch.
    #[tracing::instrument(skip(self))]
    async fn read_at_branch(&self, repo: &RepoRef, path: &str, branch: &str) -> Result<Option<(String, String)>> {
        let result = self
            .client
            .repos(&repo.owner, &repo.name)
            .get_content()
            .path(path)
            .r#ref(branch)
            .send()
            .await;
        let mut items = match result {
            Ok(items) => items,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(to_forge_error(error)),
        };
        let entries = items.take_items();
        ensure_not_directory(path, entries.len())?;
        let Some(content) = entries.into_iter().next() else {
            return Ok(None);
        };
        let text = decode_content(&content)?;
        Ok(Some((content.sha, text)))
    }

    /// Create the branch named `branch` at `sha`, tolerating an already-existing branch.
    #[tracing::instrument(skip(self))]
    async fn ensure_branch(&self, repo: &RepoRef, branch: &str, sha: &str) -> Result<()> {
        let reference = Reference::Branch(branch.to_string());
        match self
            .client
            .repos(&repo.owner, &repo.name)
            .create_ref(&reference, sha)
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if is_reference_already_exists(&error) => {
                tracing::debug!(owner = %repo.owner, name = %repo.name, branch, "branch already exists, reusing it");
                Ok(())
            }
            Err(error) => Err(to_forge_error(error)),
        }
    }

    /// Apply a single file edit as a commit on `request.branch`.
    async fn apply_edit(&self, repo: &RepoRef, request: &PullRequestRequest, edit: &FileEdit) -> Result<()> {
        let existing = self.read_at_branch(repo, &edit.path, &request.branch).await?;
        let repos = self.client.repos(&repo.owner, &repo.name);
        let outcome = match existing {
            Some((sha, _)) => {
                repos
                    .update_file(
                        edit.path.as_str(),
                        request.commit_message.as_str(),
                        edit.new_content.as_bytes(),
                        sha,
                    )
                    .branch(request.branch.as_str())
                    .send()
                    .await
            }
            None => {
                repos
                    .create_file(
                        edit.path.as_str(),
                        request.commit_message.as_str(),
                        edit.new_content.as_bytes(),
                    )
                    .branch(request.branch.as_str())
                    .send()
                    .await
            }
        };
        outcome.map(drop).map_err(to_forge_error)
    }

    /// Return the open pull request for `branch`, if one already exists.
    async fn find_open_pull_request(&self, repo: &RepoRef, branch: &str) -> Result<Option<PullRequestOutcome>> {
        let page = self
            .client
            .pulls(&repo.owner, &repo.name)
            .list()
            .head(head_ref(&repo.owner, branch))
            .state(State::Open)
            .send()
            .await
            .map_err(to_forge_error)?;
        page.items
            .into_iter()
            .next()
            .map(|pull_request| pull_request_outcome(pull_request, false))
            .transpose()
    }
}

#[async_trait]
impl Forge for GithubForge {
    #[tracing::instrument(skip(self))]
    async fn list_files(&self, repo: &RepoRef) -> Result<Vec<String>> {
        let branch = self.resolve_base_branch(repo).await?;
        let sha = self.branch_head_sha(repo, &branch).await?;
        let route = format!(
            "/repos/{owner}/{name}/git/trees/{sha}?recursive=1",
            owner = repo.owner,
            name = repo.name
        );
        let tree: serde_json::Value = self.client.get(route, None::<&()>).await.map_err(to_forge_error)?;
        blob_paths(&tree)
    }

    #[tracing::instrument(skip(self))]
    async fn read_file(&self, repo: &RepoRef, path: &str) -> Result<Option<String>> {
        let branch = self.resolve_base_branch(repo).await?;
        let found = self.read_at_branch(repo, path, &branch).await?;
        Ok(found.map(|(_, text)| text))
    }

    #[tracing::instrument(skip(self, request))]
    async fn submit_pull_request(&self, repo: &RepoRef, request: &PullRequestRequest) -> Result<PullRequestOutcome> {
        let base = self.resolve_base_branch(repo).await?;
        let base_sha = self.branch_head_sha(repo, &base).await?;
        self.ensure_branch(repo, &request.branch, &base_sha).await?;
        for (index, edit) in request.edits.iter().enumerate() {
            if let Err(error) = self.apply_edit(repo, request, edit).await {
                tracing::warn!(
                    owner = %repo.owner,
                    name = %repo.name,
                    branch = %request.branch,
                    path = %edit.path,
                    committed = index,
                    total = request.edits.len(),
                    %error,
                    "partial failure applying edits; prior edits remain committed on the branch"
                );
                return Err(UpdateError::Forge(partial_edit_failure_message(
                    &repo.owner,
                    &repo.name,
                    &request.branch,
                    &edit.path,
                    index,
                    request.edits.len(),
                    &error,
                )));
            }
        }
        if let Some(existing) = self.find_open_pull_request(repo, &request.branch).await? {
            return Ok(existing);
        }
        let pull_request = self
            .client
            .pulls(&repo.owner, &repo.name)
            .create(request.title.as_str(), request.branch.as_str(), base.as_str())
            .body(request.body.as_str())
            .send()
            .await
            .map_err(to_forge_error)?;
        pull_request_outcome(pull_request, true)
    }
}

/// Validate a GitHub Enterprise `base_url` before it is handed to `octocrab`.
///
/// Requires the `https` scheme and a non-empty host, guarding against SSRF via an
/// attacker-controlled base URL (ADR-0017). `http` is permitted only when the host is
/// `localhost` or `127.0.0.1`, so tests and local mirrors keep working.
fn validate_base_url(base_url: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(base_url)
        .map_err(|error| UpdateError::Forge(format!("invalid base_url `{base_url}`: {error}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| UpdateError::Forge(format!("base_url `{base_url}` must have a host")))?;
    let is_local_host = host == "localhost" || host == "127.0.0.1";
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if is_local_host => Ok(parsed),
        other => Err(UpdateError::Forge(format!(
            "base_url `{base_url}` must use https (http is only allowed for localhost/127.0.0.1), got scheme `{other}`"
        ))),
    }
}

/// Map any `octocrab` error to the update engine's forge error, without leaking credentials
/// (octocrab's error `Display` impls never include the auth token).
fn to_forge_error(error: octocrab::Error) -> UpdateError {
    UpdateError::Forge(error.to_string())
}

/// Whether `error` represents a `404 Not Found` response from the GitHub API.
fn is_not_found(error: &octocrab::Error) -> bool {
    matches!(error, octocrab::Error::GitHub { source, .. } if source.status_code.as_u16() == 404)
}

/// Whether `error` is GitHub's `422 Unprocessable Entity` response for a git reference
/// (branch/tag) that already exists, as opposed to some other validation failure (an invalid
/// SHA, a malformed ref name, a branch-protection rejection, ...).
fn is_reference_already_exists(error: &octocrab::Error) -> bool {
    match error {
        octocrab::Error::GitHub { source, .. } if source.status_code.as_u16() == 422 => {
            is_reference_exists_error(&source.message, source.errors.as_deref())
        }
        _ => false,
    }
}

/// Pure check for GitHub's "already exists" wording in a `422` error's top-level `message`
/// and/or nested `errors` entries. Isolated from the `octocrab` error type (whose
/// `GitHubError` is `#[non_exhaustive]` and cannot be constructed outside the crate) so it can
/// be unit tested directly against representative message strings.
fn is_reference_exists_error(message: &str, errors: Option<&[serde_json::Value]>) -> bool {
    let mentions_already_exists = |text: &str| text.to_ascii_lowercase().contains("already exists");
    if mentions_already_exists(message) {
        return true;
    }
    errors.into_iter().flatten().any(|entry| {
        entry
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(mentions_already_exists)
    })
}

/// The `owner:branch` filter GitHub expects for `head` when listing pull requests.
fn head_ref(owner: &str, branch: &str) -> String {
    format!("{owner}:{branch}")
}

/// Guard against the Contents API returning more than one entry for `path`, which happens when
/// `path` names a directory rather than a file (in which case GitHub returns one entry per
/// directory member instead of a single file body).
fn ensure_not_directory(path: &str, entry_count: usize) -> Result<()> {
    if entry_count > 1 {
        return Err(UpdateError::Forge(format!("path `{path}` is a directory, not a file")));
    }
    Ok(())
}

/// Format the diagnostic for a partial edit-application failure on `owner/name#branch`: edit
/// `index` (0-based) of `total` (`path`) failed with `error`, after `index` prior edits were
/// already committed to the branch.
fn partial_edit_failure_message(
    owner: &str,
    name: &str,
    branch: &str,
    path: &str,
    index: usize,
    total: usize,
    error: &UpdateError,
) -> String {
    let attempted = index + 1;
    format!(
        "failed to apply edit {attempted} of {total} ({path}) on {owner}/{name}#{branch}: {error} \
         ({index} edit(s) already committed to the branch)"
    )
}

/// Decode a fetched file's base64 content into UTF-8 text.
fn decode_content(content: &Content) -> Result<String> {
    let Some(encoded) = content.content.as_deref() else {
        return Err(UpdateError::Forge(format!("{} has no inline content", content.path)));
    };
    decode_base64_text(encoded).map_err(|message| UpdateError::Forge(format!("{}: {message}", content.path)))
}

/// Decode base64 (ignoring embedded whitespace, as GitHub wraps content at 60 columns) into
/// UTF-8 text.
fn decode_base64_text(encoded: &str) -> std::result::Result<String, String> {
    let cleaned: String = encoded.chars().filter(|character| !character.is_whitespace()).collect();
    let bytes = BASE64_STANDARD
        .decode(cleaned)
        .map_err(|error| format!("invalid base64 content: {error}"))?;
    String::from_utf8(bytes).map_err(|error| format!("content is not valid utf-8: {error}"))
}

/// Extract the repository-relative paths of every blob in a `git/trees?recursive=1` response.
///
/// # Errors
///
/// Returns [`UpdateError::Forge`] if the response is marked `truncated: true` (GitHub caps
/// recursive tree responses; a truncated response would silently omit files) or does not have
/// the expected shape.
fn blob_paths(tree: &serde_json::Value) -> Result<Vec<String>> {
    if tree.get("truncated").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err(UpdateError::Forge(
            "repository tree too large / truncated; cannot reliably list files".to_string(),
        ));
    }
    let entries = tree
        .get("tree")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| UpdateError::Forge("unexpected git tree response shape".to_string()))?;
    entries
        .iter()
        .filter(|entry| entry.get("type").and_then(serde_json::Value::as_str) == Some("blob"))
        .map(|entry| {
            entry
                .get("path")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| UpdateError::Forge("git tree entry is missing a path".to_string()))
        })
        .collect()
}

/// Build a [`PullRequestOutcome`] from an `octocrab` pull request response.
///
/// # Errors
///
/// Returns [`UpdateError::Forge`] if the response has no `html_url`, so callers never end up
/// with an outcome pointing at an empty link.
fn pull_request_outcome(pull_request: PullRequest, created: bool) -> Result<PullRequestOutcome> {
    let html_url = pull_request
        .html_url
        .ok_or_else(|| UpdateError::Forge("pull request response missing html_url".to_string()))?;
    Ok(PullRequestOutcome {
        number: Some(pull_request.number),
        url: html_url.to_string(),
        created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_ref_formats_as_owner_colon_branch() {
        assert_eq!(
            head_ref("Goldziher", "starmetal-forge/update-serde"),
            "Goldziher:starmetal-forge/update-serde"
        );
    }

    #[test]
    fn decode_base64_text_decodes_and_strips_github_line_wrapping() {
        // "hello world" base64-encoded, artificially wrapped like GitHub's content field.
        let wrapped = "aGVs\nbG8g\nd29y\nbGQ=\n";
        assert_eq!(decode_base64_text(wrapped).expect("decode"), "hello world");
    }

    #[test]
    fn decode_base64_text_rejects_invalid_base64() {
        let error = decode_base64_text("not-valid-base64!!!").expect_err("should fail");
        assert!(error.contains("invalid base64"), "unexpected error: {error}");
    }

    #[test]
    fn blob_paths_keeps_only_blob_entries() {
        let tree = serde_json::json!({
            "tree": [
                {"path": "Cargo.toml", "type": "blob"},
                {"path": "crates", "type": "tree"},
                {"path": "crates/starmetal-core/Cargo.toml", "type": "blob"},
            ]
        });
        let paths = blob_paths(&tree).expect("blob paths");
        assert_eq!(
            paths,
            vec!["Cargo.toml".to_string(), "crates/starmetal-core/Cargo.toml".to_string()]
        );
    }

    #[test]
    fn blob_paths_rejects_missing_tree_key() {
        let error = blob_paths(&serde_json::json!({})).expect_err("should fail");
        match error {
            UpdateError::Forge(message) => assert!(message.contains("unexpected git tree response shape")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn pull_request_outcome_reports_existing_pull_requests_as_not_created() {
        let pull_request: PullRequest = serde_json::from_value(serde_json::json!({
            "url": "https://api.github.com/repos/owner/repo/pulls/7",
            "id": 1,
            "number": 7,
            "html_url": "https://github.com/owner/repo/pull/7",
            "head": {"ref": "starmetal/update-branch", "sha": "abc123"},
            "base": {"ref": "main", "sha": "def456"},
        }))
        .expect("deserialize pull request");

        let outcome = pull_request_outcome(pull_request, false).expect("outcome");

        assert_eq!(outcome.number, Some(7));
        assert_eq!(outcome.url, "https://github.com/owner/repo/pull/7");
        assert!(!outcome.created);
    }

    #[test]
    fn pull_request_outcome_rejects_missing_html_url() {
        let pull_request: PullRequest = serde_json::from_value(serde_json::json!({
            "url": "https://api.github.com/repos/owner/repo/pulls/7",
            "id": 1,
            "number": 7,
            "head": {"ref": "starmetal/update-branch", "sha": "abc123"},
            "base": {"ref": "main", "sha": "def456"},
        }))
        .expect("deserialize pull request");

        let error = pull_request_outcome(pull_request, true).expect_err("should fail");
        match error {
            UpdateError::Forge(message) => assert!(message.contains("missing html_url")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn blob_paths_rejects_truncated_tree() {
        let tree = serde_json::json!({
            "truncated": true,
            "tree": [
                {"path": "Cargo.toml", "type": "blob"},
            ]
        });
        let error = blob_paths(&tree).expect_err("should fail");
        match error {
            UpdateError::Forge(message) => assert!(message.contains("truncated")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn blob_paths_accepts_untruncated_tree() {
        let tree = serde_json::json!({
            "truncated": false,
            "tree": [
                {"path": "Cargo.toml", "type": "blob"},
            ]
        });
        let paths = blob_paths(&tree).expect("blob paths");
        assert_eq!(paths, vec!["Cargo.toml".to_string()]);
    }

    #[test]
    fn is_reference_exists_error_matches_githubs_already_exists_message() {
        assert!(is_reference_exists_error("Reference already exists", None));
    }

    #[test]
    fn is_reference_exists_error_is_case_insensitive() {
        assert!(is_reference_exists_error("REFERENCE ALREADY EXISTS", None));
    }

    #[test]
    fn is_reference_exists_error_checks_nested_errors_array() {
        let errors =
            vec![serde_json::json!({"resource": "Ref", "code": "already_exists", "message": "already exists"})];
        assert!(is_reference_exists_error("Validation Failed", Some(&errors)));
    }

    #[test]
    fn is_reference_exists_error_rejects_unrelated_validation_failures() {
        assert!(!is_reference_exists_error(
            "Invalid request.\n\nsha is not a valid SHA",
            None
        ));
        assert!(!is_reference_exists_error("Validation Failed", None));
    }

    #[test]
    fn validate_base_url_accepts_https() {
        let url = validate_base_url("https://github.example.com/api/v3").expect("valid");
        assert_eq!(url.as_str(), "https://github.example.com/api/v3");
    }

    #[test]
    fn validate_base_url_accepts_http_localhost() {
        let url = validate_base_url("http://localhost:3000/api/v3").expect("valid");
        assert_eq!(url.host_str(), Some("localhost"));
    }

    #[test]
    fn validate_base_url_accepts_http_loopback_ip() {
        let url = validate_base_url("http://127.0.0.1:3000/api/v3").expect("valid");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
    }

    #[test]
    fn validate_base_url_rejects_http_for_remote_host() {
        let error = validate_base_url("http://github.example.com/api/v3").expect_err("should fail");
        match error {
            UpdateError::Forge(message) => assert!(message.contains("must use https"), "unexpected message: {message}"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn validate_base_url_rejects_unparseable_url() {
        let error = validate_base_url("not a url").expect_err("should fail");
        match error {
            UpdateError::Forge(message) => {
                assert!(message.contains("invalid base_url"), "unexpected message: {message}")
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn validate_base_url_rejects_non_http_scheme() {
        let error = validate_base_url("ftp://github.example.com/api/v3").expect_err("should fail");
        match error {
            UpdateError::Forge(message) => assert!(message.contains("scheme `ftp`"), "unexpected message: {message}"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn ensure_not_directory_accepts_zero_or_one_entries() {
        assert!(ensure_not_directory("Cargo.toml", 0).is_ok());
        assert!(ensure_not_directory("Cargo.toml", 1).is_ok());
    }

    #[test]
    fn ensure_not_directory_rejects_multiple_entries() {
        let error = ensure_not_directory("src", 3).expect_err("should fail");
        match error {
            UpdateError::Forge(message) => assert_eq!(message, "path `src` is a directory, not a file"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn partial_edit_failure_message_reports_path_and_progress() {
        let error = UpdateError::Forge("boom".to_string());
        let message =
            partial_edit_failure_message("acme", "widgets", "starmetal/bump-serde", "Cargo.toml", 2, 5, &error);
        assert_eq!(
            message,
            "failed to apply edit 3 of 5 (Cargo.toml) on acme/widgets#starmetal/bump-serde: forge error: boom \
             (2 edit(s) already committed to the branch)"
        );
    }

    // The default-branch cache is tested directly (not through `GithubForge`), so these tests
    // need neither a Tokio runtime nor a rustls crypto provider — building an `octocrab` client
    // would require both.

    #[test]
    fn default_branch_cache_returns_cached_value_within_ttl() {
        let cache = DefaultBranchCache::new(DEFAULT_BRANCH_CACHE_TTL);
        let key: RepoKey = ("octocat".to_string(), "hello-world".to_string());
        cache.put(key.clone(), "main".to_string());
        assert_eq!(cache.get(&key), Some("main".to_string()));
    }

    #[test]
    fn default_branch_cache_misses_for_unknown_key() {
        let cache = DefaultBranchCache::new(DEFAULT_BRANCH_CACHE_TTL);
        let key: RepoKey = ("octocat".to_string(), "hello-world".to_string());
        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn default_branch_cache_expires_after_ttl() {
        // A zero TTL makes every stored entry immediately stale, so no manufactured (and
        // potentially underflowing) past `Instant` is needed.
        let cache = DefaultBranchCache::new(Duration::ZERO);
        let key: RepoKey = ("octocat".to_string(), "hello-world".to_string());
        cache.put(key.clone(), "main".to_string());
        assert_eq!(cache.get(&key), None);
    }
}
