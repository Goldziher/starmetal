//! Live, opt-in tests against the real GitHub API.
//!
//! These are `#[ignore]`d because they need network access and a real token; they are not run
//! by `cargo test` or CI by default. Run manually with:
//!
//! ```sh
//! export STARMETAL_TEST_GITHUB_TOKEN=ghp_...
//! export STARMETAL_TEST_GITHUB_REPO_OWNER=your-org
//! export STARMETAL_TEST_GITHUB_REPO_NAME=your-repo
//! cargo test -p starmetal-forge --test github_live -- --ignored
//! ```
//!
//! The token needs `repo` scope (or fine-grained `contents: read` + `pull_requests: write`)
//! on the target repository. Use a disposable test repository — this exercises `list_files`,
//! which only reads, but the crate's other live coverage (branch/PR creation) is left to
//! manual verification to avoid leaving stray branches/PRs in shared repositories.

use starmetal_forge::GithubForge;
use starmetal_update_core::ports::{Forge, RepoRef};

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set to run this live test"))
}

#[tokio::test]
#[ignore]
async fn list_files_reads_real_repository_tree() {
    let token = env_var("STARMETAL_TEST_GITHUB_TOKEN");
    let owner = env_var("STARMETAL_TEST_GITHUB_REPO_OWNER");
    let name = env_var("STARMETAL_TEST_GITHUB_REPO_NAME");

    let forge = GithubForge::new(token).expect("build GithubForge");
    let repo = RepoRef {
        owner,
        name,
        base_branch: None,
    };

    let files = forge.list_files(&repo).await.expect("list_files should succeed");

    assert!(!files.is_empty(), "expected at least one file in the repository tree");
}
