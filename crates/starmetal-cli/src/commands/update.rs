use std::path::PathBuf;

use starmetal_core::error::{Result, StarmetalError};
use starmetal_forge::GithubForge;
use starmetal_ops::StarmetalRuntime;
use starmetal_update_core::UpdateConfig;
use starmetal_update_core::ports::RepoRef;
use starmetal_update_core::update::RangeStrategy;
use starmetal_updater::{RunOutcome, UpdatePlan};

use crate::OutputFormat;

/// Environment variable read for the GitHub token when `--token` is absent.
const GITHUB_TOKEN_ENV: &str = "STARMETAL_GITHUB_TOKEN";

/// Map an update-engine error onto the CLI's core error type.
fn to_core_error(error: starmetal_update_core::UpdateError) -> StarmetalError {
    StarmetalError::Update(error.to_string())
}

/// Build engine configuration from CLI flags.
fn build_config(pin: bool, allow_prerelease: bool) -> UpdateConfig {
    UpdateConfig {
        range_strategy: if pin { RangeStrategy::Pin } else { RangeStrategy::Auto },
        ignore: Vec::new(),
        allow_prerelease,
    }
}

/// Scan a local directory tree and report available updates.
pub async fn scan(
    runtime: &StarmetalRuntime,
    path: PathBuf,
    pin: bool,
    allow_prerelease: bool,
    output: OutputFormat,
) -> Result<()> {
    let engine = runtime.update_engine(build_config(pin, allow_prerelease));
    let plan = engine.scan_local(&path).await.map_err(to_core_error)?;
    print_plan(&plan, output)
}

/// Scan a GitHub repository and, unless `--dry-run`, open a pull request.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    runtime: &StarmetalRuntime,
    repository: String,
    token: Option<String>,
    dry_run: bool,
    pin: bool,
    allow_prerelease: bool,
    output: OutputFormat,
) -> Result<()> {
    let (owner, name) = repository
        .split_once('/')
        .ok_or_else(|| StarmetalError::Config("repository must be in <owner>/<name> form".to_string()))?;
    let repo = RepoRef::new(owner, name, None).map_err(to_core_error)?;

    let engine = runtime.update_engine(build_config(pin, allow_prerelease));

    // Reading the repository and opening a pull request both go through the authenticated
    // GitHub API, so a token is required even for `--dry-run`.
    let token = resolve_token(token)?;
    let forge = GithubForge::new(token).map_err(to_core_error)?;

    if dry_run {
        let plan = engine.scan_remote(&repo, &forge).await.map_err(to_core_error)?;
        print_plan(&plan, output)
    } else {
        let outcome = engine.run(&repo, &forge).await.map_err(to_core_error)?;
        print_outcome(&outcome, output)
    }
}

/// Resolve the GitHub token from the flag or the environment.
fn resolve_token(token: Option<String>) -> Result<String> {
    if let Some(token) = token {
        return Ok(token);
    }
    std::env::var(GITHUB_TOKEN_ENV).map_err(|_| {
        StarmetalError::Config(format!(
            "a GitHub token is required (pass --token or set {GITHUB_TOKEN_ENV})"
        ))
    })
}

/// Print a scan plan in the requested format.
fn print_plan(plan: &UpdatePlan, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => {
            let rows: Vec<_> = plan.updates.iter().map(update_json).collect();
            let value = serde_json::json!({ "updates": rows });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        OutputFormat::Human => {
            if plan.is_empty() {
                println!("no updates available");
            } else {
                println!("{} update(s) available:", plan.len());
                for update in &plan.updates {
                    println!(
                        "  {} [{}] {} -> {} ({})",
                        update.dependency.name,
                        update.dependency.dep_type,
                        update.dependency.current_value,
                        update.new_value,
                        update.update_type,
                    );
                }
            }
        }
    }
    Ok(())
}

/// Print a run outcome (updates plus any opened pull request).
fn print_outcome(outcome: &RunOutcome, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => {
            let rows: Vec<_> = outcome.updates.iter().map(update_json).collect();
            let pull_request = outcome
                .pull_request
                .as_ref()
                .map(|pr| serde_json::json!({ "number": pr.number, "url": pr.url, "created": pr.created }));
            let value = serde_json::json!({ "updates": rows, "pull_request": pull_request });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        OutputFormat::Human => match &outcome.pull_request {
            None => println!("no updates available"),
            Some(pr) => {
                let verb = if pr.created { "opened" } else { "updated" };
                println!(
                    "{} pull request with {} update(s): {}",
                    verb,
                    outcome.updates.len(),
                    pr.url
                );
            }
        },
    }
    Ok(())
}

/// Serialize a single proposed update to JSON.
fn update_json(update: &starmetal_update_core::update::DependencyUpdate) -> serde_json::Value {
    serde_json::json!({
        "name": update.dependency.name.to_string(),
        "ecosystem": update.dependency.ecosystem.to_string(),
        "dep_type": update.dependency.dep_type.to_string(),
        "file": update.dependency.file_path,
        "current_value": update.dependency.current_value,
        "new_value": update.new_value,
        "new_version": update.new_version,
        "update_type": update.update_type.to_string(),
    })
}
