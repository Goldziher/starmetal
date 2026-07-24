use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use starmetal_update_core::config::UpdateConfig;
use starmetal_update_core::dependency::Dependency;
use starmetal_update_core::error::{Result, UpdateError};
use starmetal_update_core::ports::{Datasource, FileEdit, Forge, Manager, PullRequestRequest, RepoRef, Versioning};
use starmetal_update_core::update::DependencyUpdate;

/// Directory names skipped when walking a local repository for manifests.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".venv", "vendor"];

/// Maximum directory depth walked when scanning a local repository.
const MAX_SCAN_DEPTH: usize = 24;

/// Proposed updates discovered by a scan, grouped for reporting.
#[derive(Debug, Clone, Default)]
pub struct UpdatePlan {
    /// All proposed updates, in discovery order.
    pub updates: Vec<DependencyUpdate>,
}

impl UpdatePlan {
    /// Whether the plan contains no proposed updates.
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }

    /// Number of proposed updates.
    pub fn len(&self) -> usize {
        self.updates.len()
    }
}

/// Result of a run that submits updates to a forge.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// The updates that were proposed.
    pub updates: Vec<DependencyUpdate>,
    /// The pull request that was opened or updated, if any updates were found.
    pub pull_request: Option<starmetal_update_core::ports::PullRequestOutcome>,
}

/// Composes the update ports into scan and run workflows.
pub struct UpdateEngine {
    managers: Vec<Arc<dyn Manager>>,
    versioning: HashMap<String, Arc<dyn Versioning>>,
    datasource: Arc<dyn Datasource>,
    config: UpdateConfig,
}

impl UpdateEngine {
    /// Build an engine from its ports and configuration.
    ///
    /// `versioning` schemes are indexed by their [`Versioning::scheme`] identifier,
    /// which must match the `versioning` field a [`Manager`] sets on each dependency.
    pub fn new(
        managers: Vec<Arc<dyn Manager>>,
        versioning: Vec<Arc<dyn Versioning>>,
        datasource: Arc<dyn Datasource>,
        config: UpdateConfig,
    ) -> Self {
        let versioning = versioning
            .into_iter()
            .map(|scheme| (scheme.scheme().to_string(), scheme))
            .collect();
        Self {
            managers,
            versioning,
            datasource,
            config,
        }
    }

    /// The first manager that handles `path`, if any.
    fn manager_for(&self, path: &str) -> Option<&Arc<dyn Manager>> {
        self.managers.iter().find(|manager| manager.matches_file(path))
    }

    /// Compute the proposed update for a single dependency, if a newer version exists.
    async fn determine_update(&self, dependency: &Dependency) -> Result<Option<DependencyUpdate>> {
        if self.config.is_ignored(dependency.name.as_str()) {
            return Ok(None);
        }

        let Some(scheme) = self.versioning.get(&dependency.versioning) else {
            tracing::debug!(
                dependency = dependency.name.as_str(),
                versioning = dependency.versioning,
                "no versioning scheme registered; skipping"
            );
            return Ok(None);
        };

        // Baseline concrete version the manifest currently allows.
        let Some(current) = scheme.min_version(&dependency.current_value) else {
            return Ok(None);
        };

        let releases = self
            .datasource
            .get_releases(dependency.ecosystem, &dependency.name)
            .await?;

        // Eligible releases: valid, not yanked, and stable unless pre-releases are allowed.
        let eligible: Vec<&str> = releases
            .iter()
            .filter(|release| !release.yanked && scheme.is_valid(&release.version))
            .filter(|release| self.config.allow_prerelease || scheme.is_stable(&release.version))
            .map(|release| release.version.as_str())
            .collect();

        // Prefer an upgrade: the greatest eligible release strictly newer than the baseline.
        if let Some(target) = greatest(scheme.as_ref(), &eligible)
            && scheme.compare(&target, &current) == Some(Ordering::Greater)
        {
            return Ok(self.build_update(dependency, scheme.as_ref(), &current, &target));
        }

        // No upgrade exists. If the currently-resolved version is itself yanked, propose a
        // rollback to the greatest eligible release below it.
        let current_yanked = releases
            .iter()
            .any(|release| release.yanked && scheme.compare(&release.version, &current) == Some(Ordering::Equal));
        if current_yanked {
            let below: Vec<&str> = eligible
                .iter()
                .copied()
                .filter(|version| scheme.compare(version, &current) == Some(Ordering::Less))
                .collect();
            if let Some(target) = greatest(scheme.as_ref(), &below) {
                return Ok(self.build_update(dependency, scheme.as_ref(), &current, &target));
            }
        }

        Ok(None)
    }

    /// Build a [`DependencyUpdate`] rewriting `dependency` from `current` to `target`,
    /// or `None` if no representable rewrite or classification applies.
    fn build_update(
        &self,
        dependency: &Dependency,
        scheme: &dyn Versioning,
        current: &str,
        target: &str,
    ) -> Option<DependencyUpdate> {
        let new_value = scheme.get_new_value(&dependency.current_value, self.config.range_strategy, target)?;
        if new_value == dependency.current_value {
            return None;
        }
        let update_type = scheme.diff(current, target)?;
        Some(DependencyUpdate {
            dependency: dependency.clone(),
            update_type,
            new_value,
            new_version: target.to_string(),
        })
    }

    /// Extract dependencies from one manifest and compute their updates.
    pub async fn scan_content(&self, path: &str, content: &str) -> Result<Vec<DependencyUpdate>> {
        let Some(manager) = self.manager_for(path) else {
            return Ok(Vec::new());
        };
        let dependencies = manager.extract(path, content)?;
        let mut updates = Vec::new();
        for dependency in &dependencies {
            if let Some(update) = self.determine_update(dependency).await? {
                updates.push(update);
            }
        }
        Ok(updates)
    }

    /// Scan a local directory tree for manifests and propose updates.
    pub async fn scan_local(&self, root: &Path) -> Result<UpdatePlan> {
        let manifests = self.collect_manifests(root)?;
        let mut plan = UpdatePlan::default();
        for manifest in manifests {
            let content = std::fs::read_to_string(&manifest)?;
            let path = manifest.to_string_lossy().into_owned();
            let updates = self.scan_content(&path, &content).await?;
            plan.updates.extend(updates);
        }
        Ok(plan)
    }

    /// Collect manifest files a compiled-in manager can handle under `root`.
    ///
    /// `root` may be a directory (walked recursively) or a single manifest file. A path that
    /// does not exist (or is unreadable) is a hard error, so a mistyped path is never silently
    /// reported as "no updates".
    fn collect_manifests(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let metadata = std::fs::metadata(root)
            .map_err(|error| UpdateError::Config(format!("cannot access scan path `{}`: {error}", root.display())))?;

        let mut found = Vec::new();
        if metadata.is_file() {
            if self.manager_for(&root.to_string_lossy()).is_some() {
                found.push(root.to_path_buf());
            } else {
                return Err(UpdateError::Config(format!(
                    "scan path `{}` is not a supported manifest",
                    root.display()
                )));
            }
        } else if metadata.is_dir() {
            self.walk(root, 0, &mut found)?;
        } else {
            return Err(UpdateError::Config(format!(
                "scan path `{}` is neither a file nor a directory",
                root.display()
            )));
        }
        found.sort();
        Ok(found)
    }

    fn walk(&self, dir: &Path, depth: usize, found: &mut Vec<PathBuf>) -> Result<()> {
        if depth >= MAX_SCAN_DEPTH {
            return Ok(());
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) => {
                // Surface (rather than silently swallow) an unreadable subdirectory, but keep
                // scanning the rest of the tree.
                tracing::warn!(directory = %dir.display(), %error, "skipping unreadable directory during scan");
                return Ok(());
            }
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if file_type.is_dir() {
                if SKIP_DIRS.contains(&name.as_ref()) || name.starts_with('.') {
                    continue;
                }
                self.walk(&path, depth + 1, found)?;
            } else if file_type.is_file() && self.manager_for(&path.to_string_lossy()).is_some() {
                found.push(path);
            }
        }
        Ok(())
    }

    /// Read and scan every manifest in a forge repository, returning proposed
    /// updates alongside the original content of each edited manifest.
    async fn collect_remote(
        &self,
        repo: &RepoRef,
        forge: &dyn Forge,
    ) -> Result<(Vec<DependencyUpdate>, HashMap<String, String>)> {
        let files = forge.list_files(repo).await?;
        let mut updates = Vec::new();
        // Preserve original content per manifest so edits stack cleanly.
        let mut file_contents: HashMap<String, String> = HashMap::new();

        for path in files {
            if self.manager_for(&path).is_none() {
                continue;
            }
            let Some(content) = forge.read_file(repo, &path).await? else {
                continue;
            };
            let file_updates = self.scan_content(&path, &content).await?;
            if !file_updates.is_empty() {
                file_contents.insert(path.clone(), content);
                updates.extend(file_updates);
            }
        }
        Ok((updates, file_contents))
    }

    /// Scan a forge repository and report proposed updates without submitting.
    pub async fn scan_remote(&self, repo: &RepoRef, forge: &dyn Forge) -> Result<UpdatePlan> {
        let (updates, _) = self.collect_remote(repo, forge).await?;
        Ok(UpdatePlan { updates })
    }

    /// Scan a forge repository and, if updates exist, open/update a pull request.
    pub async fn run(&self, repo: &RepoRef, forge: &dyn Forge) -> Result<RunOutcome> {
        let (updates, file_contents) = self.collect_remote(repo, forge).await?;

        if updates.is_empty() {
            return Ok(RunOutcome {
                updates,
                pull_request: None,
            });
        }

        let edits = self.build_edits(&updates, &file_contents)?;
        let request = PullRequestRequest {
            branch: "starmetal/update-dependencies".to_string(),
            title: pull_request_title(&updates),
            body: render_body(&updates),
            commit_message: pull_request_title(&updates),
            edits,
        };
        let outcome = forge.submit_pull_request(repo, &request).await?;
        Ok(RunOutcome {
            updates,
            pull_request: Some(outcome),
        })
    }

    /// Apply every update to its manifest, producing one [`FileEdit`] per file.
    fn build_edits(
        &self,
        updates: &[DependencyUpdate],
        file_contents: &HashMap<String, String>,
    ) -> Result<Vec<FileEdit>> {
        let mut edited: HashMap<String, String> = file_contents.clone();
        for update in updates {
            let path = &update.dependency.file_path;
            let manager = self
                .manager_for(path)
                .ok_or_else(|| UpdateError::Unsupported(format!("no manager for {path}")))?;
            let content = edited
                .get(path)
                .ok_or_else(|| UpdateError::manager(manager.name(), format!("missing content for {path}")))?;
            let next = manager.apply_update(content, &update.dependency, &update.new_value)?;
            edited.insert(path.clone(), next);
        }
        let mut edits: Vec<FileEdit> = edited
            .into_iter()
            .map(|(path, new_content)| FileEdit { path, new_content })
            .collect();
        edits.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(edits)
    }
}

/// Return the greatest of `versions` under `scheme`'s ordering, if any.
fn greatest(scheme: &dyn Versioning, versions: &[&str]) -> Option<String> {
    let mut best: Option<&str> = None;
    for &version in versions {
        let is_better = match best {
            None => true,
            Some(current_best) => scheme.compare(version, current_best) == Some(Ordering::Greater),
        };
        if is_better {
            best = Some(version);
        }
    }
    best.map(str::to_string)
}

/// A concise pull-request title summarizing the update count.
fn pull_request_title(updates: &[DependencyUpdate]) -> String {
    if updates.len() == 1 {
        let update = &updates[0];
        format!(
            "chore(deps): update {} to {}",
            update.dependency.name, update.new_version
        )
    } else {
        format!("chore(deps): update {} dependencies", updates.len())
    }
}

/// Render a markdown body listing each proposed update.
fn render_body(updates: &[DependencyUpdate]) -> String {
    let mut body = String::from("Automated dependency updates from Starmetal.\n\n");
    body.push_str("| Package | Type | Change |\n");
    body.push_str("| --- | --- | --- |\n");
    for update in updates {
        body.push_str(&format!(
            "| `{}` | {} | `{}` → `{}` |\n",
            update.dependency.name, update.update_type, update.dependency.current_value, update.new_value
        ));
    }
    body
}
