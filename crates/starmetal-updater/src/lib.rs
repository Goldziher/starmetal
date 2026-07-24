//! The Starmetal dependency-update engine.
//!
//! [`UpdateEngine`] composes the update ports ([`starmetal_update_core::ports`]) into two
//! workflows: [`UpdateEngine::scan_local`] reports available updates for a local checkout,
//! and [`UpdateEngine::run`] opens (or updates) a pull request on a forge. Version lookups
//! flow through [`PackageServiceDatasource`], reusing the registry proxy's cache and policy.

mod datasource;
mod engine;

pub use datasource::PackageServiceDatasource;
pub use engine::{RunOutcome, UpdateEngine, UpdatePlan};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use starmetal_core::package::{Ecosystem, PackageName};
    use starmetal_update_core::config::UpdateConfig;
    use starmetal_update_core::dependency::{DepType, Dependency};
    use starmetal_update_core::error::Result;
    use starmetal_update_core::ports::{Datasource, Manager, Release, Versioning};
    use starmetal_update_core::update::{RangeStrategy, UpdateType};

    use super::UpdateEngine;

    /// A datasource returning a fixed release list, for engine tests.
    struct StubDatasource {
        releases: Vec<Release>,
    }

    #[async_trait]
    impl Datasource for StubDatasource {
        async fn get_releases(&self, _ecosystem: Ecosystem, _name: &PackageName) -> Result<Vec<Release>> {
            Ok(self.releases.clone())
        }
    }

    /// A minimal semver-ish scheme sufficient for engine tests (real logic lives in
    /// `starmetal-versioning`; this avoids a dev-dependency cycle).
    struct TestSemver;

    fn parse(version: &str) -> Option<(u64, u64, u64)> {
        let mut parts = version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().unwrap_or("0").parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        Some((major, minor, patch))
    }

    impl Versioning for TestSemver {
        fn scheme(&self) -> &'static str {
            "semver"
        }
        fn is_valid(&self, version: &str) -> bool {
            parse(version).is_some()
        }
        fn is_stable(&self, version: &str) -> bool {
            !version.contains('-') && parse(version).is_some()
        }
        fn compare(&self, left: &str, right: &str) -> Option<std::cmp::Ordering> {
            Some(parse(left)?.cmp(&parse(right)?))
        }
        fn matches(&self, version: &str, constraint: &str) -> bool {
            parse(version).is_some() && !constraint.is_empty()
        }
        fn min_version(&self, constraint: &str) -> Option<String> {
            let trimmed = constraint.trim_start_matches(['^', '~', '=']);
            parse(trimmed).map(|(a, b, c)| format!("{a}.{b}.{c}"))
        }
        fn diff(&self, current: &str, candidate: &str) -> Option<UpdateType> {
            let current = parse(current)?;
            let candidate = parse(candidate)?;
            match candidate.cmp(&current) {
                std::cmp::Ordering::Less => Some(UpdateType::Rollback),
                std::cmp::Ordering::Equal => None,
                std::cmp::Ordering::Greater if candidate.0 != current.0 => Some(UpdateType::Major),
                std::cmp::Ordering::Greater if candidate.1 != current.1 => Some(UpdateType::Minor),
                std::cmp::Ordering::Greater => Some(UpdateType::Patch),
            }
        }
        fn get_new_value(&self, current_value: &str, strategy: RangeStrategy, target: &str) -> Option<String> {
            if strategy == RangeStrategy::Pin {
                return Some(format!("={target}"));
            }
            let prefix = current_value
                .chars()
                .take_while(|c| ['^', '~', '='].contains(c))
                .collect::<String>();
            Some(format!("{prefix}{target}"))
        }
    }

    /// A manager returning one fixed dependency, for engine tests.
    struct StubManager {
        dependency: Dependency,
    }

    impl Manager for StubManager {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn ecosystem(&self) -> Ecosystem {
            Ecosystem::Cargo
        }
        fn matches_file(&self, path: &str) -> bool {
            path.ends_with("Cargo.toml")
        }
        fn extract(&self, _path: &str, _content: &str) -> Result<Vec<Dependency>> {
            Ok(vec![self.dependency.clone()])
        }
        fn apply_update(&self, content: &str, _dependency: &Dependency, new_value: &str) -> Result<String> {
            Ok(content.replace("OLD", new_value))
        }
    }

    fn dependency(current: &str) -> Dependency {
        Dependency {
            name: PackageName::new("serde"),
            ecosystem: Ecosystem::Cargo,
            current_value: current.to_string(),
            dep_type: DepType::Runtime,
            file_path: "Cargo.toml".to_string(),
            versioning: "semver".to_string(),
        }
    }

    fn engine(current: &str, releases: &[&str]) -> UpdateEngine {
        let releases = releases
            .iter()
            .map(|version| Release {
                version: version.to_string(),
                yanked: false,
                timestamp: None,
            })
            .collect();
        UpdateEngine::new(
            vec![Arc::new(StubManager {
                dependency: dependency(current),
            })],
            vec![Arc::new(TestSemver)],
            Arc::new(StubDatasource { releases }),
            UpdateConfig::default(),
        )
    }

    #[tokio::test]
    async fn proposes_newer_version() {
        let engine = engine("^1.2.3", &["1.2.3", "1.5.0", "1.4.0"]);
        let updates = engine.scan_content("Cargo.toml", "").await.unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].new_version, "1.5.0");
        assert_eq!(updates[0].new_value, "^1.5.0");
        assert_eq!(updates[0].update_type, UpdateType::Minor);
    }

    #[tokio::test]
    async fn no_update_when_already_latest() {
        let engine = engine("^1.5.0", &["1.2.3", "1.5.0"]);
        let updates = engine.scan_content("Cargo.toml", "").await.unwrap();
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn skips_prerelease_by_default() {
        let engine = engine("^1.2.3", &["1.2.3", "2.0.0-rc.1"]);
        let updates = engine.scan_content("Cargo.toml", "").await.unwrap();
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn skips_yanked_release() {
        let releases = vec![
            Release {
                version: "1.2.3".into(),
                yanked: false,
                timestamp: None,
            },
            Release {
                version: "1.9.0".into(),
                yanked: true,
                timestamp: None,
            },
        ];
        let engine = UpdateEngine::new(
            vec![Arc::new(StubManager {
                dependency: dependency("^1.2.3"),
            })],
            vec![Arc::new(TestSemver)],
            Arc::new(StubDatasource { releases }),
            UpdateConfig::default(),
        );
        let updates = engine.scan_content("Cargo.toml", "").await.unwrap();
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn ignores_configured_packages() {
        let config = UpdateConfig {
            ignore: vec!["serde".to_string()],
            ..UpdateConfig::default()
        };
        let engine = UpdateEngine::new(
            vec![Arc::new(StubManager {
                dependency: dependency("^1.2.3"),
            })],
            vec![Arc::new(TestSemver)],
            Arc::new(StubDatasource {
                releases: vec![Release {
                    version: "1.5.0".into(),
                    yanked: false,
                    timestamp: None,
                }],
            }),
            config,
        );
        let updates = engine.scan_content("Cargo.toml", "").await.unwrap();
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn rolls_back_when_current_version_is_yanked() {
        // The pinned 1.5.0 is yanked and nothing newer exists; the only good release is the
        // older 1.4.0, so the engine proposes a rollback.
        let releases = vec![
            Release {
                version: "1.4.0".into(),
                yanked: false,
                timestamp: None,
            },
            Release {
                version: "1.5.0".into(),
                yanked: true,
                timestamp: None,
            },
        ];
        let engine = UpdateEngine::new(
            vec![Arc::new(StubManager {
                dependency: dependency("1.5.0"),
            })],
            vec![Arc::new(TestSemver)],
            Arc::new(StubDatasource { releases }),
            UpdateConfig::default(),
        );
        let updates = engine.scan_content("Cargo.toml", "").await.unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].new_version, "1.4.0");
        assert_eq!(updates[0].update_type, UpdateType::Rollback);
    }
}
