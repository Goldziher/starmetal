//! Group repository (ADR-0019) precedence and tolerance semantics that the two-member
//! `group_repository.rs` test does not exercise: unioning versions across *three* members, first-match
//! fallthrough past more than one miss, earlier-member-wins on a duplicated version, and tolerating a
//! member whose `list_versions` errors outright.
//!
//! Per `crates/starmetal-service/src/group.rs`, `GroupPackageService::list_versions` unions every
//! member's listing via `merge_version_lists` (crates/starmetal-service/src/facets.rs:29-41), keeping
//! only the *first* occurrence of a duplicated version string -- so an earlier member wins that
//! version's `yanked` flag -- and skips a member whose `list_versions` call errors rather than failing
//! the whole group (group.rs:67-86). `get_version_metadata`/`get_artifact` are first-match: the first
//! member that resolves the coordinate wins and later members are never consulted (group.rs:88-131).
//! The PyPI simple-index adapter (`build_local_project`,
//! crates/starmetal-adapters/src/pypi/mod.rs:273-297) calls `list_versions` once and then
//! `get_version_metadata` per version to build the `files` array, so a duplicated version's listed
//! filename also reflects first-match metadata resolution, not just the `list_versions` merge.
//!
//! All members are memory-backed `CachingPackageService`s pre-populated by publishing distinct data --
//! no network, no upstream -- so every test is deterministic and offline. The group is mounted through
//! `TestServer`'s config-driven group path (`TestServerBuilder::with_group_members`), which seeds
//! physically-distinct members since production shares one caching service per ecosystem across every
//! member and these tests need genuinely different backing data to exercise union/first-match/tolerance.

use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use bytes::Bytes;
use starmetal_core::config::RepositoryConfig;
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::policy::PolicyConfig;
use starmetal_core::ports::{PackageService, PublishingService};
use starmetal_core::publishing::{ProtocolMetadata, PublishRequest, PublishedArtifact};
use starmetal_core::repository::RepositoryKind;
use starmetal_integration_tests::TestServer;
use starmetal_service::CachingPackageService;
use starmetal_storage::OpenDalStorage;

/// A memory-backed PyPI member service pre-populated with a single published version + artifact.
async fn member_with_version(version: &str, filename: &str, data: &[u8]) -> Arc<CachingPackageService> {
    let storage = OpenDalStorage::memory().expect("memory storage");
    // No upstream clients: the member serves only what has been published into it, and any lookup
    // for a version it lacks errors out (which the group treats as a miss and tries the next member).
    let service = Arc::new(CachingPackageService::new(
        Arc::new(storage),
        AHashMap::new(),
        PolicyConfig::default(),
    ));
    service
        .publish_package(PublishRequest {
            ecosystem: Ecosystem::PyPI,
            name: PackageName::new("widget"),
            version: version.to_string(),
            license: Some("MIT".to_string()),
            yanked: false,
            listed: true,
            artifacts: vec![PublishedArtifact {
                filename: filename.to_string(),
                data: Bytes::copy_from_slice(data),
                upstream_hashes: AHashMap::new(),
            }],
            protocol_metadata: ProtocolMetadata::default_for(Ecosystem::PyPI),
            allow_overwrite: false,
            allow_shadowing: true,
            repository: None,
        })
        .await
        .expect("member publish should succeed");
    service
}

/// A memory-backed PyPI member service with nothing published and no upstream: any lookup for
/// "widget" errors out, simulating a member that is entirely absent from the package.
async fn empty_member() -> Arc<CachingPackageService> {
    let storage = OpenDalStorage::memory().expect("memory storage");
    Arc::new(CachingPackageService::new(
        Arc::new(storage),
        AHashMap::new(),
        PolicyConfig::default(),
    ))
}

/// Build a 3-repository-member group config named "combined" for the PyPI ecosystem. The member names
/// are placeholders: `TestServerBuilder::with_group_members` supplies the real backing services.
fn three_member_group_config(config: &mut starmetal_core::config::Config) {
    config.repositories = vec![RepositoryConfig {
        name: "combined".to_string(),
        kind: RepositoryKind::Group,
        ecosystem: Ecosystem::PyPI,
        members: vec!["member-a".to_string(), "member-b".to_string(), "member-c".to_string()],
    }];
}

/// Fetch the merged PyPI simple index for "widget" from `server` and return the parsed JSON body.
async fn fetch_widget_index(client: &reqwest::Client, server: &TestServer) -> serde_json::Value {
    let index = client
        .get(format!("{}/combined/simple/widget/", server.base_url()))
        .header(reqwest::header::ACCEPT, "application/vnd.pypi.simple.v1+json")
        .send()
        .await
        .expect("simple index request");
    assert_eq!(index.status(), reqwest::StatusCode::OK, "merged index should be served");
    index.json().await.expect("index json")
}

#[tokio::test]
async fn should_union_versions_across_three_members() {
    // Member A holds only 1.0.0, B holds only 2.0.0, C holds only 3.0.0. The group is [A, B, C].
    let member_a = member_with_version("1.0.0", "widget-1.0.0.tar.gz", b"widget-1.0.0-payload").await;
    let member_b = member_with_version("2.0.0", "widget-2.0.0.tar.gz", b"widget-2.0.0-payload").await;
    let member_c = member_with_version("3.0.0", "widget-3.0.0.tar.gz", b"widget-3.0.0-payload").await;

    let server = TestServer::builder()
        .configure(three_member_group_config)
        .with_group_members(
            "combined",
            vec![
                member_a as Arc<dyn PackageService>,
                member_b as Arc<dyn PackageService>,
                member_c as Arc<dyn PackageService>,
            ],
        )
        .start()
        .await;
    let client = reqwest::Client::new();

    let index_json = fetch_widget_index(&client, &server).await;

    let versions: AHashSet<String> = index_json["versions"]
        .as_array()
        .expect("versions array")
        .iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect();
    assert!(
        versions.contains("1.0.0") && versions.contains("2.0.0") && versions.contains("3.0.0"),
        "merged index must union all three members' versions, got: {versions:?}"
    );

    let filenames: AHashSet<String> = index_json["files"]
        .as_array()
        .expect("files array")
        .iter()
        .filter_map(|file| file["filename"].as_str().map(str::to_string))
        .collect();
    assert!(
        filenames.contains("widget-1.0.0.tar.gz")
            && filenames.contains("widget-2.0.0.tar.gz")
            && filenames.contains("widget-3.0.0.tar.gz"),
        "merged index must list files from all three members, got: {filenames:?}"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_serve_first_match_across_three_members() {
    // Member A holds only 1.0.0, member B holds only 2.0.0, member C holds only 3.0.0. Fetching 3.0.0
    // proves first-match fallthrough past both A and B (which lack it entirely) to C.
    let member_a = member_with_version("1.0.0", "widget-1.0.0.tar.gz", b"widget-1.0.0-payload").await;
    let member_b = member_with_version("2.0.0", "widget-2.0.0.tar.gz", b"widget-2.0.0-payload").await;
    let member_c = member_with_version("3.0.0", "widget-3.0.0.tar.gz", b"widget-3.0.0-payload").await;

    let server = TestServer::builder()
        .configure(three_member_group_config)
        .with_group_members(
            "combined",
            vec![
                member_a as Arc<dyn PackageService>,
                member_b as Arc<dyn PackageService>,
                member_c as Arc<dyn PackageService>,
            ],
        )
        .start()
        .await;
    let client = reqwest::Client::new();

    let third = client
        .get(format!(
            "{}/combined/packages/widget/3.0.0/widget-3.0.0.tar.gz",
            server.base_url()
        ))
        .send()
        .await
        .expect("third-member artifact request");
    assert_eq!(
        third.status(),
        reqwest::StatusCode::OK,
        "the third member's artifact should be served through the group"
    );
    assert_eq!(
        third.bytes().await.expect("third artifact bytes").as_ref(),
        b"widget-3.0.0-payload",
        "the group must serve the third member's artifact bytes verbatim, past both A and B misses"
    );

    let first = client
        .get(format!(
            "{}/combined/packages/widget/1.0.0/widget-1.0.0.tar.gz",
            server.base_url()
        ))
        .send()
        .await
        .expect("first-member artifact request");
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    assert_eq!(
        first.bytes().await.expect("first artifact bytes").as_ref(),
        b"widget-1.0.0-payload"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_prefer_earlier_member_on_duplicate_version() {
    // Members A and B both publish version "9.9.9", but with different filenames/bytes. Per
    // `merge_version_lists` (facets.rs:29-41), the version is kept the first time it is seen in member
    // order, and `build_local_project` (pypi/mod.rs:273-297) resolves each version's files via
    // first-match `get_version_metadata` -- so the merged index's 9.9.9 entry must reflect member A's
    // filename, never member B's.
    let member_a = member_with_version("9.9.9", "widget-9.9.9-a.tar.gz", b"member-a-payload").await;
    let member_b = member_with_version("9.9.9", "widget-9.9.9-b.tar.gz", b"member-b-payload").await;
    let member_c = member_with_version("3.0.0", "widget-3.0.0.tar.gz", b"widget-3.0.0-payload").await;

    let server = TestServer::builder()
        .configure(three_member_group_config)
        .with_group_members(
            "combined",
            vec![
                member_a as Arc<dyn PackageService>,
                member_b as Arc<dyn PackageService>,
                member_c as Arc<dyn PackageService>,
            ],
        )
        .start()
        .await;
    let client = reqwest::Client::new();

    let index_json = fetch_widget_index(&client, &server).await;

    let versions: Vec<&str> = index_json["versions"]
        .as_array()
        .expect("versions array")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    let occurrences = versions.iter().filter(|&&version| version == "9.9.9").count();
    assert_eq!(
        occurrences, 1,
        "the duplicated version must be deduplicated to a single entry, got: {versions:?}"
    );

    let duplicate_files: Vec<&str> = index_json["files"]
        .as_array()
        .expect("files array")
        .iter()
        .filter(|file| file["filename"].as_str().is_some_and(|name| name.contains("9.9.9")))
        .filter_map(|file| file["filename"].as_str())
        .collect();
    assert_eq!(
        duplicate_files,
        vec!["widget-9.9.9-a.tar.gz"],
        "the earlier member (A) must win the duplicated version's listed filename, got: {duplicate_files:?}"
    );

    // Fetching the version's artifact confirms the same earlier-member precedence at the byte level:
    // the group resolves through member A's stored artifact and never reaches member B's.
    let artifact = client
        .get(format!(
            "{}/combined/packages/widget/9.9.9/widget-9.9.9-a.tar.gz",
            server.base_url()
        ))
        .send()
        .await
        .expect("duplicate-version artifact request");
    assert_eq!(artifact.status(), reqwest::StatusCode::OK);
    assert_eq!(
        artifact.bytes().await.expect("duplicate artifact bytes").as_ref(),
        b"member-a-payload",
        "the group must serve member A's payload for the duplicated version"
    );

    server.shutdown();
}

#[tokio::test]
async fn should_tolerate_a_member_that_errors_on_list_versions() {
    // Member A holds widget versions; member B is entirely empty (nothing published, no upstream), so
    // its `list_versions` call for "widget" errors. Per `GroupPackageService::list_versions`
    // (group.rs:67-86), a member error is skipped rather than sinking the whole group as long as at
    // least one member succeeds. ~keep
    let member_a = member_with_version("1.0.0", "widget-1.0.0.tar.gz", b"widget-1.0.0-payload").await;
    let member_b = empty_member().await;
    let member_c = member_with_version("3.0.0", "widget-3.0.0.tar.gz", b"widget-3.0.0-payload").await;

    let server = TestServer::builder()
        .configure(three_member_group_config)
        .with_group_members(
            "combined",
            vec![
                member_a as Arc<dyn PackageService>,
                member_b as Arc<dyn PackageService>,
                member_c as Arc<dyn PackageService>,
            ],
        )
        .start()
        .await;
    let client = reqwest::Client::new();

    let index_json = fetch_widget_index(&client, &server).await;

    let versions: AHashSet<String> = index_json["versions"]
        .as_array()
        .expect("versions array")
        .iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect();
    assert_eq!(
        versions,
        AHashSet::from_iter(["1.0.0".to_string(), "3.0.0".to_string()]),
        "the group must still return the good members' versions with the erroring member skipped, got: {versions:?}"
    );

    server.shutdown();
}
