//! End-to-end proof that a `group` repository (ADR-0019) merges its members over the normal
//! ecosystem HTTP adapter: a merged PyPI simple index unions both members' versions, and an artifact
//! that only the second member holds is served through first-match fallthrough.
//!
//! The two members are memory-backed `CachingPackageService`s pre-populated by publishing distinct
//! data — no network, no upstream — so the test is deterministic and offline. The group is mounted
//! through the real `build_app` group path with a per-repository `AppState`.

use std::net::SocketAddr;
use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use bytes::Bytes;
use starmetal_adapters::cargo::upstream::CargoUpstreamClient;
use starmetal_adapters::hex::upstream::HexUpstreamClient;
use starmetal_adapters::maven::upstream::MavenUpstreamClient;
use starmetal_adapters::npm::upstream::NpmUpstreamClient;
use starmetal_adapters::nuget::upstream::NuGetUpstreamClient;
use starmetal_adapters::pubdev::upstream::PubUpstreamClient;
use starmetal_adapters::pypi::upstream::PypiUpstreamClient;
use starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient;
use starmetal_core::config::{Config, RepositoryConfig};
use starmetal_core::package::{Ecosystem, PackageName};
use starmetal_core::policy::PolicyConfig;
use starmetal_core::ports::{PackageService, PublishingService, StatisticsService};
use starmetal_core::publishing::{ProtocolMetadata, PublishRequest, PublishedArtifact};
use starmetal_core::repository::RepositoryKind;
use starmetal_git::GixMirror;
use starmetal_server::state::{AppState, GroupMount, UpstreamClients};
use starmetal_service::{CachingPackageService, GroupPackageService};
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

/// A full set of (unused) upstream clients. The group flow never fetches through these — every read
/// resolves against the members — so the PyPI client here stays cache-empty, which forces the PyPI
/// adapter to rebuild the simple index from the group-merged listing rather than a cached body.
fn unused_upstreams() -> UpstreamClients {
    let dummy = "https://unused.invalid".to_string();
    UpstreamClients {
        pypi_upstream: Arc::new(PypiUpstreamClient::new(dummy.clone())),
        cargo_upstream: Arc::new(CargoUpstreamClient::new(dummy.clone(), dummy.clone())),
        npm_upstream: Arc::new(NpmUpstreamClient::new(dummy.clone())),
        hex_upstream: Arc::new(HexUpstreamClient::new(dummy.clone(), dummy.clone())),
        maven_upstream: Arc::new(MavenUpstreamClient::new(dummy.clone())),
        rubygems_upstream: Arc::new(RubyGemsUpstreamClient::new(dummy.clone())),
        nuget_upstream: Arc::new(NuGetUpstreamClient::new(dummy.clone())),
        pub_upstream: Arc::new(PubUpstreamClient::new(dummy)),
        // The group flow never reaches Go, Zig, or Swift (this test mounts only a PyPI group), so a
        // mirror over a leaked-but-never-touched cache dir is a fine placeholder for each.
        go_mirror: Arc::new(GixMirror::new(
            tempfile::tempdir().expect("go mirror cache tempdir").keep(),
            std::time::Duration::from_secs(300),
        )),
        zig_mirror: Arc::new(GixMirror::new(
            tempfile::tempdir().expect("zig mirror cache tempdir").keep(),
            std::time::Duration::from_secs(300),
        )),
        swift_mirror: Arc::new(GixMirror::new(
            tempfile::tempdir().expect("swift mirror cache tempdir").keep(),
            std::time::Duration::from_secs(300),
        )),
        swift_archive_cache: Arc::new(starmetal_adapters::swift::upstream::SwiftArchiveCache::new()),
    }
}

struct GroupServer {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl GroupServer {
    /// Start a server whose only mount is a PyPI `group` named `combined` over the two members.
    async fn start(member_a: Arc<CachingPackageService>, member_b: Arc<CachingPackageService>) -> Self {
        let group = Arc::new(GroupPackageService::new(
            Ecosystem::PyPI,
            vec![member_a as Arc<dyn PackageService>, member_b as Arc<dyn PackageService>],
        ));

        let mut group_mounts = std::collections::HashMap::new();
        group_mounts.insert(
            "combined".to_string(),
            GroupMount {
                package_service: group.clone() as Arc<dyn PackageService>,
                publishing_service: group.clone() as Arc<dyn PublishingService>,
                statistics_service: group.clone() as Arc<dyn StatisticsService>,
            },
        );

        let config = Config {
            repositories: vec![RepositoryConfig {
                name: "combined".to_string(),
                kind: RepositoryKind::Group,
                ecosystem: Ecosystem::PyPI,
                members: vec!["member-a".to_string(), "member-b".to_string()],
            }],
            ..Config::default()
        };

        let state = AppState::new(
            config,
            group.clone() as Arc<dyn PackageService>,
            group.clone() as Arc<dyn PublishingService>,
            group as Arc<dyn StatisticsService>,
            unused_upstreams(),
        )
        .with_group_mounts(Arc::new(group_mounts));

        let app = starmetal_server::app::build_app(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("server");
        });
        Self {
            addr,
            shutdown: shutdown_tx,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

#[tokio::test]
async fn group_merges_member_versions_and_serves_first_match_artifacts() {
    // Member A holds widget 1.0.0; member B holds widget 2.0.0 (only). The group is [A, B].
    let member_a = member_with_version("1.0.0", "widget-1.0.0.tar.gz", b"widget-1.0.0-payload").await;
    let member_b = member_with_version("2.0.0", "widget-2.0.0.tar.gz", b"widget-2.0.0-payload").await;
    let server = GroupServer::start(member_a, member_b).await;
    let client = reqwest::Client::new();

    // The merged PyPI simple index unions both members' versions.
    let index = client
        .get(format!("{}/combined/simple/widget/", server.base_url()))
        .header(reqwest::header::ACCEPT, "application/vnd.pypi.simple.v1+json")
        .send()
        .await
        .expect("simple index request");
    assert_eq!(index.status(), reqwest::StatusCode::OK, "merged index should be served");
    let index_json: serde_json::Value = index.json().await.expect("index json");

    let versions: AHashSet<String> = index_json["versions"]
        .as_array()
        .expect("versions array")
        .iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect();
    assert!(
        versions.contains("1.0.0") && versions.contains("2.0.0"),
        "merged index must union both members' versions, got: {versions:?}"
    );

    let filenames: AHashSet<String> = index_json["files"]
        .as_array()
        .expect("files array")
        .iter()
        .filter_map(|file| file["filename"].as_str().map(str::to_string))
        .collect();
    assert!(
        filenames.contains("widget-1.0.0.tar.gz") && filenames.contains("widget-2.0.0.tar.gz"),
        "merged index must list files from both members, got: {filenames:?}"
    );

    // The 2.0.0 artifact exists only in the second member: serving it proves first-match fallthrough
    // past member A (which lacks the version entirely) to member B.
    let artifact = client
        .get(format!(
            "{}/combined/packages/widget/2.0.0/widget-2.0.0.tar.gz",
            server.base_url()
        ))
        .send()
        .await
        .expect("artifact request");
    assert_eq!(
        artifact.status(),
        reqwest::StatusCode::OK,
        "second member's artifact should be served through the group"
    );
    let body = artifact.bytes().await.expect("artifact bytes");
    assert_eq!(
        body.as_ref(),
        b"widget-2.0.0-payload",
        "the group must serve the second member's artifact bytes verbatim"
    );

    // The first member's artifact is likewise served.
    let first = client
        .get(format!(
            "{}/combined/packages/widget/1.0.0/widget-1.0.0.tar.gz",
            server.base_url()
        ))
        .send()
        .await
        .expect("first artifact request");
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    assert_eq!(first.bytes().await.expect("bytes").as_ref(), b"widget-1.0.0-payload");

    server.shutdown();
}
