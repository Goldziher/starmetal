use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use bytes::Bytes;
use depot_adapters::cargo::models::{cargo_entries_to_version_infos, cargo_entry_to_metadata};
use depot_adapters::cargo::upstream::CargoUpstreamClient;
use depot_adapters::hex::models::{hex_package_to_version_infos, hex_release_to_metadata};
use depot_adapters::hex::upstream::HexUpstreamClient;
use depot_adapters::maven::upstream::MavenUpstreamClient;
use depot_adapters::npm::models::{extract_version_infos, extract_version_metadata};
use depot_adapters::npm::upstream::NpmUpstreamClient;
use depot_adapters::nuget::upstream::NuGetUpstreamClient;
use depot_adapters::pubdev::upstream::PubUpstreamClient;
use depot_adapters::pypi::models::{pypi_files_to_metadata, pypi_project_to_version_infos};
use depot_adapters::pypi::upstream::PypiUpstreamClient;
use depot_adapters::rubygems::upstream::RubyGemsUpstreamClient;
use depot_adapters::{cargo, hex, maven, npm, nuget, pubdev, pypi, rubygems};
use depot_core::error::{DepotError, Result};
use depot_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use depot_core::ports::PackageService;
use depot_core::registry::cargo::{CargoConfig, CargoIndexEntry, sparse_index_path};
use depot_core::registry::hex::HexPackage;
use depot_core::registry::npm::NpmPackument;
use depot_core::registry::nuget::{NugetPackageVersions, NugetServiceIndex};
use depot_core::registry::pubdev::PubPackage;
use depot_core::registry::pypi::PypiProject;
use roxmltree::{Document, Node};
use tower::ServiceExt;

fn fixture(path: &str) -> &'static str {
    match path {
        "cargo/config.json" => include_str!("../fixtures/cargo/config.json"),
        "cargo/sample_index.ndjson" => include_str!("../fixtures/cargo/sample_index.ndjson"),
        "hex/sample-package.json" => include_str!("../fixtures/hex/sample-package.json"),
        "maven/maven-metadata.xml" => include_str!("../fixtures/maven/maven-metadata.xml"),
        "maven/sample-lib-1.2.0.pom" => include_str!("../fixtures/maven/sample-lib-1.2.0.pom"),
        "npm/sample-packument.json" => include_str!("../fixtures/npm/sample-packument.json"),
        "nuget/service-index.json" => include_str!("../fixtures/nuget/service-index.json"),
        "nuget/versions.json" => include_str!("../fixtures/nuget/versions.json"),
        "pub/sample-package.json" => include_str!("../fixtures/pub/sample-package.json"),
        "pypi/sample-project.json" => include_str!("../fixtures/pypi/sample-project.json"),
        "rubygems/versions" => include_str!("../fixtures/rubygems/versions"),
        "rubygems/info-rack" => include_str!("../fixtures/rubygems/info-rack"),
        _ => panic!("unknown fixture: {path}"),
    }
}

fn child_text<'a>(node: Node<'a, 'a>, tag_name: &str) -> Option<&'a str> {
    node.children()
        .find(|child| child.has_tag_name(tag_name))
        .and_then(|child| child.text())
}

fn compact_index_body_lines(fixture: &str) -> Vec<&str> {
    fixture
        .lines()
        .filter(|line| !line.is_empty())
        .skip_while(|line| *line != "---")
        .skip(1)
        .collect()
}

#[derive(Clone)]
struct RouteState {
    service: Arc<dyn PackageService>,
    pypi_upstream: Arc<PypiUpstreamClient>,
    npm_upstream: Arc<NpmUpstreamClient>,
    cargo_upstream: Arc<CargoUpstreamClient>,
    hex_upstream: Arc<HexUpstreamClient>,
    maven_upstream: Arc<MavenUpstreamClient>,
    rubygems_upstream: Arc<RubyGemsUpstreamClient>,
    nuget_upstream: Arc<NuGetUpstreamClient>,
    pub_upstream: Arc<PubUpstreamClient>,
}

impl RouteState {
    fn with_raw(
        fixtures: impl IntoIterator<Item = (Ecosystem, &'static str, &'static str)>,
    ) -> Self {
        Self {
            service: Arc::new(FixtureService::new(fixtures)),
            pypi_upstream: Arc::new(PypiUpstreamClient::new("http://127.0.0.1".into())),
            npm_upstream: Arc::new(NpmUpstreamClient::new("http://127.0.0.1".into())),
            cargo_upstream: Arc::new(CargoUpstreamClient::new(
                "http://127.0.0.1/index".into(),
                "http://127.0.0.1/crates".into(),
            )),
            hex_upstream: Arc::new(HexUpstreamClient::new(
                "http://127.0.0.1".into(),
                "http://127.0.0.1/repo".into(),
            )),
            maven_upstream: Arc::new(MavenUpstreamClient::new("http://127.0.0.1/maven2".into())),
            rubygems_upstream: Arc::new(RubyGemsUpstreamClient::new("http://127.0.0.1".into())),
            nuget_upstream: Arc::new(NuGetUpstreamClient::new(
                "http://127.0.0.1/v3/index.json".into(),
            )),
            pub_upstream: Arc::new(PubUpstreamClient::new("http://127.0.0.1".into())),
        }
    }
}

impl pypi::HasPypiState for RouteState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.service
    }

    fn pypi_upstream(&self) -> &Arc<PypiUpstreamClient> {
        &self.pypi_upstream
    }
}

impl npm::HasNpmState for RouteState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.service
    }

    fn npm_upstream(&self) -> &Arc<NpmUpstreamClient> {
        &self.npm_upstream
    }
}

impl cargo::HasCargoState for RouteState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.service
    }

    fn cargo_upstream(&self) -> &Arc<CargoUpstreamClient> {
        &self.cargo_upstream
    }
}

impl hex::HasHexState for RouteState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.service
    }

    fn hex_upstream(&self) -> &Arc<HexUpstreamClient> {
        &self.hex_upstream
    }
}

impl maven::HasMavenState for RouteState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.service
    }

    fn maven_upstream(&self) -> &Arc<MavenUpstreamClient> {
        &self.maven_upstream
    }
}

impl rubygems::HasRubyGemsState for RouteState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.service
    }

    fn rubygems_upstream(&self) -> &Arc<RubyGemsUpstreamClient> {
        &self.rubygems_upstream
    }
}

impl nuget::HasNuGetState for RouteState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.service
    }

    fn nuget_upstream(&self) -> &Arc<NuGetUpstreamClient> {
        &self.nuget_upstream
    }
}

impl pubdev::HasPubState for RouteState {
    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.service
    }

    fn pub_upstream(&self) -> &Arc<PubUpstreamClient> {
        &self.pub_upstream
    }
}

struct FixtureService {
    raw: HashMap<(Ecosystem, String), Bytes>,
}

impl FixtureService {
    fn new(fixtures: impl IntoIterator<Item = (Ecosystem, &'static str, &'static str)>) -> Self {
        let raw = fixtures
            .into_iter()
            .map(|(ecosystem, name, data)| {
                (
                    (ecosystem, name.to_string()),
                    Bytes::copy_from_slice(data.as_bytes()),
                )
            })
            .collect();
        Self { raw }
    }
}

#[async_trait]
impl PackageService for FixtureService {
    async fn list_versions(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Vec<VersionInfo>> {
        if ecosystem == Ecosystem::NuGet {
            return Ok(vec![VersionInfo {
                version: "1.0.0".to_string(),
                yanked: false,
            }]);
        }
        match self.get_raw_upstream(ecosystem, name).await? {
            Some(_) => Ok(Vec::new()),
            None => Err(DepotError::PackageNotFound {
                ecosystem: ecosystem.to_string(),
                name: name.as_str().to_string(),
            }),
        }
    }

    async fn get_version_metadata(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
        version: &str,
    ) -> Result<VersionMetadata> {
        Err(DepotError::VersionNotFound {
            ecosystem: ecosystem.to_string(),
            name: name.as_str().to_string(),
            version: version.to_string(),
        })
    }

    async fn validate_metadata(&self, _metadata: &VersionMetadata) -> Result<()> {
        Ok(())
    }

    async fn get_artifact(&self, artifact_id: &ArtifactId) -> Result<Bytes> {
        Ok(Bytes::from(format!("artifact:{}", artifact_id.filename)))
    }

    async fn list_packages(&self, ecosystem: Ecosystem) -> Result<Vec<PackageName>> {
        Ok(self
            .raw
            .keys()
            .filter(|(raw_ecosystem, _)| *raw_ecosystem == ecosystem)
            .map(|(_, name)| PackageName::new(name.clone()))
            .collect())
    }

    async fn get_raw_upstream(
        &self,
        ecosystem: Ecosystem,
        name: &PackageName,
    ) -> Result<Option<Bytes>> {
        Ok(self
            .raw
            .get(&(ecosystem, name.as_str().to_string()))
            .cloned())
    }

    async fn put_raw_upstream(
        &self,
        _ecosystem: Ecosystem,
        _name: &PackageName,
        _data: Bytes,
    ) -> Result<()> {
        Ok(())
    }
}

async fn response_body(router: Router, request: Request<Body>) -> (StatusCode, String) {
    let response = router.oneshot(request).await.expect("route should respond");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should buffer");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("body should be utf-8"),
    )
}

#[tokio::test]
async fn pypi_route_serves_fixture_metadata_with_rewritten_urls() {
    let state = RouteState::with_raw([(
        Ecosystem::PyPI,
        "sample-project",
        fixture("pypi/sample-project.json"),
    )]);
    let router = pypi::router::<RouteState>().with_state(state);
    let request = Request::builder()
        .uri("/simple/sample-project/")
        .header(header::ACCEPT, "application/vnd.pypi.simple.v1+json")
        .body(Body::empty())
        .expect("request should build");

    let (status, body) = response_body(router, request).await;
    assert_eq!(status, StatusCode::OK);

    let project: serde_json::Value = serde_json::from_str(&body).expect("response should be JSON");
    assert_eq!(project["name"], "Sample_Project");
    assert_eq!(
        project["files"][0]["url"],
        "/pypi/packages/Sample_Project/1.0.0/sample_project-1.0.0-py3-none-any.whl"
    );
}

#[tokio::test]
async fn npm_route_serves_fixture_packument_with_rewritten_tarballs() {
    let state = RouteState::with_raw([(
        Ecosystem::Npm,
        "@scope/sample",
        fixture("npm/sample-packument.json"),
    )]);
    let router = npm::router::<RouteState>().with_state(state);
    let request = Request::builder()
        .uri("/@scope/sample")
        .header(header::HOST, "depot.local")
        .body(Body::empty())
        .expect("request should build");

    let (status, body) = response_body(router, request).await;
    assert_eq!(status, StatusCode::OK);

    let packument: serde_json::Value =
        serde_json::from_str(&body).expect("response should be JSON");
    assert_eq!(packument["name"], "@scope/sample");
    assert_eq!(
        packument["versions"]["2.0.0"]["dist"]["tarball"],
        "http://depot.local/npm/@scope/sample/-/sample-2.0.0.tgz"
    );
    assert_eq!(
        packument["versions"]["2.0.0"]["dist"]["integrity"],
        "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    );
}

#[tokio::test]
async fn cargo_routes_serve_sparse_config_and_index_fixture() {
    let state = RouteState::with_raw([(
        Ecosystem::Cargo,
        "sample-crate",
        fixture("cargo/sample_index.ndjson"),
    )]);
    let router = cargo::router::<RouteState>().with_state(state);

    let config_request = Request::builder()
        .uri("/config.json")
        .header(header::HOST, "depot.local")
        .body(Body::empty())
        .expect("request should build");
    let (config_status, config_body) = response_body(router.clone(), config_request).await;
    assert_eq!(config_status, StatusCode::OK);
    assert!(config_body.contains("http://depot.local/cargo/crates/{crate}/{version}/download"));

    let index_request = Request::builder()
        .uri("/sa/mp/sample-crate")
        .body(Body::empty())
        .expect("request should build");
    let (index_status, index_body) = response_body(router, index_request).await;
    assert_eq!(index_status, StatusCode::OK);
    assert_eq!(index_body, fixture("cargo/sample_index.ndjson"));
}

#[tokio::test]
async fn hex_route_serves_fixture_package_metadata() {
    let state = RouteState::with_raw([(
        Ecosystem::Hex,
        "sample_hex",
        fixture("hex/sample-package.json"),
    )]);
    let router = hex::router::<RouteState>().with_state(state);
    let request = Request::builder()
        .uri("/api/packages/sample_hex")
        .body(Body::empty())
        .expect("request should build");

    let (status, body) = response_body(router, request).await;
    assert_eq!(status, StatusCode::OK);

    let package: serde_json::Value = serde_json::from_str(&body).expect("response should be JSON");
    assert_eq!(package["name"], "sample_hex");
    assert_eq!(
        package["releases"][0]["url"],
        "/hex/tarballs/sample_hex-1.0.0.tar"
    );
}

#[tokio::test]
async fn maven_route_serves_metadata_and_checksum_sidecar() {
    let state = RouteState::with_raw([(
        Ecosystem::Maven,
        "com/example/sample-lib",
        fixture("maven/maven-metadata.xml"),
    )]);
    let router = maven::router::<RouteState>().with_state(state);
    let request = Request::builder()
        .uri("/com/example/sample-lib/maven-metadata.xml")
        .body(Body::empty())
        .expect("request should build");

    let (status, body) = response_body(router, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<artifactId>sample-lib</artifactId>"));

    let state = RouteState::with_raw([]);
    let router = maven::router::<RouteState>().with_state(state);
    let request = Request::builder()
        .uri("/com/example/sample-lib/1.2.0/sample-lib-1.2.0.jar.sha1")
        .body(Body::empty())
        .expect("request should build");

    let (status, body) = response_body(router, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.trim().is_empty());
}

#[tokio::test]
async fn rubygems_route_serves_compact_index_and_gem() {
    let state = RouteState::with_raw([
        (
            Ecosystem::RubyGems,
            "_versions",
            fixture("rubygems/versions"),
        ),
        (
            Ecosystem::RubyGems,
            "info/rack",
            fixture("rubygems/info-rack"),
        ),
    ]);
    let router = rubygems::router::<RouteState>().with_state(state);
    let request = Request::builder()
        .uri("/versions")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = response_body(router.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("rack 2.2.8"));

    let request = Request::builder()
        .uri("/gems/rack-2.2.8.gem")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = response_body(router, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "artifact:rack-2.2.8.gem");
}

#[tokio::test]
async fn nuget_route_serves_service_index_versions_and_checksum() {
    let state = RouteState::with_raw([]);
    let router = nuget::router::<RouteState>().with_state(state);
    let request = Request::builder()
        .uri("/v3/index.json")
        .header(header::HOST, "depot.local")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = response_body(router.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("PackageBaseAddress/3.0.0"));

    let request = Request::builder()
        .uri("/v3-flatcontainer/sample/index.json")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = response_body(router.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("1.0.0"));

    let request = Request::builder()
        .uri("/v3-flatcontainer/sample/1.0.0/sample.1.0.0.nupkg.sha512")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = response_body(router, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.trim().is_empty());
}

#[tokio::test]
async fn pub_route_serves_fixture_package_with_rewritten_archive() {
    let state =
        RouteState::with_raw([(Ecosystem::Pub, "sample", fixture("pub/sample-package.json"))]);
    let router = pubdev::router::<RouteState>().with_state(state);
    let request = Request::builder()
        .uri("/api/packages/sample")
        .header(header::HOST, "depot.local")
        .body(Body::empty())
        .expect("request should build");
    let (status, body) = response_body(router, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("http://depot.local/pub/api/archives/sample-1.0.0.tar.gz"));
}

#[test]
fn pypi_fixture_conforms_to_pep_691_project_expectations() {
    let project: PypiProject = serde_json::from_str(fixture("pypi/sample-project.json"))
        .expect("PyPI fixture should deserialize as PEP 691 project JSON");

    assert_eq!(project.meta.api_version, "1.0");
    assert_eq!(project.name, "Sample_Project");
    assert_eq!(project.versions, ["1.0.0", "1.1.0"]);

    let version_infos = pypi_project_to_version_infos(&project);
    assert_eq!(version_infos.len(), 2);
    assert!(!version_infos[0].yanked);
    assert!(version_infos[1].yanked);

    let metadata =
        pypi_files_to_metadata(&PackageName::new("sample-project"), "1.0.0", &project.files)
            .expect("fixture contains PyPI 1.0.0 files");
    assert_eq!(
        metadata.artifacts[0].filename,
        "sample_project-1.0.0-py3-none-any.whl"
    );
    assert_eq!(metadata.artifacts[0].size, 12345);
    assert_eq!(
        metadata.artifacts[0]
            .upstream_hashes
            .get("sha256")
            .map(String::as_str),
        Some("1111111111111111111111111111111111111111111111111111111111111111")
    );
}

#[test]
fn npm_fixture_conforms_to_packument_expectations() {
    let packument: serde_json::Value = serde_json::from_str(fixture("npm/sample-packument.json"))
        .expect("npm fixture should parse as JSON");
    let typed_packument: NpmPackument = serde_json::from_value(packument.clone())
        .expect("npm fixture should deserialize as packument");

    assert_eq!(typed_packument.name, "@scope/sample");
    assert_eq!(
        typed_packument.dist_tags.get("latest").map(String::as_str),
        Some("2.0.0")
    );
    assert_eq!(
        typed_packument.versions["2.0.0"]
            .dependencies
            .get("semver")
            .map(String::as_str),
        Some("^7.6.0")
    );

    let version_infos = extract_version_infos(&packument);
    assert_eq!(
        version_infos
            .iter()
            .map(|info| info.version.as_str())
            .collect::<Vec<_>>(),
        ["1.0.0", "2.0.0"]
    );

    let metadata =
        extract_version_metadata(&PackageName::new("@scope/sample"), "2.0.0", &packument)
            .expect("fixture contains npm 2.0.0 metadata");
    assert_eq!(metadata.license.as_deref(), Some("Apache-2.0"));
    assert_eq!(metadata.artifacts[0].filename, "sample-2.0.0.tgz");
    assert_eq!(
        metadata.artifacts[0]
            .upstream_hashes
            .get("sha1")
            .map(String::as_str),
        Some("fedcba9876543210fedcba9876543210fedcba98")
    );
}

#[test]
fn cargo_fixture_conforms_to_sparse_index_expectations() {
    let config: CargoConfig = serde_json::from_str(fixture("cargo/config.json"))
        .expect("Cargo config fixture should deserialize");
    assert_eq!(config.dl, "https://static.crates.io/crates");
    assert_eq!(config.api.as_deref(), Some("https://crates.io"));
    assert!(config.auth_required);
    assert_eq!(sparse_index_path("sample-crate"), "sa/mp/sample-crate");

    let entries = fixture("cargo/sample_index.ndjson")
        .lines()
        .map(|line| {
            serde_json::from_str::<CargoIndexEntry>(line)
                .expect("Cargo index line should deserialize")
        })
        .collect::<Vec<_>>();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].deps[0].name, "serde");
    assert_eq!(entries[0].features["default"], ["serde"]);
    assert_eq!(entries[1].links.as_deref(), Some("sample_native"));

    let version_infos = cargo_entries_to_version_infos(&entries);
    assert!(!version_infos[0].yanked);
    assert!(version_infos[1].yanked);

    let metadata = cargo_entry_to_metadata(&PackageName::new("sample-crate"), &entries[0]);
    assert_eq!(metadata.artifacts[0].filename, "sample-crate-0.1.0.crate");
    assert_eq!(
        metadata.artifacts[0]
            .upstream_hashes
            .get("sha256")
            .map(String::as_str),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn hex_fixture_conforms_to_package_api_expectations() {
    let package: HexPackage = serde_json::from_str(fixture("hex/sample-package.json"))
        .expect("Hex fixture should deserialize as package API response");

    assert_eq!(package.name, "sample_hex");
    assert_eq!(
        package
            .meta
            .as_ref()
            .and_then(|meta| meta.licenses.first())
            .map(String::as_str),
        Some("Apache-2.0")
    );

    let version_infos = hex_package_to_version_infos(&package);
    assert_eq!(
        version_infos
            .iter()
            .map(|info| info.version.as_str())
            .collect::<Vec<_>>(),
        ["1.0.0", "1.1.0"]
    );
    assert!(!version_infos[0].yanked);
    assert!(version_infos[1].yanked);

    let metadata = hex_release_to_metadata(&PackageName::new("sample_hex"), &package, "1.0.0")
        .expect("fixture contains Hex 1.0.0 release");
    assert_eq!(metadata.license.as_deref(), Some("Apache-2.0"));
    assert_eq!(metadata.artifacts[0].filename, "sample_hex-1.0.0.tar");
}

#[test]
fn nuget_and_pub_fixtures_conform_to_generated_shapes() {
    let service_index: NugetServiceIndex =
        serde_json::from_str(fixture("nuget/service-index.json"))
            .expect("NuGet service index fixture should deserialize");
    assert_eq!(service_index.version, "3.0.0");

    let versions: NugetPackageVersions = serde_json::from_str(fixture("nuget/versions.json"))
        .expect("NuGet versions fixture should deserialize");
    assert_eq!(versions.versions, ["1.0.0", "1.1.0"]);

    let package: PubPackage = serde_json::from_str(fixture("pub/sample-package.json"))
        .expect("pub.dev package fixture should deserialize");
    assert_eq!(package.name, "sample");
    assert_eq!(package.versions[0].version, "1.0.0");
}

#[test]
fn maven_fixtures_conform_to_metadata_and_pom_expectations() {
    let metadata = Document::parse(fixture("maven/maven-metadata.xml"))
        .expect("Maven metadata fixture should parse as XML");
    let root = metadata.root_element();

    assert_eq!(child_text(root, "groupId"), Some("com.example"));
    assert_eq!(child_text(root, "artifactId"), Some("sample-lib"));

    let versioning = root
        .children()
        .find(|child| child.has_tag_name("versioning"))
        .expect("metadata should contain versioning");
    assert_eq!(child_text(versioning, "latest"), Some("1.2.0"));
    assert_eq!(child_text(versioning, "release"), Some("1.2.0"));
    assert_eq!(
        child_text(versioning, "lastUpdated"),
        Some("20240501010203")
    );

    let versions = versioning
        .descendants()
        .filter(|node| node.has_tag_name("version"))
        .filter_map(|node| node.text())
        .collect::<Vec<_>>();
    assert_eq!(versions, ["1.0.0", "1.1.0", "1.2.0"]);

    let pom = Document::parse(fixture("maven/sample-lib-1.2.0.pom"))
        .expect("Maven POM fixture should parse as XML");
    let project = pom.root_element();
    assert_eq!(child_text(project, "modelVersion"), Some("4.0.0"));
    assert_eq!(child_text(project, "groupId"), Some("com.example"));
    assert_eq!(child_text(project, "artifactId"), Some("sample-lib"));
    assert_eq!(child_text(project, "version"), Some("1.2.0"));
    assert_eq!(child_text(project, "packaging"), Some("jar"));

    let dependency = project
        .descendants()
        .find(|node| node.has_tag_name("dependency"))
        .expect("POM should contain a dependency");
    assert_eq!(child_text(dependency, "groupId"), Some("org.slf4j"));
    assert_eq!(child_text(dependency, "artifactId"), Some("slf4j-api"));
    assert_eq!(child_text(dependency, "version"), Some("2.0.13"));
    assert_eq!(child_text(dependency, "scope"), Some("compile"));
}

#[test]
fn rubygems_compact_index_fixtures_conform_to_text_grammar() {
    let versions = compact_index_body_lines(fixture("rubygems/versions"));
    assert_eq!(versions, ["rack 2.2.8,3.0.8", "rails 7.1.3"]);

    for line in versions {
        let (name, versions) = line
            .split_once(' ')
            .expect("versions line should contain gem name and versions");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
        assert!(
            versions
                .split(',')
                .all(|version| !version.is_empty() && !version.contains('/')),
            "versions should be comma-separated tokens"
        );
    }

    let info = compact_index_body_lines(fixture("rubygems/info-rack"));
    assert_eq!(info.len(), 2);
    for line in info {
        let (version, metadata) = line.split_once(' ').unwrap_or((line, ""));
        assert!(!version.is_empty());
        if !metadata.is_empty() {
            assert!(
                metadata.contains("checksum:sha256=") || metadata.contains(':'),
                "metadata should contain dependencies or checksums"
            );
        }
    }
}
