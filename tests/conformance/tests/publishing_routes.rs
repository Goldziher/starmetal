use std::sync::Arc;

use ahash::AHashMap;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use starmetal_adapters::cargo::upstream::CargoUpstreamClient;
use starmetal_adapters::hex::upstream::HexUpstreamClient;
use starmetal_adapters::maven::upstream::MavenUpstreamClient;
use starmetal_adapters::npm::upstream::NpmUpstreamClient;
use starmetal_adapters::nuget::upstream::NuGetUpstreamClient;
use starmetal_adapters::pubdev::upstream::PubUpstreamClient;
use starmetal_adapters::pypi::upstream::PypiUpstreamClient;
use starmetal_adapters::rubygems::upstream::RubyGemsUpstreamClient;
use starmetal_adapters::{cargo, hex, maven, npm, nuget, pubdev, pypi, rubygems};
use starmetal_core::config::Config;
use starmetal_core::package::Ecosystem;
use starmetal_core::policy::PolicyConfig;
use starmetal_core::ports::{PackageService, PublishingService, UpstreamClient};
use starmetal_service::CachingPackageService;
use starmetal_storage::OpenDalStorage;
use tower::ServiceExt;

#[derive(Clone)]
struct PublishRouteState {
    config: Arc<Config>,
    package_service: Arc<dyn PackageService>,
    publishing_service: Arc<dyn PublishingService>,
    cargo_upstream: Arc<CargoUpstreamClient>,
    npm_upstream: Arc<NpmUpstreamClient>,
    pypi_upstream: Arc<PypiUpstreamClient>,
    maven_upstream: Arc<MavenUpstreamClient>,
    hex_upstream: Arc<HexUpstreamClient>,
    rubygems_upstream: Arc<RubyGemsUpstreamClient>,
    nuget_upstream: Arc<NuGetUpstreamClient>,
    pub_upstream: Arc<PubUpstreamClient>,
}

impl PublishRouteState {
    fn new() -> Self {
        let mut config = Config::default();
        config.publishing.enabled = true;
        config
            .publishing
            .tokens
            .push(starmetal_core::publishing::PublishTokenConfig {
                token: "publish-token".to_string(),
                scopes: vec![starmetal_core::publishing::TokenScope::Publish],
                ecosystems: Vec::new(),
                packages: Vec::new(),
            });

        let service = Arc::new(CachingPackageService::new(
            Arc::new(OpenDalStorage::memory().expect("memory storage")),
            AHashMap::<Ecosystem, Arc<dyn UpstreamClient>>::new(),
            PolicyConfig::default(),
        ));

        Self {
            config: Arc::new(config),
            package_service: service.clone(),
            publishing_service: service,
            cargo_upstream: Arc::new(CargoUpstreamClient::new(
                "http://127.0.0.1/index".into(),
                "http://127.0.0.1/crates".into(),
            )),
            npm_upstream: Arc::new(NpmUpstreamClient::new("http://127.0.0.1".into())),
            pypi_upstream: Arc::new(PypiUpstreamClient::new("http://127.0.0.1".into())),
            maven_upstream: Arc::new(MavenUpstreamClient::new("http://127.0.0.1/maven2".into())),
            hex_upstream: Arc::new(HexUpstreamClient::new(
                "http://127.0.0.1".into(),
                "http://127.0.0.1/repo".into(),
            )),
            rubygems_upstream: Arc::new(RubyGemsUpstreamClient::new("http://127.0.0.1".into())),
            nuget_upstream: Arc::new(NuGetUpstreamClient::new(
                "http://127.0.0.1/v3/index.json".into(),
            )),
            pub_upstream: Arc::new(PubUpstreamClient::new("http://127.0.0.1".into())),
        }
    }
}

impl cargo::HasCargoState for PublishRouteState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn cargo_upstream(&self) -> &Arc<CargoUpstreamClient> {
        &self.cargo_upstream
    }
}

impl pypi::HasPypiState for PublishRouteState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn pypi_upstream(&self) -> &Arc<PypiUpstreamClient> {
        &self.pypi_upstream
    }
}

impl npm::HasNpmState for PublishRouteState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn npm_upstream(&self) -> &Arc<NpmUpstreamClient> {
        &self.npm_upstream
    }
}

impl maven::HasMavenState for PublishRouteState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn maven_upstream(&self) -> &Arc<MavenUpstreamClient> {
        &self.maven_upstream
    }
}

impl hex::HasHexState for PublishRouteState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn hex_upstream(&self) -> &Arc<HexUpstreamClient> {
        &self.hex_upstream
    }
}

impl rubygems::HasRubyGemsState for PublishRouteState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn rubygems_upstream(&self) -> &Arc<RubyGemsUpstreamClient> {
        &self.rubygems_upstream
    }
}

impl nuget::HasNuGetState for PublishRouteState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn nuget_upstream(&self) -> &Arc<NuGetUpstreamClient> {
        &self.nuget_upstream
    }
}

impl pubdev::HasPubState for PublishRouteState {
    fn config(&self) -> &Arc<Config> {
        &self.config
    }

    fn package_service(&self) -> &Arc<dyn PackageService> {
        &self.package_service
    }

    fn publishing_service(&self) -> &Arc<dyn PublishingService> {
        &self.publishing_service
    }

    fn pub_upstream(&self) -> &Arc<PubUpstreamClient> {
        &self.pub_upstream
    }
}

async fn response(router: Router, request: Request<Body>) -> (StatusCode, bytes::Bytes) {
    let response = router.oneshot(request).await.expect("route should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should read");
    (status, body)
}

fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buffer = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut buffer);
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, *path, *data)
                .expect("tar entry should append");
        }
        archive.finish().expect("tar should finish");
    }
    buffer
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip input should write");
    encoder.finish().expect("gzip should finish")
}

fn rubygem_bytes() -> Vec<u8> {
    let metadata = b"---\nname: sample\nversion: 1.0.0\nlicenses:\n  - MIT\n";
    let metadata = gzip_bytes(metadata);
    tar_bytes(&[("metadata.gz", &metadata)])
}

fn hex_tarball_bytes() -> Vec<u8> {
    tar_bytes(&[(
        "metadata.config",
        b"name: sample_hex\nversion: 1.0.0\nlicenses:\n  - MIT\n",
    )])
}

fn pub_archive_bytes() -> Vec<u8> {
    let tarball = tar_bytes(&[("pubspec.yaml", b"name: sample_pub\nversion: 1.0.0\n")]);
    gzip_bytes(&tarball)
}

fn nupkg_bytes() -> Vec<u8> {
    use std::io::{Cursor, Write};

    let mut buffer = Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut buffer);
        archive
            .start_file("sample.nuspec", zip::write::SimpleFileOptions::default())
            .expect("nuspec entry should start");
        archive
            .write_all(
                br#"<?xml version="1.0" encoding="utf-8"?>
<package>
  <metadata>
    <id>Sample</id>
    <version>1.0.0</version>
    <license type="expression">MIT</license>
  </metadata>
</package>"#,
            )
            .expect("nuspec should write");
        archive.finish().expect("nupkg should finish");
    }
    buffer.into_inner()
}

#[tokio::test]
async fn npm_publish_route_serves_published_packument_and_tarball() {
    let state = PublishRouteState::new();
    let router = npm::router().with_state(state);
    let payload = serde_json::json!({
        "name": "sample",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "sample",
                "version": "1.0.0",
                "license": "MIT"
            }
        },
        "_attachments": {
            "sample-1.0.0.tgz": {
                "content_type": "application/octet-stream",
                "data": "YXJ0aWZhY3Q="
            }
        }
    });

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .method(Method::PUT)
            .uri("/sample")
            .header(header::AUTHORIZATION, "Bearer publish-token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/sample")
            .header(header::HOST, "starmetal.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let packument: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(packument["dist-tags"]["latest"], "1.0.0");
    assert_eq!(
        packument["versions"]["1.0.0"]["dist"]["tarball"],
        "http://starmetal.test/npm/sample/-/sample-1.0.0.tgz"
    );

    let (status, body) = response(
        router,
        Request::builder()
            .uri("/sample/-/sample-1.0.0.tgz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes::Bytes::from_static(b"artifact"));
}

#[tokio::test]
async fn pypi_legacy_upload_route_serves_published_simple_project_and_artifact() {
    let state = PublishRouteState::new();
    let router = pypi::router().with_state(state);
    let boundary = "starmetal-boundary";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nsample\r\n\
--{boundary}\r\nContent-Disposition: form-data; name=\"version\"\r\n\r\n1.0.0\r\n\
--{boundary}\r\nContent-Disposition: form-data; name=\"license\"\r\n\r\nMIT\r\n\
--{boundary}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"sample-1.0.0.tar.gz\"\r\n\
Content-Type: application/octet-stream\r\n\r\nartifact\r\n--{boundary}--\r\n"
    );

    let (status, _) = response(
        router.clone(),
        Request::builder()
            .method(Method::POST)
            .uri("/legacy/")
            .header(header::AUTHORIZATION, "Bearer publish-token")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/simple/sample/")
            .header(header::ACCEPT, "application/vnd.pypi.simple.v1+json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let project: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(project["name"], "sample");
    assert_eq!(project["versions"][0], "1.0.0");
    assert_eq!(project["files"][0]["filename"], "sample-1.0.0.tar.gz");

    let (status, body) = response(
        router,
        Request::builder()
            .uri("/packages/sample/1.0.0/sample-1.0.0.tar.gz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes::Bytes::from_static(b"artifact"));
}

#[tokio::test]
async fn cargo_publish_route_serves_sparse_index_and_crate_download() {
    let state = PublishRouteState::new();
    let router = cargo::router().with_state(state);
    let metadata = serde_json::json!({
        "name": "sample",
        "vers": "1.0.0",
        "deps": [],
        "features": {},
        "links": null,
        "rust_version": null,
        "v": 2
    })
    .to_string()
    .into_bytes();
    let crate_bytes = b"crate";
    let mut body = Vec::new();
    body.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    body.extend_from_slice(&metadata);
    body.extend_from_slice(&(crate_bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(crate_bytes);

    let (status, _) = response(
        router.clone(),
        Request::builder()
            .method(Method::PUT)
            .uri("/api/v1/crates/new")
            .header(header::AUTHORIZATION, "Bearer publish-token")
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/3/s/sample")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let entry: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(entry["name"], "sample");
    assert_eq!(entry["vers"], "1.0.0");
    assert_eq!(
        entry["cksum"],
        "f5fe331d2367a7a67ee20bd579c77b929ae49439d8b0d8e9c3b98609797b6b69"
    );

    let (status, body) = response(
        router,
        Request::builder()
            .uri("/crates/sample/1.0.0/download")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes::Bytes::from_static(crate_bytes));
}

#[tokio::test]
async fn maven_put_route_serves_published_artifact_and_checksum() {
    let state = PublishRouteState::new();
    let router = maven::router().with_state(state);
    let path = "/com/example/sample/1.0.0/sample-1.0.0.jar";

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .method(Method::PUT)
            .uri(path)
            .header(header::AUTHORIZATION, "Bearer publish-token")
            .body(Body::from("artifact"))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = response(
        router.clone(),
        Request::builder().uri(path).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes::Bytes::from_static(b"artifact"));

    let (status, body) = response(
        router,
        Request::builder()
            .uri(format!("{path}.sha1"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        "1e5dcbb59b753cb1d46e234d8f6180285b8b86ad"
    );
}

#[tokio::test]
async fn rubygems_publish_route_serves_compact_index_and_gem() {
    let state = PublishRouteState::new();
    let router = rubygems::router().with_state(state);
    let gem = rubygem_bytes();

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/gems")
            .header(header::AUTHORIZATION, "Bearer publish-token")
            .body(Body::from(gem.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/versions")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(std::str::from_utf8(&body).unwrap().contains("sample 1.0.0"));

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/info/sample")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("1.0.0 checksum:sha256=")
    );

    let (status, body) = response(
        router,
        Request::builder()
            .uri("/gems/sample-1.0.0.gem")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes::Bytes::from(gem));
}

#[tokio::test]
async fn nuget_publish_route_serves_flat_container_registration_and_checksum() {
    let state = PublishRouteState::new();
    let router = nuget::router().with_state(state);
    let package = nupkg_bytes();

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .method(Method::PUT)
            .uri("/api/v2/package")
            .header("x-nuget-apikey", "publish-token")
            .body(Body::from(package.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/v3/index.json")
            .header(header::HOST, "starmetal.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let service_index: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        service_index["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|resource| resource["@type"] == "PackagePublish/2.0.0")
    );

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/v3-flatcontainer/sample/index.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let versions: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(versions["versions"][0], "1.0.0");

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/v3-flatcontainer/sample/1.0.0/sample.1.0.0.nupkg")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes::Bytes::from(package));

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/v3-flatcontainer/sample/1.0.0/sample.nuspec")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("<id>Sample</id>")
    );

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/v3-flatcontainer/sample/1.0.0/sample.1.0.0.nupkg.sha512")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.is_empty());

    let (status, body) = response(
        router,
        Request::builder()
            .uri("/v3/registration/sample/index.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let registration: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        registration["items"][0]["items"][0]["catalogEntry"]["version"],
        "1.0.0"
    );
}

#[tokio::test]
async fn pub_publish_route_serves_package_metadata_version_and_archive() {
    let state = PublishRouteState::new();
    let router = pubdev::router().with_state(state);
    let archive = pub_archive_bytes();

    let (status, _) = response(
        router.clone(),
        Request::builder()
            .method(Method::POST)
            .uri("/api/packages/versions/new")
            .header(header::AUTHORIZATION, "Bearer publish-token")
            .body(Body::from(archive.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/api/packages/sample_pub")
            .header(header::HOST, "starmetal.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let package: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(package["name"], "sample_pub");
    assert_eq!(package["versions"][0]["version"], "1.0.0");
    assert_eq!(
        package["versions"][0]["archive_url"],
        "http://starmetal.test/pub/api/archives/sample_pub-1.0.0.tar.gz"
    );

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/api/packages/sample_pub/versions/1.0.0")
            .header(header::HOST, "starmetal.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let version: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(version["version"], "1.0.0");
    assert!(!version["archive_sha256"].as_str().unwrap().is_empty());

    let (status, body) = response(
        router,
        Request::builder()
            .uri("/api/archives/sample_pub-1.0.0.tar.gz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes::Bytes::from(archive));
}

#[tokio::test]
async fn hex_publish_route_serves_api_metadata_registry_resource_and_tarball() {
    let state = PublishRouteState::new();
    let router = hex::router().with_state(state);
    let tarball = hex_tarball_bytes();

    let (status, _) = response(
        router.clone(),
        Request::builder()
            .method(Method::POST)
            .uri("/api/packages")
            .header(header::AUTHORIZATION, "Bearer publish-token")
            .body(Body::from(tarball.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/api/packages/sample_hex")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let package: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(package["name"], "sample_hex");
    assert_eq!(package["releases"][0]["version"], "1.0.0");

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/packages/sample_hex")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.is_empty());

    let (status, body) = response(
        router,
        Request::builder()
            .uri("/tarballs/sample_hex-1.0.0.tar")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, bytes::Bytes::from(tarball));
}
