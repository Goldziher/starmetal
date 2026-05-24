use std::sync::Arc;

use ahash::AHashMap;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use depot_adapters::cargo::upstream::CargoUpstreamClient;
use depot_adapters::maven::upstream::MavenUpstreamClient;
use depot_adapters::npm::upstream::NpmUpstreamClient;
use depot_adapters::pypi::upstream::PypiUpstreamClient;
use depot_adapters::{cargo, maven, npm, pypi};
use depot_core::config::Config;
use depot_core::package::Ecosystem;
use depot_core::policy::PolicyConfig;
use depot_core::ports::{PackageService, PublishingService, UpstreamClient};
use depot_service::CachingPackageService;
use depot_storage::OpenDalStorage;
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
}

impl PublishRouteState {
    fn new() -> Self {
        let mut config = Config::default();
        config.publishing.enabled = true;
        config
            .publishing
            .tokens
            .push(depot_core::publishing::PublishTokenConfig {
                token: "publish-token".to_string(),
                scopes: vec![depot_core::publishing::TokenScope::Publish],
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

async fn response(router: Router, request: Request<Body>) -> (StatusCode, bytes::Bytes) {
    let response = router.oneshot(request).await.expect("route should respond");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should read");
    (status, body)
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

    let (status, _) = response(
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
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = response(
        router.clone(),
        Request::builder()
            .uri("/sample")
            .header(header::HOST, "depot.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let packument: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(packument["dist-tags"]["latest"], "1.0.0");
    assert_eq!(
        packument["versions"]["1.0.0"]["dist"]["tarball"],
        "http://depot.test/npm/sample/-/sample-1.0.0.tgz"
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
    let boundary = "depot-boundary";
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

    let (status, _) = response(
        router.clone(),
        Request::builder()
            .method(Method::PUT)
            .uri(path)
            .header(header::AUTHORIZATION, "Bearer publish-token")
            .body(Body::from("artifact"))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

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
