use tokio::process::Command;

use depot_integration_tests::TestServer;

async fn require_dart() -> String {
    if let Ok(output) = Command::new("dart").arg("--version").output().await
        && output.status.success()
    {
        return "dart".to_string();
    }
    panic!("dart not found — install Dart SDK to run pub.dev E2E tests");
}

async fn dart_pub_get(
    dart: &str,
    pub_hosted_url: &str,
    project_dir: &std::path::Path,
    pub_cache: &std::path::Path,
) -> std::process::Output {
    std::fs::write(
        project_dir.join("pubspec.yaml"),
        r#"name: depot_pub_e2e
publish_to: none
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  collection: 1.18.0
"#,
    )
    .expect("failed to write pubspec.yaml");

    Command::new(dart)
        .args(["pub", "get"])
        .current_dir(project_dir)
        .env("PUB_HOSTED_URL", pub_hosted_url)
        .env("PUB_CACHE", pub_cache)
        .output()
        .await
        .expect("failed to run dart pub get")
}

#[tokio::test]
#[ignore] // requires network + dart
async fn dart_pub_get_installs_package_through_depot() {
    let dart = require_dart().await;
    let server = TestServer::start_all_enabled().await;
    let project = tempfile::tempdir().expect("project tempdir");
    let pub_cache = tempfile::tempdir().expect("pub cache tempdir");

    let output = dart_pub_get(
        &dart,
        &server.pub_hosted_url(),
        project.path(),
        pub_cache.path(),
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let command = format!(
        "{dart} pub get with PUB_HOSTED_URL={} PUB_CACHE={}",
        server.pub_hosted_url(),
        pub_cache.path().display()
    );

    assert!(
        output.status.success(),
        "dart pub get failed: {command}\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        pub_cache.path().join("hosted").exists(),
        "expected hosted packages in PUB_CACHE"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn pub_serves_metadata_and_archive() {
    let server = TestServer::start_all_enabled().await;
    let client = reqwest::Client::new();

    let package_response = client
        .get(format!("{}/pub/api/packages/collection", server.base_url()))
        .send()
        .await
        .expect("package request failed");
    assert_eq!(package_response.status(), 200);
    let package: serde_json::Value = package_response.json().await.expect("package JSON");
    let version = package["versions"]
        .as_array()
        .and_then(|versions| versions.iter().find(|item| item["version"] == "1.18.0"))
        .expect("expected collection 1.18.0 in package metadata");
    let archive_url = version["archive_url"]
        .as_str()
        .expect("expected rewritten archive URL");
    assert!(
        archive_url.starts_with(&format!("{}/pub/api/archives/", server.base_url())),
        "archive URL should point back to Depot: {archive_url}"
    );

    let version_response = client
        .get(format!(
            "{}/pub/api/packages/collection/versions/1.18.0",
            server.base_url()
        ))
        .send()
        .await
        .expect("version request failed");
    assert_eq!(version_response.status(), 200);

    let archive_response = client
        .get(archive_url)
        .send()
        .await
        .expect("archive request failed");
    assert_eq!(archive_response.status(), 200);
    assert!(
        !archive_response
            .bytes()
            .await
            .expect("archive bytes")
            .is_empty(),
        "expected non-empty pub archive"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + dart
async fn dart_pub_get_works_from_depot_cache() {
    let dart = require_dart().await;
    let server = TestServer::start_all_enabled().await;

    for attempt in ["first", "second"] {
        let project = tempfile::tempdir().expect("project tempdir");
        let pub_cache = tempfile::tempdir().expect("pub cache tempdir");
        let output = dart_pub_get(
            &dart,
            &server.pub_hosted_url(),
            project.path(),
            pub_cache.path(),
        )
        .await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{attempt} dart pub get failed\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    server.shutdown();
}
