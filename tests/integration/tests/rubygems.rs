use tokio::process::Command;

use starmetal_integration_tests::TestServer;

async fn require_bundle() -> String {
    if let Ok(output) = Command::new("bundle").arg("--version").output().await
        && output.status.success()
    {
        return "bundle".to_string();
    }
    panic!("bundle not found — install Bundler to run RubyGems E2E tests");
}

async fn bundle_install(
    bundle: &str,
    source_url: &str,
    project_dir: &std::path::Path,
    gem_home: &std::path::Path,
    bundle_path: &std::path::Path,
) -> std::process::Output {
    std::fs::write(
        project_dir.join("Gemfile"),
        format!(
            r#"source "{source_url}"
gem "rack", "2.2.8"
"#
        ),
    )
    .expect("failed to write Gemfile");

    let config_output = Command::new(bundle)
        .args(["config", "set", "path", &bundle_path.to_string_lossy()])
        .current_dir(project_dir)
        .env("GEM_HOME", gem_home)
        .env("BUNDLE_PATH", bundle_path)
        .env("BUNDLE_USER_HOME", project_dir.join(".bundle-home"))
        .env("BUNDLE_SILENCE_ROOT_WARNING", "1")
        .output()
        .await
        .expect("failed to run bundle config");
    assert!(
        config_output.status.success(),
        "bundle config set path failed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&config_output.stdout),
        String::from_utf8_lossy(&config_output.stderr)
    );

    Command::new(bundle)
        .args(["install"])
        .current_dir(project_dir)
        .env("GEM_HOME", gem_home)
        .env("BUNDLE_PATH", bundle_path)
        .env("BUNDLE_USER_HOME", project_dir.join(".bundle-home"))
        .env("BUNDLE_SILENCE_ROOT_WARNING", "1")
        .output()
        .await
        .expect("failed to run bundle")
}

#[tokio::test]
#[ignore] // requires network + bundle
async fn bundler_installs_gem_through_starmetal() {
    let bundle = require_bundle().await;
    let server = TestServer::start_all_enabled().await;
    let project = tempfile::tempdir().expect("project tempdir");
    let gem_home = tempfile::tempdir().expect("gem home tempdir");
    let bundle_path = tempfile::tempdir().expect("bundle path tempdir");

    let output = bundle_install(
        &bundle,
        &server.rubygems_url(),
        project.path(),
        gem_home.path(),
        bundle_path.path(),
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let command = format!(
        "{bundle} config set path {} && {bundle} install with source {}",
        bundle_path.path().display(),
        server.rubygems_url()
    );

    assert!(
        output.status.success(),
        "bundle install failed: {command}\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        bundle_path.path().join("ruby").exists() || bundle_path.path().join("gems").exists(),
        "expected bundle path to contain installed Ruby gems"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn rubygems_serves_compact_index() {
    let server = TestServer::start_all_enabled().await;
    let client = reqwest::Client::new();

    for path in ["versions", "info/rack"] {
        let response = client
            .get(format!("{}/rubygems/{path}", server.base_url()))
            .send()
            .await
            .expect("request failed");
        assert_eq!(response.status(), 200, "expected 200 for {path}");
        assert!(
            !response.text().await.expect("body text").is_empty(),
            "expected non-empty compact index body for {path}"
        );
    }

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + bundle
async fn bundler_install_works_from_starmetal_cache() {
    let bundle = require_bundle().await;
    let server = TestServer::start_all_enabled().await;

    for attempt in ["first", "second"] {
        let project = tempfile::tempdir().expect("project tempdir");
        let gem_home = tempfile::tempdir().expect("gem home tempdir");
        let bundle_path = tempfile::tempdir().expect("bundle path tempdir");
        let output = bundle_install(
            &bundle,
            &server.rubygems_url(),
            project.path(),
            gem_home.path(),
            bundle_path.path(),
        )
        .await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{attempt} bundle install failed\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    server.shutdown();
}
