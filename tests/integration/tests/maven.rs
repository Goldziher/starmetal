use tokio::process::Command;

use depot_integration_tests::TestServer;

async fn require_mvn() -> String {
    if let Ok(output) = Command::new("mvn").arg("--version").output().await
        && output.status.success()
    {
        return "mvn".to_string();
    }
    panic!("mvn not found — install Maven to run Maven E2E tests");
}

async fn maven_resolve(
    mvn: &str,
    depot_maven_url: &str,
    project_dir: &std::path::Path,
    repo_dir: &std::path::Path,
) -> std::process::Output {
    let settings = project_dir.join("settings.xml");
    std::fs::write(
        &settings,
        format!(
            r#"<settings>
  <mirrors>
    <mirror>
      <id>depot</id>
      <mirrorOf>*</mirrorOf>
      <url>{depot_maven_url}</url>
    </mirror>
  </mirrors>
</settings>
"#
        ),
    )
    .expect("failed to write settings.xml");
    std::fs::write(
        project_dir.join("pom.xml"),
        r#"<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>depot.e2e</groupId>
  <artifactId>maven-e2e</artifactId>
  <version>0.0.0</version>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .expect("failed to write pom.xml");

    Command::new(mvn)
        .args([
            "-B",
            "-s",
            &settings.to_string_lossy(),
            &format!("-Dmaven.repo.local={}", repo_dir.display()),
            "dependency:resolve",
        ])
        .current_dir(project_dir)
        .output()
        .await
        .expect("failed to run mvn")
}

#[tokio::test]
#[ignore] // requires network + mvn
async fn maven_resolves_dependency_through_depot() {
    let mvn = require_mvn().await;
    let server = TestServer::start_all_enabled().await;
    let project = tempfile::tempdir().expect("project tempdir");
    let repo = tempfile::tempdir().expect("maven repo tempdir");

    let output = maven_resolve(&mvn, &server.maven_url(), project.path(), repo.path()).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let command = format!(
        "{mvn} -B -s {}/settings.xml -Dmaven.repo.local={} dependency:resolve",
        project.path().display(),
        repo.path().display()
    );

    assert!(
        output.status.success(),
        "mvn dependency resolve failed: {command}\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        repo.path()
            .join("junit/junit/4.13.2/junit-4.13.2.jar")
            .exists(),
        "expected junit jar in Maven local repository"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn maven_serves_artifacts_and_checksum_sidecars() {
    let server = TestServer::start_all_enabled().await;
    let client = reqwest::Client::new();
    let base = format!("{}/maven/junit/junit/4.13.2", server.base_url());

    for path in [
        "junit-4.13.2.pom",
        "junit-4.13.2.jar",
        "junit-4.13.2.jar.sha1",
    ] {
        let response = client
            .get(format!("{base}/{path}"))
            .send()
            .await
            .expect("request failed");
        assert_eq!(response.status(), 200, "expected 200 for {path}");
        assert!(
            !response.bytes().await.expect("body bytes").is_empty(),
            "expected non-empty body for {path}"
        );
    }

    let plugin_path =
        "org/apache/maven/plugins/maven-clean-plugin/3.2.0/maven-clean-plugin-3.2.0.pom";
    let response = client
        .get(format!("{}/maven/{plugin_path}", server.base_url()))
        .send()
        .await
        .expect("plugin pom request failed");
    let status = response.status();
    let body = response.bytes().await.expect("plugin pom body");
    assert_eq!(
        status,
        200,
        "expected 200 for {plugin_path}, body: {}",
        String::from_utf8_lossy(&body)
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + mvn
async fn maven_resolve_works_from_depot_cache() {
    let mvn = require_mvn().await;
    let server = TestServer::start_all_enabled().await;

    for attempt in ["first", "second"] {
        let project = tempfile::tempdir().expect("project tempdir");
        let repo = tempfile::tempdir().expect("maven repo tempdir");
        let output = maven_resolve(&mvn, &server.maven_url(), project.path(), repo.path()).await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{attempt} mvn dependency resolve failed\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    server.shutdown();
}
