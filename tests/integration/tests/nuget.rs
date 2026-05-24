use tokio::process::Command;

use depot_integration_tests::TestServer;

async fn require_dotnet() -> String {
    if let Ok(output) = Command::new("dotnet").arg("--version").output().await
        && output.status.success()
    {
        return "dotnet".to_string();
    }
    panic!("dotnet not found — install .NET SDK to run NuGet E2E tests");
}

async fn dotnet_restore(
    dotnet: &str,
    nuget_index_url: &str,
    project_dir: &std::path::Path,
    packages_dir: &std::path::Path,
    cli_home: &std::path::Path,
) -> std::process::Output {
    std::fs::write(
        project_dir.join("nuget.config"),
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="depot" value="{nuget_index_url}" allowInsecureConnections="true" />
  </packageSources>
</configuration>
"#
        ),
    )
    .expect("failed to write nuget.config");
    std::fs::write(
        project_dir.join("depot-nuget-e2e.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
"#,
    )
    .expect("failed to write csproj");

    Command::new(dotnet)
        .args(["restore", "--packages", &packages_dir.to_string_lossy()])
        .current_dir(project_dir)
        .env("DOTNET_CLI_HOME", cli_home)
        .env("NUGET_PACKAGES", packages_dir)
        .output()
        .await
        .expect("failed to run dotnet restore")
}

#[tokio::test]
#[ignore] // requires network + dotnet
async fn dotnet_restores_package_through_depot() {
    let dotnet = require_dotnet().await;
    let server = TestServer::start_all_enabled().await;
    let project = tempfile::tempdir().expect("project tempdir");
    let packages = tempfile::tempdir().expect("packages tempdir");
    let cli_home = tempfile::tempdir().expect("dotnet cli home tempdir");

    let output = dotnet_restore(
        &dotnet,
        &server.nuget_index_url(),
        project.path(),
        packages.path(),
        cli_home.path(),
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let command = format!(
        "{dotnet} restore --packages {} using {}",
        packages.path().display(),
        server.nuget_index_url()
    );

    assert!(
        output.status.success(),
        "dotnet restore failed: {command}\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        packages.path().join("newtonsoft.json/13.0.3").exists(),
        "expected Newtonsoft.Json package in NuGet packages directory"
    );

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network
async fn nuget_serves_v3_resources() {
    let server = TestServer::start_all_enabled().await;
    let client = reqwest::Client::new();

    for path in [
        "v3/index.json",
        "v3-flatcontainer/newtonsoft.json/index.json",
        "v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
        "v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.nuspec",
        "v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg.sha512",
        "v3/registration/newtonsoft.json/index.json",
    ] {
        let response = client
            .get(format!("{}/nuget/{path}", server.base_url()))
            .send()
            .await
            .expect("request failed");
        assert_eq!(response.status(), 200, "expected 200 for {path}");
        assert!(
            !response.bytes().await.expect("body bytes").is_empty(),
            "expected non-empty body for {path}"
        );
    }

    server.shutdown();
}

#[tokio::test]
#[ignore] // requires network + dotnet
async fn dotnet_restore_works_from_depot_cache() {
    let dotnet = require_dotnet().await;
    let server = TestServer::start_all_enabled().await;

    for attempt in ["first", "second"] {
        let project = tempfile::tempdir().expect("project tempdir");
        let packages = tempfile::tempdir().expect("packages tempdir");
        let cli_home = tempfile::tempdir().expect("dotnet cli home tempdir");
        let output = dotnet_restore(
            &dotnet,
            &server.nuget_index_url(),
            project.path(),
            packages.path(),
            cli_home.path(),
        )
        .await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{attempt} dotnet restore failed\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    server.shutdown();
}
