use serde_json::Value;

/// Resolve the workspace root from CARGO_MANIFEST_DIR (starmetal-core -> workspace).
fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("could not resolve workspace root")
        .to_path_buf()
}

fn load_schema(relative_path: &str) -> Value {
    let path = workspace_root().join(relative_path);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read schema {}: {e}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse schema {}: {e}", path.display()))
}

fn validate(schema_value: &Value, instance: &Value) -> std::result::Result<(), String> {
    let validator =
        jsonschema::validator_for(schema_value).map_err(|e| format!("invalid schema: {e}"))?;
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .map(|e| e.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[test]
fn should_validate_pypi_sample_against_schema() {
    let schema = load_schema("schemas/registries/pypi.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "meta": { "api-version": "1.0" },
            "name": "requests",
            "versions": ["2.32.0"],
            "files": [{
                "filename": "requests-2.32.0.tar.gz",
                "url": "https://files.pythonhosted.org/packages/requests-2.32.0.tar.gz",
                "hashes": { "sha256": "abc123" },
                "requires-python": ">=3.8",
                "yanked": false,
                "size": 131200
            }]
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("PyPI sample should validate against schema");
}

#[test]
fn should_reject_pypi_sample_missing_required_fields() {
    let schema = load_schema("schemas/registries/pypi.schema.json");
    let invalid: Value = serde_json::from_str(r#"{ "name": "oops" }"#).unwrap();

    assert!(
        validate(&schema, &invalid).is_err(),
        "missing 'meta' and 'files' should fail validation"
    );
}

#[test]
fn should_validate_npm_sample_against_schema() {
    let schema = load_schema("schemas/registries/npm.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "name": "express",
            "dist-tags": { "latest": "4.21.0" },
            "versions": {
                "4.21.0": {
                    "name": "express",
                    "version": "4.21.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/express/-/express-4.21.0.tgz",
                        "shasum": "d57cb706d49623d4ac27833f1cbc466b668eb915"
                    }
                }
            }
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("npm sample should validate against schema");
}

#[test]
fn should_validate_cargo_sample_against_schema() {
    let schema = load_schema("schemas/registries/cargo.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "name": "serde",
            "vers": "1.0.210",
            "deps": [],
            "cksum": "abc123",
            "features": {},
            "yanked": false
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("Cargo sample should validate against schema");
}

#[test]
fn should_validate_cargo_config_sample_against_schema() {
    let schema = load_schema("schemas/registries/cargo-config.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "dl": "https://static.crates.io/crates/{crate}/{version}/download",
            "api": "https://crates.io",
            "auth-required": false
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("Cargo config sample should validate against schema");
}

#[test]
fn should_reject_cargo_sample_missing_cksum() {
    let schema = load_schema("schemas/registries/cargo.schema.json");
    let invalid: Value = serde_json::from_str(
        r#"{
            "name": "serde",
            "vers": "1.0.210",
            "deps": [],
            "features": {},
            "yanked": false
        }"#,
    )
    .unwrap();

    assert!(
        validate(&schema, &invalid).is_err(),
        "missing 'cksum' should fail validation"
    );
}

#[test]
fn should_validate_hex_sample_against_schema() {
    let schema = load_schema("schemas/registries/hex.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "name": "phoenix",
            "releases": [
                {
                    "version": "1.7.14",
                    "url": "https://hex.pm/api/packages/phoenix/releases/1.7.14",
                    "has_docs": true
                }
            ]
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("Hex sample should validate against schema");
}

#[test]
fn should_validate_pypi_index_sample_against_schema() {
    let schema = load_schema("schemas/registries/pypi-index.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "meta": { "api-version": "1.0" },
            "projects": [{ "name": "requests" }, { "name": "urllib3" }]
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("PyPI index sample should validate against schema");
}

#[test]
fn should_validate_nuget_service_index_sample_against_schema() {
    let schema = load_schema("schemas/registries/nuget-service-index.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "version": "3.0.0",
            "resources": [
                {
                    "@id": "https://api.nuget.org/v3-flatcontainer/",
                    "@type": "PackageBaseAddress/3.0.0",
                    "comment": "Base URL of where NuGet packages are stored"
                }
            ]
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("NuGet service index sample should validate against schema");
}

#[test]
fn should_validate_nuget_package_base_sample_against_schema() {
    let schema = load_schema("schemas/registries/nuget-package-base-address.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "versions": ["1.0.0", "1.1.0", "2.0.0"]
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("NuGet package base sample should validate against schema");
}

#[test]
fn should_validate_nuget_registration_sample_against_schema() {
    let schema = load_schema("schemas/registries/nuget-registration.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "@id": "https://api.nuget.org/v3/registration5-gz-semver2/sample/index.json",
            "@context": {
                "@vocab": "http://schema.nuget.org/schema#"
            },
            "count": 1,
            "items": [
                {
                    "@id": "https://api.nuget.org/v3/registration5-gz-semver2/sample/index.json#page/1.0.0/1.0.0",
                    "count": 1,
                    "lower": "1.0.0",
                    "upper": "1.0.0",
                    "items": [
                        {
                            "@id": "https://api.nuget.org/v3/registration5-gz-semver2/sample/1.0.0.json",
                            "catalogEntry": {
                                "@id": "https://api.nuget.org/v3/catalog0/data/2024.01.01/sample.1.0.0.json",
                                "id": "Sample",
                                "version": "1.0.0",
                                "description": "Sample package",
                                "dependencyGroups": []
                            },
                            "packageContent": "https://api.nuget.org/v3-flatcontainer/sample/1.0.0/sample.1.0.0.nupkg"
                        }
                    ]
                }
            ]
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("NuGet registration sample should validate against schema");
}

#[test]
fn should_validate_pub_package_sample_against_schema() {
    let schema = load_schema("schemas/registries/pub-package.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "name": "sample",
            "latest": {
                "version": "1.0.0",
                "archive_url": "https://pub.dev/api/archives/sample-1.0.0.tar.gz",
                "archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "pubspec": {
                    "name": "sample",
                    "version": "1.0.0",
                    "environment": { "sdk": ">=3.0.0 <4.0.0" },
                    "dependencies": {}
                }
            },
            "versions": [
                {
                    "version": "1.0.0",
                    "archive_url": "https://pub.dev/api/archives/sample-1.0.0.tar.gz",
                    "pubspec": {
                        "name": "sample",
                        "version": "1.0.0"
                    }
                }
            ]
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("pub package sample should validate against schema");
}

#[test]
fn should_validate_config_sample_against_schema() {
    let schema = load_schema("schemas/starmetal/config.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "server": { "bind": "127.0.0.1:8080" },
            "storage": { "backend": "fs" }
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("config sample should validate against schema");
}

#[test]
fn should_validate_lockfile_sample_against_schema() {
    let schema = load_schema("schemas/starmetal/lockfile.schema.json");
    let sample: Value = serde_json::from_str(
        r#"{
            "metadata": {
                "schema_version": 1,
                "generated_at": "2024-01-01T00:00:00Z",
                "starmetal_version": "0.1.0"
            },
            "packages": []
        }"#,
    )
    .unwrap();

    validate(&schema, &sample).expect("lockfile sample should validate against schema");
}
