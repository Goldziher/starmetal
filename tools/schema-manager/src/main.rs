use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use depot_core::config::Config;
use depot_core::lockfile::LockFile;
use depot_core::registry::cargo::{CargoConfig, CargoIndexEntry};
use depot_core::registry::hex::HexPackage;
use depot_core::registry::npm::NpmPackument;
use depot_core::registry::nuget::{
    NugetPackageVersions, NugetRegistrationIndex, NugetServiceIndex,
};
use depot_core::registry::pubdev::PubPackage;
use depot_core::registry::pypi::{PypiIndex, PypiProject};
use schemars::schema_for;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const TOOL_NAME: &str = "depot-schema-manager";
const DEFAULT_SOURCES: &str = "schemas/sources.toml";
const DEFAULT_SCHEMA_ROOT: &str = "schemas";
const MANIFEST_PATH: &str = "manifest.json";

type DynError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T> = std::result::Result<T, DynError>;

#[derive(Debug, Parser)]
#[command(
    name = "depot-schema-manager",
    about = "Manage Depot registry schema artifacts"
)]
struct Cli {
    #[arg(long, default_value = DEFAULT_SOURCES)]
    sources: PathBuf,
    #[arg(long, default_value = DEFAULT_SCHEMA_ROOT)]
    schema_root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Fetch {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        live: bool,
    },
    Generate {
        #[arg(long)]
        check: bool,
    },
    Refresh,
}

#[derive(Debug, Deserialize)]
struct SourcesFile {
    source: Vec<Source>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Source {
    id: String,
    registry: String,
    kind: String,
    url: String,
    official: bool,
    fetched: bool,
    path: Option<PathBuf>,
    description: String,
}

#[derive(Debug, Serialize)]
struct Manifest {
    schema_version: u32,
    generated_by: &'static str,
    sources: Vec<ManifestSource>,
    schemas: Vec<ManifestSchema>,
}

#[derive(Debug, Serialize)]
struct ManifestSource {
    id: String,
    registry: String,
    kind: String,
    url: String,
    official: bool,
    fetched: bool,
    path: Option<String>,
    blake3: Option<String>,
    description: String,
}

#[derive(Debug, Serialize)]
struct ManifestSchema {
    id: String,
    registry: String,
    path: String,
    schema_kind: String,
    source_type: String,
    source_file: String,
    source_ids: Vec<String>,
    source_kinds: Vec<String>,
    generated_by: &'static str,
    validated_by: String,
    blake3: String,
}

#[derive(Clone)]
struct SchemaSpec {
    id: &'static str,
    registry: &'static str,
    path: &'static str,
    title: &'static str,
    description: &'static str,
    schema_kind: &'static str,
    source_type: &'static str,
    source_file: &'static str,
    source_ids: &'static [&'static str],
    source_kinds: &'static [&'static str],
    validated_by: &'static str,
    schema: Value,
}

#[derive(Clone)]
struct RenderedSchema {
    spec: SchemaSpec,
    content: String,
    blake3: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let sources = load_sources(&cli.sources)?;

    match cli.command {
        Command::Fetch { check, live } => {
            fetch_sources(&sources, &cli.schema_root, check, live).await?
        }
        Command::Generate { check } => generate_schemas(&sources, &cli.schema_root, check)?,
        Command::Refresh => {
            fetch_sources(&sources, &cli.schema_root, false, true).await?;
            generate_schemas(&sources, &cli.schema_root, false)?;
        }
    }

    Ok(())
}

fn load_sources(path: &Path) -> Result<Vec<Source>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let parsed: SourcesFile = toml::from_str(&content)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    Ok(parsed.source)
}

async fn fetch_sources(
    sources: &[Source],
    schema_root: &Path,
    check: bool,
    live: bool,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("depot-schema-manager/0.1")
        .build()
        .map_err(|err| format!("failed to build HTTP client: {err}"))?;
    let mut failures = Vec::new();

    for source in sources.iter().filter(|source| source.fetched) {
        let relative_path = source
            .path
            .as_ref()
            .ok_or_else(|| format!("source '{}' is fetched but has no path", source.id))?;
        let output_path = schema_root.join(relative_path);
        if check && !live {
            if !output_path.exists() {
                failures.push(format!("{} is missing", output_path.display()));
            }
            continue;
        }
        let bytes = client
            .get(&source.url)
            .send()
            .await
            .map_err(|err| format!("failed to fetch {}: {err}", source.url))?
            .error_for_status()
            .map_err(|err| format!("failed to fetch {}: {err}", source.url))?
            .bytes()
            .await
            .map_err(|err| format!("failed to read response from {}: {err}", source.url))?;

        if check {
            let existing = std::fs::read(&output_path)
                .map_err(|err| format!("failed to read {}: {err}", output_path.display()))?;
            if existing != bytes {
                failures.push(format!(
                    "{} differs from {}",
                    output_path.display(),
                    source.url
                ));
            }
            continue;
        }

        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        std::fs::write(&output_path, &bytes)
            .map_err(|err| format!("failed to write {}: {err}", output_path.display()))?;
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}

fn generate_schemas(sources: &[Source], schema_root: &Path, check: bool) -> Result<()> {
    let rendered = render_all_schemas()?;
    let manifest = render_manifest(sources, schema_root, &rendered)?;
    let manifest_content = json_pretty(&manifest)?;

    let mut failures = Vec::new();

    for schema in &rendered {
        let output_path = schema_root.join(schema.spec.path);
        if check {
            compare_file(&output_path, &schema.content, &mut failures)?;
        } else {
            write_file(&output_path, &schema.content)?;
        }
    }

    let manifest_path = schema_root.join(MANIFEST_PATH);
    if check {
        compare_file(&manifest_path, &manifest_content, &mut failures)?;
    } else {
        write_file(&manifest_path, &manifest_content)?;
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}

fn compare_file(path: &Path, expected: &str, failures: &mut Vec<String>) -> Result<()> {
    let existing = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    if existing != expected {
        failures.push(format!("{} is not up to date", path.display()));
    }
    Ok(())
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    std::fs::write(path, content)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(())
}

fn render_all_schemas() -> Result<Vec<RenderedSchema>> {
    schema_specs()
        .into_iter()
        .map(|spec| {
            let mut schema = spec.schema.clone();
            enrich_schema(&mut schema, &spec)?;
            let content = json_pretty(&schema)?;
            let blake3 = blake3_hex(content.as_bytes());
            Ok(RenderedSchema {
                spec,
                content,
                blake3,
            })
        })
        .collect()
}

fn schema_specs() -> Vec<SchemaSpec> {
    vec![
        SchemaSpec {
            id: "pypi-simple-project",
            registry: "pypi",
            path: "registries/pypi.schema.json",
            title: "PyPI Simple Repository API Project Detail",
            description: "Depot-derived JSON Schema for a PEP 691 Simple API project detail response.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::pypi::PypiProject",
            source_file: "crates/depot-core/src/registry/pypi.rs",
            source_ids: &[
                "pypa-specifications-index",
                "pypi-simple-api",
                "pypi-core-metadata",
                "pypi-name-normalization",
                "pypi-binary-distribution-format",
                "pypi-source-distribution-format",
                "pypi-json-api",
            ],
            source_kinds: &["official-prose-index", "official-prose"],
            validated_by: "crates/depot-core/tests/schema_validation.rs; tests/conformance",
            schema: serde_json::to_value(schema_for!(PypiProject)).expect("schema serializes"),
        },
        SchemaSpec {
            id: "pypi-simple-index",
            registry: "pypi",
            path: "registries/pypi-index.schema.json",
            title: "PyPI Simple Repository API Project Index",
            description: "Depot-derived JSON Schema for a PEP 691 Simple API project index response.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::pypi::PypiIndex",
            source_file: "crates/depot-core/src/registry/pypi.rs",
            source_ids: &[
                "pypa-specifications-index",
                "pypi-simple-api",
                "pypi-name-normalization",
            ],
            source_kinds: &["official-prose-index", "official-prose"],
            validated_by: "crates/depot-core/tests/schema_validation.rs; tests/conformance",
            schema: serde_json::to_value(schema_for!(PypiIndex)).expect("schema serializes"),
        },
        SchemaSpec {
            id: "npm-packument",
            registry: "npm",
            path: "registries/npm.schema.json",
            title: "npm Registry Packument",
            description: "Depot-derived JSON Schema for npm registry package metadata.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::npm::NpmPackument",
            source_file: "crates/depot-core/src/registry/npm.rs",
            source_ids: &["npm-package-metadata", "npm-types"],
            source_kinds: &["official-prose", "official-typescript"],
            validated_by: "crates/depot-core/tests/schema_validation.rs; tests/conformance",
            schema: serde_json::to_value(schema_for!(NpmPackument)).expect("schema serializes"),
        },
        SchemaSpec {
            id: "cargo-sparse-index-entry",
            registry: "cargo",
            path: "registries/cargo.schema.json",
            title: "Cargo Sparse Index Entry",
            description: "Depot-derived JSON Schema for one Cargo sparse index JSONL entry.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::cargo::CargoIndexEntry",
            source_file: "crates/depot-core/src/registry/cargo.rs",
            source_ids: &["cargo-registry-index"],
            source_kinds: &["official-prose"],
            validated_by: "crates/depot-core/tests/schema_validation.rs; tests/conformance",
            schema: serde_json::to_value(schema_for!(CargoIndexEntry)).expect("schema serializes"),
        },
        SchemaSpec {
            id: "cargo-config",
            registry: "cargo",
            path: "registries/cargo-config.schema.json",
            title: "Cargo Sparse Registry Config",
            description: "Depot-derived JSON Schema for Cargo sparse registry config.json.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::cargo::CargoConfig",
            source_file: "crates/depot-core/src/registry/cargo.rs",
            source_ids: &["cargo-registry-index"],
            source_kinds: &["official-prose"],
            validated_by: "crates/depot-core/tests/schema_validation.rs; tests/conformance",
            schema: serde_json::to_value(schema_for!(CargoConfig)).expect("schema serializes"),
        },
        SchemaSpec {
            id: "hex-package-http-api",
            registry: "hex",
            path: "registries/hex.schema.json",
            title: "Hex Package HTTP API",
            description: "Depot-derived JSON Schema for the Hex package HTTP API response; official registry resources use protobuf.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::hex::HexPackage",
            source_file: "crates/depot-core/src/registry/hex.rs",
            source_ids: &[
                "hex-registry-v2",
                "hex-package-proto",
                "hex-package-metadata",
            ],
            source_kinds: &["official-prose", "official-protobuf"],
            validated_by: "crates/depot-core/tests/schema_validation.rs; tests/conformance",
            schema: serde_json::to_value(schema_for!(HexPackage)).expect("schema serializes"),
        },
        SchemaSpec {
            id: "depot-config",
            registry: "depot",
            path: "depot/config.schema.json",
            title: "Depot Configuration",
            description: "Depot-owned JSON Schema for depot.toml.",
            schema_kind: "depot-owned-json-schema",
            source_type: "depot_core::config::Config",
            source_file: "crates/depot-core/src/config.rs",
            source_ids: &["depot-config"],
            source_kinds: &["depot-rust-type"],
            validated_by: "crates/depot-core/tests/schema_validation.rs",
            schema: serde_json::to_value(schema_for!(Config)).expect("schema serializes"),
        },
        SchemaSpec {
            id: "nuget-v3-service-index",
            registry: "nuget",
            path: "registries/nuget-service-index.schema.json",
            title: "NuGet V3 Service Index",
            description: "Depot-derived JSON Schema for the NuGet V3 service index response.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::nuget::NugetServiceIndex",
            source_file: "crates/depot-core/src/registry/nuget.rs",
            source_ids: &["nuget-v3-overview", "nuget-v3-service-index"],
            source_kinds: &["official-prose"],
            validated_by: "crates/depot-core/tests/schema_validation.rs",
            schema: serde_json::to_value(schema_for!(NugetServiceIndex))
                .expect("schema serializes"),
        },
        SchemaSpec {
            id: "nuget-v3-package-base-address",
            registry: "nuget",
            path: "registries/nuget-package-base-address.schema.json",
            title: "NuGet V3 Package Base Address Versions",
            description: "Depot-derived JSON Schema for the NuGet PackageBaseAddress version listing response.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::nuget::NugetPackageVersions",
            source_file: "crates/depot-core/src/registry/nuget.rs",
            source_ids: &["nuget-v3-overview", "nuget-v3-package-base-address"],
            source_kinds: &["official-prose"],
            validated_by: "crates/depot-core/tests/schema_validation.rs",
            schema: serde_json::to_value(schema_for!(NugetPackageVersions))
                .expect("schema serializes"),
        },
        SchemaSpec {
            id: "nuget-v3-registration",
            registry: "nuget",
            path: "registries/nuget-registration.schema.json",
            title: "NuGet V3 Registration Index",
            description: "Depot-derived JSON Schema for NuGet V3 registration metadata.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::nuget::NugetRegistrationIndex",
            source_file: "crates/depot-core/src/registry/nuget.rs",
            source_ids: &[
                "nuget-v3-overview",
                "nuget-v3-registration",
                "nuget-nuspec-xsd",
            ],
            source_kinds: &["official-prose", "official-xml-schema"],
            validated_by: "crates/depot-core/tests/schema_validation.rs",
            schema: serde_json::to_value(schema_for!(NugetRegistrationIndex))
                .expect("schema serializes"),
        },
        SchemaSpec {
            id: "pub-package",
            registry: "pub",
            path: "registries/pub-package.schema.json",
            title: "Hosted Pub Package Metadata",
            description: "Depot-derived JSON Schema for Hosted Pub Repository package metadata.",
            schema_kind: "depot-derived-json-schema",
            source_type: "depot_core::registry::pubdev::PubPackage",
            source_file: "crates/depot-core/src/registry/pubdev.rs",
            source_ids: &[
                "pub-hosted-repository-v2",
                "pub-dev-supported-api",
                "pub-dev-package-api-dtos",
            ],
            source_kinds: &["official-prose", "official-dart-source"],
            validated_by: "crates/depot-core/tests/schema_validation.rs",
            schema: serde_json::to_value(schema_for!(PubPackage)).expect("schema serializes"),
        },
        SchemaSpec {
            id: "depot-lockfile",
            registry: "depot",
            path: "depot/lockfile.schema.json",
            title: "Depot Lock File",
            description: "Depot-owned JSON Schema for depot-lock.toml.",
            schema_kind: "depot-owned-json-schema",
            source_type: "depot_core::lockfile::LockFile",
            source_file: "crates/depot-core/src/lockfile.rs",
            source_ids: &["depot-lockfile"],
            source_kinds: &["depot-rust-type"],
            validated_by: "crates/depot-core/tests/schema_validation.rs",
            schema: serde_json::to_value(schema_for!(LockFile)).expect("schema serializes"),
        },
    ]
}

fn enrich_schema(schema: &mut Value, spec: &SchemaSpec) -> Result<()> {
    let object = schema
        .as_object_mut()
        .ok_or_else(|| format!("schema '{}' did not render as an object", spec.id))?;
    object.insert(
        "$id".to_string(),
        Value::String(format!("https://schemas.depot.local/{}", spec.path)),
    );
    object.insert("title".to_string(), Value::String(spec.title.to_string()));
    object.insert(
        "description".to_string(),
        Value::String(spec.description.to_string()),
    );
    object.insert(
        "x-depot-source".to_string(),
        json!({
            "schema_kind": spec.schema_kind,
            "source_type": spec.source_type,
            "source_file": spec.source_file,
            "source_ids": spec.source_ids,
            "source_kinds": spec.source_kinds,
            "generated_by": TOOL_NAME,
            "validated_by": spec.validated_by,
        }),
    );
    Ok(())
}

fn render_manifest(
    sources: &[Source],
    schema_root: &Path,
    schemas: &[RenderedSchema],
) -> Result<Manifest> {
    let manifest_sources = sources
        .iter()
        .map(|source| {
            let blake3 = source
                .path
                .as_ref()
                .filter(|_| source.fetched)
                .map(|path| file_blake3(&schema_root.join(path)))
                .transpose()?;
            Ok(ManifestSource {
                id: source.id.clone(),
                registry: source.registry.clone(),
                kind: source.kind.clone(),
                url: source.url.clone(),
                official: source.official,
                fetched: source.fetched,
                path: source
                    .path
                    .as_ref()
                    .map(|path| path.to_string_lossy().to_string()),
                blake3,
                description: source.description.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let manifest_schemas = schemas
        .iter()
        .map(|schema| ManifestSchema {
            id: schema.spec.id.to_string(),
            registry: schema.spec.registry.to_string(),
            path: schema.spec.path.to_string(),
            schema_kind: schema.spec.schema_kind.to_string(),
            source_type: schema.spec.source_type.to_string(),
            source_file: schema.spec.source_file.to_string(),
            source_ids: schema
                .spec
                .source_ids
                .iter()
                .map(|source_id| source_id.to_string())
                .collect(),
            source_kinds: schema
                .spec
                .source_kinds
                .iter()
                .map(|source_kind| source_kind.to_string())
                .collect(),
            generated_by: TOOL_NAME,
            validated_by: schema.spec.validated_by.to_string(),
            blake3: schema.blake3.clone(),
        })
        .collect();

    Ok(Manifest {
        schema_version: 1,
        generated_by: TOOL_NAME,
        sources: manifest_sources,
        schemas: manifest_schemas,
    })
}

fn file_blake3(path: &Path) -> Result<String> {
    let bytes =
        std::fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    Ok(blake3_hex(&bytes))
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn json_pretty<T: Serialize>(value: &T) -> Result<String> {
    let mut output = serde_json::to_string_pretty(value)?;
    output.push('\n');
    Ok(output)
}

#[allow(dead_code)]
fn sorted_object(value: BTreeMap<String, Value>) -> Value {
    Value::Object(value.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_schemas_include_ids_and_provenance() {
        let schemas = render_all_schemas().expect("schemas should render");

        assert!(
            schemas
                .iter()
                .any(|schema| schema.spec.id == "pypi-simple-project")
        );
        for schema in schemas {
            let value: Value = serde_json::from_str(&schema.content).expect("schema should parse");
            assert!(
                value.get("$id").is_some(),
                "{} should have $id",
                schema.spec.id
            );
            assert!(
                value.get("x-depot-source").is_some(),
                "{} should have source metadata",
                schema.spec.id
            );
            assert_eq!(schema.blake3.len(), 64);
        }
    }

    #[test]
    fn sources_toml_documents_supported_registry_inputs() {
        let sources = load_sources(&workspace_sources_path()).expect("sources should parse");

        for id in [
            "pypa-specifications-index",
            "pypi-simple-api",
            "pypi-core-metadata",
            "npm-types",
            "cargo-registry-index",
            "hex-package-proto",
            "maven-pom-xsd",
            "sonatype-central-publisher-openapi",
            "rubygems-compact-index-api",
            "rubygems-bundler-compact-index-parser",
            "rubygems-gem-validator-schema",
            "nuget-v3-service-index",
            "nuget-v3-package-base-address",
            "nuget-v3-registration",
            "nuget-nuspec-xsd",
            "pub-hosted-repository-v2",
            "pub-dev-package-api-dtos",
            "osv-schema",
        ] {
            assert!(
                sources.iter().any(|source| source.id == id),
                "sources.toml should include {id}"
            );
        }
    }

    fn workspace_sources_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("tool should live under tools/schema-manager")
            .join(DEFAULT_SOURCES)
    }
}
