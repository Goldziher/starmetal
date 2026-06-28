use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use depot_core::package::{ArtifactId, Ecosystem, PackageName, VersionInfo, VersionMetadata};
use depot_core::publishing::PublishResult;
use depot_ops::{ConfigLoadOptions, ConfigOverrides, DepotRuntime, UpstreamOverride};
use tracing_subscriber::EnvFilter;

mod commands;
mod mcp;

#[derive(Parser)]
#[command(
    name = "sm",
    bin_name = "sm",
    about = "Starmetal package registry and registry proxy",
    version,
    propagate_version = true
)]
struct Cli {
    /// Path to config file. Defaults to DEPOT_CONFIG, ./depot.toml, then built-in defaults.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Skip config file lookup and use built-in defaults plus explicit flags.
    #[arg(long, global = true)]
    no_config: bool,

    /// Override the server bind address for this invocation.
    #[arg(long, global = true)]
    bind: Option<String>,

    /// Override the storage backend for this invocation.
    #[arg(long = "storage-backend", global = true)]
    storage_backend: Option<String>,

    /// Add an OpenDAL storage option as key=value. May be repeated.
    #[arg(long = "storage-option", global = true, value_parser = parse_key_value)]
    storage_options: Vec<(String, String)>,

    /// Select command output format.
    #[arg(long, global = true, default_value = "human")]
    output: OutputFormat,

    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the registry server.
    Serve,

    /// Inspect and manage configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Inspect configured registries.
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },

    /// Inspect and operate on packages.
    Package {
        #[command(subcommand)]
        action: PackageAction,
    },

    /// Inspect and remove cache entries.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Run the Starmetal MCP server.
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },

    /// Sync packages from upstream registries.
    Sync,

    /// Manage the Starmetal lock file.
    Lock {
        #[command(subcommand)]
        action: LockAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show the effective redacted configuration.
    Show,
    /// Validate the effective configuration.
    Validate,
    /// Write a minimal safe config file.
    Init {
        /// Destination config path.
        #[arg(default_value = "depot.toml")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum RegistryAction {
    /// List registry configuration and compile-time availability.
    List,
    /// Show runtime status.
    Status,
}

#[derive(Subcommand)]
enum PackageAction {
    /// List cached packages for an ecosystem.
    List(EcosystemArg),
    /// List versions for a package, fetching upstream metadata on miss.
    Versions(PackageArgs),
    /// Show metadata for one package version.
    Metadata(VersionArgs),
    /// Fetch one artifact through the cache integrity path.
    Fetch(ArtifactArgs),
    /// Publish one local artifact with explicit package metadata.
    Publish(PublishArgs),
    /// Mark a locally known version as yanked.
    Yank(VersionArgs),
    /// Mark a locally known version as not yanked.
    Unyank(VersionArgs),
}

#[derive(Subcommand)]
enum CacheAction {
    /// Delete a cached artifact and its BLAKE3 sidecar.
    DeleteArtifact {
        #[command(flatten)]
        artifact: ArtifactArgs,
        /// Confirm deletion.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Serve MCP over stdio.
    Serve {
        /// Expose mutating MCP tools.
        #[arg(long)]
        allow_writes: bool,
    },
}

#[derive(Subcommand)]
enum LockAction {
    /// Verify lock file integrity.
    Verify,
    /// Update the lock file.
    Update,
}

#[derive(Args)]
struct EcosystemArg {
    ecosystem: Ecosystem,
}

#[derive(Args)]
struct PackageArgs {
    ecosystem: Ecosystem,
    name: String,
}

#[derive(Args)]
struct VersionArgs {
    ecosystem: Ecosystem,
    name: String,
    version: String,
}

#[derive(Args)]
struct ArtifactArgs {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    filename: String,
    /// Write artifact bytes to this path. Use '-' for stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct PublishArgs {
    ecosystem: Ecosystem,
    file: PathBuf,
    /// Package name to publish.
    #[arg(long)]
    name: String,
    /// Package version to publish.
    #[arg(long = "package-version")]
    package_version: String,
    /// Artifact filename. Defaults to the input file name.
    #[arg(long)]
    filename: Option<String>,
    /// License expression or identifier.
    #[arg(long)]
    license: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    if let Err(err) = run(cli).await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> depot_core::error::Result<()> {
    let config_options = config_options(&cli);
    match cli.command {
        Commands::Serve => {
            let runtime = DepotRuntime::new(config_options).await?;
            commands::serve::run(runtime).await
        }
        Commands::Config { action } => run_config(action, config_options, cli.output),
        Commands::Registry { action } => {
            let runtime = DepotRuntime::new(config_options).await?;
            run_registry(action, &runtime, cli.output)
        }
        Commands::Package { action } => {
            let runtime = DepotRuntime::new(config_options).await?;
            run_package(action, &runtime, cli.output).await
        }
        Commands::Cache { action } => {
            let runtime = DepotRuntime::new(config_options).await?;
            run_cache(action, &runtime, cli.output).await
        }
        Commands::Mcp { action } => {
            let runtime = DepotRuntime::new(config_options).await?;
            match action {
                McpAction::Serve { allow_writes } => mcp::serve(runtime, allow_writes).await,
            }
        }
        Commands::Sync => commands::sync::run(),
        Commands::Lock { action } => match action {
            LockAction::Verify => commands::lock::verify(),
            LockAction::Update => commands::lock::update(),
        },
    }
}

fn run_config(
    action: ConfigAction,
    options: ConfigLoadOptions,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    match action {
        ConfigAction::Show => {
            let config = depot_ops::load_config(options)?;
            print_json(&config.redacted_value(), output)
        }
        ConfigAction::Validate => {
            let config = depot_ops::load_config(options)?;
            config.validate_mvp()?;
            match output {
                OutputFormat::Json => print_json(&serde_json::json!({"valid": true}), output),
                OutputFormat::Human => {
                    println!("config valid");
                    Ok(())
                }
            }
        }
        ConfigAction::Init { path } => {
            depot_ops::write_minimal_config(&path)?;
            match output {
                OutputFormat::Json => print_json(
                    &serde_json::json!({"created": path.to_string_lossy()}),
                    output,
                ),
                OutputFormat::Human => {
                    println!("created {}", path.display());
                    Ok(())
                }
            }
        }
    }
}

fn run_registry(
    action: RegistryAction,
    runtime: &DepotRuntime,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    match action {
        RegistryAction::List | RegistryAction::Status => print_registry_status(runtime, output),
    }
}

async fn run_package(
    action: PackageAction,
    runtime: &DepotRuntime,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    match action {
        PackageAction::List(args) => {
            let packages = runtime.list_packages(args.ecosystem).await?;
            print_package_refs(&packages, output)
        }
        PackageAction::Versions(args) => {
            let versions = runtime.versions(args.ecosystem, &args.name).await?;
            print_versions(&versions, output)
        }
        PackageAction::Metadata(args) => {
            let metadata = runtime
                .metadata(args.ecosystem, &args.name, &args.version)
                .await?;
            print_metadata(&metadata, output)
        }
        PackageAction::Fetch(args) => {
            let artifact = artifact_id(&args);
            let (artifact, data) = runtime.fetch_artifact(artifact).await?;
            write_artifact_output(args.output, &data)?;
            print_fetch_result(&artifact, data.len(), output)
        }
        PackageAction::Publish(args) => {
            let data = std::fs::read(&args.file)?;
            let filename = args.filename.unwrap_or_else(|| {
                args.file
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("artifact")
                    .to_string()
            });
            let result = runtime
                .publish_artifact(
                    args.ecosystem,
                    &args.name,
                    &args.package_version,
                    filename,
                    data.into(),
                    args.license,
                )
                .await?;
            print_publish_result(&result, output)
        }
        PackageAction::Yank(args) => {
            let metadata = runtime
                .set_yanked(args.ecosystem, &args.name, &args.version, true)
                .await?;
            print_metadata(&metadata, output)
        }
        PackageAction::Unyank(args) => {
            let metadata = runtime
                .set_yanked(args.ecosystem, &args.name, &args.version, false)
                .await?;
            print_metadata(&metadata, output)
        }
    }
}

async fn run_cache(
    action: CacheAction,
    runtime: &DepotRuntime,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    match action {
        CacheAction::DeleteArtifact { artifact, yes } => {
            if !yes {
                return Err(depot_core::error::DepotError::Config(
                    "cache delete requires --yes".to_string(),
                ));
            }
            let result = runtime
                .delete_cached_artifact(&artifact_id(&artifact))
                .await?;
            match output {
                OutputFormat::Json => print_json(&result, output),
                OutputFormat::Human => {
                    if result.deleted_keys.is_empty() {
                        println!("no cache entries deleted");
                    } else {
                        println!("deleted {} cache entries", result.deleted_keys.len());
                        for key in result.deleted_keys {
                            println!("{key}");
                        }
                    }
                    Ok(())
                }
            }
        }
    }
}

fn config_options(cli: &Cli) -> ConfigLoadOptions {
    ConfigLoadOptions {
        path: cli.config.clone(),
        no_config: cli.no_config,
        overrides: ConfigOverrides {
            bind: cli.bind.clone(),
            storage_backend: cli.storage_backend.clone(),
            storage_options: cli.storage_options.clone(),
            upstreams: Vec::<UpstreamOverride>::new(),
        },
    }
}

fn init_tracing(verbose: u8) {
    let filter = match verbose {
        0 => "depot=warn",
        1 => "depot=info",
        2 => "depot=debug",
        _ => "depot=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .without_time()
        .init();
}

fn print_json<T: serde::Serialize + ?Sized>(
    value: &T,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
        OutputFormat::Human => {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
    }
    Ok(())
}

fn print_registry_status(
    runtime: &DepotRuntime,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    let status = runtime.status();
    if matches!(output, OutputFormat::Json) {
        return print_json(&status, output);
    }
    println!("bind: {}", status.bind);
    println!("storage: {}", status.storage_backend);
    println!("registries:");
    for registry in status.registries {
        let enabled = if registry.enabled {
            "enabled"
        } else {
            "disabled"
        };
        let compiled = if registry.compiled {
            "compiled"
        } else {
            "not compiled"
        };
        let url = registry.url.as_deref().unwrap_or("-");
        println!(
            "  {:<10} {:<8} {:<12} {}",
            registry.ecosystem, enabled, compiled, url
        );
    }
    Ok(())
}

fn print_package_refs(
    packages: &[depot_ops::PackageRef],
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    if matches!(output, OutputFormat::Json) {
        return print_json(&packages, output);
    }
    for package in packages {
        println!("{} {}", package.ecosystem, package.name);
    }
    Ok(())
}

fn print_versions(versions: &[VersionInfo], output: OutputFormat) -> depot_core::error::Result<()> {
    if matches!(output, OutputFormat::Json) {
        return print_json(&versions, output);
    }
    for version in versions {
        if version.yanked {
            println!("{} yanked", version.version);
        } else {
            println!("{}", version.version);
        }
    }
    Ok(())
}

fn print_metadata(
    metadata: &VersionMetadata,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    if matches!(output, OutputFormat::Json) {
        return print_json(&metadata, output);
    }
    println!("name: {}", metadata.name);
    println!("version: {}", metadata.version);
    println!("yanked: {}", metadata.yanked);
    if let Some(license) = &metadata.license {
        println!("license: {license}");
    }
    println!("artifacts:");
    for artifact in &metadata.artifacts {
        println!(
            "  {} ({} bytes, blake3 {})",
            artifact.filename, artifact.size, artifact.blake3
        );
    }
    Ok(())
}

fn print_fetch_result(
    artifact: &ArtifactId,
    bytes: usize,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    let result = depot_ops::ArtifactFetchResult {
        bytes,
        artifact: artifact.clone(),
    };
    if matches!(output, OutputFormat::Json) {
        return print_json(&result, output);
    }
    println!(
        "fetched {} {} {} {} ({} bytes)",
        artifact.ecosystem, artifact.name, artifact.version, artifact.filename, bytes
    );
    Ok(())
}

fn print_publish_result(
    result: &PublishResult,
    output: OutputFormat,
) -> depot_core::error::Result<()> {
    if matches!(output, OutputFormat::Json) {
        return print_json(&result, output);
    }
    println!(
        "published {} {} {} ({:?}, {} artifact(s))",
        result.ecosystem,
        result.name,
        result.version,
        result.mode,
        result.artifacts.len()
    );
    Ok(())
}

fn write_artifact_output(path: Option<PathBuf>, data: &[u8]) -> depot_core::error::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if path == std::path::Path::new("-") {
        use std::io::Write;
        std::io::stdout().write_all(data)?;
    } else {
        std::fs::write(path, data)?;
    }
    Ok(())
}

fn artifact_id(args: &ArtifactArgs) -> ArtifactId {
    let raw = PackageName::new(&args.name);
    ArtifactId {
        ecosystem: args.ecosystem,
        name: PackageName::new(raw.normalized(args.ecosystem).into_owned()),
        version: args.version.clone(),
        filename: args.filename.clone(),
    }
}

fn parse_key_value(raw: &str) -> Result<(String, String), String> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| "expected key=value".to_string())?;
    if key.trim().is_empty() {
        return Err("key must not be empty".to_string());
    }
    Ok((key.trim().to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_version_and_help_flags() {
        assert!(Cli::try_parse_from(["sm", "--version"]).is_err());
        assert!(Cli::try_parse_from(["sm", "--help"]).is_err());
    }

    #[test]
    fn parses_no_config_registry_status() {
        let cli = Cli::try_parse_from([
            "sm",
            "--no-config",
            "--storage-backend",
            "memory",
            "registry",
            "status",
        ])
        .expect("cli should parse");
        assert!(cli.no_config);
        assert_eq!(cli.storage_backend.as_deref(), Some("memory"));
        assert!(matches!(
            cli.command,
            Commands::Registry {
                action: RegistryAction::Status
            }
        ));
    }

    #[test]
    fn parses_storage_options_as_key_value() {
        let cli = Cli::try_parse_from(["sm", "--storage-option", "root=./data", "config", "show"])
            .expect("cli should parse");
        assert_eq!(
            cli.storage_options,
            vec![("root".to_string(), "./data".to_string())]
        );
    }

    #[test]
    fn parses_explicit_publish_command() {
        let cli = Cli::try_parse_from([
            "sm",
            "package",
            "publish",
            "npm",
            "sample.tgz",
            "--name",
            "sample",
            "--package-version",
            "1.0.0",
        ])
        .expect("cli should parse");
        assert!(matches!(
            cli.command,
            Commands::Package {
                action: PackageAction::Publish(_)
            }
        ));
    }
}
