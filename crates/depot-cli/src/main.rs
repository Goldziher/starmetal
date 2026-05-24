use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;

#[derive(Parser)]
#[command(
    name = "depot",
    about = "Self-hosted armored universal package registry",
    version,
    propagate_version = true
)]
struct Cli {
    /// Path to config file (default: depot.toml or DEPOT_CONFIG env)
    #[arg(long, global = true)]
    config: Option<String>,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the registry server
    Serve,

    /// Sync packages from upstream registries
    Sync,

    /// Manage the depot lock file
    Lock {
        #[command(subcommand)]
        action: LockAction,
    },

    /// Show current configuration
    Config,
}

#[derive(Subcommand)]
enum LockAction {
    /// Verify lock file integrity
    Verify,
    /// Update the lock file
    Update,
}

fn main() {
    let cli = Cli::parse();

    let filter = match cli.verbose {
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

    let config = match &cli.config {
        Some(path) => depot_core::config::Config::load_from(std::path::Path::new(path))
            .unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            }),
        None => depot_core::config::Config::load().unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        }),
    };

    match cli.command {
        Commands::Serve => commands::serve::run(config),
        Commands::Sync => commands::sync::run(config),
        Commands::Lock { action } => match action {
            LockAction::Verify => commands::lock::verify(config),
            LockAction::Update => commands::lock::update(config),
        },
        Commands::Config => {
            let output = toml::to_string_pretty(&config.redacted_value()).unwrap_or_else(|e| {
                eprintln!("error: failed to serialize config: {e}");
                std::process::exit(1);
            });
            println!("{output}");
        }
    }
}
