mod audit;
mod audit_parse;
mod ingest;
mod communities;
mod control;
mod daemon;
mod docker;
pub mod error;
mod events;
mod graph;
mod handlers;
mod mitre;
mod receipt;
mod semantic;
mod state;
mod syscalls;
mod util;

use clap::{Parser, Subcommand};
use error::SysconError;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "syscon",
    version,
    about = "Auditor daemon and syscall monitor for container security"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the auditor daemon (audit listener + HTTP API)
    Daemon {
        /// Port for the HTTP API
        #[arg(long, default_value_t = 9900)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), SysconError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,rocket=warn,hyper=warn,rustls=warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { port } => {
            daemon::run(daemon::DaemonConfig { port }).await
        }
    }
}
