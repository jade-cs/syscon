mod audit;
mod control;
mod daemon;
mod docker;
mod events;
mod graph;
mod handlers;
mod namespace;
mod profile;
mod receipt;
mod seccomp;
mod state;
mod syscalls;

use anyhow::Context;
use clap::{Parser, Subcommand};
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
    /// Generate a Docker seccomp profile that logs target syscalls
    GenProfile {
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
        /// Comma-separated syscalls to log (default: full auditor set)
        #[arg(short, long, value_delimiter = ',')]
        syscalls: Option<Vec<String>>,
        /// Base profile to patch (default: generate fresh)
        #[arg(short, long)]
        base: Option<String>,
        /// Also block dangerous syscalls (ptrace, module loading, etc.) with ERRNO
        #[arg(long, default_value_t = false)]
        block_dangerous: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { port } => {
            let config = daemon::DaemonConfig { port };
            daemon::run(config).await
        }
        Commands::GenProfile {
            output,
            syscalls,
            base,
            block_dangerous,
        } => {
            let prof =
                profile::generate_profile(base.as_deref(), syscalls.as_deref(), block_dangerous)?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &prof)
                        .with_context(|| format!("Failed to write {path}"))?;
                    eprintln!("Wrote seccomp profile to {path}");
                    eprintln!("Usage:");
                    eprintln!("  docker run --security-opt seccomp={path} <image>");
                    eprintln!("  Or set in /etc/docker/daemon.json: \"seccomp-profile\": \"{path}\"");
                }
                None => {
                    print!("{prof}");
                }
            }
            Ok(())
        }
    }
}
