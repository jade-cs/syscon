mod audit;
mod audit_rules;
mod binlog;
mod communities;
mod control;
mod daemon;
mod docker;
pub mod error;
mod events;
mod graph;
mod handlers;
mod mitre;
mod namespace;
mod notifier;
mod profile;
mod receipt;
mod reduce;
mod semantic;
// Phase 3 will integrate seccomp user notify into the daemon.
// Until then, most of this module is unused but architecturally important.
#[allow(dead_code)]
mod seccomp;
mod state;
mod syscalls;
mod util;

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
        /// Write binary syscall log to this file
        #[arg(long)]
        log_file: Option<String>,
        /// Listen on this Unix socket for seccomp user notify fds from container runtimes.
        /// Enables argument capture via SECCOMP_RET_USER_NOTIF.
        #[arg(long)]
        notify_socket: Option<String>,
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
        /// Use SCMP_ACT_NOTIFY instead of SCMP_ACT_LOG, pointing to this Unix socket.
        /// This enables the daemon to read syscall arguments (requires --notify-socket on daemon).
        #[arg(long)]
        notify_socket: Option<String>,
    },
    /// Analyze a binary log for repetitive patterns and show reduction stats
    Reduce {
        /// Path to binary log file
        #[arg(short, long)]
        input: String,
        /// Write a reduced log to this path (optional; if omitted, just prints stats)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Replay a binary syscall log and generate output
    Replay {
        /// Path to binary log file
        #[arg(short, long)]
        input: String,
        /// Output format: receipt, json, or dot
        #[arg(short, long, default_value = "receipt")]
        format: String,
        /// Filter by container ID prefix
        #[arg(short, long)]
        container: Option<String>,
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
        Commands::Daemon {
            port,
            log_file,
            notify_socket,
        } => {
            let config = daemon::DaemonConfig {
                port,
                log_file,
                notify_socket,
            };
            daemon::run(config).await
        }
        Commands::GenProfile {
            output,
            syscalls,
            base,
            block_dangerous,
            notify_socket,
        } => {
            let prof = profile::generate_profile(
                base.as_deref(),
                syscalls.as_deref(),
                block_dangerous,
                notify_socket.as_deref(),
            )?;
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
        Commands::Reduce { input, output } => {
            let path = std::path::Path::new(&input);
            if let Some(out_path) = output {
                let (reduced, report) = reduce::reduce_log(path)?;
                eprintln!(
                    "Reduced {} → {} events ({:.1}% reduction)",
                    report.total_events,
                    report.unique_events,
                    report.reduction_ratio * 100.0,
                );
                // Write reduced log
                let file = std::fs::File::create(&out_path)
                    .with_context(|| format!("creating {out_path}"))?;
                let mut writer = std::io::BufWriter::new(file);
                std::io::Write::write_all(&mut writer, b"SCON")?;
                for entry in &reduced {
                    let payload = bincode::serialize(entry)
                        .map_err(|e| anyhow::anyhow!("serialize: {e}"))?;
                    let len = payload.len() as u32;
                    std::io::Write::write_all(&mut writer, &len.to_le_bytes())?;
                    std::io::Write::write_all(&mut writer, &payload)?;
                }
                std::io::Write::flush(&mut writer)?;
                eprintln!("Wrote reduced log to {out_path}");
            } else {
                let report = reduce::analyze(path)?;
                print!("{}", reduce::format_report(&report));
            }
            Ok(())
        }
        Commands::Replay {
            input,
            format,
            container,
        } => {
            let fmt: binlog::ReplayFormat = format
                .parse()
                .map_err(|e: String| anyhow::anyhow!("{e}"))?;
            let output = binlog::replay(
                std::path::Path::new(&input),
                fmt,
                container.as_deref(),
            )?;
            print!("{output}");
            Ok(())
        }
    }
}
