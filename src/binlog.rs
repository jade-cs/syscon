//! Binary syscall log format for recording and replaying audit events.
//!
//! The log file consists of a sequence of length-prefixed bincode-encoded
//! `LogEntry` values. The first entry must be a `Header`. Subsequent entries
//! are `Syscall`, `ActionStart`, or `ActionEnd` records.
//!
//! Format on disk per record:
//!   [u32 little-endian length][bincode payload of that length]

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;

use serde::{Deserialize, Serialize};

use crate::error::SysconError;
use crate::util;

// ── Log entry types ─────────────────────────────────────────────────

/// A single entry in the binary log file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogEntry {
    Header(LogHeader),
    Syscall(Box<SyscallRecord>),
    ActionStart {
        action_id: u64,
        command: String,
        timestamp_ns: u64,
    },
    ActionEnd {
        action_id: u64,
        timestamp_ns: u64,
    },
}

/// File header — always the first record in a log file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHeader {
    /// Format version (currently 1).
    pub version: u16,
    /// Bitflags: 0x01 = audit/LOG mode, 0x02 = USER_NOTIF mode.
    pub flags: u16,
    /// Wall clock (CLOCK_REALTIME) at log start, for absolute time correlation.
    pub start_wall_ns: u64,
    /// Monotonic clock at log start, for relative timestamps.
    pub start_mono_ns: u64,
    /// Hostname of the machine.
    pub hostname: String,
}

/// A single syscall event with pre-resolved /proc data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRecord {
    /// Monotonic clock timestamp.
    pub timestamp_ns: u64,
    /// Wall clock timestamp for absolute time correlation.
    pub wall_clock_ns: u64,
    /// Process ID that made the syscall.
    pub pid: u32,
    /// x86_64 syscall number.
    pub syscall_nr: u32,
    /// Kernel comm field (up to 16 bytes).
    pub comm: String,
    /// Executable path from audit record.
    pub exe: String,
    /// Container ID (short 12-char hex), or None if not in a container.
    pub container_id: Option<String>,
    /// Parent PID (from /proc/pid/status).
    pub ppid: u32,
    /// Full command line (from /proc/pid/cmdline).
    pub cmdline: String,
    /// Open file descriptors (from /proc/pid/fd).
    pub open_files: Vec<String>,
    /// Active network connections (from /proc/pid/net/tcp).
    pub net_connections: Vec<String>,
    /// Resolved syscall arguments (populated in USER_NOTIF mode, None in LOG mode).
    pub args: Option<SyscallArgs>,
}

/// Resolved syscall arguments from USER_NOTIF interception.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallArgs {
    /// Raw register values (arg0..arg5).
    pub raw: [u64; 6],
    /// Resolved path argument (for open, exec, unlink, etc.).
    pub resolved_path: Option<String>,
    /// Second resolved path (for rename dest).
    pub resolved_path2: Option<String>,
    /// Resolved socket address (for connect, bind).
    pub resolved_addr: Option<String>,
    /// Flags argument (O_RDONLY, CLONE_*, etc.).
    pub flags: u64,
    /// Return value of the syscall (e.g., fd number for openat).
    #[serde(default)]
    pub return_value: i64,
}

// ── Constants ────────────────────────────────────────────────────────

const LOG_MAGIC: &[u8; 4] = b"SCON";
const LOG_VERSION: u16 = 1;

/// Flag: events captured via SECCOMP_RET_LOG + NETLINK_AUDIT.
pub const FLAG_AUDIT_MODE: u16 = 0x01;
/// Flag: events captured via SECCOMP_RET_USER_NOTIF.
#[allow(dead_code)]
pub const FLAG_NOTIFY_MODE: u16 = 0x02;

// ── Writer ──────────────────────────────────────────────────────────

/// Handle for sending log entries to the writer thread.
/// Dropping this handle signals the writer to flush and exit.
#[allow(dead_code)]
pub struct LogWriter {
    tx: mpsc::Sender<LogEntry>,
    join_handle: Option<thread::JoinHandle<io::Result<()>>>,
}

impl LogWriter {
    /// Start a new log writer that writes to the given path.
    /// Spawns a dedicated OS thread for buffered I/O.
    pub fn open(path: &Path, flags: u16) -> Result<Self, SysconError> {
        let file = File::create(path).map_err(|e| {
            SysconError::io(e, format!("creating log file {}", path.display()))
        })?;

        let (tx, rx) = mpsc::channel::<LogEntry>();

        let join_handle = thread::Builder::new()
            .name("binlog-writer".into())
            .spawn(move || writer_loop(file, rx, flags))
            .map_err(|e| SysconError::io(e, "spawning binlog writer thread"))?;

        Ok(Self {
            tx,
            join_handle: Some(join_handle),
        })
    }

    /// Send a log entry to the writer. Non-blocking; returns immediately.
    /// If the writer thread has exited, the entry is silently dropped.
    pub fn send(&self, entry: LogEntry) {
        let _ = self.tx.send(entry);
    }

    /// Flush and close the log file. Blocks until the writer finishes.
    #[allow(dead_code)]
    pub fn close(&mut self) -> io::Result<()> {
        // Replace the sender with a disconnected one to signal the writer loop to exit.
        let (dead_tx, _) = mpsc::channel();
        let _ = std::mem::replace(&mut self.tx, dead_tx);

        if let Some(handle) = self.join_handle.take() {
            handle.join().map_err(|_| {
                io::Error::other("binlog writer thread panicked")
            })?
        } else {
            Ok(())
        }
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        // If close() wasn't called explicitly, the sender is dropped here,
        // which signals the writer loop to exit. We don't wait for it
        // to avoid blocking in Drop.
    }
}

fn writer_loop(file: File, rx: mpsc::Receiver<LogEntry>, flags: u16) -> io::Result<()> {
    let mut writer = BufWriter::with_capacity(64 * 1024, file);

    // Write the magic bytes at the start of the file
    writer.write_all(LOG_MAGIC)?;

    // Write the header as the first log entry
    let wall_ns = wall_clock_ns();
    let mono_ns = util::monotonic_ns();
    let hostname = hostname();

    let header = LogEntry::Header(LogHeader {
        version: LOG_VERSION,
        flags,
        start_wall_ns: wall_ns,
        start_mono_ns: mono_ns,
        hostname,
    });
    write_entry(&mut writer, &header)?;

    // Drain entries from the channel until the sender is dropped
    while let Ok(entry) = rx.recv() {
        write_entry(&mut writer, &entry)?;
    }

    writer.flush()?;
    Ok(())
}

fn write_entry<W: Write>(writer: &mut W, entry: &LogEntry) -> io::Result<()> {
    let payload = bincode::serialize(entry).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("bincode serialize: {e}"))
    })?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    Ok(())
}

// ── Reader ──────────────────────────────────────────────────────────

/// Iterator over log entries in a binary log file.
pub struct LogReader {
    reader: BufReader<File>,
    header: LogHeader,
}

impl LogReader {
    /// Open a binary log file for reading.
    pub fn open(path: &Path) -> Result<Self, SysconError> {
        let file = File::open(path).map_err(|e| {
            SysconError::io(e, format!("opening log file {}", path.display()))
        })?;
        let mut reader = BufReader::with_capacity(64 * 1024, file);

        // Read and validate magic bytes
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).map_err(|e| {
            SysconError::io(e, "reading log file magic")
        })?;
        if &magic != LOG_MAGIC {
            return Err(SysconError::Config(format!(
                "not a syscon log file (magic: {:?}, expected: {:?})",
                magic, LOG_MAGIC
            )));
        }

        // Read the header entry
        let header_entry = read_entry(&mut reader).map_err(|e| {
            SysconError::io(e, "reading log header")
        })?;

        let header = match header_entry {
            Some(LogEntry::Header(h)) => h,
            Some(_) => {
                return Err(SysconError::Config(
                    "first log entry is not a header".into(),
                ));
            }
            None => {
                return Err(SysconError::Config("empty log file".into()));
            }
        };

        if header.version != LOG_VERSION {
            return Err(SysconError::Config(format!(
                "unsupported log version {} (expected {})",
                header.version, LOG_VERSION
            )));
        }

        Ok(Self { reader, header })
    }

    /// Get the log header.
    pub fn header(&self) -> &LogHeader {
        &self.header
    }
}

impl Iterator for LogReader {
    type Item = Result<LogEntry, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match read_entry(&mut self.reader) {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

fn read_entry<R: BufRead>(reader: &mut R) -> io::Result<Option<LogEntry>> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_bytes) as usize;

    // Sanity check: reject absurdly large entries (> 16 MiB)
    if len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("log entry too large: {len} bytes"),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;

    let entry: LogEntry = bincode::deserialize(&payload).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("bincode deserialize: {e}"))
    })?;

    Ok(Some(entry))
}

// ── Replay ──────────────────────────────────────────────────────────

/// Output format for replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayFormat {
    Receipt,
    Json,
    Dot,
}

impl fmt::Display for ReplayFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Receipt => write!(f, "receipt"),
            Self::Json => write!(f, "json"),
            Self::Dot => write!(f, "dot"),
        }
    }
}

impl std::str::FromStr for ReplayFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "receipt" => Ok(Self::Receipt),
            "json" => Ok(Self::Json),
            "dot" => Ok(Self::Dot),
            _ => Err(format!("unknown format '{}' (expected: receipt, json, dot)", s)),
        }
    }
}

/// Replay a binary log file, reconstructing state and producing output.
pub fn replay(
    path: &Path,
    format: ReplayFormat,
    container_filter: Option<&str>,
) -> Result<String, SysconError> {
    use crate::audit::SeccompEvent;
    use crate::graph;
    use crate::handlers;
    use crate::receipt;
    use crate::state::{ContainerBaseline, ContainerState, DaemonState};

    let reader = LogReader::open(path)?;
    let header = reader.header().clone();

    tracing::info!(
        version = header.version,
        hostname = %header.hostname,
        flags = header.flags,
        "replaying log file"
    );

    let mut state = DaemonState::new();
    let mut action_commands: HashMap<(String, u64), String> = HashMap::new();

    for result in reader {
        let entry = result.map_err(|e| SysconError::io(e, "reading log entry"))?;
        match entry {
            LogEntry::Header(_) => {
                // Duplicate header — skip
            }
            LogEntry::Syscall(rec) => {
                let Some(cid) = &rec.container_id else {
                    continue;
                };

                // Apply container filter if specified
                if let Some(filter) = container_filter
                    && !cid.starts_with(filter) {
                        continue;
                    }

                // Ensure container exists
                if !state.containers.contains_key(cid) {
                    state.containers.insert(
                        cid.clone(),
                        ContainerState::new(cid.clone(), ContainerBaseline::new()),
                    );
                }

                let container = state.containers.get_mut(cid).unwrap();

                // Build a SeccompEvent for the handler
                let event = SeccompEvent {
                    pid: rec.pid,
                    comm: rec.comm.clone(),
                    exe: rec.exe.clone(),
                    syscall: rec.syscall_nr,
                    arch: 0,
                    ip: 0,
                    code: 0,
                    sig: 0,
                };

                handlers::dispatch(
                    container,
                    &event,
                    rec.timestamp_ns,
                    rec.ppid,
                    &rec.cmdline,
                    &rec.open_files,
                    &rec.net_connections,
                    rec.args.as_ref(),
                );
            }
            LogEntry::ActionStart {
                action_id,
                command,
                timestamp_ns,
            } => {
                // Start action on all matching containers (or first seen)
                for (cid, container) in &mut state.containers {
                    if let Some(filter) = container_filter
                        && !cid.starts_with(filter) {
                            continue;
                        }
                    let action = crate::events::ActionLog::new(
                        action_id,
                        command.clone(),
                        timestamp_ns,
                    );
                    container.current_action = Some(action);
                    container.current_action_id = action_id;
                    action_commands
                        .insert((cid.clone(), action_id), command.clone());
                }
            }
            LogEntry::ActionEnd {
                action_id,
                timestamp_ns,
            } => {
                for (cid, container) in &mut state.containers {
                    if let Some(filter) = container_filter
                        && !cid.starts_with(filter) {
                            continue;
                        }
                    container.build_file_flow_edges();
                    container
                        .taint_graph
                        .propagate_taint(&mut container.process_table);

                    if let Some(mut action) = container.current_action.take() {
                        if action.action_id == action_id {
                            action.end_time = Some(timestamp_ns);
                            container.completed_actions.push(action);
                        } else {
                            // Mismatch — put it back
                            container.current_action = Some(action);
                        }
                    }
                    let _ = (cid, timestamp_ns);
                }
            }
        }
    }

    // Generate output
    let mut output = String::new();
    for (cid, container) in &mut state.containers {
        container
            .taint_graph
            .propagate_taint(&mut container.process_table);

        match format {
            ReplayFormat::Receipt => {
                // Generate receipts for all completed actions
                for action in &container.completed_actions {
                    let r = receipt::generate_receipt_from_action(container, action);
                    output.push_str(&r);
                    output.push('\n');
                }
                // Also generate receipt for any current (unclosed) action
                if let Some(action) = &container.current_action {
                    let r = receipt::generate_receipt_from_action(container, action);
                    output.push_str(&r);
                    output.push('\n');
                }
            }
            ReplayFormat::Dot => {
                let dot = graph::render_dot(container);
                output.push_str(&dot);
            }
            ReplayFormat::Json => {
                // Serialize the container state summary
                let summary = serde_json::json!({
                    "container_id": cid,
                    "processes": container.process_table.processes.len(),
                    "taint_edges": container.taint_graph.edges.len(),
                    "completed_actions": container.completed_actions.len(),
                    "file_nodes": container.file_nodes.len(),
                });
                if !output.is_empty() {
                    output.push('\n');
                }
                output.push_str(
                    &serde_json::to_string_pretty(&summary).unwrap_or_default(),
                );
            }
        }
    }

    if state.containers.is_empty() {
        tracing::warn!("no container events found in log file");
    }

    Ok(output)
}

// ── Helpers ─────────────────────────────────────────────────────────

fn wall_clock_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with CLOCK_REALTIME is always valid.
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes into buf, NUL-terminated.
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret == 0 {
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..len]).into_owned()
    } else {
        "unknown".to_string()
    }
}
