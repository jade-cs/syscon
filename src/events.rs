use serde::Serialize;

/// A filesystem operation observed via audit.
#[derive(Debug, Clone, Serialize)]
pub struct FileEvent {
    pub pid: u32,
    pub timestamp: u64, // monotonic nanoseconds
    pub operation: FileOp,
    /// Best-effort path — from `exe` field in LOG mode, empty if unavailable.
    pub path: String,
    pub flags: u32,
    pub is_sensitive: bool,
    pub is_new_binary: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum FileOp {
    Open,
    OpenWrite,
    Create,
    Read,
    Write,
    Unlink,
    Rename,
    Chmod,
    Chown,
    Exec,
}

impl std::fmt::Display for FileOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileOp::Open => write!(f, "open_read"),
            FileOp::OpenWrite => write!(f, "open_write"),
            FileOp::Create => write!(f, "create"),
            FileOp::Read => write!(f, "read"),
            FileOp::Write => write!(f, "write"),
            FileOp::Unlink => write!(f, "unlink"),
            FileOp::Rename => write!(f, "rename"),
            FileOp::Chmod => write!(f, "chmod"),
            FileOp::Chown => write!(f, "chown"),
            FileOp::Exec => write!(f, "exec"),
        }
    }
}

/// A network operation observed via audit.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub timestamp: u64,
    pub operation: NetOp,
    /// Address family string, e.g. "AF_INET", "AF_UNIX"
    pub family: String,
    pub local_addr: Option<String>,
    pub remote_addr: Option<String>,
    pub port: Option<u16>,
    pub is_first_seen: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum NetOp {
    Socket,
    Connect,
    Bind,
    Accept,
    SendTo,
    RecvFrom,
}

impl std::fmt::Display for NetOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetOp::Socket => write!(f, "socket"),
            NetOp::Connect => write!(f, "connect"),
            NetOp::Bind => write!(f, "bind"),
            NetOp::Accept => write!(f, "accept"),
            NetOp::SendTo => write!(f, "sendto"),
            NetOp::RecvFrom => write!(f, "recvfrom"),
        }
    }
}

/// A process-lifecycle event observed via audit.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub timestamp: u64,
    pub operation: ProcessOp,
    pub target_pid: Option<u32>,
    pub exe: String,
    pub comm: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum ProcessOp {
    Fork,
    Exec,
    Exit,
    Signal,
}

impl std::fmt::Display for ProcessOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessOp::Fork => write!(f, "fork"),
            ProcessOp::Exec => write!(f, "exec"),
            ProcessOp::Exit => write!(f, "exit"),
            ProcessOp::Signal => write!(f, "signal"),
        }
    }
}

/// Accumulated events for a single action boundary.
/// File and network events are deduplicated: we store unique facts and count occurrences.
/// Process events (fork/exec/exit) are stored individually since each is unique.
#[derive(Debug, Clone, Serialize)]
pub struct ActionLog {
    pub action_id: u64,
    pub command: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    /// Deduplicated: (pid, op) -> count
    pub file_op_counts: std::collections::HashMap<(u32, FileOp), u64>,
    /// Unique file events (first occurrence only, for anomaly checking)
    pub file_events: Vec<FileEvent>,
    /// Deduplicated: (pid, op) -> count
    pub net_op_counts: std::collections::HashMap<(u32, NetOp), u64>,
    /// Process lifecycle events (each is unique)
    pub process_events: Vec<ProcessEvent>,
    /// Total raw event count
    pub total_events: u64,
}

impl ActionLog {
    pub fn new(action_id: u64, command: String, start_time: u64) -> Self {
        Self {
            action_id,
            command,
            start_time,
            end_time: None,
            file_op_counts: std::collections::HashMap::new(),
            file_events: Vec::new(),
            net_op_counts: std::collections::HashMap::new(),
            process_events: Vec::new(),
            total_events: 0,
        }
    }

    /// Record a file event. Only stores the full event on first occurrence
    /// of a (pid, op) pair; subsequent ones just increment the counter.
    pub fn record_file_event(&mut self, event: FileEvent) {
        self.total_events += 1;
        let key = (event.pid, event.operation);
        let count = self.file_op_counts.entry(key).or_insert(0);
        *count += 1;
        // Store full event only on first occurrence (for anomaly detection)
        if *count == 1 {
            self.file_events.push(event);
        }
    }

    /// Record a network event (deduplicated by pid + op).
    pub fn record_net_event(&mut self, event: NetworkEvent) {
        self.total_events += 1;
        let key = (event.pid, event.operation);
        *self.net_op_counts.entry(key).or_insert(0) += 1;
    }

    /// Record a process event (always stored, each is unique).
    pub fn record_process_event(&mut self, event: ProcessEvent) {
        self.total_events += 1;
        self.process_events.push(event);
    }
}
