use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::events::ActionLog;

/// Default threshold for considering a process "tainted" in receipts/graphs.
pub const TAINT_THRESHOLD: f64 = 0.1;

/// Information about a tracked process inside a container.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exec_path: String,
    pub cmdline: String,
    pub open_files: Vec<String>,
    pub net_connections: Vec<String>,
    /// Taint score: 0.0 = clean, 1.0 = fully tainted (entry point / direct agent control).
    /// Intermediate values represent diminishing influence through IPC channels.
    /// See MORSE (Hossain, Sheikhi, Sekar; S&P 2020) for the tag attenuation concept.
    pub taint_score: f64,
    pub taint_source: String,
    pub is_original: bool,
    pub exited: bool,
    pub children: Vec<u32>,
}

impl ProcessInfo {
    /// Whether this process is considered tainted (score above threshold).
    pub fn is_tainted(&self) -> bool {
        self.taint_score >= TAINT_THRESHOLD
    }
}

/// A table of all known processes in a container, keyed by PID.
#[derive(Debug, Clone, Default)]
pub struct ProcessTable {
    pub processes: HashMap<u32, ProcessInfo>,
}

impl ProcessTable {
    pub fn add(&mut self, info: ProcessInfo) {
        let pid = info.pid;
        let ppid = info.ppid;
        self.processes.insert(pid, info);
        // Register as child of parent
        if let Some(parent) = self.processes.get_mut(&ppid)
            && !parent.children.contains(&pid) {
                parent.children.push(pid);
            }
    }

    #[allow(dead_code)]
    pub fn remove(&mut self, pid: u32) {
        if let Some(info) = self.processes.remove(&pid) {
            // Remove from parent's children list
            if let Some(parent) = self.processes.get_mut(&info.ppid) {
                parent.children.retain(|&c| c != pid);
            }
        }
    }

    /// Set the taint score for a process. Only updates if the new score is higher.
    pub fn mark_tainted(&mut self, pid: u32, score: f64, source: &str) {
        if let Some(info) = self.processes.get_mut(&pid)
            && score > info.taint_score
        {
            info.taint_score = score;
            info.taint_source = source.to_string();
        }
    }

    pub fn get(&self, pid: &u32) -> Option<&ProcessInfo> {
        self.processes.get(pid)
    }

    /// Get taint score for a process (0.0 if not found).
    pub fn taint_score(&self, pid: u32) -> f64 {
        self.processes
            .get(&pid)
            .map(|p| p.taint_score)
            .unwrap_or(0.0)
    }

    #[allow(dead_code)]
    pub fn is_tainted(&self, pid: u32) -> bool {
        self.processes
            .get(&pid)
            .is_some_and(|p| p.is_tainted())
    }
}

/// A directed edge in the taint graph representing inter-process communication.
#[derive(Debug, Clone, Serialize)]
pub struct TaintEdge {
    pub source_pid: u32,
    pub target_pid: u32,
    pub channel: String,
    pub channel_type: ChannelType,
    pub first_seen: u64,
    pub last_seen: u64,
    pub event_count: u64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ChannelType {
    Fork,
    UnixSocket,
    Inet,
    Pipe,
    Signal,
    /// Shared memory (shmget/shmat/shmdt or mmap MAP_SHARED)
    SharedMemory,
    /// ptrace attachment (process debugging/injection)
    Ptrace,
    /// memfd_create (anonymous file-backed memory, often used for fileless exec)
    Memfd,
    /// File-mediated data flow (process A writes file, process B reads it)
    FileFlow,
}

impl ChannelType {
    /// Decay factor for taint propagation through this channel type.
    /// Based on MORSE (S&P 2020) tag attenuation: channels that transmit
    /// more data/control inherit more taint from the source.
    pub fn decay_factor(self) -> f64 {
        match self {
            ChannelType::Fork => 0.9,         // children strongly inherit parent taint
            ChannelType::Pipe => 0.7,          // data flow, moderate inheritance
            ChannelType::UnixSocket => 0.7,    // data flow, moderate inheritance
            ChannelType::Inet => 0.8,          // significant data flow
            ChannelType::Signal => 0.3,        // weak influence (kill/tgkill)
            ChannelType::SharedMemory => 0.8,  // direct memory sharing, strong coupling
            ChannelType::Ptrace => 0.95,       // near-total control over target
            ChannelType::Memfd => 0.7,         // anonymous file-backed memory
            ChannelType::FileFlow => 0.5,      // indirect: writer → file → reader
        }
    }
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelType::Fork => write!(f, "fork"),
            ChannelType::UnixSocket => write!(f, "unix_socket"),
            ChannelType::Inet => write!(f, "inet"),
            ChannelType::Pipe => write!(f, "pipe"),
            ChannelType::Signal => write!(f, "signal"),
            ChannelType::SharedMemory => write!(f, "shm"),
            ChannelType::Ptrace => write!(f, "ptrace"),
            ChannelType::Memfd => write!(f, "memfd"),
            ChannelType::FileFlow => write!(f, "file"),
        }
    }
}

/// Append-only graph of inter-process communication channels.
#[derive(Debug, Clone, Default)]
pub struct TaintGraph {
    pub edges: Vec<TaintEdge>,
}

impl TaintGraph {
    /// Add or update a taint edge. If an edge between the same source/target
    /// with the same channel_type already exists, update last_seen and count.
    pub fn add_edge(
        &mut self,
        source_pid: u32,
        target_pid: u32,
        channel: String,
        channel_type: ChannelType,
        timestamp: u64,
    ) {
        for edge in &mut self.edges {
            if edge.source_pid == source_pid
                && edge.target_pid == target_pid
                && edge.channel_type == channel_type
            {
                edge.last_seen = timestamp;
                edge.event_count += 1;
                return;
            }
        }
        self.edges.push(TaintEdge {
            source_pid,
            target_pid,
            channel,
            channel_type,
            first_seen: timestamp,
            last_seen: timestamp,
            event_count: 1,
        });
    }

    /// Propagate taint scores through the graph using MORSE-style decay.
    ///
    /// For each edge, the target's score is updated to:
    ///   max(target.score, source.score * channel.decay_factor)
    ///
    /// This runs to fixpoint: edges are processed repeatedly until no score
    /// increases. The decay factors prevent taint explosion — distant processes
    /// get diminishing scores rather than full inheritance.
    ///
    /// Returns the set of newly tainted PIDs (those whose score crossed
    /// the TAINT_THRESHOLD).
    pub fn propagate_taint(&self, process_table: &mut ProcessTable) -> Vec<u32> {
        let mut newly_tainted = Vec::new();
        let mut changed = true;
        while changed {
            changed = false;
            for edge in &self.edges {
                let source_score = process_table.taint_score(edge.source_pid);
                if source_score < TAINT_THRESHOLD {
                    continue;
                }

                let target_exists = process_table.processes.contains_key(&edge.target_pid);
                if !target_exists {
                    continue;
                }

                let propagated_score = source_score * edge.channel_type.decay_factor();
                let current_target_score = process_table.taint_score(edge.target_pid);

                // Only update if the propagated score exceeds what the target already has.
                // Use a small epsilon to avoid infinite loops from floating point.
                if propagated_score > current_target_score + 1e-9 {
                    let was_tainted = current_target_score >= TAINT_THRESHOLD;
                    process_table.mark_tainted(
                        edge.target_pid,
                        propagated_score,
                        &format!("{} from pid {} (score {:.2}→{:.2})",
                            edge.channel_type, edge.source_pid,
                            source_score, propagated_score),
                    );
                    if !was_tainted && propagated_score >= TAINT_THRESHOLD {
                        newly_tainted.push(edge.target_pid);
                    }
                    changed = true;
                }
            }
        }
        newly_tainted
    }

    /// Return edges first seen after `since` timestamp.
    #[allow(dead_code)]
    pub fn edges_since(&self, since: u64) -> Vec<&TaintEdge> {
        self.edges
            .iter()
            .filter(|e| e.first_seen > since)
            .collect()
    }
}

/// Known-good state of a container at startup.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ContainerBaseline {
    pub original_processes: HashMap<u32, String>, // pid -> exec_path
    pub original_binaries: HashSet<String>,
    pub sensitive_paths: HashSet<String>,
}

impl ContainerBaseline {
    pub fn new() -> Self {
        let mut sensitive_paths = HashSet::new();
        for p in &[
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/root/.ssh",
            "/home/*/.ssh",
            "/etc/ssl/private",
            "/etc/crontab",
            "/var/spool/cron",
        ] {
            sensitive_paths.insert(p.to_string());
        }
        Self {
            original_processes: HashMap::new(),
            original_binaries: HashSet::new(),
            sensitive_paths,
        }
    }

    /// Check if a path matches any sensitive path pattern.
    #[allow(dead_code)]
    pub fn is_sensitive(&self, path: &str) -> bool {
        for sp in &self.sensitive_paths {
            if sp.contains('*') {
                // Simple glob: /home/*/.ssh matches /home/user/.ssh
                let parts: Vec<&str> = sp.split('*').collect();
                if parts.len() == 2
                    && path.starts_with(parts[0]) && path.ends_with(parts[1]) {
                        return true;
                    }
            } else if path.starts_with(sp) {
                return true;
            }
        }
        false
    }

    pub fn is_new_binary(&self, path: &str) -> bool {
        !path.is_empty() && !self.original_binaries.contains(path)
    }
}

/// A tracked file in the container's filesystem.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FileNode {
    pub path: String,
    /// PIDs that wrote/created this file, with the action_id when it happened
    pub writers: Vec<(u32, u64)>,
    /// PIDs that read this file
    pub readers: Vec<(u32, u64)>,
    /// PIDs that exec'd this file
    pub executors: Vec<(u32, u64)>,
    /// PIDs that deleted this file
    pub deleters: Vec<(u32, u64)>,
    /// PIDs that chmod/chown'd this file
    pub modifiers: Vec<(u32, u64)>,
}

impl FileNode {
    pub fn new(path: String) -> Self {
        Self {
            path,
            writers: Vec::new(),
            readers: Vec::new(),
            executors: Vec::new(),
            deleters: Vec::new(),
            modifiers: Vec::new(),
        }
    }
}

/// What an open file descriptor points to.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum FdTarget {
    /// A file path (from openat/open/creat).
    File(String),
    /// A network endpoint (from connect/bind/accept).
    Network(String),
    /// A socket with unknown endpoint (from socket()).
    Socket { domain: u64 },
    /// A pipe endpoint (from pipe/pipe2).
    Pipe { inode: u64 },
}

/// Per-container state.
#[allow(dead_code)]
pub struct ContainerState {
    pub container_id: String,
    pub process_table: ProcessTable,
    pub taint_graph: TaintGraph,
    pub baseline: ContainerBaseline,
    pub current_action: Option<ActionLog>,
    /// Completed action logs (kept for receipt diffing).
    pub completed_actions: Vec<ActionLog>,
    /// Timestamp of the last receipt generation.
    pub last_receipt_time: u64,
    /// Set of remote addresses seen across all actions in this container.
    pub seen_remote_addrs: HashSet<String>,
    /// Tracked files keyed by path. Captures who read/wrote/exec'd each file.
    pub file_nodes: HashMap<String, FileNode>,
    /// Current action ID (for attributing file access to actions)
    pub current_action_id: u64,
    /// Per-process fd table: (pid, fd_number) → what it points to.
    /// Populated by openat/connect/socket/pipe, consumed by sendfile/splice.
    pub fd_table: HashMap<(u32, u64), FdTarget>,
}

impl ContainerState {
    pub fn new(container_id: String, baseline: ContainerBaseline) -> Self {
        let global_action = ActionLog::new(0, "(container lifecycle)".to_string(), 0);
        Self {
            container_id,
            process_table: ProcessTable::default(),
            taint_graph: TaintGraph::default(),
            baseline,
            current_action: Some(global_action),
            completed_actions: Vec::new(),
            last_receipt_time: 0,
            seen_remote_addrs: HashSet::new(),
            file_nodes: HashMap::new(),
            current_action_id: 0,
            fd_table: HashMap::new(),
        }
    }

    /// Record a file access. Creates the FileNode if needed.
    pub fn record_file_access(&mut self, path: &str, pid: u32, op: crate::events::FileOp) {
        if path.is_empty() {
            return;
        }
        let action_id = self.current_action_id;
        let node = self
            .file_nodes
            .entry(path.to_string())
            .or_insert_with(|| FileNode::new(path.to_string()));
        let entry = (pid, action_id);
        match op {
            crate::events::FileOp::Write | crate::events::FileOp::OpenWrite | crate::events::FileOp::Create => {
                if !node.writers.contains(&entry) {
                    node.writers.push(entry);
                }
            }
            crate::events::FileOp::Read | crate::events::FileOp::Open => {
                // Don't add as reader if already a writer (avoids false self-loops
                // where cat > file shows as both writing and reading the same file)
                let already_writer = node.writers.iter().any(|(p, _)| *p == pid);
                if !already_writer && !node.readers.contains(&entry) {
                    node.readers.push(entry);
                }
            }
            crate::events::FileOp::Exec => {
                if !node.executors.contains(&entry) {
                    node.executors.push(entry);
                }
            }
            crate::events::FileOp::Unlink => {
                if !node.deleters.contains(&entry) {
                    node.deleters.push(entry);
                }
            }
            crate::events::FileOp::Chmod | crate::events::FileOp::Chown | crate::events::FileOp::Rename => {
                if !node.modifiers.contains(&entry) {
                    node.modifiers.push(entry);
                }
            }
        }
    }

    /// Create FileFlow taint edges from file_nodes: if process A wrote a file
    /// and process B read/executed it, add a FileFlow edge A→B.
    /// This enables taint to propagate through file-mediated data channels.
    pub fn build_file_flow_edges(&mut self) {
        for (path, node) in &self.file_nodes {
            // Skip noise paths
            if path.starts_with("/proc/") || path.starts_with("/dev/")
                || path.starts_with("/sys/") || path.starts_with("/usr/lib/")
                || path.starts_with("/lib/") || path.contains(".so")
            {
                continue;
            }

            let writer_pids: HashSet<u32> = node.writers.iter().map(|(p, _)| *p).collect();
            let reader_pids: HashSet<u32> = node.readers.iter()
                .chain(node.executors.iter())
                .map(|(p, _)| *p)
                .collect();

            // Create edges from each writer to each reader (that isn't also a writer)
            for &writer in &writer_pids {
                for &reader in &reader_pids {
                    if writer != reader && !writer_pids.contains(&reader) {
                        self.taint_graph.add_edge(
                            writer,
                            reader,
                            format!("file:{}", path),
                            ChannelType::FileFlow,
                            0,
                        );
                    }
                }
            }
        }
    }
}

/// Top-level daemon state holding all container states.
pub struct DaemonState {
    /// Container states keyed by container ID (short 12-char hex).
    pub containers: HashMap<String, ContainerState>,
    /// Cache: PID -> container ID for fast dispatch.
    pub pid_cache: HashMap<u32, Option<String>>,
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            containers: HashMap::new(),
            pid_cache: HashMap::new(),
        }
    }

    /// Look up or discover which container a PID belongs to.
    /// Returns None if the PID is not in any known container.
    #[allow(dead_code)]
    pub fn container_for_pid(&mut self, pid: u32) -> Option<String> {
        if let Some(cached) = self.pid_cache.get(&pid) {
            return cached.clone();
        }
        let result = crate::docker::container_from_pid(pid).map(|c| c.id);
        self.pid_cache.insert(pid, result.clone());
        result
    }

    /// Get or create a ContainerState for the given container ID.
    pub fn ensure_container(&mut self, container_id: &str) -> &mut ContainerState {
        if !self.containers.contains_key(container_id) {
            let baseline = ContainerBaseline::new();
            self.containers.insert(
                container_id.to_string(),
                ContainerState::new(container_id.to_string(), baseline),
            );
        }
        self.containers.get_mut(container_id).unwrap()
    }
}
