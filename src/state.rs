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
    pub exited: bool,
    pub children: Vec<u32>,
    /// Which action this process's events should be attributed to.
    /// Set to current_action_id when first seen. Updated when the process
    /// receives cross-action taint (IPC/file/network from a process in a
    /// different action), re-attributing subsequent events to the tainting action.
    pub attributed_action: u64,
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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum ChannelType {
    Fork,
    Pipe,
    /// File-mediated data flow (process A writes file, process B reads it)
    FileFlow,
    /// IPC message queue (SysV or POSIX): process A sends, process B receives
    MessageQueue,
}

impl ChannelType {
    /// Decay factor for taint propagation through this channel type.
    /// Based on MORSE (S&P 2020) tag attenuation: channels that transmit
    /// more data/control inherit more taint from the source.
    pub fn decay_factor(self) -> f64 {
        match self {
            ChannelType::Fork => 0.9,         // children strongly inherit parent taint
            ChannelType::Pipe => 0.7,          // data flow, moderate inheritance
            ChannelType::FileFlow => 0.5,      // indirect: writer → file → reader
            ChannelType::MessageQueue => 0.7,  // direct data channel, same as pipe
        }
    }
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelType::Fork => write!(f, "fork"),
            ChannelType::Pipe => write!(f, "pipe"),
            ChannelType::FileFlow => write!(f, "file"),
            ChannelType::MessageQueue => write!(f, "mqueue"),
        }
    }
}

/// Append-only graph of inter-process communication channels.
#[derive(Debug, Clone, Default)]
pub struct TaintGraph {
    pub edges: Vec<TaintEdge>,
    /// Fast lookup index: (source, target, channel_type) → index in edges Vec.
    edge_index: HashMap<(u32, u32, ChannelType), usize>,
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
        let key = (source_pid, target_pid, channel_type);
        if let Some(&idx) = self.edge_index.get(&key)
            && let Some(edge) = self.edges.get_mut(idx)
        {
            edge.last_seen = timestamp;
            edge.event_count += 1;
            return;
        }
        let idx = self.edges.len();
        self.edge_index.insert(key, idx);
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

}

/// Known-good state of a container at startup.
#[derive(Debug, Clone, Default)]
pub struct ContainerBaseline {
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
            sensitive_paths,
        }
    }

    /// Check if a path matches any sensitive path pattern.
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
}

/// A tracked file in the container's filesystem.
#[derive(Debug, Clone)]
pub struct FileNode {
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
    pub fn new() -> Self {
        Self {
            writers: Vec::new(),
            readers: Vec::new(),
            executors: Vec::new(),
            deleters: Vec::new(),
            modifiers: Vec::new(),
        }
    }
}

/// A tracked IPC channel (SysV or POSIX message queue).
/// Analogous to FileNode: tracks which PIDs send/receive through the channel
/// so we can build taint edges between them.
#[derive(Debug, Clone)]
pub struct IpcNode {
    /// PIDs that sent data through this channel, with the action_id
    pub senders: Vec<(u32, u64)>,
    /// PIDs that received data from this channel
    pub receivers: Vec<(u32, u64)>,
}

impl IpcNode {
    pub fn new() -> Self {
        Self {
            senders: Vec::new(),
            receivers: Vec::new(),
        }
    }
}

/// What an open file descriptor points to.
#[derive(Debug, Clone)]
pub enum FdTarget {
    /// A file path (from openat/open/creat).
    File(String),
    /// A network endpoint (from connect/bind/accept).
    Network(String),
    /// A POSIX message queue name (from mq_open).
    Ipc(String),
}

/// Per-container state.
pub struct ContainerState {
    pub process_table: ProcessTable,
    pub taint_graph: TaintGraph,
    pub baseline: ContainerBaseline,
    pub current_action: Option<ActionLog>,
    /// Completed action logs (kept for receipt diffing).
    pub completed_actions: Vec<ActionLog>,
    /// Timestamp of the last receipt generation.
    pub last_receipt_time: u64,
    /// Tracked files keyed by path. Captures who read/wrote/exec'd each file.
    pub file_nodes: HashMap<String, FileNode>,
    /// Current action ID (for attributing file access to actions)
    pub current_action_id: u64,
    /// Per-process fd table: (pid, fd_number) → what it points to.
    /// Populated by openat/connect/socket/pipe/mq_open, consumed by sendfile/splice/mq_send/recv.
    pub fd_table: HashMap<(u32, u64), FdTarget>,
    /// Tracked IPC channels keyed by channel ID.
    /// SysV message queues: "sysv_mq:<msqid>", POSIX: "posix_mq:<name>"
    pub ipc_nodes: HashMap<String, IpcNode>,
}

impl ContainerState {
    pub fn new(_container_id: String, baseline: ContainerBaseline) -> Self {
        let global_action = ActionLog::new(0, "(container lifecycle)".to_string(), 0);
        Self {
            process_table: ProcessTable::default(),
            taint_graph: TaintGraph::default(),
            baseline,
            current_action: Some(global_action),
            completed_actions: Vec::new(),
            last_receipt_time: 0,
            file_nodes: HashMap::new(),
            current_action_id: 0,
            fd_table: HashMap::new(),
            ipc_nodes: HashMap::new(),
        }
    }

    /// Determine which action was active at a given wall-clock timestamp (ms).
    /// Checks completed actions (by wall_start_ms..wall_end_ms) then falls back
    /// to current_action_id.
    pub fn action_at_time(&self, timestamp_ms: u64) -> u64 {
        if timestamp_ms == 0 {
            return self.current_action_id;
        }

        // First: exact match (timestamp falls within an action's wall-clock window)
        for action in self.completed_actions.iter().rev() {
            if let Some(end) = action.wall_end_ms {
                if timestamp_ms >= action.wall_start_ms && timestamp_ms <= end {
                    return action.action_id;
                }
            }
        }
        if let Some(ref action) = self.current_action {
            if timestamp_ms >= action.wall_start_ms {
                return action.action_id;
            }
        }

        // Second: nearest-action match. The audit timestamp can precede the
        // action_start wall-clock time (docker exec races ahead of the HTTP
        // response). Find the action whose start is closest to the timestamp,
        // but only if the gap is reasonable (< 2s) and doesn't cross into
        // a previous action's window.
        let mut best_id = self.current_action_id;
        let mut best_gap = u64::MAX;

        for (i, action) in self.completed_actions.iter().enumerate() {
            if timestamp_ms < action.wall_start_ms {
                let gap = action.wall_start_ms - timestamp_ms;
                // Don't cross into the previous action's end time
                let prev_end = if i > 0 {
                    self.completed_actions[i - 1].wall_end_ms.unwrap_or(0)
                } else {
                    0
                };
                if gap < best_gap && gap < 2000 && timestamp_ms > prev_end {
                    best_gap = gap;
                    best_id = action.action_id;
                }
            }
        }
        if let Some(ref action) = self.current_action {
            if timestamp_ms < action.wall_start_ms {
                let gap = action.wall_start_ms - timestamp_ms;
                let prev_end = self.completed_actions.last()
                    .and_then(|a| a.wall_end_ms).unwrap_or(0);
                if gap < best_gap && gap < 2000 && timestamp_ms > prev_end {
                    best_id = action.action_id;
                }
            }
        }

        best_id
    }

    /// Find the ActionLog a process's events should be attributed to.
    fn action_for(&mut self, action_id: u64) -> Option<&mut ActionLog> {
        if let Some(ref mut action) = self.current_action {
            if action.action_id == action_id {
                return self.current_action.as_mut();
            }
        }
        self.completed_actions.iter_mut().find(|a| a.action_id == action_id)
            .or(self.current_action.as_mut())
    }

    /// Route a process event to the correct ActionLog based on process attribution.
    pub fn record_process_event(&mut self, pid: u32, event: crate::events::ProcessEvent) {
        let attr = self.process_table.get(&pid)
            .map(|p| p.attributed_action)
            .unwrap_or(self.current_action_id);
        if let Some(action) = self.action_for(attr) {
            action.record_process_event(event);
        }
    }

    /// Route a file event to the correct ActionLog based on process attribution.
    pub fn record_file_event(&mut self, pid: u32, event: crate::events::FileEvent) {
        let attr = self.process_table.get(&pid)
            .map(|p| p.attributed_action)
            .unwrap_or(self.current_action_id);
        if let Some(action) = self.action_for(attr) {
            action.record_file_event(event);
        }
    }

    /// Route a network event to the correct ActionLog based on process attribution.
    pub fn record_net_event(&mut self, pid: u32, event: crate::events::NetworkEvent) {
        let attr = self.process_table.get(&pid)
            .map(|p| p.attributed_action)
            .unwrap_or(self.current_action_id);
        if let Some(action) = self.action_for(attr) {
            action.record_net_event(event);
        }
    }

    /// Record a file access. Creates the FileNode if needed.
    pub fn record_file_access(&mut self, path: &str, pid: u32, op: crate::events::FileOp) {
        if path.is_empty() {
            return;
        }
        // Canonicalize path: collapse /./, //, strip leading ./
        let path = &canonicalize_path(path);
        let action_id = self.process_table.get(&pid)
            .map(|p| p.attributed_action)
            .unwrap_or(self.current_action_id);
        let node = self
            .file_nodes
            .entry(path.to_string())
            .or_insert_with(|| FileNode::new());
        let entry = (pid, action_id);
        match op {
            crate::events::FileOp::Write | crate::events::FileOp::OpenWrite => {
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

    /// Record an IPC access (send or receive) on a named channel.
    pub fn record_ipc_send(&mut self, channel: &str, pid: u32) {
        if channel.is_empty() {
            return;
        }
        let action_id = self.process_table.get(&pid)
            .map(|p| p.attributed_action)
            .unwrap_or(self.current_action_id);
        let node = self
            .ipc_nodes
            .entry(channel.to_string())
            .or_insert_with(IpcNode::new);
        let entry = (pid, action_id);
        if !node.senders.contains(&entry) {
            node.senders.push(entry);
        }
    }

    pub fn record_ipc_recv(&mut self, channel: &str, pid: u32) {
        if channel.is_empty() {
            return;
        }
        let action_id = self.process_table.get(&pid)
            .map(|p| p.attributed_action)
            .unwrap_or(self.current_action_id);
        let node = self
            .ipc_nodes
            .entry(channel.to_string())
            .or_insert_with(IpcNode::new);
        let entry = (pid, action_id);
        if !node.receivers.contains(&entry) {
            node.receivers.push(entry);
        }
    }

    /// Create MessageQueue taint edges from ipc_nodes: if process A sent data
    /// and process B received it through the same channel, add a MessageQueue edge A→B.
    pub fn build_ipc_flow_edges(&mut self) {
        let mut seen: HashSet<(u32, u32)> = HashSet::new();

        for (channel, node) in &self.ipc_nodes {
            if node.senders.is_empty() || node.receivers.is_empty() {
                continue;
            }

            let sender_pids: HashSet<u32> = node.senders.iter().map(|(p, _)| *p).collect();
            let receiver_pids: HashSet<u32> = node.receivers.iter().map(|(p, _)| *p).collect();

            for &sender in &sender_pids {
                for &receiver in &receiver_pids {
                    if sender != receiver && seen.insert((sender, receiver)) {
                        self.taint_graph.add_edge(
                            sender,
                            receiver,
                            format!("ipc:{}", channel),
                            ChannelType::MessageQueue,
                            0,
                        );
                    }
                }
            }
        }
    }

    /// Create FileFlow taint edges from file_nodes: if process A wrote a file
    /// and process B read/executed it, add a FileFlow edge A→B.
    /// This enables taint to propagate through file-mediated data channels.
    ///
    /// Only processes files that have BOTH writers and readers (cross-process flow).
    /// Skips library/system paths since those are process infrastructure, not data flow.
    pub fn build_file_flow_edges(&mut self) {
        // Track which (writer, reader) pairs we've already added to avoid
        // the expensive linear scan in add_edge on repeated calls.
        let mut seen: HashSet<(u32, u32)> = HashSet::new();

        for (path, node) in &self.file_nodes {
            // Skip noise/infrastructure paths
            if path.starts_with("/proc/") || path.starts_with("/dev/")
                || path.starts_with("/sys/") || path.starts_with("/usr/lib/")
                || path.starts_with("/lib/") || path.contains(".so")
                || path.starts_with("/usr/include/")
                || path.starts_with("/usr/share/")
                || path.starts_with("/etc/apk/")
                || path.starts_with("/etc/terminfo/")
            {
                continue;
            }

            // Skip files with no cross-process flow
            if node.writers.is_empty() || (node.readers.is_empty() && node.executors.is_empty()) {
                continue;
            }

            let writer_pids: HashSet<u32> = node.writers.iter().map(|(p, _)| *p).collect();
            let reader_pids: HashSet<u32> = node.readers.iter()
                .chain(node.executors.iter())
                .map(|(p, _)| *p)
                .collect();

            for &writer in &writer_pids {
                for &reader in &reader_pids {
                    if writer != reader && !writer_pids.contains(&reader) && seen.insert((writer, reader)) {
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

/// An experiment groups multiple containers for aggregated receipts.
/// In eval frameworks, an experiment is one agent run that may span
/// multiple containers (agent workspace, target services, etc.).
#[derive(Debug, Clone, Serialize)]
pub struct Experiment {
    pub id: String,
    pub name: String,
    /// Container IDs belonging to this experiment.
    pub container_ids: Vec<String>,
}

/// Top-level daemon state holding all container states.
pub struct DaemonState {
    /// Container states keyed by container ID (short 12-char hex).
    pub containers: HashMap<String, ContainerState>,
    /// IP → container_id mapping for cross-container network flow resolution.
    /// Populated from /proc/{pid}/net/fib_trie when a container is first seen.
    /// If multiple containers share an IP (Docker Compose network_mode: service:x),
    /// the first one seen wins. The experiment receipt shows all containers regardless.
    pub ip_to_container: HashMap<std::net::Ipv4Addr, String>,
    /// Experiments keyed by experiment ID.
    pub experiments: HashMap<String, Experiment>,
    /// Reverse map: container_id → experiment_id.
    pub container_to_experiment: HashMap<String, String>,
    /// Auto-increment for experiment IDs.
    next_experiment_id: u64,
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            containers: HashMap::new(),
            ip_to_container: HashMap::new(),
            experiments: HashMap::new(),
            container_to_experiment: HashMap::new(),
            next_experiment_id: 1,
        }
    }

    /// Create a new experiment, returns its ID.
    pub fn create_experiment(&mut self, name: String) -> String {
        let id = format!("exp-{}", self.next_experiment_id);
        self.next_experiment_id += 1;
        self.experiments.insert(id.clone(), Experiment {
            id: id.clone(),
            name,
            container_ids: Vec::new(),
        });
        id
    }

    /// Add a container to an experiment.
    pub fn add_container_to_experiment(&mut self, experiment_id: &str, container_id: &str) -> bool {
        if let Some(exp) = self.experiments.get_mut(experiment_id) {
            if !exp.container_ids.contains(&container_id.to_string()) {
                exp.container_ids.push(container_id.to_string());
            }
            self.container_to_experiment.insert(container_id.to_string(), experiment_id.to_string());
            true
        } else {
            false
        }
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

/// Canonicalize a file path: collapse `/./ → /`, `// → /`, strip leading `./`.
/// Pure string manipulation — no I/O.
fn canonicalize_path(path: &str) -> String {
    let mut result = path.replace("/./", "/").replace("//", "/");
    if result.starts_with("./") {
        result = result[2..].to_string();
    }
    // Collapse simple parent refs: /a/b/../c → /a/c
    while let Some(pos) = result.find("/../") {
        if pos == 0 {
            break; // can't go above root
        }
        let parent_start = result[..pos].rfind('/').unwrap_or(0);
        result = format!("{}{}", &result[..parent_start], &result[pos + 3..]);
    }
    result
}
