use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::events::ActionLog;

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
    pub tainted: bool,
    pub taint_source: String,
    pub is_original: bool,
    pub exited: bool,
    pub children: Vec<u32>,
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
        if let Some(parent) = self.processes.get_mut(&ppid) {
            if !parent.children.contains(&pid) {
                parent.children.push(pid);
            }
        }
    }

    pub fn remove(&mut self, pid: u32) {
        if let Some(info) = self.processes.remove(&pid) {
            // Remove from parent's children list
            if let Some(parent) = self.processes.get_mut(&info.ppid) {
                parent.children.retain(|&c| c != pid);
            }
        }
    }

    pub fn mark_tainted(&mut self, pid: u32, source: &str) {
        if let Some(info) = self.processes.get_mut(&pid) {
            if !info.tainted {
                info.tainted = true;
                info.taint_source = source.to_string();
            }
        }
    }

    pub fn get(&self, pid: &u32) -> Option<&ProcessInfo> {
        self.processes.get(pid)
    }

    pub fn is_tainted(&self, pid: u32) -> bool {
        self.processes.get(&pid).is_some_and(|p| p.tainted)
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
pub enum ChannelType {
    Fork,
    UnixSocket,
    Inet,
    Pipe,
    Signal,
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelType::Fork => write!(f, "fork"),
            ChannelType::UnixSocket => write!(f, "unix_socket"),
            ChannelType::Inet => write!(f, "inet"),
            ChannelType::Pipe => write!(f, "pipe"),
            ChannelType::Signal => write!(f, "signal"),
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

    /// Propagate taint through the graph: if source is tainted and target is not,
    /// mark target as tainted. Returns the set of newly tainted PIDs.
    pub fn propagate_taint(&self, process_table: &mut ProcessTable) -> Vec<u32> {
        let mut newly_tainted = Vec::new();
        let mut changed = true;
        while changed {
            changed = false;
            for edge in &self.edges {
                let source_tainted = process_table.is_tainted(edge.source_pid);
                // Skip if target is not in the process table (exited)
                let target_exists = process_table.processes.contains_key(&edge.target_pid);
                if !target_exists {
                    continue;
                }
                let target_tainted = process_table.is_tainted(edge.target_pid);
                if source_tainted && !target_tainted {
                    process_table.mark_tainted(
                        edge.target_pid,
                        &format!("{} from pid {}", edge.channel_type, edge.source_pid),
                    );
                    newly_tainted.push(edge.target_pid);
                    changed = true;
                }
            }
        }
        newly_tainted
    }

    /// Return edges first seen after `since` timestamp.
    pub fn edges_since(&self, since: u64) -> Vec<&TaintEdge> {
        self.edges
            .iter()
            .filter(|e| e.first_seen > since)
            .collect()
    }
}

/// Known-good state of a container at startup.
#[derive(Debug, Clone, Default)]
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
    pub fn is_sensitive(&self, path: &str) -> bool {
        for sp in &self.sensitive_paths {
            if sp.contains('*') {
                // Simple glob: /home/*/.ssh matches /home/user/.ssh
                let parts: Vec<&str> = sp.split('*').collect();
                if parts.len() == 2 {
                    if path.starts_with(parts[0]) && path.ends_with(parts[1]) {
                        return true;
                    }
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

/// Per-container state.
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
                if !node.readers.contains(&entry) {
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
