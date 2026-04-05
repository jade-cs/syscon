//! Semantic lifting: map low-level syscall patterns to high-level operations.
//!
//! Inspired by Tactical Provenance Analysis (Hassan, Bates, Marino; S&P 2020),
//! this module identifies meaningful agent behaviors from syscall sequences.
//! Each semantic operation is annotated with a MITRE ATT&CK technique ID
//! sourced from auditd-attack (MIT) and Falco rules (Apache-2.0).
//!
//! The goal is to explain *what* tainted processes did at each action step,
//! making the influence graph human-interpretable.

use std::collections::{HashMap, HashSet};

use crate::events::ProcessOp;
use crate::mitre;
use crate::state::ContainerState;

// ── Tuning constants ───────────────────────────────────────────────

/// Max display length for cmdlines in semantic operation descriptions.
const CMDLINE_TRUNCATE: usize = 70;

/// Max remote addresses shown inline before collapsing to "+N more".
const MAX_INLINE_REMOTE_ADDRS: usize = 3;

/// A high-level operation detected from syscall patterns.
#[derive(Debug, Clone)]
pub struct SemanticOp {
    /// Human-readable description.
    pub description: String,
    /// MITRE ATT&CK technique ID (e.g., "T1059.004").
    pub mitre_id: &'static str,
    /// Severity: 0 = info, 1 = low, 2 = medium, 3 = high.
    pub severity: u8,
    /// Action ID where this was detected.
    pub action_id: u64,
}

/// Analyze a container's completed actions and detect semantic operations
/// using the MITRE ATT&CK rule database.
pub fn detect_operations(container: &ContainerState) -> Vec<SemanticOp> {
    let mut ops = Vec::new();
    let mut seen: HashSet<(u64, &'static str, u32)> = HashSet::new(); // (action_id, technique_id, pid)

    for action in &container.completed_actions {
        let aid = action.action_id;

        // Evaluate exec events against the rule database
        for pe in &action.process_events {
            if pe.operation != ProcessOp::Exec {
                continue;
            }

            let pid = pe.pid;
            let exe = &pe.exe;
            let comm = &pe.comm;

            // Gather context for this process
            let (open_files, net_connections) = match container.process_table.get(&pid) {
                Some(info) => (info.open_files.clone(), info.net_connections.clone()),
                None => (Vec::new(), Vec::new()),
            };

            // Evaluate all rules
            let matches = mitre::evaluate("execve", exe, comm, &open_files, &net_connections);
            for rule in matches {
                if !seen.insert((aid, rule.technique_id, pid)) {
                    continue; // Deduplicate
                }

                let cmdline = container
                    .process_table
                    .get(&pid)
                    .map(|i| i.cmdline.as_str())
                    .unwrap_or("");

                let description = if !cmdline.is_empty() {
                    format!("{}: {}", rule.name, truncate(cmdline, CMDLINE_TRUNCATE))
                } else {
                    rule.name.to_string()
                };

                ops.push(SemanticOp {
                    description,
                    mitre_id: rule.technique_id,
                    severity: rule.severity,
                    action_id: aid,
                });
            }
        }

        // Evaluate file-based rules (open/write to sensitive paths).
        // Skip files with no writers (vast majority) for performance.
        for (path, node) in &container.file_nodes {
            if node.writers.is_empty() {
                continue;
            }
            let action_writers: Vec<u32> = node
                .writers
                .iter()
                .filter(|(_, a)| *a == aid)
                .map(|(p, _)| *p)
                .collect();

            if action_writers.is_empty() {
                continue;
            }

            for &pid in &action_writers {
                let (exe, comm) = container
                    .process_table
                    .get(&pid)
                    .map(|i| (i.exec_path.as_str(), i.comm.as_str()))
                    .unwrap_or(("", ""));

                let file_vec = vec![path.clone()];
                let matches = mitre::evaluate("openat", exe, comm, &file_vec, &[]);

                for rule in matches {
                    if !seen.insert((aid, rule.technique_id, pid)) {
                        continue;
                    }

                    ops.push(SemanticOp {
                        description: format!("{}: {}", rule.name, path),
                        mitre_id: rule.technique_id,
                        severity: rule.severity,
                        action_id: aid,
                    });
                }
            }
        }

        // Evaluate network-level rules (outbound connections from tainted processes)
        let mut action_net_pids: HashSet<u32> = HashSet::new();
        for &(pid, _) in action.net_op_counts.keys() {
            if container.process_table.get(&pid).is_some_and(|p| p.is_tainted()) {
                action_net_pids.insert(pid);
            }
        }

        for &pid in &action_net_pids {
            if let Some(info) = container.process_table.get(&pid) {
                let matches = mitre::evaluate(
                    "connect",
                    &info.exec_path,
                    &info.comm,
                    &info.open_files,
                    &info.net_connections,
                );

                for rule in matches {
                    if !seen.insert((aid, rule.technique_id, pid)) {
                        continue;
                    }

                    // Include remote addresses in description
                    let remotes: Vec<&str> = info
                        .net_connections
                        .iter()
                        .filter_map(|c| c.strip_prefix("connect "))
                        .filter(|a| !is_local_addr(a))
                        .collect();

                    // Skip network rules when all connections are local
                    // (unix sockets, netlink, loopback)
                    if remotes.is_empty() && rule.technique_id == "T1071" {
                        continue;
                    }

                    let desc = if remotes.is_empty() {
                        rule.name.to_string()
                    } else if remotes.len() <= MAX_INLINE_REMOTE_ADDRS {
                        format!("{}: {}", rule.name, remotes.join(", "))
                    } else {
                        format!("{}: {} +{} more", rule.name, remotes[..2].join(", "), remotes.len() - 2)
                    };

                    ops.push(SemanticOp {
                        description: desc,
                        mitre_id: rule.technique_id,
                        severity: rule.severity,
                        action_id: aid,
                    });
                }
            }
        }
    }

    // Sort by severity (highest first), then action ID
    ops.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.action_id.cmp(&b.action_id)));
    ops
}

/// Format semantic operations for the receipt.
pub fn format_for_receipt(ops: &[SemanticOp]) -> String {
    if ops.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str("SEMANTIC SUMMARY:\n");

    // Group by action
    let mut by_action: HashMap<u64, Vec<&SemanticOp>> = HashMap::new();
    for op in ops {
        by_action.entry(op.action_id).or_default().push(op);
    }

    let mut action_ids: Vec<u64> = by_action.keys().copied().collect();
    action_ids.sort();

    for aid in action_ids {
        let action_ops = &by_action[&aid];

        // Deduplicate by technique_id: merge descriptions for same technique
        let mut by_technique: std::collections::BTreeMap<&str, (u8, Vec<&str>)> = std::collections::BTreeMap::new();
        for op in action_ops {
            let entry = by_technique.entry(op.mitre_id).or_insert((op.severity, Vec::new()));
            entry.0 = entry.0.max(op.severity); // keep highest severity
            // Only add unique descriptions
            if !entry.1.contains(&op.description.as_str()) {
                entry.1.push(&op.description);
            }
        }

        out.push_str(&format!("  Action #{}:\n", aid));
        // Sort by severity descending
        let mut sorted: Vec<_> = by_technique.iter().collect();
        sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0));

        for (technique_id, (severity, descriptions)) in sorted {
            let severity_marker = match severity {
                0 => " ",
                1 => ".",
                2 => "!",
                _ => "!!",
            };
            if descriptions.len() == 1 {
                out.push_str(&format!(
                    "    {} [{}] {}\n",
                    severity_marker, technique_id, descriptions[0],
                ));
            } else {
                // Multiple instances of same technique — show count + first description
                out.push_str(&format!(
                    "    {} [{}] {} (x{})\n",
                    severity_marker, technique_id, descriptions[0], descriptions.len(),
                ));
            }
        }
    }
    out.push('\n');
    out
}

fn is_local_addr(addr: &str) -> bool {
    addr.starts_with("127.")
        || addr.starts_with("0.0.0.0")
        || addr.starts_with("[::1]")
        || addr.starts_with("[::]")
        || addr.starts_with("unix:")
        || addr.starts_with("netlink:")
        || addr.starts_with("packet:")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max - 3;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}
