//! Process community detection for receipt compression.
//!
//! Inspired by DEPCOMM (Xu et al., S&P 2022), this module groups processes
//! into communities based on their binary name and fork relationships.
//! Communities are used to collapse repetitive process trees in receipts
//! (e.g., npm install spawning 200 processes).
//!
//! The algorithm:
//! 1. Group all processes by their executable name (comm field).
//! 2. Within each name group, merge processes that are connected by fork edges.
//! 3. Optionally merge groups connected by high-weight pipe/socket edges.
//! 4. Each community gets a summary label and aggregate stats.

use std::collections::{HashMap, HashSet};

use crate::state::{ChannelType, ContainerState};
use crate::util;

// ── Tuning constants ───────────────────────────────────────────────

/// Minimum event_count on a non-fork edge before two communities are
/// merged. Pipe/socket edges with fewer events are likely incidental
/// (e.g., a brief status check), not sustained data flow.
const COMMUNITY_MERGE_EVENT_THRESHOLD: u64 = 10;

/// Max display width for a single-member community representative cmdline.
const COMMUNITY_SINGLE_TRUNCATE: usize = 100;

/// Max display width for a multi-member community representative cmdline.
const COMMUNITY_MULTI_TRUNCATE: usize = 80;

/// A community of related processes.
#[derive(Debug, Clone)]
pub struct Community {
    /// Unique community ID (index).
    pub id: usize,
    /// Human-readable label for this community (dominant binary name).
    pub label: String,
    /// PIDs in this community.
    pub members: Vec<u32>,
    /// The PID with the longest cmdline (best representative).
    pub representative_pid: u32,
    /// Average taint score of members.
    pub avg_taint_score: f64,
}

/// Detect process communities in a container.
///
/// Returns communities sorted by size (largest first). Singleton communities
/// (single process) are included but can be filtered by the caller.
pub fn detect_communities(
    container: &ContainerState,
    action_pids: &HashSet<u32>,
) -> Vec<Community> {
    if action_pids.is_empty() {
        return Vec::new();
    }

    // Step 1: Group processes by comm (binary name)
    let mut by_comm: HashMap<String, Vec<u32>> = HashMap::new();
    for &pid in action_pids {
        let comm = container
            .process_table
            .get(&pid)
            .map(|info| util::decode_comm(&info.comm))
            .unwrap_or_else(|| "?".to_string());
        by_comm.entry(comm).or_default().push(pid);
    }

    // Step 2: Within each name group, find connected components via fork edges.
    // Two processes with the same comm that are connected by fork edges are in
    // the same community.
    let mut communities: Vec<Community> = Vec::new();
    let mut pid_to_community: HashMap<u32, usize> = HashMap::new();

    for (comm, pids) in &by_comm {
        // Build adjacency from fork edges within this comm group
        let pid_set: HashSet<u32> = pids.iter().copied().collect();
        let mut adj: HashMap<u32, Vec<u32>> = HashMap::new();
        for edge in &container.taint_graph.edges {
            if edge.channel_type == ChannelType::Fork
                && pid_set.contains(&edge.source_pid)
                && pid_set.contains(&edge.target_pid)
            {
                adj.entry(edge.source_pid)
                    .or_default()
                    .push(edge.target_pid);
                adj.entry(edge.target_pid)
                    .or_default()
                    .push(edge.source_pid);
            }
        }

        // Find connected components via BFS
        let mut visited: HashSet<u32> = HashSet::new();
        for &pid in pids {
            if visited.contains(&pid) {
                continue;
            }
            let mut component = Vec::new();
            let mut queue = vec![pid];
            while let Some(current) = queue.pop() {
                if !visited.insert(current) {
                    continue;
                }
                component.push(current);
                if let Some(neighbors) = adj.get(&current) {
                    for &n in neighbors {
                        if !visited.contains(&n) {
                            queue.push(n);
                        }
                    }
                }
            }

            let community_id = communities.len();
            for &p in &component {
                pid_to_community.insert(p, community_id);
            }

            let representative = find_representative(container, &component);
            let avg_score = avg_taint_score(container, &component);

            communities.push(Community {
                id: community_id,
                label: comm.clone(),
                members: component,
                representative_pid: representative,
                avg_taint_score: avg_score,
            });
        }
    }

    // Step 3: Merge communities connected by high-weight non-fork edges
    // (pipe/socket with event_count > 10). This handles cases like
    // two different binaries that communicate heavily.
    let mut merges: Vec<(usize, usize)> = Vec::new();
    for edge in &container.taint_graph.edges {
        if edge.channel_type == ChannelType::Fork {
            continue;
        }
        if edge.event_count < COMMUNITY_MERGE_EVENT_THRESHOLD {
            continue;
        }
        if let (Some(&c1), Some(&c2)) = (
            pid_to_community.get(&edge.source_pid),
            pid_to_community.get(&edge.target_pid),
        )
            && c1 != c2 {
                merges.push((c1.min(c2), c1.max(c2)));
            }
    }

    // Apply merges using union-find
    if !merges.is_empty() {
        let mut parent: Vec<usize> = (0..communities.len()).collect();
        for (a, b) in &merges {
            let ra = find_root(&parent, *a);
            let rb = find_root(&parent, *b);
            if ra != rb {
                parent[rb] = ra;
            }
        }

        // Rebuild communities based on merged roots
        let mut merged_groups: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..communities.len() {
            let root = find_root(&parent, i);
            merged_groups.entry(root).or_default().push(i);
        }

        let mut new_communities = Vec::new();
        for (_root, group) in merged_groups {
            if group.len() == 1 {
                new_communities.push(communities[group[0]].clone());
            } else {
                // Merge all communities in this group
                let mut merged_members = Vec::new();
                let mut labels = Vec::new();
                for &idx in &group {
                    merged_members.extend(&communities[idx].members);
                    if !labels.contains(&communities[idx].label) {
                        labels.push(communities[idx].label.clone());
                    }
                }
                let representative = find_representative(container, &merged_members);
                let avg_score = avg_taint_score(container, &merged_members);
                let label = if labels.len() <= 2 {
                    labels.join("+")
                } else {
                    format!("{}+{} others", labels[0], labels.len() - 1)
                };
                new_communities.push(Community {
                    id: new_communities.len(),
                    label,
                    members: merged_members,
                    representative_pid: representative,
                    avg_taint_score: avg_score,
                });
            }
        }
        communities = new_communities;
    }

    // Re-index and sort by size (largest first)
    communities.sort_by(|a, b| b.members.len().cmp(&a.members.len()));
    for (i, c) in communities.iter_mut().enumerate() {
        c.id = i;
    }

    communities
}

/// Format a community summary for the receipt.
pub fn format_community(container: &ContainerState, community: &Community) -> String {
    let count = community.members.len();
    let repr = container
        .process_table
        .get(&community.representative_pid)
        .map(|info| {
            if !info.cmdline.is_empty() {
                info.cmdline.clone()
            } else {
                info.exec_path.clone()
            }
        })
        .unwrap_or_else(|| community.label.clone());

    if count == 1 {
        format!("  {}", truncate(&repr, COMMUNITY_SINGLE_TRUNCATE))
    } else {
        format!(
            "  [{} x{}] {} (taint avg {:.0}%)",
            community.label,
            count,
            truncate(&repr, COMMUNITY_MULTI_TRUNCATE),
            community.avg_taint_score * 100.0,
        )
    }
}

// ── helpers ─────────────────────────────────────────────────────────

fn find_representative(container: &ContainerState, pids: &[u32]) -> u32 {
    pids.iter()
        .copied()
        .max_by_key(|pid| {
            container
                .process_table
                .get(pid)
                .map(|info| info.cmdline.len())
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

fn avg_taint_score(container: &ContainerState, pids: &[u32]) -> f64 {
    if pids.is_empty() {
        return 0.0;
    }
    let total: f64 = pids
        .iter()
        .map(|pid| container.process_table.taint_score(*pid))
        .sum();
    total / pids.len() as f64
}

fn find_root(parent: &[usize], mut i: usize) -> usize {
    while parent[i] != i {
        i = parent[i];
    }
    i
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
