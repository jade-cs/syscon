use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use crate::state::{ContainerState, DaemonState, Experiment};
use crate::util;

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Word-wrap a string for HTML labels, inserting <BR/> at ~max_width chars.
/// Breaks at spaces, then at / or - in paths if needed.
fn wrap_html(s: &str, max_width: usize) -> String {
    let escaped = escape_html(s);
    if escaped.len() <= max_width {
        return escaped;
    }
    let mut result = String::new();
    let mut line_len = 0;
    for word in escaped.split(' ') {
        // If a single "word" (e.g. a long path) exceeds max_width, break it at /
        if word.len() > max_width && word.contains('/') {
            for (i, segment) in word.split('/').enumerate() {
                if i > 0 {
                    if line_len + 1 + segment.len() > max_width {
                        result.push_str("/<BR/>  ");
                        line_len = 2;
                    } else {
                        result.push('/');
                        line_len += 1;
                    }
                } else if line_len > 0 {
                    if line_len + 1 + segment.len() > max_width {
                        result.push_str("<BR/>  ");
                        line_len = 2;
                    } else {
                        result.push(' ');
                        line_len += 1;
                    }
                }
                result.push_str(segment);
                line_len += segment.len();
            }
        } else {
            if line_len > 0 && line_len + 1 + word.len() > max_width {
                result.push_str("<BR/>  ");
                line_len = 2;
            } else if line_len > 0 {
                result.push(' ');
                line_len += 1;
            }
            result.push_str(word);
            line_len += word.len();
        }
    }
    result
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Action 0 (container baseline) color.
const BASELINE_COLOR: (&str, &str) = ("#e8e8e8", "#999999");

/// Action color palette — cycles for action IDs beyond the palette size.
const ACTION_COLORS: &[(&str, &str)] = &[
    ("#bbdefb", "#1565c0"), // 1  blue
    ("#c8e6c9", "#2e7d32"), // 2  green
    ("#fff9c4", "#f9a825"), // 3  yellow
    ("#ffccbc", "#d84315"), // 4  orange
    ("#e1bee7", "#7b1fa2"), // 5  purple
    ("#b2ebf2", "#00838f"), // 6  teal
    ("#f8bbd0", "#c2185b"), // 7  pink
    ("#d7ccc8", "#5d4037"), // 8  brown
    ("#c5cae9", "#283593"), // 9  indigo
    ("#dcedc8", "#558b2f"), // 10 lime
    ("#ffe0b2", "#e65100"), // 11 deep orange
    ("#b3e5fc", "#0277bd"), // 12 light blue
    ("#f0f4c3", "#9e9d24"), // 13 yellow-green
    ("#ffcdd2", "#b71c1c"), // 14 red
    ("#d1c4e9", "#4527a0"), // 15 deep purple
    ("#b2dfdb", "#00695c"), // 16 green-teal
    ("#ffe082", "#ff8f00"), // 17 amber
    ("#f3e5f5", "#6a1b9a"), // 18 light purple
    ("#e0f7fa", "#006064"), // 19 cyan
    ("#fce4ec", "#880e4f"), // 20 deep pink
];

/// Blend a hex color toward gray (#e8e8e8) based on taint score.
/// score=1.0 → full color, score=0.1 → mostly gray.
fn taint_gradient(hex: &str, score: f64) -> String {
    let score = score.clamp(0.0, 1.0);
    // Parse hex color
    let hex = hex.trim_start_matches('#');
    if hex.len() != 6 {
        return format!("#{hex}");
    }
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(232);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(232);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(232);

    // Blend with gray (0xe8 = 232)
    let gray = 232.0;
    let blend = |c: u8| -> u8 {
        (gray + (c as f64 - gray) * score) as u8
    };
    format!("#{:02x}{:02x}{:02x}", blend(r), blend(g), blend(b))
}

fn action_color(action_id: u64) -> (&'static str, &'static str) {
    if action_id == 0 {
        return BASELINE_COLOR;
    }
    let idx = ((action_id - 1) as usize) % ACTION_COLORS.len();
    ACTION_COLORS[idx]
}

/// Render the knowledge graph showing data flow between processes via files.
///
/// Process nodes: boxes colored by action, labeled with cmdline
/// File nodes: ovals, only shown when they mediate cross-process data flow
///   (written by process A, read/exec'd by process B where A != B)
///   or are sensitive files that were read
/// Edges: process→file (write), file→process (read/exec)
pub fn render_dot(container: &ContainerState) -> String {
    let mut dot = String::with_capacity(16384);
    writeln!(dot, "digraph syscon {{").unwrap();
    writeln!(dot, "  rankdir=LR;").unwrap();
    writeln!(dot, "  bgcolor=\"#fafafa\";").unwrap();
    writeln!(dot, "  newrank=true;").unwrap();
    writeln!(dot, "  node [fontname=\"monospace\", fontsize=9, margin=\"0.15,0.1\"];").unwrap();
    writeln!(dot, "  edge [fontname=\"monospace\", fontsize=8];").unwrap();
    writeln!(dot, "  graph [nodesep=0.4, ranksep=0.6];").unwrap();
    writeln!(dot).unwrap();

    // === Determine which files to show ===
    // Only files that create cross-process data flow or are sensitive.
    // Exclude pure binary exec paths — those are shown in process labels.
    let mut shown_files: HashSet<&str> = HashSet::new();
    for (path, node) in &container.file_nodes {
        if skip_path(path) {
            continue;
        }
        // Skip if the file is ONLY exec'd (binary path, not data flow)
        let only_exec = node.writers.is_empty()
            && node.readers.is_empty()
            && node.deleters.is_empty()
            && node.modifiers.is_empty()
            && !node.executors.is_empty();
        if only_exec {
            continue;
        }

        let writer_pids: HashSet<u32> = node.writers.iter().map(|(p, _)| *p).collect();
        let reader_pids: HashSet<u32> = node.readers.iter().map(|(p, _)| *p).collect();
        let executor_pids: HashSet<u32> = node.executors.iter().map(|(p, _)| *p).collect();
        let consumer_pids: HashSet<u32> = reader_pids.union(&executor_pids).copied().collect();

        let has_cross_flow = writer_pids.iter().any(|w| consumer_pids.iter().any(|r| w != r));

        if has_cross_flow
            || is_sensitive_path(path)
            || !node.deleters.is_empty()
            || !node.modifiers.is_empty()
            || (!node.writers.is_empty() && !consumer_pids.is_empty())
        {
            shown_files.insert(path.as_str());
        }
    }

    // === PROCESS NODES ===
    // Limit to avoid crashing viz.js on large containers.
    // Sort by taint score (most tainted first) so we show the interesting ones.
    let mut process_list: Vec<_> = container.process_table.processes.iter().collect();
    process_list.sort_by(|a, b| b.1.taint_score.partial_cmp(&a.1.taint_score).unwrap_or(std::cmp::Ordering::Equal));
    let max_nodes = 50;
    if process_list.len() > max_nodes {
        writeln!(dot, "  // Showing top {} of {} processes (by taint score)", max_nodes, process_list.len()).unwrap();
    }

    writeln!(dot, "  // Process nodes").unwrap();
    for &(pid, info) in process_list.iter().take(max_nodes) {
        // Determine which action this process belongs to
        let action_id = find_process_action(container, *pid);
        let (fill, border) = if info.is_tainted() {
            let (f, b) = action_color(action_id);
            // Blend with gray based on taint score for gradient effect
            let fill = taint_gradient(f, info.taint_score);
            (fill, b.to_string())
        } else {
            ("#e8e8e8".to_string(), "#999999".to_string())
        };

        let comm = util::decode_comm(if !info.comm.is_empty() { &info.comm } else { "?" });

        let cmd = if !info.cmdline.is_empty() && !info.cmdline.starts_with("runc") {
            Some(info.cmdline.clone())
        } else if !info.exec_path.is_empty() && !info.exec_path.starts_with("/runc") {
            Some(info.exec_path.clone())
        } else {
            None
        };

        let pid_line = format!("pid {} | action #{}", pid, action_id);

        // Build HTML label
        let mut rows = Vec::new();
        rows.push(format!("<B>{}</B>", escape_html(&comm)));
        if let Some(cmd) = cmd {
            rows.push(format!("<FONT POINT-SIZE=\"8\">$ {}</FONT>", wrap_html(&cmd, 40)));
        }
        rows.push(format!("<FONT POINT-SIZE=\"7\" COLOR=\"#666666\">{}</FONT>", escape_html(&pid_line)));
        if info.exited {
            rows.push("<FONT POINT-SIZE=\"7\" COLOR=\"#666666\">(exited)</FONT>".to_string());
        }

        let label = rows
            .iter()
            .map(|r| format!("<TR><TD ALIGN=\"LEFT\">{}</TD></TR>", r))
            .collect::<Vec<_>>()
            .join("");

        let _style = if info.exited {
            "filled,rounded,dashed"
        } else {
            "filled,rounded"
        };

        writeln!(
            dot,
            "  p{} [shape=plaintext, label=<<TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"2\" CELLPADDING=\"4\" BGCOLOR=\"{}\" COLOR=\"{}\" STYLE=\"ROUNDED\">{}</TABLE>>];",
            pid, fill, border, label
        )
        .unwrap();
    }

    // Group docker exec entry points (ppid not in container) at same rank
    let exec_entries: Vec<u32> = container
        .process_table
        .processes
        .iter()
        .filter(|(_, info)| {
            info.ppid != 0
                && !container.process_table.processes.contains_key(&info.ppid)
                && info.taint_source != "container entry point"
        })
        .map(|(pid, _)| *pid)
        .collect();
    if exec_entries.len() > 1 {
        writeln!(dot, "  {{ rank=same; {} }}",
            exec_entries.iter().map(|p| format!("p{}", p)).collect::<Vec<_>>().join("; ")
        ).unwrap();
    }

    writeln!(dot).unwrap();

    // === FILE NODES ===
    writeln!(dot, "  // File nodes (data flow mediators)").unwrap();
    for path in &shown_files {
        let node = &container.file_nodes[*path];
        let short = short_path(path);

        let fill = if is_sensitive_path(path) {
            "#ffcdd2" // red — sensitive
        } else if !node.executors.is_empty() {
            "#ffe0b2" // orange — executed
        } else if !node.deleters.is_empty() {
            "#ef9a9a" // light red — deleted
        } else {
            "#e3f2fd" // light blue — data
        };

        writeln!(
            dot,
            "  f{} [shape=ellipse, label=\"{}\", fillcolor=\"{}\", style=filled, color=\"#666666\"];",
            path_id(path),
            escape_dot(short),
            fill
        )
        .unwrap();
    }

    writeln!(dot).unwrap();

    // === NETWORK ENDPOINT NODES ===
    writeln!(dot, "  // Network endpoints").unwrap();
    let mut net_endpoints: HashMap<String, Vec<(u32, &str)>> = HashMap::new(); // endpoint → [(pid, direction)]
    for (pid, info) in &container.process_table.processes {
        for conn in &info.net_connections {
            let (direction, addr) = if let Some(a) = conn.strip_prefix("connect ") {
                ("connect", a)
            } else if let Some(a) = conn.strip_prefix("listen ") {
                ("listen", a)
            } else {
                continue;
            };
            net_endpoints
                .entry(addr.to_string())
                .or_default()
                .push((*pid, direction));
        }
    }
    for endpoint in net_endpoints.keys() {
        // Skip localhost listen endpoints (noise)
        if endpoint.starts_with("0.0.0.0:") || endpoint.starts_with("[::]:") {
            // Only show listens if something connects to them
            continue;
        }
        writeln!(
            dot,
            "  n{} [shape=diamond, label=\"{}\", fillcolor=\"#ffe0e0\", style=filled, color=\"#cc0000\"];",
            path_id(endpoint),
            escape_dot(endpoint)
        )
        .unwrap();
    }

    writeln!(dot).unwrap();

    // === FORK EDGES ===
    writeln!(dot, "  // Fork/spawn edges").unwrap();
    for edge in &container.taint_graph.edges {
        let source_score = container.process_table.taint_score(edge.source_pid);
        let color = if source_score >= crate::state::TAINT_THRESHOLD {
            // Gradient red based on score: 1.0 → #cc0000, 0.1 → #cc9999
            let intensity = (source_score * 255.0) as u8;
            format!("#cc{:02x}{:02x}", 255 - intensity, 255 - intensity)
        } else {
            "#cccccc".to_string()
        };
        let label = format!("{}", edge.channel_type);
        writeln!(
            dot,
            "  p{} -> p{} [label=\"{}\", color=\"{}\", fontcolor=\"{}\", style=dashed, penwidth=1.0];",
            edge.source_pid, edge.target_pid, escape_dot(&label), color, color
        )
        .unwrap();
    }

    writeln!(dot).unwrap();

    // === DATA FLOW EDGES ===
    writeln!(dot, "  // Data flow edges").unwrap();
    for path in &shown_files {
        let node = &container.file_nodes[*path];
        let fid = path_id(path);

        // Process → File (write)
        for (pid, _) in &node.writers {
            if container.process_table.processes.contains_key(pid) {
                writeln!(
                    dot,
                    "  p{} -> f{} [label=\"write\", color=\"#2e7d32\", fontcolor=\"#2e7d32\", penwidth=1.5];",
                    pid, fid
                )
                .unwrap();
            }
        }

        // File → Process (read)
        for (pid, _) in &node.readers {
            if container.process_table.processes.contains_key(pid) {
                writeln!(
                    dot,
                    "  f{} -> p{} [label=\"read\", color=\"#1565c0\", fontcolor=\"#1565c0\"];",
                    fid, pid
                )
                .unwrap();
            }
        }

        // File → Process (exec) — bold
        for (pid, _) in &node.executors {
            if container.process_table.processes.contains_key(pid) {
                writeln!(
                    dot,
                    "  f{} -> p{} [label=\"exec\", color=\"#e65100\", fontcolor=\"#e65100\", penwidth=2.0, style=bold];",
                    fid, pid
                )
                .unwrap();
            }
        }

        // Process → File (delete)
        for (pid, _) in &node.deleters {
            if container.process_table.processes.contains_key(pid) {
                writeln!(
                    dot,
                    "  p{} -> f{} [label=\"delete\", color=\"#b71c1c\", fontcolor=\"#b71c1c\", style=dotted];",
                    pid, fid
                )
                .unwrap();
            }
        }

        // Process → File (chmod/chown)
        for (pid, _) in &node.modifiers {
            if container.process_table.processes.contains_key(pid) {
                writeln!(
                    dot,
                    "  p{} -> f{} [label=\"chmod\", color=\"#6a1b9a\", fontcolor=\"#6a1b9a\"];",
                    pid, fid
                )
                .unwrap();
            }
        }
    }

    // === NETWORK EDGES ===
    writeln!(dot, "  // Network edges").unwrap();
    for (endpoint, procs) in &net_endpoints {
        if endpoint.starts_with("0.0.0.0:") || endpoint.starts_with("[::]:") {
            continue;
        }
        let nid = path_id(endpoint);
        for (pid, direction) in procs {
            if !container.process_table.processes.contains_key(pid) {
                continue;
            }
            match *direction {
                "connect" => {
                    writeln!(
                        dot,
                        "  p{} -> n{} [label=\"connect\", color=\"#cc0000\", fontcolor=\"#cc0000\", penwidth=1.5];",
                        pid, nid
                    )
                    .unwrap();
                }
                "listen" => {
                    writeln!(
                        dot,
                        "  n{} -> p{} [label=\"listen\", color=\"#0d47a1\", fontcolor=\"#0d47a1\"];",
                        nid, pid
                    )
                    .unwrap();
                }
                _ => {}
            }
        }
    }

    // === LEGEND ===
    writeln!(dot).unwrap();
    writeln!(dot, "  // Legend").unwrap();
    writeln!(dot, "  subgraph cluster_legend {{").unwrap();
    writeln!(dot, "    label=\"Legend\"; style=rounded; color=\"#cccccc\"; fontsize=10;").unwrap();
    writeln!(dot, "    node [shape=plaintext, fontsize=8];").unwrap();
    let mut legend_parts = Vec::new();
    for action in container.completed_actions.iter() {
        let (fill, _) = action_color(action.action_id);
        let cmd_short = if action.command.len() > 30 {
            &action.command[..30]
        } else {
            &action.command
        };
        legend_parts.push(format!(
            "<TR><TD BGCOLOR=\"{}\">Action #{}: {}</TD></TR>",
            fill,
            action.action_id,
            escape_html(cmd_short)
        ));
    }
    if !legend_parts.is_empty() {
        writeln!(
            dot,
            "    legend [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">{}</TABLE>>];",
            legend_parts.join("")
        )
        .unwrap();
    }
    writeln!(dot, "  }}").unwrap();

    writeln!(dot, "}}").unwrap();
    dot
}

/// Find which action a process was first seen in.
fn find_process_action(container: &ContainerState, pid: u32) -> u64 {
    // Check completed actions for first exec/fork of this PID
    for action in &container.completed_actions {
        for pe in &action.process_events {
            if pe.pid == pid {
                return action.action_id;
            }
        }
    }
    if let Some(action) = &container.current_action {
        for pe in &action.process_events {
            if pe.pid == pid {
                return action.action_id;
            }
        }
    }
    0 // container baseline
}

fn skip_path(path: &str) -> bool {
    path.is_empty()
        || path == "/"
        || path.starts_with("/proc/")
        || path.starts_with("/dev/")
        || path.starts_with("/sys/")
        || path.contains("(deleted)")
        || path.contains("(null)")
        || path.starts_with("pipe:")
        || path.starts_with("anon_inode:")
        || path.starts_with("socket:")
        || path.starts_with("//")
        // Docker overlay2 paths (contain long hex layer IDs)
        || path.contains("/overlay2/")
        || path.contains("/docker/")
        // Bare numbers (fd numbers, inodes)
        || path.chars().all(|c| c.is_ascii_digit())
        // Long hex strings (container IDs, hashes from audit)
        || (path.len() >= 12 && path.chars().all(|c| c.is_ascii_hexdigit()))
        // Path segments that are entirely hex and long (overlay hashes)
        || path.split('/').any(|seg| seg.len() >= 20 && seg.chars().all(|c| c.is_ascii_hexdigit()))
        // Bare filenames without path separators (audit noise like "installed", "triggers")
        || (!path.contains('/') && !path.starts_with('.'))
}

fn is_sensitive_path(path: &str) -> bool {
    path.contains("/etc/shadow")
        || path.contains("/etc/passwd")
        || path.contains("/.ssh/")
        || path.contains("/etc/sudoers")
}

fn short_path(p: &str) -> &str {
    if p.len() > 45 {
        &p[p.len() - 45..]
    } else {
        p
    }
}

fn path_id(path: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in path.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

/// Render a DOT graph for an experiment, with each container in a cluster box.
/// Cross-container network edges are drawn between clusters.
pub fn render_experiment_dot(state: &DaemonState, experiment: &Experiment) -> String {
    let mut dot = String::with_capacity(16384);
    writeln!(dot, "digraph experiment {{").unwrap();
    writeln!(dot, "  rankdir=LR;").unwrap();
    writeln!(dot, "  bgcolor=\"#fafafa\";").unwrap();
    writeln!(dot, "  compound=true;").unwrap();
    writeln!(dot, "  node [fontname=\"monospace\", fontsize=9, margin=\"0.15,0.1\"];").unwrap();
    writeln!(dot, "  edge [fontname=\"monospace\", fontsize=8];").unwrap();
    writeln!(dot).unwrap();

    // Collect all actions across all containers for the legend
    let mut all_actions: Vec<(u64, String)> = Vec::new();

    // Render each container as a subgraph cluster (same data flow logic as render_dot)
    for (idx, cid) in experiment.container_ids.iter().enumerate() {
        let Some(container) = state.containers.get(cid) else { continue };
        let short = &cid[..cid.len().min(12)];

        // Collect actions for legend
        for action in &container.completed_actions {
            if action.action_id == 0 { continue; }
            if !all_actions.iter().any(|(id, _)| *id == action.action_id) {
                all_actions.push((action.action_id, action.command.clone()));
            }
        }

        // Determine which files to show (same logic as render_dot)
        let mut shown_files: HashSet<&str> = HashSet::new();
        for (path, node) in &container.file_nodes {
            if skip_path(path) { continue; }
            let only_exec = node.writers.is_empty() && node.readers.is_empty()
                && node.deleters.is_empty() && node.modifiers.is_empty()
                && !node.executors.is_empty();
            if only_exec { continue; }
            let writer_pids: HashSet<u32> = node.writers.iter().map(|(p, _)| *p).collect();
            let reader_pids: HashSet<u32> = node.readers.iter().map(|(p, _)| *p).collect();
            let executor_pids: HashSet<u32> = node.executors.iter().map(|(p, _)| *p).collect();
            let consumer_pids: HashSet<u32> = reader_pids.union(&executor_pids).copied().collect();
            let has_cross_flow = writer_pids.iter().any(|w| consumer_pids.iter().any(|r| w != r));
            if has_cross_flow || is_sensitive_path(path) || !node.deleters.is_empty()
                || !node.modifiers.is_empty() || (!node.writers.is_empty() && !consumer_pids.is_empty()) {
                shown_files.insert(path.as_str());
            }
        }

        // Container cluster box
        writeln!(dot, "  subgraph cluster_{} {{", idx).unwrap();
        writeln!(dot, "    label=\"Container {}\";", short).unwrap();
        writeln!(dot, "    style=rounded; color=\"#666666\"; fontsize=10;").unwrap();
        writeln!(dot).unwrap();

        // Process nodes (top N by taint)
        let mut proc_list: Vec<_> = container.process_table.processes.iter()
            .filter(|(_, info)| info.taint_score >= 0.1)
            .collect();
        proc_list.sort_by(|a, b| b.1.taint_score.partial_cmp(&a.1.taint_score).unwrap_or(std::cmp::Ordering::Equal));
        let max_nodes = 50;
        let shown_pids: HashSet<u32> = proc_list.iter().take(max_nodes).map(|(pid, _)| **pid).collect();

        for &(pid, info) in proc_list.iter().take(max_nodes) {
            let action_id = find_process_action(container, *pid);
            let (fill, border) = action_color(action_id);
            let fill = taint_gradient(fill, info.taint_score);
            let comm = util::decode_comm(&info.comm);
            let cmd_short = if info.cmdline.len() > 40 {
                format!("{}...", &info.cmdline[..40])
            } else {
                info.cmdline.clone()
            };
            writeln!(dot, "    c{}p{} [shape=plaintext, label=<<TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"2\" CELLPADDING=\"4\" BGCOLOR=\"{}\" COLOR=\"{}\" STYLE=\"ROUNDED\"><TR><TD ALIGN=\"LEFT\"><B>{}</B></TD></TR><TR><TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"8\">$ {}</FONT></TD></TR><TR><TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"7\" COLOR=\"#666666\">pid {} | action #{}</FONT></TD></TR></TABLE>>];",
                idx, pid, fill, border,
                escape_html(&comm), escape_html(&cmd_short), pid, action_id,
            ).unwrap();
        }

        // File nodes
        for path in &shown_files {
            let node = &container.file_nodes[*path];
            let fill = if is_sensitive_path(path) { "#ffcdd2" }
                else if !node.executors.is_empty() { "#ffe0b2" }
                else if !node.deleters.is_empty() { "#ef9a9a" }
                else { "#e3f2fd" };
            writeln!(dot, "    c{}f{} [shape=ellipse, label=\"{}\", fillcolor=\"{}\", style=filled, color=\"#666666\"];",
                idx, path_id(path), escape_dot(short_path(path)), fill).unwrap();
        }

        // Network endpoint nodes
        let mut net_endpoints: HashMap<String, Vec<(u32, &str)>> = HashMap::new();
        for (pid, info) in &container.process_table.processes {
            for conn in &info.net_connections {
                if let Some(a) = conn.strip_prefix("connect ") {
                    net_endpoints.entry(a.to_string()).or_default().push((*pid, "connect"));
                } else if let Some(a) = conn.strip_prefix("listen ") {
                    net_endpoints.entry(a.to_string()).or_default().push((*pid, "listen"));
                }
            }
        }
        for endpoint in net_endpoints.keys() {
            if endpoint.starts_with("0.0.0.0:") || endpoint.starts_with("[::]:") { continue; }
            writeln!(dot, "    c{}n{} [shape=diamond, label=\"{}\", fillcolor=\"#ffe0e0\", style=filled, color=\"#cc0000\"];",
                idx, path_id(endpoint), escape_dot(endpoint)).unwrap();
        }

        // Fork/taint edges
        for edge in &container.taint_graph.edges {
            if shown_pids.contains(&edge.source_pid) && shown_pids.contains(&edge.target_pid) {
                let source_score = container.process_table.taint_score(edge.source_pid);
                let color = if source_score >= 0.1 {
                    let intensity = (source_score * 255.0) as u8;
                    format!("#cc{:02x}{:02x}", 255 - intensity, 255 - intensity)
                } else { "#cccccc".to_string() };
                writeln!(dot, "    c{}p{} -> c{}p{} [label=\"{}\", color=\"{}\", fontcolor=\"{}\", style=dashed, penwidth=1.0];",
                    idx, edge.source_pid, idx, edge.target_pid,
                    escape_dot(&format!("{}", edge.channel_type)), color, color).unwrap();
            }
        }

        // Data flow edges (process → file → process)
        for path in &shown_files {
            let node = &container.file_nodes[*path];
            let fid = path_id(path);
            for (pid, _) in &node.writers {
                if shown_pids.contains(pid) {
                    writeln!(dot, "    c{}p{} -> c{}f{} [label=\"write\", color=\"#2e7d32\", fontcolor=\"#2e7d32\", penwidth=1.5];",
                        idx, pid, idx, fid).unwrap();
                }
            }
            for (pid, _) in &node.readers {
                if shown_pids.contains(pid) {
                    writeln!(dot, "    c{}f{} -> c{}p{} [label=\"read\", color=\"#1565c0\", fontcolor=\"#1565c0\"];",
                        idx, fid, idx, pid).unwrap();
                }
            }
            for (pid, _) in &node.executors {
                if shown_pids.contains(pid) {
                    writeln!(dot, "    c{}f{} -> c{}p{} [label=\"exec\", color=\"#e65100\", fontcolor=\"#e65100\", penwidth=2.0, style=bold];",
                        idx, fid, idx, pid).unwrap();
                }
            }
        }

        // Network edges
        for (endpoint, procs) in &net_endpoints {
            if endpoint.starts_with("0.0.0.0:") || endpoint.starts_with("[::]:") { continue; }
            let nid = path_id(endpoint);
            for (pid, direction) in procs {
                if !shown_pids.contains(pid) { continue; }
                match *direction {
                    "connect" => writeln!(dot, "    c{}p{} -> c{}n{} [label=\"connect\", color=\"#cc0000\", fontcolor=\"#cc0000\", penwidth=1.5];",
                        idx, pid, idx, nid).unwrap(),
                    "listen" => writeln!(dot, "    c{}n{} -> c{}p{} [label=\"listen\", color=\"#0d47a1\", fontcolor=\"#0d47a1\"];",
                        idx, nid, idx, pid).unwrap(),
                    _ => {}
                }
            }
        }

        writeln!(dot, "  }}").unwrap();
        writeln!(dot).unwrap();
    }

    // Cross-container network edges
    for (idx_a, cid_a) in experiment.container_ids.iter().enumerate() {
        let Some(container_a) = state.containers.get(cid_a) else { continue };
        for info in container_a.process_table.processes.values() {
            if info.taint_score < 0.1 { continue; }
            for conn in &info.net_connections {
                if let Some(addr) = conn.strip_prefix("connect ") {
                    if let Some((ip_str, _port)) = addr.rsplit_once(':') {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            if let Some(target_cid) = state.ip_to_container.get(&ip) {
                                if let Some(idx_b) = experiment.container_ids.iter().position(|c| c == target_cid) {
                                    if idx_a != idx_b {
                                        writeln!(dot, "  c{}p{} -> c{}listen_{} [label=\"{}\", color=\"#d32f2f\", penwidth=2.0, style=bold];",
                                            idx_a, info.pid, idx_b, path_id(&format!("0.0.0.0:{}", addr.rsplit_once(':').map(|(_,p)| p).unwrap_or(""))),
                                            escape_dot(addr)).unwrap();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Legend
    all_actions.sort_by_key(|(id, _)| *id);
    writeln!(dot).unwrap();
    writeln!(dot, "  subgraph cluster_legend {{").unwrap();
    writeln!(dot, "    label=\"Legend\"; style=rounded; color=\"#cccccc\"; fontsize=10;").unwrap();
    writeln!(dot, "    node [shape=plaintext, fontsize=8];").unwrap();
    let mut legend_parts = Vec::new();
    for (action_id, command) in &all_actions {
        let (fill, _) = action_color(*action_id);
        let cmd_short = if command.len() > 30 { &command[..30] } else { command };
        legend_parts.push(format!(
            "<TR><TD BGCOLOR=\"{}\">Action #{}: {}</TD></TR>",
            fill, action_id, escape_html(cmd_short)
        ));
    }
    if !legend_parts.is_empty() {
        writeln!(dot, "    legend [label=<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">{}</TABLE>>];",
            legend_parts.join("")).unwrap();
    }
    writeln!(dot, "  }}").unwrap();

    writeln!(dot, "}}").unwrap();
    dot
}

