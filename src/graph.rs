use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use crate::state::ContainerState;

/// Decode hex-encoded kernel comm names (e.g. "6E706D2072756E" → "npm run")
fn decode_comm(comm: &str) -> String {
    if comm.len() > 8 && comm.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Vec<u8> = (0..comm.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&comm[i..i + 2], 16).ok())
            .collect();
        if let Ok(s) = String::from_utf8(bytes) {
            if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return s;
            }
        }
    }
    comm.to_string()
}

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
    // Group processes by the action they were first seen in
    writeln!(dot, "  // Process nodes").unwrap();
    for (pid, info) in &container.process_table.processes {
        // Determine which action this process belongs to
        let action_id = find_process_action(container, *pid);
        let (fill, border) = if info.tainted {
            let (f, b) = action_color(action_id);
            (f, b)
        } else {
            ("#e8e8e8", "#999999")
        };

        let comm = decode_comm(if !info.comm.is_empty() { &info.comm } else { "?" });

        let cmd = if !info.cmdline.is_empty() && !info.cmdline.starts_with("runc") {
            Some(info.cmdline.clone())
        } else if !info.exec_path.is_empty() && !info.exec_path.starts_with("/runc") {
            Some(info.exec_path.clone())
        } else {
            None
        };

        let mut pid_line = format!("pid {} | action #{}", pid, action_id);
        if info.exited {
            pid_line.push_str(" (exited)");
        }

        // Build HTML label with word-wrapped cmdline
        let mut rows = Vec::new();
        rows.push(format!("<B>{}</B>", escape_html(&comm)));
        if let Some(cmd) = cmd {
            rows.push(format!("<FONT POINT-SIZE=\"8\">$ {}</FONT>", wrap_html(&cmd, 55)));
        }
        rows.push(format!("<FONT POINT-SIZE=\"7\" COLOR=\"#666666\">{}</FONT>", escape_html(&pid_line)));

        let label = rows
            .iter()
            .map(|r| format!("<TR><TD ALIGN=\"LEFT\">{}</TD></TR>", r))
            .collect::<Vec<_>>()
            .join("");

        let style = if info.exited {
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
    for (endpoint, procs) in &net_endpoints {
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
        let color = if container.process_table.is_tainted(edge.source_pid) {
            "#cc0000"
        } else {
            "#cccccc"
        };
        writeln!(
            dot,
            "  p{} -> p{} [label=\"fork\", color=\"{}\", fontcolor=\"{}\", style=dashed, penwidth=1.0];",
            edge.source_pid, edge.target_pid, color, color
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
    for (i, action) in container.completed_actions.iter().enumerate() {
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
    path.starts_with("/proc/")
        || path.starts_with("/dev/")
        || path.starts_with("/sys/")
        || path.contains("(deleted)")
        || path.starts_with("pipe:")
        || path.starts_with("anon_inode:")
        || path.starts_with("socket:")
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

/// Render DOT to SVG using the `dot` command.
pub fn render_svg(dot: &str) -> Result<String, String> {
    let mut child = std::process::Command::new("dot")
        .arg("-Tsvg")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn dot: {} (is graphviz installed?)", e))?;

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().ok_or("no stdin")?;
        stdin
            .write_all(dot.as_bytes())
            .map_err(|e| format!("write to dot stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("dot failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("dot error: {}", stderr));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("dot output not utf8: {}", e))
}
