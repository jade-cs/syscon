use std::collections::HashMap;
use std::fmt::Write;

use crate::events::{FileOp, NetOp, ProcessOp};
use crate::state::ContainerState;

const RUNTIME_BINARIES: &[&str] = &["/runc", "/usr/bin/runc", "/usr/sbin/runc"];

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

/// Filter out paths that are artifacts of our /proc/fd resolution, not real files.
fn is_noise_file(f: &str) -> bool {
    if f == "/" || f == "/runc" {
        return true;
    }
    // Leaked /proc-internal paths (numeric prefix like /1234/setgroups)
    if f.starts_with('/') {
        if let Some(c) = f.chars().nth(1) {
            if c.is_ascii_digit() {
                return true;
            }
        }
    }
    // Socket/pipe references that leaked through with // prefix
    if f.starts_with("//") || f.starts_with("socket:") || f.starts_with("pipe:") || f.starts_with("anon_inode:") {
        return true;
    }
    false
}

/// Compress a list of file paths into grouped directory output lines.
/// e.g. ["/usr/share/doc/curl/copyright", "/usr/share/doc/krb5/copyright"]
/// → "/usr/share/doc/{curl, krb5, ...}/copyright"
fn compress_file_list(files: &[String]) -> Vec<String> {
    if files.len() <= 4 {
        return files.iter().map(|f| f.clone()).collect();
    }

    // Group by parent directory
    let mut by_dir: HashMap<String, Vec<String>> = HashMap::new();
    for f in files {
        let dir = f.rfind('/').map(|i| &f[..i]).unwrap_or("/");
        let fname = f.rfind('/').map(|i| &f[i + 1..]).unwrap_or(f);
        by_dir.entry(dir.to_string()).or_default().push(fname.to_string());
    }

    let mut result = Vec::new();
    let mut dirs: Vec<_> = by_dir.iter().collect();
    dirs.sort_by_key(|(d, _)| d.clone());

    for (dir, fnames) in dirs {
        if fnames.len() == 1 {
            result.push(format!("{}/{}", dir, fnames[0]));
        } else if fnames.len() <= 3 {
            result.push(format!("{}/{{{}}}", dir, fnames.join(", ")));
        } else {
            result.push(format!(
                "{}/{{{}, ... +{} more}}",
                dir,
                fnames[..2].join(", "),
                fnames.len() - 2
            ));
        }
    }

    // If still too many lines (many directories), group by grandparent
    if result.len() > 12 {
        let mut by_grandparent: HashMap<String, usize> = HashMap::new();
        for f in files {
            // Take first 2 path components as grandparent
            let parts: Vec<&str> = f.split('/').collect();
            let gp = if parts.len() >= 4 {
                parts[..3].join("/")
            } else if parts.len() >= 3 {
                parts[..2].join("/")
            } else {
                f.clone()
            };
            *by_grandparent.entry(gp).or_default() += 1;
        }
        let mut compressed = Vec::new();
        let mut gps: Vec<_> = by_grandparent.iter().collect();
        gps.sort_by(|a, b| b.1.cmp(a.1));
        for (gp, count) in gps {
            if *count > 1 {
                compressed.push(format!("{}/ ({} files)", gp, count));
            } else {
                compressed.push(gp.clone());
            }
        }
        return compressed;
    }

    result
}

fn process_name(container: &ContainerState, pid: u32) -> String {
    container
        .process_table
        .get(&pid)
        .map(|i| decode_comm(&i.comm))
        .unwrap_or_else(|| "?".to_string())
}

fn process_cmd(container: &ContainerState, pid: u32) -> String {
    container
        .process_table
        .get(&pid)
        .map(|i| i.cmdline.clone())
        .unwrap_or_default()
}

pub fn generate_receipt_from_action(
    container: &ContainerState,
    action: &crate::events::ActionLog,
) -> String {
    generate_receipt_inner(container, action)
}

pub fn generate_receipt(container: &ContainerState, action_id: u64) -> String {
    let action = match &container.current_action {
        Some(a) if a.action_id == action_id => a,
        _ => {
            return format!(
                "=== Post-Action Receipt: Action #{} ===\nNo action data found.\n",
                action_id
            );
        }
    };
    generate_receipt_inner(container, action)
}

fn generate_receipt_inner(
    container: &ContainerState,
    action: &crate::events::ActionLog,
) -> String {
    let mut out = String::with_capacity(4096);

    let now = monotonic_ns();
    let start = if action.start_time == 0 {
        action.process_events.first().map(|e| e.timestamp).unwrap_or(now)
    } else {
        action.start_time
    };
    let end = action.end_time.unwrap_or(now);
    let duration_s = (end.saturating_sub(start)) as f64 / 1_000_000_000.0;

    let action_pids: std::collections::HashSet<u32> =
        action.process_events.iter().map(|e| e.pid).collect();

    writeln!(out, "=== Post-Action Receipt: Action #{} ===", action.action_id).unwrap();
    writeln!(out, "Command: {}", action.command).unwrap();
    writeln!(out, "Duration: {:.1}s | {} syscall events", duration_s, action.total_events).unwrap();
    writeln!(out).unwrap();

    write_process_summary(&mut out, container, action);
    write_commands_run(&mut out, container, action);
    write_process_tree(&mut out, container, &action_pids);
    write_activity_summary(&mut out, container, action);
    write_files_observed(&mut out, container, &action_pids);
    write_data_flows(&mut out, container, action.action_id, &action_pids);
    write_network_summary(&mut out, container, &action_pids);

    out
}

/// Process summary: binaries and counts.
fn write_process_summary(
    out: &mut String,
    _container: &ContainerState,
    action: &crate::events::ActionLog,
) {
    let mut exec_counts: HashMap<String, u32> = HashMap::new();
    let mut exit_count = 0u32;
    let mut fork_count = 0u32;

    for event in &action.process_events {
        match event.operation {
            ProcessOp::Exec => {
                let path = if RUNTIME_BINARIES.contains(&event.exe.as_str()) {
                    continue; // skip runc from counts
                } else {
                    event.exe.clone()
                };
                *exec_counts.entry(path).or_default() += 1;
            }
            ProcessOp::Fork => fork_count += 1,
            ProcessOp::Exit => exit_count += 1,
            ProcessOp::Signal => {}
        }
    }

    if exec_counts.is_empty() && fork_count == 0 {
        return;
    }

    let total_exec: u32 = exec_counts.values().sum();
    writeln!(out, "PROCESSES: {} spawned, {} exited", fork_count + total_exec, exit_count).unwrap();

    let mut sorted: Vec<_> = exec_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (binary, count) in &sorted {
        if **count > 1 {
            writeln!(out, "  {} (x{})", binary, count).unwrap();
        } else {
            writeln!(out, "  {}", binary).unwrap();
        }
    }
    writeln!(out).unwrap();
}

/// All unique commands run during this action (the most important section for the monitor).
/// Deduplicated, with repeat counts. Sorted by first occurrence.
fn write_commands_run(
    out: &mut String,
    container: &ContainerState,
    action: &crate::events::ActionLog,
) {
    // Collect unique cmdlines, count duplicates.
    // Normalize temp paths so commands differing only in random filenames
    // (e.g. /tmp/ccYlVQ3o.s vs /tmp/ccXnI1OH.s) are grouped together.
    let mut cmd_counts: Vec<(String, String, u32)> = Vec::new(); // (display, normalized, count)
    let mut seen: HashMap<String, usize> = HashMap::new();

    for event in &action.process_events {
        if event.operation != ProcessOp::Exec {
            continue;
        }
        let cmd = process_cmd(container, event.pid);
        if cmd.is_empty()
            || cmd.starts_with("runc")
            || cmd == "/usr/bin/dash"
            || cmd == "/bin/sh"
        {
            continue;
        }
        let normalized = normalize_cmd(&cmd);
        if let Some(&idx) = seen.get(&normalized) {
            cmd_counts[idx].2 += 1;
        } else {
            seen.insert(normalized.clone(), cmd_counts.len());
            cmd_counts.push((cmd, normalized, 1));
        }
    }

    if cmd_counts.is_empty() {
        return;
    }

    writeln!(out, "COMMANDS RUN:").unwrap();
    for (display, _normalized, count) in &cmd_counts {
        // For display, show the normalized form if count > 1 (since the
        // original is just one example), otherwise show original
        let shown = if *count > 1 {
            &_normalized
        } else {
            display
        };
        let short = if shown.len() > 120 {
            let mut end = 117;
            while end > 0 && !shown.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &shown[..end])
        } else {
            shown.clone()
        };
        if *count > 1 {
            writeln!(out, "  $ {} (x{})", short, count).unwrap();
        } else {
            writeln!(out, "  $ {}", short).unwrap();
        }
    }
    writeln!(out).unwrap();
}

/// Normalize a command string for deduplication.
/// Replaces random-looking path components (temp files, hashes) with <TMP>
/// so that commands differing only in generated filenames are grouped.
fn normalize_cmd(cmd: &str) -> String {
    let mut result = String::with_capacity(cmd.len());
    for token in cmd.split(' ') {
        if !result.is_empty() {
            result.push(' ');
        }
        if looks_like_temp_path(token) {
            // Replace the random filename but keep the directory
            if let Some(slash) = token.rfind('/') {
                result.push_str(&token[..slash + 1]);
                result.push_str("<TMP>");
            } else {
                result.push_str("<TMP>");
            }
        } else {
            result.push_str(token);
        }
    }
    result
}

/// Check if a token looks like a path with a random/generated filename.
/// Matches patterns like /tmp/ccYlVQ3o.s, /tmp/pip-unpack-skq_x52f/foo.whl,
/// conftest.er1, etc.
fn looks_like_temp_path(token: &str) -> bool {
    // Must contain a path separator or start with a temp-like prefix
    let filename = token.rsplit('/').next().unwrap_or(token);

    // Skip if it's a well-known name
    if filename.starts_with('-') || filename.is_empty() {
        return false;
    }

    // Count random-looking characters (mixed case + digits in the basename)
    let base = filename.split('.').next().unwrap_or(filename);
    if base.len() < 6 {
        return false;
    }

    let has_upper = base.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = base.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = base.chars().any(|c| c.is_ascii_digit());
    let mixed = (has_upper as u8) + (has_lower as u8) + (has_digit as u8);

    // Looks random if it mixes 3 char classes and is in /tmp/ or has
    // a temp-like prefix (cc, conf, pip-)
    if mixed >= 3 && token.contains("/tmp/") {
        return true;
    }

    // Compiler temp files: cc*.s, cc*.o patterns
    if base.starts_with("cc") && mixed >= 2 && base.len() >= 8 {
        return true;
    }

    false
}

/// Compact process tree showing spawn hierarchy.
/// Uses taint graph fork edges to build parent→children relationships.
fn write_process_tree(
    out: &mut String,
    container: &ContainerState,
    action_pids: &std::collections::HashSet<u32>,
) {
    if action_pids.is_empty() {
        return;
    }

    // Build parent→children map from taint graph edges, scoped to this action
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut has_parent: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for edge in &container.taint_graph.edges {
        if action_pids.contains(&edge.source_pid) && action_pids.contains(&edge.target_pid) {
            children.entry(edge.source_pid).or_default().push(edge.target_pid);
            has_parent.insert(edge.target_pid);
        }
    }

    // Roots: PIDs in this action that have no parent in this action
    let mut roots: Vec<u32> = action_pids
        .iter()
        .filter(|pid| !has_parent.contains(pid))
        .copied()
        .collect();
    roots.sort();

    // Skip if tree is trivial (0-1 nodes, no edges)
    if children.is_empty() {
        return;
    }

    writeln!(out, "PROCESS TREE:").unwrap();

    // Render each root and its subtree
    for root in &roots {
        render_tree_node(out, container, *root, &children, 1, 0);
    }
    writeln!(out).unwrap();
}

/// Recursively render a process tree node with indentation.
/// Collapses subtrees deeper than max_depth.
fn render_tree_node(
    out: &mut String,
    container: &ContainerState,
    pid: u32,
    children: &HashMap<u32, Vec<u32>>,
    indent: usize,
    depth: usize,
) {
    let prefix = "  ".repeat(indent);
    let name = process_name(container, pid);
    let cmd = process_cmd(container, pid);

    // Show process with its command
    if !cmd.is_empty() && !cmd.starts_with("runc") {
        let short_cmd = if cmd.len() > 80 {
            let mut end = 77;
            while end > 0 && !cmd.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &cmd[..end])
        } else {
            cmd
        };
        writeln!(out, "{}{}  $ {}", prefix, name, short_cmd).unwrap();
    } else {
        writeln!(out, "{}{}", prefix, name).unwrap();
    }

    let kids = match children.get(&pid) {
        Some(k) => k,
        None => return,
    };

    if depth >= 4 && !kids.is_empty() {
        // Collapse deep subtrees
        writeln!(out, "{}  └─ ({} children)", prefix, kids.len()).unwrap();
        return;
    }

    // Group identical children (same comm) to avoid repetition
    let mut by_name: HashMap<String, Vec<u32>> = HashMap::new();
    for kid in kids {
        let kid_name = process_name(container, *kid);
        by_name.entry(kid_name).or_default().push(*kid);
    }

    for (kid_name, kid_pids) in &by_name {
        if kid_pids.len() > 3 {
            // Collapse repeated children
            // Show one example, then count
            render_tree_node(out, container, kid_pids[0], children, indent + 1, depth + 1);
            writeln!(out, "{}  ... +{} more {} processes", prefix, kid_pids.len() - 1, kid_name).unwrap();
        } else {
            for kid in kid_pids {
                render_tree_node(out, container, *kid, children, indent + 1, depth + 1);
            }
        }
    }
}

/// Filesystem and network activity grouped by process name.
fn write_activity_summary(
    out: &mut String,
    container: &ContainerState,
    action: &crate::events::ActionLog,
) {
    if action.file_op_counts.is_empty() && action.net_op_counts.is_empty() {
        return;
    }

    writeln!(out, "ACTIVITY:").unwrap();

    // File ops by process name
    let mut file_by_name: HashMap<String, HashMap<FileOp, u64>> = HashMap::new();
    for ((pid, op), count) in &action.file_op_counts {
        let name = process_name(container, *pid);
        *file_by_name.entry(name).or_default().entry(*op).or_default() += count;
    }
    if !file_by_name.is_empty() {
        let total: u64 = action.file_op_counts.values().sum();
        writeln!(out, "  Filesystem ({} ops):", total).unwrap();
        let mut sorted: Vec<_> = file_by_name.iter().collect();
        sorted.sort_by(|a, b| {
            let ta: u64 = a.1.values().sum();
            let tb: u64 = b.1.values().sum();
            tb.cmp(&ta)
        });
        for (name, ops) in &sorted {
            let ops_str: Vec<String> = ops.iter().map(|(op, c)| format!("{} x{}", op, c)).collect();
            writeln!(out, "    {}: {}", name, ops_str.join(", ")).unwrap();
        }
    }

    // Net ops by process name
    let mut net_by_name: HashMap<String, HashMap<NetOp, u64>> = HashMap::new();
    for ((pid, op), count) in &action.net_op_counts {
        let name = process_name(container, *pid);
        *net_by_name.entry(name).or_default().entry(*op).or_default() += count;
    }
    if !net_by_name.is_empty() {
        writeln!(out, "  Network:").unwrap();
        for (name, ops) in &net_by_name {
            let ops_str: Vec<String> = ops.iter().map(|(op, c)| format!("{} x{}", op, c)).collect();
            writeln!(out, "    {}: {}", name, ops_str.join(", ")).unwrap();
        }
    }

    writeln!(out).unwrap();
}

/// Files observed open by processes in this action (from /proc/fd snapshots).
/// Grouped by process name, showing unique paths. Filters noise.
fn write_files_observed(
    out: &mut String,
    container: &ContainerState,
    action_pids: &std::collections::HashSet<u32>,
) {
    let mut by_name: HashMap<String, Vec<String>> = HashMap::new();

    for pid in action_pids {
        let info = match container.process_table.get(pid) {
            Some(i) => i,
            None => continue,
        };
        if info.open_files.is_empty() {
            continue;
        }
        let name = decode_comm(&info.comm);
        let files = by_name.entry(name).or_default();
        for f in &info.open_files {
            if is_noise_file(f) {
                continue;
            }
            if !files.contains(f) {
                files.push(f.clone());
            }
        }
    }

    // Remove entries with no interesting files
    by_name.retain(|_, files| !files.is_empty());

    if by_name.is_empty() {
        return;
    }

    writeln!(out, "FILES OBSERVED OPEN:").unwrap();
    let mut sorted: Vec<_> = by_name.iter().collect();
    sorted.sort_by_key(|(name, _)| name.clone());
    for (name, files) in sorted {
        let compressed = compress_file_list(files);
        for line in &compressed {
            writeln!(out, "  {}: {}", name, line).unwrap();
        }
    }
    writeln!(out).unwrap();
}

/// Data flows scoped to this action.
fn write_data_flows(
    out: &mut String,
    container: &ContainerState,
    action_id: u64,
    action_pids: &std::collections::HashSet<u32>,
) {
    let mut flows: Vec<String> = Vec::new();
    let mut writes_by_dir: HashMap<String, Vec<String>> = HashMap::new();

    for (path, node) in &container.file_nodes {
        if path.starts_with("/proc/") || path.starts_with("/dev/")
            || path.starts_with("/sys/") || path.contains("(deleted)")
        {
            continue;
        }

        let action_writers: Vec<u32> = node.writers.iter()
            .filter(|(_, aid)| *aid == action_id)
            .map(|(p, _)| *p).collect();
        let action_consumers: Vec<u32> = node.readers.iter().chain(node.executors.iter())
            .filter(|(p, _)| action_pids.contains(p))
            .map(|(p, _)| *p).collect();

        // Cross-process data flow (skip .so libraries)
        let is_lib = path.starts_with("/usr/lib/") && path.contains(".so");
        if !is_lib {
            let all_writers: std::collections::HashSet<u32> =
                node.writers.iter().map(|(p, _)| *p).collect();
            let mut consumers: Vec<String> = Vec::new();
            for rpid in &action_consumers {
                if !all_writers.contains(rpid) {
                    let name = process_name(container, *rpid);
                    if !consumers.contains(&name) { consumers.push(name); }
                }
            }
            if !all_writers.is_empty() && !consumers.is_empty() {
                if !action_writers.is_empty() {
                    let mut wnames: Vec<String> = action_writers.iter()
                        .map(|p| process_name(container, *p)).collect();
                    wnames.sort(); wnames.dedup();
                    flows.push(format!("  {} -[{}]-> {}", wnames.join(", "), path, consumers.join(", ")));
                } else {
                    flows.push(format!("  (prior) -[{}]-> {}", path, consumers.join(", ")));
                }
            }
        }

        if !action_writers.is_empty() {
            let dir = path.rfind('/').map(|i| &path[..i]).unwrap_or("/");
            let filename = path.rfind('/').map(|i| &path[i + 1..]).unwrap_or(path);
            writes_by_dir.entry(dir.to_string()).or_default().push(filename.to_string());
        }
    }

    if !flows.is_empty() {
        writeln!(out, "DATA FLOWS:").unwrap();
        for f in &flows { writeln!(out, "{}", f).unwrap(); }
        writeln!(out).unwrap();
    }

    if !writes_by_dir.is_empty() {
        // Flatten back to full paths for compression
        let mut all_written: Vec<String> = Vec::new();
        for (dir, files) in &writes_by_dir {
            for f in files {
                all_written.push(format!("{}/{}", dir, f));
            }
        }
        all_written.sort();
        let compressed = compress_file_list(&all_written);
        writeln!(out, "FILES WRITTEN:").unwrap();
        for line in &compressed {
            writeln!(out, "  {}", line).unwrap();
        }
        writeln!(out).unwrap();
    }
}

/// Network connections grouped by destination.
fn write_network_summary(
    out: &mut String,
    container: &ContainerState,
    action_pids: &std::collections::HashSet<u32>,
) {
    let mut by_endpoint: HashMap<String, Vec<String>> = HashMap::new();
    let mut listeners: Vec<String> = Vec::new();

    for (pid, info) in &container.process_table.processes {
        if !action_pids.contains(pid) || info.net_connections.is_empty() {
            continue;
        }
        let name = process_name(container, *pid);
        for conn in &info.net_connections {
            if let Some(addr) = conn.strip_prefix("connect ") {
                let names = by_endpoint.entry(addr.to_string()).or_default();
                if !names.contains(&name) { names.push(name.clone()); }
            } else if let Some(addr) = conn.strip_prefix("listen ") {
                let entry = format!("{} on {}", name, addr);
                if !listeners.contains(&entry) { listeners.push(entry); }
            }
        }
    }

    if by_endpoint.is_empty() && listeners.is_empty() {
        return;
    }

    writeln!(out, "NETWORK:").unwrap();
    let mut sorted: Vec<_> = by_endpoint.iter().collect();
    sorted.sort_by_key(|(addr, _)| addr.clone());
    for (addr, procs) in &sorted {
        if procs.len() == 1 {
            writeln!(out, "  {} -> {}", procs[0], addr).unwrap();
        } else {
            writeln!(out, "  [{}] -> {}", procs.join(", "), addr).unwrap();
        }
    }
    if !listeners.is_empty() {
        writeln!(out, "  Listening:").unwrap();
        for l in &listeners {
            writeln!(out, "    {}", l).unwrap();
        }
    }
    writeln!(out).unwrap();
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
