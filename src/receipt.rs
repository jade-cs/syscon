use std::collections::HashMap;
use std::fmt::Write;

use crate::communities;
use crate::events::ProcessOp;
use crate::semantic;
use crate::state::{ContainerState, DaemonState, Experiment};
use crate::util;

// ── Tuning constants ───────────────────────────────────────────────

/// Initial capacity for the receipt string builder (bytes).
/// Typical receipts are 1-4 KB; 4096 avoids most reallocations.
const RECEIPT_STRING_CAPACITY: usize = 4096;

/// Minimum length of a hex-only string to be treated as noise
/// (container IDs, hashes from audit records).
const HEX_NOISE_MIN_LEN: usize = 12;

/// Minimum basename length before we consider whether it looks random/temp.
const TEMP_BASENAME_MIN_LEN: usize = 6;

/// Minimum basename length for "cc*" compiler temp file detection.
const CC_TEMP_MIN_LEN: usize = 8;

/// Minimum community size before it's shown in the PROCESS COMMUNITIES section.
/// Communities with <= this many members are readable in the normal process tree.
const COMMUNITY_DISPLAY_THRESHOLD: usize = 3;



const RUNTIME_BINARIES: &[&str] = &["/runc", "/usr/bin/runc", "/usr/sbin/runc"];


/// Filter out paths that are artifacts of our /proc/fd resolution, not real files.
fn is_noise_file(f: &str) -> bool {
    // Root directory, runc binary
    if f == "/" || f == "/runc" || f.is_empty() {
        return true;
    }
    // /proc, /dev, /sys — kernel pseudo-filesystems
    if f.starts_with("/proc/") || f.starts_with("/dev/") || f.starts_with("/sys/") {
        return true;
    }
    // Shared libraries, dynamic linker, and binary paths — process infrastructure, not data
    if f.contains(".so") || f.contains("ld-musl") || f.contains("ld-linux") {
        return true;
    }
    // Standard binary directories (the exe itself is shown in PROCESSES)
    if f.starts_with("/bin/") || f.starts_with("/sbin/") || f.starts_with("/usr/bin/") || f.starts_with("/usr/sbin/") {
        return true;
    }
    // Library directories
    if f.starts_with("/usr/lib/") || f.starts_with("/lib/") {
        return true;
    }
    // Python bytecache
    if f.contains("__pycache__") || f.ends_with(".pyc") {
        return true;
    }
    // Leaked /proc-internal paths (numeric prefix like /1234/setgroups)
    if f.starts_with('/')
        && let Some(c) = f.chars().nth(1)
            && c.is_ascii_digit() {
                return true;
            }
    // Bare numbers (fd numbers, inodes from audit records)
    if f.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // Socket/pipe/anon references
    if f.starts_with("//") || f.starts_with("socket:") || f.starts_with("pipe:") || f.starts_with("anon_inode:") {
        return true;
    }
    // (null) from audit records
    if f.contains("(null)") {
        return true;
    }
    // Long hex strings (container IDs, hashes from audit)
    if f.len() >= HEX_NOISE_MIN_LEN && f.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // Bare filenames without path separators that look like audit noise
    // (e.g., "installed", "triggers", "scripts.tar.gz.tmp")
    if !f.contains('/') && !f.starts_with('.') {
        return true;
    }
    false
}

/// Files that must never be collapsed into a glob pattern.
/// These are security-relevant and must always appear individually in receipts.
fn is_sensitive_file(path: &str) -> bool {
    path.contains("/etc/shadow")
        || path.contains("/etc/passwd")
        || path.contains("/.ssh/")
        || path.contains("/etc/sudoers")
        || path.contains("api_token")
        || path.contains("secret")
        || path.contains("credential")
        || path.contains(".env")
        || path.contains("private_key")
        || path.contains("/etc/firewall")
}

/// Compress a sorted list of file paths using glob patterns.
/// Groups files by directory, detects numeric ranges, and uses brace notation.
/// Sensitive files are never compressed — they always appear individually.
fn compress_file_list(files: &[String]) -> Vec<String> {
    if files.len() <= 3 {
        return files.to_vec();
    }

    // Separate sensitive files (never compressed)
    let mut sensitive: Vec<String> = Vec::new();
    let mut compressible: Vec<&String> = Vec::new();
    for f in files {
        if is_sensitive_file(f) {
            sensitive.push(f.clone());
        } else {
            compressible.push(f);
        }
    }

    if compressible.len() <= 3 {
        let mut result = sensitive;
        result.extend(compressible.iter().map(|s| (*s).clone()));
        result.sort();
        return result;
    }

    // Group by directory
    let mut by_dir: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for path in &compressible {
        let (dir, name) = match path.rfind('/') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("", path.as_str()),
        };
        by_dir.entry(dir).or_default().push(name);
    }

    let mut result = sensitive;

    for (dir, names) in &by_dir {
        if names.len() == 1 {
            if dir.is_empty() {
                result.push(names[0].to_string());
            } else {
                result.push(format!("{}/{}", dir, names[0]));
            }
            continue;
        }

        // Try to find numeric range pattern
        if let Some(compressed) = try_numeric_range(dir, names) {
            result.push(compressed);
            continue;
        }

        // Brace notation for same-directory files
        if names.len() <= 5 {
            let mut sorted = names.clone();
            sorted.sort();
            result.push(format!("{}/{{{}}}", dir, sorted.join(",")));
        } else {
            let mut sorted = names.clone();
            sorted.sort();
            result.push(format!("{}/{{{},{},... {}}} ({} files)",
                dir, sorted[0], sorted[1], sorted.last().unwrap(), names.len()));
        }
    }

    result.sort();
    result
}

/// Try to compress filenames in a directory as a numeric range.
/// Returns e.g. "/data/output/file_{000..109}_processed.json (110 files)"
fn try_numeric_range(dir: &str, names: &[&str]) -> Option<String> {
    if names.len() < 3 {
        return None;
    }

    // Find common prefix and suffix around numeric parts
    // e.g. "file_000_processed.json" → prefix="file_", suffix="_processed.json", num="000"
    let first = names[0];

    // Find first digit run in the first filename
    let num_start = first.find(|c: char| c.is_ascii_digit())?;
    let num_end = first[num_start..].find(|c: char| !c.is_ascii_digit())
        .map(|i| num_start + i)
        .unwrap_or(first.len());

    let prefix = &first[..num_start];
    let suffix = &first[num_end..];
    let num_width = num_end - num_start;

    // Check all names match this pattern
    let mut nums: Vec<u64> = Vec::new();
    for name in names {
        if !name.starts_with(prefix) || !name.ends_with(suffix) {
            return None;
        }
        let mid = &name[num_start..name.len() - suffix.len()];
        if mid.len() != num_width {
            return None;
        }
        nums.push(mid.parse().ok()?);
    }

    nums.sort();

    // Check if contiguous
    let min = nums[0];
    let max = *nums.last().unwrap();
    if max - min + 1 != nums.len() as u64 {
        return None; // Not contiguous — fall back to brace notation
    }

    let min_str = format!("{:0>width$}", min, width = num_width);
    let max_str = format!("{:0>width$}", max, width = num_width);

    if dir.is_empty() {
        Some(format!("{}{{{min_str}..{max_str}}}{suffix} ({} files)", prefix, nums.len()))
    } else {
        Some(format!("{dir}/{prefix}{{{min_str}..{max_str}}}{suffix} ({} files)", nums.len()))
    }
}

/// Annotate a network address with the target container ID if the IP belongs
/// to a monitored container. "172.17.0.3:8080" becomes "172.17.0.3:8080 (container abc123def456)".
fn annotate_addr(addr: &str, ip_map: &IpMap) -> String {
    // Parse the IP from addr formats like "1.2.3.4:8080", "[::1]:80", "unix:/path"
    if let Some((ip_str, _port)) = addr.rsplit_once(':') {
        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
            if let Some(cid) = ip_map.get(&ip) {
                return format!("{addr} (container {cid})");
            }
        }
    }
    addr.to_string()
}

fn process_name(container: &ContainerState, pid: u32) -> String {
    container
        .process_table
        .get(&pid)
        .map(|i| format!("{}:{}", util::decode_comm(&i.comm), pid))
        .unwrap_or_else(|| format!("?:{}", pid))
}

/// IP → container_id mapping for annotating cross-container network flows.
pub type IpMap = std::collections::HashMap<std::net::Ipv4Addr, String>;

pub fn generate_receipt_from_action(
    container: &ContainerState,
    action: &crate::events::ActionLog,
    ip_map: &IpMap,
) -> String {
    generate_receipt_inner(container, action, ip_map)
}

pub fn generate_receipt(container: &ContainerState, action_id: u64, ip_map: &IpMap) -> String {
    let action = match &container.current_action {
        Some(a) if a.action_id == action_id => a,
        _ => {
            return format!(
                "=== Post-Action Receipt: Action #{} ===\nNo action data found.\n",
                action_id
            );
        }
    };
    generate_receipt_inner(container, action, ip_map)
}

fn generate_receipt_inner(
    container: &ContainerState,
    action: &crate::events::ActionLog,
    ip_map: &IpMap,
) -> String {
    let mut out = String::with_capacity(RECEIPT_STRING_CAPACITY);

    let now = util::monotonic_ns();
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
    writeln!(out, "Duration: {:.1}s | {} syscall events", duration_s, action.total_events()).unwrap();
    writeln!(out).unwrap();

    write_process_summary(&mut out, container, action);
    write_communities(&mut out, container, &action_pids);
    write_graph_diff(&mut out, container, action.action_id, &action_pids, ip_map);
    write_semantic_summary(&mut out, container, action.action_id);

    out
}

/// Process summary: binaries and counts.
fn write_process_summary(
    out: &mut String,
    container: &ContainerState,
    action: &crate::events::ActionLog,
) {
    // Collect unique processes with their cmdlines, deduped and counted.
    // Each entry: (exe, cmdline, count, taint_score)
    let mut procs: Vec<(u32, String, String, f64, u32)> = Vec::new(); // (pid, exe, cmdline, taint, count)
    let mut seen_cmds: HashMap<String, usize> = HashMap::new();
    let mut exit_count = 0u32;
    let mut fork_count = 0u32;

    for event in &action.process_events {
        match event.operation {
            ProcessOp::Exec => {
                if RUNTIME_BINARIES.contains(&event.exe.as_str()) {
                    continue;
                }
                let cmdline = container
                    .process_table
                    .get(&event.pid)
                    .map(|i| i.cmdline.clone())
                    .unwrap_or_default();
                let taint = container.process_table.taint_score(event.pid);
                // Normalize for dedup: strip temp paths AND IP/URL variations
                // so commands differing only in target collapse together.
                let normalized = normalize_cmd_for_dedup(&cmdline);
                if let Some(&idx) = seen_cmds.get(&normalized) {
                    procs[idx].4 += 1; // increment count
                } else {
                    seen_cmds.insert(normalized, procs.len());
                    procs.push((event.pid, event.exe.clone(), cmdline, taint, 1));
                }
            }
            ProcessOp::Fork => fork_count += 1,
            ProcessOp::Exit => exit_count += 1,
            ProcessOp::Signal => {}
        }
    }

    if procs.is_empty() && fork_count == 0 {
        return;
    }

    writeln!(
        out,
        "PROCESSES: {} unique, {} forked, {} exited",
        procs.len(),
        fork_count,
        exit_count,
    )
    .unwrap();

    for (pid, exe, cmdline, _taint, count) in &procs {
        // Use the current comm from process table (updated by handle_exec)
        // rather than the event's exe field, which may be the parent shell.
        let name = container.process_table.get(pid)
            .map(|i| util::decode_comm(&i.comm))
            .unwrap_or_else(|| exe.rsplit('/').next().unwrap_or(exe).to_string());
        let count_str = if *count > 1 {
            format!(" (x{})", count)
        } else {
            String::new()
        };
        if !cmdline.is_empty() && *cmdline != *exe {
            writeln!(out, "  [{}:{}] $ {}{}", name, pid, cmdline, count_str).unwrap();
        } else {
            writeln!(out, "  [{}:{}]{}", name, pid, count_str).unwrap();
        }
    }
    writeln!(out).unwrap();
}


/// Normalize a command string for dedup: strip temp paths, IPs, and URLs
/// so commands differing only in target or temp file collapse together.
fn normalize_cmd_for_dedup(cmd: &str) -> String {
    let mut result = String::with_capacity(cmd.len());
    for token in cmd.split(' ') {
        if !result.is_empty() {
            result.push(' ');
        }
        if looks_like_temp_path(token) {
            result.push_str("<TMP>");
        } else if looks_like_ip_or_url(token) {
            result.push_str("<ADDR>");
        } else {
            result.push_str(token);
        }
    }
    result
}

fn looks_like_ip_or_url(token: &str) -> bool {
    // URLs
    if token.starts_with("http://") || token.starts_with("https://") {
        return true;
    }
    // IP:port or bare IP (N.N.N.N or N.N.N.N:port)
    let base = token.split(':').next().unwrap_or(token);
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return true;
    }
    false
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
    if base.len() < TEMP_BASENAME_MIN_LEN {
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
    if base.starts_with("cc") && mixed >= 2 && base.len() >= CC_TEMP_MIN_LEN {
        return true;
    }

    false
}

/// Process communities — groups of related processes collapsed for readability.
/// Only shown when there are communities with >3 members (otherwise the
/// process tree is already readable).
fn write_communities(
    out: &mut String,
    container: &ContainerState,
    action_pids: &std::collections::HashSet<u32>,
) {
    let comms = communities::detect_communities(container, action_pids);

    // Only show if there are non-trivial communities (>3 members)
    let large_communities: Vec<_> = comms.iter().filter(|c| c.members.len() > COMMUNITY_DISPLAY_THRESHOLD).collect();
    if large_communities.is_empty() {
        return;
    }

    writeln!(out, "PROCESS COMMUNITIES:").unwrap();
    for community in &large_communities {
        writeln!(out, "{}", communities::format_community(container, community)).unwrap();
    }

    // Summary of small communities
    let small_count: usize = comms
        .iter()
        .filter(|c| c.members.len() <= COMMUNITY_DISPLAY_THRESHOLD)
        .map(|c| c.members.len())
        .sum();
    if small_count > 0 {
        writeln!(out, "  + {} individual processes", small_count).unwrap();
    }
    writeln!(out).unwrap();
}

/// Unified graph diff: all data relationships for this action as labeled edges.
///
/// Edge types:
///   - `<proc> reads <file>`              — file inputs
///   - `<proc> writes <file>`             — file outputs / side effects
///   - `<proc> -> <proc> (fork)`          — process spawning
///   - `<proc> -> <proc> (pipe)`          — pipe data flow
///   - `<proc> connects <addr>`           — network outputs
///   - `<proc> listens <addr>`            — network listeners
///   - `<proc> (action #N) wrote <file> -> <proc> reads` — cross-action file flow
///   - `<proc> [pre-existing] influenced by <proc> via <channel>` — taint crossing to pre-action process
fn write_graph_diff(
    out: &mut String,
    container: &ContainerState,
    action_id: u64,
    action_pids: &std::collections::HashSet<u32>,
    ip_map: &IpMap,
) {
    let mut edges: Vec<String> = Vec::new();

    // Pre-pass: build cross-action file flows and track which (pid, path) pairs
    // are already explained by a cross-action edge, so we can suppress redundant
    // intra-action read edges.
    let mut cross_action_covered: std::collections::HashSet<(u32, String)> =
        std::collections::HashSet::new();
    for (path, node) in &container.file_nodes {
        if is_noise_file(path) { continue; }
        let prior_writers: Vec<(u32, u64)> = node.writers.iter()
            .filter(|(_, aid)| *aid != action_id && *aid != 0)
            .copied()
            .collect();
        if prior_writers.is_empty() { continue; }
        let action_readers: Vec<u32> = node.readers.iter()
            .chain(node.executors.iter())
            .filter(|(pid, _)| action_pids.contains(pid))
            .map(|(pid, _)| *pid)
            .collect();
        if action_readers.is_empty() { continue; }

        for (wpid, waid) in &prior_writers {
            let wname = process_name(container, *wpid);
            for &rpid in &action_readers {
                if node.writers.iter().any(|(p, _)| *p == rpid) { continue; }
                let rname = process_name(container, rpid);
                edges.push(format!("  {} (action #{}) wrote {} -> {} reads", wname, waid, path, rname));
                cross_action_covered.insert((rpid, path.clone()));
            }
        }
    }

    // 1. File reads — what this action's processes consumed
    //    Excludes paths already shown via cross-action flow edges above.
    let mut reads_by_proc: HashMap<String, Vec<String>> = HashMap::new();
    for (path, node) in &container.file_nodes {
        if is_noise_file(path) { continue; }
        for (pid, _aid) in node.readers.iter().chain(node.executors.iter()) {
            if !action_pids.contains(pid) { continue; }
            if cross_action_covered.contains(&(*pid, path.clone())) { continue; }
            let name = process_name(container, *pid);
            let files = reads_by_proc.entry(name).or_default();
            if !files.contains(path) {
                files.push(path.clone());
            }
        }
    }
    for pid in action_pids {
        let Some(info) = container.process_table.get(pid) else { continue };
        let name = process_name(container, *pid);
        let files = reads_by_proc.entry(name).or_default();
        for f in &info.open_files {
            if !is_noise_file(f) && !files.contains(f)
                && !cross_action_covered.contains(&(*pid, f.clone()))
            {
                files.push(f.clone());
            }
        }
    }
    for (name, mut files) in reads_by_proc {
        files.sort();
        files.dedup();
        let compressed = compress_file_list(&files);
        if !compressed.is_empty() {
            edges.push(format!("  {} reads {}", name, compressed.join(", ")));
        }
    }

    // 2. File writes — side effects
    let mut writes_by_proc: HashMap<String, Vec<String>> = HashMap::new();
    for (path, node) in &container.file_nodes {
        if is_noise_file(path) { continue; }
        for (pid, aid) in &node.writers {
            if *aid != action_id || !action_pids.contains(pid) { continue; }
            let name = process_name(container, *pid);
            let files = writes_by_proc.entry(name).or_default();
            if !files.contains(path) {
                files.push(path.clone());
            }
        }
    }
    for (name, mut files) in writes_by_proc {
        files.sort();
        let compressed = compress_file_list(&files);
        if !compressed.is_empty() {
            edges.push(format!("  {} writes {}", name, compressed.join(", ")));
        }
    }

    // 3. Process relationships (fork/pipe edges within this action)
    for edge in &container.taint_graph.edges {
        if !action_pids.contains(&edge.source_pid) && !action_pids.contains(&edge.target_pid) {
            continue;
        }
        let src = process_name(container, edge.source_pid);
        let dst = process_name(container, edge.target_pid);
        let label = match edge.channel_type {
            crate::state::ChannelType::Fork => "fork",
            crate::state::ChannelType::Pipe => "pipe",
            crate::state::ChannelType::FileFlow => continue, // shown as read/write edges instead
            crate::state::ChannelType::MessageQueue => "mqueue",
        };
        edges.push(format!("  {} -> {} ({})", src, dst, label));
    }

    // 4. Network connections (annotated with container IDs for cross-container flows)
    for pid in action_pids {
        let Some(info) = container.process_table.get(pid) else { continue };
        if info.net_connections.is_empty() { continue; }
        let name = process_name(container, *pid);
        let mut connects: Vec<String> = Vec::new();
        let mut listens: Vec<String> = Vec::new();
        for conn in &info.net_connections {
            if let Some(addr) = conn.strip_prefix("connect ") {
                let annotated = annotate_addr(addr, ip_map);
                if !connects.contains(&annotated) {
                    connects.push(annotated);
                }
            } else if let Some(addr) = conn.strip_prefix("listen ") {
                if !listens.contains(&addr.to_string()) {
                    listens.push(addr.to_string());
                }
            }
        }
        if !connects.is_empty() {
            edges.push(format!("  {} connects {}", name, connects.join(", ")));
        }
        if !listens.is_empty() {
            edges.push(format!("  {} listens {}", name, listens.join(", ")));
        }
    }

    // 5. Pre-existing process influence (agent tainting a clean process)
    for edge in &container.taint_graph.edges {
        let Some(target) = container.process_table.get(&edge.target_pid) else { continue };
        let Some(source) = container.process_table.get(&edge.source_pid) else { continue };
        // Source is agent-tainted, target was pre-existing (taint was 0 before this edge)
        if source.taint_score >= crate::state::TAINT_THRESHOLD
            && target.taint_source.contains("from pid")
            && !action_pids.contains(&edge.target_pid)
            && action_pids.contains(&edge.source_pid)
        {
            let src = process_name(container, edge.source_pid);
            let dst = process_name(container, edge.target_pid);
            edges.push(format!("  {} [pre-existing] influenced by {} via {}", dst, src, edge.channel_type));
        }
    }

    if edges.is_empty() {
        return;
    }

    edges.dedup();

    // Sort by (verb, detail, subject) so identical actions group together.
    // This puts "curl:X reads /etc/passwd" next to "curl:Y reads /etc/passwd"
    // rather than interleaved with "curl:X connects ...".
    edges.sort_by(|a, b| {
        let ak = edge_sort_key(a);
        let bk = edge_sort_key(b);
        ak.cmp(&bk)
    });

    // Merge lines where PIDs of the same comm do the identical thing.
    // Exception: if a PID's detail differs from the group, keep it separate
    // (e.g., one curl reading .ssh/id_rsa should stand out from other curls).
    let compressed = compress_fork_edges(&edges);

    writeln!(out, "DATA FLOWS:").unwrap();
    for e in &compressed {
        writeln!(out, "{}", e).unwrap();
    }
    writeln!(out).unwrap();
}

/// Merge edges that differ only in PID into single lines.
///
/// Fork edges from the same parent to same comm:
///   "python3:99 -> curl:100 (fork)" + "python3:99 -> curl:101 (fork)"
///   → "python3:99 -> curl:100, curl:101 (fork)"
///
/// Identical reads across PIDs of the same comm:
///   "curl:100 reads /etc/passwd" + "curl:101 reads /etc/passwd"
///   → "curl:100, curl:101 reads /etc/passwd"
///
/// All PIDs preserved. No data lost.
fn compress_fork_edges(edges: &[String]) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let mut i = 0;

    while i < edges.len() {
        let trimmed = edges[i].trim();

        // Try to merge consecutive fork/pipe edges from same parent to same comm
        if let Some((left, right)) = trimmed.split_once(" -> ") {
            if let Some((target_name, edge_type)) = right.rsplit_once(' ') {
                let target_comm = strip_pid(target_name);
                let mut targets = vec![target_name.to_string()];
                // Collect consecutive edges with same source and same target comm
                let mut j = i + 1;
                while j < edges.len() {
                    let next = edges[j].trim();
                    if let Some((nl, nr)) = next.split_once(" -> ") {
                        if let Some((nt_name, nt_type)) = nr.rsplit_once(' ') {
                            if nl == left && nt_type == edge_type && strip_pid(nt_name) == target_comm {
                                targets.push(nt_name.to_string());
                                j += 1;
                                continue;
                            }
                        }
                    }
                    break;
                }
                if targets.len() > 1 {
                    result.push(format!("  {} -> {} {}", left, targets.join(", "), edge_type));
                    i = j;
                    continue;
                }
            }
        }

        // Try to merge consecutive identical-detail edges (same verb+detail, different PIDs)
        // e.g., "curl:100 reads X" + "curl:101 reads X" → "curl:100, curl:101 reads X"
        if let Some(verb_pos) = find_verb(trimmed) {
            let subject = &trimmed[..verb_pos];
            let verb_and_rest = &trimmed[verb_pos..];
            let subject_comm = strip_pid(subject.trim());

            let mut subjects = vec![subject.trim().to_string()];
            let mut j = i + 1;
            while j < edges.len() {
                let next = edges[j].trim();
                if let Some(nv) = find_verb(next) {
                    let ns = next[..nv].trim();
                    let nvr = &next[nv..];
                    if nvr == verb_and_rest && strip_pid(ns) == subject_comm {
                        subjects.push(ns.to_string());
                        j += 1;
                        continue;
                    }
                }
                break;
            }
            if subjects.len() > 1 {
                result.push(format!("  {} {}", subjects.join(", "), verb_and_rest));
                i = j;
                continue;
            }
        }

        // No merge — keep as-is
        result.push(edges[i].clone());
        i += 1;
    }

    result
}

/// Sort key: (verb_priority, detail, subject) so edges group by action type.
fn edge_sort_key(edge: &str) -> (u8, String, String) {
    let s = edge.trim();
    if s.contains(" -> ") {
        return (0, s.to_string(), String::new()); // fork/pipe first
    }
    for (priority, verb) in [(1, " reads "), (2, " writes "), (3, " connects "), (4, " listens ")] {
        if let Some(pos) = s.find(verb) {
            let subject = &s[..pos];
            let detail = &s[pos + verb.len()..];
            return (priority, detail.to_string(), subject.to_string());
        }
    }
    if s.contains("wrote") {
        return (5, s.to_string(), String::new()); // cross-action flows
    }
    if s.contains("pre-existing") {
        return (6, s.to_string(), String::new());
    }
    (9, s.to_string(), String::new())
}

/// Find the position of the verb ("reads ", "writes ", "connects ", "listens ") in an edge string.
fn find_verb(s: &str) -> Option<usize> {
    for verb in &[" reads ", " writes ", " connects ", " listens "] {
        if let Some(pos) = s.find(verb) {
            return Some(pos + 1); // +1 to skip the leading space
        }
    }
    None
}

/// Strip ":PID" suffix from a process name. "curl:12345" → "curl"
fn strip_pid(name: &str) -> &str {
    match name.rfind(':') {
        Some(i) if name[i+1..].chars().all(|c| c.is_ascii_digit()) => &name[..i],
        _ => name,
    }
}

// ── Experiment receipt (multi-container aggregation) ────────────────

/// Generate a unified receipt for an experiment spanning multiple containers.
/// Shows per-container summaries and cross-container data flows.
pub fn generate_experiment_receipt(state: &DaemonState, experiment: &Experiment) -> String {
    let mut out = String::with_capacity(RECEIPT_STRING_CAPACITY * 2);

    writeln!(out, "=== Experiment Receipt: {} ===", experiment.name).unwrap();
    writeln!(out, "Containers: {}", experiment.container_ids.len()).unwrap();
    writeln!(out).unwrap();

    // Per-container summaries
    for cid in &experiment.container_ids {
        let Some(container) = state.containers.get(cid) else { continue };
        let total_actions = container.completed_actions.len();
        let total_processes = container.process_table.processes.len();
        let total_events: u64 = container.completed_actions.iter()
            .map(|a| a.total_events())
            .sum();

        writeln!(out, "── Container {} ──", &cid[..cid.len().min(12)]).unwrap();
        writeln!(out, "  {} actions, {} processes, {} events",
            total_actions, total_processes, total_events).unwrap();

        // List actions with their commands
        for action in &container.completed_actions {
            if action.action_id == 0 { continue; } // skip lifecycle
            let events = action.total_events();
            if events > 0 {
                writeln!(out, "  Action #{}: {} ({} events)",
                    action.action_id, action.command, events).unwrap();
            }
        }
        writeln!(out).unwrap();
    }

    // Cross-container network flows
    let mut cross_flows: Vec<String> = Vec::new();
    for cid in &experiment.container_ids {
        let Some(container) = state.containers.get(cid) else { continue };
        let short = &cid[..cid.len().min(12)];
        for info in container.process_table.processes.values() {
            for conn in &info.net_connections {
                if let Some(addr) = conn.strip_prefix("connect ") {
                    // Check if target IP belongs to another container in this experiment
                    if let Some((ip_str, _port)) = addr.rsplit_once(':') {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            if let Some(target_cid) = state.ip_to_container.get(&ip) {
                                if target_cid != cid && experiment.container_ids.contains(target_cid) {
                                    let target_short = &target_cid[..target_cid.len().min(12)];
                                    let name = format!("{}:{}",
                                        util::decode_comm(&info.comm), info.pid);
                                    let flow = format!("  {} [{}] -> {} [{}]",
                                        name, short, addr, target_short);
                                    if !cross_flows.contains(&flow) {
                                        cross_flows.push(flow);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !cross_flows.is_empty() {
        writeln!(out, "CROSS-CONTAINER FLOWS:").unwrap();
        for flow in &cross_flows {
            writeln!(out, "{}", flow).unwrap();
        }
        writeln!(out).unwrap();
    }

    // Per-container data flows (abbreviated)
    for cid in &experiment.container_ids {
        let Some(container) = state.containers.get(cid) else { continue };
        let short = &cid[..cid.len().min(12)];

        // Collect all actions' process events to build the PID set
        let mut all_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for action in &container.completed_actions {
            for pe in &action.process_events {
                all_pids.insert(pe.pid);
            }
        }
        if let Some(ref action) = container.current_action {
            for pe in &action.process_events {
                all_pids.insert(pe.pid);
            }
        }

        // Network connections
        let mut net_edges: Vec<String> = Vec::new();
        for pid in &all_pids {
            let Some(info) = container.process_table.get(pid) else { continue };
            if info.net_connections.is_empty() { continue; }
            let name = format!("{}:{}", util::decode_comm(&info.comm), pid);
            for conn in &info.net_connections {
                if let Some(addr) = conn.strip_prefix("connect ") {
                    let annotated = annotate_addr(addr, &state.ip_to_container);
                    net_edges.push(format!("  {} [{}] connects {}", name, short, annotated));
                }
            }
        }
        if !net_edges.is_empty() {
            writeln!(out, "NETWORK [{}]:", short).unwrap();
            for edge in &net_edges {
                writeln!(out, "{}", edge).unwrap();
            }
            writeln!(out).unwrap();
        }
    }

    out
}

/// Generate a receipt for a specific action across all containers in an experiment.
/// Merges activity from the same action_id across all experiment containers.
pub fn generate_experiment_action_receipt(
    state: &DaemonState,
    experiment: &Experiment,
    action_id: u64,
) -> String {
    let mut out = String::with_capacity(RECEIPT_STRING_CAPACITY * 2);

    writeln!(out, "=== Experiment Action Receipt: {} — Action #{} ===",
        experiment.name, action_id).unwrap();
    writeln!(out).unwrap();

    let mut any_data = false;

    for cid in &experiment.container_ids {
        let Some(container) = state.containers.get(cid) else { continue };
        let short = &cid[..cid.len().min(12)];

        // Find this action in completed or current
        let action = container.completed_actions.iter()
            .find(|a| a.action_id == action_id)
            .or(container.current_action.as_ref()
                .filter(|a| a.action_id == action_id));

        let Some(action) = action else { continue };
        if action.total_events() == 0 && action.process_events.is_empty() {
            continue;
        }
        any_data = true;

        writeln!(out, "── Container {} ──", short).unwrap();
        writeln!(out, "Command: {}", action.command).unwrap();
        writeln!(out, "{} syscall events", action.total_events()).unwrap();
        writeln!(out).unwrap();

        // Process summary
        let action_pids: std::collections::HashSet<u32> =
            action.process_events.iter().map(|e| e.pid).collect();

        if !action_pids.is_empty() {
            writeln!(out, "PROCESSES:").unwrap();
            for pid in &action_pids {
                let Some(info) = container.process_table.get(pid) else { continue };
                writeln!(out, "  [{}:{}] $ {}", info.comm, pid, info.cmdline).unwrap();
            }
            writeln!(out).unwrap();
        }

        // Network connections with cross-container annotation
        let mut net_lines: Vec<String> = Vec::new();
        for pid in &action_pids {
            let Some(info) = container.process_table.get(pid) else { continue };
            for conn in &info.net_connections {
                if let Some(addr) = conn.strip_prefix("connect ") {
                    let annotated = annotate_addr(addr, &state.ip_to_container);
                    let name = format!("{}:{}", info.comm, pid);
                    net_lines.push(format!("  {} connects {}", name, annotated));
                }
            }
        }
        if !net_lines.is_empty() {
            writeln!(out, "NETWORK:").unwrap();
            for line in &net_lines {
                writeln!(out, "{}", line).unwrap();
            }
            writeln!(out).unwrap();
        }

        // Data flows (use the per-container receipt generator for this action)
        write_graph_diff(&mut out, container, action_id, &action_pids, &state.ip_to_container);
    }

    if !any_data {
        writeln!(out, "No activity for action #{} across experiment containers.", action_id).unwrap();
    }

    out
}

/// Semantic summary: high-level operations with MITRE ATT&CK mappings.
fn write_semantic_summary(out: &mut String, container: &ContainerState, action_id: u64) {
    let all_ops = semantic::detect_operations(container);
    let ops: Vec<_> = all_ops.into_iter().filter(|op| op.action_id == action_id).collect();
    let formatted = semantic::format_for_receipt(&ops);
    if !formatted.is_empty() {
        out.push_str(&formatted);
    }
}

