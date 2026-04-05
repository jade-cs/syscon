
// ── container ID lookup ─────────────────────────────────────────────

/// Information about a container derived from /proc/{pid}/cgroup.
pub struct ContainerInfo {
    /// Short (12-char) hex container ID
    pub id: String,
}

/// Look up the Docker container ID for a given PID by reading
/// /proc/{pid}/cgroup. Returns None if the PID is not in a container.
///
/// On cgroup v2 (this system), the cgroup path looks like:
///   0::/system.slice/docker-<64-char-hex-id>.scope
///
/// On cgroup v1, it looks like:
///   N:controller:/docker/<64-char-hex-id>
///
/// We also handle containerd's pattern:
///   0::/system.slice/cri-containerd-<64-char-hex-id>.scope
pub fn container_from_pid(pid: u32) -> Option<ContainerInfo> {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;

    // Skip BuildKit build containers — they generate massive noise
    // from compilation and are not agent-controlled environments.
    let cgroup_lower = cgroup.to_ascii_lowercase();
    if cgroup_lower.contains("buildkit") || cgroup_lower.contains("buildx") {
        return None;
    }

    for line in cgroup.lines() {
        if let Some(id) = extract_container_id(line) {
            return Some(ContainerInfo { id });
        }
    }
    None
}

/// Scan all running Docker containers and return a map of PID → container_id.
/// Reads from /sys/fs/cgroup to find all PIDs in each container's cgroup.
/// This is used as a fallback when /proc/pid/cgroup is unavailable (dead process).
pub fn scan_container_pids() -> std::collections::HashMap<u32, String> {
    let mut pid_map = std::collections::HashMap::new();

    // cgroup v2 with systemd: /sys/fs/cgroup/system.slice/docker-<id>.scope/cgroup.procs
    // cgroup v2 without systemd: /sys/fs/cgroup/docker/<id>/cgroup.procs
    for base in &["/sys/fs/cgroup/system.slice", "/sys/fs/cgroup/docker"] {
        let Ok(entries) = std::fs::read_dir(base) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();

            // Extract container ID from directory name
            let cid = if let Some(rest) = name.strip_prefix("docker-") {
                rest.strip_suffix(".scope").map(|s| &s[..s.len().min(12)])
            } else if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(&name[..12])
            } else {
                None
            };

            let Some(cid) = cid else { continue };
            let procs_path = entry.path().join("cgroup.procs");
            let Ok(content) = std::fs::read_to_string(&procs_path) else { continue };

            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    pid_map.insert(pid, cid.to_string());
                }
            }
        }
    }

    pid_map
}

/// Read the container's IP addresses from /proc/{pid}/net/fib_trie.
/// All processes in a container share the same network namespace, so any
/// PID in the container gives the same result. Returns non-loopback IPs
/// marked as `/32 host LOCAL` in the routing table.
///
/// Only needs to be called once per container — results should be cached.
pub fn container_ips_from_pid(pid: u32) -> Vec<std::net::Ipv4Addr> {
    let path = format!("/proc/{pid}/net/fib_trie");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut ips = Vec::new();
    let mut last_ip: Option<std::net::Ipv4Addr> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        // Lines like "|-- 172.17.0.2" contain the IP
        if let Some(ip_str) = trimmed.strip_prefix("|-- ") {
            last_ip = ip_str.parse().ok();
        } else if trimmed.contains("host LOCAL") {
            // The previous line's IP is a local address on this interface
            if let Some(ip) = last_ip.take() {
                if !ip.is_loopback() && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        } else {
            last_ip = None;
        }
    }
    ips
}

fn extract_container_id(line: &str) -> Option<String> {
    // cgroup v2 with systemd driver: "0::/system.slice/docker-<id>.scope"
    if let Some(pos) = line.find("docker-") {
        let rest = &line[pos + 7..];
        if let Some(end) = rest.find('.') {
            let candidate = &rest[..end];
            if candidate.len() >= 12 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(candidate[..12].to_string());
            }
        }
    }

    // cgroupfs driver: "/docker/<id>" or "/docker/<id>/..."
    if let Some(pos) = line.find("/docker/") {
        let rest = &line[pos + 8..];
        // Take up to the next '/' or end of string
        let end = rest.find('/').unwrap_or(rest.len());
        let candidate = &rest[..end];
        if candidate.len() >= 12 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(candidate[..12].to_string());
        }
    }

    // containerd/CRI: "cri-containerd-<id>.scope"
    if let Some(pos) = line.find("cri-containerd-") {
        let rest = &line[pos + 15..];
        if let Some(end) = rest.find('.') {
            let candidate = &rest[..end];
            if candidate.len() >= 12 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(candidate[..12].to_string());
            }
        }
    }

    None
}

