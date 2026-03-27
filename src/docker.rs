
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

