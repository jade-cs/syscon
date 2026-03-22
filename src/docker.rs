use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

use crate::{audit, syscalls};

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

// ── docker monitor ──────────────────────────────────────────────────

/// Monitor AUDIT_SECCOMP events, enriching them with Docker container info.
/// Only shows events from processes inside Docker containers.
pub fn docker_monitor(stop: &AtomicBool) -> Result<()> {
    let fd = audit::open_audit_socket()?;
    audit::set_recv_timeout(fd, 200);

    tracing::info!("Monitoring Docker container syscalls via AUDIT_SECCOMP...");
    tracing::info!("Containers must use the syscon seccomp profile (syscon docker gen-profile).");
    tracing::info!("Press Ctrl+C to stop.");

    let mut counts: HashMap<(String, u32), u64> = HashMap::new();
    // Cache container ID lookups to avoid hitting /proc on every event
    let mut pid_cache: HashMap<u32, Option<String>> = HashMap::new();

    while !stop.load(Ordering::Relaxed) {
        match audit::try_recv_event(fd) {
            Ok(Some(event)) => {
                // Look up container ID (with cache)
                let container_id = pid_cache
                    .entry(event.pid)
                    .or_insert_with(|| {
                        container_from_pid(event.pid).map(|c| c.id)
                    })
                    .clone();

                let Some(cid) = container_id else {
                    // Not a Docker container process — skip
                    continue;
                };

                let nr = event.syscall;
                *counts.entry((cid.clone(), nr)).or_insert(0) += 1;

                let name = syscalls::name(nr);
                let action = syscalls::action_name(event.code);
                println!(
                    "[{cid}] [pid:{pid}] {comm} {name}({nr}) action={action}",
                    pid = event.pid,
                    comm = event.comm,
                );
            }
            Ok(None) => continue,
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                return Err(e);
            }
        }
    }

    // Print per-container summary
    if !counts.is_empty() {
        // Group by container
        let mut by_container: HashMap<&str, HashMap<u32, u64>> = HashMap::new();
        for ((cid, nr), count) in &counts {
            *by_container
                .entry(cid.as_str())
                .or_default()
                .entry(*nr)
                .or_insert(0) += count;
        }

        for (cid, syscall_counts) in &by_container {
            tracing::info!(container = %cid, "--- Container summary ---");
            audit::print_summary(syscall_counts);
        }
    } else {
        tracing::info!("No container syscalls captured.");
    }

    // SAFETY: close(2) on the audit socket fd we opened.
    unsafe { libc::close(fd) };
    Ok(())
}
