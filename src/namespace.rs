use std::collections::{HashMap, HashSet};

use crate::state::ContainerBaseline;

/// Scan the host filesystem to build a ContainerBaseline for a given
/// container ID. Uses /proc to find container processes and accesses
/// the container's root filesystem via /proc/{pid}/root/.
#[allow(dead_code)]
pub fn scan_baseline_for_container(container_id: &str) -> ContainerBaseline {
    let mut baseline = ContainerBaseline::new();

    // Find a PID inside this container to access its root filesystem
    let container_pid = find_container_pid(container_id);

    if let Some(pid) = container_pid {
        // Scan original processes
        baseline.original_processes = scan_container_processes(container_id);

        // Scan original binaries via /proc/{pid}/root
        baseline.original_binaries = scan_container_binaries(pid);
    }

    baseline
}

/// Find any PID that belongs to the given container.
fn find_container_pid(container_id: &str) -> Option<u32> {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return None,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if pid_in_container(pid, container_id) {
            return Some(pid);
        }
    }
    None
}

/// Check if a PID belongs to the given container by reading its cgroup.
fn pid_in_container(pid: u32, container_id: &str) -> bool {
    let cgroup = match std::fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
        Ok(c) => c,
        Err(_) => return false,
    };
    cgroup.contains(container_id)
}

/// Scan /proc for all processes belonging to a container.
fn scan_container_processes(container_id: &str) -> HashMap<u32, String> {
    let mut procs = HashMap::new();
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return procs,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if pid_in_container(pid, container_id) {
            let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            procs.insert(pid, exe);
        }
    }
    procs
}

/// Scan a container's root filesystem for executable binaries.
/// Uses /proc/{pid}/root/ to access the container's mount namespace.
fn scan_container_binaries(pid: u32) -> HashSet<String> {
    let mut binaries = HashSet::new();
    let root = format!("/proc/{}/root", pid);

    // Scan common binary directories
    let bin_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"];

    for dir in &bin_dirs {
        let full_path = format!("{}{}", root, dir);
        if let Ok(entries) = std::fs::read_dir(&full_path) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    // Check if executable (any execute bit set)
                    use std::os::unix::fs::PermissionsExt;
                    if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                        let container_path = format!(
                            "{}/{}",
                            dir,
                            entry.file_name().to_string_lossy()
                        );
                        binaries.insert(container_path);
                    }
                }
            }
        }
    }

    binaries
}

/// Scan a container's filesystem for recently modified files.
/// Returns paths relative to the container root.
#[allow(dead_code)]
pub fn scan_new_files(container_id: &str) -> Vec<String> {
    let pid = match find_container_pid(container_id) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let root = format!("/proc/{}/root", pid);
    let mut files = Vec::new();

    // Scan writable locations for any files
    let scan_dirs = [
        "/tmp",
        "/var/tmp",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/lib",
        "/root",
        "/home",
    ];

    for dir in &scan_dirs {
        let full_path = format!("{}{}", root, dir);
        scan_dir_recursive(&full_path, dir, &mut files, 2); // max depth 2
    }

    files
}

fn scan_dir_recursive(host_path: &str, container_path: &str, files: &mut Vec<String>, depth: u32) {
    if depth == 0 {
        return;
    }
    let entries = match std::fs::read_dir(host_path) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let cpath = format!("{}/{}", container_path, name);
        if let Ok(ft) = entry.file_type() {
            if ft.is_file() {
                files.push(cpath);
            } else if ft.is_dir() {
                let hpath = format!("{}/{}", host_path, name);
                scan_dir_recursive(&hpath, &cpath, files, depth - 1);
            }
        }
    }
}
