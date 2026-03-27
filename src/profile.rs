use anyhow::Result;
use serde::Serialize;

/// Syscalls that should be blocked with ERRNO(EPERM).
const ERRNO_SYSCALLS: &[&str] = &[
    "ptrace",
    "init_module",
    "finit_module",
    "kexec_load",
    "kexec_file_load",
    "process_vm_readv",
    "process_vm_writev",
];

/// Syscalls that should generate AUDIT_SECCOMP via SCMP_ACT_LOG.
/// These are the syscalls we monitor for the taint graph and receipts.
const LOG_SYSCALLS: &[&str] = &[
    // Process lifecycle
    "clone",
    "clone3",
    "fork",
    "vfork",
    "execve",
    "execveat",
    "exit_group",
    // Network
    "socket",
    "connect",
    "bind",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    // Filesystem
    "open",
    "openat",
    "openat2",
    // Note: read/write/close excluded — too high-frequency, and in LOG mode
    // we can't see the fd or data anyway. Add back for USER_NOTIF mode.
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "fchownat",
    // IPC
    "pipe",
    "pipe2",
    "dup",
    "dup2",
    "dup3",
    "kill",
    "tgkill",
    // Shared memory
    "shmget",
    "shmat",
    "shmdt",
    // Anonymous memory (fileless execution vector)
    "memfd_create",
    // Process debugging (injection vector — also in ERRNO list but tracked if allowed)
    "ptrace",
    // Hidden data flows — kernel-space transfers that bypass userspace monitoring
    "sendfile",      // file→socket without touching userspace
    "splice",        // fd→fd zero-copy (pipe↔socket, pipe↔file)
    "tee",           // duplicate pipe data without consuming it
    "copy_file_range", // file→file in kernel space
];

/// Syscalls to intercept with SCMP_ACT_NOTIFY (USER_NOTIF mode).
/// This is a superset of LOG_SYSCALLS — we can capture arguments for all of these.
const NOTIFY_SYSCALLS: &[&str] = &[
    // Process lifecycle
    "clone",
    "clone3",
    "fork",
    "vfork",
    "execve",
    "execveat",
    "exit_group",
    // Network
    "socket",
    "connect",
    "bind",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    // Filesystem — full set including read/write (we can see fd now)
    "open",
    "openat",
    "openat2",
    "creat",
    // Note: close excluded from NOTIFY — extremely high-frequency and only yields fd number.
    // read/write also excluded — they would block every I/O operation.
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "fchownat",
    // IPC
    "pipe",
    "pipe2",
    "dup",
    "dup2",
    "dup3",
    "kill",
    "tgkill",
    // Shared memory
    "shmget",
    "shmat",
    "shmdt",
    // Anonymous memory
    "memfd_create",
    // Process debugging
    "ptrace",
    // Hidden data flows
    "sendfile",
    "splice",
    "tee",
    "copy_file_range",
];

#[derive(Serialize)]
struct SeccompProfile {
    #[serde(rename = "defaultAction")]
    default_action: String,
    #[serde(rename = "archMap")]
    arch_map: Vec<ArchMap>,
    syscalls: Vec<SyscallGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "listenerPath")]
    listener_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "listenerMetadata")]
    listener_metadata: Option<String>,
}

#[derive(Serialize)]
struct ArchMap {
    architecture: String,
    #[serde(rename = "subArchitectures")]
    sub_architectures: Vec<String>,
}

#[derive(Serialize)]
struct SyscallGroup {
    names: Vec<String>,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "errnoRet")]
    errno_ret: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

/// Generate a Docker-compatible seccomp profile JSON string.
///
/// If `base` is Some, reads and patches an existing profile.
/// Otherwise, generates a fresh profile with three tiers:
///   - ERRNO: dangerous syscalls blocked
///   - LOG or NOTIFY: monitored syscalls
///   - ALLOW: everything else (defaultAction)
///
/// If `notify_socket` is Some, generates a USER_NOTIF profile that sends
/// intercepted syscalls to the specified Unix socket path. This enables
/// the daemon to read syscall arguments.
pub fn generate_profile(
    base: Option<&str>,
    log_syscalls: Option<&[String]>,
    block_dangerous: bool,
    notify_socket: Option<&str>,
) -> Result<String> {
    if let Some(base_path) = base {
        return patch_existing_profile(base_path, log_syscalls, block_dangerous);
    }

    let use_notify = notify_socket.is_some();
    let (action, action_comment, syscall_set) = if use_notify {
        (
            "SCMP_ACT_NOTIFY",
            "syscon: intercepted syscalls — blocked until daemon responds (USER_NOTIF)",
            NOTIFY_SYSCALLS,
        )
    } else {
        (
            "SCMP_ACT_LOG",
            "syscon: monitored syscalls — allowed but generate AUDIT_SECCOMP events",
            LOG_SYSCALLS,
        )
    };

    let log_names: Vec<String> = match log_syscalls {
        Some(names) => names.to_vec(),
        None => syscall_set.iter().map(|s| s.to_string()).collect(),
    };

    let mut groups = vec![SyscallGroup {
        names: {
            let mut n = log_names;
            n.sort();
            n
        },
        action: action.to_string(),
        errno_ret: None,
        comment: Some(action_comment.to_string()),
    }];

    if block_dangerous {
        groups.push(SyscallGroup {
            names: ERRNO_SYSCALLS.iter().map(|s| s.to_string()).collect(),
            action: "SCMP_ACT_ERRNO".to_string(),
            errno_ret: Some(1),
            comment: Some("syscon: dangerous syscalls — denied".to_string()),
        });
    }

    let profile = SeccompProfile {
        default_action: "SCMP_ACT_ALLOW".to_string(),
        arch_map: vec![
            ArchMap {
                architecture: "SCMP_ARCH_X86_64".to_string(),
                sub_architectures: vec![
                    "SCMP_ARCH_X86".to_string(),
                    "SCMP_ARCH_X32".to_string(),
                ],
            },
            ArchMap {
                architecture: "SCMP_ARCH_AARCH64".to_string(),
                sub_architectures: vec![],
            },
        ],
        syscalls: groups,
        listener_path: notify_socket.map(|s| s.to_string()),
        listener_metadata: if use_notify {
            Some("syscon".to_string())
        } else {
            None
        },
    };

    let json = serde_json::to_string_pretty(&profile)?;
    Ok(json)
}

/// Patch an existing Docker seccomp profile: move target syscalls to LOG,
/// add ERRNO group for dangerous syscalls.
fn patch_existing_profile(
    base_path: &str,
    log_syscalls: Option<&[String]>,
    block_dangerous: bool,
) -> Result<String> {
    let base_json = std::fs::read_to_string(base_path)
        .map_err(|e| anyhow::anyhow!("Failed to read base profile {}: {}", base_path, e))?;

    let mut profile: serde_json::Value = serde_json::from_str(&base_json)?;

    let log_names: Vec<&str> = match log_syscalls {
        Some(names) => names.iter().map(|s| s.as_str()).collect(),
        None => LOG_SYSCALLS.to_vec(),
    };

    let mut all_target: std::collections::HashSet<&str> =
        log_names.iter().copied().collect();
    if block_dangerous {
        all_target.extend(ERRNO_SYSCALLS.iter());
    }

    // Remove target syscalls from existing ALLOW groups
    if let Some(syscalls) = profile.get_mut("syscalls").and_then(|v| v.as_array_mut()) {
        for group in syscalls.iter_mut() {
            if group.get("action").and_then(|a| a.as_str()) == Some("SCMP_ACT_ALLOW")
                && let Some(names) = group.get_mut("names").and_then(|v| v.as_array_mut()) {
                    names.retain(|n| {
                        n.as_str().is_none_or(|s| !all_target.contains(s))
                    });
                }
        }
        // Remove empty groups
        syscalls.retain(|g| {
            g.get("names")
                .and_then(|v| v.as_array())
                .is_none_or(|a| !a.is_empty())
        });

        // Insert LOG group at front
        let mut sorted_log: Vec<&str> = log_names;
        sorted_log.sort();
        let log_group = serde_json::json!({
            "names": sorted_log,
            "action": "SCMP_ACT_LOG",
            "comment": "syscon: monitored syscalls — allowed but generate AUDIT_SECCOMP events"
        });
        syscalls.insert(0, log_group);

        // Insert ERRNO group if requested
        if block_dangerous {
            let errno_group = serde_json::json!({
                "names": ERRNO_SYSCALLS,
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 1,
                "comment": "syscon: dangerous syscalls — denied"
            });
            syscalls.insert(1, errno_group);
        }
    }

    Ok(serde_json::to_string_pretty(&profile)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_profile_default_no_block() {
        let json = generate_profile(None, None, false, None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["defaultAction"], "SCMP_ACT_ALLOW");

        let syscalls = v["syscalls"].as_array().unwrap();
        assert_eq!(syscalls.len(), 1); // LOG only, no ERRNO
        assert_eq!(syscalls[0]["action"], "SCMP_ACT_LOG");

        let log_names = syscalls[0]["names"].as_array().unwrap();
        let names: Vec<&str> = log_names.iter().map(|n| n.as_str().unwrap()).collect();
        assert!(names.contains(&"execve"));
        assert!(names.contains(&"connect"));
        assert!(names.contains(&"openat"));
    }

    #[test]
    fn test_generate_profile_with_block() {
        let json = generate_profile(None, None, true, None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let syscalls = v["syscalls"].as_array().unwrap();
        assert_eq!(syscalls.len(), 2);
        assert_eq!(syscalls[0]["action"], "SCMP_ACT_LOG");
        assert_eq!(syscalls[1]["action"], "SCMP_ACT_ERRNO");

        let errno_names = syscalls[1]["names"].as_array().unwrap();
        let enames: Vec<&str> = errno_names.iter().map(|n| n.as_str().unwrap()).collect();
        assert!(enames.contains(&"ptrace"));
        assert!(enames.contains(&"init_module"));
    }

    #[test]
    fn test_generate_profile_custom_syscalls() {
        let custom = vec!["read".to_string(), "write".to_string()];
        let json = generate_profile(None, Some(&custom), false, None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let log_names = v["syscalls"][0]["names"].as_array().unwrap();
        assert_eq!(log_names.len(), 2);
    }
}
