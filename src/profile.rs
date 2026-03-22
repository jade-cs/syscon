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
];

#[derive(Serialize)]
struct SeccompProfile {
    #[serde(rename = "defaultAction")]
    default_action: String,
    #[serde(rename = "archMap")]
    arch_map: Vec<ArchMap>,
    syscalls: Vec<SyscallGroup>,
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
///   - LOG: monitored syscalls that generate audit events
///   - ALLOW: everything else (defaultAction)
pub fn generate_profile(
    base: Option<&str>,
    log_syscalls: Option<&[String]>,
    block_dangerous: bool,
) -> Result<String> {
    if let Some(base_path) = base {
        return patch_existing_profile(base_path, log_syscalls, block_dangerous);
    }

    let log_names: Vec<String> = match log_syscalls {
        Some(names) => names.to_vec(),
        None => LOG_SYSCALLS.iter().map(|s| s.to_string()).collect(),
    };

    let mut groups = vec![SyscallGroup {
        names: {
            let mut n = log_names;
            n.sort();
            n
        },
        action: "SCMP_ACT_LOG".to_string(),
        errno_ret: None,
        comment: Some(
            "syscon: monitored syscalls — allowed but generate AUDIT_SECCOMP events"
                .to_string(),
        ),
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
            if group.get("action").and_then(|a| a.as_str()) == Some("SCMP_ACT_ALLOW") {
                if let Some(names) = group.get_mut("names").and_then(|v| v.as_array_mut()) {
                    names.retain(|n| {
                        n.as_str().map_or(true, |s| !all_target.contains(s))
                    });
                }
            }
        }
        // Remove empty groups
        syscalls.retain(|g| {
            g.get("names")
                .and_then(|v| v.as_array())
                .map_or(true, |a| !a.is_empty())
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
        let json = generate_profile(None, None, false).unwrap();
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
        let json = generate_profile(None, None, true).unwrap();
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
        let json = generate_profile(None, Some(&custom), false).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let log_names = v["syscalls"][0]["names"].as_array().unwrap();
        assert_eq!(log_names.len(), 2);
    }
}
