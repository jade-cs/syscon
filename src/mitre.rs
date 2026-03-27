//! MITRE ATT&CK rule database for syscall-to-technique mapping.
//!
//! Rules are compiled from two sources:
//! - bfuzzy/auditd-attack (MIT) — syscall/file-watch → technique mappings
//! - falcosecurity/rules (Apache-2.0) — container-aware syscall rules
//!
//! Old technique IDs from auditd-attack have been updated to current ATT&CK v14.
//! Rules are deduplicated where both sources cover the same behavior.

/// A detection rule mapping system behavior to a MITRE ATT&CK technique.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Rule {
    /// Human-readable rule name.
    pub name: &'static str,
    /// Syscalls that trigger this rule (empty = file/process pattern only).
    pub syscalls: &'static [&'static str],
    /// File path patterns to match (glob-style with * prefix/suffix).
    /// Empty = no file constraint.
    pub file_patterns: &'static [&'static str],
    /// Process name patterns to match (exe basename).
    /// Empty = any process.
    pub process_patterns: &'static [&'static str],
    /// Processes to exclude (allowlist).
    pub process_exclude: &'static [&'static str],
    /// ATT&CK technique ID (e.g., "T1055.008").
    pub technique_id: &'static str,
    /// ATT&CK technique name.
    pub technique_name: &'static str,
    /// ATT&CK tactic.
    pub tactic: &'static str,
    /// Severity: 0=info, 1=low, 2=medium, 3=high.
    pub severity: u8,
    /// Source attribution.
    pub source: RuleSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    AuditdAttack,
    Falco,
    Custom,
}

/// Evaluate rules against observed process behavior.
/// Returns all matching rules.
pub fn evaluate(
    syscall_name: &str,
    process_exe: &str,
    process_comm: &str,
    file_paths: &[String],
    net_connections: &[String],
) -> Vec<&'static Rule> {
    let proc_basename = process_exe.rsplit('/').next().unwrap_or(process_exe);
    let comm = process_comm;

    RULES
        .iter()
        .filter(|rule| {
            // Check syscall match (empty = match any)
            let syscall_match = rule.syscalls.is_empty()
                || rule.syscalls.contains(&syscall_name);

            if !syscall_match {
                return false;
            }

            // Check process exclude (allowlist) + always exclude container runtime noise
            let is_runtime = proc_basename == "runc"
                || proc_basename == "containerd-shim"
                || comm == "runc"
                || comm.starts_with("runc:");
            if is_runtime {
                return false;
            }
            if !rule.process_exclude.is_empty()
                && rule.process_exclude.iter().any(|p| {
                    *p == proc_basename || *p == comm
                })
            {
                return false;
            }

            // Check process pattern match (empty = any process)
            // Match against exe basename and comm field only — no substring matching
            // to avoid false positives like "runc" matching the "nc" pattern.
            let process_match = rule.process_patterns.is_empty()
                || rule.process_patterns.iter().any(|p| {
                    *p == proc_basename || *p == comm
                });

            if !process_match {
                return false;
            }

            // Check file pattern match (empty = no file constraint)
            if !rule.file_patterns.is_empty() {
                let file_match = file_paths.iter().any(|fp| {
                    rule.file_patterns.iter().any(|pat| path_matches(fp, pat))
                });
                if !file_match {
                    // Also check net connections for network rules
                    if !net_connections.is_empty() && rule.file_patterns.iter().any(|p| p.starts_with("net:")) {
                        // Network pattern
                    } else {
                        return false;
                    }
                }
            }

            true
        })
        .collect()
}

/// Simple glob matching: supports * at start/end of pattern.
fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return path.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern || path.starts_with(pattern)
}

// ── Rule database ───────────────────────────────────────────────────
//
// Combined from auditd-attack (MIT) and falcosecurity/rules (Apache-2.0).
// Old auditd-attack IDs updated to ATT&CK v14.
// Deduplicated: where both sources cover the same behavior, kept the
// more specific rule (usually Falco).

pub static RULES: &[Rule] = &[
    // ── Execution ───────────────────────────────────────────────
    // Note: shell spawned, interpreter executed, package manager, sudo,
    // and basic discovery (whoami, uname, ps) rules omitted — in our
    // agent-in-container threat model these fire on every session. The
    // taint graph already captures the causal chain; MITRE tags should
    // only flag behaviors that go beyond normal programming/sysadmin work.

    // ── Persistence ─────────────────────────────────────────────
    Rule {
        name: "Cron job modification",
        syscalls: &["openat", "open", "rename", "renameat"],
        file_patterns: &["/etc/cron*", "/var/spool/cron*", "*/crontab"],
        process_patterns: &[],
        process_exclude: &["cron", "crond", "anacron"],
        technique_id: "T1053.003",
        technique_name: "Cron",
        tactic: "persistence",
        severity: 3,
        source: RuleSource::Falco,
    },
    Rule {
        name: "Shell config modification",
        syscalls: &["openat", "open"],
        file_patterns: &[
            "*/.bashrc", "*/.bash_profile", "*/.profile",
            "*/.zshrc", "*/.cshrc", "/etc/profile*",
            "/etc/bash.bashrc", "/etc/zsh*",
        ],
        process_patterns: &[],
        process_exclude: &[],
        technique_id: "T1546.004",
        technique_name: "Unix Shell Configuration Modification",
        tactic: "persistence",
        severity: 2,
        source: RuleSource::Falco,
    },
    Rule {
        name: "Systemd service modification",
        syscalls: &["openat", "open"],
        file_patterns: &["/etc/systemd/*", "/lib/systemd/*", "/usr/lib/systemd/*"],
        process_patterns: &[],
        process_exclude: &["systemd", "systemctl"],
        technique_id: "T1543",
        technique_name: "Create or Modify System Process",
        tactic: "persistence",
        severity: 3,
        source: RuleSource::Falco,
    },
    Rule {
        name: "SSH authorized_keys modification",
        syscalls: &["openat", "open"],
        file_patterns: &["*/.ssh/authorized_keys*"],
        process_patterns: &[],
        process_exclude: &["sshd"],
        technique_id: "T1098.004",
        technique_name: "SSH Authorized Keys",
        tactic: "persistence",
        severity: 3,
        source: RuleSource::Falco,
    },

    // ── Privilege Escalation ────────────────────────────────────
    Rule {
        name: "Setuid/setgid call",
        syscalls: &["setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid"],
        file_patterns: &[],
        process_patterns: &[],
        process_exclude: &["sudo", "su", "login", "sshd", "passwd", "chsh", "newgrp"],
        technique_id: "T1548.001",
        technique_name: "Setuid and Setgid",
        tactic: "privilege_escalation",
        severity: 2,
        source: RuleSource::AuditdAttack,
    },
    Rule {
        name: "Kernel module load",
        syscalls: &["init_module", "finit_module"],
        file_patterns: &[],
        process_patterns: &[],
        process_exclude: &[],
        technique_id: "T1547.006",
        technique_name: "Kernel Modules and Extensions",
        tactic: "privilege_escalation",
        severity: 3,
        source: RuleSource::AuditdAttack,
    },
    Rule {
        name: "Container escape attempt",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["nsenter", "unshare"],
        process_exclude: &[],
        technique_id: "T1611",
        technique_name: "Escape to Host",
        tactic: "privilege_escalation",
        severity: 3,
        source: RuleSource::Falco,
    },

    // ── Defense Evasion ─────────────────────────────────────────
    Rule {
        name: "Timestomping",
        syscalls: &["settimeofday", "clock_settime", "adjtimex"],
        file_patterns: &[],
        process_patterns: &[],
        process_exclude: &["chronyd", "ntpd", "systemd-timesyncd"],
        technique_id: "T1070.006",
        technique_name: "Timestomp",
        tactic: "defense_evasion",
        severity: 2,
        source: RuleSource::AuditdAttack,
    },
    Rule {
        name: "File deletion (evidence removal)",
        syscalls: &["unlink", "unlinkat", "rename", "renameat", "renameat2"],
        file_patterns: &["/var/log*", "*/.bash_history", "*/auth.log*", "*/syslog*"],
        process_patterns: &[],
        process_exclude: &["logrotate"],
        technique_id: "T1070",
        technique_name: "Indicator Removal",
        tactic: "defense_evasion",
        severity: 3,
        source: RuleSource::Falco,
    },
    Rule {
        name: "Hidden file/directory creation",
        syscalls: &["openat", "open", "mkdir", "mkdirat"],
        file_patterns: &["/tmp/.*", "/var/tmp/.*", "/dev/shm/.*"],
        process_patterns: &[],
        process_exclude: &[],
        technique_id: "T1564.001",
        technique_name: "Hidden Files and Directories",
        tactic: "defense_evasion",
        severity: 2,
        source: RuleSource::Falco,
    },
    Rule {
        name: "Chmod sensitive file",
        syscalls: &["chmod", "fchmod", "fchmodat"],
        file_patterns: &["/etc/*", "/usr/bin/*", "/usr/sbin/*"],
        process_patterns: &[],
        process_exclude: &["dpkg", "rpm", "apk", "apt"],
        technique_id: "T1222.002",
        technique_name: "Linux and Mac File and Directory Permissions Modification",
        tactic: "defense_evasion",
        severity: 2,
        source: RuleSource::AuditdAttack,
    },

    // ── Credential Access ───────────────────────────────────────
    Rule {
        name: "Credential file read",
        syscalls: &["openat", "open"],
        file_patterns: &[
            "/etc/shadow", "/etc/gshadow", "/etc/master.passwd",
            "*/.ssh/id_*", "*/.ssh/known_hosts",
            "*/.aws/credentials", "*/.docker/config.json",
            "*/.kube/config", "*/.netrc", "*/.pgpass",
        ],
        process_patterns: &[],
        process_exclude: &["sshd", "login", "passwd", "shadow", "chage"],
        technique_id: "T1552.001",
        technique_name: "Credentials In Files",
        tactic: "credential_access",
        severity: 3,
        source: RuleSource::Falco,
    },
    Rule {
        name: "Password store access",
        syscalls: &["openat", "open"],
        file_patterns: &[
            "*/passwords.xml", "*/.mozilla/*/logins.json",
            "*/.config/chromium/*/Login*", "*/key3.db", "*/key4.db",
        ],
        process_patterns: &[],
        process_exclude: &[],
        technique_id: "T1555",
        technique_name: "Credentials from Password Stores",
        tactic: "credential_access",
        severity: 3,
        source: RuleSource::Falco,
    },
    Rule {
        name: "Passwd/shadow modification",
        syscalls: &["openat", "open"],
        file_patterns: &["/etc/passwd", "/etc/shadow", "/etc/group"],
        process_patterns: &[],
        process_exclude: &["passwd", "useradd", "usermod", "groupadd", "groupmod", "adduser", "addgroup"],
        technique_id: "T1098",
        technique_name: "Account Manipulation",
        tactic: "persistence",
        severity: 3,
        source: RuleSource::AuditdAttack,
    },

    // ── Discovery ───────────────────────────────────────────────
    // System info (uname, hostname), account (whoami, id), and process
    // (ps, top) discovery omitted — routine for programming/sysadmin agents.
    Rule {
        name: "Network discovery",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &[
            "ifconfig", "ip", "netstat", "ss", "arp", "route",
            "nmap", "masscan", "ping", "traceroute",
        ],
        process_exclude: &[],
        technique_id: "T1046",
        technique_name: "Network Service Discovery",
        tactic: "discovery",
        severity: 1,
        source: RuleSource::Falco,
    },
    // ── Collection ──────────────────────────────────────────────
    Rule {
        name: "Archive creation (staging data)",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["tar", "gzip", "zip", "bzip2", "xz", "7z", "rar"],
        process_exclude: &[],
        technique_id: "T1560",
        technique_name: "Archive Collected Data",
        tactic: "collection",
        severity: 1,
        source: RuleSource::Custom,
    },

    // ── Command and Control ─────────────────────────────────────
    Rule {
        name: "Outbound network connection",
        syscalls: &["connect"],
        file_patterns: &[],
        process_patterns: &[],
        process_exclude: &["apt", "apt-get", "apk", "yum", "dnf", "pip", "npm", "git"],
        technique_id: "T1071",
        technique_name: "Application Layer Protocol",
        tactic: "command_and_control",
        severity: 1,
        source: RuleSource::AuditdAttack,
    },
    Rule {
        name: "Curl/wget download",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["curl", "wget"],
        process_exclude: &[],
        technique_id: "T1105",
        technique_name: "Ingress Tool Transfer",
        tactic: "command_and_control",
        severity: 2,
        source: RuleSource::AuditdAttack,
    },
    Rule {
        name: "Netcat/socat (reverse shell tool)",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["nc", "ncat", "netcat", "socat"],
        process_exclude: &[],
        technique_id: "T1059.004",
        technique_name: "Unix Shell (reverse shell tool)",
        tactic: "command_and_control",
        severity: 3,
        source: RuleSource::Falco,
    },

    // ── Exfiltration ────────────────────────────────────────────
    Rule {
        name: "Data exfiltration tool",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["scp", "sftp", "rsync"],
        process_exclude: &[],
        technique_id: "T1048",
        technique_name: "Exfiltration Over Alternative Protocol",
        tactic: "exfiltration",
        severity: 2,
        source: RuleSource::Custom,
    },

    // ── Impact ──────────────────────────────────────────────────
    Rule {
        name: "Cryptominer detection",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["xmrig", "minerd", "minergate", "cpuminer", "ethminer"],
        process_exclude: &[],
        technique_id: "T1496",
        technique_name: "Resource Hijacking",
        tactic: "impact",
        severity: 3,
        source: RuleSource::Falco,
    },
    Rule {
        name: "Data destruction (bulk delete)",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["rm", "shred", "wipe"],
        process_exclude: &[],
        technique_id: "T1485",
        technique_name: "Data Destruction",
        tactic: "impact",
        severity: 2,
        source: RuleSource::Falco,
    },

    // ── Process Injection ───────────────────────────────────────
    Rule {
        name: "Ptrace process injection",
        syscalls: &["ptrace"],
        file_patterns: &[],
        process_patterns: &[],
        process_exclude: &["gdb", "strace", "ltrace", "lldb"],
        technique_id: "T1055.008",
        technique_name: "Ptrace System Calls",
        tactic: "defense_evasion",
        severity: 3,
        source: RuleSource::Falco,
    },
    Rule {
        name: "Debug tool execution",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["gdb", "strace", "ltrace", "lldb"],
        process_exclude: &[],
        technique_id: "T1055",
        technique_name: "Process Injection (debug tools)",
        tactic: "defense_evasion",
        severity: 2,
        source: RuleSource::Custom,
    },

    // ── Compile After Delivery ──────────────────────────────────
    Rule {
        name: "Source compilation",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["gcc", "g++", "cc", "c++", "clang", "clang++", "rustc", "javac", "go"],
        process_exclude: &[],
        technique_id: "T1027.004",
        technique_name: "Compile After Delivery",
        tactic: "defense_evasion",
        severity: 1,
        source: RuleSource::Custom,
    },

    // ── Fileless Execution ──────────────────────────────────────
    Rule {
        name: "Memfd create (fileless execution vector)",
        syscalls: &["memfd_create"],
        file_patterns: &[],
        process_patterns: &[],
        process_exclude: &[],
        technique_id: "T1620",
        technique_name: "Reflective Code Loading",
        tactic: "defense_evasion",
        severity: 3,
        source: RuleSource::Falco,
    },

    // ── Hidden Data Flows ────────────────────────────────────────
    Rule {
        name: "Kernel-space data transfer (sendfile/splice)",
        syscalls: &["sendfile", "splice", "tee", "copy_file_range"],
        file_patterns: &[],
        process_patterns: &[],
        process_exclude: &["nginx", "apache2", "httpd", "haproxy"], // web servers use these legitimately
        technique_id: "T1048",
        technique_name: "Exfiltration Over Alternative Protocol",
        tactic: "exfiltration",
        severity: 2,
        source: RuleSource::Custom,
    },

    // ── Lateral Movement ────────────────────────────────────────
    Rule {
        name: "SSH client execution",
        syscalls: &["execve", "execveat"],
        file_patterns: &[],
        process_patterns: &["ssh", "sshpass"],
        process_exclude: &[],
        technique_id: "T1021.004",
        technique_name: "SSH",
        tactic: "lateral_movement",
        severity: 2,
        source: RuleSource::AuditdAttack,
    },
];
