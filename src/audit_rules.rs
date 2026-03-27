//! Hybrid audit mode: install AUDIT_SYSCALL rules for path-bearing syscalls.
//!
//! The kernel audit subsystem can generate multi-record events that include
//! resolved filenames (AUDIT_PATH) and socket addresses (AUDIT_SOCKADDR).
//! This is more reliable than reading /proc/pid/fd after the fact, because
//! the kernel resolves the path at syscall time — no TOCTOU race.
//!
//! We install rules only for syscalls where we need the arguments:
//! openat, execve, connect, bind, rename, unlink, chmod, chown.
//! Everything else stays on SECCOMP_RET_LOG (lightweight, no arguments).

use std::io;
use std::mem;

use anyhow::{Context, Result};

/// Syscalls for which we install AUDIT_SYSCALL rules to get PATH/SOCKADDR records.
const AUDIT_SYSCALLS: &[(&str, u32)] = &[
    // File operations — get AUDIT_PATH records
    ("openat", 257),
    ("open", 2),
    ("openat2", 437),
    ("creat", 85),
    ("execve", 59),
    ("execveat", 322),
    ("rename", 82),
    ("renameat", 264),
    ("renameat2", 316),
    ("unlink", 87),
    ("unlinkat", 263),
    ("chmod", 90),
    ("fchmodat", 268),
    ("chown", 92),
    ("fchownat", 260),
    // Network operations — get AUDIT_SOCKADDR records
    ("connect", 42),
    ("bind", 49),
    // Hidden data flow syscalls — kernel-space transfers
    // These move data between fds without touching userspace, making them
    // invisible to traditional monitoring. We need audit records to see them.
    ("sendfile", 40),       // file fd → socket fd
    ("splice", 275),        // fd → pipe or pipe → fd (zero-copy)
    ("tee", 276),           // pipe → pipe (duplicate data)
    ("copy_file_range", 326), // file fd → file fd (in-kernel copy)
];

/// Our audit rule key — used to identify and clean up our rules.
const AUDIT_KEY: &str = "syscon";

// Netlink audit protocol constants
#[allow(dead_code)]
const AUDIT_ADD_RULE: u16 = 1011;
#[allow(dead_code)]
const AUDIT_DEL_RULE: u16 = 1012;
const AUDIT_FILTER_EXIT: u32 = 0x04;
const AUDIT_ALWAYS: u32 = 0x02;
// Field IDs
const AUDIT_ARCH: u32 = 11;
const AUDIT_SYSCALL_FIELD: u32 = 12;
const AUDIT_FILTERKEY: u32 = 210;
// Operators
const AUDIT_EQUAL: u32 = 0x40000000;
// x86_64 audit arch
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

/// Install audit rules for path-bearing syscalls.
/// Uses `auditctl` command for reliable rule installation.
/// Returns the number of rules installed.
pub fn install_rules(_audit_fd: libc::c_int) -> Result<usize> {
    // First, remove any stale rules from a previous run
    let _ = std::process::Command::new("auditctl")
        .args(["-D", "-k", AUDIT_KEY])
        .output();

    let mut count = 0;
    for (name, _nr) in AUDIT_SYSCALLS {
        let result = std::process::Command::new("auditctl")
            .args([
                "-a", "always,exit",
                "-F", "arch=b64",
                "-S", name,
                "-F", &format!("key={AUDIT_KEY}"),
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                tracing::debug!(syscall = name, "installed audit rule");
                count += 1;
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!(syscall = name, "failed to install audit rule: {}", stderr.trim());
            }
            Err(e) => {
                tracing::warn!(syscall = name, "auditctl not found: {}", e);
                return Err(anyhow::anyhow!("auditctl not available: {}", e));
            }
        }
    }
    tracing::info!(count, "audit syscall rules installed");
    Ok(count)
}

/// Remove all our audit rules (cleanup on shutdown).
#[allow(dead_code)]
pub fn remove_rules(_audit_fd: libc::c_int) {
    let _ = std::process::Command::new("auditctl")
        .args(["-D", "-k", AUDIT_KEY])
        .output();
    tracing::info!("audit syscall rules removed");
}

/// A parsed multi-record audit event with resolved paths/addresses.
#[derive(Debug, Default)]
pub struct AuditSyscallEvent {
    /// Serial number grouping related records.
    pub serial: u64,
    /// From AUDIT_SYSCALL record.
    pub pid: u32,
    pub ppid: u32,
    pub syscall: u32,
    pub success: bool,
    pub comm: String,
    pub exe: String,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    /// Return value of the syscall (e.g., fd number for openat, connect).
    pub exit_value: i64,
    /// From AUDIT_PATH records (there can be multiple, e.g., rename has 2).
    pub paths: Vec<String>,
    /// From AUDIT_CWD record.
    pub cwd: String,
    /// From AUDIT_SOCKADDR record (hex-encoded, we parse it).
    pub sockaddr: Option<String>,
    /// From AUDIT_EXECVE record (argv).
    pub argv: Vec<String>,
    /// Whether this event is complete (received EOE or timeout).
    pub complete: bool,
}

/// Audit message types we care about.
pub const AUDIT_SYSCALL_TYPE: u16 = 1300;
pub const AUDIT_PATH_TYPE: u16 = 1302;
pub const AUDIT_CWD_TYPE: u16 = 1307;
pub const AUDIT_SOCKADDR_TYPE: u16 = 1306;
pub const AUDIT_EXECVE_TYPE: u16 = 1309;
pub const AUDIT_EOE_TYPE: u16 = 1320;
#[allow(dead_code)]
pub const AUDIT_SECCOMP_TYPE: u16 = 1326;
#[allow(dead_code)]
pub const AUDIT_PROCTITLE_TYPE: u16 = 1327;

/// Parse the timestamp:serial from an audit message header.
/// Format: "audit(1234567890.123:456): ..."
pub fn parse_serial(text: &str) -> Option<u64> {
    let start = text.find("audit(")?;
    let colon = text[start..].find(':')?;
    let end = text[start..].find(')')?;
    let serial_str = &text[start + colon + 1..start + end];
    serial_str.parse().ok()
}

/// Parse an AUDIT_SYSCALL record and populate the event.
pub fn parse_syscall_record(text: &str, event: &mut AuditSyscallEvent) {
    let fields = parse_fields(text);
    event.pid = fields.get("pid").and_then(|v| v.parse().ok()).unwrap_or(0);
    event.ppid = fields.get("ppid").and_then(|v| v.parse().ok()).unwrap_or(0);
    event.syscall = fields.get("syscall").and_then(|v| v.parse().ok()).unwrap_or(0);
    event.success = fields.get("success").map(|v| v == "yes").unwrap_or(false);
    event.comm = fields.get("comm").cloned().unwrap_or_default();
    event.exe = fields.get("exe").cloned().unwrap_or_default();
    event.a0 = parse_hex_or_dec(fields.get("a0").map(|s| s.as_str()).unwrap_or("0"));
    event.a1 = parse_hex_or_dec(fields.get("a1").map(|s| s.as_str()).unwrap_or("0"));
    event.a2 = parse_hex_or_dec(fields.get("a2").map(|s| s.as_str()).unwrap_or("0"));
    event.a3 = parse_hex_or_dec(fields.get("a3").map(|s| s.as_str()).unwrap_or("0"));
    event.exit_value = fields.get("exit").and_then(|v| v.parse().ok()).unwrap_or(-1);
}

/// Parse an AUDIT_PATH record and add the path to the event.
pub fn parse_path_record(text: &str, event: &mut AuditSyscallEvent) {
    let fields = parse_fields(text);
    if let Some(name) = fields.get("name") {
        // Skip /proc paths — noise from our own /proc reads
        if !name.starts_with("/proc/") {
            event.paths.push(name.clone());
        }
    }
}

/// Parse an AUDIT_CWD record.
pub fn parse_cwd_record(text: &str, event: &mut AuditSyscallEvent) {
    let fields = parse_fields(text);
    if let Some(cwd) = fields.get("cwd") {
        event.cwd = cwd.clone();
    }
}

/// Parse an AUDIT_SOCKADDR record. The `saddr` field is a hex-encoded sockaddr.
pub fn parse_sockaddr_record(text: &str, event: &mut AuditSyscallEvent) {
    let fields = parse_fields(text);
    if let Some(saddr) = fields.get("saddr") {
        event.sockaddr = decode_sockaddr(saddr);
    }
}

/// Parse an AUDIT_EXECVE record (argv).
pub fn parse_execve_record(text: &str, event: &mut AuditSyscallEvent) {
    let fields = parse_fields(text);
    // argv is in fields a0, a1, a2, ... or argc + a0..aN
    if let Some(argc) = fields.get("argc").and_then(|v| v.parse::<usize>().ok()) {
        for i in 0..argc {
            let key = format!("a{i}");
            if let Some(arg) = fields.get(&key) {
                event.argv.push(arg.clone());
            }
        }
    }
}

// ── Netlink audit rule management ───────────────────────────────────

/// Add an audit rule for a specific syscall number on x86_64.
#[allow(dead_code)]
fn add_syscall_rule(fd: libc::c_int, syscall_nr: u32) -> Result<()> {
    let rule = build_rule(syscall_nr);
    send_audit_rule(fd, AUDIT_ADD_RULE, &rule)
}

#[allow(dead_code)]
fn del_syscall_rule(fd: libc::c_int, syscall_nr: u32) -> Result<()> {
    let rule = build_rule(syscall_nr);
    send_audit_rule(fd, AUDIT_DEL_RULE, &rule)
}

/// Build an audit_rule_data struct for: -a always,exit -F arch=b64 -S <nr> -F key=syscon
fn build_rule(syscall_nr: u32) -> Vec<u8> {
    // struct audit_rule_data layout (from linux/audit.h):
    //   u32 flags          (AUDIT_FILTER_EXIT)
    //   u32 action          (AUDIT_ALWAYS)
    //   u32 field_count
    //   u32 mask[64]        (syscall bitmask, 64 u32s = 2048 bits for syscall 0-2047)
    //   u32 fields[64]      (field IDs)
    //   u32 values[64]      (field values)
    //   u32 fieldflags[64]  (operators)
    //   u32 buflen          (length of string data after struct)
    //   [u8 buf]            (string data, e.g., key)

    let key_bytes = AUDIT_KEY.as_bytes();
    let buflen = key_bytes.len() as u32;

    // Total fields: arch + syscall + key = 3
    let field_count: u32 = 3;

    let mut rule = Vec::new();

    // flags (u32)
    rule.extend_from_slice(&AUDIT_FILTER_EXIT.to_ne_bytes());
    // action (u32)
    rule.extend_from_slice(&AUDIT_ALWAYS.to_ne_bytes());
    // field_count (u32)
    rule.extend_from_slice(&field_count.to_ne_bytes());

    // mask[64] — set bit for our syscall number
    let mut mask = [0u32; 64];
    if (syscall_nr as usize) < 64 * 32 {
        mask[syscall_nr as usize / 32] |= 1 << (syscall_nr % 32);
    }
    for m in &mask {
        rule.extend_from_slice(&m.to_ne_bytes());
    }

    // fields[64]
    let mut fields = [0u32; 64];
    fields[0] = AUDIT_ARCH;
    fields[1] = AUDIT_SYSCALL_FIELD;
    fields[2] = AUDIT_FILTERKEY;
    for f in &fields {
        rule.extend_from_slice(&f.to_ne_bytes());
    }

    // values[64]
    let mut values = [0u32; 64];
    values[0] = AUDIT_ARCH_X86_64;
    values[1] = syscall_nr;
    values[2] = buflen;
    for v in &values {
        rule.extend_from_slice(&v.to_ne_bytes());
    }

    // fieldflags[64]
    let mut fieldflags = [0u32; 64];
    fieldflags[0] = AUDIT_EQUAL;
    fieldflags[1] = AUDIT_EQUAL;
    fieldflags[2] = AUDIT_EQUAL;
    for ff in &fieldflags {
        rule.extend_from_slice(&ff.to_ne_bytes());
    }

    // buflen (u32)
    rule.extend_from_slice(&buflen.to_ne_bytes());

    // buf (key string)
    rule.extend_from_slice(key_bytes);

    rule
}

/// Send an audit rule via netlink.
fn send_audit_rule(fd: libc::c_int, msg_type: u16, rule_data: &[u8]) -> Result<()> {
    let nlmsg_len = mem::size_of::<libc::nlmsghdr>() + rule_data.len();

    let mut buf = vec![0u8; nlmsg_len];

    // Build nlmsghdr
    let hdr = libc::nlmsghdr {
        nlmsg_len: nlmsg_len as u32,
        nlmsg_type: msg_type,
        nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    // SAFETY: copying a plain C struct into our buffer
    unsafe {
        std::ptr::copy_nonoverlapping(
            &hdr as *const _ as *const u8,
            buf.as_mut_ptr(),
            mem::size_of::<libc::nlmsghdr>(),
        );
    }
    buf[mem::size_of::<libc::nlmsghdr>()..].copy_from_slice(rule_data);

    // SAFETY: send(2) on the audit netlink socket
    let ret = unsafe {
        libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("send audit rule");
    }

    // Read the ACK
    let mut ack_buf = [0u8; 1024];
    let n = unsafe {
        libc::recv(fd, ack_buf.as_mut_ptr() as *mut libc::c_void, ack_buf.len(), 0)
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EAGAIN) {
            return Err(err).context("recv audit rule ack");
        }
    }

    Ok(())
}

// ── Parsing helpers ─────────────────────────────────────────────────

fn parse_fields(text: &str) -> std::collections::HashMap<String, String> {
    // Reuse the same parser as audit.rs but we can't import it (circular).
    // Simple key=value parser, handling quoted values.
    let mut fields = std::collections::HashMap::new();
    let text = if let Some(pos) = text.find("): ") {
        &text[pos + 3..]
    } else {
        text
    };

    let mut chars = text.chars().peekable();
    loop {
        while chars.peek() == Some(&' ') { chars.next(); }
        if chars.peek().is_none() { break; }

        let mut key = String::new();
        let mut found_eq = false;
        while let Some(&c) = chars.peek() {
            if c == '=' { chars.next(); found_eq = true; break; }
            if c == ' ' { break; }
            key.push(c); chars.next();
        }
        if key.is_empty() || !found_eq { continue; }
        if chars.peek() == Some(&'=') { chars.next(); }

        let value = if chars.peek() == Some(&'"') {
            chars.next();
            let mut v = String::new();
            for c in chars.by_ref() { if c == '"' { break; } v.push(c); }
            v
        } else {
            let mut v = String::new();
            while let Some(&c) = chars.peek() { if c == ' ' { break; } v.push(c); chars.next(); }
            v
        };
        fields.insert(key, value);
    }
    fields
}

fn parse_hex_or_dec(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

/// Decode a hex-encoded sockaddr into a human-readable string.
fn decode_sockaddr(hex: &str) -> Option<String> {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= hex.len() {
                u8::from_str_radix(&hex[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect();

    if bytes.len() < 2 {
        return None;
    }

    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);

    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    const AF_UNIX: u16 = 1;

    match family {
        AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            Some(format!("{}.{}.{}.{}:{}", bytes[4], bytes[5], bytes[6], bytes[7], port))
        }
        AF_INET6 if bytes.len() >= 28 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let addr_bytes: [u8; 16] = bytes[8..24].try_into().ok()?;
            let addr = std::net::Ipv6Addr::from(addr_bytes);
            if let Some(v4) = addr.to_ipv4_mapped() {
                Some(format!("{v4}:{port}"))
            } else {
                Some(format!("[{addr}]:{port}"))
            }
        }
        AF_UNIX if bytes.len() > 2 => {
            let path_bytes = &bytes[2..];
            if path_bytes.first() == Some(&0) {
                let name = String::from_utf8_lossy(&path_bytes[1..]);
                Some(format!("@{}", name.trim_end_matches('\0')))
            } else {
                let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
                Some(String::from_utf8_lossy(&path_bytes[..nul]).to_string())
            }
        }
        _ => Some(format!("AF_{family}")),
    }
}
