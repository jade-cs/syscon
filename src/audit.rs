//! NETLINK_AUDIT socket: syscon acts as the audit daemon.
//!
//! With auditd disabled, we bind as the unicast audit receiver (AUDIT_SET
//! with our pid). The kernel sends ALL audit events to us — multi-record
//! AUDIT_SYSCALL groups (1300 + 1302 + 1306 + 1307 + 1309 + 1320).
//!
//! Non-container events (subj != docker-default) are discarded at
//! AUDIT_SYSCALL time via `skip_serials`, avoiding allocation and parsing
//! of their ancillary records. Container IDs are resolved eagerly while
//! the process is still in-kernel.
//!
//! Multi-record events are assembled by serial number in `PendingEvents`.
//! When the EOE (End Of Event, type 1320) record arrives, the complete
//! `SyscallGroup` is returned to the caller.

use std::collections::{HashMap, HashSet};
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Result, SysconError};
use crate::ingest::SocketTarget;

// ── Tuning constants ───────────────────────────────────────────────

/// Initial capacity for the pending-events hashmap.
/// Sized for typical burst of ~50-100 concurrent in-flight syscall groups.
/// Each entry is a partially-assembled SyscallGroup (~200 bytes), so 64
/// entries costs ~13 KB — cheap to over-allocate vs. repeated rehashing.
const PENDING_INITIAL_CAPACITY: usize = 64;

/// Trigger garbage collection when pending map exceeds this many entries.
/// Normal operation sees <100 entries; 256 indicates a sustained burst or
/// leaked entries from pre-registration events that will never get an EOE.
const PENDING_GC_THRESHOLD: usize = 256;

/// GC retention window: keep entries whose serial is within this many of
/// the highest serial seen. At ~1000 events/sec, 500 serials covers
/// ~500 ms of in-flight events — enough for multi-record assembly while
/// still evicting stale entries from before we registered as the daemon.
const PENDING_GC_SERIAL_WINDOW: u64 = 500;

/// Receive buffer size for the NETLINK_AUDIT socket (bytes).
/// 64 MB matches the rmem_max we set via sysctl. Audit events are ~200-800
/// bytes each; at peak burst of 10k events/sec the kernel can queue ~80k
/// events before dropping. This is set via SO_RCVBUFFORCE (bypasses rmem_max
/// if we have CAP_NET_ADMIN) with fallback to SO_RCVBUF.
const AUDIT_RECV_BUF_BYTES: libc::c_int = 64 * 1024 * 1024;

/// Kernel audit backlog limit. Controls how many audit events the kernel
/// will buffer before it starts dropping. Default is 64; 65536 handles
/// burst-heavy container workloads (e.g., `npm install` spawning hundreds
/// of processes). Matches the value used by production auditd deployments.
const AUDIT_BACKLOG_LIMIT: u32 = 65536;

/// Size of the per-recv netlink message buffer (bytes).
/// A single audit netlink message is at most ~8 KB (nlmsghdr + payload).
/// 8192 handles the largest audit records (EXECVE with long argv).
const RECV_BUF_SIZE: usize = 8192;

/// Size of the netlink ACK buffer (bytes).
/// ACK/NACK from AUDIT_SET is an nlmsghdr (16 bytes) + nlmsgerr (20 bytes);
/// 1024 is generous to handle any extended error attributes.
const ACK_BUF_SIZE: usize = 1024;

// ── Kernel audit constants (from linux-raw-sys, sourced from linux/audit.h) ──

use linux_raw_sys::ptrace::{
    AUDIT_SET,
    AUDIT_SYSCALL, AUDIT_PATH, AUDIT_SOCKADDR, AUDIT_CWD, AUDIT_EXECVE,
    AUDIT_EOE,
    AUDIT_STATUS_PID, AUDIT_STATUS_BACKLOG_LIMIT,
};

// ── Public types ────────────────────────────────────────────────────

/// A completed multi-record audit event assembled from SYSCALL + PATH +
/// SOCKADDR + CWD + EXECVE + EOE records sharing the same serial.
#[derive(Debug, Default)]
pub struct SyscallGroup {
    pub serial: u64,
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
    pub exit_value: i64,
    /// From AUDIT_PATH records. Each entry is (item_number, nametype, path).
    /// We keep all records and select the best path at classification time.
    pub path_records: Vec<(u32, String, String)>,
    pub cwd: String,
    /// Parsed socket target from AUDIT_SOCKADDR record.
    pub sockaddr: Option<SocketTarget>,
    /// Argv from AUDIT_EXECVE record.
    pub argv: Vec<String>,
    /// Whether this process is in a Docker container (from subj=docker-default).
    pub is_container: bool,
    /// Container ID resolved eagerly at AUDIT_SYSCALL recv time (while the
    /// process is still alive in-kernel). This avoids the race where short-lived
    /// processes exit before EOE arrives and /proc/pid/cgroup disappears.
    pub container_id: Option<String>,
    /// Wall-clock timestamp from the audit record (milliseconds since epoch).
    /// Used for action boundary attribution — determines which action was
    /// active when the syscall actually occurred, not when it was processed.
    pub timestamp_ms: u64,
    /// Container IPs resolved eagerly from /proc/{pid}/net/fib_trie while the
    /// process is mid-syscall. Only populated for the first event per container.
    pub container_ips: Vec<std::net::Ipv4Addr>,
}

impl SyscallGroup {
    /// Get resolved file paths, preferring NORMAL/CREATE records over PARENT.
    /// For openat: returns the actual file (NORMAL), not the containing directory (PARENT).
    /// For rename: returns [old_file, new_file] (items 2 and 3, which are NORMAL).
    pub fn paths(&self) -> Vec<&str> {
        // If we have NORMAL/CREATE records, use only those
        let non_parent: Vec<&str> = self.path_records.iter()
            .filter(|(_, nametype, _)| nametype != "PARENT")
            .map(|(_, _, path)| path.as_str())
            .collect();
        if !non_parent.is_empty() {
            return non_parent;
        }
        // Fall back to all records (some syscalls only emit PARENT)
        self.path_records.iter()
            .map(|(_, _, path)| path.as_str())
            .collect()
    }
}

/// Assembles multi-record events by serial number.
pub struct PendingEvents {
    pending: HashMap<u64, SyscallGroup>,
    /// Serials for non-container events (subj != docker-default).
    /// Ancillary records (PATH, SOCKADDR, etc.) for these serials are
    /// skipped immediately — no allocation, no parsing.
    skip_serials: HashSet<u64>,
    /// Monotonically increasing — used for GC of stale entries.
    max_serial: u64,
}

impl PendingEvents {
    pub fn new() -> Self {
        Self {
            pending: HashMap::with_capacity(PENDING_INITIAL_CAPACITY),
            skip_serials: HashSet::with_capacity(PENDING_INITIAL_CAPACITY),
            max_serial: 0,
        }
    }

    /// GC entries whose serial is far behind the current max.
    /// Events that never received an EOE are likely from before we
    /// registered as the daemon.
    fn gc(&mut self) {
        if self.pending.len() > PENDING_GC_THRESHOLD {
            let cutoff = self.max_serial.saturating_sub(PENDING_GC_SERIAL_WINDOW);
            self.pending.retain(|s, _| *s > cutoff);
            self.skip_serials.retain(|s| *s > cutoff);
        }
    }
}

// ── Socket setup ────────────────────────────────────────────────────

/// Open a NETLINK_AUDIT socket and register as the audit daemon.
///
/// Unlike the old multicast-only approach, we set our PID as the audit
/// receiver, which means ALL audit events (unicast) come to us —
/// including multi-record SYSCALL groups with resolved paths and addrs.
///
/// Requires CAP_AUDIT_CONTROL (or root).
pub fn open_audit_socket() -> Result<libc::c_int> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        return Err(SysconError::audit_io(
            io::Error::last_os_error(),
            "failed to open NETLINK_AUDIT socket",
        ));
    }

    // Bind with nl_pid = our PID (needed for unicast delivery).
    // sockaddr_nl has a private padding field, so mem::zeroed() is required.
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = std::process::id();
    addr.nl_groups = 0;

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(SysconError::audit_io(err, "failed to bind audit socket"));
    }

    // Enlarge the receive buffer
    let buf_size: libc::c_int = AUDIT_RECV_BUF_BYTES;
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &buf_size as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret < 0 {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // Register as the audit daemon via AUDIT_SET
    register_as_audit_daemon(fd)?;

    // Set backlog limit
    set_backlog_limit(fd, AUDIT_BACKLOG_LIMIT)?;

    Ok(fd)
}

/// Tell the kernel we are the audit daemon. This gives us unicast delivery
/// of all audit events, replacing auditd.
fn register_as_audit_daemon(fd: libc::c_int) -> Result<()> {
    // struct audit_status (from include/uapi/linux/audit.h):
    //   u32 mask           — which fields to set
    //   u32 enabled        — 1/0
    //   u32 failure        — action on failure
    //   u32 pid            — audit daemon pid
    //   u32 rate_limit
    //   u32 backlog_limit
    //   u32 lost
    //   u32 backlog
    //   ... (extended fields in newer kernels, but these 8 u32s work everywhere)
    let mut status = [0u32; 8];
    status[0] = AUDIT_STATUS_PID; // mask: we're setting the PID field
    status[3] = std::process::id(); // pid

    send_netlink(fd, AUDIT_SET, &status_to_bytes(&status))?;
    tracing::info!(pid = std::process::id(), "registered as audit daemon");
    Ok(())
}

/// Set the kernel audit backlog limit.
fn set_backlog_limit(fd: libc::c_int, limit: u32) -> Result<()> {
    let mut status = [0u32; 8];
    status[0] = AUDIT_STATUS_BACKLOG_LIMIT;
    status[5] = limit;

    send_netlink(fd, AUDIT_SET, &status_to_bytes(&status))?;
    tracing::debug!(limit, "set audit backlog limit");
    Ok(())
}

fn status_to_bytes(status: &[u32; 8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    for v in status {
        bytes.extend_from_slice(&v.to_ne_bytes());
    }
    bytes
}

fn send_netlink(fd: libc::c_int, msg_type: u32, payload: &[u8]) -> Result<()> {
    let nlmsg_len = (16 + payload.len()) as u32; // nlmsghdr is 16 bytes
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;

    // Build nlmsghdr as raw bytes (avoids unsafe ptr::copy_nonoverlapping)
    let mut buf = Vec::with_capacity(nlmsg_len as usize);
    buf.extend_from_slice(&nlmsg_len.to_ne_bytes());      // nlmsg_len: u32
    buf.extend_from_slice(&(msg_type as u16).to_ne_bytes()); // nlmsg_type: u16
    buf.extend_from_slice(&flags.to_ne_bytes());           // nlmsg_flags: u16
    buf.extend_from_slice(&1u32.to_ne_bytes());            // nlmsg_seq: u32
    buf.extend_from_slice(&0u32.to_ne_bytes());            // nlmsg_pid: u32
    buf.extend_from_slice(payload);

    let ret = unsafe {
        libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0)
    };
    if ret < 0 {
        return Err(SysconError::audit_io(
            io::Error::last_os_error(),
            "send netlink message",
        ));
    }

    // Read the ACK (may be NLMSG_ERROR with error=0 for success)
    let mut ack_buf = [0u8; ACK_BUF_SIZE];
    let n = unsafe {
        libc::recv(fd, ack_buf.as_mut_ptr() as *mut libc::c_void, ack_buf.len(), 0)
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EAGAIN) {
            return Err(SysconError::audit_io(err, "recv netlink ack"));
        }
    }
    Ok(())
}

/// Set a receive timeout on the audit socket.
pub fn set_recv_timeout(fd: libc::c_int, ms: u64) {
    let timeout = libc::timeval {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

/// Deregister as the audit daemon on shutdown.
pub fn deregister(fd: libc::c_int) {
    let mut status = [0u32; 8];
    status[0] = AUDIT_STATUS_PID;
    status[3] = 0; // pid = 0 means "no daemon"
    let _ = send_netlink(fd, AUDIT_SET, &status_to_bytes(&status));
    tracing::info!("deregistered as audit daemon");
}

// ── Receive + parse ─────────────────────────────────────────────────

/// Result of trying to receive an audit event.
pub enum RecvResult {
    /// A fully assembled multi-record SYSCALL group.
    Record(SyscallGroup),
    /// Received a message but it wasn't relevant or is still being assembled.
    Pending,
    /// No data available (EAGAIN / timeout / EINTR / ENOBUFS).
    WouldBlock,
}

/// Try to receive one netlink message. If it completes a multi-record
/// event group, returns `Record`. Otherwise returns `Pending`.
pub fn try_recv(fd: libc::c_int, pending: &mut PendingEvents) -> Result<RecvResult> {
    let mut buf = [0u8; RECV_BUF_SIZE];

    let n = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
        )
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN | libc::EINTR | libc::ENOBUFS) => {
                return Ok(RecvResult::WouldBlock);
            }
            _ => return Err(SysconError::audit_io(err, "recv on audit socket failed")),
        }
    }
    let n = n as usize;

    // nlmsghdr is 16 bytes: u32 len, u16 type, u16 flags, u32 seq, u32 pid
    if n < 16 {
        return Ok(RecvResult::Pending);
    }

    // Read nlmsg_type (bytes 4..6, native endian) without unsafe
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]) as u32;
    let payload_start = 16; // sizeof(nlmsghdr)
    if payload_start >= n {
        return Ok(RecvResult::Pending);
    }
    let payload = &buf[payload_start..n];

    // Use the zero-copy parser (operates on &[u8], no HashMap allocation)
    use crate::audit_parse;

    match msg_type {
        AUDIT_SYSCALL => {
            let serial = audit_parse::parse_serial(payload).unwrap_or(0);
            if serial == 0 {
                return Ok(RecvResult::Pending);
            }
            pending.max_serial = pending.max_serial.max(serial);

            let f = audit_parse::parse_syscall(payload);
            let is_container = f.subj == "docker-default";

            // Early discard: non-container events never produce useful records.
            // Track the serial so ancillary records (PATH, SOCKADDR, etc.) are
            // also skipped without parsing.
            if !is_container {
                pending.skip_serials.insert(serial);
                return Ok(RecvResult::Pending);
            }

            let group = pending.pending.entry(serial).or_default();
            group.serial = serial;
            group.timestamp_ms = audit_parse::parse_timestamp_ms(payload).unwrap_or(0);
            group.pid = f.pid;
            group.ppid = f.ppid;
            group.syscall = f.syscall;
            group.success = f.success;
            group.comm = f.comm.to_string();
            group.exe = f.exe.to_string();
            group.a0 = f.a0;
            group.a1 = f.a1;
            group.a2 = f.a2;
            group.a3 = f.a3;
            group.exit_value = f.exit_value;
            group.is_container = true;

            // Eager container resolution: the process is still in-kernel
            // (blocked on the syscall), so /proc/pid/cgroup is guaranteed
            // to exist. Resolve now to avoid the race with short-lived
            // processes that exit before EOE arrives.
            if group.container_id.is_none() {
                group.container_id = crate::docker::container_from_pid(f.pid)
                    .map(|info| info.id);
                // Also read container IPs while the process is alive.
                // /proc/{pid}/net/fib_trie gives the container's network
                // namespace IPs. Must be read now — by the time the async
                // processor runs, the process may have exited and the PID
                // recycled by a host process.
                if group.container_id.is_some() {
                    group.container_ips = crate::docker::container_ips_from_pid(f.pid);
                }
            }

            Ok(RecvResult::Pending)
        }

        AUDIT_PATH => {
            let serial = audit_parse::parse_serial(payload).unwrap_or(0);
            if pending.skip_serials.contains(&serial) {
                return Ok(RecvResult::Pending);
            }
            if let Some(group) = pending.pending.get_mut(&serial) {
                let f = audit_parse::parse_path(payload);
                let name = f.name;
                if !name.is_empty()
                    && !name.starts_with("/proc/")
                    && name != "(null)"
                    && name != "."
                    && name != "/"
                {
                    let path = strip_overlay_path(name);
                    if !path.is_empty() {
                        group.path_records.push((f.item, f.nametype.to_string(), path));
                    }
                }
            }
            Ok(RecvResult::Pending)
        }

        AUDIT_SOCKADDR => {
            let serial = audit_parse::parse_serial(payload).unwrap_or(0);
            if pending.skip_serials.contains(&serial) {
                return Ok(RecvResult::Pending);
            }
            if let Some(group) = pending.pending.get_mut(&serial) {
                let f = audit_parse::parse_sockaddr(payload);
                if !f.saddr.is_empty() {
                    // Strip trailing SADDR={...} annotation
                    let hex = if let Some(idx) = f.saddr.find("SADDR") {
                        &f.saddr[..idx]
                    } else {
                        f.saddr
                    };
                    group.sockaddr = decode_sockaddr(hex);
                }
            }
            Ok(RecvResult::Pending)
        }

        AUDIT_CWD => {
            let serial = audit_parse::parse_serial(payload).unwrap_or(0);
            if pending.skip_serials.contains(&serial) {
                return Ok(RecvResult::Pending);
            }
            if let Some(group) = pending.pending.get_mut(&serial) {
                let f = audit_parse::parse_cwd(payload);
                if !f.cwd.is_empty() {
                    group.cwd = f.cwd.to_string();
                }
            }
            Ok(RecvResult::Pending)
        }

        AUDIT_EXECVE => {
            let serial = audit_parse::parse_serial(payload).unwrap_or(0);
            if pending.skip_serials.contains(&serial) {
                return Ok(RecvResult::Pending);
            }
            if let Some(group) = pending.pending.get_mut(&serial) {
                group.argv = audit_parse::parse_execve_args(payload);
            }
            Ok(RecvResult::Pending)
        }

        AUDIT_EOE => {
            let serial = audit_parse::parse_serial(payload).unwrap_or(0);
            if pending.skip_serials.remove(&serial) {
                return Ok(RecvResult::Pending);
            }
            if let Some(group) = pending.pending.remove(&serial) {
                if group.pid > 0 && (group.success || group.sockaddr.is_some()) {
                    pending.gc();
                    return Ok(RecvResult::Record(group));
                }
            }
            pending.gc();
            Ok(RecvResult::Pending)
        }

        // NLMSG_ERROR (type 2) — ACK/NACK for our AUDIT_SET commands
        // AUDIT_PROCTITLE, AUDIT_FEATURE_CHANGE, etc. — ignore
        _ => Ok(RecvResult::Pending),
    }
}

// ── Audit rule installation ─────────────────────────────────────────

/// Syscall names for which we install AUDIT_SYSCALL rules.
/// These define our audit policy — the syscall *numbers* are resolved at
/// runtime via `crate::syscalls::number()` rather than being hardcoded.
const AUDIT_SYSCALL_NAMES: &[&str] = &[
    "openat", "open", "openat2", "creat",
    "execve", "execveat",
    "rename", "renameat", "renameat2",
    "unlink", "unlinkat",
    "chmod", "fchmodat",
    "chown", "fchownat",
    "connect", "bind",
    "sendto", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    // SysV message queues
    "msgget", "msgsnd", "msgrcv",
    // POSIX message queues
    "mq_open", "mq_timedsend", "mq_timedreceive",
    "sendfile", "splice", "tee", "copy_file_range",
];

const AUDIT_KEY: &str = "syscon";

/// Install audit rules via `auditctl` CLI.
pub fn install_rules() -> Result<usize> {
    // Remove stale rules from a previous run
    let _ = std::process::Command::new("auditctl")
        .args(["-D", "-k", AUDIT_KEY])
        .output();

    // NOTE: Kernel-side subj_type=docker-default filtering was tested but
    // doesn't work reliably with AppArmor (auditctl accepts it but it
    // silently drops events for some container processes). We rely on
    // userspace skip_serials instead — the AUDIT_SYSCALL handler checks
    // subj=docker-default and skips non-container serials immediately.

    let mut count = 0;
    for name in AUDIT_SYSCALL_NAMES {
        let mut args = vec!["-a", "always,exit", "-F", "arch=b64", "-S", name];

        match *name {
            "openat" | "open" => {
                args.push("-F");
                args.push("success=1");
            }
            _ => {}
        }

        let key_arg = format!("key={AUDIT_KEY}");
        args.push("-F");
        args.push(&key_arg);

        match std::process::Command::new("auditctl").args(&args).output() {
            Ok(output) if output.status.success() => {
                tracing::debug!(syscall = name, "installed audit rule");
                count += 1;
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!(syscall = name, "failed to install audit rule: {}", stderr.trim());
            }
            Err(e) => {
                return Err(SysconError::Audit(format!("auditctl not available: {}", e)));
            }
        }
    }
    tracing::info!(count, "audit rules installed");
    Ok(count)
}

/// Strip container overlay prefixes from audit PATH record names.
fn strip_overlay_path(name: &str) -> String {
    if let Some(idx) = name.find("/merged/") {
        name[idx + 7..].to_string()
    } else if let Some(idx) = name.find("/fs/") {
        name[idx + 3..].to_string()
    } else if let Some(idx) = name.find("/rootfs/overlayfs/") {
        let after_prefix = &name[idx + 18..];
        if let Some(slash) = after_prefix.find('/') {
            after_prefix[slash..].to_string()
        } else {
            String::new()
        }
    } else {
        name.to_string()
    }
}

/// Decode a hex-encoded sockaddr into a structured `SocketTarget`.
fn decode_sockaddr(hex: &str) -> Option<SocketTarget> {
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

    // Address family constants (from linux/socket.h)
    const AF_UNIX: u16 = 1;
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;

    match family {
        AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let addr = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some(SocketTarget::Inet { addr, port })
        }
        AF_INET6 if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            // Pad short payloads (kernel sometimes truncates all-zero addrs)
            let mut addr_buf = [0u8; 16];
            let copy_len = (bytes.len() - 8).min(16);
            if copy_len > 0 {
                addr_buf[..copy_len].copy_from_slice(&bytes[8..8 + copy_len]);
            }
            let addr = Ipv6Addr::from(addr_buf);
            if let Some(v4) = addr.to_ipv4_mapped() {
                Some(SocketTarget::Inet { addr: v4, port })
            } else {
                Some(SocketTarget::Inet6 { addr, port })
            }
        }
        AF_UNIX if bytes.len() > 2 => {
            let path_bytes = &bytes[2..];
            let path = if path_bytes.first() == Some(&0) {
                let name = String::from_utf8_lossy(&path_bytes[1..]);
                format!("@{}", name.trim_end_matches('\0'))
            } else {
                let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
                String::from_utf8_lossy(&path_bytes[..nul]).to_string()
            };
            Some(SocketTarget::Unix { path })
        }
        16 => { // AF_NETLINK
            let proto = if bytes.len() >= 8 {
                u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
            } else {
                0
            };
            // Protocol constants from linux/netlink.h
            let proto_name = match proto {
                0 => "route",         // NETLINK_ROUTE: routing/device hook
                2 => "usersock",      // NETLINK_USERSOCK: user mode socket
                3 => "firewall",      // NETLINK_FIREWALL (legacy ip_queue)
                4 => "sock_diag",     // NETLINK_SOCK_DIAG: socket monitoring
                5 => "nflog",         // NETLINK_NFLOG: netfilter/iptables ULOG
                6 => "xfrm",          // NETLINK_XFRM: IPsec
                7 => "selinux",       // NETLINK_SELINUX
                8 => "iscsi",         // NETLINK_ISCSI
                9 => "audit",         // NETLINK_AUDIT
                10 => "fib_lookup",   // NETLINK_FIB_LOOKUP
                11 => "connector",    // NETLINK_CONNECTOR
                12 => "netfilter",    // NETLINK_NETFILTER
                13 => "ip6_fw",       // NETLINK_IP6_FW
                15 => "kobject_uevent", // NETLINK_KOBJECT_UEVENT
                16 => "generic",      // NETLINK_GENERIC
                18 => "scsi",         // NETLINK_SCSITRANSPORT
                19 => "ecryptfs",     // NETLINK_ECRYPTFS
                20 => "rdma",         // NETLINK_RDMA
                21 => "crypto",       // NETLINK_CRYPTO
                22 => "smc",          // NETLINK_SMC: SMC monitoring
                _ => "unknown",
            };
            Some(SocketTarget::Unknown {
                family,
                raw: format!("netlink:{proto_name}"),
            })
        }
        17 => { // AF_PACKET
            Some(SocketTarget::Unknown {
                family,
                raw: "packet:raw".to_string(),
            })
        }
        _ => Some(SocketTarget::Unknown {
            family,
            raw: format!("af{family}"),
        }),
    }
}
