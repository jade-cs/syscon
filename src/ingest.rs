//! Core event types for syscall ingestion.
//!
//! The AUDIT_SYSCALL multi-record path produces `SyscallEvent` values.
//! The `SyscallDetail` enum ensures that per-syscall-class data is
//! correctly shaped -- a file event can't accidentally carry a network
//! address.
//!
//! Design principles:
//!   - `container_id` is `Arc<str>`, never Option -- events without a
//!     container are dropped at the ingestion boundary.
//!   - `SyscallDetail` makes illegal states unrepresentable.
//!   - `BStr` for byte strings from the kernel (exe, cmdline, paths) --
//!     data stays as bytes through the hot ingestion path, UTF-8 conversion
//!     only happens at display time.
//!   - `Arc<str>` only for `container_id` (known ASCII hex).
//!   - `SocketTarget` is a parsed enum, not a String.

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use serde::Serialize;

// ── BStr: byte string from the kernel ──────────────────────────────

/// Byte string from the kernel. UTF-8 conversion deferred to display time.
///
/// Wraps `Arc<[u8]>` so cloning is cheap (refcount bump). Fields like
/// `exe`, `cmdline`, and file paths arrive as bytes from audit records
/// or `/proc` reads; forcing UTF-8 on the hot path wastes cycles and
/// can panic on non-UTF-8 data (rare but possible with overlay mounts).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BStr(Arc<[u8]>);

impl BStr {
    /// Create from a known-UTF-8 string (convenience for literals / test data).
    pub fn from_str(s: &str) -> Self {
        Self(Arc::from(s.as_bytes()))
    }

    /// Lossy UTF-8 conversion -- only for display / serialization.
    pub fn to_str_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for BStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str_lossy())
    }
}

impl std::fmt::Debug for BStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_str_lossy())
    }
}

/// A resolved syscall event, ready for handler dispatch.
///
/// Produced by the audit recv thread from multi-record AUDIT_SYSCALL groups.
#[derive(Debug, Clone)]
pub struct SyscallEvent {
    pub pid: u32,
    pub ppid: u32,
    pub syscall: u32,
    pub comm: CommBuf,
    pub exe: BStr,
    pub container_id: Arc<str>,
    pub cmdline: BStr,
    pub detail: SyscallDetail,
    /// Wall-clock timestamp from the audit record (ms since epoch).
    /// Used for action boundary attribution.
    pub timestamp_ms: u64,
    /// Container IPs resolved eagerly at recv time (from /proc/{pid}/net/fib_trie).
    /// Only non-empty for the first event of a new container.
    pub container_ips: Vec<std::net::Ipv4Addr>,
}

/// Fixed-size buffer for the kernel `comm` field (always <= 16 bytes).
/// Avoids a heap allocation for every event.
#[derive(Clone)]
pub struct CommBuf {
    buf: [u8; 16],
    len: u8,
}

impl CommBuf {
    pub fn new(s: &str) -> Self {
        let bytes = s.as_bytes();
        let len = bytes.len().min(16);
        let mut buf = [0u8; 16];
        buf[..len].copy_from_slice(&bytes[..len]);
        Self { buf, len: len as u8 }
    }

    pub fn as_str(&self) -> &str {
        // comm is always valid UTF-8 (kernel guarantees printable ASCII)
        std::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
}

impl std::fmt::Debug for CommBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

impl std::fmt::Display for CommBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl PartialEq<str> for CommBuf {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

/// Per-syscall resolved data. Each variant carries exactly the data
/// that syscall class produces -- no optional grab-bags.
#[derive(Debug, Clone)]
pub enum SyscallDetail {
    /// File operation with kernel-resolved path (openat, creat, unlink, etc.).
    File {
        path: BStr,
        flags: u64,
        /// Return value (e.g., fd number from openat, 0 for unlink).
        ret: i64,
    },

    /// Network operation with kernel-resolved address.
    Network {
        target: SocketTarget,
        /// The fd used (arg0 for connect/bind, return value for accept).
        fd: u64,
    },

    /// execve/execveat with resolved argv from AUDIT_EXECVE record.
    Exec {
        /// The executable path from the AUDIT_PATH record (may differ from exe
        /// if argv[0] is a symlink or the binary was replaced between exec).
        path: Option<BStr>,
    },

    /// Kernel-space fd-to-fd transfer (sendfile, splice, tee, copy_file_range).
    Transfer {
        src_fd: u64,
        dst_fd: u64,
    },

    /// IPC message queue operation (SysV msgget/msgsnd/msgrcv, POSIX mq_*).
    Ipc {
        /// Channel identifier: "sysv_mq:<msqid>" or "posix_mq:<name>".
        /// Empty if the channel must be resolved via fd lookup (mq_timedsend/recv).
        channel: String,
        /// The fd (for POSIX mq) or msqid (for SysV), used for fd_table lookup.
        fd: i64,
    },

    /// Process lifecycle (fork/clone/exit) or IPC (signal/pipe/ptrace/shm/memfd).
    /// No extra per-event data needed -- the syscall number distinguishes them.
    Process,
}

// ── Syscall classification ─────────────────────────────────────────

use crate::audit;

/// Convert a completed AUDIT_SYSCALL group into the appropriate SyscallDetail variant.
pub fn classify_syscall_group(syscall_name: &str, group: &audit::SyscallGroup) -> SyscallDetail {
    let paths = group.paths();
    match syscall_name {
        "openat" | "openat2" => SyscallDetail::File {
            path: BStr::from_str(paths.first().copied().unwrap_or("")),
            flags: group.a2, // openat(dirfd, path, flags, mode): a2 = flags
            ret: group.exit_value,
        },
        "open" => SyscallDetail::File {
            path: BStr::from_str(paths.first().copied().unwrap_or("")),
            flags: group.a1, // open(path, flags, mode): a1 = flags
            ret: group.exit_value,
        },
        "creat" => SyscallDetail::File {
            path: BStr::from_str(paths.first().copied().unwrap_or("")),
            flags: libc::O_CREAT as u64 | libc::O_WRONLY as u64 | libc::O_TRUNC as u64,
            ret: group.exit_value,
        },
        "rename" | "renameat" | "renameat2" => SyscallDetail::File {
            path: BStr::from_str(paths.first().copied().unwrap_or("")),
            flags: 0,
            ret: group.exit_value,
        },
        "unlink" | "unlinkat" | "chmod" | "fchmodat" | "chown" | "fchownat" => SyscallDetail::File {
            path: BStr::from_str(paths.first().copied().unwrap_or("")),
            flags: 0,
            ret: group.exit_value,
        },
        "execve" | "execveat" => SyscallDetail::Exec {
            path: paths.first().map(|s| BStr::from_str(s)),
        },
        "connect" | "bind" | "sendto" | "sendmsg" | "sendmmsg" => {
            if let Some(ref target) = group.sockaddr {
                SyscallDetail::Network {
                    target: target.clone(),
                    fd: group.a0,
                }
            } else {
                SyscallDetail::Process // no addr resolved
            }
        }
        "recvmsg" | "recvmmsg" => {
            if let Some(ref target) = group.sockaddr {
                SyscallDetail::Network {
                    target: target.clone(),
                    fd: group.a0,
                }
            } else {
                SyscallDetail::Process
            }
        }
        // SysV message queues: a0=key for msgget (exit=msqid), a0=msqid for others
        "msgget" => SyscallDetail::Ipc {
            channel: format!("sysv_mq:{}", group.exit_value),
            fd: group.exit_value,
        },
        "msgsnd" | "msgrcv" | "msgctl" => SyscallDetail::Ipc {
            channel: format!("sysv_mq:{}", group.a0),
            fd: group.a0 as i64,
        },
        // POSIX message queues: mq_open returns fd, name in PATH record
        "mq_open" => {
            let name = paths.first().copied().unwrap_or("");
            SyscallDetail::Ipc {
                channel: format!("posix_mq:{}", name),
                fd: group.exit_value,
            }
        }
        // mq_timedsend/receive: a0=mqdes (fd), channel resolved via fd_table
        "mq_timedsend" | "mq_timedreceive" => SyscallDetail::Ipc {
            channel: String::new(), // resolved in handler via fd lookup
            fd: group.a0 as i64,
        },
        "sendfile" => SyscallDetail::Transfer {
            src_fd: group.a1,
            dst_fd: group.a0,
        },
        "splice" | "copy_file_range" => SyscallDetail::Transfer {
            src_fd: group.a0,
            dst_fd: group.a2,
        },
        "tee" => SyscallDetail::Transfer {
            src_fd: group.a0,
            dst_fd: group.a1,
        },
        _ => SyscallDetail::Process,
    }
}

/// A parsed socket address. Structured, not a string.
#[derive(Debug, Clone, Serialize)]
pub enum SocketTarget {
    Inet { addr: Ipv4Addr, port: u16 },
    Inet6 { addr: Ipv6Addr, port: u16 },
    Unix { path: String },
    /// Unknown address family -- store the raw hex for debugging.
    Unknown { family: u16, raw: String },
}

impl SocketTarget {
    /// Format for display (e.g., in receipts and net_connections).
    pub fn display_addr(&self) -> String {
        match self {
            Self::Inet { addr, port } => format!("{addr}:{port}"),
            Self::Inet6 { addr, port } => format!("[{addr}]:{port}"),
            Self::Unix { path } => format!("unix:{path}"),
            Self::Unknown { family, raw } => {
                if raw.is_empty() {
                    format!("unknown(AF={})", family)
                } else {
                    raw.clone()
                }
            }
        }
    }

}

impl std::fmt::Display for SocketTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_addr())
    }
}
