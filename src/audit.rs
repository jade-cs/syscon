use std::collections::HashMap;
use std::io;
use std::mem;

use anyhow::{Context, Result};

// Kernel constants — see include/uapi/linux/audit.h and include/uapi/linux/netlink.h.
const NETLINK_AUDIT: libc::c_int = 9; // Protocol number for audit netlink
const AUDIT_SECCOMP: u16 = 1326; // Message type for seccomp events
const AUDIT_NLGRP_READLOG: u32 = 1; // Multicast group for read-only audit

/// A parsed AUDIT_SECCOMP event (kernel audit message type 1326).
/// Fields are extracted from the text payload of the netlink message.
/// See kernel/auditsc.c :: audit_seccomp() for the format.
#[allow(dead_code)]
pub struct SeccompEvent {
    pub pid: u32,
    pub comm: String,
    pub exe: String,
    pub syscall: u32,
    pub arch: u32,
    pub ip: u64,
    pub code: u32,
    pub sig: u32,
}

/// Open a NETLINK_AUDIT socket bound to the AUDIT_NLGRP_READLOG multicast
/// group. This allows us to receive audit events (including AUDIT_SECCOMP)
/// without conflicting with auditd — multiple consumers can bind to the
/// multicast group simultaneously. Requires CAP_AUDIT_READ.
///
/// See: audit(7), netlink(7), and kernel/audit.c :: kauditd_send_multicast_skb.
pub fn open_audit_socket() -> Result<libc::c_int> {
    // SAFETY: socket(2) creates a new socket. AF_NETLINK + SOCK_RAW +
    // NETLINK_AUDIT is a well-defined combination (see netlink(7)).
    // SOCK_CLOEXEC prevents fd leakage across exec. On success, a
    // non-negative fd is returned. On failure, -1 is returned and errno
    // is set.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("Failed to open NETLINK_AUDIT socket");
    }

    // SAFETY: mem::zeroed() produces an all-zero sockaddr_nl, which is valid:
    // nl_family will be overwritten, nl_pad is padding (zero is correct),
    // nl_pid=0 tells the kernel to auto-assign, nl_groups=0 is overwritten.
    // See netlink(7) § "Socket address".
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = 0; // kernel assigns
    // AUDIT_NLGRP_READLOG = 1; group 1 maps to bit 0 in nl_groups.
    addr.nl_groups = 1 << (AUDIT_NLGRP_READLOG - 1);

    // SAFETY: bind(2) binds the socket to the specified netlink address.
    // addr is a valid sockaddr_nl on the stack, and the size matches.
    // The kernel checks CAP_AUDIT_READ before allowing this bind
    // (see kernel/audit.c :: audit_multicast_bind).
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // SAFETY: close(2) on the fd we just opened.
        unsafe { libc::close(fd) };
        return Err(err).context(
            "Failed to bind audit multicast socket (need CAP_AUDIT_READ or root)",
        );
    }

    // Enlarge the receive buffer to handle high event volumes.
    // Default is ~200KB which overflows easily under container load.
    let buf_size: libc::c_int = 8 * 1024 * 1024; // 8 MB
    // SAFETY: setsockopt with SO_RCVBUFFORCE bypasses rmem_max.
    // Falls back to SO_RCVBUF if we lack CAP_NET_ADMIN.
    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &buf_size as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret < 0 {
            // Fall back to regular SO_RCVBUF (capped by rmem_max)
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    Ok(fd)
}

/// Set a receive timeout on the audit socket so recv() unblocks periodically,
/// allowing us to check the stop flag and child process status.
pub fn set_recv_timeout(fd: libc::c_int, ms: u64) {
    let timeout = libc::timeval {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
    };
    // SAFETY: setsockopt(2) with SOL_SOCKET/SO_RCVTIMEO sets the receive
    // timeout. The timeval struct is valid and correctly sized. If this
    // fails we silently ignore it — the worst case is blocking indefinitely
    // on recv (which Ctrl+C can still interrupt via EINTR).
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

/// Result of trying to receive an audit event.
pub enum RecvResult {
    /// Got a SECCOMP event.
    Event(SeccompEvent),
    /// Got a raw audit message (type + payload text). Used for AUDIT_SYSCALL
    /// and related multi-record types (PATH, SOCKADDR, CWD, EXECVE, EOE).
    Raw { msg_type: u16, text: String },
    /// Received a message but it wasn't relevant — keep reading.
    Filtered,
    /// No data available (EAGAIN / timeout / EINTR / ENOBUFS).
    WouldBlock,
}

/// Try to receive one audit message, distinguishing between
/// "no data available" and "got a non-SECCOMP message".
pub fn try_recv(fd: libc::c_int) -> Result<RecvResult> {
    let mut buf = [0u8; 8192];

    // SAFETY: recv(2) reads up to buf.len() bytes from the socket into buf.
    // buf is a stack-allocated array with a valid pointer and known size.
    // On timeout/interrupt recv returns -1 with EAGAIN/EINTR, which we
    // handle below.
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
            // EAGAIN = timeout or non-blocking would-block; EINTR = signal.
            // ENOBUFS = kernel audit backlog overflow (transient, retry).
            Some(libc::EAGAIN | libc::EINTR | libc::ENOBUFS) => {
                return Ok(RecvResult::WouldBlock);
            }
            _ => return Err(err).context("recv on audit socket failed"),
        }
    }
    let n = n as usize;

    // Need at least a netlink message header (16 bytes on all Linux archs).
    if n < mem::size_of::<libc::nlmsghdr>() {
        return Ok(RecvResult::Filtered);
    }

    // SAFETY: We've verified n >= sizeof(nlmsghdr). The buf is properly
    // populated by recv. We use read_unaligned because buf is a byte array
    // and may not be aligned to nlmsghdr's alignment requirement. nlmsghdr
    // is a simple C struct with no pointers or invariants — any bit pattern
    // that recv wrote is valid to read.
    let hdr = unsafe {
        std::ptr::read_unaligned(buf.as_ptr() as *const libc::nlmsghdr)
    };
    // Dispatch based on message type
    let msg_type = hdr.nlmsg_type;
    let is_seccomp = msg_type == AUDIT_SECCOMP;
    let is_multi_record = matches!(
        msg_type,
        1300 | 1302 | 1306 | 1307 | 1309 | 1320 | 1327 // SYSCALL, PATH, SOCKADDR, CWD, EXECVE, EOE, PROCTITLE
    );

    if !is_seccomp && !is_multi_record {
        return Ok(RecvResult::Filtered);
    }

    let payload_start = mem::size_of::<libc::nlmsghdr>();
    if payload_start >= n {
        return Ok(RecvResult::Filtered);
    }
    let payload = &buf[payload_start..n];
    let text = std::str::from_utf8(payload)
        .unwrap_or("")
        .trim_end_matches('\0')
        .trim();

    if is_seccomp {
        Ok(RecvResult::Event(parse_seccomp_event(text)))
    } else {
        Ok(RecvResult::Raw {
            msg_type,
            text: text.to_string(),
        })
    }
}

fn parse_seccomp_event(text: &str) -> SeccompEvent {
    let fields = parse_audit_fields(text);

    SeccompEvent {
        pid: fields
            .get("pid")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        comm: fields.get("comm").cloned().unwrap_or_default(),
        exe: fields.get("exe").cloned().unwrap_or_default(),
        syscall: fields
            .get("syscall")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        arch: fields
            .get("arch")
            .and_then(|v| u32::from_str_radix(v, 16).ok())
            .unwrap_or(0),
        ip: fields
            .get("ip")
            .and_then(|v| {
                let v = v.strip_prefix("0x").or(v.strip_prefix("0X")).unwrap_or(v);
                u64::from_str_radix(v, 16).ok()
            })
            .unwrap_or(0),
        code: fields
            .get("code")
            .and_then(|v| {
                let v = v.strip_prefix("0x").or(v.strip_prefix("0X")).unwrap_or(v);
                u32::from_str_radix(v, 16).ok()
            })
            .unwrap_or(0),
        sig: fields
            .get("sig")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    }
}

/// Parse audit event text into key=value pairs.
///
/// Audit messages have the format:
///   audit(TIMESTAMP:SERIAL): key1=val1 key2="quoted val" key3=val3 ...
///
/// Special cases handled:
///   - The "audit(...): " prefix is skipped.
///   - Quoted values: comm="cat", exe="/usr/bin/cat"
///   - Double-equals: subj==unconfined (SELinux contexts)
fn parse_audit_fields(text: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();

    // Skip the "audit(timestamp:serial): " header if present
    let text = if let Some(pos) = text.find("): ") {
        &text[pos + 3..]
    } else {
        text
    };

    let mut chars = text.chars().peekable();
    loop {
        // Skip whitespace
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }

        // Read key (up to '=' or end)
        let mut key = String::new();
        let mut found_eq = false;
        while let Some(&c) = chars.peek() {
            if c == '=' {
                chars.next();
                found_eq = true;
                break;
            }
            if c == ' ' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if key.is_empty() || !found_eq {
            continue;
        }

        // Handle "subj==unconfined" (double equals — SELinux context)
        if chars.peek() == Some(&'=') {
            chars.next();
        }

        // Read value
        let value = if chars.peek() == Some(&'"') {
            chars.next(); // skip opening quote
            let mut v = String::new();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                v.push(c);
            }
            v
        } else {
            let mut v = String::new();
            while let Some(&c) = chars.peek() {
                if c == ' ' {
                    break;
                }
                v.push(c);
                chars.next();
            }
            v
        };

        fields.insert(key, value);
    }

    fields
}

