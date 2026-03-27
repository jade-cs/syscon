//! Seccomp user notification handler for the daemon.
//!
//! This module implements the seccomp notifier protocol:
//! 1. The daemon listens on a Unix socket (`--notify-socket`).
//! 2. When a container runtime (runc 1.1+) starts a container whose seccomp
//!    profile uses `SCMP_ACT_NOTIFY` with a `listenerPath`, the runtime
//!    connects to our socket and sends the seccomp notify fd via SCM_RIGHTS.
//! 3. We spawn a dedicated handler thread per container that processes
//!    notifications: reading syscall arguments from `/proc/{pid}/mem`,
//!    building structured events, and pushing them to the shared event buffer.
//! 4. Each notification is responded to with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
//!    to let the original syscall proceed.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use libseccomp::*;

use crate::binlog::SyscallArgs;

// ── OCI notifier listener ───────────────────────────────────────────

/// Event produced by the notification handler, ready for the daemon pipeline.
#[allow(dead_code)]
pub struct NotifyEvent {
    pub pid: u32,
    pub syscall_nr: u32,
    pub comm: String,
    pub exe: String,
    pub args: Option<SyscallArgs>,
}

/// Configuration for the notifier listener.
pub struct NotifierConfig {
    pub socket_path: PathBuf,
}

/// A running notifier listener that accepts container connections.
pub struct NotifierListener {
    socket_path: PathBuf,
    #[allow(dead_code)]
    join_handle: thread::JoinHandle<()>,
}

impl NotifierListener {
    /// Start listening for seccomp notify fd connections.
    ///
    /// `event_callback` is called for each resolved notification event.
    /// It runs on the handler thread, so it should be fast (e.g., push to a channel).
    pub fn start<F>(config: NotifierConfig, event_callback: F) -> io::Result<Self>
    where
        F: Fn(String, NotifyEvent) + Send + Sync + 'static,
    {
        // Remove stale socket file if it exists
        let _ = std::fs::remove_file(&config.socket_path);

        // Ensure parent directory exists
        if let Some(parent) = config.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&config.socket_path)?;
        tracing::info!(path = %config.socket_path.display(), "seccomp notifier socket listening");

        let socket_path = config.socket_path.clone();
        let callback = Arc::new(event_callback);

        let join_handle = thread::Builder::new()
            .name("notify-listener".into())
            .spawn(move || {
                accept_loop(listener, callback);
            })
            .map_err(io::Error::other)?;

        Ok(Self {
            socket_path,
            join_handle,
        })
    }
}

impl Drop for NotifierListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn accept_loop<F>(listener: UnixListener, callback: Arc<F>)
where
    F: Fn(String, NotifyEvent) + Send + Sync + 'static,
{
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cb = callback.clone();
                thread::Builder::new()
                    .name("notify-handler".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(stream, cb) {
                            tracing::error!("notifier connection error: {:#}", e);
                        }
                    })
                    .ok();
            }
            Err(e) => {
                tracing::error!("notifier accept error: {}", e);
            }
        }
    }
}

/// Handle a single connection from the container runtime.
///
/// Protocol (runc seccomp notifier):
/// 1. Runtime connects to our Unix socket.
/// 2. Sends the seccomp notify fd via SCM_RIGHTS ancillary data.
///    The payload is the `listenerMetadata` string (typically container ID).
/// 3. We read the fd and metadata.
/// 4. We send back an empty response (0 bytes) to signal readiness.
/// 5. We enter the notification loop for this container.
fn handle_connection<F>(
    stream: std::os::unix::net::UnixStream,
    callback: Arc<F>,
) -> anyhow::Result<()>
where
    F: Fn(String, NotifyEvent) + Send + Sync + 'static,
{
    use std::os::unix::io::AsRawFd;

    let raw_fd = stream.as_raw_fd();

    // Receive the seccomp notify fd + metadata via SCM_RIGHTS
    let (notify_fd, metadata) = recv_fd_with_metadata(raw_fd)?;

    let container_id = if metadata.is_empty() {
        "unknown".to_string()
    } else {
        // Metadata might be JSON or a plain string container ID.
        // Try to parse as JSON first (runc sends container state JSON).
        parse_container_id(&metadata)
    };

    tracing::info!(
        container = %container_id,
        notify_fd,
        "received seccomp notify fd from runtime"
    );

    // Send empty response to signal readiness (runc expects this)
    let response: [u8; 0] = [];
    // SAFETY: write(2) with 0 bytes is valid.
    unsafe {
        libc::write(raw_fd, response.as_ptr() as *const libc::c_void, 0);
    }

    // Enter the notification loop for this container
    notification_handler(notify_fd, &container_id, &*callback);

    // SAFETY: close(2) on the notify fd we received.
    unsafe { libc::close(notify_fd) };

    Ok(())
}

/// Parse container ID from the metadata sent by runc.
///
/// runc sends `listenerMetadata` as the payload. This could be:
/// - A plain container ID string
/// - JSON with container state info
fn parse_container_id(metadata: &str) -> String {
    // Try parsing as JSON (runc sends {"id": "...", ...})
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(metadata)
        && let Some(id) = v.get("id").and_then(|v| v.as_str())
    {
        // Return short (12-char) ID like docker.rs does
        let short = if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
            &id[..12]
        } else {
            id
        };
        return short.to_string();
    }

    // Otherwise treat the whole metadata as the container ID
    let trimmed = metadata.trim();
    if trimmed.len() >= 12 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        trimmed[..12].to_string()
    } else {
        trimmed.to_string()
    }
}

// ── SCM_RIGHTS fd receiving ─────────────────────────────────────────

/// Receive a file descriptor and payload data via SCM_RIGHTS on a Unix socket.
fn recv_fd_with_metadata(sock: libc::c_int) -> anyhow::Result<(libc::c_int, String)> {
    let mut data_buf = vec![0u8; 4096];
    let mut iov = libc::iovec {
        iov_base: data_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: data_buf.len(),
    };

    // SAFETY: CMSG_SPACE computes aligned buffer size for one fd.
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    // SAFETY: zeroed msghdr is valid, fields overwritten immediately.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // SAFETY: recvmsg(2) on a connected Unix stream socket.
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error())
            .map_err(|e| anyhow::anyhow!("recvmsg failed: {}", e));
    }

    // Extract the fd from the control message
    let fd = unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            anyhow::bail!("no control message received (expected SCM_RIGHTS fd)");
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            anyhow::bail!(
                "unexpected cmsg: level={} type={}",
                (*cmsg).cmsg_level,
                (*cmsg).cmsg_type
            );
        }
        std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const libc::c_int)
    };

    // Extract the metadata payload
    let n = n as usize;
    let metadata = if n > 0 {
        String::from_utf8_lossy(&data_buf[..n]).to_string()
    } else {
        String::new()
    };

    Ok((fd, metadata))
}

// ── Notification handler loop ───────────────────────────────────────

/// Process seccomp notifications on a notify fd until the container exits.
fn notification_handler<F>(notify_fd: libc::c_int, container_id: &str, callback: &F)
where
    F: Fn(String, NotifyEvent),
{
    loop {
        // Poll with 500ms timeout to allow graceful shutdown
        let mut pfd = libc::pollfd {
            fd: notify_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll(2) on a single valid fd.
        let poll_ret = unsafe { libc::poll(&mut pfd, 1, 500) };

        if poll_ret == 0 {
            continue; // Timeout
        }
        if poll_ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            tracing::error!(container = %container_id, "poll error: {}", err);
            break;
        }

        // POLLHUP/POLLERR without POLLIN means container exited
        if pfd.revents & libc::POLLIN == 0 {
            tracing::info!(container = %container_id, "container exited (POLLHUP)");
            break;
        }

        // Receive the notification
        let req = match ScmpNotifReq::receive(notify_fd) {
            Ok(req) => req,
            Err(e) => {
                let msg = format!("{e}");
                // ENOENT/EBADF typically means container exited
                if msg.contains("No such") || msg.contains("ENOENT") || msg.contains("EBADF") {
                    tracing::info!(container = %container_id, "container exited");
                    break;
                }
                tracing::error!(container = %container_id, "receive error: {}", e);
                break;
            }
        };

        let pid = req.pid;
        let nr = i32::from(req.data.syscall) as u32;

        // Resolve syscall arguments while the process is blocked
        let args = resolve_args(pid, nr, &req.data);

        // Read process info from /proc (process is blocked, safe to read)
        let comm = read_proc_field(pid, "comm");
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Respond: allow the syscall to proceed
        let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
        if let Err(e) = resp.respond(notify_fd) {
            let msg = format!("{e}");
            if msg.contains("No such") || msg.contains("ENOENT") {
                continue; // Process exited between receive and respond
            }
            tracing::error!(container = %container_id, pid, "respond error: {}", e);
            continue;
        }

        // Send the resolved event to the daemon pipeline
        callback(
            container_id.to_string(),
            NotifyEvent {
                pid,
                syscall_nr: nr,
                comm,
                exe,
                args: Some(args),
            },
        );
    }

    tracing::info!(container = %container_id, "notification handler exiting");
}

// ── Argument resolution ─────────────────────────────────────────────

/// Resolve syscall arguments into structured form.
///
/// The target process is blocked on the seccomp notification, so reading
/// `/proc/{pid}/mem` is safe from TOCTOU (the process can't modify its
/// own memory while blocked in the kernel).
fn resolve_args(pid: u32, nr: u32, data: &ScmpNotifData) -> SyscallArgs {
    let a = data.args;
    let mut args = SyscallArgs {
        raw: a,
        resolved_path: None,
        resolved_path2: None,
        resolved_addr: None,
        flags: 0,
        return_value: 0, // Not available until after the syscall completes
    };

    match nr {
        // open(pathname, flags, mode)
        2 => {
            args.resolved_path = read_child_string(pid, a[0]);
            args.flags = a[1];
        }
        // openat(dirfd, pathname, flags, mode)
        257 => {
            args.resolved_path = read_child_string(pid, a[1]);
            args.flags = a[2];
        }
        // openat2(dirfd, pathname, how, size)
        437 => {
            args.resolved_path = read_child_string(pid, a[1]);
        }
        // creat(pathname, mode)
        85 => {
            args.resolved_path = read_child_string(pid, a[0]);
            args.flags = a[1];
        }
        // execve(filename, argv, envp)
        59 => {
            args.resolved_path = read_child_string(pid, a[0]);
        }
        // execveat(dirfd, pathname, argv, envp, flags)
        322 => {
            args.resolved_path = read_child_string(pid, a[1]);
            args.flags = a[4];
        }
        // unlink(pathname)
        87 => {
            args.resolved_path = read_child_string(pid, a[0]);
        }
        // unlinkat(dirfd, pathname, flags)
        263 => {
            args.resolved_path = read_child_string(pid, a[1]);
            args.flags = a[2];
        }
        // rename(oldpath, newpath)
        82 => {
            args.resolved_path = read_child_string(pid, a[0]);
            args.resolved_path2 = read_child_string(pid, a[1]);
        }
        // renameat(olddirfd, oldpath, newdirfd, newpath)
        264 => {
            args.resolved_path = read_child_string(pid, a[1]);
            args.resolved_path2 = read_child_string(pid, a[3]);
        }
        // renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
        316 => {
            args.resolved_path = read_child_string(pid, a[1]);
            args.resolved_path2 = read_child_string(pid, a[3]);
            args.flags = a[4];
        }
        // chmod(pathname, mode)
        90 => {
            args.resolved_path = read_child_string(pid, a[0]);
            args.flags = a[1];
        }
        // fchmodat(dirfd, pathname, mode, flags)
        268 => {
            args.resolved_path = read_child_string(pid, a[1]);
            args.flags = a[2];
        }
        // chown(pathname, owner, group) / fchownat(dirfd, pathname, ...)
        92 => {
            args.resolved_path = read_child_string(pid, a[0]);
        }
        260 => {
            args.resolved_path = read_child_string(pid, a[1]);
        }
        // connect(fd, sockaddr*, addrlen) / bind(fd, sockaddr*, addrlen)
        42 | 49 => {
            args.resolved_addr = read_child_sockaddr(pid, a[1], a[2] as u32);
        }
        // accept(fd, sockaddr*, addrlen*) / accept4(fd, sockaddr*, addrlen*, flags)
        43 | 288 => {
            // For accept, the address is output, not input — skip reading
        }
        // kill(pid, sig)
        62 => {
            // Target PID and signal are register values, not pointers
            args.flags = a[1]; // signal number
        }
        // tgkill(tgid, tid, sig)
        234 => {
            args.flags = a[2]; // signal number
        }
        // clone(flags, ...)
        56 => {
            args.flags = a[0]; // clone flags
        }
        // clone3(cl_args, size)
        435 => {
            // cl_args is a struct — flags are at offset 0
            args.flags = read_child_u64(pid, a[0]).unwrap_or(0);
        }
        // pipe(pipefd[2]) / pipe2(pipefd[2], flags)
        22 | 293 => {
            if nr == 293 {
                args.flags = a[1]; // O_CLOEXEC, O_NONBLOCK, etc.
            }
        }
        // read/write variants — fd is arg[0]
        0 | 1 | 17 | 18 | 19 | 20 | 295 | 296 | 327 | 328 => {
            // fd is already in raw args, no pointer resolution needed
        }
        // sendfile(out_fd, in_fd, offset, count) — kernel-space file→socket
        40 => {
            // out_fd = a[0], in_fd = a[1] — both are fd numbers in raw args
            args.flags = a[1]; // store in_fd so we know the source
        }
        // splice(fd_in, off_in, fd_out, off_out, len, flags)
        275 => {
            args.flags = a[5]; // splice flags
        }
        // tee(fd_in, fd_out, len, flags)
        276 => {
            args.flags = a[3]; // tee flags
        }
        // copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
        326 => {
            // fd_in = a[0], fd_out = a[2]
        }
        // close(fd) / close_range(first, last, flags)
        3 | 436 => {}
        // socket(domain, type, protocol)
        41 => {
            args.flags = a[0]; // domain (AF_INET, AF_UNIX, etc.)
        }
        // sendto(fd, buf, len, flags, dest_addr, addrlen)
        44 => {
            if a[4] != 0 {
                args.resolved_addr = read_child_sockaddr(pid, a[4], a[5] as u32);
            }
        }
        _ => {}
    }

    args
}

// ── /proc memory reading ────────────────────────────────────────────

/// Read a NUL-terminated C string from another process's address space.
///
/// The target process must be blocked (e.g., on a seccomp notification)
/// for this to be safe from TOCTOU.
fn read_child_string(pid: u32, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let path = format!("/proc/{pid}/mem");
    let mut f = File::open(path).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = vec![0u8; 4096];
    let n = f.read(&mut buf).ok()?;
    let nul_pos = buf[..n].iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..nul_pos].to_vec()).ok()
}

/// Read a u64 from another process's address space.
fn read_child_u64(pid: u32, addr: u64) -> Option<u64> {
    if addr == 0 {
        return None;
    }
    let path = format!("/proc/{pid}/mem");
    let mut f = File::open(path).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf).ok()?;
    Some(u64::from_ne_bytes(buf))
}

/// Read and parse a sockaddr struct from another process's address space.
///
/// Returns a human-readable string like "127.0.0.1:8080" or "/var/run/docker.sock".
fn read_child_sockaddr(pid: u32, addr: u64, len: u32) -> Option<String> {
    if addr == 0 || len < 2 {
        return None;
    }
    let len = len.min(128) as usize; // sockaddr is at most ~128 bytes

    let path = format!("/proc/{pid}/mem");
    let mut f = File::open(path).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf).ok()?;

    // First 2 bytes are sa_family (u16 in native byte order)
    let family = u16::from_ne_bytes([buf[0], buf[1]]);

    const AF_INET: u16 = libc::AF_INET as u16;
    const AF_INET6: u16 = libc::AF_INET6 as u16;
    const AF_UNIX: u16 = libc::AF_UNIX as u16;

    match family {
        AF_INET => {
            // struct sockaddr_in: family(2) + port(2) + addr(4) + zero(8)
            if buf.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            Some(format!("{ip}:{port}"))
        }
        AF_INET6 => {
            // struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) + scope_id(4)
            if buf.len() < 28 {
                return None;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let addr_bytes: [u8; 16] = buf[8..24].try_into().ok()?;
            let addr = std::net::Ipv6Addr::from(addr_bytes);

            // Check for v4-mapped addresses
            if let Some(v4) = addr.to_ipv4_mapped() {
                Some(format!("{v4}:{port}"))
            } else {
                Some(format!("[{addr}]:{port}"))
            }
        }
        AF_UNIX => {
            // struct sockaddr_un: family(2) + path(up to 108 bytes)
            if buf.len() <= 2 {
                return None;
            }
            let path_bytes = &buf[2..];
            // Handle abstract sockets (first byte is \0)
            if path_bytes.first() == Some(&0) {
                let abstract_name = String::from_utf8_lossy(&path_bytes[1..]);
                let trimmed = abstract_name.trim_end_matches('\0');
                Some(format!("@{trimmed}"))
            } else {
                let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
                let path = String::from_utf8_lossy(&path_bytes[..nul]);
                Some(path.to_string())
            }
        }
        _ => {
            Some(format!("AF_{family}"))
        }
    }
}

/// Read a /proc/{pid}/{field} file, returning the trimmed contents.
fn read_proc_field(pid: u32, field: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/{field}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
