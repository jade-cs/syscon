use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use libseccomp::*;

use crate::{audit, syscalls};

/// Default syscalls to intercept in intercept mode.
/// Focused on file I/O and exec — the user plans to expand this later.
const DEFAULT_INTERCEPT_SYSCALLS: &[&str] = &[
    // File reads
    "read",
    "pread64",
    "readv",
    "preadv",
    "preadv2",
    // File writes
    "write",
    "pwrite64",
    "writev",
    "pwritev",
    "pwritev2",
    // File open / create
    "open",
    "openat",
    "openat2",
    "creat",
    // File close
    "close",
    "close_range",
    // Exec
    "execve",
    "execveat",
];

// ── fd passing via SCM_RIGHTS ───────────────────────────────────────
//
// We pass the seccomp notification fd from child to parent through a UNIX
// domain socketpair using the SCM_RIGHTS ancillary message mechanism.
// See cmsg(3), unix(7).

fn send_fd(sock: libc::c_int, fd: libc::c_int) -> Result<()> {
    let mut data: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut data) as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };

    // SAFETY: CMSG_SPACE computes the aligned buffer size needed to hold one
    // control message carrying a single file descriptor (sizeof(c_int) = 4).
    // On x86_64 Linux this evaluates to 24 bytes. The function is defined in
    // linux/socket.h via the libc crate and only performs arithmetic on its
    // argument — no memory access, no side effects.
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    // SAFETY: msghdr is a C struct where all-zero is a valid state (NULL
    // pointers and zero lengths). We immediately overwrite the fields we need.
    // This is the idiomatic way to initialize a C struct in Rust — see
    // mem::zeroed() docs and the sendmsg(2) man page.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // SAFETY: We set up the control message buffer according to the cmsg(3)
    // protocol:
    //
    //   1. CMSG_FIRSTHDR(&msg) returns a pointer to the first cmsghdr in our
    //      cmsg_buf. The buffer is large enough (CMSG_SPACE bytes) and properly
    //      aligned because vec![0u8; N] guarantees at least byte alignment and
    //      CMSG_FIRSTHDR only requires msg_control to be non-NULL with
    //      msg_controllen >= sizeof(cmsghdr).
    //
    //   2. We populate cmsg_level = SOL_SOCKET, cmsg_type = SCM_RIGHTS per
    //      unix(7) § "Ancillary messages".
    //
    //   3. cmsg_len = CMSG_LEN(sizeof(int)) accounts for the cmsghdr header
    //      plus one int-sized payload (the fd). On x86_64 this is 20 bytes.
    //
    //   4. CMSG_DATA(cmsg) returns a pointer to the payload area immediately
    //      after the cmsghdr. We use write_unaligned because CMSG_DATA's
    //      return may not be int-aligned. The written value (fd) is a valid
    //      open file descriptor.
    //
    //   5. sendmsg(2) transmits the message. The fd in sock is a connected
    //      UNIX stream socket (created by socketpair earlier). On success
    //      the kernel duplicates fd into the receiver's fd table.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len =
            libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(cmsg) as *mut libc::c_int,
            fd,
        );

        let ret = libc::sendmsg(sock, &msg, 0);
        if ret < 0 {
            return Err(io::Error::last_os_error())
                .context("sendmsg (SCM_RIGHTS) failed");
        }
    }
    Ok(())
}

fn recv_fd(sock: libc::c_int) -> Result<libc::c_int> {
    let mut data: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut data) as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };

    // SAFETY: same as in send_fd — CMSG_SPACE is pure arithmetic.
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    // SAFETY: same as send_fd — zeroed msghdr is valid, fields overwritten.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // SAFETY:
    //   1. recvmsg(2) reads one message from the connected UNIX stream socket.
    //      The iov and control buffers are valid and correctly sized.
    //
    //   2. CMSG_FIRSTHDR returns a pointer into our cmsg_buf (which recvmsg
    //      has now populated). We check for NULL (no control message).
    //
    //   3. We verify cmsg_level == SOL_SOCKET and cmsg_type == SCM_RIGHTS
    //      before reading the payload.
    //
    //   4. CMSG_DATA returns a pointer to the payload (the received fd).
    //      We use read_unaligned since the pointer may not be int-aligned.
    //      The kernel guarantees the payload is a valid fd number that has
    //      been installed in our fd table by recvmsg.
    unsafe {
        let ret = libc::recvmsg(sock, &mut msg, 0);
        if ret < 0 {
            return Err(io::Error::last_os_error())
                .context("recvmsg (SCM_RIGHTS) failed");
        }

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            anyhow::bail!("No control message received (expected SCM_RIGHTS)");
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            anyhow::bail!(
                "Unexpected cmsg: level={} type={}",
                (*cmsg).cmsg_level,
                (*cmsg).cmsg_type
            );
        }
        Ok(std::ptr::read_unaligned(
            libc::CMSG_DATA(cmsg) as *const libc::c_int,
        ))
    }
}

// ── child helpers ───────────────────────────────────────────────────

/// Replace the current process with `command`.
/// This function never returns on success (exec replaces the process image).
/// On failure it prints an error and calls _exit(127).
fn child_exec(command: &[String]) -> ! {
    let prog = CString::new(command[0].as_str()).unwrap();
    let args_c: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();
    let mut argv: Vec<*const libc::c_char> =
        args_c.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: execvp(3) replaces the current process image. The prog pointer
    // is a valid NUL-terminated C string (from CString). The argv array is a
    // NULL-terminated array of pointers to valid C strings. All CString values
    // are alive for the duration of this call (owned by args_c). On success
    // execvp does not return. On failure we fall through and _exit.
    unsafe {
        libc::execvp(prog.as_ptr(), argv.as_ptr());
    }
    eprintln!("execvp({}): {}", command[0], io::Error::last_os_error());
    // SAFETY: _exit(2) terminates the process immediately without running
    // atexit handlers or flushing stdio. This is correct post-fork: we must
    // not run Rust destructors or flush parent's buffered I/O.
    unsafe { libc::_exit(127) }
}

/// Set PR_SET_NO_NEW_PRIVS on the current process. Required before
/// installing a seccomp filter without CAP_SYS_ADMIN. See prctl(2),
/// seccomp(2) § "SECCOMP_SET_MODE_FILTER".
fn child_set_no_new_privs() {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is a well-defined
    // operation (prctl(2)). The 5-argument form is correct for this operation.
    // It only affects the calling thread/process and cannot corrupt memory.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        eprintln!(
            "prctl(PR_SET_NO_NEW_PRIVS): {}",
            io::Error::last_os_error()
        );
        unsafe { libc::_exit(1) }
    }
}

// ── trace mode ──────────────────────────────────────────────────────

/// Fork a child with SECCOMP_RET_LOG filter, monitor its syscalls via audit.
pub fn trace(command: &[String], stop: &AtomicBool) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("No command specified");
    }

    // Open audit socket *before* fork so we're ready to receive events
    // the instant the child starts making syscalls.
    let audit_fd = audit::open_audit_socket()
        .context("Trace mode requires the audit netlink multicast socket")?;

    // SAFETY: fork(2) creates a child process. The child inherits the parent's
    // memory and file descriptors (including audit_fd). After fork, each
    // process has its own copy of the address space. We check the return value:
    //   -1 = error, 0 = child, >0 = parent (value is child PID).
    // Post-fork, the child must not use non-async-signal-safe functions from
    // libc until exec. Our child code only calls prctl, libseccomp (which
    // internally calls seccomp(2)), and execvp — all safe.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(io::Error::last_os_error()).context("fork failed");
    }

    if child_pid == 0 {
        // ── child ──
        // SAFETY: close(2) on a valid fd. audit_fd was opened before fork
        // and is valid in the child's fd table.
        unsafe { libc::close(audit_fd) };
        child_set_no_new_privs();

        // Build a SECCOMP_RET_LOG filter: every syscall is allowed to execute
        // but generates an AUDIT_SECCOMP record (type 1326) in the kernel
        // audit subsystem. The parent reads these via NETLINK_AUDIT multicast.
        let ctx = ScmpFilterContext::new(ScmpAction::Log)
            .expect("Failed to create seccomp filter");
        ctx.load().expect("Failed to load seccomp filter");

        child_exec(command);
    }

    // ── parent ──
    tracing::info!(pid = child_pid, command = %command.join(" "), "Tracing child process");
    tracing::info!("Press Ctrl+C to stop.");

    // TODO(phase3): Re-integrate trace_child and summary printing
    // when this module is wired into the daemon.

    // SAFETY: close(2) on the audit socket fd we opened.
    unsafe { libc::close(audit_fd) };

    if stop.load(Ordering::Relaxed) {
        // SAFETY: kill(2) sends SIGTERM to child_pid. The child is our direct
        // descendant so we have permission. waitpid(2) reaps the child.
        unsafe {
            libc::kill(child_pid, libc::SIGTERM);
            let mut status = 0;
            libc::waitpid(child_pid, &mut status, 0);
        }
    }

    Ok(())
}

// ── intercept mode ──────────────────────────────────────────────────

/// Fork a child with SECCOMP_RET_USER_NOTIF for specific syscalls.
/// Non-intercepted syscalls are allowed to proceed normally.
///
/// The child installs a seccomp-bpf filter (via libseccomp) whose default
/// action is ALLOW. Only the syscalls in `syscall_names` (or the defaults)
/// use SECCOMP_RET_USER_NOTIF, which causes them to block until the parent
/// responds via the notification fd. The parent allows each intercepted
/// syscall to proceed by replying with SECCOMP_USER_NOTIF_FLAG_CONTINUE.
///
/// The notification fd is passed from child to parent via SCM_RIGHTS over a
/// UNIX socketpair. This works because sendmsg/recvmsg/close are NOT in the
/// intercept list, so the child can freely use them after filter installation.
pub fn intercept(
    command: &[String],
    syscall_names: Option<&[String]>,
    stop: &AtomicBool,
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("No command specified");
    }

    // Resolve which syscalls to intercept
    let intercept_list: Vec<&str> = match syscall_names {
        Some(names) => names.iter().map(|s| s.as_str()).collect(),
        None => DEFAULT_INTERCEPT_SYSCALLS.to_vec(),
    };

    // Validate syscall names before forking
    let mut scmp_syscalls = Vec::new();
    for name in &intercept_list {
        match ScmpSyscall::from_name(name) {
            Ok(sc) => scmp_syscalls.push((name.to_string(), sc)),
            Err(e) => anyhow::bail!("Unknown syscall '{}': {}", name, e),
        }
    }

    // Create a UNIX socketpair for passing the seccomp notification fd.
    //
    // SAFETY: socketpair(2) creates a pair of connected UNIX stream sockets.
    // AF_UNIX + SOCK_STREAM + SOCK_CLOEXEC is a well-defined combination.
    // The sv array receives two valid fds on success (return 0).
    // SOCK_CLOEXEC ensures neither fd leaks across exec.
    let mut sv: [libc::c_int; 2] = [0; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error()).context("socketpair failed");
    }
    let parent_sock = sv[0];
    let child_sock = sv[1];

    // SAFETY: fork(2) — see trace() for full rationale.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(io::Error::last_os_error()).context("fork failed");
    }

    if child_pid == 0 {
        // ── child ──
        // SAFETY: close(2) on parent_sock, which the child doesn't need.
        unsafe { libc::close(parent_sock) };
        child_set_no_new_privs();

        // Build the seccomp filter: default ALLOW, Notify for specific syscalls.
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)
            .expect("Failed to create seccomp filter");

        for (name, sc) in &scmp_syscalls {
            if let Err(e) = ctx.add_rule(ScmpAction::Notify, *sc) {
                eprintln!("Warning: could not add rule for {}: {}", name, e);
            }
        }

        ctx.load().expect("Failed to load seccomp filter");
        let notify_fd = ctx
            .get_notify_fd()
            .expect("Failed to get seccomp notify fd");

        // Send the listener fd to the parent via SCM_RIGHTS.
        // sendmsg/close/etc are not in the intercept list — they proceed normally.
        if let Err(e) = send_fd(child_sock, notify_fd) {
            eprintln!("Failed to send notify fd: {e}");
            // SAFETY: _exit in child, see child_exec.
            unsafe { libc::_exit(1) }
        }
        // SAFETY: close(2) on fds we no longer need. Both are valid: notify_fd
        // was returned by get_notify_fd, child_sock by socketpair.
        unsafe {
            libc::close(notify_fd);
            libc::close(child_sock);
        }

        // From this point, intercepted syscalls block until the parent responds.
        child_exec(command);
    }

    // ── parent ──
    // SAFETY: close(2) on child_sock, which the parent doesn't need.
    unsafe { libc::close(child_sock) };

    let listener_fd = recv_fd(parent_sock)
        .context("Failed to receive seccomp listener fd from child")?;
    // SAFETY: close(2) on parent_sock, done with fd passing.
    unsafe { libc::close(parent_sock) };

    tracing::info!(pid = child_pid, command = %command.join(" "), "Intercepting child process");
    tracing::info!(syscalls = %intercept_list.join(", "), "Intercepted syscalls");
    tracing::info!("Press Ctrl+C to stop.");

    let _counts = notification_loop(listener_fd, child_pid, stop)?;

    // SAFETY: close(2) on listener_fd (valid, received via SCM_RIGHTS).
    // waitpid(2) reaps our direct child.
    unsafe {
        libc::close(listener_fd);
        let mut status = 0;
        libc::waitpid(child_pid, &mut status, 0);
    }

    Ok(())
}

fn notification_loop(
    listener_fd: ScmpFd,
    child_pid: libc::pid_t,
    stop: &AtomicBool,
) -> Result<HashMap<u32, u64>> {
    let mut counts: HashMap<u32, u64> = HashMap::new();

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // Poll the listener fd with a 200ms timeout so we can periodically
        // check if the child exited or the user pressed Ctrl+C.
        //
        // SAFETY: poll(2) with a single pollfd is well-defined. The pollfd
        // struct is valid: fd is the seccomp listener fd (open), events=POLLIN
        // requests notification of readable data. timeout=200 means 200ms.
        // poll returns: >0 if events ready, 0 on timeout, -1 on error.
        let mut pfd = libc::pollfd {
            fd: listener_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pfd, 1, 200) };

        if poll_ret == 0 {
            // Timeout — check if child is still alive
            let mut status = 0;
            // SAFETY: waitpid(2) with WNOHANG on our direct child.
            if unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) }
                == child_pid
            {
                break;
            }
            continue;
        }
        if poll_ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err).context("poll on seccomp listener fd failed");
        }

        // POLLHUP or POLLERR without POLLIN means the child exited
        if pfd.revents & libc::POLLIN == 0 {
            break;
        }

        let req = match ScmpNotifReq::receive(listener_fd) {
            Ok(req) => req,
            Err(e) => {
                // Check if child is still alive
                let mut status = 0;
                // SAFETY: waitpid(2) with WNOHANG on our direct child.
                // Returns child_pid if exited, 0 if still running, -1 on error.
                if unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) }
                    == child_pid
                {
                    break;
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                return Err(e).context("Failed to receive seccomp notification");
            }
        };

        let nr = i32::from(req.data.syscall) as u32;
        *counts.entry(nr).or_insert(0) += 1;

        let name = syscalls::name(nr);
        let detail = format_syscall_args(req.pid, nr, &req.data);
        println!(
            "[pid:{pid}] {name}({detail})",
            pid = req.pid,
        );

        // Respond: allow the real syscall to proceed.
        // SECCOMP_USER_NOTIF_FLAG_CONTINUE tells the kernel to execute the
        // original syscall rather than returning a spoofed value.
        let resp =
            ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
        if let Err(e) = resp.respond(listener_fd) {
            // ENOENT = process exited between receive and respond — benign
            let msg = format!("{e}");
            if msg.contains("No such") || msg.contains("ENOENT") {
                continue;
            }
            return Err(e).context("Failed to send seccomp notification response");
        }
    }

    Ok(counts)
}

// ── reading strings from child process memory ───────────────────────

/// Read a NUL-terminated C string from another process's address space via
/// /proc/{pid}/mem. The child must be stopped (e.g. blocked on a seccomp
/// notification) for this to be safe from TOCTOU. Returns None on any failure.
fn read_child_string(pid: u32, addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let path = format!("/proc/{pid}/mem");
    let mut f = File::open(&path).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    // Read up to 4096 bytes looking for NUL
    let mut buf = vec![0u8; 4096];
    let n = f.read(&mut buf).ok()?;
    let nul_pos = buf[..n].iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..nul_pos].to_vec()).ok()
}

/// Format syscall arguments in a human-readable way, resolving filename
/// pointers for file and exec syscalls by reading child memory.
fn format_syscall_args(pid: u32, nr: u32, data: &ScmpNotifData) -> String {
    let a = &data.args;
    match nr {
        // open(pathname, flags, mode)
        2 => {
            let path = read_child_string(pid, a[0]).unwrap_or_else(|| format!("{:#x}", a[0]));
            format!("\"{}\"  flags={:#x}", path, a[1])
        }
        // openat(dirfd, pathname, flags, mode)
        257 => {
            let path = read_child_string(pid, a[1]).unwrap_or_else(|| format!("{:#x}", a[1]));
            let dirfd = if a[0] as i32 == libc::AT_FDCWD { "AT_FDCWD".into() } else { format!("{}", a[0] as i32) };
            format!("{}, \"{}\"  flags={:#x}", dirfd, path, a[2])
        }
        // openat2(dirfd, pathname, how, size)
        437 => {
            let path = read_child_string(pid, a[1]).unwrap_or_else(|| format!("{:#x}", a[1]));
            let dirfd = if a[0] as i32 == libc::AT_FDCWD { "AT_FDCWD".into() } else { format!("{}", a[0] as i32) };
            format!("{}, \"{}\"", dirfd, path)
        }
        // creat(pathname, mode)
        85 => {
            let path = read_child_string(pid, a[0]).unwrap_or_else(|| format!("{:#x}", a[0]));
            format!("\"{}\"  mode={:#o}", path, a[1])
        }
        // execve(filename, argv, envp)
        59 => {
            let path = read_child_string(pid, a[0]).unwrap_or_else(|| format!("{:#x}", a[0]));
            format!("\"{}\"", path)
        }
        // execveat(dirfd, pathname, argv, envp, flags)
        322 => {
            let path = read_child_string(pid, a[1]).unwrap_or_else(|| format!("{:#x}", a[1]));
            let dirfd = if a[0] as i32 == libc::AT_FDCWD { "AT_FDCWD".into() } else { format!("{}", a[0] as i32) };
            format!("{}, \"{}\"  flags={:#x}", dirfd, path, a[4])
        }
        // read/pread64/readv/preadv/preadv2: just show fd and count
        0 | 17 | 19 | 295 | 327 => format!("fd={}, count={}", a[0], a[2]),
        // write/pwrite64/writev/pwritev/pwritev2: just show fd and count
        1 | 18 | 20 | 296 | 328 => format!("fd={}, count={}", a[0], a[2]),
        // close(fd)
        3 => format!("fd={}", a[0]),
        // close_range(first, last, flags)
        436 => format!("{}..{}  flags={:#x}", a[0], a[1], a[2]),
        // Fallback: raw hex args
        _ => format!(
            "{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
            a[0], a[1], a[2], a[3], a[4], a[5]
        ),
    }
}
