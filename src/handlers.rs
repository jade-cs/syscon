use crate::audit::SeccompEvent;
use crate::binlog::SyscallArgs;
use crate::events::{FileEvent, FileOp, NetOp, NetworkEvent, ProcessEvent, ProcessOp};
use crate::state::{ChannelType, ContainerState, FdTarget, ProcessInfo};
use crate::syscalls;

/// Dispatch an audit event to the appropriate handler based on syscall number.
/// `ppid` and `cmdline` are resolved outside the lock by the daemon's event processor.
/// `args` contains resolved syscall arguments when using USER_NOTIF mode.
#[allow(clippy::too_many_arguments)]
pub fn dispatch(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64, ppid: u32, cmdline: &str, open_files: &[String], net_connections: &[String], args: Option<&SyscallArgs>) {
    ensure_process(container, event, ppid, cmdline, open_files, net_connections);

    let name = syscalls::name(event.syscall);
    match name {
        // Process lifecycle
        "clone" | "clone3" | "fork" | "vfork" => {
            handle_fork(container, event, timestamp);
        }
        "execve" | "execveat" => {
            handle_exec(container, event, timestamp);
        }
        "exit_group" => {
            handle_exit(container, event, timestamp);
        }

        // File operations
        "open" | "openat" | "openat2" => {
            handle_open(container, event, timestamp, args);
        }
        "read" | "pread64" | "readv" | "preadv" | "preadv2" => {
            handle_file_rw(container, event, FileOp::Read, timestamp);
        }
        "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" => {
            handle_file_rw(container, event, FileOp::Write, timestamp);
        }
        "unlink" | "unlinkat" => {
            handle_file_meta(container, event, FileOp::Unlink, timestamp, args);
        }
        "rename" | "renameat" | "renameat2" => {
            handle_file_meta(container, event, FileOp::Rename, timestamp, args);
        }
        "chmod" | "fchmod" | "fchmodat" => {
            handle_file_meta(container, event, FileOp::Chmod, timestamp, args);
        }
        "chown" | "fchown" | "fchownat" => {
            handle_file_meta(container, event, FileOp::Chown, timestamp, args);
        }

        // Network
        "socket" => {
            handle_network(container, event, NetOp::Socket, timestamp, args);
        }
        "connect" => {
            handle_network(container, event, NetOp::Connect, timestamp, args);
        }
        "bind" => {
            handle_network(container, event, NetOp::Bind, timestamp, args);
        }
        "accept" | "accept4" => {
            handle_network(container, event, NetOp::Accept, timestamp, args);
        }
        "sendto" => {
            handle_network(container, event, NetOp::SendTo, timestamp, args);
        }
        "recvfrom" => {
            handle_network(container, event, NetOp::RecvFrom, timestamp, args);
        }

        // IPC
        "pipe" | "pipe2" => {
            handle_pipe(container, event, timestamp);
        }
        "dup" | "dup2" | "dup3" => {}
        "kill" | "tgkill" => {
            handle_signal(container, event, timestamp);
        }

        // close — just track for completeness
        "close" => {}

        // Shared memory
        "shmget" | "shmat" | "shmdt" => {
            handle_shm(container, event, timestamp);
        }

        // Anonymous memory-backed fd (fileless execution vector)
        "memfd_create" => {
            handle_memfd(container, event, timestamp);
        }

        // Process debugging/injection
        "ptrace" => {
            handle_ptrace(container, event, timestamp);
        }

        // Hidden data flow syscalls — kernel-space fd-to-fd transfers.
        // These move data without touching userspace, making them invisible
        // to traditional file monitoring. We log them as notable events.
        "sendfile" => {
            handle_kernel_transfer(container, event, "sendfile", timestamp, args);
        }
        "splice" => {
            handle_kernel_transfer(container, event, "splice", timestamp, args);
        }
        "tee" => {
            handle_kernel_transfer(container, event, "tee", timestamp, args);
        }
        "copy_file_range" => {
            handle_kernel_transfer(container, event, "copy_file_range", timestamp, args);
        }

        _ => {}
    }
}

fn handle_shm(_container: &mut ContainerState, _event: &SeccompEvent, _timestamp: u64) {
    // In LOG mode we can't see the shmid or key.
    // In NOTIFY mode, we could track shared memory segments and create
    // SharedMemory taint edges between processes sharing the same segment.
    // For now, just note the syscall occurred.
}

fn handle_memfd(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64) {
    // memfd_create is notable: it creates anonymous file-backed memory that
    // can be used for fileless execution (write ELF to memfd, then execveat it).
    let proc_event = ProcessEvent {
        pid: event.pid,
        timestamp,
        operation: ProcessOp::Fork, // Reuse fork as "notable IPC" for now
        target_pid: None,
        exe: event.exe.clone(),
        comm: event.comm.clone(),
    };
    if let Some(action) = &mut container.current_action {
        action.record_process_event(proc_event);
    }
}

fn handle_kernel_transfer(
    container: &mut ContainerState,
    event: &SeccompEvent,
    syscall_name: &str,
    timestamp: u64,
    args: Option<&SyscallArgs>,
) {
    // These syscalls move data between file descriptors entirely in kernel space.
    // Look up the source and dest fds to reconstruct the data flow.
    //
    // sendfile(out_fd, in_fd, offset, count): a0=out_fd, a1=in_fd
    // splice(fd_in, off_in, fd_out, off_out, len, flags): a0=fd_in, a2=fd_out
    // copy_file_range(fd_in, off_in, fd_out, off_out, len, flags): a0=fd_in, a2=fd_out
    // tee(fd_in, fd_out, len, flags): a0=fd_in, a1=fd_out

    let (src_fd, dst_fd) = if let Some(a) = args {
        match syscall_name {
            "sendfile" => (Some(a.raw[1]), Some(a.raw[0])), // sendfile(out, in, ...) — note reversed!
            "splice" | "copy_file_range" => (Some(a.raw[0]), Some(a.raw[2])),
            "tee" => (Some(a.raw[0]), Some(a.raw[1])),
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    // Resolve fd numbers to paths/addresses via our fd table
    let src_target = src_fd.and_then(|fd| container.fd_table.get(&(event.pid, fd)).cloned());
    let dst_target = dst_fd.and_then(|fd| container.fd_table.get(&(event.pid, fd)).cloned());

    let src_desc = match &src_target {
        Some(FdTarget::File(p)) => p.clone(),
        Some(FdTarget::Network(a)) => format!("net:{a}"),
        Some(FdTarget::Socket { domain }) => format!("socket(AF_{domain})"),
        Some(FdTarget::Pipe { inode }) => format!("pipe:[{inode}]"),
        None => src_fd.map(|fd| format!("fd:{fd}")).unwrap_or_default(),
    };
    let dst_desc = match &dst_target {
        Some(FdTarget::File(p)) => p.clone(),
        Some(FdTarget::Network(a)) => format!("net:{a}"),
        Some(FdTarget::Socket { domain }) => format!("socket(AF_{domain})"),
        Some(FdTarget::Pipe { inode }) => format!("pipe:[{inode}]"),
        None => dst_fd.map(|fd| format!("fd:{fd}")).unwrap_or_default(),
    };

    let path = if !src_desc.is_empty() && !dst_desc.is_empty() {
        format!("(kernel:{syscall_name} {src_desc} → {dst_desc})")
    } else {
        format!("(kernel:{syscall_name})")
    };

    // If source is a file, record it as a read so it shows in data flows
    if let Some(FdTarget::File(ref src_path)) = src_target {
        container.record_file_access(src_path, event.pid, FileOp::Read);
    }

    let file_event = FileEvent {
        pid: event.pid,
        timestamp,
        operation: FileOp::Read,
        path,
        flags: 0,
        is_sensitive: false,
        is_new_binary: false,
    };
    if let Some(action) = &mut container.current_action {
        action.record_file_event(file_event);
    }
}

fn handle_ptrace(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64) {
    // ptrace is a powerful IPC channel: the tracer has near-total control
    // over the tracee. Create a strong taint edge if we know the target.
    // In LOG mode we don't know the target PID, but we note the attempt.
    let proc_event = ProcessEvent {
        pid: event.pid,
        timestamp,
        operation: ProcessOp::Signal, // Closest existing operation type
        target_pid: None,             // Unknown in LOG mode
        exe: event.exe.clone(),
        comm: event.comm.clone(),
    };
    if let Some(action) = &mut container.current_action {
        action.record_process_event(proc_event);
    }
}

fn handle_fork(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64) {
    // In LOG mode, we see the parent's event but don't know the child PID
    // from the audit record. We ensure the parent is tracked and note the fork.


    let proc_event = ProcessEvent {
        pid: event.pid,
        timestamp,
        operation: ProcessOp::Fork,
        target_pid: None, // Unknown in LOG mode
        exe: event.exe.clone(),
        comm: event.comm.clone(),
    };

    if let Some(action) = &mut container.current_action {
        action.record_process_event(proc_event);
    }

    // Any child forked from a tainted process inherits taint.
    // We'll pick this up when we first see an event from the child PID
    // and discover its parent via /proc.
}

fn handle_exec(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64) {
    let is_new = container.baseline.is_new_binary(&event.exe);

    // Update or create the process entry with the new exe
    if let Some(info) = container.process_table.processes.get_mut(&event.pid) {
        info.exec_path = event.exe.clone();
        info.comm = event.comm.clone();
    }

    let proc_event = ProcessEvent {
        pid: event.pid,
        timestamp,
        operation: ProcessOp::Exec,
        target_pid: None,
        exe: event.exe.clone(),
        comm: event.comm.clone(),
    };

    // Also log as a file event (exec = loading a binary)
    let file_event = FileEvent {
        pid: event.pid,
        timestamp,
        operation: FileOp::Exec,
        path: event.exe.clone(),
        flags: 0,
        is_sensitive: false,
        is_new_binary: is_new,
    };

    // Record exec in the file graph
    container.record_file_access(&event.exe, event.pid, FileOp::Exec);

    if let Some(action) = &mut container.current_action {
        action.record_process_event(proc_event);
        action.record_file_event(file_event);
    }
}

fn handle_exit(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64) {
    let proc_event = ProcessEvent {
        pid: event.pid,
        timestamp,
        operation: ProcessOp::Exit,
        target_pid: None,
        exe: event.exe.clone(),
        comm: event.comm.clone(),
    };

    if let Some(action) = &mut container.current_action {
        action.record_process_event(proc_event);
    }

    if let Some(info) = container.process_table.processes.get_mut(&event.pid) {
        info.exited = true;
    }
}

fn handle_open(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64, args: Option<&SyscallArgs>) {
    // In USER_NOTIF mode, args.resolved_path has the actual file path.
    // In LOG mode, path is unknown (empty).
    let path = args
        .and_then(|a| a.resolved_path.clone())
        .unwrap_or_default();
    let flags = args.map(|a| a.flags as u32).unwrap_or(0);
    let is_sensitive = !path.is_empty() && container.baseline.is_sensitive(&path);
    let is_write = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32 | libc::O_CREAT as u32 | libc::O_TRUNC as u32) != 0;

    let op = if is_write { FileOp::OpenWrite } else { FileOp::Open };

    if !path.is_empty() {
        container.record_file_access(&path, event.pid, op);

        // Record fd→path mapping. For AUDIT_SYSCALL, return_value is the new fd.
        if let Some(a) = args
            && a.return_value >= 0
        {
            container.fd_table.insert(
                (event.pid, a.return_value as u64),
                FdTarget::File(path.clone()),
            );
        }
    }

    let file_event = FileEvent {
        pid: event.pid,
        timestamp,
        operation: op,
        path,
        flags,
        is_sensitive,
        is_new_binary: false,
    };

    if let Some(action) = &mut container.current_action {
        action.record_file_event(file_event);
    }
}

fn handle_file_rw(
    container: &mut ContainerState,
    event: &SeccompEvent,
    op: FileOp,
    timestamp: u64,
) {


    let file_event = FileEvent {
        pid: event.pid,
        timestamp,
        operation: op,
        path: String::new(),
        flags: 0,
        is_sensitive: false,
        is_new_binary: false,
    };

    if let Some(action) = &mut container.current_action {
        action.record_file_event(file_event);
    }
}

fn handle_file_meta(
    container: &mut ContainerState,
    event: &SeccompEvent,
    op: FileOp,
    timestamp: u64,
    args: Option<&SyscallArgs>,
) {
    let path = args
        .and_then(|a| a.resolved_path.clone())
        .unwrap_or_default();

    if !path.is_empty() {
        container.record_file_access(&path, event.pid, op);
    }

    let file_event = FileEvent {
        pid: event.pid,
        timestamp,
        operation: op,
        path,
        flags: 0,
        is_sensitive: false,
        is_new_binary: false,
    };

    if let Some(action) = &mut container.current_action {
        action.record_file_event(file_event);
    }
}

fn handle_network(
    container: &mut ContainerState,
    event: &SeccompEvent,
    op: NetOp,
    timestamp: u64,
    args: Option<&SyscallArgs>,
) {
    let remote_addr = args.and_then(|a| a.resolved_addr.clone());

    // Record fd→network endpoint for connect/bind.
    // The socket fd is in args.raw[0] (first argument to connect/bind).
    if matches!(op, NetOp::Connect | NetOp::Bind)
        && let Some(a) = args
        && let Some(addr) = &remote_addr
    {
        container.fd_table.insert(
            (event.pid, a.raw[0]),
            FdTarget::Network(addr.clone()),
        );
    }

    let net_event = NetworkEvent {
        pid: event.pid,
        timestamp,
        operation: op,
        family: String::new(),
        local_addr: None,
        remote_addr,
        port: None,
        is_first_seen: false,
    };

    if let Some(action) = &mut container.current_action {
        action.record_net_event(net_event);
    }
}

fn handle_pipe(_container: &mut ContainerState, _event: &SeccompEvent, timestamp: u64) {
    // In LOG mode we can't track the fd pair. Just note pipe creation.
    // We could create a taint edge if we knew the child — deferred.
    let _ = timestamp;
}

fn handle_signal(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64) {


    let proc_event = ProcessEvent {
        pid: event.pid,
        timestamp,
        operation: ProcessOp::Signal,
        target_pid: None, // Unknown in LOG mode
        exe: event.exe.clone(),
        comm: event.comm.clone(),
    };

    if let Some(action) = &mut container.current_action {
        action.record_process_event(proc_event);
    }

    // In LOG mode we can't determine the target PID from the audit record,
    // so we can't create taint edges for signals.
}

/// Ensure a process is in the process table.
/// ppid is pre-resolved outside the lock by the daemon.
fn ensure_process(container: &mut ContainerState, event: &SeccompEvent, ppid: u32, cmdline: &str, open_files: &[String], net_connections: &[String]) {
    let pid = event.pid;
    let already_exists = container.process_table.processes.contains_key(&pid);

    if already_exists {
        // Update existing process (scoped borrow)
        {
            let info = container.process_table.processes.get_mut(&pid).unwrap();
            if !cmdline.is_empty() && cmdline != info.cmdline {
                info.cmdline = cmdline.to_string();
            }
            for f in open_files {
                if !info.open_files.contains(f) {
                    info.open_files.push(f.clone());
                }
            }
            for c in net_connections {
                if !info.net_connections.contains(c) {
                    info.net_connections.push(c.clone());
                }
            }
            if !event.comm.is_empty() {
                info.comm = event.comm.clone();
            }
            if !event.exe.is_empty() {
                info.exec_path = event.exe.clone();
            }
        }
        // Record open files in file graph (borrow on process_table released)
        for f in open_files {
            container.record_file_access(f, pid, FileOp::Open);
        }
        return;
    }

    let is_original = false;

    let parent_score = container.process_table.taint_score(ppid);
    let is_first_process = container.process_table.processes.is_empty();
    let has_active_action = container.current_action.is_some()
        && container.current_action_id > 0;

    // Taint model:
    //   - First process in container (sleep entrypoint): 0.0 (not agent-controlled)
    //   - Process appearing during an active action: 1.0 (agent directly ran this)
    //   - Child of a tainted process (fork): parent_score * 0.9
    //   - Process not during an action and no tainted parent: 0.0
    //
    // This means taint originates from agent actions and propagates through
    // IPC channels with decay. Pre-existing processes start clean and only
    // become tainted if the agent's influence reaches them.
    let taint_score = if is_first_process {
        0.0 // Container entrypoint (e.g., `sleep 300`) — not agent-controlled
    } else if has_active_action && parent_score == 0.0 {
        1.0 // New process during an agent action — directly agent-controlled
    } else {
        // Inherit from parent via fork decay
        parent_score * ChannelType::Fork.decay_factor()
    };

    let info = ProcessInfo {
        pid: event.pid,
        ppid,
        comm: event.comm.clone(),
        exec_path: event.exe.clone(),
        cmdline: cmdline.to_string(),
        open_files: open_files.to_vec(),
        net_connections: net_connections.to_vec(),
        taint_score,
        taint_source: if has_active_action && parent_score == 0.0 {
            format!("agent action #{}", container.current_action_id)
        } else if parent_score > 0.0 {
            format!("fork from pid {} (score {:.2})", ppid, taint_score)
        } else {
            String::new()
        },
        is_original,
        exited: false,
        children: Vec::new(),
    };
    container.process_table.add(info);

    // Record open files in the file graph
    for f in open_files {
        container.record_file_access(f, event.pid, FileOp::Open);
    }

    // Add fork edge only if the parent is actually in this container's process table.
    // docker exec processes have host-side parents (containerd-shim) that aren't in the
    // container — these show up as independent entry points, not children.
    if !is_first_process && container.process_table.processes.contains_key(&ppid) {
        container.taint_graph.add_edge(
            ppid,
            event.pid,
            format!("fork (child of pid {})", ppid),
            ChannelType::Fork,
            0,
        );

    }
}

