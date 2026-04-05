use crate::events::{FileEvent, FileOp, NetOp, NetworkEvent, ProcessEvent, ProcessOp};
use crate::ingest::{SyscallDetail, SyscallEvent};
use crate::state::{ChannelType, ContainerState, FdTarget, ProcessInfo};
use crate::syscalls;

/// Dispatch a syscall event to the appropriate handler.
pub fn dispatch(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    ensure_process(container, ev);

    let name = syscalls::name(ev.syscall);
    match name {
        // Process lifecycle
        "clone" | "clone3" | "fork" | "vfork" => handle_fork(container, ev, timestamp),
        "execve" | "execveat" => handle_exec(container, ev, timestamp),
        "exit_group" => handle_exit(container, ev, timestamp),

        // File operations -- resolved args come from SyscallDetail::File
        "open" | "openat" | "openat2" | "creat" => handle_open(container, ev, timestamp),
        "read" | "pread64" | "readv" | "preadv" | "preadv2" => {
            handle_file_rw(container, ev, FileOp::Read, timestamp);
        }
        "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" => {
            handle_file_rw(container, ev, FileOp::Write, timestamp);
        }
        "unlink" | "unlinkat" => handle_file_meta(container, ev, FileOp::Unlink, timestamp),
        "rename" | "renameat" | "renameat2" => handle_file_meta(container, ev, FileOp::Rename, timestamp),
        "chmod" | "fchmod" | "fchmodat" => handle_file_meta(container, ev, FileOp::Chmod, timestamp),
        "chown" | "fchown" | "fchownat" => handle_file_meta(container, ev, FileOp::Chown, timestamp),

        // Network
        "socket" => handle_network(container, ev, NetOp::Socket, timestamp),
        "connect" => handle_network(container, ev, NetOp::Connect, timestamp),
        "bind" => handle_network(container, ev, NetOp::Bind, timestamp),
        "accept" | "accept4" => handle_network(container, ev, NetOp::Accept, timestamp),
        "sendto" => handle_network(container, ev, NetOp::SendTo, timestamp),
        "sendmsg" => handle_network(container, ev, NetOp::SendTo, timestamp),
        "recvfrom" => handle_network(container, ev, NetOp::RecvFrom, timestamp),
        "recvmsg" => handle_network(container, ev, NetOp::RecvFrom, timestamp),
        "sendmmsg" => handle_network(container, ev, NetOp::SendTo, timestamp),
        "recvmmsg" => handle_network(container, ev, NetOp::RecvFrom, timestamp),

        // IPC
        "pipe" | "pipe2" => {}
        "dup" | "dup2" | "dup3" => {}
        "kill" | "tgkill" => handle_signal(container, ev, timestamp),

        // Shared memory / memfd / ptrace
        "shmget" | "shmat" | "shmdt" => {}
        // SysV message queues
        "msgget" => handle_ipc_open(container, ev, timestamp),
        "msgsnd" => handle_ipc_send(container, ev, timestamp),
        "msgrcv" => handle_ipc_recv(container, ev, timestamp),
        // POSIX message queues
        "mq_open" => handle_mq_open(container, ev, timestamp),
        "mq_timedsend" => handle_ipc_send(container, ev, timestamp),
        "mq_timedreceive" => handle_ipc_recv(container, ev, timestamp),
        "memfd_create" => handle_memfd(container, ev, timestamp),
        "ptrace" => handle_ptrace(container, ev, timestamp),

        // Kernel-space fd-to-fd transfers
        "sendfile" | "splice" | "tee" | "copy_file_range" => {
            handle_kernel_transfer(container, ev, name, timestamp);
        }

        _ => {}
    }
}

fn handle_memfd(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Fork,
        target_pid: None,
        exe: ev.exe.to_string(),
        comm: ev.comm.as_str().to_string(),
    };
    container.record_process_event(ev.pid, proc_event);
}

fn handle_kernel_transfer(
    container: &mut ContainerState,
    ev: &SyscallEvent,
    syscall_name: &str,
    timestamp: u64,
) {
    let (src_fd, dst_fd) = match &ev.detail {
        SyscallDetail::Transfer { src_fd, dst_fd } => (Some(*src_fd), Some(*dst_fd)),
        _ => (None, None),
    };

    let src_target = src_fd.and_then(|fd| container.fd_table.get(&(ev.pid, fd)).cloned());
    let dst_target = dst_fd.and_then(|fd| container.fd_table.get(&(ev.pid, fd)).cloned());

    let src_desc = fd_target_desc(&src_target, src_fd);
    let dst_desc = fd_target_desc(&dst_target, dst_fd);

    let path = if !src_desc.is_empty() && !dst_desc.is_empty() {
        format!("(kernel:{syscall_name} {src_desc} → {dst_desc})")
    } else {
        format!("(kernel:{syscall_name})")
    };

    if let Some(FdTarget::File(ref src_path)) = src_target {
        container.record_file_access(src_path, ev.pid, FileOp::Read);
    }

    let file_event = FileEvent {
        pid: ev.pid,
        timestamp,
        operation: FileOp::Read,
        path,
        flags: 0,
        is_sensitive: false,
        is_new_binary: false,
    };
    container.record_file_event(ev.pid, file_event);
}

fn fd_target_desc(target: &Option<FdTarget>, fd: Option<u64>) -> String {
    match target {
        Some(FdTarget::File(p)) => p.clone(),
        Some(FdTarget::Network(a)) => format!("net:{a}"),
        Some(FdTarget::Ipc(name)) => format!("mq:{name}"),
        None => fd.map(|fd| format!("fd:{fd}")).unwrap_or_default(),
    }
}

fn handle_ptrace(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Signal,
        target_pid: None,
        exe: ev.exe.to_string(),
        comm: ev.comm.as_str().to_string(),
    };
    container.record_process_event(ev.pid, proc_event);
}

fn handle_fork(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Fork,
        target_pid: None,
        exe: ev.exe.to_string(),
        comm: ev.comm.as_str().to_string(),
    };
    container.record_process_event(ev.pid, proc_event);
}

fn handle_exec(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    // Prefer the kernel-resolved path from AUDIT_PATH over ev.exe (from /proc/pid/exe).
    // For short-lived processes, /proc/pid/exe may be gone but the audit record has it.
    let exe_str = match &ev.detail {
        SyscallDetail::Exec { path: Some(p), .. } if !p.is_empty() => p.to_string(),
        _ => ev.exe.to_string(),
    };

    if let Some(info) = container.process_table.processes.get_mut(&ev.pid) {
        info.exec_path = exe_str.clone();
        info.comm = ev.comm.as_str().to_string();
    }

    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Exec,
        target_pid: None,
        exe: exe_str.clone(),
        comm: ev.comm.as_str().to_string(),
    };

    let file_event = FileEvent {
        pid: ev.pid,
        timestamp,
        operation: FileOp::Exec,
        path: exe_str.clone(),
        flags: 0,
        is_sensitive: false,
        is_new_binary: false,
    };

    container.record_file_access(&exe_str, ev.pid, FileOp::Exec);
    container.record_process_event(ev.pid, proc_event);
    container.record_file_event(ev.pid, file_event);
}

fn handle_exit(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Exit,
        target_pid: None,
        exe: ev.exe.to_string(),
        comm: ev.comm.as_str().to_string(),
    };
    container.record_process_event(ev.pid, proc_event);
    if let Some(info) = container.process_table.processes.get_mut(&ev.pid) {
        info.exited = true;
    }
    // Clean up fd_table entries for the exiting process.
    // Without this, stale (pid, fd) → path mappings accumulate if PIDs
    // are reused by long-lived containers.
    container.fd_table.retain(|(pid, _), _| *pid != ev.pid);
}

fn handle_open(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let (path, flags, ret) = match &ev.detail {
        SyscallDetail::File { path, flags, ret, .. } => {
            (path.to_string(), *flags as u32, *ret)
        }
        _ => (String::new(), 0, -1),
    };

    let is_sensitive = !path.is_empty() && container.baseline.is_sensitive(&path);
    let is_write = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32 | libc::O_CREAT as u32 | libc::O_TRUNC as u32) != 0;
    let op = if is_write { FileOp::OpenWrite } else { FileOp::Open };

    if !path.is_empty() {
        container.record_file_access(&path, ev.pid, op);

        if let Some(info) = container.process_table.processes.get_mut(&ev.pid)
            && !info.open_files.contains(&path)
        {
            info.open_files.push(path.clone());
        }

        if ret >= 0 {
            container.fd_table.insert(
                (ev.pid, ret as u64),
                FdTarget::File(path.clone()),
            );
        }
    }

    let file_event = FileEvent {
        pid: ev.pid,
        timestamp,
        operation: op,
        path,
        flags,
        is_sensitive,
        is_new_binary: false,
    };
    container.record_file_event(ev.pid, file_event);
}

fn handle_file_rw(
    container: &mut ContainerState,
    ev: &SyscallEvent,
    op: FileOp,
    timestamp: u64,
) {
    let file_event = FileEvent {
        pid: ev.pid,
        timestamp,
        operation: op,
        path: String::new(),
        flags: 0,
        is_sensitive: false,
        is_new_binary: false,
    };
    container.record_file_event(ev.pid, file_event);
}

fn handle_file_meta(
    container: &mut ContainerState,
    ev: &SyscallEvent,
    op: FileOp,
    timestamp: u64,
) {
    let path = match &ev.detail {
        SyscallDetail::File { path, .. } => path.to_string(),
        _ => String::new(),
    };

    if !path.is_empty() {
        container.record_file_access(&path, ev.pid, op);
    }

    let file_event = FileEvent {
        pid: ev.pid,
        timestamp,
        operation: op,
        path,
        flags: 0,
        is_sensitive: false,
        is_new_binary: false,
    };
    container.record_file_event(ev.pid, file_event);
}

fn handle_network(
    container: &mut ContainerState,
    ev: &SyscallEvent,
    op: NetOp,
    timestamp: u64,
) {
    let (remote_addr_str, fd) = match &ev.detail {
        SyscallDetail::Network { target, fd } => (Some(target.display_addr()), Some(*fd)),
        _ => (None, None),
    };

    // Record fd→network endpoint for connect/bind
    if matches!(op, NetOp::Connect | NetOp::Bind)
        && let Some(ref addr) = remote_addr_str
        && let Some(fd) = fd
    {
        container.fd_table.insert(
            (ev.pid, fd),
            FdTarget::Network(addr.clone()),
        );
    }

    // Add to process net_connections for receipt display
    if let Some(ref addr) = remote_addr_str
        && let Some(info) = container.process_table.processes.get_mut(&ev.pid)
    {
        let conn_str = match op {
            NetOp::Connect | NetOp::SendTo => format!("connect {addr}"),
            NetOp::Bind => format!("listen {addr}"),
            _ => String::new(),
        };
        if !conn_str.is_empty() && !info.net_connections.contains(&conn_str) {
            info.net_connections.push(conn_str);
        }
    }

    let net_event = NetworkEvent {
        pid: ev.pid,
        timestamp,
        operation: op,
        remote_addr: remote_addr_str,
    };
    container.record_net_event(ev.pid, net_event);
}

fn handle_signal(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Signal,
        target_pid: None,
        exe: ev.exe.to_string(),
        comm: ev.comm.as_str().to_string(),
    };
    container.record_process_event(ev.pid, proc_event);
}

fn handle_ipc_open(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let channel = match &ev.detail {
        SyscallDetail::Ipc { channel, .. } => channel.clone(),
        _ => return,
    };

    // Record as both potential sender and receiver (opener may do either)
    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Signal, // reuse Signal for IPC events in action log
        target_pid: None,
        exe: ev.exe.to_string(),
        comm: ev.comm.as_str().to_string(),
    };
    container.record_process_event(ev.pid, proc_event);

    // Ensure the IpcNode exists for this channel
    container
        .ipc_nodes
        .entry(channel)
        .or_insert_with(crate::state::IpcNode::new);
}

fn handle_mq_open(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let (channel, fd) = match &ev.detail {
        SyscallDetail::Ipc { channel, fd } => (channel.clone(), *fd),
        _ => return,
    };

    // Register the fd → IPC channel mapping for later mq_timedsend/recv lookup
    if fd >= 0 && !channel.is_empty() {
        container.fd_table.insert(
            (ev.pid, fd as u64),
            FdTarget::Ipc(channel.clone()),
        );
    }

    handle_ipc_open(container, ev, timestamp);
}

fn handle_ipc_send(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let channel = resolve_ipc_channel(container, ev);
    if channel.is_empty() {
        return;
    }

    container.record_ipc_send(&channel, ev.pid);

    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Signal,
        target_pid: None,
        exe: ev.exe.to_string(),
        comm: ev.comm.as_str().to_string(),
    };
    container.record_process_event(ev.pid, proc_event);
}

fn handle_ipc_recv(container: &mut ContainerState, ev: &SyscallEvent, timestamp: u64) {
    let channel = resolve_ipc_channel(container, ev);
    if channel.is_empty() {
        return;
    }

    container.record_ipc_recv(&channel, ev.pid);

    let proc_event = ProcessEvent {
        pid: ev.pid,
        timestamp,
        operation: ProcessOp::Signal,
        target_pid: None,
        exe: ev.exe.to_string(),
        comm: ev.comm.as_str().to_string(),
    };
    container.record_process_event(ev.pid, proc_event);
}

/// Resolve the IPC channel name from the event detail.
/// For SysV (msgget/msgsnd/msgrcv), the channel is in the detail directly.
/// For POSIX mq (mq_timedsend/recv), the fd must be looked up in the fd_table.
fn resolve_ipc_channel(container: &ContainerState, ev: &SyscallEvent) -> String {
    match &ev.detail {
        SyscallDetail::Ipc { channel, fd } => {
            if !channel.is_empty() {
                return channel.clone();
            }
            // Empty channel means we need fd lookup (POSIX mq_timedsend/recv)
            if *fd >= 0 {
                if let Some(FdTarget::Ipc(name)) = container.fd_table.get(&(ev.pid, *fd as u64)) {
                    return name.clone();
                }
            }
            String::new()
        }
        _ => String::new(),
    }
}

/// Ensure a process is in the process table.
fn ensure_process(container: &mut ContainerState, ev: &SyscallEvent) {
    let pid = ev.pid;
    let ppid = ev.ppid;
    let cmdline_str = ev.cmdline.to_string();
    let exe_str = ev.exe.to_string();
    let comm_str = ev.comm.as_str().to_string();

    let already_exists = container.process_table.processes.contains_key(&pid);

    if already_exists {
        let info = container.process_table.processes.get_mut(&pid).unwrap();
        if !cmdline_str.is_empty() && cmdline_str != info.cmdline {
            info.cmdline = cmdline_str;
        }
        if !comm_str.is_empty() {
            info.comm = comm_str;
        }
        if !exe_str.is_empty() {
            info.exec_path = exe_str;
        }
        return;
    }

    let parent_score = container.process_table.taint_score(ppid);
    let is_first_process = container.process_table.processes.is_empty();
    let has_active_action = container.current_action.is_some()
        && container.current_action_id > 0;

    let taint_score = if is_first_process {
        0.0
    } else if has_active_action && parent_score == 0.0 {
        1.0
    } else {
        parent_score * ChannelType::Fork.decay_factor()
    };

    // Attribution follows causality:
    // 1. Use the audit record's wall-clock timestamp to determine which
    //    action was active when the syscall actually happened (not when
    //    the daemon processed it). This fixes events leaking across
    //    action boundaries due to the 200ms batch processing interval.
    // 2. If the parent has an attributed action, inherit it (fork inheritance).
    //    A `find / &` from action 1 stays attributed to action 1.
    // 3. Fall back to current_action_id for processes without audit timestamps.
    let attributed_action = if let Some(parent) = container.process_table.get(&ppid) {
        parent.attributed_action
    } else {
        container.action_at_time(ev.timestamp_ms)
    };

    let info = ProcessInfo {
        pid,
        ppid,
        comm: comm_str,
        exec_path: exe_str,
        cmdline: cmdline_str,
        open_files: Vec::new(),
        net_connections: Vec::new(),
        taint_score,
        taint_source: if has_active_action && parent_score == 0.0 {
            format!("agent action #{}", container.current_action_id)
        } else if parent_score > 0.0 {
            format!("fork from pid {} (score {:.2})", ppid, taint_score)
        } else {
            String::new()
        },
        exited: false,
        children: Vec::new(),
        attributed_action,
    };
    container.process_table.add(info);

    if !is_first_process && container.process_table.processes.contains_key(&ppid) {
        container.taint_graph.add_edge(
            ppid,
            ev.pid,
            format!("fork (child of pid {})", ppid),
            ChannelType::Fork,
            0,
        );
    }
}
