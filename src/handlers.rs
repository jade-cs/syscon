use crate::audit::SeccompEvent;
use crate::events::{FileEvent, FileOp, NetOp, NetworkEvent, ProcessEvent, ProcessOp};
use crate::state::{ChannelType, ContainerState, ProcessInfo};
use crate::syscalls;

/// Dispatch an audit event to the appropriate handler based on syscall number.
/// `ppid` and `cmdline` are resolved outside the lock by the daemon's event processor.
pub fn dispatch(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64, ppid: u32, cmdline: &str, open_files: &[String], net_connections: &[String]) {
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
            handle_open(container, event, timestamp);
        }
        "read" | "pread64" | "readv" | "preadv" | "preadv2" => {
            handle_file_rw(container, event, FileOp::Read, timestamp);
        }
        "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" => {
            handle_file_rw(container, event, FileOp::Write, timestamp);
        }
        "unlink" | "unlinkat" => {
            handle_file_meta(container, event, FileOp::Unlink, timestamp);
        }
        "rename" | "renameat" | "renameat2" => {
            handle_file_meta(container, event, FileOp::Rename, timestamp);
        }
        "chmod" | "fchmod" | "fchmodat" => {
            handle_file_meta(container, event, FileOp::Chmod, timestamp);
        }
        "chown" | "fchown" | "fchownat" => {
            handle_file_meta(container, event, FileOp::Chown, timestamp);
        }

        // Network
        "socket" => {
            handle_network(container, event, NetOp::Socket, timestamp);
        }
        "connect" => {
            handle_network(container, event, NetOp::Connect, timestamp);
        }
        "bind" => {
            handle_network(container, event, NetOp::Bind, timestamp);
        }
        "accept" | "accept4" => {
            handle_network(container, event, NetOp::Accept, timestamp);
        }
        "sendto" => {
            handle_network(container, event, NetOp::SendTo, timestamp);
        }
        "recvfrom" => {
            handle_network(container, event, NetOp::RecvFrom, timestamp);
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

        _ => {}
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
    } else {
    
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

fn handle_open(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64) {


    // In LOG mode we don't have the path argument — use exe as context.
    // The exe field tells us which binary is doing the open.
    let is_sensitive = false; // Can't determine without path arg
    let file_event = FileEvent {
        pid: event.pid,
        timestamp,
        operation: FileOp::Open,
        path: String::new(), // Unknown in LOG mode
        flags: 0,
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

fn handle_network(
    container: &mut ContainerState,
    event: &SeccompEvent,
    op: NetOp,
    timestamp: u64,
) {


    let net_event = NetworkEvent {
        pid: event.pid,
        timestamp,
        operation: op,
        family: String::new(), // Unknown in LOG mode
        local_addr: None,
        remote_addr: None,
        port: None,
        is_first_seen: false,
    };

    if let Some(action) = &mut container.current_action {
        action.record_net_event(net_event);
    }
}

fn handle_pipe(container: &mut ContainerState, event: &SeccompEvent, timestamp: u64) {

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

    let parent_tainted = container.process_table.is_tainted(ppid);
    let is_root = container.process_table.processes.is_empty();
    // Any process entering this container's namespace is considered influenced
    // (the agent controls the container). Also mark first process as root.
    let any_tainted = container.process_table.processes.values().any(|p| p.tainted);
    let tainted = is_root || parent_tainted || any_tainted;

    let info = ProcessInfo {
        pid: event.pid,
        ppid,
        comm: event.comm.clone(),
        exec_path: event.exe.clone(),
        cmdline: cmdline.to_string(),
        open_files: open_files.to_vec(),
        net_connections: net_connections.to_vec(),
        tainted,
        taint_source: if is_root {
            "container entry point".to_string()
        } else if parent_tainted {
            format!("fork from pid {}", ppid)
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
    if !is_root && container.process_table.processes.contains_key(&ppid) {
        container.taint_graph.add_edge(
            ppid,
            event.pid,
            format!("fork (child of pid {})", ppid),
            ChannelType::Fork,
            0,
        );
    }
}

/// Read the parent PID from /proc/{pid}/status.
fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse().ok();
        }
    }
    None
}
