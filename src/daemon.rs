use std::sync::{Arc, Mutex as StdMutex};

use anyhow::Result;
use tokio::sync::Mutex;

use crate::{audit, audit_rules, binlog, control, handlers, notifier, util};
use crate::state::DaemonState;

pub struct DaemonConfig {
    pub port: u16,
    /// If set, write a binary syscall log to this path.
    pub log_file: Option<String>,
    /// If set, listen on this Unix socket for seccomp user notify fds.
    pub notify_socket: Option<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            port: 9900,
            log_file: None,
            notify_socket: None,
        }
    }
}

/// A resolved audit event with pre-resolved /proc data.
struct ResolvedEvent {
    event: audit::SeccompEvent,
    container_id: Option<String>,
    ppid: u32,
    cmdline: String,
    open_files: Vec<String>,
    net_connections: Vec<String>,
    /// Pipe inode numbers from /proc/pid/fd (e.g., "pipe:[12345]" → 12345).
    /// Used to create Pipe taint edges between processes sharing the same pipe.
    pipe_inodes: Vec<u64>,
    /// Resolved syscall arguments (populated in USER_NOTIF mode).
    args: Option<binlog::SyscallArgs>,
}

pub async fn run(config: DaemonConfig) -> Result<()> {
    let audit_fd = audit::open_audit_socket()?;
    audit::set_recv_timeout(audit_fd, 50);

    let state = Arc::new(Mutex::new(DaemonState::new()));

    tracing::info!("syscon daemon starting");
    tracing::info!(fd = audit_fd, "audit socket opened");

    // Install AUDIT_SYSCALL rules for path-bearing syscalls (hybrid mode).
    // These give us resolved filenames and socket addresses from the kernel,
    // eliminating the need for /proc/pid/fd reads on those syscalls.
    match audit_rules::install_rules(audit_fd) {
        Ok(n) => tracing::info!(rules = n, "hybrid audit rules installed"),
        Err(e) => tracing::warn!("could not install audit rules (need CAP_AUDIT_CONTROL): {}", e),
    }

    // Optional binary log writer
    let log_writer: Option<Arc<binlog::LogWriter>> = match &config.log_file {
        Some(path) => {
            let writer = binlog::LogWriter::open(
                std::path::Path::new(path),
                binlog::FLAG_AUDIT_MODE,
            )?;
            tracing::info!(path = %path, "binary log file opened");
            Some(Arc::new(writer))
        }
        None => None,
    };

    // Resolved event buffer: the audit thread does recv + PID resolution,
    // then pushes fully resolved events here. The async processor just
    // does fast in-memory dispatch — no /proc I/O.
    let event_buf: Arc<StdMutex<Vec<ResolvedEvent>>> =
        Arc::new(StdMutex::new(Vec::with_capacity(256)));

    // Clone for notifier (if enabled)
    let event_buf_for_notify = event_buf.clone();

    // Audit thread: recv + resolve PIDs (all /proc I/O here, on a dedicated OS thread)
    let buf_writer = event_buf.clone();
    std::thread::Builder::new()
        .name("audit-recv".into())
        .spawn(move || {
            audit_recv_loop(audit_fd, buf_writer);
            unsafe { libc::close(audit_fd); }
        })?;

    // Async processor: drains resolved events every 200ms, updates state
    let process_state = state.clone();
    let buf_reader = event_buf;
    let processor_log = log_writer.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));
        // Track pipe inodes → (pid, container_id, ppid) for creating Pipe taint edges
        // between sibling processes sharing the same pipe inode.
        let mut pipe_registry: std::collections::HashMap<u64, (u32, String, u32)> = std::collections::HashMap::new();
        loop {
            interval.tick().await;

            // Drain buffer (StdMutex, held < 1us for a swap)
            let batch: Vec<ResolvedEvent> = {
                let mut buf = buf_reader.lock().unwrap_or_else(|e| e.into_inner());
                std::mem::take(&mut *buf)
            };

            if batch.is_empty() {
                continue;
            }

            tracing::debug!(events = batch.len(), "processing batch");

            let timestamp = util::monotonic_ns();

            // Write to binary log (non-blocking, just sends to channel)
            if let Some(writer) = &processor_log {
                for rev in &batch {
                    writer.send(binlog::LogEntry::Syscall(Box::new(binlog::SyscallRecord {
                        timestamp_ns: timestamp,
                        wall_clock_ns: 0, // TODO: add wall clock
                        pid: rev.event.pid,
                        syscall_nr: rev.event.syscall,
                        comm: rev.event.comm.clone(),
                        exe: rev.event.exe.clone(),
                        container_id: rev.container_id.clone(),
                        ppid: rev.ppid,
                        cmdline: rev.cmdline.clone(),
                        open_files: rev.open_files.clone(),
                        net_connections: rev.net_connections.clone(),
                        args: None, // LOG mode — no arguments
                    })));
                }
            }

            // Update state (tokio::Mutex — cooperates with Rocket).
            // Process in chunks to avoid holding the lock too long during
            // large batches, allowing API requests to interleave.
            for chunk in batch.chunks(32) {
                let mut state = process_state.lock().await;
                for rev in chunk {
                    let Some(cid) = &rev.container_id else { continue };
                    if !state.containers.contains_key(cid) {
                        state.containers.insert(
                            cid.clone(),
                            crate::state::ContainerState::new(
                                cid.clone(),
                                crate::state::ContainerBaseline::new(),
                            ),
                        );
                    }
                    let container = state.containers.get_mut(cid).unwrap();
                    handlers::dispatch(container, &rev.event, timestamp, rev.ppid, &rev.cmdline, &rev.open_files, &rev.net_connections, rev.args.as_ref());

                    // Create Pipe taint edges from shared pipe inodes.
                    // Only match sibling processes (same parent) that are NOT
                    // shells — this captures pipeline data flow (cat | base64 | gzip)
                    // while skipping shell plumbing and docker exec stdio pipes.
                    let is_shell = matches!(
                        rev.event.comm.as_str(),
                        "sh" | "bash" | "dash" | "ash" | "zsh"
                    );
                    if !is_shell {
                        for &inode in &rev.pipe_inodes {
                            if let Some((other_pid, other_cid, other_ppid)) = pipe_registry.remove(&inode) {
                                // Only connect siblings (same parent = same pipeline)
                                if other_pid != rev.event.pid
                                    && other_cid == *cid
                                    && other_ppid == rev.ppid
                                {
                                    container.taint_graph.add_edge(
                                        other_pid,
                                        rev.event.pid,
                                        format!("pipe:[{}]", inode),
                                        crate::state::ChannelType::Pipe,
                                        timestamp,
                                    );
                                }
                            } else {
                                pipe_registry.insert(inode, (rev.event.pid, cid.clone(), rev.ppid));
                            }
                        }
                    }
                }
            }
        }
    });
    tracing::info!("audit event processor started");

    // Optional: seccomp user notify listener (USER_NOTIF mode)
    let _notifier_handle = if let Some(socket_path) = &config.notify_socket {
        let notify_buf = event_buf_for_notify.clone();
        let socket_path = socket_path.clone();

        let listener = notifier::NotifierListener::start(
            notifier::NotifierConfig {
                socket_path: std::path::PathBuf::from(&socket_path),
            },
            move |container_id, event| {
                // Convert NotifyEvent into a ResolvedEvent and push to the
                // shared buffer, just like the audit thread does.
                let ppid = util::read_ppid(event.pid).unwrap_or(0);
                let cmdline = read_cmdline(event.pid);
                let (open_files, pipe_inodes) = read_open_files(event.pid);
                let net_connections = Vec::new(); // TODO: read if needed

                let audit_event = crate::audit::SeccompEvent {
                    pid: event.pid,
                    comm: event.comm,
                    exe: event.exe,
                    syscall: event.syscall_nr,
                    arch: 0,
                    ip: 0,
                    code: 0x7FC0_0000, // SECCOMP_RET_USER_NOTIF
                    sig: 0,
                };

                let resolved = ResolvedEvent {
                    event: audit_event,
                    container_id: Some(container_id),
                    ppid,
                    cmdline,
                    open_files,
                    net_connections,
                    pipe_inodes,
                    args: event.args,
                };

                let mut buf = notify_buf.lock().unwrap_or_else(|e| e.into_inner());
                buf.push(resolved);
            },
        )
        .map_err(|e| anyhow::anyhow!("failed to start notifier: {}", e))?;

        tracing::info!(socket = %socket_path, "seccomp user notify listener started");
        Some(listener)
    } else {
        None
    };

    // Rocket HTTP server
    let figment = rocket::Config::figment()
        .merge(("port", config.port))
        .merge(("address", "0.0.0.0"))
        .merge(("log_level", "off"));

    let rocket = control::rocket(state, log_writer)
        .configure(figment)
        .ignite()
        .await
        .map_err(|e| anyhow::anyhow!("rocket ignite failed: {}", e))?;

    tracing::info!(port = config.port, "HTTP server listening");

    rocket
        .launch()
        .await
        .map_err(|e| anyhow::anyhow!("rocket launch failed: {}", e))?;

    Ok(())
}

/// Blocking audit loop on a dedicated OS thread.
/// Does recv + PID/ppid resolution (all /proc I/O), then pushes resolved events.
/// Look up a container ID for a pid, walking up the ppid chain if the process
/// has already exited and /proc/pid/cgroup is gone. This handles short-lived
/// processes like `cat /etc/passwd` whose cgroup file disappears before we
/// can read it — we find their parent's container instead.
fn resolve_container(
    pid: u32,
    ppid_hint: u32,
    pid_cache: &mut std::collections::HashMap<u32, Option<String>>,
    ppid_cache: &std::collections::HashMap<u32, u32>,
) -> Option<String> {
    // Direct lookup first
    if let Some(cached) = pid_cache.get(&pid) {
        return cached.clone();
    }

    // Try reading /proc/pid/cgroup directly
    if let Some(info) = crate::docker::container_from_pid(pid) {
        pid_cache.insert(pid, Some(info.id.clone()));
        return Some(info.id);
    }

    // Process might be dead — walk up ppid chain
    let mut current = if ppid_hint > 0 { ppid_hint } else {
        ppid_cache.get(&pid).copied().unwrap_or(0)
    };
    for _ in 0..10 {
        if current == 0 || current == 1 {
            break;
        }
        // Check cache (clone to release borrow)
        let cached_result = pid_cache.get(&current).cloned();
        if let Some(Some(cid)) = cached_result {
            pid_cache.insert(pid, Some(cid.clone()));
            return Some(cid);
        }
        // Try this ancestor's cgroup
        if let Some(info) = crate::docker::container_from_pid(current) {
            pid_cache.insert(current, Some(info.id.clone()));
            pid_cache.insert(pid, Some(info.id.clone()));
            return Some(info.id);
        }
        // Go up one more level
        current = ppid_cache.get(&current).copied()
            .or_else(|| util::read_ppid(current))
            .unwrap_or(0);
    }

    pid_cache.insert(pid, None);
    None
}

fn audit_recv_loop(fd: libc::c_int, buf: Arc<StdMutex<Vec<ResolvedEvent>>>) {
    let mut pid_cache: std::collections::HashMap<u32, Option<String>> =
        std::collections::HashMap::new();
    let mut ppid_cache: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::new();
    let mut cmdline_cache: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();
    let mut files_cache: std::collections::HashMap<u32, (Vec<String>, Vec<u64>)> =
        std::collections::HashMap::new();

    // Accumulator for multi-record AUDIT_SYSCALL events, keyed by serial number.
    let mut pending_events: std::collections::HashMap<u64, audit_rules::AuditSyscallEvent> =
        std::collections::HashMap::new();

    loop {
        match audit::try_recv(fd) {
            Ok(audit::RecvResult::Raw { msg_type, text }) => {
                // Multi-record audit event (AUDIT_SYSCALL + PATH + SOCKADDR + EOE)
                let serial = audit_rules::parse_serial(&text).unwrap_or(0);
                if serial == 0 {
                    continue;
                }

                let event = pending_events
                    .entry(serial)
                    .or_default();

                match msg_type {
                    audit_rules::AUDIT_SYSCALL_TYPE => {
                        event.serial = serial;
                        audit_rules::parse_syscall_record(&text, event);
                    }
                    audit_rules::AUDIT_PATH_TYPE => {
                        audit_rules::parse_path_record(&text, event);
                    }
                    audit_rules::AUDIT_CWD_TYPE => {
                        audit_rules::parse_cwd_record(&text, event);
                    }
                    audit_rules::AUDIT_SOCKADDR_TYPE => {
                        audit_rules::parse_sockaddr_record(&text, event);
                    }
                    audit_rules::AUDIT_EXECVE_TYPE => {
                        audit_rules::parse_execve_record(&text, event);
                    }
                    audit_rules::AUDIT_EOE_TYPE => {
                        // End of event — process the complete event
                        if let Some(mut complete) = pending_events.remove(&serial) {
                            complete.complete = true;
                            // Process both successful AND failed syscalls —
                            // failed connects still have SOCKADDR with target IP,
                            // failed opens still have PATH records.
                            if complete.pid > 0 && (complete.success || complete.sockaddr.is_some()) {
                                // Build SyscallArgs from the resolved data
                                let args = binlog::SyscallArgs {
                                    raw: [complete.a0, complete.a1, complete.a2, complete.a3, 0, 0],
                                    resolved_path: complete.paths.first().cloned(),
                                    resolved_path2: complete.paths.get(1).cloned(),
                                    resolved_addr: complete.sockaddr.clone(),
                                    flags: complete.a2,
                                    return_value: complete.exit_value,
                                };

                                // Cache the ppid from the audit record (always available,
                                // even if the process already exited)
                                if complete.ppid > 0 {
                                    ppid_cache.insert(complete.pid, complete.ppid);
                                }
                                let ppid = complete.ppid;

                                let container_id = resolve_container(
                                    complete.pid, ppid, &mut pid_cache, &ppid_cache,
                                );

                                cmdline_cache.entry(complete.pid).or_insert_with(|| {
                                    if !complete.argv.is_empty() {
                                        complete.argv.join(" ")
                                    } else {
                                        read_cmdline(complete.pid)
                                    }
                                });

                                // For AUDIT_SYSCALL events, we get paths from the kernel —
                                // no need to read /proc/pid/fd for these syscalls.
                                let cmdline = cmdline_cache.get(&complete.pid).cloned().unwrap_or_default();

                                let audit_event = crate::audit::SeccompEvent {
                                    pid: complete.pid,
                                    comm: complete.comm,
                                    exe: complete.exe,
                                    syscall: complete.syscall,
                                    arch: 0,
                                    ip: 0,
                                    code: 0,
                                    sig: 0,
                                };

                                let mut b = buf.lock().unwrap_or_else(|e| e.into_inner());
                                b.push(ResolvedEvent {
                                    event: audit_event,
                                    container_id,
                                    ppid,
                                    cmdline,
                                    open_files: complete.paths.clone(), // Use kernel-resolved paths
                                    net_connections: Vec::new(),
                                    pipe_inodes: Vec::new(), // Audit records don't have pipe info
                                    args: Some(args),
                                });
                            }
                        }
                    }
                    _ => {} // PROCTITLE etc — ignore
                }

                // Garbage collect stale pending events (older than 100 entries)
                if pending_events.len() > 200 {
                    let cutoff = serial.saturating_sub(100);
                    pending_events.retain(|s, _| *s > cutoff);
                }
            }
            Ok(audit::RecvResult::Event(event)) => {
                // Resolve ppid first, then drop the borrow before resolving container
                let ppid = *ppid_cache
                    .entry(event.pid)
                    .or_insert_with(|| util::read_ppid(event.pid).unwrap_or(0));

                let container_id = resolve_container(
                    event.pid, ppid, &mut pid_cache, &ppid_cache,
                );

                // With hybrid audit mode, AUDIT_SYSCALL records give us
                // resolved paths for file syscalls and addresses for network
                // syscalls. The SECCOMP event path only needs:
                // - cmdline (once per pid, on exec)
                // - open fds (once per pid, for pipe inode detection)
                // No per-syscall /proc/pid/fd rescans or /proc/pid/net parses.
                let syscall_name = crate::syscalls::name(event.syscall);
                let is_exec = matches!(syscall_name, "execve" | "execveat");
                if is_exec || !cmdline_cache.contains_key(&event.pid) {
                    cmdline_cache.insert(event.pid, read_cmdline(event.pid));
                }
                // Read fds: on exec (new process image) and on first sight.
                // Also refresh on file-open syscalls so we catch files opened
                // after the initial snapshot (e.g., python3 opens api_tokens.json
                // after it's already been running).
                let refresh_fds = is_exec
                    || !files_cache.contains_key(&event.pid)
                    || matches!(syscall_name, "openat" | "open" | "openat2");
                if refresh_fds {
                    files_cache.insert(event.pid, read_open_files(event.pid));
                }

                let cmdline = cmdline_cache.get(&event.pid).cloned().unwrap_or_default();
                let (open_files, pipe_inodes) = files_cache.get(&event.pid).cloned().unwrap_or_default();
                // Network connections: only read on accept (for listen detection).
                // connect/bind addresses come from AUDIT_SOCKADDR records.
                let net_connections = if matches!(syscall_name, "accept" | "accept4") {
                    read_net_connections(event.pid, true)
                } else {
                    Vec::new()
                };

                let mut b = buf.lock().unwrap_or_else(|e| e.into_inner());
                b.push(ResolvedEvent {
                    event,
                    container_id,
                    ppid,
                    cmdline,
                    open_files,
                    net_connections,
                    pipe_inodes,
                    args: None, // LOG mode — no arguments
                });
            }
            Ok(audit::RecvResult::Filtered | audit::RecvResult::WouldBlock) => {}
            Err(e) => {
                tracing::error!("audit recv error: {:#}", e);
                return;
            }
        }
    }
}

/// Read open file descriptors for a process via /proc/{pid}/fd/.
/// Returns (files, pipe_inodes): deduplicated file paths and pipe inode numbers.
fn read_open_files(pid: u32) -> (Vec<String>, Vec<u64>) {
    let fd_dir = format!("/proc/{}/fd", pid);
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let mut files = Vec::new();
    let mut pipes = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for entry in entries.flatten() {
        let link = match std::fs::read_link(entry.path()) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        // Extract pipe inodes for inter-process pipe tracking
        if let Some(rest) = link.strip_prefix("pipe:[")
            && let Some(inode_str) = rest.strip_suffix(']')
            && let Ok(inode) = inode_str.parse::<u64>()
        {
            if !pipes.contains(&inode) {
                pipes.push(inode);
            }
            continue;
        }
        // Skip non-file entries
        if link.starts_with("anon_inode:")
            || link == "/dev/null"
            || link.starts_with("/dev/pts/")
            || link.starts_with("socket:")
        {
            continue;
        }
        if seen.insert(link.clone()) {
            files.push(link);
        }
    }
    (files, pipes)
}

/// Read active network connections for a process from /proc/{pid}/net/tcp and tcp6.
/// Returns strings like "connect 93.184.216.34:80", "listen 0.0.0.0:8080".
fn read_net_connections(pid: u32, include_listen: bool) -> Vec<String> {
    let mut conns = Vec::new();

    // First, get socket inodes from /proc/{pid}/fd/ to know which sockets belong to this process
    let mut process_inodes = std::collections::HashSet::new();
    if let Ok(entries) = std::fs::read_dir(format!("/proc/{}/fd", pid)) {
        for entry in entries.flatten() {
            if let Ok(link) = std::fs::read_link(entry.path()) {
                let s = link.to_string_lossy();
                if let Some(rest) = s.strip_prefix("socket:[")
                    && let Some(inode) = rest.strip_suffix(']') {
                        process_inodes.insert(inode.to_string());
                    }
            }
        }
    }

    // Then read /proc/{pid}/net/tcp{,6} and match by inode
    for proto in &["tcp", "tcp6"] {
        let path = format!("/proc/{}/net/{}", pid, proto);
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let local = parse_hex_addr(fields[1], *proto == "tcp6");
            let remote = parse_hex_addr(fields[2], *proto == "tcp6");
            let state = fields[3];
            let inode = fields[9];

            // Only include sockets owned by this process
            if !process_inodes.is_empty() && !process_inodes.contains(inode) {
                continue;
            }

            let is_remote = !remote.starts_with("0.0.0.0")
                && !remote.starts_with("127.")
                && remote != "0.0.0.0:0";
            match state {
                "01" | "02" | "03" | "04" | "05" | "06" | "08" | "09" => {
                    if is_remote {
                        conns.push(format!("connect {}", remote));
                    }
                }
                "0A" => {
                    if include_listen {
                        conns.push(format!("listen {}", local));
                    }
                }
                _ => {}
            }
        }
    }
    conns.sort();
    conns.dedup();
    conns
}

/// Parse a hex-encoded address:port from /proc/net/tcp or tcp6.
///
/// IPv4 format: "0100007F:0050" → "127.0.0.1:80" (little-endian u32)
/// IPv6 format: 32 hex chars in 4 little-endian 32-bit words + ":port"
///   e.g. "00000000000000000000000001000000:0035" → "[::1]:53"
fn parse_hex_addr(hex: &str, is_v6: bool) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return hex.to_string();
    }
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    if is_v6 {
        let h = parts[0];
        if h.len() != 32 {
            return format!("[?]:{}", port);
        }
        // /proc/net/tcp6 stores as 4 little-endian 32-bit words
        // Each word is 8 hex chars, stored in network byte order within the word
        // but the words themselves represent the address in host byte order
        let mut bytes = [0u8; 16];
        for word in 0..4 {
            let w = u32::from_str_radix(&h[word * 8..word * 8 + 8], 16).unwrap_or(0);
            // Each 32-bit word is in host (little-endian) byte order
            bytes[word * 4] = (w & 0xff) as u8;
            bytes[word * 4 + 1] = ((w >> 8) & 0xff) as u8;
            bytes[word * 4 + 2] = ((w >> 16) & 0xff) as u8;
            bytes[word * 4 + 3] = ((w >> 24) & 0xff) as u8;
        }

        // All zeros = [::]
        if bytes == [0u8; 16] {
            return format!("[::]:{}",port);
        }

        // v4-mapped ::ffff:x.x.x.x
        if bytes[..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
            return format!("{}.{}.{}.{}:{}", bytes[12], bytes[13], bytes[14], bytes[15], port);
        }

        // Loopback ::1
        if bytes[..15] == [0; 15] && bytes[15] == 1 {
            return format!("[::1]:{}", port);
        }

        // Full IPv6 — format as standard notation
        let words: Vec<u16> = (0..8)
            .map(|i| u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]))
            .collect();
        let addr = std::net::Ipv6Addr::new(
            words[0], words[1], words[2], words[3],
            words[4], words[5], words[6], words[7],
        );
        format!("[{}]:{}", addr, port)
    } else {
        let addr = u32::from_str_radix(parts[0], 16).unwrap_or(0);
        let a = addr & 0xff;
        let b = (addr >> 8) & 0xff;
        let c = (addr >> 16) & 0xff;
        let d = (addr >> 24) & 0xff;
        format!("{}.{}.{}.{}:{}", a, b, c, d, port)
    }
}

fn read_cmdline(pid: u32) -> String {
    match std::fs::read(format!("/proc/{}/cmdline", pid)) {
        Ok(bytes) => {
            // cmdline is NUL-separated; replace NULs with spaces, trim
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        }
        Err(_) => String::new(),
    }
}

