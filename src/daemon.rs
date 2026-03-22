use std::sync::{Arc, Mutex as StdMutex};

use anyhow::Result;
use tokio::sync::Mutex;

use crate::{audit, control, handlers};
use crate::state::DaemonState;

pub struct DaemonConfig {
    pub port: u16,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self { port: 9900 }
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
}

pub async fn run(config: DaemonConfig) -> Result<()> {
    let audit_fd = audit::open_audit_socket()?;
    audit::set_recv_timeout(audit_fd, 50);

    let state = Arc::new(Mutex::new(DaemonState::new()));

    tracing::info!("syscon daemon starting");
    tracing::info!(fd = audit_fd, "audit socket opened");

    // Resolved event buffer: the audit thread does recv + PID resolution,
    // then pushes fully resolved events here. The async processor just
    // does fast in-memory dispatch — no /proc I/O.
    let event_buf: Arc<StdMutex<Vec<ResolvedEvent>>> =
        Arc::new(StdMutex::new(Vec::with_capacity(256)));

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
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));
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

            // Update state (tokio::Mutex — cooperates with Rocket)
            {
                let mut state = process_state.lock().await;
                let timestamp = monotonic_ns();
                for rev in &batch {
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
                    handlers::dispatch(container, &rev.event, timestamp, rev.ppid, &rev.cmdline, &rev.open_files, &rev.net_connections);
                }
            }
        }
    });
    tracing::info!("audit event processor started");

    // Rocket HTTP server
    let figment = rocket::Config::figment()
        .merge(("port", config.port))
        .merge(("address", "0.0.0.0"))
        .merge(("log_level", "off"));

    let rocket = control::rocket(state)
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
fn audit_recv_loop(fd: libc::c_int, buf: Arc<StdMutex<Vec<ResolvedEvent>>>) {
    let mut pid_cache: std::collections::HashMap<u32, Option<String>> =
        std::collections::HashMap::new();
    let mut ppid_cache: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::new();
    let mut cmdline_cache: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();
    let mut files_cache: std::collections::HashMap<u32, Vec<String>> =
        std::collections::HashMap::new();

    loop {
        match audit::try_recv(fd) {
            Ok(audit::RecvResult::Event(event)) => {
                let container_id = pid_cache
                    .entry(event.pid)
                    .or_insert_with(|| {
                        crate::docker::container_from_pid(event.pid).map(|c| c.id)
                    })
                    .clone();

                let ppid = *ppid_cache
                    .entry(event.pid)
                    .or_insert_with(|| read_ppid(event.pid).unwrap_or(0));

                // Refresh process info on key syscalls
                let syscall_name = crate::syscalls::name(event.syscall);
                let refresh_files = matches!(
                    syscall_name,
                    "execve" | "execveat" | "openat" | "open" | "openat2"
                        | "rename" | "renameat" | "renameat2"
                        | "chmod" | "fchmod" | "fchmodat"
                        | "unlink" | "unlinkat"
                );
                let is_exec = matches!(syscall_name, "execve" | "execveat");
                if is_exec || !cmdline_cache.contains_key(&event.pid) {
                    cmdline_cache.insert(event.pid, read_cmdline(event.pid));
                }
                if refresh_files || !files_cache.contains_key(&event.pid) {
                    files_cache.insert(event.pid, read_open_files(event.pid));
                }

                // Read network connections on network syscalls
                let is_net = matches!(
                    syscall_name,
                    "connect" | "bind" | "accept" | "accept4" | "socket"
                        | "sendto" | "recvfrom"
                );
                let include_listen = matches!(
                    syscall_name,
                    "bind" | "accept" | "accept4"
                );
                let net_connections = if is_net {
                    read_net_connections(event.pid, include_listen)
                } else {
                    Vec::new()
                };

                let cmdline = cmdline_cache.get(&event.pid).cloned().unwrap_or_default();
                let open_files = files_cache.get(&event.pid).cloned().unwrap_or_default();

                let mut b = buf.lock().unwrap_or_else(|e| e.into_inner());
                b.push(ResolvedEvent {
                    event,
                    container_id,
                    ppid,
                    cmdline,
                    open_files,
                    net_connections,
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
/// Returns a deduplicated list of paths, filtering out common noise.
fn read_open_files(pid: u32) -> Vec<String> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for entry in entries.flatten() {
        let link = match std::fs::read_link(entry.path()) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        // Skip common noise: pipes, sockets without info, /dev/null, /dev/pts
        if link.starts_with("pipe:")
            || link.starts_with("anon_inode:")
            || link == "/dev/null"
            || link.starts_with("/dev/pts/")
        {
            continue;
        }
        if seen.insert(link.clone()) {
            files.push(link);
        }
    }
    files
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
                if let Some(rest) = s.strip_prefix("socket:[") {
                    if let Some(inode) = rest.strip_suffix(']') {
                        process_inodes.insert(inode.to_string());
                    }
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

fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
