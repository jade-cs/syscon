use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Mutex;

use crate::error::{Result, SysconError};
use crate::{audit, control, handlers, util};
use crate::ingest::{BStr, CommBuf, SyscallEvent};
use crate::state::DaemonState;

// ── Tuning constants ───────────────────────────────────────────────

/// Initial capacity for the cross-thread event buffer.
/// Sized for one processing interval (~200 ms) at moderate load (~1000
/// events/sec). Over-allocating avoids reallocation under burst.
const EVENT_BUF_INITIAL_CAPACITY: usize = 256;

/// Interval between batch processing ticks (milliseconds).
/// 200 ms balances latency (receipts reflect recent events) against CPU
/// cost (fewer lock acquisitions on the shared state).
const PROCESS_INTERVAL_MS: u64 = 200;

/// Number of events processed per state-lock acquisition.
/// Smaller chunks yield to other tasks more often; 32 keeps the lock
/// held for <1 ms even on slow machines.
const PROCESS_CHUNK_SIZE: usize = 32;

/// Maximum depth when walking the ppid chain to resolve container IDs.
/// 10 hops covers the deepest realistic nesting (containerd-shim → runc
/// → init → bash → ... → target) without spinning on degenerate trees.
const PPID_WALK_MAX_DEPTH: u32 = 10;

/// Receive timeout for the audit socket (milliseconds).
/// Short timeout (50 ms) ensures the recv loop doesn't block longer than
/// one processing interval, keeping batch latency bounded.
const AUDIT_RECV_TIMEOUT_MS: u64 = 50;

/// Value for net.core.rmem_max sysctl (bytes). Must be >= the audit
/// socket's SO_RCVBUFFORCE value (64 MB) for the fallback SO_RCVBUF
/// path to work when we lack CAP_NET_ADMIN.
const RMEM_MAX_BYTES: &str = "net.core.rmem_max=67108864";

pub struct DaemonConfig {
    pub port: u16,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self { port: 9900 }
    }
}

pub async fn run(config: DaemonConfig) -> Result<()> {
    let _ = std::process::Command::new("sysctl")
        .args(["-w", RMEM_MAX_BYTES])
        .output();

    let audit_fd = audit::open_audit_socket()?;
    audit::set_recv_timeout(audit_fd, AUDIT_RECV_TIMEOUT_MS);

    let state = Arc::new(Mutex::new(DaemonState::new()));

    tracing::info!("syscon daemon starting (acting as audit daemon)");
    tracing::info!(fd = audit_fd, "audit socket opened, registered as audit daemon");

    match audit::install_rules() {
        Ok(n) => tracing::info!(rules = n, "audit rules installed"),
        Err(e) => tracing::warn!("could not install audit rules: {}", e),
    }

    let event_buf: Arc<StdMutex<Vec<SyscallEvent>>> =
        Arc::new(StdMutex::new(Vec::with_capacity(EVENT_BUF_INITIAL_CAPACITY)));

    let buf_writer = event_buf.clone();
    std::thread::Builder::new()
        .name("audit-recv".into())
        .spawn(move || {
            audit_recv_loop(audit_fd, buf_writer);
            audit::deregister(audit_fd);
            unsafe { libc::close(audit_fd); }
        })?;

    // Async processor
    let process_state = state.clone();
    let buf_reader = event_buf;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(PROCESS_INTERVAL_MS));
        loop {
            interval.tick().await;

            let batch: Vec<SyscallEvent> = {
                let mut buf = buf_reader.lock().unwrap_or_else(|e| e.into_inner());
                std::mem::take(&mut *buf)
            };

            if batch.is_empty() {
                continue;
            }

            tracing::debug!(events = batch.len(), "processing batch");

            let timestamp = util::monotonic_ns();

            for chunk in batch.chunks(PROCESS_CHUNK_SIZE) {
                let mut state = process_state.lock().await;
                for ev in chunk {
                    let cid: &str = &ev.container_id;
                    if !state.containers.contains_key(cid) {
                        // Use IPs resolved eagerly in the recv thread (process
                        // was mid-syscall, /proc guaranteed valid). Don't read
                        // fib_trie here — by now the process may have exited
                        // and the PID recycled by a host process.
                        if !ev.container_ips.is_empty() {
                            for &ip in &ev.container_ips {
                                // First container to claim an IP wins. Shared-network
                                // containers (Docker Compose network_mode: service:x)
                                // will all report the same IPs — that's expected.
                                state.ip_to_container.entry(ip).or_insert_with(|| cid.to_string());
                            }
                            tracing::info!(
                                container = %cid,
                                pid = ev.pid,
                                ips = %ev.container_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", "),
                                "resolved container IPs"
                            );
                        }
                        state.containers.insert(
                            cid.to_string(),
                            crate::state::ContainerState::new(
                                cid.to_string(),
                                crate::state::ContainerBaseline::new(),
                            ),
                        );
                    }
                    let container = state.containers.get_mut(cid).unwrap();
                    handlers::dispatch(container, ev, timestamp);
                }
            }
        }
    });
    tracing::info!("audit event processor started");

    let figment = rocket::Config::figment()
        .merge(("port", config.port))
        .merge(("address", "0.0.0.0"))
        .merge(("log_level", "off"));

    let rocket = control::rocket(state)
        .configure(figment)
        .ignite()
        .await
        .map_err(|e| SysconError::Rocket(format!("rocket ignite failed: {}", e)))?;

    tracing::info!(port = config.port, "HTTP server listening");

    rocket
        .launch()
        .await
        .map_err(|e| SysconError::Rocket(format!("rocket launch failed: {}", e)))?;

    Ok(())
}

// ── Container resolution ────────────────────────────────────────────

fn resolve_container(
    pid: u32,
    ppid_hint: u32,
    is_container: bool,
    pid_cache: &mut std::collections::HashMap<u32, Option<String>>,
    ppid_cache: &std::collections::HashMap<u32, u32>,
) -> Option<String> {
    if let Some(cached) = pid_cache.get(&pid) {
        return cached.clone();
    }

    if let Some(info) = crate::docker::container_from_pid(pid) {
        pid_cache.insert(pid, Some(info.id.clone()));
        return Some(info.id);
    }

    // Walk the ppid chain
    let mut current = if ppid_hint > 0 { ppid_hint } else {
        ppid_cache.get(&pid).copied().unwrap_or(0)
    };
    for _ in 0..PPID_WALK_MAX_DEPTH {
        if current == 0 || current == 1 {
            break;
        }
        let cached_result = pid_cache.get(&current).cloned();
        if let Some(Some(cid)) = cached_result {
            pid_cache.insert(pid, Some(cid.clone()));
            return Some(cid);
        }
        if let Some(info) = crate::docker::container_from_pid(current) {
            pid_cache.insert(current, Some(info.id.clone()));
            pid_cache.insert(pid, Some(info.id.clone()));
            return Some(info.id);
        }
        current = ppid_cache.get(&current).copied()
            .or_else(|| util::read_ppid(current))
            .unwrap_or(0);
    }

    // Last resort for confirmed container processes (subj=docker-default):
    // If /proc/pid/cgroup is gone (process exited), find the unique container
    // this pid most likely belongs to by looking at known containers.
    // Docker exec processes join the container's cgroup but their ppid chain
    // goes through containerd-shim (host-side), not the container entrypoint.
    if is_container {
        // Find all unique container IDs in the cache
        let mut known_containers: Vec<String> = pid_cache
            .values()
            .filter_map(|v| v.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        known_containers.sort();
        known_containers.dedup();

        // If there's exactly one container, it's unambiguous
        if known_containers.len() == 1 {
            let cid = known_containers.into_iter().next().unwrap();
            pid_cache.insert(pid, Some(cid.clone()));
            return Some(cid);
        }

        // If there are multiple containers, try scanning the cgroup filesystem
        // for this PID in any container's cgroup.procs (only works if alive)
        if known_containers.len() > 1 {
            let scan = crate::docker::scan_container_pids();
            if let Some(cid) = scan.get(&pid) {
                pid_cache.insert(pid, Some(cid.clone()));
                return Some(cid.clone());
            }
        }
    }

    None
}

// ── Audit recv loop ─────────────────────────────────────────────────

/// Single recv thread: drains all available messages from the netlink socket,
/// then processes completed SYSCALL groups with container resolution.
fn audit_recv_loop(fd: libc::c_int, buf: Arc<StdMutex<Vec<SyscallEvent>>>) {
    let mut pid_cache: std::collections::HashMap<u32, Option<String>> =
        std::collections::HashMap::new();
    let mut ppid_cache: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::new();
    let mut cmdline_cache: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();

    let mut exe_intern: std::collections::HashMap<String, BStr> =
        std::collections::HashMap::new();
    let mut cid_intern: std::collections::HashMap<String, Arc<str>> =
        std::collections::HashMap::new();
    let mut cmd_intern: std::collections::HashMap<String, BStr> =
        std::collections::HashMap::new();

    let mut pending = audit::PendingEvents::new();
    let mut syscall_batch: Vec<audit::SyscallGroup> = Vec::new();

    loop {
        // Phase 1: Drain all available messages from the socket
        syscall_batch.clear();

        loop {
            match audit::try_recv(fd, &mut pending) {
                Ok(audit::RecvResult::Record(group)) => {
                    syscall_batch.push(group);
                }
                Ok(audit::RecvResult::Pending) => {
                    continue;
                }
                Ok(audit::RecvResult::WouldBlock) => {
                    break;
                }
                Err(e) => {
                    tracing::error!("audit recv error: {:#}", e);
                    return;
                }
            }
        }

        if syscall_batch.is_empty() {
            continue;
        }

        // Phase 2: Process completed SYSCALL groups
        for mut group in syscall_batch.drain(..) {
            if !group.is_container {
                continue;
            }

            if group.ppid > 0 {
                ppid_cache.insert(group.pid, group.ppid);
            }

            // Use eagerly-resolved container_id from AUDIT_SYSCALL recv time,
            // falling back to resolve_container for edge cases (e.g. if /proc
            // was unreadable at recv time but the process is still alive).
            let container_id = match group.container_id {
                Some(ref cid) => {
                    pid_cache.insert(group.pid, Some(cid.clone()));
                    cid.clone()
                }
                None => match resolve_container(
                    group.pid, group.ppid, group.is_container, &mut pid_cache, &ppid_cache,
                ) {
                    Some(cid) => cid,
                    None => continue,
                },
            };

            let cmdline = if !group.argv.is_empty() {
                group.argv.join(" ")
            } else {
                cmdline_cache.get(&group.pid).cloned()
                    .unwrap_or_else(|| read_cmdline(group.pid))
            };
            cmdline_cache.insert(group.pid, cmdline.clone());

            let syscall_name = crate::syscalls::name(group.syscall);
            let detail = crate::ingest::classify_syscall_group(syscall_name, &group);

            let ev = SyscallEvent {
                pid: group.pid,
                ppid: group.ppid,
                syscall: group.syscall,
                comm: CommBuf::new(&group.comm),
                exe: intern_bstr(&mut exe_intern, &group.exe),
                container_id: intern(&mut cid_intern, &container_id),
                cmdline: intern_bstr(&mut cmd_intern, &cmdline),
                detail,
                timestamp_ms: group.timestamp_ms,
                container_ips: std::mem::take(&mut group.container_ips),
            };

            let mut b = buf.lock().unwrap_or_else(|e| e.into_inner());
            b.push(ev);
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn intern(cache: &mut std::collections::HashMap<String, Arc<str>>, s: &str) -> Arc<str> {
    if let Some(existing) = cache.get(s) {
        existing.clone()
    } else {
        let arc: Arc<str> = Arc::from(s);
        cache.insert(s.to_string(), arc.clone());
        arc
    }
}

fn intern_bstr(cache: &mut std::collections::HashMap<String, BStr>, s: &str) -> BStr {
    if let Some(existing) = cache.get(s) {
        existing.clone()
    } else {
        let bstr = BStr::from_str(s);
        cache.insert(s.to_string(), bstr.clone());
        bstr
    }
}

fn read_cmdline(pid: u32) -> String {
    match std::fs::read(format!("/proc/{}/cmdline", pid)) {
        Ok(bytes) => {
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
