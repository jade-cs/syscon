# TODO

## High Priority

### Network socket tracking (LOG mode)
- Read `/proc/{pid}/net/tcp`, `/proc/{pid}/net/tcp6`, `/proc/{pid}/net/unix` in the audit thread alongside fd snapshots
- On `connect`/`bind`/`accept`/`socket` syscalls, snapshot the process's network state
- Create network nodes in the graph (like file nodes but for endpoints: `1.2.3.4:80`, `unix:/var/run/docker.sock`)
- Show edges: `process --connect--> endpoint`, `process --bind--> endpoint`
- Add to receipt: which processes connected to which remote addresses
- Detect: first-seen remote IPs, AF_NETLINK usage, listening sockets

### Filesystem diff improvements
- Track file modifications (not just new files) by storing mtimes at action_start and diffing at action_end
- Detect files that were modified but not created (config tampering)
- Show deleted files in the graph

### Receipt compression for LLM consumption
- Group file operations by directory: `/etc/ssh/{sshd_config, ssh_host_rsa_key, [3 others]}`
- Collapse repetitive library reads: `curl loaded 12 shared libraries from /usr/lib/`
- Token budget enforcement (~500-2000 tokens target)
- Priority ordering: anomalies first, then data flows, then routine ops

## Medium Priority

### USER_NOTIF mode (deferred from initial plan)
**Why:** LOG mode can't see syscall arguments (file paths, socket addresses). We rely on `/proc/{pid}/fd/` snapshots which miss files opened and closed quickly. USER_NOTIF blocks the syscall, letting us read the arguments from `/proc/{pid}/mem` before allowing it to proceed.

**What it gives us:**
- Actual filenames from `openat(dirfd, pathname, flags)` — no more guessing from fd snapshots
- Socket addresses from `connect(fd, sockaddr)` — know exactly which IP:port
- `execve` argv — full command lines without racing `/proc/{pid}/cmdline`
- BPF pre-filtering: only trap `openat` with write flags, let reads through as LOG

**Implementation plan:**
1. Container runtime wrapper that installs a SECCOMP_RET_USER_NOTIF filter and passes the notification fd to the daemon via SCM_RIGHTS (the existing `seccomp.rs` has the fd-passing code)
2. OCI runtime hook or custom Docker seccomp agent that holds the USER_NOTIF fd
3. Daemon receives notifications via `SECCOMP_IOCTL_NOTIF_RECV`, reads args from `/proc/{pid}/mem`, responds with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
4. TOCTOU guard: check `SECCOMP_IOCTL_NOTIF_ID_VALID` before and after memory reads
5. Selective interception: `execve`, `connect`, `bind`, `openat` (write flags only) via USER_NOTIF; everything else via LOG

**Risks:**
- Latency: each intercepted syscall blocks until daemon responds (~1ms target)
- fd passing from container to host daemon (SCM_RIGHTS over socketpair)
- runc/containerd version compatibility for `seccomp_unotify`

### Per-action graph view
- Generate a graph scoped to a single action (only processes/files from that action)
- Highlight new relationships vs pre-existing ones
- Show diff from previous action's graph

### Graph layout improvements
- Group shared libraries into a single cluster node to reduce clutter
- Rank processes chronologically (left=earlier, right=later)
- Different node shapes: process=box, file=ellipse, network=diamond, sensitive=double-border

## Low Priority

### Pipe/IPC tracking
- Track `pipe`/`pipe2` fd pairs across fork (requires fd table tracking)
- Detect inter-process data flow via pipes: `sh -c "cmd1 | cmd2"` creates a data channel
- SysV IPC: `msgget`/`msgsnd`/`msgrcv` key→PID mapping
- Shared memory: `shmget`/`shmat` inode→PID mapping

### Signal tracking
- `kill`/`tgkill` target PID resolution (requires USER_NOTIF to read args)
- Create signal edges in influence graph
- Detect suspicious signals (SIGSTOP, SIGKILL to monitoring processes)

### Container baseline scanning
- Scan container filesystem at startup to build a proper `original_binaries` set
- Bootstrap process table from `/proc` filtered by container cgroup
- Read `/proc/net/unix` and `/proc/net/tcp` for original listening sockets

### Block dangerous syscalls (optional)
- `--block-dangerous` flag already exists in gen-profile
- Syscalls: ptrace, init_module, finit_module, kexec_load, kexec_file_load, process_vm_readv, process_vm_writev
- Returns ERRNO(EPERM) — these are observation-only in the current LOG mode

## Setup Reference

### Daemon-wide seccomp profile

```bash
# Generate profile
sudo syscon gen-profile -o /etc/syscon.json

# Configure Docker
echo '{"seccomp-profile": "/etc/syscon.json"}' | sudo tee /etc/docker/daemon.json

# Restart Docker (restarts all containers)
sudo systemctl restart docker

# Start daemon
sudo syscon daemon --port 9903
```

### Caveats
- Restarting dockerd restarts all containers (unless `"live-restore": true`)
- `--security-opt seccomp=unconfined` bypasses the profile
- Already-running containers keep their original profile until restarted
