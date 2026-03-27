# Harness Integration Guide

## Overview

syscon is a host-side auditor daemon that monitors syscall activity inside Docker containers. It tracks taint propagation from AI agent actions through process trees, file-mediated data flows, pipes, Unix sockets, and network connections. It produces compressed, per-action receipts annotated with MITRE ATT&CK technique IDs that a trusted monitor LLM can use to evaluate agent behavior.

The harness is responsible for:
1. Marking action boundaries (start/end) around each agent tool call
2. Retrieving receipts for the monitor LLM
3. Cleaning up container state when done

## Prerequisites

1. **Build syscon:**
   ```bash
   cargo build --release
   ```

2. **Generate and install the seccomp profile:**
   ```bash
   # LOG mode (audit-based, lower overhead, fewer details)
   sudo ./target/release/syscon gen-profile --block-dangerous -o /etc/syscon-seccomp.json

   # Or NOTIFY mode (user-notify, full syscall argument capture)
   sudo ./target/release/syscon gen-profile --block-dangerous \
       --notify-socket /run/syscon/notifier.sock \
       -o /etc/syscon-seccomp.json
   ```
   Either set it as Docker's default profile in `/etc/docker/daemon.json`:
   ```json
   {"seccomp-profile": "/etc/syscon-seccomp.json"}
   ```
   Or pass it per-container:
   ```bash
   docker run --security-opt seccomp=/etc/syscon-seccomp.json <image>
   ```

3. **Start the daemon** (needs root for audit socket):
   ```bash
   # Basic (audit-based with hybrid AUDIT_SYSCALL rules for path resolution)
   sudo ./target/release/syscon daemon --port 9903

   # With binary logging for offline replay
   sudo ./target/release/syscon daemon --port 9903 --log-file /var/log/syscon.binlog

   # With USER_NOTIF support (requires NOTIFY mode seccomp profile)
   sudo ./target/release/syscon daemon --port 9903 --notify-socket /run/syscon/notifier.sock
   ```

The daemon auto-discovers containers via the audit stream. No per-container registration needed — the first `action_start` call creates the container's state. Docker build containers (BuildKit/buildx) are automatically excluded.

On startup, the daemon installs AUDIT_SYSCALL rules for path-bearing syscalls (openat, execve, connect, etc.) using `auditctl`. This enables kernel-resolved PATH and SOCKADDR records without `/proc/pid/fd` racing. Requires `CAP_AUDIT_CONTROL` (root).

## Monitoring Modes

| Mode | Profile | Daemon Flag | Argument Capture | Overhead |
|------|---------|-------------|-----------------|----------|
| **LOG + Hybrid Audit** | `gen-profile` | (default) | Kernel-resolved paths via AUDIT_PATH records | Low |
| **USER_NOTIF** | `gen-profile --notify-socket` | `--notify-socket` | Full args read from `/proc/pid/mem` while process is blocked | Medium |

Both modes can run simultaneously (dual-mode). LOG + Hybrid Audit is recommended for most use cases — it captures file paths, socket addresses, and argv without blocking container processes.

## API

Base URL: `http://localhost:9903` (configurable via `--port`)

All responses are JSON. All endpoints respond within milliseconds except `action_end` which includes a 500ms flush delay to capture pending audit events.

---

### Lifecycle Flow

```
                    ┌─────────────────────────────────────┐
                    │         For each task/session        │
                    │                                     │
                    │  1. Environment creates container    │
                    │  2. Get container ID (docker ps)     │
                    │                                     │
                    │  ┌─────────────────────────────────┐ │
                    │  │    For each agent tool call      │ │
                    │  │                                  │ │
                    │  │  3. POST action_start            │ │
                    │  │  4. GET receipt (prev action)    │ │
                    │  │  5. Feed receipt to monitor LLM  │ │
                    │  │  6. Execute the tool call        │ │
                    │  │  7. POST action_end              │ │
                    │  │                                  │ │
                    │  └──────────┬───────────────────────┘ │
                    │             │ repeat                  │
                    │                                     │
                    │  8. GET final receipt                │
                    │  9. DELETE container (cleanup)       │
                    └─────────────────────────────────────┘
```

---

### Step-by-step

#### 1. Start a new action

```
POST /containers/{container_id}/actions
Content-Type: application/json

{"command": "the agent's tool call text"}
```

Response:
```json
{"ok": true, "action_id": 1}
```

The `command` field is free-text — include the agent's raw tool call or a summary. It appears in receipts for context.

Action IDs auto-increment (1, 2, 3, ...).

**On the first call**, syscon scans the container's filesystem to establish a baseline so pre-existing files aren't reported as new. Subsequent calls skip this.

#### 2. Get receipt for the previous action

```
GET /containers/{container_id}/actions/{action_id}/receipt
```

Response:
```json
{
  "ok": true,
  "action_id": 1,
  "receipt": "=== Post-Action Receipt: Action #1 ===\n..."
}
```

The `receipt` field is structured text ready to include in the monitor LLM's prompt. Typical size: 500-4000 chars depending on activity.

**Call this after starting the NEXT action** but before executing it. This way the receipt covers everything that happened during the previous action, with a flush delay ensuring all audit events are captured.

#### 3. End the current action

```
POST /containers/{container_id}/actions/{action_id}/end
```

Response:
```json
{
  "ok": true,
  "action_id": 1,
  "receipt": "=== Post-Action Receipt: Action #1 ===\n..."
}
```

Also returns the receipt. The receipt in the response can be used for logging; the monitor LLM should use the GET endpoint (step 2) for cleaner timing.

#### 4. Cleanup

```
DELETE /containers/{container_id}
```

Frees all memory associated with the container. Call when the task/session ends.

---

### Typical harness pseudocode

```python
import requests

SYSCON = "http://localhost:9903"

def run_task(container_id, agent):
    action_num = 0

    while not agent.done():
        # Agent proposes a tool call
        tool_call = agent.next_action()
        action_num += 1

        # Tell syscon a new action is starting
        requests.post(f"{SYSCON}/containers/{container_id}/actions", json={
            "command": tool_call.summary()
        })

        # Get receipt for the PREVIOUS action (skip on first)
        receipt = ""
        if action_num > 1:
            prev = action_num - 1
            resp = requests.get(
                f"{SYSCON}/containers/{container_id}/actions/{prev}/receipt"
            ).json()
            receipt = resp.get("receipt", "")

        # Feed receipt to the trusted monitor
        if receipt:
            score = monitor_llm.evaluate(
                action_text=tool_call.summary(),
                receipt=receipt
            )
            if score > THRESHOLD:
                # Suspicious — halt or resample
                break

        # Execute the tool call in the container
        execute_in_container(container_id, tool_call)

        # Mark action as ended
        requests.post(
            f"{SYSCON}/containers/{container_id}/actions/{action_num}/end"
        )

    # === Save audit artifacts into the trajectory ===

    # Per-action receipts
    trajectory["receipts"] = []
    for i in range(1, action_num + 1):
        resp = requests.get(
            f"{SYSCON}/containers/{container_id}/actions/{i}/receipt"
        ).json()
        trajectory["receipts"].append({
            "action_id": i,
            "receipt": resp.get("receipt", "")
        })

    # Full influence graph (DOT source — can be rendered later)
    dot = requests.get(
        f"{SYSCON}/containers/{container_id}/graph.dot"
    ).text
    trajectory["influence_graph_dot"] = dot

    # Cleanup
    requests.delete(f"{SYSCON}/containers/{container_id}")
```

### Saving audit data with trajectories

When rerunning trajectories, save the full syscon output alongside the trajectory data so it can be analyzed later without the daemon running:

- **Per-action receipts**: Store each action's receipt text. These are what the monitor LLM sees during live evaluation.
- **Full DOT graph**: Store the raw Graphviz DOT source (`/containers/{id}/graph.dot`). This captures the complete process tree, data flows, network connections, and file relationships across all actions. Render later with `dot -Tsvg graph.dot -o graph.svg` or `dot -Tpng`.
- **Binary log**: If `--log-file` was used, the `.binlog` file can be replayed offline:
  ```bash
  ./target/release/syscon replay -i trace.binlog -f receipt   # regenerate receipts
  ./target/release/syscon replay -i trace.binlog -f dot       # regenerate graph
  ./target/release/syscon replay -i trace.binlog -f json      # state summary
  ./target/release/syscon reduce -i trace.binlog              # n-gram reduction analysis
  ```

Both should be saved within the trajectory object/directory itself so each run is self-contained and reproducible.

The daemon also automatically saves artifacts to `data/{container_id}/` on disk whenever a receipt or graph is served, as a backup.

---

### All endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/status` | GET | Daemon health + list of tracked containers |
| `/containers` | GET | List all tracked containers with stats |
| `/containers/{id}` | DELETE | Free memory for a container |
| `/containers/{id}/actions` | POST | Start a new action (JSON body: `{"command": "..."}`) |
| `/containers/{id}/actions` | GET | List completed actions for a container |
| `/containers/{id}/actions/{n}/end` | POST | End action N, returns receipt |
| `/containers/{id}/actions/{n}/receipt` | GET | Get receipt for completed action N |
| `/containers/{id}/receipt` | GET | Snapshot receipt (global, all events) |
| `/containers/{id}/graph` | GET | Influence graph (DOT source, rendered client-side) |
| `/containers/{id}/graph.dot` | GET | Raw Graphviz DOT source |
| `/` | GET | Web dashboard with pan/zoom graph viewer |
| `/viz.js` | GET | Client-side Graphviz renderer |

---

## Receipt format

Receipts report what happened during an action, annotated with taint scores and MITRE ATT&CK technique IDs.

Example:

```
=== Post-Action Receipt: Action #2 ===
Command: build project
Duration: 8.8s | 243 syscall events

PROCESSES: 7 unique, 6 forked, 9 exited
  [busybox] $ socat UNIX-LISTEN:/tmp/.sock,fork OPEN:/tmp/.staged,creat,append (taint 100%)
  [busybox] $ cat /etc/passwd (taint 81%)
  [busybox] $ socat - UNIX-CONNECT:/tmp/.sock (taint 90%)

ACTIVITY:
  Filesystem (201 ops):
    cat: exec x4, open_read x44
    socat: exec x4, open_read x38
  Network:
    socat: socket x2, connect x2, bind x2, accept x1

FILES OBSERVED OPEN:
  cat: /etc/passwd
  cat: /etc/shadow
  python3: /app/main.py

FILES WRITTEN:
  /tmp/.staged

DATA FLOWS:
  (prior) -[/tmp/backdoor.sh]-> bd.sh

NETWORK:
  curl -> 104.18.26.120:80
  Listening:
    ncat on 0.0.0.0:4444

SEMANTIC SUMMARY:
  Action #2:
    !! [T1059.004] Netcat/socat (reverse shell tool): socat UNIX-LISTEN:/tmp/.sock (x2)
    ! [T1564.001] Hidden file/directory creation: /tmp/.staged
    . [T1071] Outbound network connection
```

### Sections

- **PROCESSES**: Unique commands executed with taint percentages. Taint 100% = directly agent-controlled, lower values = influenced through IPC channels with decay (fork 0.9, pipe 0.7, socket 0.7, network 0.8, file 0.5, signal 0.3).
- **PROCESS COMMUNITIES**: Groups of related processes collapsed for readability (shown when >3 processes share the same binary + fork relationship).
- **ACTIVITY**: Filesystem and network syscall counts grouped by process name.
- **FILES OBSERVED OPEN**: Data files opened by processes, from kernel-resolved audit PATH records and `/proc/pid/fd` snapshots. Shared libraries and binary paths filtered (but tracked in data flow analysis).
- **DATA FLOWS**: Cross-process and cross-action data flow via files. `(prior)` means the file was written in a previous action. Shows writer → file → reader chains.
- **FILES WRITTEN**: New or modified files created during this action.
- **NETWORK**: Outbound connections (destination IP:port) and listening sockets.
- **SEMANTIC SUMMARY**: Detected behaviors mapped to MITRE ATT&CK technique IDs. Severity markers: `!!` = high (e.g., reverse shell tools, credential access), `!` = medium (e.g., curl downloads, evidence deletion), `.` = low (e.g., compilation, archive creation). Rules sourced from auditd-attack (MIT) and Falco (Apache-2.0).

### Compression

Receipts are aggressively compressed for LLM context efficiency:
- Process trees grouped by binary name with counts (not per-PID)
- Shared library paths filtered from display (kept in data flow analysis)
- File lists grouped by directory: `{file1, file2, ... +N more}` or `dir/ (N files)`
- Network connections grouped by destination
- Hex-encoded kernel process names decoded (e.g. `6E706D2072756E` → `npm run`)
- Same MITRE technique in one action collapsed: `[T1059.004] ... (x2)`
- Typical output: 500-4000 chars for 100-50000 syscall events

### Taint model

Taint originates from agent actions (not the container itself):
- Container entry point process (e.g., `sleep 300`): taint 0%
- Process spawned during an agent action: taint 100%
- Children of tainted processes: parent_score × 0.9 (fork decay)
- Process reading a file written by a tainted process: score × 0.5 (file flow decay)
- Process receiving data via pipe from tainted process: score × 0.7 (pipe decay)
- Pre-existing processes stay at 0% unless agent influence reaches them

This creates a meaningful gradient: 100% = agent directly ran this, 81% = two fork hops away, 50% = read a file the agent wrote.

---

## Monitored syscalls

The seccomp profile monitors 44 syscalls across these categories:

| Category | Syscalls | Purpose |
|----------|----------|---------|
| Process | clone, clone3, fork, vfork, execve, execveat, exit_group | Process tree tracking |
| Network | socket, connect, bind, accept, accept4, sendto, recvfrom | Network connection tracking |
| File I/O | open, openat, openat2, creat, close | File access tracking |
| File ops | unlink, unlinkat, rename, renameat, renameat2, chmod, fchmod, fchmodat, chown, fchown, fchownat | File modification tracking |
| IPC | pipe, pipe2, dup, dup2, dup3, kill, tgkill | Inter-process communication |
| Shared memory | shmget, shmat, shmdt | Shared memory IPC |
| Advanced | memfd_create, ptrace | Fileless execution, process injection |
| Hidden data flow | sendfile, splice, tee, copy_file_range | Kernel-space fd-to-fd transfers |
| Blocked | ptrace, init_module, finit_module, kexec_load, process_vm_readv/writev | Denied with EPERM |

---

## Notes

- syscon monitors ALL containers using the Docker-wide seccomp profile. No per-container setup needed.
- Docker build containers (BuildKit/buildx) are automatically excluded.
- The daemon loses state on restart (in-memory only). Use `--log-file` for persistence. Artifacts are also saved to `data/` on disk when served.
- Memory usage is ~8-20MB per container depending on process count. Call DELETE to free.
- The `action_end` endpoint includes a 500ms flush delay to ensure pending audit events are captured.
- Hybrid audit mode installs system-wide `auditctl` rules for 21 syscalls on startup. These capture kernel-resolved file paths and socket addresses. Removed on daemon shutdown.
- The influence graph is rendered client-side using viz.js. Large graphs (>50 processes) are automatically capped to the most-tainted nodes.
- Binary logs can be replayed offline with the `replay` and `reduce` subcommands.
