# Harness Integration Guide

## Overview

syscon is a host-side auditor daemon that monitors syscall activity inside Docker containers via the Linux audit subsystem. It produces compressed, per-action receipts that a trusted monitor (blue team) LLM can use to evaluate whether an untrusted agent (red team) is behaving suspiciously.

The harness is responsible for:
1. Marking action boundaries (start/end) around each agent tool call
2. Retrieving receipts for the monitor LLM
3. Cleaning up container state when done

## Prerequisites

1. **Build syscon:**
   ```bash
   cargo build --release
   ```

2. **Install the seccomp profile in Docker:**
   ```bash
   sudo ./target/release/syscon gen-profile -o /etc/syscon.json
   ```
   Add to `/etc/docker/daemon.json`:
   ```json
   {"seccomp-profile": "/etc/syscon.json"}
   ```
   Then restart Docker:
   ```bash
   sudo systemctl restart docker
   ```

3. **Start the daemon** (needs root for audit socket):
   ```bash
   sudo ./target/release/syscon daemon --port 9903
   ```

The daemon auto-discovers containers via the audit stream. No per-container registration needed — the first `action_start` call creates the container's state. Docker build containers (BuildKit/buildx) are automatically excluded.

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

    # Get final receipt
    resp = requests.get(
        f"{SYSCON}/containers/{container_id}/actions/{action_num}/receipt"
    ).json()
    final_receipt = resp.get("receipt", "")

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

Receipts are unopinionated structured text — they report what happened without flagging or judging. The monitor LLM decides what's suspicious.

Example:

```
=== Post-Action Receipt: Action #2 ===
Command: curl http://example.com > /tmp/page.html
Duration: 1.6s | 108 syscall events

PROCESSES: 2 spawned, 1 exited
  /usr/bin/curl

COMMANDS RUN:
  $ sh -c curl -s http://example.com > /tmp/page.html

ACTIVITY:
  Filesystem (70 ops):
    curl: open_read x68, exec x2
  Network:
    curl: sendto x3, socket x8, connect x7

FILES OBSERVED OPEN:
  curl: /etc/ssl/openssl.cnf
  curl: /usr/lib/x86_64-linux-gnu/{libcurl.so.4, libssl.so.3, ... +12 more}

DATA FLOWS:
  (prior) -[/tmp/setup.sh]-> sh

FILES WRITTEN:
  /tmp/page.html

NETWORK:
  curl -> 104.18.26.120:80
```

### Sections

- **PROCESSES**: Binaries executed with counts, total spawned/exited
- **COMMANDS RUN**: Every unique command line, deduplicated with repeat counts. Commands differing only in temp filenames are normalized and grouped (e.g. `as -o /tmp/<TMP> (x500)`)
- **ACTIVITY**: Filesystem and network syscall counts grouped by process name
- **FILES OBSERVED OPEN**: Files seen in `/proc/{pid}/fd/` snapshots, grouped by process and directory
- **DATA FLOWS**: Cross-process data flow via files (process A wrote file, process B read it)
- **FILES WRITTEN**: New files created during this action, grouped by directory
- **NETWORK**: Outbound connections (destination IP:port) and listening sockets, grouped by destination

### Compression

Receipts are aggressively compressed for LLM context efficiency:
- Process trees grouped by binary name with counts (not per-PID)
- Commands deduplicated with temp path normalization
- Shared library data flows suppressed (only application-level flows shown)
- File lists grouped by directory: `{file1, file2, ... +N more}` or `dir/ (N files)`
- Network connections grouped by destination
- Hex-encoded kernel process names decoded (e.g. `6E706D2072756E` → `npm run`)
- Typical output: 500-4000 chars for 100-50000 syscall events (77x compression on large containers)

---

## Notes

- syscon monitors ALL containers using the Docker-wide seccomp profile. No per-container setup needed.
- Docker build containers (BuildKit/buildx) are automatically excluded.
- The daemon loses state on restart (in-memory only). Artifacts are persisted to `data/` on disk when served.
- Memory usage is ~8-20MB per container depending on process count. Call DELETE to free.
- The `action_end` endpoint includes a 500ms flush delay to ensure pending audit events are captured.
- The seccomp profile logs ~35 syscalls: process lifecycle (`fork`, `execve`, `exit_group`), network (`connect`, `bind`, `accept`, `socket`, `sendto`, `recvfrom`), filesystem (`openat`, `unlink`, `rename`, `chmod`, `chown`), and IPC (`pipe`, `dup`, `kill`). High-frequency syscalls (`read`, `write`, `close`) are excluded for performance.
- The influence graph is rendered client-side using viz.js. The server only returns DOT source.
