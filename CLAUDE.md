The goal of this project is to monitor commands run by AI agents inside docker instances, and any processes affected by those commands using taint analysis.

When running, please take extra care to not disrupt docker when it is being used by others. Ask before restarting docker, killing other containers, etc.

## Architecture

syscon acts as the Linux audit daemon (replaces auditd). It receives all audit events via a single unicast NETLINK_AUDIT socket and installs AUDIT_SYSCALL rules for path-bearing syscalls.

Key modules:
- `audit.rs` — Netlink socket management, AUDIT_SET registration, rule installation
- `audit_parse.rs` — Zero-copy parser for audit record text (no HashMap per event)
- `ingest.rs` — Core event types: SyscallEvent, SyscallDetail enum, BStr, SocketTarget, classification
- `daemon.rs` — Recv loop (batch drain), container resolution, /proc enrichment
- `handlers.rs` — Event dispatch into ContainerState (process table, file nodes, fd table, taint graph)
- `state.rs` — Core data model: ProcessTable, TaintGraph, FileNode, FdTarget
- `receipt.rs` — Receipt generation with unified DATA FLOWS graph diff
- `control.rs` — Rocket HTTP API (action boundaries, receipts, graphs)

Container events are identified by `subj=docker-default` in audit records (AppArmor profile). Non-container events are discarded at AUDIT_SYSCALL time via `skip_serials` (no allocation/parsing of ancillary records). Container IDs resolved eagerly at AUDIT_SYSCALL recv time while the process is mid-syscall.

Action attribution uses the audit record's wall-clock timestamp to determine which action was active when a syscall occurred, not when the daemon processed it. Forked processes inherit their parent's attribution. This prevents events from leaking across action boundaries due to the 200ms batch processing interval. A 2-second tolerance window (`ACTION_TIME_TOLERANCE_MS`) accounts for latency between the harness's HTTP action_start call and the docker exec syscall.

## Building and Testing

```bash
cargo build
cargo test                    # 9 unit tests (audit parser)

# Start daemon (needs root for audit socket)
sudo systemctl stop auditd && sudo systemctl disable auditd
sudo ./target/debug/syscon daemon --port 9900

# Run all 11 integration tests (daemon must be running)
sudo bash tests/run-tests.sh            # verbose
sudo bash tests/run-tests.sh -q         # quiet (summary only)

# Run a specific scenario
sudo bash tests/run-tests.sh scenario-08-stealth-audit
```

Integration tests are the primary validation — they exercise the full pipeline (audit rules → netlink recv → container resolution → taint graph → receipts) across 11 scenarios including data exfiltration, IPC covert channels, stealth attacks, and multi-container lateral movement. Always run them after non-trivial changes.

auditd must be disabled since only one process can be the audit daemon.

## Code Conventions

- No magic numbers — named constants with rationale
- Kernel constants from `linux-raw-sys::ptrace` or `libc`, not hand-written
- `BStr` for kernel byte strings (UTF-8 conversion deferred to display)
- `thiserror` for errors, no `anyhow`
- Minimize unsafe — parse nlmsghdr from bytes, not ptr::read_unaligned
- Kernel AUDIT_EXECVE hex-encodes args with control chars (unquoted = hex, quoted = plaintext) — auto-decoded in `audit_parse.rs`
