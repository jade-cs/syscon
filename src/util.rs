/// Get the current monotonic clock time in nanoseconds.
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with CLOCK_MONOTONIC is always valid.
    // The timespec is stack-allocated and correctly sized.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Decode hex-encoded kernel comm names (e.g. "6E706D2072756E" -> "npm run").
///
/// The kernel's `comm` field is limited to 16 bytes. When the real command name
/// is longer, some audit implementations hex-encode it. This function detects
/// and decodes that pattern.
pub fn decode_comm(comm: &str) -> String {
    if comm.len() > 8 && comm.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Vec<u8> = (0..comm.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&comm[i..i + 2], 16).ok())
            .collect();
        if let Ok(s) = String::from_utf8(bytes)
            && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return s;
            }
    }
    comm.to_string()
}

/// Read the parent PID from /proc/{pid}/status.
pub fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:\t") {
            return rest.trim().parse().ok();
        }
    }
    None
}
