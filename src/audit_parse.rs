//! Zero-copy parser for Linux audit record text.
//!
//! The kernel audit subsystem formats all records as `key=value` text
//! inside netlink message payloads. This parser extracts typed fields
//! directly from the byte slice without building a HashMap.
//!
//! Record format:
//!   `audit(TIMESTAMP.MS:SERIAL): key1=val1 key2="quoted val" ...`

// ── Header parsing ─────────────────────────────────────────────────

/// Extract the serial number from `audit(TIMESTAMP:SERIAL): ...`
pub fn parse_serial(input: &[u8]) -> Option<u64> {
    let pos = input.windows(6).position(|w| w == b"audit(")?;
    let after = &input[pos + 6..];
    let colon = after.iter().position(|&b| b == b':')?;
    let end = after.iter().position(|&b| b == b')')?;
    let serial_bytes = &after[colon + 1..end];
    // Fast decimal parse without allocation
    parse_u64_bytes(serial_bytes)
}

/// Extract the wall-clock timestamp from `audit(EPOCH.MS:SERIAL): ...`
/// Returns milliseconds since epoch.
pub fn parse_timestamp_ms(input: &[u8]) -> Option<u64> {
    let pos = input.windows(6).position(|w| w == b"audit(")?;
    let after = &input[pos + 6..];
    let colon = after.iter().position(|&b| b == b':')?;
    let ts_bytes = &after[..colon];
    // Format: "1775080751.254" → seconds.milliseconds
    if let Some(dot) = ts_bytes.iter().position(|&b| b == b'.') {
        let secs = parse_u64_bytes(&ts_bytes[..dot])?;
        let ms = parse_u64_bytes(&ts_bytes[dot + 1..])?;
        Some(secs * 1000 + ms)
    } else {
        let secs = parse_u64_bytes(ts_bytes)?;
        Some(secs * 1000)
    }
}

/// Return the slice after "): " (the fields portion).
fn skip_header(input: &[u8]) -> &[u8] {
    match input.windows(3).position(|w| w == b"): ") {
        Some(pos) => &input[pos + 3..],
        None => input,
    }
}

// ── Field extraction (zero-copy, no HashMap) ───────────────────────

/// Find a field value by key. Returns (raw_bytes, was_quoted).
/// Quoted values (`key="val"`) are plaintext; unquoted values (`key=HEX`)
/// may be hex-encoded by the kernel (AUDIT_EXECVE encodes args containing
/// control characters as raw hex without quotes).
fn find_field_ex<'a>(input: &'a [u8], key: &[u8]) -> Option<(&'a [u8], bool)> {
    // Search for ` key=` or start-of-input `key=`
    let needle_len = key.len() + 1; // key + '='
    let mut pos = 0;
    while pos < input.len() {
        // Check if key matches at this position (must be preceded by space or start)
        let at_start = pos == 0 || input[pos - 1] == b' ';
        if at_start
            && pos + needle_len <= input.len()
            && &input[pos..pos + key.len()] == key
            && input[pos + key.len()] == b'='
        {
            let val_start = pos + needle_len;
            // Handle double-equals (subj==unconfined)
            let val_start = if val_start < input.len() && input[val_start] == b'=' {
                val_start + 1
            } else {
                val_start
            };

            if val_start >= input.len() {
                return Some((b"", true));
            }

            return if input[val_start] == b'"' {
                // Quoted value (plaintext)
                let content_start = val_start + 1;
                let end = input[content_start..].iter()
                    .position(|&b| b == b'"')
                    .map(|i| content_start + i)
                    .unwrap_or(input.len());
                Some((&input[content_start..end], true))
            } else {
                // Unquoted value — may be hex-encoded by kernel
                let end = input[val_start..].iter()
                    .position(|&b| b == b' ')
                    .map(|i| val_start + i)
                    .unwrap_or(input.len());
                Some((&input[val_start..end], false))
            };
        }
        // Advance to next space
        match input[pos..].iter().position(|&b| b == b' ') {
            Some(skip) => pos += skip + 1,
            None => break,
        }
    }
    None
}

/// Shorthand: get raw bytes only (ignoring quoted flag).
fn find_field<'a>(input: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    find_field_ex(input, key).map(|(bytes, _)| bytes)
}

/// Extract a u32 field, or 0 if not found.
fn field_u32(input: &[u8], key: &[u8]) -> u32 {
    find_field(input, key)
        .and_then(parse_u32_bytes)
        .unwrap_or(0)
}

/// Extract a u64 field that is always hex (no 0x prefix).
/// The kernel's a0-a3 syscall argument fields are always raw hex.
fn field_raw_hex(input: &[u8], key: &[u8]) -> u64 {
    find_field(input, key)
        .map(parse_raw_hex_bytes)
        .unwrap_or(0)
}

/// Extract a string field, or empty string if not found.
fn field_str<'a>(input: &'a [u8], key: &[u8]) -> &'a str {
    find_field(input, key)
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("")
}

/// Extract a string field, auto-decoding hex if the kernel hex-encoded it.
/// Quoted values (`key="plaintext"`) are returned as-is.
/// Unquoted values (`key=4865786865`) are hex-decoded to "Hexhe".
fn field_string_decoded(input: &[u8], key: &[u8]) -> String {
    match find_field_ex(input, key) {
        Some((bytes, true)) => {
            // Quoted = plaintext
            std::str::from_utf8(bytes).unwrap_or("").to_string()
        }
        Some((bytes, false)) => {
            // Unquoted = possibly hex-encoded by kernel
            if looks_hex_encoded(bytes) {
                decode_hex_string(bytes)
            } else {
                std::str::from_utf8(bytes).unwrap_or("").to_string()
            }
        }
        None => String::new(),
    }
}

/// Check if a field equals a specific value.
fn field_eq(input: &[u8], key: &[u8], expected: &[u8]) -> bool {
    find_field(input, key).is_some_and(|v| v == expected)
}

// ── Typed record parsers ───────────────────────────────────────────

/// Parsed AUDIT_SYSCALL record fields.
pub struct SyscallFields<'a> {
    pub pid: u32,
    pub ppid: u32,
    pub syscall: u32,
    pub success: bool,
    pub comm: &'a str,
    pub exe: &'a str,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub exit_value: i64,
    pub subj: &'a str,
}

/// Parse an AUDIT_SYSCALL payload.
pub fn parse_syscall(payload: &[u8]) -> SyscallFields<'_> {
    let fields = skip_header(payload);
    SyscallFields {
        pid: field_u32(fields, b"pid"),
        ppid: field_u32(fields, b"ppid"),
        syscall: field_u32(fields, b"syscall"),
        success: field_eq(fields, b"success", b"yes"),
        comm: field_str(fields, b"comm"),
        exe: field_str(fields, b"exe"),
        a0: field_raw_hex(fields, b"a0"),
        a1: field_raw_hex(fields, b"a1"),
        a2: field_raw_hex(fields, b"a2"),
        a3: field_raw_hex(fields, b"a3"),
        exit_value: find_field(fields, b"exit")
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1),
        subj: field_str(fields, b"subj"),
    }
}

/// Parsed AUDIT_PATH record fields.
pub struct PathFields<'a> {
    pub item: u32,
    pub name: &'a str,
    pub nametype: &'a str,
}

/// Parse an AUDIT_PATH payload.
pub fn parse_path(payload: &[u8]) -> PathFields<'_> {
    let fields = skip_header(payload);
    PathFields {
        item: field_u32(fields, b"item"),
        name: field_str(fields, b"name"),
        nametype: field_str(fields, b"nametype"),
    }
}

/// Parsed AUDIT_SOCKADDR record.
pub struct SockaddrFields<'a> {
    pub saddr: &'a str,
}

/// Parse an AUDIT_SOCKADDR payload.
pub fn parse_sockaddr(payload: &[u8]) -> SockaddrFields<'_> {
    let fields = skip_header(payload);
    SockaddrFields {
        saddr: field_str(fields, b"saddr"),
    }
}

/// Parsed AUDIT_CWD record.
pub struct CwdFields<'a> {
    pub cwd: &'a str,
}

/// Parse an AUDIT_CWD payload.
pub fn parse_cwd(payload: &[u8]) -> CwdFields<'_> {
    let fields = skip_header(payload);
    CwdFields {
        cwd: field_str(fields, b"cwd"),
    }
}

/// Parse an AUDIT_EXECVE payload. Returns decoded argv strings.
/// The kernel hex-encodes args containing control characters (newlines, etc.);
/// this function transparently decodes them.
pub fn parse_execve_args(payload: &[u8]) -> Vec<String> {
    let fields = skip_header(payload);
    let argc = field_u32(fields, b"argc") as usize;
    let mut args = Vec::with_capacity(argc);
    for i in 0..argc {
        let key = format!("a{i}");
        args.push(field_string_decoded(fields, key.as_bytes()));
    }
    args
}

// ── Hex decoding (for kernel-encoded EXECVE args) ──────────────────

/// Check if a byte slice looks like a hex-encoded string from the kernel.
/// Must be non-empty, even length, and all hex digits.
fn looks_hex_encoded(b: &[u8]) -> bool {
    b.len() >= 2
        && b.len() % 2 == 0
        && b.iter().all(|&c| c.is_ascii_hexdigit())
}

/// Decode a hex-encoded byte string, escaping control characters
/// so the result is a readable single-line string.
/// e.g., `6563686F0A` → `echo\n`
fn decode_hex_string(hex_bytes: &[u8]) -> String {
    let hex_str = std::str::from_utf8(hex_bytes).unwrap_or("");
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return hex_str.to_string(), // not valid hex, return as-is
    };

    let mut out = String::with_capacity(bytes.len());
    for &b in &bytes {
        match b {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b'\0' => out.push_str("\\0"),
            0x20..=0x7e => out.push(b as char),
            _ => {
                out.push_str(&format!("\\x{:02x}", b));
            }
        }
    }
    out
}

// ── Numeric parsing (no allocation) ────────────────────────────────

fn parse_u64_bytes(b: &[u8]) -> Option<u64> {
    let mut n: u64 = 0;
    for &ch in b {
        if ch < b'0' || ch > b'9' {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((ch - b'0') as u64)?;
    }
    Some(n)
}

fn parse_u32_bytes(b: &[u8]) -> Option<u32> {
    parse_u64_bytes(b).and_then(|n| u32::try_from(n).ok())
}

/// Parse raw hex bytes (no 0x prefix) as u64.
fn parse_raw_hex_bytes(b: &[u8]) -> u64 {
    let mut n: u64 = 0;
    for &ch in b {
        let digit = match ch {
            b'0'..=b'9' => ch - b'0',
            b'a'..=b'f' => ch - b'a' + 10,
            b'A'..=b'F' => ch - b'A' + 10,
            _ => return n,
        };
        n = n.wrapping_mul(16).wrapping_add(digit as u64);
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_serial() {
        let input = b"audit(1775080751.254:146448013): arch=c000003e syscall=2";
        assert_eq!(parse_serial(input), Some(146448013));
    }

    #[test]
    fn test_parse_syscall() {
        let input = b"audit(1234.567:890): arch=c000003e syscall=2 success=yes exit=3 a0=7ffd85c1cf5e a1=8000 a2=0 a3=0 pid=100 ppid=99 comm=\"cat\" exe=\"/bin/busybox\" subj=docker-default key=\"syscon\"";
        let f = parse_syscall(input);
        assert_eq!(f.pid, 100);
        assert_eq!(f.ppid, 99);
        assert_eq!(f.syscall, 2);
        assert!(f.success);
        assert_eq!(f.exit_value, 3);
        assert_eq!(f.a0, 0x7ffd85c1cf5e);
        assert_eq!(f.a1, 0x8000);
        assert_eq!(f.comm, "cat");
        assert_eq!(f.exe, "/bin/busybox");
        assert_eq!(f.subj, "docker-default");
    }

    #[test]
    fn test_parse_path() {
        let input = b"audit(1234.567:890): item=0 name=\"/opt/configs/api_tokens.json\" inode=1053939 nametype=NORMAL";
        let f = parse_path(input);
        assert_eq!(f.item, 0);
        assert_eq!(f.name, "/opt/configs/api_tokens.json");
        assert_eq!(f.nametype, "NORMAL");
    }

    #[test]
    fn test_parse_path_parent() {
        let input = b"audit(1234.567:890): item=0 name=\"/opt/configs\" nametype=PARENT";
        let f = parse_path(input);
        assert_eq!(f.nametype, "PARENT");
    }

    #[test]
    fn test_double_equals() {
        // subj==unconfined (SELinux double-equals)
        let input = b"audit(1234:5): pid=1 subj==unconfined syscall=1";
        let f = parse_syscall(input);
        assert_eq!(f.pid, 1);
        assert_eq!(f.subj, "unconfined");
    }

    #[test]
    fn test_raw_hex_fields() {
        // Kernel a0-a3 are always raw hex (no 0x prefix)
        let input = b"audit(1:2): a0=ff a1=8000 a2=0 a3=DEAD";
        let fields = skip_header(input);
        assert_eq!(field_raw_hex(fields, b"a0"), 0xff);
        assert_eq!(field_raw_hex(fields, b"a1"), 0x8000);
        assert_eq!(field_raw_hex(fields, b"a2"), 0);
        assert_eq!(field_raw_hex(fields, b"a3"), 0xDEAD);
    }

    #[test]
    fn test_sockaddr() {
        let input = b"audit(1:2): saddr=020001BB8EFBD3BB0000000000000000SADDR={...}";
        let f = parse_sockaddr(input);
        // saddr stops at space, so includes trailing SADDR annotation
        // The caller strips SADDR={...} separately
        assert!(f.saddr.starts_with("020001BB"));
    }

    #[test]
    fn test_execve_plaintext() {
        let input = b"audit(1:2): argc=3 a0=\"curl\" a1=\"-sf\" a2=\"http://example.com\"";
        let args = parse_execve_args(input);
        assert_eq!(args, vec!["curl", "-sf", "http://example.com"]);
    }

    #[test]
    fn test_execve_hex_decoded() {
        // Kernel hex-encodes args with control chars (newlines etc.)
        // "echo hello\n" = 6563686F2068656C6C6F0A
        let input = b"audit(1:2): argc=3 a0=\"sh\" a1=\"-c\" a2=6563686F2068656C6C6F0A6563686F20776F726C64";
        let args = parse_execve_args(input);
        assert_eq!(args[0], "sh");
        assert_eq!(args[1], "-c");
        assert_eq!(args[2], "echo hello\\necho world"); // newline escaped
    }
}
