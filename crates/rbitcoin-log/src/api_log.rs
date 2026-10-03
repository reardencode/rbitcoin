//! Optional JSONL API call log (`--api-log PATH`).
//!
//! Always emits a TRACE `api:` line. When [`init_api_log`] has been called,
//! also appends one JSON object per call so the operator can `tail -f` without
//! turning the main log up.

use crate::{format_timestamp, trace};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

const PARAMS_MAX: usize = 384;

static API_LOG: Mutex<Option<File>> = Mutex::new(None);

/// Open (append) `path` as the process API call log.
pub fn init_api_log(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let f = OpenOptions::new().create(true).append(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut g = API_LOG.lock().unwrap_or_else(|e| e.into_inner());
    *g = Some(f);
    Ok(())
}

/// Stop writing the API call file (tests).
pub fn close_api_log() {
    let mut g = API_LOG.lock().unwrap_or_else(|e| e.into_inner());
    *g = None;
}

/// Truncate a params blob for the log (UTF-8 safe).
fn compact_params(params: &str) -> String {
    if params.len() <= PARAMS_MAX {
        return params.to_string();
    }
    let mut end = PARAMS_MAX;
    while end > 0 && !params.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &params[..end])
}

/// Record one Electrum / Esplora / RPC call.
///
/// Extended private keys and silent-payment scan secrets are stripped here,
/// then the params blob is compacted. `err` is `None` on success.
pub fn api_call(
    surface: &str,
    peer: &str,
    method: &str,
    params: &str,
    wall_ms: u64,
    err: Option<&str>,
) {
    let params = compact_params(&redact_secrets(method, params));
    match err {
        None => trace!("api: {surface} peer={peer} {method} {params} wall_ms={wall_ms} ok"),
        Some(e) => trace!("api: {surface} peer={peer} {method} {params} wall_ms={wall_ms} err={e}"),
    }

    let mut g = API_LOG.lock().unwrap_or_else(|e| e.into_inner());
    let Some(file) = g.as_mut() else {
        return;
    };
    let ts = format_timestamp(SystemTime::now());
    let ok = err.is_none();
    let err_json = match err {
        None => "null".to_string(),
        Some(e) => format!("\"{}\"", json_escape(e)),
    };
    let line = format!(
        "{{\"ts\":\"{ts}\",\"surface\":\"{}\",\"peer\":\"{}\",\"method\":\"{}\",\"params\":\"{}\",\"wall_ms\":{wall_ms},\"ok\":{ok},\"err\":{err_json}}}\n",
        json_escape(surface),
        json_escape(peer),
        json_escape(method),
        json_escape(&params),
    );
    let _ = file.write_all(line.as_bytes());
    let _ = file.flush();
}

fn redact_secrets(method: &str, params: &str) -> String {
    let out = redact_ext_privkeys(params);
    if method.contains("silentpayment") {
        redact_quoted_hex64(&out)
    } else {
        out
    }
}

fn is_base58(b: u8) -> bool {
    matches!(
        b,
        b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z'
    )
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// `xprv` / `tprv` / `yprv` / `zprv` plus the following base58 key material.
fn redact_ext_privkeys(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if i + 4 <= b.len() {
            let tag = &b[i..i + 4];
            if matches!(tag, b"xprv" | b"tprv" | b"yprv" | b"zprv") {
                let mut j = i + 4;
                while j < b.len() && is_base58(b[j]) {
                    j += 1;
                }
                if j > i + 4 {
                    out.push_str("<redacted>");
                    i = j;
                    continue;
                }
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// A quoted 64-hex string is a silent-payment scan secret on that method.
fn redact_quoted_hex64(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"'
            && i + 65 < b.len()
            && b[i + 65] == b'"'
            && b[i + 1..i + 65].iter().copied().all(is_hex)
        {
            out.push_str("\"<redacted>\"");
            i += 66;
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn compact_params_truncates() {
        assert_eq!(compact_params("[]"), "[]");
        let long = "x".repeat(500);
        let c = compact_params(&long);
        assert!(c.ends_with('…'));
        assert!(c.len() < 400);
    }

    #[test]
    fn api_log_file_records_json_line() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-api-log-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&path);
        init_api_log(&path).unwrap();
        api_call(
            "electrum",
            "127.0.0.1:1",
            "blockchain.tweaks.subscribe",
            "[0,1,false]",
            12,
            None,
        );
        api_call(
            "electrum",
            "127.0.0.1:1",
            "no.such",
            "[]",
            1,
            Some("unknown method: no.such"),
        );
        close_api_log();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "api log must be owner-only");
        }
        let body = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(body.contains("\"method\":\"blockchain.tweaks.subscribe\""));
        assert!(body.contains("\"params\":\"[0,1,false]\""));
        assert!(body.contains("\"wall_ms\":12"));
        assert!(!body.contains("join_ms"));
        assert!(body.contains("\"ok\":true"));
        assert!(body.contains("\"ok\":false"));
        assert!(body.contains("unknown method"));
    }

    #[test]
    fn api_stderr_line_is_trace() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::capture_logs(true);
        api_call("electrum", "127.0.0.1:1", "server.ping", "[]", 3, None);
        let logs = crate::take_logs();
        crate::capture_logs(false);
        let (level, msg) = logs.last().expect("api_call stderr");
        assert_eq!(*level, crate::Level::Trace, "{msg}");
        assert!(msg.contains("api: electrum"), "{msg}");
        assert!(msg.contains("server.ping"), "{msg}");
    }

    #[test]
    fn json_escape_quotes() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn api_call_redacts_scan_secrets_and_ext_privkeys() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let scan = "ab".repeat(32);
        let xprv = format!("xprv{}", "1".repeat(40));
        let tprv = format!("tprv{}", "A".repeat(20));
        let path = std::env::temp_dir().join(format!(
            "rbitcoin-api-redact-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&path);
        init_api_log(&path).unwrap();
        crate::capture_logs(true);
        api_call(
            "electrum",
            "127.0.0.1:1",
            "blockchain.silentpayments.unsubscribe",
            &format!("[\"{scan}\",\"02ff\",1]"),
            4,
            None,
        );
        api_call(
            "rpc",
            "-",
            "scantxoutset",
            &format!("[\"start\",[\"{xprv}\",\"{tprv}\"]]"),
            5,
            None,
        );
        let logs = crate::take_logs();
        crate::capture_logs(false);
        close_api_log();
        let body = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let trace = logs
            .iter()
            .map(|(_, msg)| msg.clone())
            .collect::<Vec<_>>()
            .join("\n");
        let all = format!("{body}\n{trace}");
        assert!(!all.contains(&scan), "{all}");
        assert!(!all.contains(&xprv), "{all}");
        assert!(!all.contains(&tprv), "{all}");
        assert!(all.contains("<redacted>"), "{all}");
    }
}
