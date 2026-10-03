//! RPC authentication: Bearer token plus optional Core cookie credentials.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Bearer token accepted by the RPC server.
#[derive(Clone, PartialEq, Eq)]
pub struct RpcAuth {
    pub token: String,
}

impl std::fmt::Debug for RpcAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RpcAuth(<redacted>)")
    }
}

impl RpcAuth {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }

    pub fn matches_token(&self, token: &str) -> bool {
        ct_eq(self.token.as_bytes(), token.as_bytes())
    }
}

/// Core-format `username:password` cookie accepted by an opted-in TCP listener.
#[derive(Clone, PartialEq, Eq)]
pub struct RpcCookie {
    credentials: String,
}

impl RpcCookie {
    pub fn matches_credentials(&self, credentials: &str) -> bool {
        ct_eq(self.credentials.as_bytes(), credentials.as_bytes())
    }
}

/// Compare two byte strings without returning on the first mismatch.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= usize::from(*x ^ *y);
    }
    diff == 0
}

pub fn default_token_path(datadir: &Path) -> PathBuf {
    datadir.join("rpc.token")
}

pub fn default_socket_path(datadir: &Path) -> PathBuf {
    datadir.join("rpc.sock")
}

/// Read a Core-format RPC cookie. The configured file is never created or logged.
///
/// The file must be exactly `username:password` with no line ending, as Core
/// writes it. bitcoin-cli reads the cookie with `getline`, but mempool sends the
/// raw file bytes as Basic credentials, so a trailing newline would make the two
/// clients disagree. Refusing it here turns mempool's endless 401 into a startup
/// error.
pub fn read_cookie_file(path: &Path) -> Result<RpcCookie, String> {
    let credentials =
        fs::read_to_string(path).map_err(|e| format!("read RPC cookie {}: {e}", path.display()))?;
    if credentials.ends_with(['\n', '\r']) {
        return Err(format!(
            "RPC cookie {}: ends with a line ending; write it without one (Core format, e.g. printf not echo)",
            path.display()
        ));
    }
    if credentials.is_empty()
        || credentials.contains(['\n', '\r'])
        || !matches!(credentials.split_once(':'), Some((user, password)) if !user.is_empty() && !password.is_empty())
    {
        return Err(format!(
            "RPC cookie {}: expected username:password",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        static WARNED: AtomicBool = AtomicBool::new(false);
        if let Ok(meta) = fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 && !WARNED.swap(true, Ordering::Relaxed) {
                rbitcoin_log::warn!(
                    "rpc: cookie {} mode {mode:o} is group or world accessible",
                    path.display()
                );
            }
        }
    }
    Ok(RpcCookie { credentials })
}

/// Read an existing token or write a new CSPRNG token (mode 0600).
pub fn resolve_rpc_auth(
    datadir: &Path,
    token_path: Option<&Path>,
) -> Result<(RpcAuth, PathBuf), String> {
    let path = token_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| default_token_path(datadir));
    if path.is_file() {
        let auth = read_token_file(&path)?;
        return Ok((auth, path));
    }
    let auth = write_token_file(&path)?;
    Ok((auth, path))
}

pub fn read_token_file(path: &Path) -> Result<RpcAuth, String> {
    let line =
        fs::read_to_string(path).map_err(|e| format!("read token {}: {e}", path.display()))?;
    let token = line.trim();
    if token.is_empty() {
        return Err(format!("token file {}: empty", path.display()));
    }
    Ok(RpcAuth::new(token))
}

pub fn write_token_file(path: &Path) -> Result<RpcAuth, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("token parent: {e}"))?;
    }
    let auth = RpcAuth::new(random_token());
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("token create: {e}"))?;
    f.write_all(auth.token.as_bytes())
        .map_err(|e| format!("token write: {e}"))?;
    f.sync_all().map_err(|e| format!("token sync: {e}"))?;
    Ok(auth)
}

/// Parse `Authorization: Bearer …`.
pub fn parse_bearer_auth(header: &str) -> Option<&str> {
    let header = header.trim();
    header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Decode `Authorization: Basic …` into Core cookie credentials.
pub fn parse_basic_auth(header: &str) -> Option<String> {
    use base64::Engine;

    let encoded = header
        .trim()
        .strip_prefix("Basic ")
        .or_else(|| header.trim().strip_prefix("basic "))?
        .trim();
    if encoded.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("CSPRNG for RPC token");
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rbitcoin-rpc-auth-{n}"))
    }

    #[test]
    fn debug_does_not_print_the_token() {
        let auth = RpcAuth::new("secret-token");
        let shown = format!("{auth:?}");
        assert!(!shown.contains("secret-token"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    #[test]
    fn token_roundtrip() {
        let dir = tmp();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rpc.token");
        let a = write_token_file(&path).unwrap();
        let b = read_token_file(&path).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.token.len(), 64);
        assert!(a
            .token
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_reuses_existing_token() {
        let dir = tmp();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rpc.token");
        fs::write(&path, "fixed-token\n").unwrap();
        let (a, p) = resolve_rpc_auth(&dir, None).unwrap();
        assert_eq!(a.token, "fixed-token");
        assert_eq!(p, path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_is_csprng_hex() {
        let dir = tmp();
        fs::create_dir_all(&dir).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 0..32 {
            let path = dir.join(format!("rpc.token-{i}"));
            let a = write_token_file(&path).unwrap();
            assert_eq!(a.token.len(), 64);
            assert!(seen.insert(a.token.clone()));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bearer_parse_and_token_paths() {
        assert_eq!(parse_bearer_auth("Bearer abc"), Some("abc"));
        assert_eq!(parse_bearer_auth("bearer xyz"), Some("xyz"));
        assert!(parse_bearer_auth("Bearer ").is_none());
        assert!(parse_bearer_auth("Basic abc").is_none());
        assert_eq!(
            parse_basic_auth("Basic dXNlcjpwYXNz").as_deref(),
            Some("user:pass")
        );
        assert!(parse_basic_auth("Basic !!!").is_none());
        let a = RpcAuth::new("s3cret");
        assert!(a.matches_token("s3cret"));
        assert!(!a.matches_token("nope"));
        assert!(a.matches_token("s3cret"));
        let mut one_bit = a.token.clone().into_bytes();
        one_bit[0] ^= 0x01;
        let one_bit = String::from_utf8(one_bit).unwrap();
        assert!(!a.matches_token(&one_bit));
        assert!(ct_eq(b"s3cret", b"s3cret"));
        assert!(!ct_eq(b"s3cret", one_bit.as_bytes()));
        assert!(
            !ct_eq(b"s3cret", b"s3cre"),
            "shorter equal prefix is not the token"
        );
        assert!(
            !ct_eq(b"s3cret", b"s3cret!"),
            "longer equal prefix is not the token"
        );
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"", b"x"));
        assert_eq!(
            default_socket_path(Path::new("/d")),
            PathBuf::from("/d/rpc.sock")
        );
        assert_eq!(
            default_token_path(Path::new("/d")),
            PathBuf::from("/d/rpc.token")
        );
    }

    #[test]
    fn empty_token_file_errors() {
        let dir = tmp();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rpc.token");
        fs::write(&path, "  \n").unwrap();
        assert!(read_token_file(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cookie_file_requires_one_nonempty_credential_line() {
        let dir = tmp();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".cookie");
        fs::write(&path, "mempool:secret").unwrap();
        let cookie = read_cookie_file(&path).unwrap();
        assert!(cookie.matches_credentials("mempool:secret"));
        assert!(!cookie.matches_credentials("mempool:wrong"));
        for contents in [
            "",
            "\n",
            "mempool",
            ":secret",
            "mempool:",
            "mempool:secret\nnext",
        ] {
            fs::write(&path, contents).unwrap();
            assert!(read_cookie_file(&path).is_err(), "{contents:?}");
        }
        // mempool sends the file verbatim, so a line ending would never match:
        // refuse it with an error that names the fix.
        for contents in ["mempool:secret\n", "mempool:secret\r\n", "mempool:secret\r"] {
            fs::write(&path, contents).unwrap();
            let err = read_cookie_file(&path).err().expect("line ending rejected");
            assert!(err.contains("line ending"), "{contents:?}: {err}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rpc.token");
        let _ = write_token_file(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file mode {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }
}
