use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum StoreError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    BadMagic,
    BadSchema(u16),
    BadKind {
        expected: u16,
        got: u16,
    },
    NotFound,
    InvalidFk,
    NotDirectory(PathBuf),
    Corrupt(&'static str),
    /// Soft capacity (io_uring SQ in-flight cap) — not data corruption.
    BudgetFull(&'static str),
    /// Cooperative abort (SIGINT / IBD stop) — not data corruption.
    Cancelled(&'static str),
    /// io_uring cannot be opened in this process — not on-disk corruption.
    Unavailable,
    /// Operator layout / open-option error (not on-disk corruption).
    Layout(String),
    /// Published chain prefix moved (reorg) during a confirmed-tx read. Retry.
    Stale(&'static str),
}

impl StoreError {
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        StoreError::Io {
            path: path.into(),
            source,
        }
    }

    /// Ring in-flight cap — not on-disk corruption. Do not WARN as `corrupt record`.
    pub fn is_io_backpressure(&self) -> bool {
        matches!(self, StoreError::BudgetFull(m) if m.contains("SQ"))
    }

    /// Completion-session failure (not on-disk corruption, not SQ backpressure).
    pub fn is_uring_session_fault(&self) -> bool {
        match self {
            StoreError::Corrupt(m) => Self::is_uring_session_fault_msg(m),
            _ => false,
        }
    }

    pub fn is_uring_session_fault_msg(m: &str) -> bool {
        m.contains("io_uring undrained")
            || m.contains("io_uring wait timeout")
            || m.contains("io_uring session poisoned")
            || m.contains("io_uring unexpected cqe")
            || m.contains("io_uring cq overflow")
            || m.contains("io_uring submit_and_wait failed")
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { path, source } => {
                write!(f, "io error at {}: {source}", path.display())
            }
            StoreError::BadMagic => f.write_str("invalid store magic"),
            StoreError::BadSchema(v) => write!(f, "unsupported schema version {v}"),
            StoreError::BadKind { expected, got } => {
                write!(f, "unexpected table kind (expected {expected}, got {got})")
            }
            StoreError::NotFound => f.write_str("record not found"),
            StoreError::InvalidFk => f.write_str("invalid foreign key"),
            StoreError::NotDirectory(p) => {
                write!(f, "store path is not a directory: {}", p.display())
            }
            StoreError::Corrupt(m) => write!(f, "corrupt record: {m}"),
            StoreError::BudgetFull(m) => write!(f, "budget full: {m}"),
            StoreError::Cancelled(m) => write!(f, "cancelled: {m}"),
            StoreError::Unavailable => f.write_str("io_uring unavailable"),
            StoreError::Layout(m) => write!(f, "{m}"),
            StoreError::Stale(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn display_and_source_arms() {
        let io = StoreError::io("/tmp/x", io::Error::new(io::ErrorKind::NotFound, "nope"));
        let s = io.to_string();
        assert!(s.contains("io error"));
        assert!(s.contains("/tmp/x"));
        assert!(io.source().is_some());

        let arms: Vec<StoreError> = vec![
            StoreError::BadMagic,
            StoreError::BadSchema(9),
            StoreError::BadKind {
                expected: 1,
                got: 2,
            },
            StoreError::NotFound,
            StoreError::InvalidFk,
            StoreError::NotDirectory(PathBuf::from("/not/a/dir")),
            StoreError::Corrupt("broken"),
            StoreError::BudgetFull("block_queue"),
            StoreError::Cancelled("stop"),
            StoreError::Unavailable,
            StoreError::Layout("inwit is on a cold datadir".into()),
            StoreError::Stale("chain view moved"),
        ];
        let texts: Vec<String> = arms.iter().map(|e| e.to_string()).collect();
        assert_eq!(texts[0], "invalid store magic");
        assert!(texts[1].contains("unsupported schema version 9"));
        assert!(texts[2].contains("expected 1"));
        assert!(texts[2].contains("got 2"));
        assert_eq!(texts[3], "record not found");
        assert_eq!(texts[4], "invalid foreign key");
        assert!(texts[5].contains("not a directory"));
        assert!(texts[6].contains("corrupt record: broken"));
        assert!(texts[7].contains("budget full: block_queue"));
        assert!(texts[8].contains("cancelled: stop"));
        assert_eq!(texts[9], "io_uring unavailable");
        assert_eq!(texts[10], "inwit is on a cold datadir");
        assert_eq!(texts[11], "chain view moved");
        for e in &arms {
            assert!(e.source().is_none());
        }

        let sq = StoreError::BudgetFull("io_session SQ (in_flight cap)");
        assert!(sq.is_io_backpressure());
        assert!(
            !sq.to_string().contains("corrupt"),
            "SQ full must not print as corrupt record: {}",
            sq
        );
        assert!(!StoreError::Corrupt("broken").is_io_backpressure());
    }

    #[test]
    fn uring_session_fault_strings() {
        for m in [
            "invariant: io_uring undrained",
            "invariant: io_uring wait timeout",
            "invariant: io_uring session poisoned",
            "invariant: io_uring unexpected cqe",
            "invariant: io_uring cq overflow",
            "io_uring submit_and_wait failed",
        ] {
            assert!(StoreError::Corrupt(m).is_uring_session_fault(), "{m}");
        }
        assert!(!StoreError::BudgetFull("io_uring SQ").is_uring_session_fault());
        assert!(!StoreError::Unavailable.is_uring_session_fault());
        assert!(!StoreError::Corrupt("broken").is_uring_session_fault());
        assert!(!StoreError::Io {
            path: PathBuf::from("/tmp/x"),
            source: io::Error::other("disk"),
        }
        .is_uring_session_fault());
    }
}
