//! Exclusive datadir flock (Core `LockDirectory`).

use crate::config::NodeConfig;
use crate::error::NodeError;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Held exclusive `.lock` files. Dropping releases the flock.
#[derive(Debug)]
pub struct DirLocks {
    _files: Vec<File>,
}

/// Core-shaped lock refusal (operator name is rbitcoin; harness maps CLIENT_NAME).
pub fn lock_busy_msg(dir: &Path) -> String {
    format!(
        "Cannot obtain a lock on directory {}. rbitcoin is probably already running.",
        dir.display()
    )
}

/// Exclusive-lock the process datadir.
pub fn lock_node_dirs(config: &NodeConfig) -> Result<DirLocks, NodeError> {
    Ok(DirLocks {
        _files: vec![lock_dir(config.datadir.path())?],
    })
}

fn lock_dir(dir: &Path) -> Result<File, NodeError> {
    let path = dir.join(".lock");
    match open_lockfile(&path) {
        Ok(file) => match try_exclusive(&file) {
            Ok(()) => Ok(file),
            Err(LockBusy) => Err(NodeError::Locked(dir.to_path_buf())),
        },
        Err(e) if is_lock_busy_io(&e) => Err(NodeError::Locked(dir.to_path_buf())),
        Err(source) => Err(NodeError::Datadir {
            path: path.clone(),
            source,
        }),
    }
}

fn is_lock_busy_io(e: &io::Error) -> bool {
    #[cfg(windows)]
    {
        // ERROR_SHARING_VIOLATION
        e.raw_os_error() == Some(32)
    }
    #[cfg(not(windows))]
    {
        let _ = e;
        false
    }
}

struct LockBusy;

fn open_lockfile(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        // A symlink `.lock` must fail closed. Do not create the target.
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.share_mode(0);
    }
    opts.open(path)
}

fn try_exclusive(file: &File) -> Result<(), LockBusy> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            Ok(())
        } else {
            Err(LockBusy)
        }
    }
    #[cfg(windows)]
    {
        let _ = file;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("rbitcoin-dirlock-{n}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn lock_file_does_not_follow_a_symlink() {
        let dir = tmp();
        let outside = tmp();
        let link = dir.join(".lock");
        std::os::unix::fs::symlink(outside.join("elsewhere.lock"), &link).unwrap();
        let err = lock_dir(&dir).expect_err("symlink lock");
        match err {
            NodeError::Datadir { .. } => {}
            other => panic!("expected datadir open failure, got {other}"),
        }
        assert!(
            !outside.join("elsewhere.lock").exists(),
            "open followed the symlink"
        );
    }

    #[test]
    fn second_lock_on_same_datadir_is_busy() {
        let dir = tmp();
        let cfg = NodeConfig::default().with_datadir(&dir).with_tiny_heads();
        let _held = lock_node_dirs(&cfg).expect("first lock");
        let err = lock_node_dirs(&cfg).expect_err("second lock");
        match err {
            NodeError::Locked(ref p) => assert_eq!(*p, dir, "locked {p:?}"),
            other => panic!("expected Locked, got {other}"),
        }
        assert!(
            format!("{err}").contains("Cannot obtain a lock on directory"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_does_not_create_core_blocks_dir() {
        let dir = tmp();
        let cfg = NodeConfig::default().with_datadir(&dir).with_tiny_heads();
        let _held = lock_node_dirs(&cfg).expect("lock");
        assert!(
            !dir.join("blocks").exists(),
            "rbitcoin has no Core blocks/ product"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
