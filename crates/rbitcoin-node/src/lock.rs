//! Exclusive datadir / blocksdir flock (Core `LockDirectory`).

use crate::config::NodeConfig;
use crate::error::NodeError;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

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

/// Exclusive-lock the process datadir, `{datadir}/blocks`, and optional `--blocksdir`.
pub fn lock_node_dirs(config: &NodeConfig) -> Result<DirLocks, NodeError> {
    let mut files = Vec::new();
    let datadir = config.datadir.path();
    files.push(lock_dir(datadir)?);
    let default_blocks = datadir.join("blocks");
    std::fs::create_dir_all(&default_blocks).map_err(|source| NodeError::Datadir {
        path: default_blocks.clone(),
        source,
    })?;
    files.push(lock_dir(&default_blocks)?);
    if let Some(extra) = &config.blocks_dir {
        std::fs::create_dir_all(extra).map_err(|source| NodeError::Datadir {
            path: extra.clone(),
            source,
        })?;
        if extra != &default_blocks {
            files.push(lock_dir(extra)?);
        }
    }
    Ok(DirLocks { _files: files })
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
    fn second_lock_on_same_datadir_is_busy() {
        let dir = tmp();
        let cfg = NodeConfig::default().with_datadir(&dir).with_tiny_heads();
        let _held = lock_node_dirs(&cfg).expect("first lock");
        let err = lock_node_dirs(&cfg).expect_err("second lock");
        match err {
            NodeError::Locked(ref p) => {
                assert!(*p == dir || *p == dir.join("blocks"), "locked {p:?}");
            }
            other => panic!("expected Locked, got {other}"),
        }
        assert!(
            format!("{err}").contains("Cannot obtain a lock on directory"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extra_blocksdir_lock_collides_across_datadirs() {
        let dir = tmp();
        let extra = dir.join("ext-blocks");
        std::fs::create_dir_all(&extra).unwrap();
        let other = dir.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let mut cfg_a = NodeConfig::default()
            .with_datadir(dir.join("a"))
            .with_tiny_heads();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        cfg_a.blocks_dir = Some(extra.clone());
        let _held = lock_node_dirs(&cfg_a).expect("first extra lock");
        let mut cfg_b = NodeConfig::default().with_datadir(&other).with_tiny_heads();
        cfg_b.blocks_dir = Some(extra);
        let err = lock_node_dirs(&cfg_b).expect_err("blocksdir collision");
        assert!(
            matches!(err, NodeError::Locked(_)),
            "expected Locked, got {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
