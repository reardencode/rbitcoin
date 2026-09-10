//! Shared helpers for high-level scenarios.
//!
//! Prefer writing scenarios in `tests/` that exercise public crate APIs.

pub mod chain_fixture;
pub mod mine;

pub use chain_fixture::{
    assert_reconstruct_eq, build_mature_regtest_with_spend, pad_empty_from, MatureRegtestChain,
};

use std::path::PathBuf;

pub use rbitcoin_store::testutil::TempDir;

/// Temporary datadir that is removed when dropped.
pub struct TestDatadir {
    pub dir: TempDir,
}

impl TestDatadir {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            dir: TempDir::new()?,
        })
    }

    pub fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    pub fn store_path(&self) -> PathBuf {
        self.path().join("store")
    }
}
