//! Drop-cleaning Tiny [`Query`](crate::Query) for tests. Not an operator API.

pub use rbitcoin_store::testutil::TempDir;

use crate::Query;

/// Tiny-head query in a drop-cleaning directory (not Mainnet GiB heads).
pub fn tiny_query() -> (TempDir, Query) {
    tiny_query_labeled("query")
}

pub fn tiny_query_labeled(label: &str) -> (TempDir, Query) {
    let dir = TempDir::labeled(label).expect("create temp dir");
    let q = Query::open_or_create_tiny(dir.path()).expect("open_or_create_tiny");
    (dir, q)
}
