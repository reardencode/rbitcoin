//! Historical `getdata` witness-block serve meters for the 5s `tip: perf` line.

use std::sync::atomic::{AtomicU64, Ordering};

static SERVE_N: AtomicU64 = AtomicU64::new(0);
static SERVE_BYTES: AtomicU64 = AtomicU64::new(0);
static SERVE_NTX: AtomicU64 = AtomicU64::new(0);
static SERVE_WALL_NS: AtomicU64 = AtomicU64::new(0);
static SERVE_MAX_NS: AtomicU64 = AtomicU64::new(0);

/// One 5s window of historical block-serve reconstruct+encode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServePerfSample {
    pub n: u64,
    pub bytes: u64,
    pub ntx: u64,
    pub wall_ns: u64,
    pub max_ns: u64,
}

pub(crate) fn note_serve(ntx: u32, bytes: usize, wall_ns: u128) {
    let ns = wall_ns.min(u128::from(u64::MAX)) as u64;
    SERVE_N.fetch_add(1, Ordering::Relaxed);
    SERVE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    SERVE_NTX.fetch_add(u64::from(ntx), Ordering::Relaxed);
    SERVE_WALL_NS.fetch_add(ns, Ordering::Relaxed);
    let mut cur = SERVE_MAX_NS.load(Ordering::Relaxed);
    while ns > cur {
        match SERVE_MAX_NS.compare_exchange_weak(cur, ns, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(c) => cur = c,
        }
    }
}

/// Sample-and-reset serve meters for `DEBUG tip: perf`.
pub fn sample_reset_serve_perf() -> ServePerfSample {
    ServePerfSample {
        n: SERVE_N.swap(0, Ordering::Relaxed),
        bytes: SERVE_BYTES.swap(0, Ordering::Relaxed),
        ntx: SERVE_NTX.swap(0, Ordering::Relaxed),
        wall_ns: SERVE_WALL_NS.swap(0, Ordering::Relaxed),
        max_ns: SERVE_MAX_NS.swap(0, Ordering::Relaxed),
    }
}

/// `serve n= bytes= ntx= avg_us= max_us=` — reconstruct+encode, not BIP324 send.
pub fn format_serve_perf(s: &ServePerfSample) -> String {
    let avg_us = if s.n == 0 { 0 } else { s.wall_ns / s.n / 1_000 };
    let max_us = s.max_ns / 1_000;
    format!(
        "serve n={} bytes={} ntx={} avg_us={} max_us={}",
        s.n, s.bytes, s.ntx, avg_us, max_us
    )
}
