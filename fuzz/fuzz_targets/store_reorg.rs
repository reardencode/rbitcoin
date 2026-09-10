#![no_main]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use libfuzzer_sys::fuzz_target;
use rbitcoin_consensus::Milestone;
use rbitcoin_fuzz::tmp_dir;
use rbitcoin_net::{
    check_diff_env, diff_regtest_params, store_reorg_apply, store_reorg_recycle_hub, ChainHub,
};
use rbitcoin_query::Query;

struct Base {
    hub: ChainHub,
    _store: PathBuf,
}

static STATE: Mutex<Option<Base>> = Mutex::new(None);
static APPLIES: AtomicU64 = AtomicU64::new(0);
static COMPARISONS: AtomicU64 = AtomicU64::new(0);

fn harness_failure(what: &str) -> ! {
    eprintln!("=== STORE-REORG FUZZ HARNESS FAILURE ===");
    eprintln!("{what}");
    std::process::exit(2);
}

fn note_comparison(k: u32) {
    let n = COMPARISONS.fetch_add(k as u64, Ordering::Relaxed) + k as u64;
    if n == 1 || n.is_multiple_of(100) {
        eprintln!("store-reorg: comparisons={n}");
    }
}

fn open_base() -> Base {
    if std::env::var_os("RBITCOIN_IO").is_none() {
        std::env::set_var("RBITCOIN_IO", "fd");
    }
    let io = std::env::var("RBITCOIN_IO").ok();
    if let Err(e) = check_diff_env(None, io.as_deref()) {
        harness_failure(e);
    }
    let store = tmp_dir("rbtc-store-reorg");
    let q = Query::open_or_create_tiny(store.join("store")).unwrap_or_else(|e| {
        harness_failure(&format!("query open: {e}"));
    });
    let hub = ChainHub::new(q, diff_regtest_params(), Milestone::NONE);
    hub.ensure_genesis()
        .unwrap_or_else(|e| harness_failure(&format!("genesis: {e}")));
    Base { hub, _store: store }
}

fuzz_target!(|data: &[u8]| {
    let n = APPLIES.fetch_add(1, Ordering::Relaxed);
    let mut slot = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_none() || store_reorg_recycle_hub(n) {
        *slot = Some(open_base());
    }
    let b = slot.as_ref().unwrap();
    match store_reorg_apply(&b.hub, data) {
        Ok(k) if k > 0 => note_comparison(k),
        Ok(_) => {}
        Err(msg) => panic!("store_reorg: {msg}"),
    }
});
