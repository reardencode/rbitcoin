#![no_main]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rbitcoin_consensus::Milestone;
use rbitcoin_net::{
    check_diff_env, compare_one, diff_regtest_params, genesis_diff_tip, CompareOne, DiffTip,
};
use rbitcoin_query::Query;

use rbitcoin_fuzz::{spawn_bitcoind, tmp_dir, CoreChild};

struct Base {
    hub: rbitcoin_net::ChainHub,
    core: CoreChild,
    tip: std::sync::Mutex<DiffTip>,
    _store: PathBuf,
}

static BASE: OnceLock<Base> = OnceLock::new();
static COMPARISONS: AtomicU64 = AtomicU64::new(0);

fn harness_failure(what: &str) -> ! {
    eprintln!("=== BLOCK-DIFFERENTIAL FUZZ HARNESS FAILURE ===");
    eprintln!("{what}");
    eprintln!(
        "comparisons_before_failure={}",
        COMPARISONS.load(Ordering::Relaxed)
    );
    std::process::exit(2);
}

fn note_comparison() {
    let n = COMPARISONS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_multiple_of(100) {
        eprintln!("block-differential: comparisons={n}");
    }
}

fn base() -> &'static Base {
    BASE.get_or_init(|| {
        let head = std::env::var("RBITCOIN_HEAD_SCALE").ok();
        let io = std::env::var("RBITCOIN_IO").ok();
        if let Err(e) = check_diff_env(head.as_deref(), io.as_deref()) {
            harness_failure(e);
        }
        let bin = std::env::var("RBITCOIN_CORE_BITCOIND").unwrap_or_default();
        if bin.is_empty() {
            harness_failure("RBITCOIN_CORE_BITCOIND unset");
        }
        let store = tmp_dir("rbtc-diff-store");
        let core_dir = tmp_dir("rbtc-diff-core");
        let q = Query::open_or_create(store.join("store")).unwrap_or_else(|e| {
            harness_failure(&format!("query open: {e}"));
        });
        let params = diff_regtest_params();
        let hub = rbitcoin_net::ChainHub::new(q, params.clone(), Milestone::NONE);
        hub.ensure_genesis()
            .unwrap_or_else(|e| harness_failure(&format!("genesis: {e}")));
        let core = spawn_bitcoind(std::path::Path::new(&bin), &core_dir)
            .unwrap_or_else(|e| harness_failure(&e));
        Base {
            hub,
            core,
            tip: std::sync::Mutex::new(genesis_diff_tip(&params)),
            _store: store,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let b = base();
    let mut tip = b.tip.lock().unwrap_or_else(|e| e.into_inner());
    match compare_one(&b.hub, &mut tip, &b.core.rpc, data) {
        CompareOne::NotABlock | CompareOne::Skipped => {}
        CompareOne::Agreed { .. } => note_comparison(),
        CompareOne::Disagreed { ours, core, hex } => {
            eprintln!("=== BLOCK-DIFFERENTIAL FUZZ CONSENSUS DIVERGENCE ===");
            eprintln!("ours_accept={ours} core_accept={core}");
            eprintln!("block_hex={hex}");
            panic!("block-differential: ours={ours} core={core} hex={hex}");
        }
        CompareOne::Harness(msg) => harness_failure(msg),
    }
});
