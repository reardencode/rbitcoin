#![no_main]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rbitcoin_consensus::Milestone;
use rbitcoin_net::{
    check_diff_env, compare_script_verify_one, diff_regtest_params, mine_diff_pad,
    submit_pad_to_oracle, CompareOne, DiffPad, DIFF_MATURE_PAD_HEIGHT,
};
use rbitcoin_query::Query;

use rbitcoin_fuzz::{spawn_bitcoind, tmp_dir, CoreChild};

struct Base {
    core: CoreChild,
    pad: DiffPad,
    _hub: rbitcoin_net::ChainHub,
    _store: PathBuf,
}

static BASE: OnceLock<Base> = OnceLock::new();
static COMPARISONS: AtomicU64 = AtomicU64::new(0);
static ORACLE_DOWN_STREAK: AtomicU64 = AtomicU64::new(0);
const MAX_ORACLE_DOWN_STREAK: u64 = 20;

fn harness_failure(what: &str) -> ! {
    eprintln!("=== SCRIPT-VERIFY-DIFFERENTIAL FUZZ HARNESS FAILURE ===");
    eprintln!("{what}");
    eprintln!(
        "comparisons_before_failure={}",
        COMPARISONS.load(Ordering::Relaxed)
    );
    std::process::exit(2);
}

fn note_comparison() {
    ORACLE_DOWN_STREAK.store(0, Ordering::Relaxed);
    let n = COMPARISONS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_multiple_of(100) {
        eprintln!("script-verify-differential: comparisons={n}");
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
        let store = tmp_dir("rbtc-script-verify-store");
        let core_dir = tmp_dir("rbtc-script-verify-core");
        let q = Query::open_or_create(store.join("store")).unwrap_or_else(|e| {
            harness_failure(&format!("query open: {e}"));
        });
        let params = diff_regtest_params();
        let hub = rbitcoin_net::ChainHub::new(q, params, Milestone::NONE);
        hub.ensure_genesis()
            .unwrap_or_else(|e| harness_failure(&format!("genesis: {e}")));
        let core = spawn_bitcoind(std::path::Path::new(&bin), &core_dir)
            .unwrap_or_else(|e| harness_failure(&e));
        let pad =
            mine_diff_pad(&hub, DIFF_MATURE_PAD_HEIGHT).unwrap_or_else(|e| harness_failure(e));
        if let Err(e) = submit_pad_to_oracle(&core.rpc, &pad.bodies) {
            harness_failure(e);
        }
        Base {
            core,
            pad,
            _hub: hub,
            _store: store,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let b = base();
    match compare_script_verify_one(&b.core.rpc, b.pad.mature, &b.pad.tip, data) {
        CompareOne::NotABlock | CompareOne::Skipped => {
            ORACLE_DOWN_STREAK.store(0, Ordering::Relaxed);
        }
        CompareOne::Agreed { .. } => note_comparison(),
        CompareOne::Disagreed { ours, core, hex } => {
            eprintln!("=== SCRIPT-VERIFY-DIFFERENTIAL FUZZ CONSENSUS DIVERGENCE ===");
            eprintln!("ours_accept={ours} core_accept={core}");
            eprintln!("tx_hex={hex}");
            panic!("script-verify-differential: ours={ours} core={core} hex={hex}");
        }
        CompareOne::Harness(msg) if msg == "oracle dead" => {
            let n = ORACLE_DOWN_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= MAX_ORACLE_DOWN_STREAK {
                harness_failure(msg);
            }
        }
        CompareOne::Harness(msg) => harness_failure(msg),
    }
});
