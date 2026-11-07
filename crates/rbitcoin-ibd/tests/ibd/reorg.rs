use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, CompactTarget, Target};
use rbitcoin_ibd::ibd::reorg::*;
use rbitcoin_net::chain::ChainHub;
use rbitcoin_net::error::NetError;
use rbitcoin_primitives::Height;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// An unproved walk may rewind through its lead, which is deeper than 1,024.
/// A proved walk still stops at [`REWIND_MAX_DEPTH`].
#[test]
fn unproved_lead_rewinds_past_1024_and_a_proved_walk_does_not() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut prev = gen;
    let mut time = 1_500_080_000u32;
    for height in 1..=1_025u32 {
        time = time.saturating_add(600);
        let block = mine(prev, time, height);
        hub.accept_block(block.clone()).unwrap();
        prev = block.block_hash();
    }
    assert_eq!(hub.tip_height(), Some(1_025));
    let side = distinct_sib(mine(gen, 1_500_080_100, 1), prev);
    hub.ensure_header(&side.header).unwrap();
    let path = [side.block_hash()];
    assert!(
        prepare_header_rewind(&hub, &path, REWIND_MAX_DEPTH)
            .unwrap()
            .is_none(),
        "1,025 blocks is past the proved cap, and this call must not move the tip"
    );
    assert_eq!(hub.tip_height(), Some(1_025));
    assert!(
        prepare_header_rewind(
            &hub,
            &path,
            rbitcoin_ibd::ibd::header_walk::UNPROVEN_LEAD_BLOCKS
        )
        .unwrap()
        .is_some(),
        "1,025 is inside the unproved lead and not past it"
    );
    // That prepare disconnected. The proved-walk case needs its own chain.
    let (dir_proved, hub_proved) = tmp_hub();
    hub_proved.ensure_genesis().unwrap();
    let gen_b = hub_proved.tip_hash().unwrap();
    let mut prev_b = gen_b;
    let mut time_b = 1_500_090_000u32;
    for height in 1..=1_025u32 {
        time_b = time_b.saturating_add(600);
        let block = mine(prev_b, time_b, height);
        hub_proved.accept_block(block.clone()).unwrap();
        prev_b = block.block_hash();
    }
    let side_b = distinct_sib(mine(gen_b, 1_500_090_100, 1), prev_b);
    hub_proved.ensure_header(&side_b.header).unwrap();
    let mut proved = rbitcoin_ibd::ibd::state::IbdWorkState::new(
        Vec::new(),
        hub_proved.tip_hash(),
        hub_proved.tip_height(),
    );
    proved.header_walk.origin = true;
    proved.header_walk.proven = true;
    assert_eq!(
        rbitcoin_ibd::ibd::header_walk::rewind_depth_cap(&proved),
        REWIND_MAX_DEPTH
    );
    assert!(!apply_header_rewind(&mut proved, &hub_proved, &[side_b.block_hash()]).unwrap());
    assert_eq!(hub_proved.tip_height(), Some(1_025));
    let mut unproved =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), Some(prev), Some(1_025));
    unproved.header_walk.origin = true;
    unproved.header_walk.proven = false;
    assert_eq!(
        rbitcoin_ibd::ibd::header_walk::rewind_depth_cap(&unproved),
        rbitcoin_ibd::ibd::header_walk::UNPROVEN_LEAD_BLOCKS
    );
    // The first prepare already disconnected `hub`. Rebuild is the proved hub's
    // twin: a fresh chain checked through `apply_header_rewind`.
    let (dir_lead, hub_lead) = tmp_hub();
    hub_lead.ensure_genesis().unwrap();
    let gen_c = hub_lead.tip_hash().unwrap();
    let mut prev_c = gen_c;
    let mut time_c = 1_500_100_000u32;
    for height in 1..=1_025u32 {
        time_c = time_c.saturating_add(600);
        let block = mine(prev_c, time_c, height);
        hub_lead.accept_block(block.clone()).unwrap();
        prev_c = block.block_hash();
    }
    let side_c = distinct_sib(mine(gen_c, 1_500_100_100, 1), prev_c);
    hub_lead.ensure_header(&side_c.header).unwrap();
    let kept = prev_c;
    let mut lead = rbitcoin_ibd::ibd::state::IbdWorkState::new(
        Vec::new(),
        hub_lead.tip_hash(),
        hub_lead.tip_height(),
    );
    lead.header_walk.origin = true;
    lead.header_walk.proven = false;
    assert!(apply_header_rewind(&mut lead, &hub_lead, &[side_c.block_hash()]).unwrap());
    assert_eq!(hub_lead.tip_height(), Some(0));
    assert!(
        hub_lead
            .query
            .get_header_by_hash(kept.as_byte_array())
            .unwrap()
            .is_some(),
        "the abandoned header row stays"
    );
    let _ = (dir, dir_proved, dir_lead);
}

fn tmp_hub() -> (rbitcoin_query::testutil::TempDir, ChainHub) {
    rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-reorg")
}

fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
    rbitcoin_consensus::mine_empty_regtest(prev, time, height)
}

#[test]
fn header_hashes_to_best_ancestor_walks_mid_path() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let l1 = mine(gen, 1_500_060_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    // Side path not confirmed: w1 → w2
    let mut w1 = mine(gen, 1_500_060_101, 1);
    if w1.block_hash() == l1.block_hash() {
        let target = Target::from_compact(w1.header.bits);
        for nonce in 0..u32::MAX {
            w1.header.nonce = nonce;
            if w1.header.validate_pow(target).is_ok() && w1.block_hash() != l1.block_hash() {
                break;
            }
        }
    }
    hub.ensure_header(&w1.header).unwrap();
    let w2 = mine(w1.block_hash(), 1_500_060_200, 2);
    hub.ensure_header(&w2.header).unwrap();
    let path = header_hashes_to_best_ancestor(&hub, w2.block_hash()).unwrap();
    assert_eq!(
        path,
        vec![w1.block_hash(), w2.block_hash()],
        "oldest-first mid path to LCA"
    );
    // Already on best chain → empty.
    assert!(header_hashes_to_best_ancestor(&hub, l1.block_hash())
        .unwrap()
        .is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn reorg_state_held_awaiting_need_getdata() {
    let mut st = IbdReorgState::new();
    assert!(st.need_getdata().is_empty());
    let gen = BlockHash::from_byte_array([0x11; 32]);
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let held = mine(gen, 1_300_000_000, 1);
    let mut need_h = mine(gen, 1_300_000_001, 1);
    if need_h.block_hash() == held.block_hash() {
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            need_h.header.nonce = nonce;
            if need_h.header.validate_pow(target).is_ok()
                && need_h.block_hash() != held.block_hash()
            {
                break;
            }
        }
    }
    let need = need_h.block_hash();
    st.register_explore([need], None);
    assert_eq!(st.need_getdata(), vec![need]);
    st.hold_body(need_h);
    assert!(st.need_getdata().is_empty(), "held satisfies need");
    let explore = mine(gen, 1_300_000_050, 1);
    let eh = explore.block_hash();
    st.register_explore([eh], Some(eh));
    assert_eq!(st.need_getdata(), vec![eh]);
    st.hold_body(explore);
    assert!(st.need_getdata().is_empty());
    let mut st_cap = IbdReorgState::new();
    let mut held_keys = Vec::new();
    let mut prev = gen;
    for i in 0u32..(IbdReorgState::HELD_CAP as u32 + 4) {
        let b = mine(prev, 1_300_001_000 + i, 1);
        prev = b.block_hash();
        held_keys.push(b.block_hash());
        st_cap.hold_body(b);
    }
    for k in &held_keys {
        st_cap.register_explore([*k], None);
    }
    let still = held_keys
        .iter()
        .filter(|k| !st_cap.need_getdata().contains(k))
        .count();
    assert_eq!(
        still,
        IbdReorgState::HELD_CAP,
        "held map must stay exactly HELD_CAP after overflow inserts"
    );
    let _ = held;
}

fn distinct_sib(mut b: Block, avoid: BlockHash) -> Block {
    if b.block_hash() == avoid {
        let target = Target::from_compact(b.header.bits);
        for nonce in 0..u32::MAX {
            b.header.nonce = nonce;
            if b.header.validate_pow(target).is_ok() && b.block_hash() != avoid {
                break;
            }
        }
    }
    b
}

/// Tip on a 2-block loser; heavier winner headers do not connect at
/// tip+1. Name the connecting hashes (not a dead-tip child).
#[test]
fn heavier_disconnected_path_names_connecting_hashes() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let l1 = mine(gen, 1_500_060_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_500_060_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    assert_eq!(hub.tip_hash().unwrap(), l2.block_hash());

    let w1 = distinct_sib(mine(gen, 1_500_060_101, 1), l1.block_hash());
    hub.ensure_header(&w1.header).unwrap();
    let w2 = mine(w1.block_hash(), 1_500_060_201, 2);
    hub.ensure_header(&w2.header).unwrap();
    let w3 = mine(w2.block_hash(), 1_500_060_301, 3);
    hub.ensure_header(&w3.header).unwrap();
    let w4 = mine(w3.block_hash(), 1_500_060_401, 4);
    hub.ensure_header(&w4.header).unwrap();

    // Connected loser child is not a disconnected heavier path.
    let l3 = mine(l2.block_hash(), 1_500_060_300, 3);
    hub.ensure_header(&l3.header).unwrap();
    assert!(
        connecting_hashes_heavier_disconnected(&hub, l3.block_hash())
            .unwrap()
            .is_none(),
        "child of current tip is a normal extension, not a connecting search"
    );

    let path = connecting_hashes_heavier_disconnected(&hub, w4.block_hash())
        .unwrap()
        .expect("heavier winner that does not connect at tip must name a path");
    assert_eq!(
        path,
        vec![
            w1.block_hash(),
            w2.block_hash(),
            w3.block_hash(),
            w4.block_hash()
        ],
        "path must be winner mids from LCA, not the loser tip+1"
    );
    assert!(!path.contains(&l3.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

/// Work-path tip+1 / far header (no resume seed) still registers the
/// connecting prefix — the live IBD hook, not BadPrev.
#[test]
fn consider_disconnected_from_work_path_without_resume_seed() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let l1 = mine(gen, 1_500_062_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_500_062_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    let w1 = distinct_sib(mine(gen, 1_500_062_101, 1), l1.block_hash());
    hub.ensure_header(&w1.header).unwrap();
    let w2 = mine(w1.block_hash(), 1_500_062_201, 2);
    hub.ensure_header(&w2.header).unwrap();
    let w3 = mine(w2.block_hash(), 1_500_062_301, 3);
    hub.ensure_header(&w3.header).unwrap();
    let w4 = mine(w3.block_hash(), 1_500_062_401, 4);
    hub.ensure_header(&w4.header).unwrap();

    let mut st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    st.record_height(w3.block_hash(), 3);
    st.note_path_prev(w3.block_hash(), w2.block_hash());
    st.record_height(w4.block_hash(), 4);
    st.max_ordered_height = 4;
    let shared = std::sync::Mutex::new(st);
    assert!(rewind_off_coord_lock(&shared, &hub, None).unwrap());
    let st = shared.into_inner().unwrap_or_else(|err| err.into_inner());
    assert_eq!(
        hub.tip_height(),
        Some(0),
        "competing tip+1 must rewind to the LCA"
    );
    assert_eq!(st.height_to_hash.get(&1), Some(&w1.block_hash()));
    assert_eq!(st.height_to_hash.get(&2), Some(&w2.block_hash()));
    assert!(
        st.header_fks.contains_key(&w1.block_hash()),
        "a rewound header keeps the fk the body path needs"
    );
    assert!(
        st.reorg.need_getdata().is_empty(),
        "winner is a linear extension after rewind; need={:?}",
        st.reorg.need_getdata()
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The walk's candidate forks below the confirmed tip, as after a retire
/// walks back and a heavier chain arrives that forked under it. None of it
/// is planted, so the path's next height names no fork. Its stored tip is
/// where the rewind walks back from. A walk tip that is not stored is not,
/// and once a path is planted the walk's tip is not read from the store.
#[test]
fn a_walk_candidate_forked_below_the_tip_is_rewound_to() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let l1 = mine(gen, 1_500_063_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_500_063_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    let w1 = distinct_sib(mine(gen, 1_500_063_101, 1), l1.block_hash());
    let w2 = mine(w1.block_hash(), 1_500_063_201, 2);
    let w3 = mine(w2.block_hash(), 1_500_063_301, 3);
    for w in [&w1, &w2, &w3] {
        hub.ensure_header(&w.header).unwrap();
    }
    let w4 = mine(w3.block_hash(), 1_500_063_401, 4);

    let st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let shared = Mutex::new(st);
    {
        let mut st = shared.lock().unwrap_or_else(|err| err.into_inner());
        st.header_walk.tip.hash = Some(w4.block_hash());
        st.header_walk.tip.height = 4;
    }
    assert!(!consider_disconnected_heavier(&shared, &hub).unwrap());
    assert_eq!(
        hub.tip_height(),
        Some(2),
        "an unstored walk tip is not a rewind"
    );

    {
        let mut st = shared.lock().unwrap_or_else(|err| err.into_inner());
        st.header_walk.tip.hash = Some(w3.block_hash());
        st.header_walk.tip.height = 3;
    }
    assert!(consider_disconnected_heavier(&shared, &hub).unwrap());
    assert_eq!(hub.tip_height(), Some(0), "rewound to the fork");
    {
        let st = shared.lock().unwrap_or_else(|err| err.into_inner());
        assert_eq!(st.height_to_hash.get(&1), Some(&w1.block_hash()));
        assert_eq!(st.height_to_hash.get(&3), Some(&w3.block_hash()));
    }
    reset_parent_hash_of_count();
    assert!(!consider_disconnected_heavier(&shared, &hub).unwrap());
    assert_eq!(
        parent_hash_of_count(),
        0,
        "a planted path is not a store walk"
    );
    let _ = std::fs::remove_dir_all(dir);
}

struct ClearRewindHook;
impl Drop for ClearRewindHook {
    fn drop(&mut self) {
        arm_after_header_rewind_prepare_for_test(None);
        *HOOK_HUB.lock().unwrap_or_else(|err| err.into_inner()) = None;
        *HOOK_SHARED.lock().unwrap_or_else(|err| err.into_inner()) = None;
        HOOK_G1.lock().unwrap_or_else(|err| err.into_inner()).take();
    }
}

static HOOK_HUB: Mutex<Option<Arc<ChainHub>>> = Mutex::new(None);
static HOOK_SHARED: Mutex<Option<Arc<Mutex<rbitcoin_ibd::ibd::state::IbdWorkState>>>> =
    Mutex::new(None);
static HOOK_G1: Mutex<Option<BlockHash>> = Mutex::new(None);
static HOOK_RAN: AtomicBool = AtomicBool::new(false);

/// Stands in for the header thread committing a deeper fork after this
/// prepare already disconnected, and before its commit.
fn commit_deeper_fork_after_prepare() {
    let hub = HOOK_HUB
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .as_ref()
        .expect("hub armed")
        .clone();
    let shared = HOOK_SHARED
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .as_ref()
        .expect("shared armed")
        .clone();
    let g1 = HOOK_G1
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .expect("side hash armed");
    let prep = prepare_header_rewind(&hub, &[g1], REWIND_MAX_DEPTH)
        .unwrap()
        .expect("deeper fork disconnects to genesis");
    let mut st = shared.lock().unwrap_or_else(|err| err.into_inner());
    commit_header_rewind(&mut st, &hub, &[g1], &prep);
    HOOK_RAN.store(true, Ordering::Release);
}

/// The coordinator prepared a rewind to L1. The header thread then rewound
/// to genesis and committed that fork. The prepared L1 commit must not run.
#[test]
fn stale_heavier_rewind_does_not_commit_after_the_tip_moves() {
    let _clear = ClearRewindHook;
    HOOK_RAN.store(false, Ordering::Release);
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let l1 = mine(gen, 1_500_064_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_500_064_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    let w2 = distinct_sib(mine(l1.block_hash(), 1_500_064_201, 2), l2.block_hash());
    let w3 = mine(w2.block_hash(), 1_500_064_301, 3);
    let w4 = mine(w3.block_hash(), 1_500_064_401, 4);
    let w5 = mine(w4.block_hash(), 1_500_064_501, 5);
    for w in [&w2, &w3, &w4, &w5] {
        hub.ensure_header(&w.header).unwrap();
    }
    let g1 = distinct_sib(mine(gen, 1_500_064_111, 1), l1.block_hash());
    hub.ensure_header(&g1.header).unwrap();

    let mut st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    st.header_walk.tip.hash = Some(w5.block_hash());
    st.header_walk.tip.height = 5;
    let shared = Arc::new(Mutex::new(st));
    let hub = Arc::new(hub);
    *HOOK_HUB.lock().unwrap_or_else(|err| err.into_inner()) = Some(Arc::clone(&hub));
    *HOOK_SHARED.lock().unwrap_or_else(|err| err.into_inner()) = Some(Arc::clone(&shared));
    *HOOK_G1.lock().unwrap_or_else(|err| err.into_inner()) = Some(g1.block_hash());
    arm_after_header_rewind_prepare_for_test(Some(commit_deeper_fork_after_prepare));
    rbitcoin_ibd::ibd::settle_disconnected_heavier_for_test(&shared, &hub);

    assert!(
        HOOK_RAN.load(Ordering::Acquire),
        "the header-thread commit ran while the coordinator rewind was prepared"
    );
    assert_eq!(
        hub.tip_height(),
        Some(0),
        "the later rewind to genesis stays the tip"
    );
    assert_eq!(
        hub.query.lookup_taken_hi(),
        Some(0),
        "the prepared L1 commit must not move lookup_taken_hi back up"
    );
    let st = shared.lock().unwrap_or_else(|err| err.into_inner());
    assert!(
        !st.ordered.contains(&w2.block_hash()),
        "losing hashes from the prepared path stay off ordered"
    );
    assert_eq!(st.height_to_hash.get(&1), Some(&g1.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

/// A real block whose prev is not a stored header fails the live confirm
/// load as BadPrev. That reject is soft reget: the tip stays, the slot is
/// evicted, and the hash is not blacklisted or fetched again.
#[test]
fn unknown_prev_header_is_soft_reget_not_a_rewind() {
    use rbitcoin_ibd::ibd::confirm::ConfirmRejectClass;
    use rbitcoin_ibd::ibd::events::apply_confirm_reject;

    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let tip = mine(gen, 1_500_080_100, 1);
    hub.accept_block(tip).unwrap();
    assert_eq!(hub.tip_height(), Some(1));

    let unknown = BlockHash::from_byte_array([0x9e; 32]);
    assert!(
        hub.query
            .get_header_by_hash(&unknown.to_byte_array())
            .unwrap()
            .is_none(),
        "prev must not be a stored header"
    );
    let orphan = mine(unknown, 1_500_080_200, 2);
    let err = match hub.confirm_wire_load_phase(&[(Height(2), orphan.clone())]) {
        Err(e) => e,
        Ok(_) => panic!("unknown prev must fail confirm load"),
    };
    assert!(
        matches!(err, NetError::BadPrev),
        "live load maps ConsensusError::BadPrev, got {err}"
    );
    let msg = err.to_string();
    let class = ConfirmRejectClass::from_net(&err);
    assert_eq!(class, ConfirmRejectClass::SoftWire, "{msg}");
    assert!(is_bad_prev_err(&msg), "{msg}");

    let mut st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    st.headers_done = true;
    st.record_height(orphan.block_hash(), 2);
    apply_confirm_reject(
        &mut st,
        2,
        orphan.block_hash(),
        class,
        &msg,
        Some(hub.query.as_ref()),
        Some(&hub),
        1,
        None,
        None,
        rbitcoin_ibd::ibd::confirm::RejectParent::default(),
    );
    assert_eq!(hub.tip_height(), Some(1), "unknown prev must not rewind");
    assert!(!st.headers_done, "soft reget clears the header latch");
    assert!(
        !st.height_to_hash.contains_key(&2),
        "the rejected slot is evicted"
    );
    assert!(
        !st.reorg
            .invalid
            .contains(orphan.block_hash().to_byte_array()),
        "soft reget does not blacklist"
    );
    assert!(
        !st.reorg.need_getdata().contains(&orphan.block_hash()),
        "BadPrev does not re-get the same hash"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Linear headers ahead of tip are a normal extension, not a fork search.
/// (CI: two_node IBD hung at tip=1 after consider treated h=8 as disconnected.)
#[test]
fn linear_ahead_headers_are_not_a_disconnected_fork() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_500_070_100, 1);
    hub.accept_block(b1.clone()).unwrap();
    let mut prev = b1.block_hash();
    let mut time = 1_500_070_200u32;
    let mut ahead = Vec::new();
    for h in 2..=8u32 {
        let b = mine(prev, time, h);
        hub.ensure_header(&b.header).unwrap();
        prev = b.block_hash();
        time += 100;
        ahead.push((h, prev));
    }
    let last = ahead.last().unwrap().1;
    assert!(
        connecting_hashes_heavier_disconnected(&hub, last)
            .unwrap()
            .is_none(),
        "far header on the same chain as tip is not a disconnected fork"
    );
    let mut st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    for (h, hash) in &ahead {
        st.record_height(*hash, *h);
    }
    st.max_ordered_height = 8;
    let shared = Mutex::new(st);
    let rewound = consider_disconnected_heavier(&shared, &hub).unwrap();
    let st = shared.into_inner().unwrap_or_else(|err| err.into_inner());
    assert!(
        !rewound,
        "linear work-path must not register connecting search; need={:?}",
        st.reorg.need_getdata()
    );
    assert!(st.reorg.need_getdata().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

/// Early IBD: headers sit far above a low tip. The ancestor walk hits its
/// cap on a header-only mid, so join is not a confirmed LCA. That is still
/// a linear extension, not a connecting search.
///
/// Production walk is 10_000; a smaller cap plus ~20 headers hits the same
/// branch without mining a mainnet-scale horizon.
#[test]
fn capped_walk_on_linear_headers_is_not_a_disconnected_fork() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_500_080_100, 1);
    hub.accept_block(b1.clone()).unwrap();
    let mut prev = b1.block_hash();
    let mut time = 1_500_080_200u32;
    let mut last = prev;
    for h in 2..=20u32 {
        let b = mine(prev, time, h);
        hub.ensure_header(&b.header).unwrap();
        prev = b.block_hash();
        last = prev;
        time += 100;
    }
    let path = connecting_hashes_heavier_disconnected_n(&hub, last, 8).unwrap();
    assert!(
        path.is_none(),
        "capped walk whose join is header-only must not start connecting search; got {path:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn connecting_search_skips_linear_tip_plus_one() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut prev = gen;
    let mut time = 1_500_090_100u32;
    let b1 = mine(prev, time, 1);
    hub.accept_block(b1.clone()).unwrap();
    prev = b1.block_hash();
    time += 100;
    let b2 = mine(prev, time, 2);
    hub.accept_block(b2.clone()).unwrap();
    prev = b2.block_hash();
    time += 100;
    let mut st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let mut last = prev;
    for h in 3..=20u32 {
        let b = mine(prev, time, h);
        hub.ensure_header(&b.header).unwrap();
        prev = b.block_hash();
        last = prev;
        time += 100;
        st.record_height(prev, h);
    }
    st.max_ordered_height = 20;
    assert!(
        connecting_search_candidates(&st, &hub).unwrap().is_empty(),
        "linear tip+1 must not be a connecting-search candidate (avoids a 10k max_ordered walk)"
    );
    let shared = Mutex::new(st);
    let rewound = consider_disconnected_heavier(&shared, &hub).unwrap();
    let st = shared.into_inner().unwrap_or_else(|err| err.into_inner());
    assert!(
        !rewound,
        "linear tip+1 + far headers must not register; last={last} need={:?}",
        st.reorg.need_getdata()
    );
    assert!(st.reorg.need_getdata().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn connecting_search_uses_recorded_prev_not_the_header_store() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mut st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let child = BlockHash::from_byte_array([0xab; 32]);
    st.record_height(child, 1);
    st.note_path_prev(child, BlockHash::from_byte_array([0xcd; 32]));
    assert!(
        hub.query
            .get_header_by_hash(&child.to_byte_array())
            .unwrap()
            .is_none(),
        "this hash was never stored"
    );
    assert_eq!(
        connecting_search_candidates(&st, &hub).unwrap(),
        vec![child],
        "a recorded parent that is not the tip is a competing child"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn connecting_search_candidates_is_tip_plus_one_when_competing() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let l1 = mine(gen, 1_500_091_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_500_091_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    let w1 = distinct_sib(mine(gen, 1_500_091_101, 1), l1.block_hash());
    hub.ensure_header(&w1.header).unwrap();
    let w2 = mine(w1.block_hash(), 1_500_091_201, 2);
    hub.ensure_header(&w2.header).unwrap();
    let w3 = mine(w2.block_hash(), 1_500_091_301, 3);
    hub.ensure_header(&w3.header).unwrap();
    let w4 = mine(w3.block_hash(), 1_500_091_401, 4);
    hub.ensure_header(&w4.header).unwrap();
    let mut st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    st.record_height(w3.block_hash(), 3);
    st.note_path_prev(w3.block_hash(), w2.block_hash());
    st.record_height(w4.block_hash(), 4);
    st.max_ordered_height = 4;
    assert_eq!(
        connecting_search_candidates(&st, &hub).unwrap(),
        vec![w3.block_hash()],
        "competing tip+1 is the only candidate; far header is the same fork"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn connecting_search_skips_when_tip_plus_one_is_own_child() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let l1 = mine(gen, 1_500_092_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_500_092_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    let l3 = mine(l2.block_hash(), 1_500_092_300, 3);
    hub.ensure_header(&l3.header).unwrap();
    let w1 = distinct_sib(mine(gen, 1_500_092_101, 1), l1.block_hash());
    hub.ensure_header(&w1.header).unwrap();
    let w2 = mine(w1.block_hash(), 1_500_092_201, 2);
    hub.ensure_header(&w2.header).unwrap();
    let w3 = mine(w2.block_hash(), 1_500_092_301, 3);
    hub.ensure_header(&w3.header).unwrap();
    let w4 = mine(w3.block_hash(), 1_500_092_401, 4);
    hub.ensure_header(&w4.header).unwrap();
    let mut st =
        rbitcoin_ibd::ibd::state::IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    st.record_height(l3.block_hash(), 3);
    st.record_height(w4.block_hash(), 4);
    st.max_ordered_height = 4;
    assert!(
        connecting_search_candidates(&st, &hub).unwrap().is_empty(),
        "own-child tip+1 is linear; heavier far header is not a consider candidate"
    );
    let shared = Mutex::new(st);
    assert!(
        !consider_disconnected_heavier(&shared, &hub).unwrap(),
        "accepted miss: heavier fork only at max_ordered while tip+1 is our child"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn explore_need_and_tips_stay_capped() {
    let mut st = IbdReorgState::new();
    let mut last = BlockHash::from_byte_array([1u8; 32]);
    for i in 0..80u32 {
        let mut raw = [0u8; 32];
        raw[0..4].copy_from_slice(&i.to_le_bytes());
        last = BlockHash::from_byte_array(raw);
        st.register_explore([last], Some(last));
    }
    assert!(
        st.explore_need_hashes().len() <= 64,
        "explore_need grew to {}",
        st.explore_need_hashes().len()
    );
    assert!(
        st.explore_tips().len() <= 64,
        "explore_tips grew to {}",
        st.explore_tips().len()
    );
    assert!(st.explore_need_hashes().contains(&last));
    assert!(st.explore_tips().contains(&last));
}
