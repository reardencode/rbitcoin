use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Target, Transaction, TxOut, Work,
};
use rbitcoin_consensus::{genesis_block, mine_regtest_paying, ChainParams, Milestone};
use rbitcoin_net::chain::*;
use rbitcoin_net::error::NetError;
use rbitcoin_net::most_work::work_better;
use rbitcoin_primitives::{Fk, Height};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[test]
fn fork_tips_drop_the_oldest_at_the_cap() {
    let mut tips = ForkTips::new();
    let hashes: Vec<BlockHash> = (0..65u8)
        .map(|i| BlockHash::from_byte_array([i; 32]))
        .collect();
    for hash in &hashes {
        tips.insert(*hash);
    }
    let kept: Vec<BlockHash> = tips.iter().collect();
    assert_eq!(kept.len(), FORK_TIP_CAP);
    assert!(!kept.contains(&hashes[0]));
    assert_eq!(kept[0], hashes[1]);
    assert_eq!(*kept.last().unwrap(), hashes[64]);
    tips.remove(&hashes[1]);
    assert!(!tips.iter().any(|h| h == hashes[1]));
    let before = tips.iter().count();
    tips.insert(hashes[64]);
    assert_eq!(
        tips.iter().count(),
        before,
        "a hash already kept is not moved"
    );
    tips.insert(hashes[1]);
    assert_eq!(tips.iter().count(), before + 1);
    assert_eq!(tips.iter().last(), Some(hashes[1]));
}
use bitcoin::absolute::LockTime;
use bitcoin::block::Version;
use rbitcoin_net::most_work::sum_work;

use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Sequence, TxIn, Witness};

use rbitcoin_mempool::UtxoProvider;
use rbitcoin_query::confirm_scripts_phase;

fn tmp_hub() -> (rbitcoin_query::testutil::TempDir, ChainHub) {
    rbitcoin_net::chain::tiny_regtest_hub_labeled("chain")
}

/// Two classifies of one announcement must not both ask. The claim is the
/// check and the insert under one write lock.
#[test]
fn two_threads_claiming_one_block_produce_one_ask() {
    let (_dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    assert!(
        !hub.claim_block_ask(&tip),
        "a connected block is not an ask"
    );
    let hash = BlockHash::from_byte_array([0x41; 32]);
    let hub = Arc::new(hub);
    let start = Arc::new(std::sync::Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let hub = Arc::clone(&hub);
        let start = Arc::clone(&start);
        threads.push(std::thread::spawn(move || {
            start.wait();
            hub.claim_block_ask(&hash)
        }));
    }
    let wins: usize = threads
        .into_iter()
        .map(|t| usize::from(t.join().expect("claim thread")))
        .sum();
    assert_eq!(wins, 1, "one claim wins the ask");
    assert!(hub.already_have_or_asked_block(&hash));
    assert!(!hub.claim_block_ask(&hash), "the loser stays a loser");
}

/// A full `block.invalid` drops its oldest hash for a new failure, so the
/// newest one survives restart.
#[test]
fn a_full_invalid_file_keeps_the_newest_failure() {
    let (dir, hub) = tmp_hub();
    drop(hub);
    let mut full = b"rbtcinv1".to_vec();
    full.extend_from_slice(&4_096u32.to_le_bytes());
    for i in 0..4_096u32 {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&i.to_le_bytes());
        raw[31] = 0xaa;
        full.extend_from_slice(&raw);
    }
    let marks = dir.path().join("block.invalid");
    std::fs::write(&marks, &full).unwrap();
    let q = rbitcoin_query::Query::open_or_create_tiny(dir.path()).unwrap();
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    let newest = BlockHash::from_byte_array([0xbb; 32]);
    hub.note_failed_connect(newest);
    let kept = std::fs::read(&marks).unwrap();
    assert_eq!(kept.len(), full.len(), "the file stays at its cap");
    assert!(
        kept.windows(32).any(|w| w == newest.as_byte_array()),
        "the newest failure is kept"
    );
    assert!(
        !kept.windows(32).any(|w| w == &full[12..44]),
        "the oldest one gives way"
    );
}

#[test]
fn ancestor_walk_stops_at_cap() {
    let hashes: Vec<BlockHash> = (0..9u8)
        .map(|i| BlockHash::from_byte_array([i + 1; 32]))
        .collect();
    let mut steps = 0u32;
    let got = ancestor_walk(
        &hashes[0],
        4,
        |hash| {
            steps += 1;
            let idx = hashes.iter().position(|h| h == hash)?;
            let prev = *hashes.get(idx + 1)?;
            Some(Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
                time: 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            })
        },
        |hash| (hash == &hashes[8]).then_some(0),
    );
    assert_eq!(got, None);
    assert_eq!(steps, 4);
}

/// A stored header past the cap is still kept, and the next header does
/// not walk those steps again.
#[test]
fn stored_run_past_the_cap_is_kept_and_walks_once() {
    let hashes: Vec<BlockHash> = (0..9u8)
        .map(|i| BlockHash::from_byte_array([i + 1; 32]))
        .collect();
    let header_for = |prev: BlockHash| Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let lookup = |hash: &BlockHash| {
        let idx = hashes.iter().position(|h| h == hash)?;
        let prev = *hashes.get(idx + 1)?;
        Some(header_for(prev))
    };
    let known = |hash: &BlockHash| (hash == &hashes[8]).then_some(0);
    let mut steps = 0u32;
    let mut batch = HashMap::new();
    let cap = 4;
    remember_stored_header(
        &mut batch,
        hashes[0].to_byte_array(),
        hashes[1].to_byte_array(),
        rbitcoin_primitives::Fk::NULL,
        header_for(hashes[1]),
        || {
            ancestor_walk(
                &hashes[0],
                cap,
                |hash| {
                    steps += 1;
                    lookup(hash)
                },
                known,
            )
        },
    );
    let child = BlockHash::from_byte_array([0x44; 32]);
    remember_stored_header(
        &mut batch,
        child.to_byte_array(),
        hashes[0].to_byte_array(),
        rbitcoin_primitives::Fk(1),
        header_for(hashes[0]),
        || {
            ancestor_walk(
                &child,
                cap,
                |hash| {
                    steps += 1;
                    lookup(hash)
                },
                known,
            )
        },
    );
    assert_eq!(
        steps, 4,
        "the run walks one capped chain, not one per header"
    );
    assert_eq!(
        batch.get(&hashes[0].to_byte_array()).map(|n| n.height),
        Some(None),
        "a header past the cap is still kept"
    );
    assert_eq!(
        batch.get(&child.to_byte_array()).map(|n| n.height),
        Some(None)
    );
}

#[test]
fn tip_hash_after_genesis_is_the_published_snapshot() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pub-tip");
    hub.ensure_genesis().unwrap();
    let published = hub
        .query
        .published_tip()
        .expect("genesis publishes the tip");
    assert_eq!(hub.tip_height(), Some(published.height));
    assert_eq!(
        hub.tip_hash().map(|h| h.to_byte_array()),
        Some(published.hash)
    );
}

/// An empty-store branch, a block the node already has, a held child that
/// finishes the accept, rewind bounds, a stale body cache, and the body
/// count on the tip perf line.
#[test]
fn latest_run_chain_surfaces() {
    let (dir, hub) = tmp_hub();
    let genesis = genesis_block(&hub.params);
    let ghash = genesis.block_hash();
    let child = mine(ghash, genesis.header.time.saturating_add(1), 1);
    match hub
        .accept_branch(&[genesis.clone(), child.clone()])
        .unwrap()
    {
        AcceptOutcome::Accepted { height } => assert_eq!(height, 1),
        other => panic!("an empty store connects a genesis branch, got {other:?}"),
    }
    assert_eq!(hub.tip_height(), Some(1));
    assert_eq!(
        hub.cache_body_count(),
        2,
        "tip: perf cache_bodies counts the genesis and the child still in the body window"
    );
    assert!(
        matches!(
            hub.accept_block(genesis.clone()).unwrap(),
            AcceptOutcome::AlreadyHave
        ),
        "genesis is already on the chain, so a second accept does not connect it"
    );

    let t0 = child.header.time;
    let parent = mine(child.block_hash(), t0.saturating_add(1), 2);
    let taller = mine(parent.block_hash(), t0.saturating_add(2), 3);
    let taller_hash = taller.block_hash();
    hub.hold_body(Arc::new(taller), false);
    match hub.accept_received_block(parent).unwrap() {
        AcceptOutcome::Accepted { height } => assert_eq!(
            height, 3,
            "the outcome names the held child the offer pulled in"
        ),
        other => panic!("held child should connect, got {other:?}"),
    }
    assert_eq!(hub.tip_hash(), Some(taller_hash));

    let tip_h = hub.tip_height().unwrap();
    hub.chain_work().unwrap();
    let prefix_at_tip = hub.test_chain_work_prefix_len();
    hub.rewind_to_height(tip_h).unwrap();
    assert_eq!(
        hub.tip_height(),
        Some(tip_h),
        "rewinding to the tip keeps it"
    );
    assert_eq!(
        hub.test_chain_work_prefix_len(),
        prefix_at_tip,
        "rewinding to the tip keeps the chain-work prefix"
    );
    let err = hub.rewind_to_height(tip_h + 1).unwrap_err();
    assert!(
        err.to_string().contains("rewind above tip"),
        "a height past the tip is refused: {err}"
    );

    hub.chain_work().unwrap();
    assert_eq!(hub.test_chain_work_prefix_len(), tip_h as usize + 1);
    hub.query.disconnect_tip().unwrap();
    hub.cache.truncate_to_height(tip_h - 1);
    assert_eq!(hub.tip_height(), Some(tip_h - 1));
    hub.chain_work().unwrap();
    assert_eq!(
        hub.test_chain_work_prefix_len(),
        tip_h as usize,
        "chain work drops the prefix entry above the new tip"
    );
    assert!(hub.cached_chain_work().is_some());

    let store_tip = hub.tip_hash().unwrap();
    let store_header = hub.header_of(&store_tip).unwrap();
    let store_h = hub.tip_height().unwrap();
    hub.cache.truncate_to_height(0);
    let stale = mine_distinct(
        ghash,
        genesis.header.time.saturating_add(9),
        1,
        &[store_tip, child.block_hash()],
    );
    hub.cache.push_best(stale.clone()).unwrap();
    let mut stale_tip = stale;
    for n in 2..=store_h {
        stale_tip = mine(
            stale_tip.block_hash(),
            genesis.header.time.saturating_add(9 + n),
            n,
        );
        hub.cache.push_best(stale_tip.clone()).unwrap();
    }
    assert_eq!(hub.cache.tip_height(), Some(store_h));
    assert_eq!(hub.query.tip_height().map(|h| h.0), Some(store_h));
    assert_ne!(hub.cache.tip_hash(), Some(store_tip));
    assert_eq!(
        hub.tip_hash(),
        Some(store_tip),
        "equal cache and store heights keep the published tip"
    );
    assert_eq!(
        hub.header_of(&store_tip).unwrap().block_hash(),
        store_header.block_hash(),
        "a stale cached body is not the header of the store block"
    );
    let ahead = mine(
        stale_tip.block_hash(),
        genesis.header.time.saturating_add(40),
        store_h + 1,
    );
    hub.cache.push_best(ahead.clone()).unwrap();
    assert!(hub.cache.tip_height().unwrap() > store_h);
    assert_eq!(
        hub.tip_hash(),
        Some(ahead.block_hash()),
        "a cache ahead of the store is the tip hash"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn precious_archive_block_returns_after_the_tip_is_invalidated() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = hub.tip_header().unwrap().time;
    let a1 = mine(gen, t0.saturating_add(1), 1);
    let a1_hash = a1.block_hash();
    let a2 = mine(a1_hash, t0.saturating_add(2), 2);
    let a2_hash = a2.block_hash();
    hub.accept_block(a1).unwrap();
    hub.accept_block(a2).unwrap();
    hub.precious_block(a2_hash).unwrap();
    hub.rewind_to_height(0).unwrap();
    let weak = mine_distinct(gen, t0.saturating_add(3), 1, &[a2_hash]);
    let weak_hash = weak.block_hash();
    hub.accept_block(weak).unwrap();
    assert_eq!(hub.tip_hash(), Some(weak_hash));
    hub.invalidate_block(weak_hash).unwrap();
    assert_eq!(
        hub.tip_hash(),
        Some(a2_hash),
        "invalidate applies the precious chain that is only in the archive"
    );
    assert_eq!(hub.tip_height(), Some(2));

    hub.rewind_to_height(0).unwrap();
    let sibling = mine_distinct(gen, t0.saturating_add(4), 1, &[a2_hash, weak_hash]);
    let sibling_hash = sibling.block_hash();
    hub.precious_block(a1_hash).unwrap();
    // a1 is one archive block and the tip is genesis, so precious connects it.
    // Park it as precious while a taller chain is the tip, then rewind again.
    let tall = mine(sibling_hash, t0.saturating_add(5), 2);
    hub.accept_branch(&[sibling, tall]).unwrap();
    assert_eq!(hub.tip_height(), Some(2));
    hub.precious_block(a1_hash).unwrap();
    assert_ne!(hub.tip_hash(), Some(a1_hash));
    hub.rewind_to_height(0).unwrap();
    let other = mine_distinct(
        gen,
        t0.saturating_add(6),
        1,
        &[a2_hash, weak_hash, sibling_hash],
    );
    hub.accept_received_block(other).unwrap();
    assert_eq!(
        hub.tip_hash(),
        Some(a1_hash),
        "a precious archive block that is not held replaces the block just received"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn invalid_child_missing_parent_and_linked_reconsider() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = hub.tip_header().unwrap().time;
    let on_tip = mine(gen, t0.saturating_add(1), 1);
    hub.hold_body(Arc::new(on_tip.clone()), false);
    assert!(
        hub.held_missing_parents().is_empty(),
        "the parent is connected, so the held block is not missing one"
    );
    let orphan = mine(on_tip.block_hash(), t0.saturating_add(2), 2);
    hub.drop_held(on_tip.block_hash());
    hub.hold_body(Arc::new(orphan.clone()), false);
    assert_eq!(hub.held_missing_parents(), vec![on_tip.block_hash()]);

    hub.accept_block(on_tip.clone()).unwrap();
    hub.invalidate_block(on_tip.block_hash()).unwrap();
    let child = mine_distinct(
        on_tip.block_hash(),
        t0.saturating_add(3),
        2,
        &[orphan.block_hash()],
    );
    hub.hold_body(Arc::new(child.clone()), false);
    assert!(
        hub.is_block_invalid(&child.block_hash()),
        "a held child of an invalid block is invalid"
    );
    let status = hub
        .chaintips()
        .into_iter()
        .find(|t| t.hash == on_tip.block_hash())
        .map(|t| t.status.to_string());
    assert_eq!(status.as_deref(), Some("invalid"));

    let b = mine(gen, t0.saturating_add(4), 1);
    let c = mine(b.block_hash(), t0.saturating_add(5), 2);
    let c_hash = c.block_hash();
    hub.accept_block(b.clone()).unwrap();
    hub.accept_block(c).unwrap();
    let d = mine(c_hash, t0.saturating_add(6), 3);
    let d_hash = d.block_hash();
    hub.ensure_header(&d.header).unwrap();
    hub.hold_body(Arc::new(d), false);
    hub.invalidate_block(d_hash).unwrap();
    hub.invalidate_block(b.block_hash()).unwrap();
    hub.reconsider_block(b.block_hash()).unwrap();
    assert!(
        !hub.is_block_invalid(&d_hash),
        "reconsider clears a path whose parent was on the path just restored"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn held_genesis_is_a_valid_header_chain() {
    let (dir, hub) = tmp_hub();
    let genesis = genesis_block(&hub.params);
    let hash = genesis.block_hash();
    hub.hold_body(Arc::new(genesis), false);
    let status = hub
        .chaintips()
        .into_iter()
        .find(|t| t.hash == hash)
        .map(|t| t.status.to_string());
    assert_eq!(
        status.as_deref(),
        Some("valid-headers"),
        "a held genesis body has no gap: {status:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn wire_load_skips_a_block_below_the_pipeline_floor() {
    use rbitcoin_query::WireLoadPipeline;

    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = hub.tip_header().unwrap().time;
    let b1 = mine(gen, t0.saturating_add(1), 1);
    let b2 = mine(b1.block_hash(), t0.saturating_add(2), 2);
    hub.accept_block(b1.clone()).unwrap();
    let stray = mine_distinct(gen, t0.saturating_add(3), 1, &[b1.block_hash()]);
    let batch = [(Height(1), stray), (Height(2), b2)];
    let inflight = rbitcoin_query::InFlight::new();
    let pipe = WireLoadPipeline {
        path_lo: 2,
        parent_hash: Some(b1.block_hash().to_byte_array()),
        next_tx_start: hub.query.tx_body_count().saturating_add(1).max(1),
        in_flight: &inflight,
        skeleton: None,
        carried_need: Vec::new(),
        carried_header_fks: Vec::new(),
        carried_header_hashes: Vec::new(),
    };
    let loaded = hub
        .confirm_wire_load_phase_pipelined(&batch, Some(&pipe))
        .expect("load")
        .expect("the height-2 block is still a contiguous load");
    assert_eq!(loaded.batch.len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn conflicting_mempool_spend_leaves_with_the_block() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mp = attach_mp(dir.path(), &hub);
    hub.generate_to_script(101, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let cb = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap()
        .txdata[0]
        .compute_txid();
    let spend = |seq: u32| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(seq),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let live = spend(Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus_u32());
    let in_block = spend(Sequence::MAX.to_consensus_u32());
    let live_id = live.compute_txid();
    mp.accept_tx(&live).expect("mature coinbase spend");
    assert!(mp.contains(&live_id));
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let block = rbitcoin_consensus::mine_regtest_paying(
        prev,
        time,
        height,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![in_block],
    );
    hub.accept_block(block)
        .expect("block that spends the same coinbase");
    assert!(
        !mp.contains(&live_id),
        "the mempool tx that spends the coinbase leaves with the block"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Production cap is 10_000. One past it is refused before genesis is
/// touched. The inclusive bound uses a stand-in cap of 2: the same `>`
/// comparison, two blocks mined, one more refused.
#[test]
fn generate_accepts_its_cap_and_refuses_one_more() {
    let (_dir, hub) = tmp_hub();
    let err = hub
        .generate_to_script(
            ChainHub::GENERATE_MAX_BLOCKS + 1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![],
        )
        .expect_err("one past the production cap");
    assert!(
        err.to_string().contains("nblocks too large (max 10000)"),
        "{err}"
    );
    assert_eq!(hub.tip_height(), None, "refusal must not mine");
    let mined = hub
        .generate_to_script_limited(2, ScriptBuf::from_bytes(vec![0x51]), vec![], 2)
        .expect("the cap itself");
    assert_eq!(mined.len(), 2);
    assert_eq!(hub.tip_height(), Some(2));
    let err = hub
        .generate_to_script_limited(3, ScriptBuf::from_bytes(vec![0x51]), vec![], 2)
        .expect_err("one past the stand-in cap");
    assert!(
        err.to_string().contains("nblocks too large (max 2)"),
        "{err}"
    );
    assert_eq!(hub.tip_height(), Some(2));
}

/// Block 1 on a real clock is still the pow limit (the min-difficulty gap).
/// Block 2 takes the overlay. `0x1b7fffff` does not fit one nonce span, so
/// generate returns instead of panicking inside the grind.
#[test]
fn generate_returns_when_regtest_pow_does_not_fit_one_nonce_span() {
    let (_dir, mut hub) = tmp_hub();
    hub.params.apply_regtest_pow_bits(0x1b7f_ffff).unwrap();
    let err = hub
        .generate_to_script(2, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .expect_err("block 2 cannot be ground");
    assert!(
        err.to_string().contains("regtest pow grind exhausted"),
        "{err}"
    );
    assert_eq!(hub.tip_height(), Some(1));
    assert_eq!(
        hub.tip_header().unwrap().bits,
        CompactTarget::from_consensus(0x207f_ffff)
    );
}

#[test]
fn rewind_defers_while_a_tip_commit_is_open() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_041_000, 1);
    hub.accept_block(b1).unwrap();
    assert_eq!(hub.tip_height(), Some(1));
    let hold = hub.query.lock_tip_commit().unwrap();
    assert!(
        !hub.try_rewind_to_height(0).unwrap(),
        "rewind must not disconnect while the tip commit is open"
    );
    assert_eq!(hub.tip_height(), Some(1));
    drop(hold);
    assert!(hub.try_rewind_to_height(0).unwrap());
    assert_eq!(hub.tip_height(), Some(0));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn into_arc_shares_one_hub() {
    let (_dir, hub) = tmp_hub();
    assert!(hub.shared_arc().is_none());
    let hub = ChainHub::into_arc(hub);
    let again = hub.shared_arc().expect("weak upgrades");
    assert!(std::sync::Arc::ptr_eq(&hub, &again));
}

#[test]
fn wait_tip_accept_idle_blocks_until_the_job_finishes() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (_dir, hub) = tmp_hub();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        rbitcoin_net::tip_accept::run_on_tip_accept(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
    });
    started_rx.recv().unwrap();
    let waiter = thread::spawn(move || hub.wait_tip_accept_idle());
    thread::sleep(Duration::from_millis(30));
    assert!(
        !waiter.is_finished(),
        "wait_tip_accept_idle returned while a tip-accept job was running"
    );
    release_tx.send(()).unwrap();
    waiter.join().expect("wait");
    worker.join().expect("job");
}

fn attach_mp(dir: &std::path::Path, hub: &ChainHub) -> Arc<rbitcoin_net::tx_relay::MempoolHub> {
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    mp
}

/// A tx spending the coinbase at `height`.
fn mature_spend_tx(hub: &ChainHub, height: u32) -> Transaction {
    let cb = hub
        .query
        .reconstruct_block_at_height(Height(height))
        .unwrap()
        .txdata[0]
        .compute_txid();
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// One regtest hub with DERSIG at 102 and CLTV at 111, mined forward:
/// the compact prefill knob, a mock clock behind the tip, the SH index
/// after generate, the version floors, and which txs a generated or
/// submitted block prefills.
#[test]
fn chain_hub_prefill_and_version() {
    use bitcoin::block::Version;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_store::script_hash;

    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("prefill-version");
    let mut params = ChainParams::regtest();
    params.apply_test_activation_height("dersig", 102).unwrap();
    params.apply_test_activation_height("cltv", 111).unwrap();
    let hub = ChainHub::new(q, params, Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let op_true = || ScriptBuf::from_bytes(vec![0x51]);

    // A prefill plan is kept only with the knob on and only for a tip
    // child, and the knob off neither shows nor overwrites it.
    let tip = hub.tip_hash().expect("genesis");
    let child = BlockHash::from_byte_array([2; 32]);
    hub.remember_cmpct_prefill(child, tip, vec![0, 1]);
    assert!(
        hub.cmpct_prefill_indexes(&child).is_none(),
        "default knob off"
    );
    hub.set_prefill_compact(true);
    hub.remember_cmpct_prefill(child, tip, vec![0, 1]);
    assert_eq!(hub.cmpct_prefill_indexes(&child), Some(vec![0, 1]));
    hub.remember_cmpct_prefill(child, BlockHash::from_byte_array([3; 32]), vec![0, 2]);
    assert_eq!(
        hub.cmpct_prefill_indexes(&child),
        Some(vec![0, 1]),
        "non tip-child must not replace"
    );
    hub.set_prefill_compact(false);
    hub.remember_cmpct_prefill(child, tip, vec![0, 9]);
    assert!(
        hub.cmpct_prefill_indexes(&child).is_none(),
        "knob off hides the plan"
    );
    hub.set_prefill_compact(true);
    assert_eq!(
        hub.cmpct_prefill_indexes(&child),
        Some(vec![0, 1]),
        "off remember must not overwrite"
    );
    hub.set_prefill_compact(false);

    // Two blocks put the tip 10,000 s past the median time. A mock clock
    // between them still mines, stamped from the mock (Core UpdateTime).
    let mid = 1_300_000_000u32;
    let tip_time = mid + 10_000;
    let h1 = mine(tip, mid, 1);
    hub.accept_block(h1.clone()).unwrap();
    hub.accept_block(mine(h1.block_hash(), tip_time, 2))
        .unwrap();
    let mock = i64::from(tip_time) - 3_000;
    assert!(mock as u32 > mid, "mock must sit above MTP");
    hub.clock.set_mock(mock);
    assert_eq!(
        hub.generate_to_script(1, op_true(), vec![]).unwrap().len(),
        1
    );
    let t = hub.tip_header().unwrap().time;
    assert!(
        t >= mock as u32 && t < tip_time,
        "expected mock-based stamp, got {t} tip={tip_time} mock={mock}"
    );
    hub.clock.set_mock(0);

    // Generate drains the SH write-behind, so its coinbase is indexed.
    let sh_script = ScriptBuf::from_bytes(vec![0x52]);
    let sh = script_hash(sh_script.as_bytes());
    hub.generate_to_script(1, sh_script, vec![]).unwrap();
    let hist = hub.query.scripthash_history(&sh).unwrap();
    assert!(
        hist.iter().any(|row| row.height == 4),
        "generate must drain SH so the height-4 coinbase is indexed, got {hist:?}"
    );

    // `feature_dersig.py`: from 102 a version-2 block is `bad-version`.
    hub.generate_to_script(97, op_true(), vec![]).unwrap();
    assert_eq!(hub.tip_height(), Some(101));
    let bad_version = |height: u32, version: i32| {
        let prev = hub.tip_hash().unwrap();
        let time = hub.tip_header().unwrap().time + 1;
        let mut block = mine_regtest_paying(prev, time, height, op_true(), vec![]);
        block.header.version = Version::from_consensus(version);
        rbitcoin_consensus::grind_regtest_pow(&mut block.header);
        let hash = block.block_hash();
        let err = hub
            .accept_block(block)
            .expect_err("bad version")
            .to_string();
        let needle = format!("bad-version(0x{version:08x})");
        assert!(err.contains(&needle), "shipped reject: {err}");
        assert_eq!(
            rbitcoin_consensus::block_reject_log_line(hash, &needle),
            format!("{hash}, {needle}")
        );
    };
    bad_version(102, 2);

    // With the knob on and a mempool attached, a generated block
    // prefills a tx the mempool lacks, not one it already has; a
    // submitted block prefills one the mempool lacks.
    let mp = attach_mp(dir.path(), &hub);
    hub.set_prefill_compact(true);
    let hashes = hub
        .generate_to_script(1, op_true(), vec![mature_spend_tx(&hub, 1)])
        .unwrap();
    assert_eq!(
        hub.cmpct_prefill_indexes(&hashes[0]),
        Some(vec![0, 1]),
        "tx absent from mempool rides the generate announce"
    );
    let live = mature_spend_tx(&hub, 2);
    mp.accept_tx(&live).expect("in mempool");
    let hashes = hub.generate_to_script(1, op_true(), vec![live]).unwrap();
    assert_eq!(
        hub.cmpct_prefill_indexes(&hashes[0]),
        Some(vec![0]),
        "live mempool hit stays coinbase-only after strip"
    );
    let block = mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time + 600,
        104,
        op_true(),
        vec![mature_spend_tx(&hub, 3)],
    );
    let hash = block.block_hash();
    match hub.accept_received_block(block) {
        Ok(AcceptOutcome::Accepted { .. }) => {}
        other => panic!("submit must connect: {other:?}"),
    }
    assert_eq!(hub.cmpct_prefill_indexes(&hash), Some(vec![0, 1]));

    // `feature_cltv.py`: from 111 a version-3 block is `bad-version`.
    hub.generate_to_script(6, op_true(), vec![]).unwrap();
    assert_eq!(hub.tip_height(), Some(110));
    bad_version(111, 3);

    let _ = std::fs::remove_dir_all(dir);
}

fn coinbase(height: u32) -> Transaction {
    rbitcoin_consensus::regtest_coinbase(
        height,
        Amount::from_sat(50_0000_0000),
        ScriptBuf::from_bytes(vec![0x51]),
    )
}

#[test]
fn strip_txids_from_pres_match_compute_txid() {
    let a = coinbase(1);
    let b = coinbase(2);
    let pres: Vec<_> = [&a, &b]
        .into_iter()
        .map(rbitcoin_query::TxPrecompute::from_tx)
        .collect();
    let got = ChainHub::strip_txids_from_pres(&pres);
    assert_eq!(got, vec![a.compute_txid(), b.compute_txid()]);
}

fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
    rbitcoin_consensus::mine_empty_regtest(prev, time, height)
}

fn mine_distinct(prev: BlockHash, time: u32, height: u32, avoid: &[BlockHash]) -> Block {
    let mut b = mine(prev, time, height);
    if !avoid.iter().any(|h| *h == b.block_hash()) {
        return b;
    }
    let target = Target::from_compact(b.header.bits);
    for nonce in 0..u32::MAX {
        b.header.nonce = nonce;
        if b.header.validate_pow(target).is_ok() && !avoid.iter().any(|h| *h == b.block_hash()) {
            return b;
        }
    }
    panic!("no distinct pow sibling");
}
fn block_with_wire_len(n: usize) -> Block {
    let mut b = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut len = n;
    for _ in 0..6 {
        b.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0u8; len]);
        let got = b.total_size();
        if got == n {
            return b;
        }
        if got > n {
            len = len.saturating_sub(got - n);
        } else {
            len = len.saturating_add(n - got);
        }
    }
    panic!("wire len {n} landed on {}", b.total_size());
}

#[test]
fn hold_body_caps_fifo() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mut exact = block_with_wire_len(HeldBodies::MAX_BLOCK_SERIALIZED);
    exact.header.nonce = 1;
    let exact_h = exact.block_hash();
    hub.hold_body(Arc::new(exact), false);
    assert!(hub.held_body(&exact_h).is_some());
    let mut over = block_with_wire_len(HeldBodies::MAX_BLOCK_SERIALIZED);
    over.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0u8; 4_000_001]);
    over.header.nonce = 2;
    let over_h = over.block_hash();
    hub.hold_body(Arc::new(over), false);
    assert!(hub.held_body(&over_h).is_none());
    hub.drop_held(exact_h);
    let gen = hub.tip_hash().unwrap();
    let n = HeldBodies::CAP.saturating_add(1);
    let mut hashes = Vec::with_capacity(n);
    let mut avoid = Vec::new();
    for i in 0..n as u32 {
        let b = mine_distinct(gen, 1_300_000_000 + i, 1, &avoid);
        let h = b.block_hash();
        avoid.push(h);
        hashes.push(h);
        hub.hold_body(Arc::new(b), false);
    }
    assert_eq!(hub.held_body_count(), HeldBodies::CAP);
    assert!(
        hub.held_body(&hashes[0]).is_none(),
        "lowest-seq (first held) must be FIFO-evicted at cap"
    );
    assert!(hub.held_body(&hashes[HeldBodies::CAP]).is_some());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn hold_body_spares_asked_getdata_from_fifo() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let asked = mine_distinct(gen, 1_400_000_000, 1, &[]);
    let asked_h = asked.block_hash();
    hub.note_asked_block(asked_h);
    hub.hold_body(Arc::new(asked), false);
    let mut avoid = vec![asked_h];
    for i in 0..HeldBodies::CAP as u32 {
        let b = mine_distinct(gen, 1_400_000_100 + i, 1, &avoid);
        avoid.push(b.block_hash());
        hub.hold_body(Arc::new(b), false);
    }
    assert!(
        hub.held_body(&asked_h).is_some(),
        "in-flight getdata body must not FIFO-evict at cap"
    );
    assert_eq!(hub.held_body_count(), HeldBodies::CAP);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn held_missing_parents_skips_connected_and_held() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let orphan_prev = BlockHash::from_byte_array([0x09; 32]);
    let b = mine(orphan_prev, 1_300_000_500, 1);
    hub.hold_body(Arc::new(b), false);
    let parent = mine(gen, 1_300_000_600, 1);
    let child = mine(parent.block_hash(), 1_300_000_700, 2);
    hub.hold_body(Arc::new(parent.clone()), false);
    hub.hold_body(Arc::new(child), false);
    let missing = hub.held_missing_parents();
    assert!(missing.contains(&orphan_prev));
    assert!(!missing.contains(&gen));
    assert!(
        !missing.contains(&parent.block_hash()),
        "a held parent that is not connected yet is not missing"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn core_log_helpers_match_step21_needles() {
    let h = BlockHash::from_byte_array([0x11; 32]);
    assert_eq!(
        accept_block_header_nodos_log(h),
        format!("p2p: header {h} missing pow proof — not stored")
    );
    assert_eq!(
        accept_prev_not_found_log(h),
        format!("p2p: accept dropped {h} (prev not found)")
    );
    assert_eq!(
        ignoring_low_work_chain_log(14),
        "p2p: ignore low-work headers height=14"
    );
    assert_eq!(
        synchronizing_blockheaders_log(14),
        "p2p: headers sync height=14"
    );
    assert_eq!(
        initial_getheaders_log(0, 0),
        "p2p: initial getheaders height=0 peer=0"
    );
    assert_eq!(
        headers_timeout_disconnect_log(0),
        "p2p: headers sync timeout, disconnect peer=0"
    );
    assert_eq!(
        headers_timeout_noban_log(0),
        "p2p: headers sync timeout, keep peer=0"
    );
    assert_eq!(
        received_getdata_wtx_log("aabbccdd", 3),
        "p2p: getdata wtx aabbccdd peer=3"
    );
    assert_eq!(received_tx_log(), "p2p: received tx");
    // Test formula: now=1_000_000, genesis=0 → variable = ceil(1e6/6e5)=2.
    assert_eq!(
        headers_download_timeout_secs(1_000_000, 0),
        1_000_000 + 900 + 2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generate_to_script_from_tokio_connects_off_worker() {
    let (dir, hub) = tmp_hub();
    let task = tokio::task::spawn_blocking(move || {
        let _g = rbitcoin_net::reactor::BlockingRegion::enter();
        let hashes = hub
            .generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("generate");
        (hashes, hub.tip_height())
    });
    let (hashes, tip) = task.await.expect("join blocking");
    assert_eq!(hashes.len(), 1);
    assert_eq!(tip, Some(1));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_received_block_async_connects_off_worker() {
    let (dir, hub) = tmp_hub();
    let hub = ChainHub::into_arc(hub);
    let task = tokio::spawn(async move {
        {
            let _g = rbitcoin_net::reactor::BlockingRegion::enter();
            hub.ensure_genesis().unwrap();
        }
        let genesis = hub.tip_hash().unwrap();
        let b = mine(genesis, 1_300_000_000, 1);
        let out = hub.accept_received_block_async(b).await.unwrap();
        (out, hub.tip_height())
    });
    let (out, tip) = task.await.expect("join worker task");
    assert_eq!(out, AcceptOutcome::Accepted { height: 1 });
    assert_eq!(tip, Some(1));
    let _ = std::fs::remove_dir_all(dir);
}

fn linux_thread_comms() -> Vec<String> {
    let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    dir.filter_map(|e| {
        let p = e.ok()?.path().join("comm");
        std::fs::read_to_string(p).ok()
    })
    .map(|s| s.trim().to_string())
    .collect()
}

/// Two real script jobs in one tip block must publish to `rbtc-scripts-*`
/// (same steal pool as IBD). Single-item waves still run inline on the
/// publisher — this pin needs N≥2.
#[test]
fn tip_accept_script_jobs_use_steal_pool() {
    let (dir, hub) = tmp_hub();
    hub.generate_to_script(101, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .expect("mature coinbases");
    let cb1 = hub.block_at_height(1).unwrap().unwrap().txdata[0].compute_txid();
    let cb2 = hub.block_at_height(2).unwrap().unwrap().txdata[0].compute_txid();
    let spend = |txid, value| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    hub.generate_to_script(
        1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend(cb1, 49_9999_0000), spend(cb2, 49_9999_0000)],
    )
    .expect("spend block");
    assert_eq!(hub.tip_height(), Some(102));
    let comms = linux_thread_comms();
    if comms.is_empty() {
        let _ = std::fs::remove_dir_all(dir);
        return;
    }
    assert!(
        comms.iter().any(|c| c.starts_with("rbtc-scripts-")),
        "tip connect must publish script jobs to steal workers, comms={comms:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_is_stale_respects_configured_max_tip_age() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let tip_time = 1_700_000_000u32;
    hub.accept_block(mine(gen, tip_time, 1)).unwrap();

    hub.set_max_tip_age_secs(3600);
    hub.clock.set_mock(i64::from(tip_time) + 3601);
    assert!(
        hub.tip_is_stale_for_ibd(),
        "tip older than configured max must be stale for IBD"
    );

    hub.clock.set_mock(i64::from(tip_time) + 3600);
    assert!(
        !hub.tip_is_stale_for_ibd(),
        "tip at exactly max age must leave IBD"
    );
    assert!(!hub.in_ibd(), "leaving IBD latches");
    hub.clock.set_mock(i64::from(tip_time) + 3600 * 48);
    assert!(
        hub.tip_is_stale_for_ibd(),
        "stale helper still follows clock"
    );
    assert!(
        !hub.in_ibd(),
        "Core m_cached_finished_ibd stays false after leave"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn feefilter_sat_kvb_is_rounded_max_during_ibd() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    assert!(hub.in_ibd(), "regtest genesis is older than 24h");
    assert_eq!(hub.feefilter_sat_kvb(), IBD_FEEFILTER_SAT_KVB);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ibd_accept_does_not_fill_recent_confirmed_wtxid() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.path().join("mp"), Arc::clone(&hub.query))
            .unwrap();
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    assert!(hub.in_ibd(), "regtest genesis is older than 24h");
    assert!(!mp.relay_enabled());
    let gen = hub.tip_hash().unwrap();
    let old = hub.clock.now_secs() as u32 - 2 * 24 * 3600;
    let block = mine(gen, old, 1);
    let wtxid = block.txdata[0].compute_wtxid();
    hub.accept_block(block).unwrap();
    assert!(hub.in_ibd());
    assert!(
        !mp.try_contains_wtxid(&wtxid),
        "txs confirmed during IBD must not be in the recently-confirmed filter"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Regtest `generate` runs while scripthash materialize still holds the
/// startup task, so the tip-follow loop has not enabled peer relay yet.
/// Leaving IBD on this path maintains the pool (purge, then per-block
/// strip) so `getblocktemplate` can run. It does not tell peers about
/// transactions or preload fee history (`feature_nulldummy`).
#[test]
fn fresh_tip_accept_maintains_pool_without_peer_relay() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.path().join("mp"), Arc::clone(&hub.query))
            .unwrap();
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    assert!(hub.in_ibd());
    assert!(!mp.relay_enabled());
    let gen = hub.tip_hash().unwrap();
    let now = hub.clock.now_secs() as u32;
    hub.accept_block(mine(gen, now, 1)).unwrap();
    assert!(!hub.in_ibd());
    assert!(
        !mp.relay_enabled(),
        "leaving IBD maintains the pool and leaves peer relay off"
    );
    assert!(
        mp.pool_maintained(),
        "leaving IBD purges the pool and strips later blocks"
    );
    assert!(
        !mp.take_fee_backfill_due(),
        "fee-history preload waits until peer relay turns on"
    );
    assert!(
        mp.block_p10_history.lock().unwrap().get(1).is_some(),
        "the block that leaves IBD is in fee history before peer relay"
    );
    // Coinbase at height 1 matures once the tip reaches 101. Those blocks
    // are still inside the pack, with relay off, and must strip.
    hub.generate_to_script(100, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    assert!(!mp.relay_enabled());
    let spend = mature_spend_tx(&hub, 1);
    let txid = spend.compute_txid();
    mp.accept_tx(&spend).expect("mature coinbase spend");
    assert_eq!(mp.live_count(), 1);
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let block = rbitcoin_consensus::mine_regtest_paying(
        prev,
        time,
        height,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend],
    );
    hub.accept_block(block)
        .expect("block confirms the mempool tx");
    assert!(
        !mp.contains(&txid),
        "a later block strips while peer relay is still off"
    );
    assert!(!mp.relay_enabled());
    let _ = std::fs::remove_dir_all(dir);
}

/// Catch-up can still be writing blocks after the connect that leaves IBD
/// has latched maintenance. That writer has to strip and move the template
/// mark while peer relay is still off. `connect_at` never sees those blocks.
#[test]
fn bulk_confirm_strips_once_the_pool_is_maintained() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.path().join("mp"), Arc::clone(&hub.query))
            .unwrap();
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let gen = hub.tip_hash().unwrap();
    let now = hub.clock.now_secs() as u32;
    hub.accept_block(mine(gen, now, 1)).unwrap();
    assert!(mp.pool_maintained());
    assert!(!mp.relay_enabled());
    hub.generate_to_script(100, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let spend = mature_spend_tx(&hub, 1);
    let txid = spend.compute_txid();
    mp.accept_tx(&spend).expect("mature coinbase spend");
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let block = mine_regtest_paying(
        prev,
        time,
        height,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend],
    );
    let hash = block.block_hash();
    let header = block.header;
    rbitcoin_query::accept_and_connect_block(
        &hub.query,
        &hub.params,
        Height(height),
        &block,
        hub.milestone,
    )
    .expect("connect without the mempool strip");
    assert!(
        mp.contains(&txid),
        "the query connect must leave the pool alone"
    );
    let buried = mp.template_prev();
    hub.note_confirmed_tip(&[(height, hash)], &[header])
        .expect("bulk confirm");
    assert!(
        !mp.contains(&txid),
        "a catch-up batch after maintenance must drop the confirmed tx"
    );
    assert_eq!(
        mp.template_prev(),
        Some(hash.to_byte_array()),
        "templates must follow that batch, not {buried:?}"
    );
    assert!(
        mp.block_p10_history.lock().unwrap().get(height).is_some(),
        "the catch-up batch is in fee history"
    );
    assert!(!mp.relay_enabled());
    let _ = std::fs::remove_dir_all(dir);
}

/// `-blocksonly` stays quiet after the same fresh tip. The accept path must
/// not turn relay on just because the tip left IBD.
#[test]
fn fresh_tip_accept_stays_quiet_when_blocks_only() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    hub.set_blocks_only(true);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.path().join("mp"), Arc::clone(&hub.query))
            .unwrap();
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let gen = hub.tip_hash().unwrap();
    let now = hub.clock.now_secs() as u32;
    hub.accept_block(mine(gen, now, 1)).unwrap();
    assert!(!hub.in_ibd());
    assert!(!mp.relay_enabled());
    assert!(!mp.pool_maintained());
    assert!(!mp.take_fee_backfill_due());
    let _ = std::fs::remove_dir_all(dir);
}

/// A local `accept_block` does not start peer relay. Maintenance stays set
/// once the leaving-IBD connect has published it. A later peer block is a
/// different path and can turn relay on.
#[test]
fn fresh_tip_does_not_reenable_relay_once_ibd_has_ended() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.path().join("mp"), Arc::clone(&hub.query))
            .unwrap();
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let gen = hub.tip_hash().unwrap();
    let now = hub.clock.now_secs() as u32;
    hub.accept_block(mine(gen, now, 1)).unwrap();
    assert!(
        !mp.relay_enabled(),
        "the block that leaves IBD does not enable peer relay"
    );
    assert!(mp.pool_maintained());
    assert!(!mp.take_fee_backfill_due());
    mp.set_relay_enabled(true);
    assert!(mp.take_fee_backfill_due());
    mp.set_relay_enabled(false);
    assert!(!mp.take_fee_backfill_due());
    assert!(
        mp.pool_maintained(),
        "pausing peer relay leaves maintenance on"
    );
    let tip = hub.tip_hash().unwrap();
    hub.accept_block(mine(tip, now.saturating_add(1), 2))
        .unwrap();
    assert!(!hub.in_ibd());
    assert!(
        !mp.relay_enabled(),
        "a local accept_block does not start peer relay"
    );
    assert!(mp.pool_maintained());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn feefilter_sat_kvb_is_min_relay_once_tip_is_fresh() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let now = 1_700_000_000u32;
    hub.clock.set_mock(i64::from(now));
    hub.accept_block(mine(gen, now, 1)).unwrap();
    assert!(!hub.in_ibd());
    assert_eq!(
        hub.feefilter_sat_kvb(),
        rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn feefilter_sat_kvb_tracks_enforced_floor() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let now = 1_700_000_000u32;
    hub.clock.set_mock(i64::from(now));
    hub.accept_block(mine(gen, now, 1)).unwrap();
    assert!(!hub.in_ibd());
    let mp = rbitcoin_net::tx_relay::MempoolHub::open_with_weight(
        dir.path().join("mp"),
        Arc::clone(&hub.query),
        0,
    )
    .unwrap();
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let min = rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB;
    // A zero weight cap is within one standard tx of full, so the floor
    // is min relay plus one incremental step.
    assert_eq!(hub.feefilter_sat_kvb(), min + min);
    mp.set_min_relay_sat_kvb(1_000);
    assert_eq!(hub.feefilter_sat_kvb(), 1_100);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn stale_relay_allowed_withholds_month_old_side_block() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = 1_700_000_000u32;
    hub.clock.set_mock(i64::from(t0));
    let a = mine(gen, t0, 1);
    hub.accept_block(a.clone()).unwrap();
    let a_hash = a.block_hash();
    hub.invalidate_block(a_hash).unwrap();
    let best_time = t0 + STALE_RELAY_AGE_LIMIT_SECS as u32;
    hub.clock.set_mock(i64::from(best_time));
    let c1 = mine(gen, best_time, 1);
    hub.accept_block(c1.clone()).unwrap();
    assert!(!hub.is_connected(&a_hash));
    assert!(
        !hub.stale_relay_allowed(&a_hash),
        "a side block exactly one month behind the best header is not served"
    );
    let younger = mine_distinct(gen, best_time - 1, 1, &[a.block_hash(), c1.block_hash()]);
    assert!(matches!(
        hub.accept_received_block(younger.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(
        hub.stale_relay_allowed(&younger.block_hash()),
        "one second inside the month is still served"
    );
    let older = mine_distinct(
        gen,
        t0 - 1,
        1,
        &[a.block_hash(), c1.block_hash(), younger.block_hash()],
    );
    assert!(matches!(
        hub.accept_received_block(older.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(
        !hub.stale_relay_allowed(&older.block_hash()),
        "stale more than a month behind best header must not be served"
    );
    assert!(hub.stale_relay_allowed(&hub.tip_hash().unwrap()));
    let _ = std::fs::remove_dir_all(dir);
}

/// Work floor, submitheader parents, chaintips rank, and the 288-header
/// window past which an unrequested header is too far ahead.
#[test]
#[allow(clippy::cognitive_complexity)] // one hub, many chain-edge arms
fn chain_edges_pin_work_headers_and_reopen() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let genesis = hub.header_of(&gen).unwrap();

    let fresh = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let (dir0, bare) = tmp_hub();
    let genesis_submit = bare.process_submitted_header(&fresh.header);
    assert!(
        genesis_submit
            .as_ref()
            .err()
            .map(|e| !e.contains("Must submit previous header"))
            .unwrap_or(true),
        "the zero parent is known before genesis is stored: {genesis_submit:?}"
    );
    let _ = std::fs::remove_dir_all(dir0);

    let child = mine(gen, genesis.time.saturating_add(1), 1);
    let equal_work = hub.work_with_header(&child.header).to_be_bytes();
    hub.set_minimum_chain_work(Some(equal_work));
    assert!(
        !hub.header_below_minwork(&child.header),
        "work equal to -minimumchainwork is not below it"
    );
    assert!(
        !hub.header_below_anti_dos(&child.header),
        "anti-DoS threshold equal to the header's work still accepts it"
    );
    let mut above = equal_work;
    for byte in above.iter_mut().rev() {
        if *byte != u8::MAX {
            *byte += 1;
            break;
        }
        *byte = 0;
    }
    hub.set_minimum_chain_work(Some(above));
    assert!(hub.header_below_minwork(&child.header));
    assert!(hub.header_below_anti_dos(&child.header));
    hub.set_minimum_chain_work(None);

    hub.process_submitted_header(&child.header).unwrap();
    assert!(hub.process_submitted_header(&child.header).is_ok());
    let grandchild = mine(child.block_hash(), child.header.time.saturating_add(1), 2);
    hub.process_submitted_header(&grandchild.header)
        .expect("a header-only parent is enough");

    let parked = mine_distinct(
        gen,
        genesis.time.saturating_add(2),
        1,
        &[child.block_hash()],
    );
    hub.hold_body(Arc::new(parked.clone()), false);
    assert!(hub
        .query
        .get_header_by_hash(&parked.block_hash().to_byte_array())
        .unwrap()
        .is_none());
    let parked_child = mine(parked.block_hash(), parked.header.time.saturating_add(1), 2);
    let parked_err = hub
        .process_submitted_header(&parked_child.header)
        .expect_err("the parked parent has no header row");
    assert!(
        !parked_err.contains("Must submit previous header"),
        "a held body is a known parent: {parked_err}"
    );
    let missing = BlockHash::from_byte_array([0x44; 32]);
    let err = hub.reconsider_block(missing).unwrap_err();
    assert!(
        err.to_string().contains("Block not found"),
        "reconsider of an unknown hash fails: {err}"
    );
    hub.reconsider_block(parked.block_hash())
        .expect("a parked body is a known block");
    assert_eq!(
        hub.tip_hash(),
        Some(parked.block_hash()),
        "reconsider connects a parked body that is not on an invalidated path"
    );

    let main = mine_distinct(
        gen,
        genesis.time.saturating_add(3),
        1,
        &[child.block_hash(), parked.block_hash()],
    );
    hub.accept_block(main.clone()).unwrap();
    let side = mine_distinct(
        gen,
        genesis.time.saturating_add(4),
        1,
        &[child.block_hash(), parked.block_hash(), main.block_hash()],
    );
    assert!(matches!(
        hub.accept_received_block(side.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    hub.ensure_header(&side.header).unwrap();
    let side_status = |hub: &ChainHub| {
        hub.chaintips()
            .into_iter()
            .find(|t| t.hash == side.block_hash())
            .map(|t| t.status.to_string())
    };
    assert_eq!(
        side_status(&hub).as_deref(),
        Some("valid-headers"),
        "a held side block outranks a header-only label"
    );
    hub.reconsider_block(side.block_hash()).unwrap();
    assert_eq!(
        side_status(&hub).as_deref(),
        Some("valid-headers"),
        "a block that never connected is not a valid fork after reconsider"
    );
    hub.invalidate_block(side.block_hash()).unwrap();
    assert_eq!(
        side_status(&hub).as_deref(),
        Some("invalid"),
        "invalidate replaces the held status"
    );

    let s1 = mine_distinct(
        gen,
        genesis.time.saturating_add(5),
        1,
        &[
            child.block_hash(),
            parked.block_hash(),
            main.block_hash(),
            side.block_hash(),
        ],
    );
    let s2 = mine(s1.block_hash(), s1.header.time.saturating_add(1), 2);
    hub.accept_branch(&[s1, s2]).unwrap();
    assert_eq!(hub.tip_height(), Some(2));
    hub.hold_body(Arc::new(parked.clone()), false);
    let fork_status = hub
        .chaintips()
        .into_iter()
        .find(|t| t.hash == parked.block_hash())
        .map(|t| t.status.to_string());
    assert_eq!(
        fork_status.as_deref(),
        Some("valid-fork"),
        "a reorg loser that is also held stays a valid fork"
    );
    hub.invalidate_block(parked.block_hash()).unwrap();
    let fork_status = hub
        .chaintips()
        .into_iter()
        .find(|t| t.hash == parked.block_hash())
        .map(|t| t.status.to_string());
    assert_eq!(
        fork_status.as_deref(),
        Some("invalid"),
        "invalidate outranks the valid-fork label"
    );
    hub.reconsider_block(parked.block_hash()).unwrap();
    assert!(!hub.is_block_invalid(&parked.block_hash()));
    let tip = hub.tip_hash().unwrap();
    let tip_h = hub.tip_height().unwrap();
    hub.invalidate_block(tip).unwrap();
    assert_eq!(hub.tip_height(), Some(tip_h - 1));
    hub.reconsider_block(tip).unwrap();
    assert_eq!(hub.tip_height(), Some(tip_h));

    let mut prev = hub.tip_hash().unwrap();
    let mut time = hub.tip_header().unwrap().time;
    let tip_h = hub.tip_height().unwrap();
    for n in 1..=288u32 {
        time = time.saturating_add(1);
        let block = mine(prev, time, tip_h + n);
        if n == 288 {
            assert!(!hub.unrequested_too_far_ahead(&block.header));
        }
        hub.process_submitted_header(&block.header)
            .unwrap_or_else(|e| panic!("header {n}: {e}"));
        prev = block.block_hash();
    }
    time = time.saturating_add(1);
    let past = mine(prev, time, tip_h + 289);
    assert!(hub.unrequested_too_far_ahead(&past.header));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn min_diff_limit_starts_after_two_spacings_and_walks_back() {
    let (dir, mut hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    hub.params.btc.no_pow_retargeting = false;
    hub.params.btc.allow_min_difficulty_blocks = true;
    let spacing = hub.params.btc.pow_target_spacing;
    hub.params.btc.pow_target_timespan = spacing.saturating_mul(20);
    let limit = hub.params.pow_limit.to_compact_lossy();
    let gen_hash = hub.tip_hash().unwrap();
    let genesis = hub.header_of(&gen_hash).unwrap();
    let mut prev = genesis;
    let mut headers = Vec::new();
    for height in 1..=22u32 {
        let parent = headers.last().copied().unwrap_or(genesis);
        let time = if height == 21 {
            parent
                .time
                .saturating_add((spacing as u32).saturating_mul(2) + 1)
        } else if height == 22 {
            parent.time.saturating_add(1)
        } else {
            genesis
                .time
                .saturating_add((spacing as u32 / 2).saturating_mul(height))
        };
        let probe = Header { time, ..parent };
        let bits = hub
            .expected_bits_off_tip(&probe, &parent, height - 1, &HashMap::new())
            .unwrap();
        let mut block = mine(prev.block_hash(), time, height);
        block.header.bits = bits;
        block.header.nonce = 0;
        rbitcoin_consensus::grind_regtest_pow(&mut block.header);
        hub.accept_block(block.clone())
            .unwrap_or_else(|e| panic!("height {height} bits {bits:?}: {e}"));
        headers.push(block.header);
        prev = block.header;
    }
    let h20 = headers[19];
    let h21 = headers[20];
    assert_ne!(h20.bits, limit, "the retarget leaves the pow limit");
    assert_eq!(
        h21.bits, limit,
        "two spacings plus one second is min difficulty"
    );
    let on_the_line = Header {
        time: h20.time.saturating_add((spacing as u32).saturating_mul(2)),
        ..h21
    };
    let empty = HashMap::new();
    assert_eq!(
        hub.min_diff_off_tip(&on_the_line, &h20, 20, &empty),
        h20.bits,
        "exactly two spacings keeps the parent's bits"
    );
    let past = Header {
        time: h20
            .time
            .saturating_add((spacing as u32).saturating_mul(2) + 1),
        ..h21
    };
    assert_eq!(
        hub.min_diff_off_tip(&past, &h20, 20, &empty),
        limit,
        "one second past two spacings is the pow limit"
    );
    assert_eq!(
        hub.min_diff_off_tip(&headers[21], &h21, 21, &empty),
        h20.bits,
        "a fast header after min difficulty walks back to the last harder bits"
    );
    let odd_bits = CompactTarget::from_consensus(0x1e00ffff);
    assert_ne!(odd_bits, h20.bits);
    assert_ne!(odd_bits, limit);
    let odd = Header {
        bits: odd_bits,
        time: h21.time.saturating_add(1),
        ..h21
    };
    assert_eq!(
        hub.min_diff_off_tip(&odd, &odd, 21, &empty),
        odd_bits,
        "non-limit bits are kept without walking"
    );
    let threshold = hub.anti_dos_work_threshold();
    let tip_work = hub.chain_work().unwrap();
    assert!(threshold <= tip_work);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn reopened_chain_seeds_heights_between_genesis_and_the_tip() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mut prev = hub.tip_hash().unwrap();
    let mut time = hub.tip_header().unwrap().time;
    for h in 1..=3u32 {
        time = time.saturating_add(1);
        let b = mine(prev, time, h);
        prev = b.block_hash();
        hub.accept_block(b).unwrap();
    }
    let mid = hub
        .query
        .header_at_height(Height(1))
        .unwrap()
        .expect("height 1")
        .1
        .hash;
    let mid = BlockHash::from_byte_array(mid);
    drop(hub);
    let q = rbitcoin_query::Query::open_or_create_tiny(dir.path()).unwrap();
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !hub.has_block(&mid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        hub.has_block(&mid),
        "reopening a height-3 chain fills the height between genesis and the tip"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn confirmed_seed_does_not_restore_a_disconnected_block() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mut prev = hub.tip_hash().unwrap();
    let mut time = hub.tip_header().unwrap().time;
    for h in 1..=3u32 {
        time = time.saturating_add(1);
        let b = mine(prev, time, h);
        prev = b.block_hash();
        hub.accept_block(b).unwrap();
    }
    let gone = prev;
    hub.rewind_to_height(0).unwrap();
    assert!(
        !hub.has_block(&gone),
        "rewind drops the disconnected tip from the confirmed set"
    );
    publish_confirmed_heights(&hub.query, &hub.confirmed);
    assert!(
        !hub.has_block(&gone),
        "the seed copy must not put that block back"
    );
    assert!(
        hub.has_block(&genesis_block(&hub.params).block_hash()),
        "genesis is still the header at height 0"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn unrequested_header_below_minwork_is_anti_dos() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mut min = [0u8; 32];
    min[31] = 0x10;
    hub.set_minimum_chain_work(Some(min));
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_000_000, 1);
    assert!(
        hub.header_below_minwork(&b1.header),
        "genesis+1 must stay below 0x10"
    );
    hub.set_minimum_chain_work(None);
    hub.accept_block(b1.clone()).unwrap();
    let b2 = mine(b1.block_hash(), 1_300_000_100, 2);
    hub.accept_block(b2.clone()).unwrap();
    let fork = mine(gen, 1_300_000_200, 1);
    assert!(
        rbitcoin_net::most_work::work_better(
            hub.chain_work().unwrap(),
            hub.work_with_header(&fork.header)
        ),
        "genesis-fork at height 1 is weaker than tip 2"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn disconnect_to_without_mempool_skips_block_at_height() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_040_000, 1);
    hub.accept_block(b1).unwrap();
    assert!(hub.mempool().is_none());
    hub.reset_block_at_height_calls();
    hub.rewind_to_height(0).unwrap();
    assert_eq!(
        hub.block_at_height_calls(),
        0,
        "IBD disconnect must not reconstruct the losing branch"
    );
    assert_eq!(hub.tip_height(), Some(0));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn disconnect_to_with_mempool_still_harvests() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_040_100, 1);
    hub.accept_block(b1).unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    hub.reset_block_at_height_calls();
    hub.rewind_to_height(0).unwrap();
    assert!(
        hub.block_at_height_calls() >= 1,
        "tip-mode reorg still reconstructs for reorg_reaccept"
    );
    assert_eq!(hub.tip_height(), Some(0));
    let _ = std::fs::remove_dir_all(dir);
}

/// Fork point `fork` (mature coinbases at 1 and 2), then the old branch:
/// `parent` at `fork + 1` and `child` at `fork + 2`. The child's lock time is
/// `fork + 1`, the height a Core wallet stamps after one block: final in its
/// block and on any later tip, not on the fork point.
struct ReorgPad {
    dir: rbitcoin_query::testutil::TempDir,
    hub: ChainHub,
    mp: Arc<rbitcoin_net::tx_relay::MempoolHub>,
    fork: u32,
    fork_hash: BlockHash,
    fork_time: u32,
    parent: Transaction,
    child: Transaction,
}

fn spend_out0(prev: bitcoin::Txid, sat: u64, lock_time: LockTime) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn reorg_pad() -> ReorgPad {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let gen = hub.tip_hash().unwrap();
    hub.accept_block(mine(gen, hub.clock.now_secs() as u32, 1))
        .unwrap();
    hub.generate_to_script(100, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let fork = hub.tip_height().unwrap();
    let fork_hash = hub.tip_hash().unwrap();
    let fork_time = hub.tip_header().unwrap().time;
    let parent = mature_spend_tx(&hub, 1);
    let child = spend_out0(
        parent.compute_txid(),
        49_9998_0000,
        LockTime::from_height(fork + 1).unwrap(),
    );
    let a1 = mine_with_extra(fork_hash, fork_time + 1, fork + 1, vec![parent.clone()]);
    let a2 = mine_with_extra(
        a1.block_hash(),
        fork_time + 2,
        fork + 2,
        vec![child.clone()],
    );
    hub.accept_block(a1).unwrap();
    hub.accept_block(a2).unwrap();
    ReorgPad {
        dir,
        hub,
        mp,
        fork,
        fork_hash,
        fork_time,
        parent,
        child,
    }
}

/// Mine `txs.len()` blocks on the fork point, block `i` holding `txs[i]`.
fn pad_branch(pad: &ReorgPad, txs: Vec<Vec<Transaction>>) -> Vec<Block> {
    let mut branch = Vec::new();
    let mut prev = pad.fork_hash;
    for (i, extra) in txs.into_iter().enumerate() {
        let i = i as u32 + 1;
        let b = mine_with_extra(prev, pad.fork_time + 10 + i, pad.fork + i, extra);
        prev = b.block_hash();
        branch.push(b);
    }
    branch
}

/// Core re-adds disconnected txs after the new branch connects
/// (`MaybeUpdateMempoolForReorg`), so the child is final there (issue #1236).
/// Parents go first, so the child comes back from its block, not the orphanage.
#[test]
fn branch_reorg_reaccepts_on_the_new_tip() {
    let pad = reorg_pad();
    let branch = pad_branch(&pad, vec![vec![], vec![], vec![]]);
    assert_eq!(
        pad.hub.accept_branch(&branch).unwrap(),
        AcceptOutcome::Accepted {
            height: pad.fork + 3
        }
    );
    assert!(
        pad.mp.contains(&pad.parent.compute_txid()),
        "parent is back"
    );
    assert!(
        pad.mp.contains(&pad.child.compute_txid()),
        "the child is final on the new tip"
    );
    let _ = std::fs::remove_dir_all(pad.dir);
}

/// Core signals `BlockConnected` after `MaybeUpdateMempoolForReorg`. The
/// branch's first tip event already finds the child back, so an Electrum
/// restatus on that event does not go stale.
#[test]
fn branch_reorg_tip_events_follow_the_reaccept() {
    let pad = reorg_pad();
    let mut tips = pad.hub.subscribe_tips();
    let mp = Arc::clone(&pad.mp);
    let child = pad.child.compute_txid();
    let seen = std::thread::spawn(move || {
        let ev = tips.blocking_recv().expect("tip event");
        (ev.height, mp.contains(&child))
    });
    let branch = pad_branch(&pad, vec![vec![], vec![], vec![]]);
    pad.hub.accept_branch(&branch).unwrap();
    let (height, back) = seen.join().unwrap();
    assert_eq!(height, pad.fork + 1);
    assert!(back, "the child is back before the first tip event");
    let _ = std::fs::remove_dir_all(pad.dir);
}

/// A disconnect whose blocks cannot all be read back fails before it moves
/// the tip. The 16 cached tip bodies read fine, and the next one down
/// faults, so a disconnect that read as it went would stop halfway.
#[test]
fn disconnect_fails_when_the_block_read_faults() {
    let pad = reorg_pad();
    let tip = pad.hub.tip_height();
    let tip_hash = pad.hub.tip_hash();
    let inputs = find_store_file(pad.dir.path(), "input.body").expect("input.body");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&inputs)
        .unwrap()
        .set_len(0)
        .unwrap();
    pad.hub
        .rewind_to_height(pad.fork - 20)
        .expect_err("a block below the cache cannot be read back");
    assert_eq!(pad.hub.tip_height(), tip, "nothing was disconnected");
    assert_eq!(pad.hub.tip_hash(), tip_hash);
    let _ = std::fs::remove_dir_all(pad.dir);
}

/// A connected height below the cached bodies whose header row is gone
/// reads back as no block. That fails the disconnect too, before it moves
/// the tip, and is not read as an empty block.
#[test]
fn disconnect_fails_when_a_connected_height_has_no_block() {
    let pad = reorg_pad();
    let tip = pad.hub.tip_height();
    let tip_hash = pad.hub.tip_hash();
    let hole = pad.fork - 20;
    pad.hub
        .query
        .store()
        .confirmed
        .set_raw_for_test(&rbitcoin_store::ClassCWrite::for_test(), Height(hole), 0)
        .unwrap();
    assert!(pad.hub.block_at_height(hole).unwrap().is_none());
    pad.hub
        .rewind_to_height(hole - 1)
        .expect_err("a connected height has no block");
    assert_eq!(pad.hub.tip_height(), tip, "nothing was disconnected");
    assert_eq!(pad.hub.tip_hash(), tip_hash);
    let _ = std::fs::remove_dir_all(pad.dir);
}

/// The new branch double-spends the parent. Core drops the parent and its
/// child. The child does not wait in the orphanage for a parent that cannot
/// come back.
#[test]
fn branch_reorg_drops_the_child_of_a_double_spent_parent() {
    let pad = reorg_pad();
    let mut rival = mature_spend_tx(&pad.hub, 1);
    rival.output[0].value = Amount::from_sat(49_9998_0000);
    let branch = pad_branch(&pad, vec![vec![rival], vec![], vec![]]);
    pad.hub.accept_branch(&branch).unwrap();
    assert!(!pad.mp.contains(&pad.parent.compute_txid()));
    assert!(!pad.mp.contains(&pad.child.compute_txid()));
    assert_eq!(pad.mp.orphan_count(), 0);
    let _ = std::fs::remove_dir_all(pad.dir);
}

/// A failed connect restores the old branch under the same template hold.
/// A tx only in the dropped prefix goes back in the pool. Subscribers last
/// saw the old tip, so the one tip event is that tip, with the restored
/// length, as a reorg Electrum reads every status again for.
#[test]
fn branch_reorg_restore_puts_the_prefix_back() {
    let pad = reorg_pad();
    let old_tip = pad.hub.tip_hash().unwrap();
    let old_height = pad.hub.tip_height().unwrap();
    let mut tips = pad.hub.subscribe_tips();
    let side = mature_spend_tx(&pad.hub, 2);
    let bad = spend_out0(
        bitcoin::Txid::from_byte_array([0xee; 32]),
        1,
        LockTime::ZERO,
    );
    let branch = pad_branch(&pad, vec![vec![side.clone()], vec![bad], vec![]]);
    pad.hub
        .accept_branch(&branch)
        .expect_err("the second block spends a missing coin");
    assert_eq!(pad.hub.tip_hash(), Some(old_tip));
    let mut events = Vec::new();
    while let Ok(tip) = tips.try_recv() {
        events.push((tip.height, tip.hash, tip.reorg_branch_len));
    }
    assert!(
        events.iter().all(|&(height, _, _)| height >= old_height),
        "no event below the old tip: {events:?}"
    );
    assert_eq!(events, vec![(old_height, old_tip, 2)]);
    assert!(pad.mp.contains(&side.compute_txid()), "prefix tx is back");
    assert!(!pad.mp.contains(&pad.parent.compute_txid()));
    assert!(!pad.mp.contains(&pad.child.compute_txid()));
    let _ = std::fs::remove_dir_all(pad.dir);
}

/// A branch on the tip whose second block hits a store fault comes off
/// with no old block to put back. Subscribers never saw its first block,
/// but that block's tx is now in the pool, so one reorg event for the tip
/// has Electrum read every status again.
#[test]
fn branch_on_the_tip_undone_by_a_fault_sends_one_reorg_event() {
    let pad = reorg_pad();
    let tip_h = pad.hub.tip_height().unwrap();
    let tip = pad.hub.tip_hash().unwrap();
    let time = pad.hub.tip_header().unwrap().time;
    let side = mature_spend_tx(&pad.hub, 2);
    let late = spend_out0(pad.child.compute_txid(), 49_9997_0000, LockTime::ZERO);
    let b1 = mine_with_extra(tip, time + 1, tip_h + 1, vec![side.clone()]);
    let b2 = mine_with_extra(b1.block_hash(), time + 2, tip_h + 2, vec![late]);
    // Class A appends by height. Half the outputs keep the side's coin and
    // drop the child's, so only the second block faults.
    let txout = find_store_file(pad.dir.path(), "txout.body").expect("txout.body");
    let len = std::fs::metadata(&txout).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&txout)
        .unwrap()
        .set_len(len / 2)
        .unwrap();
    let mut tips = pad.hub.subscribe_tips();
    let err = pad
        .hub
        .accept_branch(&[b1, b2])
        .expect_err("the second block faults");
    assert!(err.is_local_fault(), "{err}");
    assert_eq!(pad.hub.tip_hash(), Some(tip));
    assert!(
        pad.mp.contains(&side.compute_txid()),
        "the first block's tx is back"
    );
    let mut events = Vec::new();
    while let Ok(ev) = tips.try_recv() {
        events.push((ev.height, ev.hash, ev.reorg_branch_len > 0));
    }
    assert_eq!(events, vec![(tip_h, tip, true)]);
    let _ = std::fs::remove_dir_all(pad.dir);
}

/// A branch whose first block fails puts the old blocks back as they were,
/// with the pool unchanged. No tip event is sent, as Core sends no
/// `UpdatedBlockTip` when the tip ends where it started.
#[test]
fn branch_reorg_whose_first_block_fails_sends_no_tip_event() {
    let pad = reorg_pad();
    let old_tip = pad.hub.tip_hash().unwrap();
    let mut tips = pad.hub.subscribe_tips();
    let bad = spend_out0(
        bitcoin::Txid::from_byte_array([0xee; 32]),
        1,
        LockTime::ZERO,
    );
    let branch = pad_branch(&pad, vec![vec![bad], vec![], vec![]]);
    pad.hub
        .accept_branch(&branch)
        .expect_err("the first block spends a missing coin");
    assert_eq!(pad.hub.tip_hash(), Some(old_tip));
    assert!(tips.try_recv().is_err(), "no tip event");
    let _ = std::fs::remove_dir_all(pad.dir);
}

#[test]
fn ensure_header_rejects_claimed_hard_bits_without_pow() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut bad = mine(gen, 1_300_031_000, 1).header;
    bad.bits = CompactTarget::from_consensus(0x1d00ffff);
    bad.nonce = 0;
    assert!(
        hub.ensure_header(&bad).is_err(),
        "persist must not accept nBits/POW that confirm would reject"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ensure_header_fork_child_rejects_old_time_and_wrong_bits() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_000_000, 1);
    hub.ensure_header(&b1.header).unwrap();
    let before = hub.query.store().header_count();

    let mut old = b1.header;
    old.prev_blockhash = b1.block_hash();
    old.time = b1.header.time;
    old.merkle_root = bitcoin::TxMerkleNode::from_byte_array([1u8; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut old);
    let err = hub.ensure_header(&old).unwrap_err();
    assert!(
        err.to_string().contains("median-time-past"),
        "fork child with time==parent must fail MTP: {err}"
    );
    assert_eq!(hub.query.store().header_count(), before);

    let mut wrong_bits = b1.header;
    wrong_bits.prev_blockhash = b1.block_hash();
    wrong_bits.time = b1.header.time.saturating_add(600);
    wrong_bits.bits = CompactTarget::from_consensus(0x207f_fffe);
    wrong_bits.merkle_root = bitcoin::TxMerkleNode::from_byte_array([2u8; 32]);
    let target = Target::from_compact(wrong_bits.bits);
    for nonce in 0..u32::MAX {
        wrong_bits.nonce = nonce;
        if wrong_bits.validate_pow(target).is_ok() {
            break;
        }
    }
    let err = hub.ensure_header(&wrong_bits).unwrap_err();
    assert!(
        err.to_string().contains("proof of work bits"),
        "fork child with nBits != parent continuation must fail: {err}"
    );
    assert_eq!(hub.query.store().header_count(), before);

    let mut low_ver = b1.header;
    low_ver.prev_blockhash = b1.block_hash();
    low_ver.time = b1.header.time.saturating_add(600);
    low_ver.version = Version::from_consensus(1);
    low_ver.merkle_root = bitcoin::TxMerkleNode::from_byte_array([3u8; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut low_ver);
    let err = hub.ensure_header(&low_ver).unwrap_err();
    assert!(
        err.to_string().contains("bad-version"),
        "fork child below BIP65 nVersion: {err}"
    );
    assert_eq!(hub.query.store().header_count(), before);

    let mut h2 = b1.header;
    h2.prev_blockhash = b1.block_hash();
    h2.time = b1.header.time.saturating_add(600);
    h2.merkle_root = bitcoin::TxMerkleNode::from_byte_array([4u8; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut h2);
    let n = hub
        .ensure_headers_batch(&[b1.header, h2])
        .expect("in-batch parent of a valid fork child")
        .len();
    assert_eq!(n, 2);
    assert!(hub.query.store().header_count() > before);

    let mut far = h2;
    far.prev_blockhash = h2.block_hash();
    far.time = h2.time.saturating_add(1_201);
    far.merkle_root = bitcoin::TxMerkleNode::from_byte_array([5u8; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut far);
    hub.ensure_header(&far)
        .expect("regtest min-diff after 2×spacing must persist pow_limit bits");

    let mut batch_old = h2;
    batch_old.prev_blockhash = h2.block_hash();
    batch_old.time = b1.header.time;
    batch_old.merkle_root = bitcoin::TxMerkleNode::from_byte_array([6u8; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut batch_old);
    let after_far = hub.query.store().header_count();
    let err = hub
        .ensure_headers_batch(&[h2, batch_old])
        .expect_err("batch must fail closed on MTP");
    assert!(
        err.to_string().contains("median-time-past"),
        "in-batch MTP fail: {err}"
    );
    assert_eq!(hub.query.store().header_count(), after_far);

    let empty = HashMap::new();
    assert_eq!(hub.stored_header_height(&b1.block_hash()), Some(1));
    assert!(hub
        .stored_header_height(&BlockHash::from_byte_array([0xab; 32]))
        .is_none());
    let mtp = hub.mtp_off_tip(&b1.header, &empty);
    assert!(mtp <= b1.header.time);
    let child_bits = hub
        .expected_bits_off_tip(&h2, &b1.header, 1, &empty)
        .unwrap();
    assert_eq!(child_bits, b1.header.bits);
    let mut far_bits = h2;
    far_bits.time = b1.header.time.saturating_add(10_000);
    let md = hub.min_diff_off_tip(&far_bits, &b1.header, 1, &empty);
    assert_eq!(md, hub.params.pow_limit.to_compact_lossy());
    let along = hub
        .header_along_off_tip(&b1.header, 1, 0, &empty)
        .expect("walk back one header reaches genesis");
    assert_eq!(along.block_hash(), gen);
    assert_eq!(
        hub.header_along_off_tip(&b1.header, 1, 1, &empty)
            .expect("the parent height is that header")
            .block_hash(),
        b1.block_hash()
    );
    assert!(hub.header_along_off_tip(&b1.header, 1, 2, &empty).is_none());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_follow_accept_logs_update_tip_per_block() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_000_000, 1);
    let h = b1.header;
    let hash = b1.block_hash();
    let line_probe = log_update_tip_line(1, &hash, &h, b1.txdata.len());
    assert_eq!(
        line_probe,
        format!(
            "tip: best={hash} height=1 version={} tx={} date={}",
            h.version.to_consensus(),
            b1.txdata.len(),
            h.time
        )
    );
    assert!(!line_probe.contains("UpdateTip"), "{line_probe}");
    assert!(matches!(
        hub.accept_block(b1).unwrap(),
        AcceptOutcome::Accepted { height: 1 }
    ));
    assert_eq!(hub.tip_height(), Some(1));
    // Second block also accepted (one log per height on real path).
    let b2 = mine(hash, 1_300_000_600, 2);
    assert!(matches!(
        hub.accept_block(b2).unwrap(),
        AcceptOutcome::Accepted { height: 2 }
    ));
    assert_eq!(hub.tip_height(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ensure_headers_batch_chain_and_missing_parent() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_000_000, 1);
    let b2 = mine(b1.block_hash(), 1_300_000_600, 2);
    let b3 = mine(b2.block_hash(), 1_300_001_200, 3);
    let before = hub.query.store().header_count();
    let fks = hub
        .ensure_headers_batch(&[b1.header, b2.header, b3.header])
        .unwrap();
    assert_eq!(fks.len(), 3);
    assert_eq!(hub.query.store().header_count(), before + 3);
    assert_eq!(
        hub.query
            .get_header_by_hash(&b2.header.block_hash().to_byte_array())
            .unwrap()
            .unwrap()
            .0,
        fks[1]
    );
    let mut orphan = b1.header;
    orphan.prev_blockhash = BlockHash::from_byte_array([0x9e; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut orphan);
    let err = hub.ensure_headers_batch(&[orphan]).unwrap_err();
    assert!(err.to_string().contains("header parent unknown"), "{err}");
    let b4 = mine(b3.block_hash(), 1_300_001_800, 4);
    let mut bad = b4.header;
    bad.prev_blockhash = BlockHash::from_byte_array([0x9e; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut bad);
    let after_ok = hub.query.store().header_count();
    assert!(hub
        .ensure_headers_batch(&[b4.header, bad])
        .unwrap_err()
        .to_string()
        .contains("header parent unknown"));
    assert_eq!(hub.query.store().header_count(), after_ok);
    // Only genesis has an all-zero parent. Any other zero-parent header
    // is an orphan, as in Core, and writes no row.
    let mut zero = b4.header;
    zero.prev_blockhash = BlockHash::from_byte_array([0u8; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut zero);
    let err = hub.ensure_header(&zero).unwrap_err();
    assert!(err.to_string().contains("header parent unknown"), "{err}");
    let err = hub.ensure_headers_batch(&[zero, b4.header]).unwrap_err();
    assert!(err.to_string().contains("header parent unknown"), "{err}");
    assert_eq!(
        hub.process_submitted_header(&zero).unwrap_err(),
        "Must submit previous header"
    );
    assert_eq!(hub.query.store().header_count(), after_ok);
    assert!(!hub.knows_header(&zero.block_hash()));
    hub.ensure_header(&rbitcoin_consensus::genesis_block(&hub.params).header)
        .expect("genesis still writes its zero-parent row");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tip_accept_line_is_timestamped_json() {
    let line = format_tip_accept_sh_line(&TipAcceptShInput {
        height: 961_445,
        tx_count: 4,
        wall_ns: 2_500_000_000,
        load_ns: 100_000_000,
        script_ns: 0,
        class_a_ns: 0,
        class_c_ns: 0,
        spend_ns: 0,
        strong_ns: 0,
        tip_ns: 0,
        lookup_ns: 0,
        structural_ns: 0,
        drain_ns: 0,
        mp_strip_ns: 0,
        pres_ns: 0,
        bf_ns: 0,
        bf_lag: 0,
        sh_lag: 0,
        sh: rbitcoin_query::TipShSnap::default(),
    });
    assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
    assert!(line.contains("\"height\":961445"), "{line}");
    assert!(line.contains("\"ts\":"), "{line}");
    assert!(line.contains("\"wall_ns\":2500000000"), "{line}");
}

#[test]
fn ensure_genesis_accept_extend_and_already_have() {
    let (dir, hub) = tmp_hub();
    assert!(hub.tip_height().is_none());
    hub.ensure_genesis().unwrap();
    assert_eq!(hub.tip_height(), Some(0));
    // Second call is a no-op once tip exists.
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    assert!(hub.has_block(&gen));
    assert!(hub.query.is_block_archived(&gen.to_byte_array()).unwrap());

    let b1 = mine(gen, 1_300_000_000, 1);
    assert!(matches!(
        hub.accept_block(b1.clone()).unwrap(),
        AcceptOutcome::Accepted { height: 1 }
    ));
    assert_eq!(hub.tip_height(), Some(1));
    assert!(matches!(
        hub.accept_block(b1.clone()).unwrap(),
        AcceptOutcome::AlreadyHave
    ));

    let (dir2, empty) = tmp_hub();
    let err = empty.accept_block(b1.clone()).unwrap_err();
    assert!(matches!(err, NetError::Protocol(_)));

    assert!(hub.chain_work().unwrap().to_be_bytes() != [0u8; 32]);
    assert!(hub.tip_header().is_some());
    let gwork = hub.work_through_height(0).unwrap();
    assert_eq!(gwork, hub.tip_header().unwrap().work());
    let b2 = mine(hub.tip_hash().unwrap(), 1_300_000_100, 2);
    assert!(matches!(
        hub.accept_block(b2.clone()).unwrap(),
        AcceptOutcome::Accepted { height: 2 }
    ));
    let tip_w = hub.chain_work().unwrap();
    assert_eq!(tip_w, hub.work_through_height(2).unwrap());
    assert_eq!(hub.work_through_height(0).unwrap(), gwork);
    assert_eq!(tip_w - gwork, b1.header.work() + b2.header.work());
    hub.test_clear_chain_work_prefix();
    assert_eq!(hub.chain_work().unwrap(), tip_w);
    let extra = mine(b2.block_hash(), 1_300_000_200, 3);
    assert_eq!(
        hub.work_with_header(&extra.header),
        tip_w + extra.header.work()
    );
    assert!(hub.mempool().is_none());
    let _ = hub.subscribe_tips();

    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(dir2);
}

/// A failed rebuild must not leave a prefix the next call will extend.
#[test]
fn chain_work_error_leaves_prefix_empty() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let b1 = mine(hub.tip_hash().unwrap(), 1_300_000_000, 1);
    hub.accept_block(b1).unwrap();
    hub.test_clear_chain_work_prefix();
    hub.query
        .store()
        .confirmed
        .set(
            &rbitcoin_store::ClassCWrite::for_test(),
            rbitcoin_primitives::Height(1),
            Fk(9_000),
        )
        .unwrap();
    assert!(hub.chain_work().is_err());
    assert_eq!(
        hub.test_chain_work_prefix_len(),
        0,
        "a failed chain-work fill does not keep the heights already summed"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Shifted `nBits` must not still sum, so the three headers use different targets.
#[test]
fn chain_work_sums_distinct_header_bits() {
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let (dir, hub) = tmp_hub();
    let targets = [0x207f_ffffu32, 0x1e0f_ffff, 0x1d00_ffff];
    let works: Vec<_> = targets.iter().copied().map(header_work_bits).collect();
    assert_ne!(works[0], works[1]);
    assert_ne!(works[1], works[2]);
    let mut prev_fk = Fk::NULL;
    let mut parent = [0u8; 32];
    let mut sum = Work::from_be_bytes([0u8; 32]);
    for (h, &bits) in targets.iter().enumerate() {
        sum = sum + works[h];
        let label = h as u32;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&label.to_le_bytes());
        let hash = if h == 0 {
            merkle
        } else {
            rbitcoin_store::block_header_hash(1, &parent, &merkle, label + 1, bits, label)
        };
        let rec = HeaderRecord {
            prev_fk,
            version: 1,
            timestamp: label + 1,
            bits,
            nonce: label,
            merkle_root: merkle,
            hash,
            ..HeaderRecord::default()
        };
        let mut txid = [0u8; 32];
        txid[31] = label as u8;
        prev_fk = hub
            .query
            .connect_block(
                Height(label),
                &rec,
                &[TxApply {
                    tx: TxRecord {
                        txid,
                        version: 1,
                        locktime: 0,
                        input_count: 1,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![label as u8], vec![])],
                    outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
                }],
            )
            .unwrap();
        parent = hash;
    }
    hub.test_clear_chain_work_prefix();
    assert_eq!(hub.chain_work().unwrap(), sum);
    let _ = std::fs::remove_dir_all(dir);
}

/// Multi-peer concurrent accept of the same tip block: exactly one Accepted,
/// rest AlreadyHave; single tip height; no orphan Class C outside tip body.
#[test]
fn concurrent_same_block_accept_no_orphan_class_c() {
    use std::sync::Arc;
    let (dir, hub) = tmp_hub();
    let hub = Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_000_000, 1);
    let n = 8usize;
    let mut handles = Vec::new();
    for _ in 0..n {
        let h = Arc::clone(&hub);
        let b = b1.clone();
        handles.push(std::thread::spawn(move || h.accept_block(b)));
    }
    let mut accepted = 0u32;
    let mut already = 0u32;
    for h in handles {
        match h.join().unwrap().unwrap() {
            AcceptOutcome::Accepted { height: 1 } => accepted += 1,
            AcceptOutcome::AlreadyHave => already += 1,
            other => panic!("unexpected outcome {other:?}"),
        }
    }
    assert_eq!(accepted, 1, "exactly one Accepted");
    assert_eq!(already, (n as u32) - 1);
    assert_eq!(hub.tip_height(), Some(1));
    // Tip body membership: every strong+height tx at tip is in header_txs.
    let tip_fks = hub
        .query
        .block_tx_fks(rbitcoin_primitives::Height(1))
        .unwrap();
    let tip_set: std::collections::HashSet<u64> = tip_fks.iter().filter_map(|f| f.get()).collect();
    for &fk in &tip_fks {
        let id = fk.get().unwrap();
        assert!(
            tip_set.contains(&id),
            "orphan Class C fk={id} at tip height not in header_txs"
        );
        assert!(hub.query.store().is_confirmed_strong(fk).unwrap());
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Load batch N+1 must succeed while N is only loaded (not committed).
/// Regression: hub used store tip+1 only → Ok(None) "empty outcome" thrash.
#[test]
fn wire_prep_ahead_of_store_tip_with_pipeline() {
    use rbitcoin_query::WireLoadPipeline;

    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    hub.query.enter_direct_index_mode().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_000_200, 1);
    let b2 = mine(b1.block_hash(), 1_300_000_800, 2);
    let h1 = b1.block_hash();
    let h2 = b2.block_hash();

    let batch1 = [(rbitcoin_primitives::Height(1), b1.clone())];
    let mut inflight = rbitcoin_query::InFlight::new();
    let mut next_tx_start = hub.query.tx_body_count().saturating_add(1).max(1);
    let mat1 = {
        let pipe = WireLoadPipeline {
            path_lo: 1,
            parent_hash: None,
            next_tx_start,
            in_flight: &inflight,
            skeleton: None,
            carried_need: Vec::new(),
            carried_header_fks: Vec::new(),
            carried_header_hashes: Vec::new(),
        };
        hub.confirm_wire_load_phase_pipelined(&batch1, Some(&pipe))
            .expect("prep1")
            .expect("prep1 some")
    };
    assert_eq!(mat1.batch.len(), 1);
    assert!(mat1.batch.archive_plan.is_some());
    assert_eq!(
        hub.tip_height(),
        Some(0),
        "tip must not advance on load alone"
    );

    // Update pipeline caches from plan (load-thread note_lookup_ok).
    let plan = mat1.batch.archive_plan.as_ref().unwrap();
    inflight.note_pins(
        plan.planned_fks
            .iter()
            .zip(plan.batch_pin.iter())
            .map(|(fk, pin)| (*fk, pin)),
        None,
    );
    if let Some(last) = plan.planned_fks.last().and_then(|f| f.get()) {
        next_tx_start = last.saturating_add(1).max(1);
    }

    let batch2 = [(rbitcoin_primitives::Height(2), b2.clone())];
    let mat2 = {
        let pipe = WireLoadPipeline {
            path_lo: 2,
            parent_hash: Some(h1.to_byte_array()),
            next_tx_start,
            in_flight: &inflight,
            skeleton: None,
            carried_need: Vec::new(),
            carried_header_fks: Vec::new(),
            carried_header_hashes: Vec::new(),
        };
        hub.confirm_wire_load_phase_pipelined(&batch2, Some(&pipe))
            .expect("prep2 err")
            .expect("prep2 must Some — pipeline path_lo=2 with tip=0")
    };
    assert_eq!(mat2.batch.len(), 1);
    assert!(mat2.batch.archive_plan.is_some());
    let p1_last = plan.planned_fks.last().unwrap().get().unwrap();
    let p2_first = mat2
        .batch
        .archive_plan
        .as_ref()
        .unwrap()
        .planned_fks
        .first()
        .unwrap()
        .get()
        .unwrap();
    assert!(
        p2_first > p1_last,
        "batch2 fks must not collide with batch1 reserved fks ({p2_first} <= {p1_last})"
    );
    assert_eq!(hub.tip_height(), Some(0));
    let _ = (h2,);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn archive_then_confirm_run_and_empty_paths() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_000_100, 1);
    let h1 = b1.block_hash();

    // Header then accept (confirm is sole Class A).
    hub.ensure_header(&b1.header).unwrap();
    hub.ensure_header_fk(&b1.header).unwrap();
    assert!(hub.confirm_wire_load_phase(&[]).unwrap().is_none());
    let acc = hub.accept_block(b1.clone()).unwrap();
    assert!(matches!(acc, AcceptOutcome::Accepted { height: 1 }));
    assert!(hub.has_block(&h1));
    assert_eq!(hub.tip_height(), Some(1));
    assert!(matches!(
        hub.accept_block(b1.clone()).unwrap(),
        AcceptOutcome::AlreadyHave
    ));
    assert!(hub
        .confirm_wire_load_phase(&[(Height(1), b1.clone())])
        .unwrap()
        .is_none());

    let orphan = mine(BlockHash::from_byte_array([9u8; 32]), 1_300_000_200, 99);
    assert!(matches!(
        hub.accept_block(orphan).unwrap_err(),
        NetError::UnknownParent
    ));

    assert!(hub.accept_branch(&[]).is_err());
    let b2 = mine(h1, 1_300_000_300, 2);
    let b3_bad = mine(BlockHash::from_byte_array([1u8; 32]), 1_300_000_400, 3);
    assert!(hub.accept_branch(&[b2.clone(), b3_bad]).is_err());
    assert!(matches!(
        hub.accept_branch(std::slice::from_ref(&b2)).unwrap(),
        AcceptOutcome::Accepted { height: 2 }
    ));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn accept_unknown_parent_errors() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let orphan = mine(BlockHash::from_byte_array([9u8; 32]), 1_300_000_500, 99);
    assert!(matches!(
        hub.accept_block(orphan).unwrap_err(),
        NetError::UnknownParent
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn submit_header_child_is_headers_only_tip() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_020_000, 1);
    hub.accept_block(b1.clone()).unwrap();
    let child = mine(b1.block_hash(), 1_300_020_100, 2);
    hub.ensure_header(&child.header).unwrap();
    let tips = hub.chaintips();
    let ho = tips
        .iter()
        .find(|t| t.status == "headers-only")
        .expect("headers-only child");
    assert_eq!(ho.hash, child.block_hash());
    assert_eq!(ho.height, 2);
    assert_eq!(ho.branchlen, 1);
    assert_eq!(hub.best_header_height(), 2);
    assert_eq!(hub.tip_height(), Some(1));
    let shorter = mine(gen, 1_300_020_200, 9);
    hub.ensure_header(&shorter.header).unwrap();
    assert_eq!(
        hub.best_header_height(),
        2,
        "a shorter valid header cannot lower the best header height"
    );
    hub.invalidate_block(child.block_hash()).unwrap();
    assert_eq!(
        hub.best_header_height(),
        1,
        "an invalidated taller header does not count"
    );
    // Cross the old ancestry cap with headers only, not a tall block fixture.
    let mut header = b1.header;
    let mut headers = Vec::new();
    for height in 2u32..=10_003 {
        header.prev_blockhash = if height == 2 {
            b1.block_hash()
        } else {
            header.block_hash()
        };
        header.time = b1.header.time + height;
        header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(
            bitcoin::hashes::sha256d::Hash::hash(&height.to_le_bytes()).to_byte_array(),
        );
        rbitcoin_consensus::grind_regtest_pow(&mut header);
        headers.push(header);
    }
    hub.ensure_headers_batch(&headers).unwrap();
    assert_eq!(hub.best_header_height(), 10_003);
    let interior = headers[4_998].block_hash();
    hub.invalidate_block(interior).unwrap();
    assert_eq!(
        hub.best_header_height(),
        4_999,
        "keep the valid prefix below height 5,000"
    );
    let higher = headers[6_998].block_hash();
    hub.invalidate_block(higher).unwrap();
    assert_eq!(
        hub.best_header_height(),
        4_999,
        "a second invalid descendant must not hide the lower failure"
    );
    hub.reconsider_block(interior).unwrap();
    assert_eq!(hub.best_header_height(), 6_999);
    hub.reconsider_block(higher).unwrap();
    assert_eq!(hub.best_header_height(), 10_003);
    hub.invalidate_block(b1.block_hash()).unwrap();
    assert_eq!(
        hub.best_header_height(),
        1,
        "only the shorter valid sibling remains"
    );
    hub.reconsider_block(b1.block_hash()).unwrap();
    assert_eq!(hub.best_header_height(), 10_003);
    let _ = std::fs::remove_dir_all(dir);
}

/// `best_header_height` and `chaintips` walk ancestry through `prev_of`,
/// which read-locks `header_tips` and (via `load_side_body`)
/// `held_bodies`. std's `RwLock` refuses a new reader while a writer
/// waits, so a walk that holds one of those guards deadlocks against a
/// writer: the writer waits for the held read, and the walk's second read
/// waits for the writer.
#[test]
fn ancestry_walks_never_reread_a_held_chain_lock() {
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::thread;
    use std::time::{Duration, Instant};

    let (_dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_030_000, 1);
    hub.accept_block(b1.clone()).unwrap();
    // A header-only tip (`header_tips`) and a parked side body (`held_bodies`).
    let child = mine(b1.block_hash(), 1_300_030_100, 2);
    hub.ensure_header(&child.header).unwrap();
    let side = mine(gen, 1_300_030_200, 1);
    hub.hold_body(Arc::new(side.clone()), false);
    assert!(hub.held_body(&side.block_hash()).is_some());
    let tip = child.block_hash();

    let hub = ChainHub::into_arc(hub);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (hub, stop) = (hub.clone(), stop.clone());
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                drop(hub.header_tips.write().unwrap());
                drop(hub.held_bodies.write().unwrap());
            }
        })
    };
    let (done_tx, done_rx) = mpsc::channel();
    {
        let hub = hub.clone();
        thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(2);
            while Instant::now() < until {
                assert_eq!(hub.best_header_height(), 2);
                assert!(hub.chaintips().iter().any(|t| t.hash == tip));
            }
            let _ = done_tx.send(());
        });
    }
    let outcome = done_rx.recv_timeout(Duration::from_secs(20));
    stop.store(true, Ordering::Relaxed);
    match outcome {
        Ok(()) => writer.join().unwrap(),
        Err(RecvTimeoutError::Timeout) => {
            panic!("an ancestry walk deadlocked against a chain-lock writer")
        }
        Err(RecvTimeoutError::Disconnected) => panic!("the walk thread panicked"),
    }
}

#[test]
fn accept_competing_tip_and_block_at_height_paths() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_001_000, 1);
    hub.accept_block(b1.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(1));
    assert_eq!(
        hub.tip_header().expect("tip header").work(),
        b1.header.work(),
        "equal-height compare uses header work, not a body reconstruct"
    );

    // Competing tip at same height with more work reorgs (or IgnoredWeaker if equal).
    // Mine many nonces for a sibling of b1 with higher work is hard on regtest
    // equal-bits; exercise IgnoredWeaker via accept of a different equal-work sibling.
    let mut sibling = mine(gen, 1_300_001_001, 1);
    if sibling.block_hash() == b1.block_hash() {
        sibling.header.nonce = sibling.header.nonce.wrapping_add(1);
        let target = Target::from_compact(sibling.header.bits);
        for nonce in sibling.header.nonce..u32::MAX {
            sibling.header.nonce = nonce;
            if sibling.header.validate_pow(target).is_ok()
                && sibling.block_hash() != b1.block_hash()
            {
                break;
            }
        }
    }
    let out = hub.accept_block(sibling).unwrap();
    assert!(matches!(
        out,
        AcceptOutcome::IgnoredWeaker | AcceptOutcome::Accepted { .. }
    ));

    let b2 = mine(hub.tip_hash().unwrap(), 1_300_001_100, 2);
    hub.accept_block(b2.clone()).unwrap();
    let got = hub.block_at_height(2).unwrap().unwrap();
    assert_eq!(got.block_hash(), b2.block_hash());
    assert!(hub.block_at_height(9_999).unwrap().is_none());

    let mp_dir = dir.join("mp");
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(&mp_dir, Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    assert!(hub.mempool().is_some());
    let tip = hub.tip_hash().unwrap();
    let tip_h = hub.tip_height().unwrap();
    let b_next = mine(tip, 1_300_001_200, tip_h + 1);
    hub.accept_block(b_next).unwrap();

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn connect_at_releases_sh_after_tip_event() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let genesis = hub
        .block_at_height(0)
        .unwrap()
        .expect("genesis after ensure");
    rbitcoin_query::pad_empty_from(
        hub.query.as_ref(),
        &hub.params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        2,
        0,
    );
    assert_eq!(hub.query.sh_indexed_through_height(), Some(2));
    let mut tip_rx = hub.subscribe_tips();
    let block = hub
        .assemble_block_to_script(ScriptBuf::from_bytes(vec![0x51]), vec![])
        .expect("assemble");
    match hub.accept_block(block).expect("connect") {
        AcceptOutcome::Accepted { height } => assert_eq!(height, 3),
        other => panic!("expected Accepted, got {other:?}"),
    }
    let ev = tip_rx.try_recv().expect("tip event after accept");
    assert_eq!(ev.height, 3);
    assert_eq!(hub.query.index_released_through_height(), Some(3));
    assert_eq!(
        hub.query.sh_indexed_through_height(),
        Some(2),
        "release must not seed; worker/apply does that"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn note_confirmed_tip_sends_the_wire_header() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let block = hub
        .assemble_block_to_script(ScriptBuf::from_bytes(vec![0x51]), vec![])
        .expect("assemble");
    let wire = block.header;
    let hash = block.block_hash();
    match hub.accept_block(block).expect("connect") {
        AcceptOutcome::Accepted { height } => assert_eq!(height, 1),
        other => panic!("expected Accepted, got {other:?}"),
    }
    let stored = hub
        .query
        .wire_header_at_height(Height(1))
        .expect("stored header");
    assert_eq!(stored.nonce, wire.nonce);
    let mut claimed = wire;
    claimed.nonce = wire.nonce.wrapping_add(1);
    let mut tip_rx = hub.subscribe_tips();
    hub.note_confirmed_tip(&[(1, hash)], &[claimed])
        .expect("note");
    let ev = tip_rx.try_recv().expect("tip event");
    assert_eq!(ev.header, claimed);
    assert_eq!(
        hub.query
            .wire_header_at_height(Height(1))
            .expect("store")
            .nonce,
        stored.nonce
    );
    let err = hub
        .note_confirmed_tip(&[(1, hash)], &[])
        .expect_err("header count");
    assert!(
        err.to_string().contains("invariant: wire headers length"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn exclusive_sh_handoff_mempool_to_pending() {
    use rbitcoin_store::script_hash;

    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let genesis = hub
        .block_at_height(0)
        .unwrap()
        .expect("genesis after ensure");
    let (_tip, _time, cbs) = rbitcoin_query::pad_empty_from(
        hub.query.as_ref(),
        &hub.params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        100,
        1,
    );
    assert_eq!(hub.tip_height(), Some(100));
    let through = hub.query.sh_indexed_through_height();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let sh = script_hash(spk.as_bytes());
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());

    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_0000),
            script_pubkey: spk.clone(),
        }],
    };
    let spend_id = spend.compute_txid().to_byte_array();
    mp.accept_tx(&spend).expect("accept spend");
    let in_mp = |mp: &rbitcoin_net::tx_relay::MempoolHub| {
        mp.scripthash_mempool(&sh)
            .iter()
            .any(|r| r.txid == spend_id)
    };
    let in_hist = || {
        hub.query
            .scripthash_history(&sh)
            .unwrap()
            .iter()
            .any(|r| r.txid == spend_id)
    };
    assert!(in_mp(&mp), "pre-connect: tx must be in mempool overlay");
    assert!(!in_hist(), "pre-connect: tx must not be confirmed history");

    let cold0 = hub
        .query
        .confirm_stats()
        .sh_collect_cold
        .load(std::sync::atomic::Ordering::Relaxed);
    let block = hub
        .assemble_block_to_script(spk, vec![spend])
        .expect("assemble");
    match hub.accept_block(block).expect("connect spend block") {
        AcceptOutcome::Accepted { height } => assert_eq!(height, 101),
        other => panic!("expected Accepted, got {other:?}"),
    }
    let cold1 = hub
        .query
        .confirm_stats()
        .sh_collect_cold
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        cold1, cold0,
        "mempool-origin creates must collect from pins, not cold Class A"
    );
    assert_eq!(
        hub.query.sh_indexed_through_height(),
        through,
        "accept must not drain durable SH"
    );
    assert!(
        !in_mp(&mp),
        "post-connect: mempool overlay must not keep the confirmed tx"
    );
    assert!(
        in_hist(),
        "post-connect: pending SH must show the confirmed tx before durable apply"
    );
    let hist_hits = hub
        .query
        .scripthash_history(&sh)
        .unwrap()
        .iter()
        .filter(|r| r.txid == spend_id)
        .count();
    let mp_hits = mp
        .scripthash_mempool(&sh)
        .iter()
        .filter(|r| r.txid == spend_id)
        .count();
    assert_eq!(
        hist_hits + mp_hits,
        1,
        "tx must not vanish or duplicate across overlay and history"
    );

    let h101 = hub.tip_hash().expect("spend block");
    hub.invalidate_block(h101).expect("reorg spend block");
    assert_eq!(hub.tip_height(), Some(100));
    assert!(
        in_mp(&mp),
        "reorg must restore mempool overlay before dropping RAM SH head"
    );
    assert!(
        !in_hist(),
        "disconnected spend must not remain confirmed history"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// `mempool_reorg.py`: invalidate below coinbase maturity must empty the spend.
#[test]
fn invalidate_evicts_immature_coinbase_spend() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let hashes = hub
        .generate_to_script(103, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .expect("pad to mature coinbase");
    assert_eq!(hashes.len(), 103);
    assert_eq!(hub.tip_height(), Some(103));
    let b1 = hub.block_at_height(1).unwrap().expect("height 1");
    let cb = b1.txdata[0].compute_txid();

    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp.clone()).is_ok());

    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    mp.accept_tx(&spend).expect("mature coinbase spend");
    let child = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: spend.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9998_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    mp.accept_tx(&child).expect("child of coinbase spend");
    assert_eq!(mp.live_count(), 2);

    // QueryUtxoProvider must see a coinbase at height 1 (same path evict uses).
    let coin = rbitcoin_net::tx_relay::QueryUtxoProvider::new(hub.query.as_ref())
        .get_coin(&OutPoint { txid: cb, vout: 0 })
        .expect("coinbase still a chain coin");
    assert!(coin.is_coinbase, "shipped get_coin must mark coinbase");
    assert_eq!(coin.create_height, 1);

    let h10 = hub.block_at_height(10).unwrap().expect("height 10");
    hub.invalidate_block(h10.block_hash())
        .expect("invalidate height 10");
    assert_eq!(hub.tip_height(), Some(9));
    assert_eq!(
        mp.live_count(),
        0,
        "invalidate below maturity must evict the coinbase spend and its child"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn work_better_and_sum_work_helpers() {
    let z = Work::from_be_bytes([0u8; 32]);
    let one = {
        let mut b = [0u8; 32];
        b[31] = 1;
        Work::from_be_bytes(b)
    };
    assert!(work_better(one, z));
    assert!(!work_better(z, one));
    assert_eq!(sum_work(std::iter::empty()).unwrap(), z);
    assert_eq!(sum_work([one].into_iter()).unwrap(), one);
}

#[test]
fn confirm_wire_script_split() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_004_000, 1);
    let cb_txid = b1.txdata[0].compute_txid();
    let cb_wtxid = b1.txdata[0].compute_wtxid();
    let loaded = hub.confirm_wire_load_phase(&[(Height(1), b1)]).unwrap();
    assert!(loaded.is_some());
    let batch = loaded.unwrap();
    let script_out = confirm_scripts_phase(batch.batch).unwrap();
    let mp = attach_mp(dir.path(), &hub);
    let write_out = hub.confirm_write(script_out.batch).unwrap();
    assert_eq!(write_out.len(), 1);
    assert!(matches!(
        write_out[0],
        AcceptOutcome::Accepted { height: 1 }
    ));
    assert_eq!(hub.tip_height(), Some(1));
    assert!(
        mp.try_contains_wtxid(&cb_wtxid),
        "IBD confirm_write must fill recent-confirmed wtxid"
    );
    assert!(mp.try_contains(&cb_txid));

    let _ = std::fs::remove_dir_all(dir);
}

/// Mine a coinbase-only block with optional extra txs (for invalid mid-branch).
fn mine_with_extra(prev: BlockHash, time: u32, height: u32, extra: Vec<Transaction>) -> Block {
    mine_regtest_paying(prev, time, height, ScriptBuf::from_bytes(vec![0x51]), extra)
}

/// Journey: deep most-work reorg (≥16), weaker ignored, mid-branch invalid
/// restores pre-attempt tip (shipped `accept_branch`).
#[test]
fn most_work_reorg_depth16_and_invalid_mid_branch_restores_tip() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut tip = gen;
    let time = 1_400_000_000u32;
    for h in 1..=8u32 {
        let b = mine(tip, time + h * 600, h);
        tip = b.block_hash();
        hub.accept_block(b).unwrap();
    }
    assert_eq!(hub.tip_height(), Some(8));
    let main_tip = hub.tip_hash().unwrap();

    let fork_parent = hub
        .query
        .header_at_height(Height(2))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let fork_prev = BlockHash::from_byte_array(fork_parent);
    let fork_time = hub
        .query
        .header_at_height(Height(2))
        .unwrap()
        .unwrap()
        .1
        .timestamp;

    let mut branch = Vec::new();
    let mut p = fork_prev;
    let mut t = fork_time;
    for (i, h) in (3..=18u32).enumerate() {
        let b = mine(p, t + 601 + i as u32, h);
        p = b.block_hash();
        t = b.header.time;
        branch.push(b);
    }
    assert_eq!(branch.len(), 16);
    let out = hub.accept_branch(&branch).unwrap();
    assert!(
        matches!(out, AcceptOutcome::Accepted { height: 18 }),
        "depth-16 reorg must accept, got {out:?}"
    );
    assert_eq!(hub.tip_height(), Some(18));
    assert_eq!(hub.tip_hash().unwrap(), branch.last().unwrap().block_hash());
    assert_ne!(hub.tip_hash().unwrap(), main_tip);

    // Weaker shorter branch from height 17 → IgnoredWeaker.
    let weak = mine(hub.tip_hash().unwrap(), t + 10, 19); // extends tip — Accepted
    let _ = weak;
    let weak_side = mine(fork_prev, t + 9000, 3);
    let weak_out = hub.accept_branch(&[weak_side]).unwrap();
    assert!(
        matches!(weak_out, AcceptOutcome::IgnoredWeaker),
        "short side from old LCA must be weaker: {weak_out:?}"
    );
    assert_eq!(hub.tip_height(), Some(18));

    let pre_tip = hub.tip_hash().unwrap();
    let pre_h = hub.tip_height().unwrap();
    let fork2 = hub
        .query
        .header_at_height(Height(10))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let fork2_prev = BlockHash::from_byte_array(fork2);
    let fork2_time = hub
        .query
        .header_at_height(Height(10))
        .unwrap()
        .unwrap()
        .1
        .timestamp;

    // Path length 10 (> remaining 8 on main from 11..=18) so work_better.
    let mut bad_branch = Vec::new();
    let mut p = fork2_prev;
    let mut t = fork2_time;
    for (i, h) in (11..=20u32).enumerate() {
        let b = if i == 2 {
            let bad_tx = Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([0xee; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            };
            mine_with_extra(p, t + 701 + i as u32, h, vec![bad_tx])
        } else {
            mine(p, t + 701 + i as u32, h)
        };
        p = b.block_hash();
        t = b.header.time;
        bad_branch.push(b);
    }
    assert_eq!(bad_branch.len(), 10);
    let err = hub
        .accept_branch(&bad_branch)
        .expect_err("invalid mid-branch must fail connect");
    assert!(
        matches!(err, NetError::Consensus(_) | NetError::ConnectFailed { .. }),
        "expected consensus fail, got {err}"
    );
    // The two-block valid prefix does not out-work the eight-block old
    // branch, so the old tip is restored.
    assert_eq!(
        hub.tip_height(),
        Some(pre_h),
        "tip height must restore after failed reorg"
    );
    assert_eq!(
        hub.tip_hash().unwrap(),
        pre_tip,
        "tip hash must equal pre-attempt tip after mid-branch invalid"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// Tip-follow capacity: 99-block competing branch via shipped `accept_branch`.
#[test]
fn most_work_reorg_depth99_tip_follow_capacity() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut tip = gen;
    let time = 1_600_000_000u32;
    for h in 1..=10u32 {
        let b = mine(tip, time + h * 600, h);
        tip = b.block_hash();
        hub.accept_block(b).unwrap();
    }
    assert_eq!(hub.tip_height(), Some(10));
    let fork_parent = hub
        .query
        .header_at_height(Height(1))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let fork_prev = BlockHash::from_byte_array(fork_parent);
    let fork_time = hub
        .query
        .header_at_height(Height(1))
        .unwrap()
        .unwrap()
        .1
        .timestamp;
    let mut branch = Vec::with_capacity(99);
    let mut p = fork_prev;
    let mut t = fork_time;
    for (i, h) in (2..=100u32).enumerate() {
        let b = mine(p, t + 601 + i as u32, h);
        p = b.block_hash();
        t = b.header.time;
        branch.push(b);
    }
    assert_eq!(branch.len(), 99);
    const {
        assert!(rbitcoin_net::peer::MAX_PENDING_BLOCKS_FOR_TEST >= 99);
    }
    let out = hub.accept_branch(&branch).unwrap();
    assert!(
        matches!(out, AcceptOutcome::Accepted { height: 100 }),
        "99-block reorg must accept, got {out:?}"
    );
    assert_eq!(hub.tip_height(), Some(100));
    assert_eq!(hub.tip_hash().unwrap(), branch.last().unwrap().block_hash());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn held_bodies_trim_stale_below_unrequested_window() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_040_000, 1);
    hub.accept_block(b1.clone()).unwrap();
    let stale = mine_distinct(gen, 1_300_040_001, 1, &[b1.block_hash()]);
    assert!(matches!(
        hub.accept_received_block(stale.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(hub.held_body(&stale.block_hash()).is_some());

    rbitcoin_query::pad_empty_from(
        hub.query.as_ref(),
        &hub.params,
        b1.block_hash(),
        b1.header.time,
        2,
        288,
        0,
    );
    assert_eq!(hub.tip_height(), Some(288));
    let padded = hub.tip_hash().unwrap();
    let padded_block = hub
        .block_at_height(288)
        .unwrap()
        .expect("padded tip reconstructable");
    let step = rbitcoin_consensus::mine_empty_regtest(
        padded,
        padded_block.header.time.saturating_add(600),
        289,
    );
    hub.accept_block(step).unwrap();
    assert_eq!(hub.tip_height(), Some(289));
    assert!(
        hub.held_body(&stale.block_hash()).is_some(),
        "288 blocks behind the tip is still inside the hold window"
    );
    let edge = mine_distinct(
        gen,
        1_300_040_050,
        1,
        &[b1.block_hash(), stale.block_hash()],
    );
    assert!(matches!(
        hub.accept_received_block(edge.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(
        hub.held_body(&edge.block_hash()).is_some(),
        "a new body exactly 288 behind the tip is held"
    );
    let tip_hash = hub.tip_hash().unwrap();
    let tip_block = hub
        .block_at_height(289)
        .unwrap()
        .expect("height 289 reconstructable");
    let mut near = rbitcoin_consensus::mine_empty_regtest(
        tip_block.header.prev_blockhash,
        tip_block.header.time.saturating_add(1),
        289,
    );
    if near.block_hash() == tip_hash {
        let target = Target::from_compact(near.header.bits);
        for nonce in 0..u32::MAX {
            near.header.nonce = nonce;
            if near.header.validate_pow(target).is_ok() && near.block_hash() != tip_hash {
                break;
            }
        }
    }
    assert!(matches!(
        hub.accept_received_block(near.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(hub.held_body(&near.block_hash()).is_some());

    let next = rbitcoin_consensus::mine_empty_regtest(
        tip_hash,
        tip_block.header.time.saturating_add(600),
        290,
    );
    hub.accept_block(next).unwrap();
    assert_eq!(hub.tip_height(), Some(290));
    assert!(
        hub.held_body(&stale.block_hash()).is_none(),
        "held body 289 heights behind tip must trim"
    );
    assert!(
        hub.held_body(&near.block_hash()).is_some(),
        "sibling at previous tip height must stay held"
    );

    let far = mine_distinct(
        gen,
        1_300_040_002,
        1,
        &[b1.block_hash(), stale.block_hash(), edge.block_hash()],
    );
    assert!(matches!(
        hub.accept_received_block(far.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(
        hub.held_body(&far.block_hash()).is_none(),
        "must not hold IgnoredWeaker already >288 below tip"
    );

    let _ = std::fs::remove_dir_all(dir);
}

fn missing_prevout_child(prev: BlockHash, time: u32, height: u32) -> Block {
    let spend = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x29; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    mine_regtest_paying(
        prev,
        time,
        height,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend],
    )
}

#[test]
fn invalid_held_child_does_not_poison_later_apply() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_050_000, 1);
    hub.accept_block(b1.clone()).unwrap();
    let side = mine_distinct(gen, 1_300_050_001, 1, &[b1.block_hash()]);
    assert!(matches!(
        hub.accept_received_block(side.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(hub.held_body(&side.block_hash()).is_some());

    let bad = missing_prevout_child(side.block_hash(), side.header.time.saturating_add(600), 2);
    let err = hub
        .accept_received_block(bad.clone())
        .expect_err("missing prevout must reject");
    match err {
        NetError::Consensus(s) => {
            assert!(s.contains("bad-txns-inputs-missingorspent"), "got {s}");
        }
        NetError::ConnectFailed { msg, hash, .. } => {
            assert!(msg.contains("bad-txns-inputs-missingorspent"), "got {msg}");
            assert_eq!(hash, bad.block_hash().to_byte_array());
        }
        other => panic!("expected consensus reject, got {other:?}"),
    }
    assert_eq!(hub.tip_hash(), Some(b1.block_hash()));
    assert!(
        hub.held_body(&bad.block_hash()).is_none(),
        "consensus-invalid child must leave held_bodies"
    );
    assert!(
        hub.is_block_invalid(&bad.block_hash()),
        "missingorspent child is BLOCK_FAILED"
    );

    assert!(matches!(
        hub.accept_received_block(side.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker | AcceptOutcome::AlreadyHave
    ));
    assert_eq!(
        hub.tip_hash(),
        Some(b1.block_hash()),
        "retrying the sibling must not fail or reorg onto the invalid child"
    );

    let good = mine(side.block_hash(), side.header.time.saturating_add(601), 2);
    assert!(matches!(
        hub.accept_received_block(good.clone()).unwrap(),
        AcceptOutcome::Accepted { height: 2 }
    ));
    assert_eq!(hub.tip_hash(), Some(good.block_hash()));

    hub.note_invalid_block(good.block_hash());
    let err = hub
        .accept_branch(&[side.clone(), good.clone()])
        .expect_err("invalidated tip must not apply");
    match err {
        NetError::Consensus(s) => {
            assert!(s.contains("invalidat"), "got {s}");
        }
        other => panic!("expected invalidated refuse, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(dir);
}

fn mine_chain(hub: &ChainHub, len: u32, time: u32) -> Vec<Block> {
    let mut prev = hub.tip_hash().unwrap();
    let base = hub.tip_height().unwrap();
    let mut out = Vec::new();
    for h in base + 1..=base + len {
        let b = mine(prev, time + h * 600, h);
        prev = b.block_hash();
        hub.accept_block(b.clone()).unwrap();
        out.push(b);
    }
    out
}

#[test]
fn sibling_claiming_more_work_with_wrong_bits_keeps_the_tip() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let main = mine_chain(&hub, 5, 1_300_060_000);
    let tip = main[4].block_hash();
    for h in (2..=5u32).rev() {
        let parent = &main[h as usize - 2];
        let mut bogus = mine(parent.block_hash(), parent.header.time + 1, h);
        bogus.header.bits = CompactTarget::from_consensus(0x1700_ffff);
        let err = hub
            .accept_received_block(bogus)
            .expect_err("a sibling with wrong nBits must be rejected");
        assert!(err.to_string().contains("bits"), "height {h}: {err}");
        assert_eq!(
            hub.tip_hash(),
            Some(tip),
            "a rejected sibling at height {h} must not move the tip"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Side branch `w2, w3, w4` off `main[0]`, where `w4` has a wrong BIP34
/// height. `w2` and `w4` arrive first; returns `w3`'s outcome.
fn side_branch_with_bad_tip(
    hub: &ChainHub,
    main: &[Block],
) -> (Result<AcceptOutcome, NetError>, [Block; 3]) {
    let x1 = &main[0];
    let w2 = mine_distinct(
        x1.block_hash(),
        x1.header.time + 1,
        2,
        &[main[1].block_hash()],
    );
    let w3 = mine(w2.block_hash(), w2.header.time + 600, 3);
    let w4 = mine(w3.block_hash(), w3.header.time + 600, 9);
    for early in [&w2, &w4] {
        assert!(matches!(
            hub.accept_received_block(early.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
    }
    let out = hub.accept_received_block(w3.clone());
    (out, [w2, w3, w4])
}

#[test]
fn failed_branch_tip_keeps_the_heavier_valid_prefix() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let main = mine_chain(&hub, 2, 1_300_070_000);
    let (out, [_, w3, w4]) = side_branch_with_bad_tip(&hub, &main);
    assert!(
        matches!(out, Ok(AcceptOutcome::Accepted { height: 3 })),
        "valid w3 out-works x2: {out:?}"
    );
    assert_eq!(hub.tip_hash(), Some(w3.block_hash()));
    assert!(hub.is_block_invalid(&w4.block_hash()));
    assert!(!hub.is_block_invalid(&w3.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

/// `w2, w3` are held and out-work `x2`; the offered `w4` fails connect.
/// The prefix stays the tip, and the call that delivered `w4` fails.
#[test]
fn failed_offered_block_is_rejected_when_its_held_prefix_stays() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let main = mine_chain(&hub, 2, 1_300_074_000);
    let x1 = &main[0];
    let w2 = mine_distinct(
        x1.block_hash(),
        x1.header.time + 1,
        2,
        &[main[1].block_hash()],
    );
    let w3 = mine(w2.block_hash(), w2.header.time + 600, 3);
    let w4 = mine(w3.block_hash(), w3.header.time + 600, 9);
    hub.hold_body(Arc::new(w2), false);
    hub.hold_body(Arc::new(w3.clone()), false);
    let err = hub
        .accept_received_block(w4.clone())
        .expect_err("w4 has a wrong BIP34 height");
    assert_eq!(
        err.failing_block_hash(),
        Some(w4.block_hash().to_byte_array())
    );
    assert_eq!(hub.tip_hash(), Some(w3.block_hash()));
    assert!(hub.is_block_invalid(&w4.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn failed_branch_tip_does_not_reject_the_offered_parent() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let main = mine_chain(&hub, 3, 1_300_071_000);
    let (out, [_, w3, w4]) = side_branch_with_bad_tip(&hub, &main);
    assert!(
        matches!(out, Ok(AcceptOutcome::IgnoredWeaker)),
        "w3 only ties x3, and w4's failure is not w3's: {out:?}"
    );
    assert_eq!(hub.tip_hash(), Some(main[2].block_hash()));
    assert!(hub.is_block_invalid(&w4.block_hash()));
    assert!(!hub.is_block_invalid(&w3.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

/// Two held branches score the same work from their own fork points.
/// The later one forks higher, so it has more total chain work.
#[test]
fn held_branch_with_more_total_work_beats_an_earlier_local_tie() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let main = mine_chain(&hub, 3, 1_300_072_000);
    let [x1, x2, x3] = [&main[0], &main[1], &main[2]];
    let y2 = mine_distinct(x1.block_hash(), x1.header.time + 1, 2, &[x2.block_hash()]);
    let y3 = mine(y2.block_hash(), y2.header.time + 600, 3);
    let z3 = mine_distinct(x2.block_hash(), x2.header.time + 1, 3, &[x3.block_hash()]);
    let z4 = mine(z3.block_hash(), z3.header.time + 600, 4);
    for b in [&y2, &y3, &z3] {
        assert!(matches!(
            hub.accept_received_block(b.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
    }
    let out = hub.accept_received_block(z4.clone()).unwrap();
    assert!(
        matches!(out, AcceptOutcome::Accepted { height: 4 }),
        "z4 has the most total work: {out:?}"
    );
    assert_eq!(hub.tip_hash(), Some(z4.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

/// `p2` completes two held branches. The heavier one fails at `m3`; the
/// lighter `n3` is still heavier than the tip and must win.
#[test]
fn failed_heavier_held_branch_does_not_hide_a_valid_one() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let main = mine_chain(&hub, 2, 1_300_073_000);
    let x1 = &main[0];
    let p2 = mine_distinct(
        x1.block_hash(),
        x1.header.time + 1,
        2,
        &[main[1].block_hash()],
    );
    let m3 = mine(p2.block_hash(), p2.header.time + 600, 9);
    let m4 = mine(m3.block_hash(), m3.header.time + 600, 4);
    let n3 = mine_distinct(p2.block_hash(), p2.header.time + 601, 3, &[m3.block_hash()]);
    for b in [&m3, &m4, &n3] {
        assert!(matches!(
            hub.accept_received_block(b.clone()).unwrap(),
            AcceptOutcome::IgnoredWeaker
        ));
    }
    let out = hub.accept_received_block(p2.clone()).unwrap();
    assert!(
        matches!(out, AcceptOutcome::Accepted { height: 3 }),
        "n3 is the most-work valid tip: {out:?}"
    );
    assert_eq!(hub.tip_hash(), Some(n3.block_hash()));
    assert!(hub.is_block_invalid(&m3.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

fn find_store_file(root: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    for e in std::fs::read_dir(root).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(hit) = find_store_file(&p, name) {
                return Some(hit);
            }
        } else if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
    }
    None
}

fn spend_block(prev: BlockHash, time: u32, height: u32, outpoint: OutPoint) -> Block {
    let spend = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    mine_regtest_paying(
        prev,
        time,
        height,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend],
    )
}

/// Hub at `t2` on `b1` with `txout.body` cut to zero bytes: any later
/// read of a confirmed out is a local IO fault, not a block verdict.
fn hub_with_truncated_body() -> (rbitcoin_query::testutil::TempDir, ChainHub, Block, Block) {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_080_000, 1);
    hub.accept_block(b1.clone()).unwrap();
    let t2 = mine(b1.block_hash(), b1.header.time + 600, 2);
    hub.accept_block(t2.clone()).unwrap();
    let body = find_store_file(dir.path(), "txout.body").expect("txout.body");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&body)
        .unwrap()
        .set_len(0)
        .unwrap();
    (dir, hub, b1, t2)
}

fn coinbase_out(b: &Block) -> OutPoint {
    OutPoint {
        txid: b.txdata[0].compute_txid(),
        vout: 0,
    }
}

/// Core treats a local read fault as fatal, never `BLOCK_FAILED_VALID`.
/// The spend is also immature, so a missed fault would cache the hash.
#[test]
fn store_fault_on_tip_connect_does_not_cache_block_invalid() {
    let (dir, hub, b1, t2) = hub_with_truncated_body();

    let b3 = spend_block(t2.block_hash(), t2.header.time + 600, 3, coinbase_out(&b1));
    let err = hub
        .accept_received_block(b3.clone())
        .expect_err("parent body read past EOF must fail");
    assert!(matches!(err, NetError::Store(_)), "tip extend: {err:?}");
    assert!(
        !hub.is_block_invalid(&b3.block_hash()),
        "a store fault on tip extend is not a block verdict"
    );
    assert_eq!(hub.tip_hash(), Some(t2.block_hash()));

    let s2 = mine_distinct(b1.block_hash(), t2.header.time + 1, 2, &[t2.block_hash()]);
    assert!(matches!(
        hub.accept_received_block(s2.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    let s3 = spend_block(s2.block_hash(), s2.header.time + 600, 3, coinbase_out(&b1));
    let err = hub
        .accept_received_block(s3.clone())
        .expect_err("reorg must hit the same read fault");
    assert!(matches!(err, NetError::Store(_)), "reorg: {err:?}");
    assert!(
        !hub.is_block_invalid(&s3.block_hash()),
        "a store fault during reorg is not a block verdict"
    );
    assert_eq!(hub.tip_hash(), Some(t2.block_hash()));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn store_fault_applying_held_child_does_not_cache_block_invalid() {
    let (dir, hub, b1, t2) = hub_with_truncated_body();

    let b3 = mine(t2.block_hash(), t2.header.time + 600, 3);
    let c4 = spend_block(b3.block_hash(), b3.header.time + 600, 4, coinbase_out(&b1));
    assert!(matches!(
        hub.accept_received_block(c4.clone()).unwrap(),
        AcceptOutcome::IgnoredWeaker
    ));
    assert!(hub.held_body(&c4.block_hash()).is_some());

    let err = hub
        .accept_received_block(b3.clone())
        .expect_err("held child connect must hit the read fault");
    assert!(matches!(err, NetError::Store(_)), "held apply: {err:?}");
    assert_eq!(hub.tip_hash(), Some(b3.block_hash()));
    assert!(
        !hub.is_block_invalid(&c4.block_hash()),
        "a store fault applying a held child is not a block verdict"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// A tip-connect store fault must not stick the hash in `asked_blocks`.
/// The session stays up and the block is not cached invalid.
#[test]
fn store_fault_on_block_releases_the_body_ask() {
    let (dir, hub, b1, t2) = hub_with_truncated_body();
    let b3 = spend_block(t2.block_hash(), t2.header.time + 600, 3, coinbase_out(&b1));
    let hash = b3.block_hash();
    assert!(hub.claim_block_ask(&hash));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("on_block runtime");
    rt.block_on(async {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut follow = rbitcoin_net::peer::PeerFollowState::new();
        follow.requested_blocks.insert(hash);
        rbitcoin_net::peer::on_block(&hub, &tx, &mut follow, None, &b3)
            .await
            .expect("store fault keeps the session");
    });
    assert!(
        !hub.is_block_invalid(&hash),
        "store fault is not a block verdict"
    );
    assert_eq!(hub.tip_hash(), Some(t2.block_hash()));
    assert!(
        hub.claim_block_ask(&hash),
        "on_block store fault must release the body ask"
    );

    let mut pending = rbitcoin_net::peer::PendingBlocks::new();
    pending.insert(hash, b3);
    let mut headers = HashMap::new();
    rt.block_on(async {
        rbitcoin_net::peer::drain_pending_once(&hub, &mut pending, &mut headers, None)
            .await
            .expect("drain keeps the session");
    });
    assert!(
        hub.claim_block_ask(&hash),
        "drain_pending store fault must release the body ask"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Coinbase outputs with distinct values and scripts. Sum is the subsidy.
fn mine_split(prev: BlockHash, time: u32, height: u32, scripts: &[u8]) -> Block {
    let subsidy = rbitcoin_consensus::block_subsidy(height, &ChainParams::regtest()) as u64;
    let mut outputs = Vec::with_capacity(scripts.len());
    let mut used = 0u64;
    for (i, script) in scripts.iter().enumerate() {
        let value = if i + 1 == scripts.len() {
            subsidy - used
        } else {
            10_000 * (i as u64 + 1)
        };
        used += value;
        outputs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![*script]),
        });
    }
    let mut tx =
        rbitcoin_consensus::regtest_coinbase(height, Amount::from_sat(0), ScriptBuf::new());
    tx.output = outputs;
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
        time,
        bits: CompactTarget::from_consensus(rbitcoin_consensus::REGTEST_POW_BITS),
        nonce: 0,
    };
    let mut block = Block {
        header,
        txdata: vec![tx],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    block
}

fn connected_outputs(hub: &ChainHub, txid: &bitcoin::Txid) -> Vec<(u64, Vec<u8>)> {
    let Some(fk) = hub.query.tx_fk_by_txid_tip(txid.as_byte_array()).unwrap() else {
        return Vec::new();
    };
    let meta = hub.query.get_tx(fk).unwrap();
    (0..meta.output_count)
        .map(|vout| {
            let out = hub.query.tx_output_at_fk(fk, vout).unwrap();
            (out.value, out.script)
        })
        .collect()
}

fn expect_outputs(block: &Block, got: &[(u64, Vec<u8>)]) {
    let want: Vec<(u64, Vec<u8>)> = block.txdata[0]
        .output
        .iter()
        .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
        .collect();
    assert_eq!(got, want, "gettxout value/script");
}

/// A short body write during tip connect is a store fault. It must not mark
/// the block or the next valid block invalid, and a later connect must not
/// make `gettxout` return another output. A real consensus failure still
/// persists.
#[test]
fn short_pwrite_on_tip_connect_does_not_swap_gettxout() {
    let (dir, mut hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = hub.tip_header().unwrap().time;
    let base = mine(gen, t0 + 1, 1);
    let base_txid = base.txdata[0].compute_txid();
    hub.accept_received_block(base.clone()).unwrap();
    let base_outs = connected_outputs(&hub, &base_txid);

    let failed = mine_split(base.block_hash(), t0 + 2, 2, &[0x51, 0x52, 0x53, 0x54]);
    let failed_hash = failed.block_hash();
    let failed_txid = failed.txdata[0].compute_txid();
    let err = {
        // Tip connect runs on another thread. Disarm on drop so a panic
        // cannot leave later tests in this process short-writing.
        struct Disarm<'a>(&'a ChainHub);
        impl Drop for Disarm<'_> {
            fn drop(&mut self) {
                self.0.query.store().txs.disarm_short_body_pwrite();
            }
        }
        hub.query.store().txs.arm_short_body_pwrite("spent");
        let _disarm = Disarm(&hub);
        hub.accept_received_block(failed.clone())
    };
    let err = err.expect_err("short spent.body write");
    assert!(matches!(err, NetError::Store(_)), "tip extend: {err:?}");
    assert!(
        !hub.is_block_invalid(&failed_hash),
        "store fault is not a verdict"
    );
    assert_eq!(hub.tip_hash(), Some(base.block_hash()));
    assert_eq!(connected_outputs(&hub, &base_txid), base_outs);
    assert!(
        connected_outputs(&hub, &failed_txid).is_empty(),
        "the failed block is not served as another output"
    );
    let marks = dir.path().join("block.invalid");
    let file_has = |hash: &BlockHash| {
        std::fs::read(&marks)
            .unwrap_or_default()
            .windows(32)
            .any(|w| w == hash.as_byte_array())
    };
    assert!(
        !file_has(&failed_hash),
        "block.invalid gained the store fault"
    );

    drop(hub);
    let q = rbitcoin_query::Query::open_or_create_tiny(dir.path()).unwrap();
    hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    assert!(!hub.is_block_invalid(&failed_hash));
    assert!(!file_has(&failed_hash));
    assert_eq!(connected_outputs(&hub, &base_txid), base_outs);

    hub.accept_received_block(failed.clone()).unwrap();
    expect_outputs(&failed, &connected_outputs(&hub, &failed_txid));
    let next = mine_split(failed_hash, t0 + 3, 3, &[0x61, 0x62, 0x63, 0x64]);
    let next_hash = next.block_hash();
    let next_txid = next.txdata[0].compute_txid();
    hub.accept_received_block(next.clone()).unwrap();
    expect_outputs(&next, &connected_outputs(&hub, &next_txid));
    expect_outputs(&failed, &connected_outputs(&hub, &failed_txid));
    assert!(!hub.is_block_invalid(&failed_hash));
    assert!(!hub.is_block_invalid(&next_hash));
    assert!(!file_has(&failed_hash));
    assert!(!file_has(&next_hash));

    drop(hub);
    let q = rbitcoin_query::Query::open_or_create_tiny(dir.path()).unwrap();
    hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    expect_outputs(&failed, &connected_outputs(&hub, &failed_txid));
    expect_outputs(&next, &connected_outputs(&hub, &next_txid));
    assert!(!file_has(&failed_hash));
    assert!(!file_has(&next_hash));

    let mut bad = mine(next_hash, t0 + 4, 4);
    let cb = &mut bad.txdata[0].output[0].value;
    *cb = Amount::from_sat(cb.to_sat() + 1);
    bad.header.merkle_root = bad.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut bad.header);
    let bad_hash = bad.block_hash();
    let err = hub.accept_received_block(bad).expect_err("excess coinbase");
    assert!(
        matches!(err, NetError::Rules(_) | NetError::Consensus(_)),
        "consensus reject: {err:?}"
    );
    assert!(hub.is_block_invalid(&bad_hash));
    assert!(
        file_has(&bad_hash),
        "a consensus connect failure is persisted"
    );
    assert!(!file_has(&failed_hash));
    assert!(!file_has(&next_hash));

    let _ = std::fs::remove_dir_all(dir);
}

/// A reconstructed compact block takes the same tip-connect read fault.
/// The hub ask must come back so a later getdata can claim the hash.
#[test]
fn store_fault_on_cmpct_releases_the_body_ask() {
    use bitcoin::bip152::HeaderAndShortIds;

    let (dir, hub, b1, t2) = hub_with_truncated_body();
    let b3 = spend_block(t2.block_hash(), t2.header.time + 600, 3, coinbase_out(&b1));
    let hash = b3.block_hash();
    assert!(hub.claim_block_ask(&hash));
    let hsi = HeaderAndShortIds::from_block(&b3, 1, 2, &[0]).expect("compact header");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("cmpct runtime");
    rt.block_on(async {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut follow = rbitcoin_net::peer::PeerFollowState::new();
        follow.requested_blocks.insert(hash);
        rbitcoin_net::peer::on_cmpct_got_block(&hub, &tx, &mut follow, None, &hsi, hash, b3, None)
            .await
            .expect("compact store fault keeps the session");
    });
    assert!(
        !hub.is_block_invalid(&hash),
        "store fault is not a block verdict"
    );
    assert_eq!(hub.tip_hash(), Some(t2.block_hash()));
    assert!(
        hub.claim_block_ask(&hash),
        "compact store fault must release the body ask"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[allow(clippy::cognitive_complexity)] // one hub: tip rejects, 64-byte body, in-block duplicates
#[test]
fn hostile_peer_session() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();

    let mut zero = mine(tip, 1_300_000_100, 1);
    zero.header.prev_blockhash = BlockHash::from_byte_array([0u8; 32]);
    let err = hub.accept_received_block(zero).expect_err("zero prev");
    assert!(
        err.to_string().contains("non-genesis prev is zero"),
        "{err}"
    );
    assert_eq!(hub.tip_hash(), Some(tip));
    assert_eq!(hub.held_body_count(), 0);

    let honest = mine(tip, 1_300_070_000, 1);
    let mut padded = honest.clone();
    let mut wit = Witness::new();
    wit.push(vec![0u8; 4_000_000]);
    padded.txdata[0].input[0].witness = wit;
    assert_eq!(padded.block_hash(), honest.block_hash());
    hub.note_asked_block(honest.block_hash());
    let _err = hub
        .accept_received_block(padded)
        .expect_err("witness padding past the weight limit must reject");
    assert!(
        !hub.is_block_invalid(&honest.block_hash()),
        "witness padding must not cache the block hash"
    );
    let mut short_cb = honest.clone();
    short_cb.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    assert_eq!(short_cb.block_hash(), honest.block_hash());
    let err = hub
        .accept_received_block(short_cb)
        .expect_err("a coinbase the header does not commit to must reject");
    assert!(matches!(&err, NetError::Mutated(_)), "{err:?}");
    assert!(
        !hub.is_block_invalid(&honest.block_hash()),
        "a swapped coinbase scriptSig must not cache the block hash"
    );
    assert!(matches!(
        hub.accept_received_block(honest.clone()).unwrap(),
        AcceptOutcome::Accepted { height: 1 }
    ));

    let inner =
        rbitcoin_net::chain::sixty_four_byte_body(honest.block_hash(), honest.header.time + 1);
    hub.note_asked_block(inner.block_hash());
    let err = hub
        .accept_received_block(inner.clone())
        .expect_err("a body with no coinbase must reject");
    assert!(matches!(err, NetError::Mutated(_)), "got {err:?}");
    assert!(
        !hub.is_block_invalid(&inner.block_hash()),
        "a 64-byte tx without a coinbase may be an inner merkle node: \
         the header's real body must stay acceptable"
    );
    assert!(
        !hub.already_have_or_asked_block(&inner.block_hash()),
        "a mutated reject forgets the ask so the real body can be fetched"
    );
    assert_eq!(hub.tip_hash(), Some(honest.block_hash()));

    // The header commits to these txs, so the hash itself is invalid
    // (Core bad-cb-multiple; a repeat that leaves the tree unmutated is
    // bad-txns-inputs-missingorspent at connect).
    let spend = |n: u8| Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let t2 = honest.header.time + 600;
    for (extra, want) in [
        (vec![coinbase(3)], "bad-cb-multiple"),
        (
            vec![spend(1), spend(2), spend(1)],
            "bad-txns-inputs-missingorspent",
        ),
    ] {
        let bad = mine_with_extra(honest.block_hash(), t2, 2, extra);
        hub.note_asked_block(bad.block_hash());
        let err = hub.accept_received_block(bad.clone()).expect_err(want);
        let reason = err
            .consensus_rules()
            .map(rbitcoin_consensus::block_reject_reason);
        assert!(
            reason.as_deref().is_some_and(|s| s.contains(want)),
            "{want}: {err:?}"
        );
        assert!(hub.is_block_invalid(&bad.block_hash()), "{want} cached");
    }

    let now = honest.header.time;
    hub.clock.set_mock(i64::from(now));
    let far = now + 2 * 3600 + 1;
    let future = mine(honest.block_hash(), far, 2);
    hub.note_asked_block(future.block_hash());
    let err = hub
        .accept_received_block(future.clone())
        .expect_err("header more than two hours ahead of mock");
    let msg = err
        .consensus_rules()
        .map(rbitcoin_consensus::block_reject_reason)
        .unwrap_or_else(|| panic!("expected a rule failure, got {err:?}"));
    assert!(msg.contains("time-too-new"), "got {msg}");
    assert!(
        !hub.is_block_invalid(&future.block_hash()),
        "time-too-new must not cache BLOCK_FAILED"
    );
    assert!(
        !hub.already_have_or_asked_block(&future.block_hash()),
        "time-too-new must forget asked_blocks so a later getdata can retry"
    );
    assert_eq!(hub.tip_hash(), Some(honest.block_hash()));

    let _ = std::fs::remove_dir_all(dir);
}

/// A cached create height is not spendable once the fence drops that fk.
/// The maturity short-circuit must not run on a height the best chain no
/// longer has: a disconnect between the parent memo and this check is
/// `bad-txns-inputs-missingorspent`.
#[test]
fn coinbase_spend_rejects_cached_height_after_disconnect() {
    let (dir, hub) = tmp_hub();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, op_true, vec![]).unwrap();
    let fk = hub.query.block_tx_fks(Height(1)).unwrap()[0];
    let created_h = hub.query.store().tx_height_get(fk).unwrap().unwrap();
    assert_eq!(created_h, 1);
    hub.invalidate_block(hub.tip_hash().unwrap()).unwrap();
    assert_eq!(
        hub.query.store().tx_height_get(fk).unwrap(),
        None,
        "invalidate drops the create off the fence"
    );
    let err = coinbase_spend_is_immature(
        hub.query.as_ref(),
        fk,
        created_h,
        created_h.saturating_add(100),
        100,
    )
    .expect_err("a disconnected create is not a mature input");
    assert_eq!(err, "bad-txns-inputs-missingorspent");
    let _ = std::fs::remove_dir_all(dir);
}

/// One regtest node at height 101 checking block proposals, the Core
/// `TestBlockValidity` path behind `getblocktemplate` proposal mode.
/// Regtest coinbase maturity is 100, so a mature spend needs a 101-block
/// chain and no smaller N reaches one; that one boot is what runs this
/// test past the two-second budget, and it serves every beat. The
/// tip-child, coinbase-amount, immature-coinbase, and mature-spend beats
/// do not observe each other; they ride this hub rather than a shared
/// fixture because they only read the 101-block tip the mutating beats
/// then build on (the parent mined at 102, its child confirmed at 103,
/// that block invalidated), so a second setup would add store copies and
/// test names without a new observation.
/// A tip child passes; a block on any other
/// parent is `inconclusive-not-best-prevblk`. Core prices the coinbase
/// in ConnectBlock, after CheckBlock: a coinbase over subsidy + fees is
/// `bad-cb-amount` once the structure checks pass, and a structure
/// reject on the same block still wins. An immature coinbase is not a
/// fee source: spending this block's coinbase, or one still inside the
/// maturity window, is `bad-txns-premature-spend-of-coinbase` before
/// fees are summed, even when that spend would cover an overpaying
/// coinbase. `Ok` carries the block fees, so a template provider can
/// price the coinbase at exactly subsidy + fees. A fan-out parent is
/// decoded once per check, not once per child
/// (`TxTable::sample_reset_body_decodes`); output `i` carries a distinct
/// value so the fee total also pins vout indexing. Spentness is probed
/// per input: with vout 0 confirmed spent, a proposal whose first sight
/// of the parent is the unspent vout 1 still rejects a fresh spend of
/// vout 0 (a fresh tx, so Core's answer is the same reject and not
/// `bad-txns-BIP30`).
/// Parents resolve on the connected chain only: after the block that
/// confirmed `child(0)` is invalidated, a spend of its output is
/// `bad-txns-inputs-missingorspent` and the stale row is not decoded.
#[test]
fn check_block_proposal_prices_fees_and_rejects_on_one_chain() {
    let (dir, hub) = tmp_hub();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(101, op_true.clone(), vec![])
        .unwrap();

    let block = hub
        .assemble_block_to_script(op_true.clone(), vec![])
        .unwrap();
    assert_eq!(
        hub.check_block_proposal(&block),
        Ok(0),
        "no fees in a coinbase-only block"
    );
    let mut off_tip = block.clone();
    off_tip.header.prev_blockhash = BlockHash::from_byte_array([0xab; 32]);
    assert_eq!(
        hub.check_block_proposal(&off_tip).unwrap_err(),
        "inconclusive-not-best-prevblk"
    );

    let mut fat_cb = block;
    let cb = &mut fat_cb.txdata[0].output[0].value;
    *cb = Amount::from_sat(cb.to_sat() + 1);
    let root_for_fat_cb = fat_cb.compute_merkle_root().unwrap();
    assert_eq!(
        hub.check_block_proposal(&fat_cb).unwrap_err(),
        "bad-txnmrklroot",
        "structure checks run before the coinbase is priced"
    );
    fat_cb.header.merkle_root = root_for_fat_cb;
    assert_eq!(
        hub.check_block_proposal(&fat_cb).unwrap_err(),
        "bad-cb-amount"
    );

    let cb_txid = fat_cb.txdata[0].compute_txid();
    fat_cb.txdata.push(spend_out(cb_txid, 0));
    assert_eq!(
        hub.check_block_proposal(&fat_cb).unwrap_err(),
        "bad-txnmrklroot",
        "structure checks run before the immature spend"
    );
    fat_cb.header.merkle_root = fat_cb.compute_merkle_root().unwrap();
    assert_eq!(
        hub.check_block_proposal(&fat_cb).unwrap_err(),
        "bad-txns-premature-spend-of-coinbase",
        "a same-block coinbase spend must not inflate fees"
    );
    let tip_cb = hub
        .query
        .reconstruct_block_at_height(Height(101))
        .unwrap()
        .txdata[0]
        .clone();
    let tip_cb_value = tip_cb.output[0].value.to_sat();
    let immature = spend_out(tip_cb.compute_txid(), tip_cb_value - 1_000);
    let block = hub
        .assemble_block_to_script(op_true.clone(), vec![immature])
        .unwrap();
    assert_eq!(
        hub.check_block_proposal(&block).unwrap_err(),
        "bad-txns-premature-spend-of-coinbase"
    );
    let over = spend_out(tip_cb.compute_txid(), tip_cb_value + 1);
    let block = hub
        .assemble_block_to_script(op_true.clone(), vec![over])
        .unwrap();
    assert_eq!(
        hub.check_block_proposal(&block).unwrap_err(),
        "bad-txns-premature-spend-of-coinbase",
        "maturity is reported before bad-txns-in-belowout"
    );

    let spend = mature_spend_tx(&hub, 1);
    let mut block = hub
        .assemble_block_to_script(op_true.clone(), vec![spend])
        .unwrap();
    assert_eq!(hub.check_block_proposal(&block), Ok(10_000));
    let subsidy = rbitcoin_consensus::block_subsidy(102, &hub.params) as u64;
    block.txdata[0].output[0].value = Amount::from_sat(subsidy + 10_000);
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    assert_eq!(hub.check_block_proposal(&block), Ok(10_000));

    let payout = 98_000_000u64;
    let parent_value = |vout: u32| payout + 1_000 * u64::from(vout + 1);
    let mut parent = mature_spend_tx(&hub, 1);
    parent.output = (0..50)
        .map(|vout| TxOut {
            value: Amount::from_sat(parent_value(vout)),
            script_pubkey: op_true.clone(),
        })
        .collect();
    let parent_txid = parent.compute_txid();
    hub.generate_to_script(1, op_true.clone(), vec![parent])
        .unwrap();
    let child_paying = |vout: u32, value: u64| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: op_true.clone(),
        }],
    };
    let child = |vout: u32| child_paying(vout, payout);
    let block = hub
        .assemble_block_to_script(op_true.clone(), (0..50).map(child).collect())
        .unwrap();
    let fees: u64 = (0..50).map(|vout| parent_value(vout) - payout).sum();
    let store = hub.query.store();
    let _ = store.txs.sample_reset_body_decodes();
    assert_eq!(hub.check_block_proposal(&block), Ok(fees));
    assert_eq!(
        store.txs.sample_reset_body_decodes(),
        1,
        "one packed body decode per distinct parent; the spentness probes and the fk resolve decode nothing"
    );

    hub.generate_to_script(1, op_true.clone(), vec![child(0)])
        .unwrap();
    let respend = child_paying(0, payout - 1_000);
    let block = hub
        .assemble_block_to_script(op_true.clone(), vec![child(1), respend])
        .unwrap();
    let _ = store.txs.sample_reset_body_decodes();
    assert_eq!(
        hub.check_block_proposal(&block).unwrap_err(),
        "bad-txns-inputs-missingorspent",
        "spentness is probed per input; the parent seen first through unspent vout 1 does not vouch for vout 0"
    );
    assert_eq!(store.txs.sample_reset_body_decodes(), 1);

    let stale = hub.tip_hash().unwrap();
    hub.invalidate_block(stale).unwrap();
    assert_eq!(hub.tip_height(), Some(102));
    let grandchild = spend_out(child(0).compute_txid(), payout - 1_000);
    let block = hub
        .assemble_block_to_script(op_true, vec![grandchild])
        .unwrap();
    let _ = store.txs.sample_reset_body_decodes();
    assert_eq!(
        hub.check_block_proposal(&block).unwrap_err(),
        "bad-txns-inputs-missingorspent",
        "an output that exists only in a reorged-out block is not spendable"
    );
    assert_eq!(
        store.txs.sample_reset_body_decodes(),
        0,
        "a row with no fence height is not decoded"
    );
    let _ = std::fs::remove_dir_all(dir);
}

fn trust_log_text() -> String {
    rbitcoin_log::take_logs()
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn spend_coinbase(txid: bitcoin::Txid, sats: u64, spk: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: spk,
        }],
    }
}

/// A side block whose parent header read is cancelled is not `BLOCK_FAILED`.
#[test]
fn cancelled_header_read_on_a_side_block_is_not_cached_invalid() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine(gen, 1_300_050_000, 1);
    hub.accept_block(b1.clone()).unwrap();
    let side = mine_distinct(gen, 1_300_050_001, 1, &[b1.block_hash()]);
    hub.query.fail_next_header_read_cancelled();
    let err = hub
        .accept_received_block(side.clone())
        .expect_err("a cancelled header read is not an accept");
    assert!(
        err.is_local_fault(),
        "cancel must stay a store/engine result, got {err}"
    );
    assert!(
        !hub.is_block_invalid(&side.block_hash()),
        "a cancelled header read must not be BLOCK_FAILED, err={err}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn store_fault_during_header_check_is_not_a_failed_block() {
    let hash = [0x11; 32];
    let store = connect_failed_for_header(hash, NetError::Store("budget full: SQ".into()));
    assert!(
        matches!(store, NetError::Store(_)),
        "a store fault must not name a block, got {store}"
    );
    let bad = connect_failed_for_header(hash, NetError::Consensus("bad-diffbits".into()));
    match bad {
        NetError::ConnectFailed { hash: h, msg, .. } => {
            assert_eq!(h, hash);
            assert!(msg.contains("bad-diffbits"), "{msg}");
        }
        other => panic!("consensus header failure must name the block, got {other}"),
    }
}

/// A proposal reads its medians from confirmed headers, as connect does.
/// With blocks 600 s apart, a coin's time is the median of the block
/// before the one that created it: 118 intervals pass and 119 do not,
/// and 118 would fail on the creating block's own median. A median the
/// store cannot read is that store error. The tip median does not fall
/// back to the tip's own time, and a coin median is not
/// `bad-txns-nonfinal`.
#[test]
fn check_block_proposal_reads_medians_from_confirmed_headers() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let t0 = hub.tip_header().unwrap().time;
    let mut tip = hub.tip_hash().unwrap();
    for h in 1..=112u32 {
        let b = mine(tip, t0 + 600 * h, h);
        tip = b.block_hash();
        hub.accept_block(b).unwrap();
    }
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let time_locked = |intervals: u16| {
        let mut tx = mature_spend_tx(&hub, 12);
        tx.input[0].sequence = Sequence::from_512_second_intervals(intervals);
        hub.assemble_block_to_script(op_true.clone(), vec![tx])
            .unwrap()
    };
    let met = time_locked(118);
    assert_eq!(hub.check_block_proposal(&met), Ok(10_000));
    assert_eq!(
        hub.check_block_proposal(&time_locked(119)).unwrap_err(),
        "bad-txns-nonfinal"
    );
    let empty = hub
        .assemble_block_to_script(op_true.clone(), vec![])
        .unwrap();

    let missing = "missing confirmed header";
    let confirmed = &hub.query.store().confirmed;
    confirmed
        .set_raw_for_test(&rbitcoin_store::ClassCWrite::for_test(), Height(11), 0)
        .unwrap();
    let err = hub.check_block_proposal(&met).unwrap_err();
    assert!(err.contains(missing), "coin median: {err}");
    assert_eq!(hub.check_block_proposal(&empty), Ok(0));
    confirmed
        .set_raw_for_test(&rbitcoin_store::ClassCWrite::for_test(), Height(110), 0)
        .unwrap();
    hub.query.store().rebuild_height_fence().unwrap();
    let err = hub.check_block_proposal(&empty).unwrap_err();
    assert!(err.contains(missing), "tip median: {err}");
    let _ = std::fs::remove_dir_all(dir);
}

/// Witness sigops are not in the structure walk. Nine P2WSH inputs of
/// 10_000 `OP_CHECKSIG` each are over the 80_000 block limit.
#[test]
fn check_block_proposal_rejects_witness_sigops_over_the_limit() {
    let (dir, hub) = tmp_hub();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(101, op_true.clone(), vec![])
        .unwrap();
    let ws = ScriptBuf::from_bytes(vec![0xac; 10_000]);
    let p2wsh = ScriptBuf::new_p2wsh(&ws.wscript_hash());
    let cb = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap()
        .txdata[0]
        .compute_txid();
    let per = (50_0000_0000u64 - 1_000) / 9;
    let fan = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: (0..9)
            .map(|_| TxOut {
                value: Amount::from_sat(per),
                script_pubkey: p2wsh.clone(),
            })
            .collect(),
    };
    let fan_id = fan.compute_txid();
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: (0..9u32)
            .map(|vout| TxIn {
                previous_output: OutPoint { txid: fan_id, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[ws.as_bytes()]),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(per * 9 - 1_000),
            script_pubkey: op_true.clone(),
        }],
    };
    let block = hub
        .assemble_block_to_script(op_true, vec![fan, spend])
        .unwrap();
    assert_eq!(
        hub.check_block_proposal(&block).unwrap_err(),
        "bad-blk-sigops"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `HaveInputs` drops a leading `OP_RETURN` and a script longer than
/// 10_000 bytes before fee math. A 10_000-byte non-`OP_RETURN` script is
/// still a coin. Creating the output and not spending it connects.
#[test]
fn proposal_spend_of_an_unspendable_output_is_missing() {
    fn spendable_10k() -> Vec<u8> {
        let mut script = Vec::with_capacity(10_000);
        let chunk = [0x11u8; 520];
        for _ in 0..19 {
            script.push(0x4d);
            script.extend_from_slice(&520u16.to_le_bytes());
            script.extend_from_slice(&chunk);
        }
        script.push(0x4c);
        script.push(61);
        script.extend_from_slice(&[0x11u8; 61]);
        script
    }
    fn one_sat(txid: bitcoin::Txid, vout: u32, script: Vec<u8>) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(script),
            }],
        }
    }

    let (dir, hub) = tmp_hub();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(101, op_true.clone(), vec![])
        .unwrap();
    let mut op_return = one_sat(
        mature_spend_tx(&hub, 1).input[0].previous_output.txid,
        0,
        vec![0x6a],
    );
    // The coinbase pays 50 BTC. One sat in the output leaves the rest unclaimed.
    op_return.input = mature_spend_tx(&hub, 1).input;
    let mut oversize_script = spendable_10k();
    oversize_script.push(0x00);
    let mut oversize = one_sat(
        mature_spend_tx(&hub, 2).input[0].previous_output.txid,
        0,
        oversize_script,
    );
    oversize.input = mature_spend_tx(&hub, 2).input;
    let mut coin = one_sat(
        mature_spend_tx(&hub, 3).input[0].previous_output.txid,
        0,
        spendable_10k(),
    );
    coin.input = mature_spend_tx(&hub, 3).input;
    hub.generate_to_script(1, op_true.clone(), vec![op_return.clone()])
        .expect("an unspent OP_RETURN output still connects");
    hub.generate_to_script(1, op_true.clone(), vec![oversize.clone()])
        .unwrap();
    hub.generate_to_script(1, op_true.clone(), vec![coin.clone()])
        .unwrap();

    let missing = |tx: Transaction| {
        let block = hub
            .assemble_block_to_script(op_true.clone(), vec![tx])
            .unwrap();
        assert_eq!(
            hub.check_block_proposal(&block).unwrap_err(),
            "bad-txns-inputs-missingorspent"
        );
    };
    missing(one_sat(op_return.compute_txid(), 0, vec![0x51]));
    missing(one_sat(oversize.compute_txid(), 0, vec![0x51]));
    let block = hub
        .assemble_block_to_script(
            op_true.clone(),
            vec![one_sat(coin.compute_txid(), 0, vec![0x51])],
        )
        .unwrap();
    assert_eq!(hub.check_block_proposal(&block), Ok(0));

    let parent = one_sat(
        mature_spend_tx(&hub, 4).input[0].previous_output.txid,
        0,
        vec![0x6a],
    );
    let child = one_sat(parent.compute_txid(), 0, vec![0x51]);
    let block = hub
        .assemble_block_to_script(op_true.clone(), vec![parent, child])
        .unwrap();
    assert_eq!(
        hub.check_block_proposal(&block).unwrap_err(),
        "bad-txns-inputs-missingorspent"
    );
    let _ = std::fs::remove_dir_all(dir);
}

fn spend_out(txid: bitcoin::Txid, value: u64) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
fn reconsider_skips_a_branch_that_fails() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = hub.tip_header().unwrap().time;
    let mut a = Vec::new();
    let mut prev = gen;
    for h in 1..=4u32 {
        let b = mine(prev, t0 + h, h);
        prev = b.block_hash();
        a.push(prev);
        hub.accept_block(b).unwrap();
    }
    let mut bad = mine(a[0], t0 + 20, 2);
    let cb = &mut bad.txdata[0].output[0].value;
    *cb = Amount::from_sat(cb.to_sat() + 1);
    bad.header.merkle_root = bad.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut bad.header);
    let bad_hash = bad.block_hash();
    let b3 = mine(bad_hash, t0 + 21, 3);
    let b4 = mine(b3.block_hash(), t0 + 22, 4);
    for b in [bad, b3, b4] {
        let _ = hub.accept_received_block(b);
    }
    assert_eq!(hub.tip_hash(), Some(a[3]));
    let _ = hub.invalidate_block(a[1]);
    assert_eq!(hub.tip_hash(), Some(a[0]));
    hub.reconsider_block(a[1]).unwrap();
    assert_eq!(hub.tip_hash(), Some(a[3]));
    assert!(hub.is_block_invalid(&bad_hash));

    // A held child of a4 whose time is below the median fails its header
    // check. That is not a mark, and a4 under it still connects.
    hub.invalidate_block(a[3]).unwrap();
    assert_eq!(hub.tip_hash(), Some(a[2]));
    let late = mine(a[3], t0, 5);
    let _ = hub.accept_received_block(late);
    hub.reconsider_block(a[3]).unwrap();
    assert_eq!(hub.tip_hash(), Some(a[3]));

    // A tip child that failed connect keeps its archived body. It was
    // never connected, so reconsider does not make it a valid fork.
    let mut bad5 = mine(a[3], t0 + 30, 5);
    let cb = &mut bad5.txdata[0].output[0].value;
    *cb = Amount::from_sat(cb.to_sat() + 1);
    bad5.header.merkle_root = bad5.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut bad5.header);
    let bad5_hash = bad5.block_hash();
    assert!(hub.accept_received_block(bad5).is_err());
    let marks = dir.path().join("block.invalid");
    let kept = |marks: &std::path::Path| {
        std::fs::read(marks)
            .unwrap()
            .windows(32)
            .any(|w| w == bad5_hash.as_byte_array())
    };
    assert!(kept(&marks), "a connect failure is kept across restart");
    let a5 = mine_distinct(a[3], t0 + 31, 5, &[bad5_hash]);
    let a6 = mine(a5.block_hash(), t0 + 32, 6);
    hub.accept_block(a5).unwrap();
    hub.accept_block(a6).unwrap();
    hub.invalidate_block(bad5_hash).unwrap();
    hub.reconsider_block(bad5_hash).unwrap();
    assert!(!kept(&marks), "reconsiderblock forgets the kept failure");
    let tip_block = hub
        .block_at_height(hub.tip_height().unwrap())
        .unwrap()
        .unwrap();
    let tip_hash = tip_block.block_hash();
    hub.invalidate_block(tip_hash).unwrap();
    assert!(hub.accept_received_block(tip_block).is_err());
    assert!(
        !std::fs::read(&marks)
            .unwrap()
            .windows(32)
            .any(|w| w == tip_hash.as_byte_array()),
        "a block refused as already invalidated is not a connect failure"
    );
    hub.reconsider_block(tip_hash).unwrap();
    assert!(
        !hub.fork_tips.read().unwrap().iter().any(|h| h == bad5_hash),
        "a block that never connected is not kept as a fork tip"
    );

    // Last, because it truncates the store: a fault reading chain work
    // while ranking is an error. Its invalidate path is gone, so the
    // restored tip is still kept as a fork tip to return to.
    let tip = hub.tip_hash().unwrap();
    let tip_body = hub
        .block_at_height(hub.tip_height().unwrap())
        .unwrap()
        .unwrap();
    hub.invalidate_block(tip).unwrap();
    hub.hold_body(Arc::new(tip_body), false);
    hub.chain_work_prefix.write().unwrap().clear();
    let header_body = dir.path().join("header.body");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&header_body)
        .unwrap()
        .set_len(16)
        .unwrap();
    let err = hub.reconsider_block(tip).unwrap_err();
    assert!(err.is_local_fault(), "{err}");
    assert!(hub.fork_tips.read().unwrap().iter().any(|h| h == tip));
    let _ = std::fs::remove_dir_all(dir);
}

/// A block that extends the tip, claims difficulty 1, and has no matching
/// proof of work must not connect and must not add that claimed work.
#[test]
fn review_trust_no_pow_block_credits_claimed_work() {
    fn forged_block(hub: &ChainHub) -> bitcoin::Block {
        let op_true = ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(1, op_true.clone(), vec![]).unwrap();
        let mut forged = hub.assemble_block_to_script(op_true, vec![]).unwrap();
        forged.header.bits = bitcoin::CompactTarget::from_consensus(0x1d00_ffff);
        forged.header.merkle_root = forged.compute_merkle_root().unwrap();
        while forged.header.validate_pow(forged.header.target()).is_ok() {
            forged.header.nonce = forged.header.nonce.wrapping_add(1);
        }
        forged
    }
    let (_d_off, off_hub) = tiny_regtest_hub_labeled("review-pow-off");
    let r_off = off_hub.accept_received_block(forged_block(&off_hub));
    assert!(r_off.is_err(), "flag off rejects: {r_off:?}");

    let (_d_on, hub) = tiny_regtest_hub_labeled("review-pow-on");
    let forged = forged_block(&hub);
    let hash = forged.block_hash();
    let before = hub.chain_work().unwrap();
    hub.query.set_trust_peer(true);
    let r = hub.accept_received_block(forged);
    let after = hub.chain_work().unwrap();
    assert!(r.is_err(), "no-PoW block applied: {r:?}");
    assert_eq!(
        after, before,
        "claimed work moved\nbefore {before:?}\nafter {after:?}"
    );
    assert!(
        hub.header_of(&hash).is_none(),
        "high-hash header was stored"
    );
    // `capture_logs` is thread-local. Tip-accept emits the not-applied line
    // on its own thread; the same-thread header and confirm tests pin that text.
    assert!(r.as_ref().err().is_some_and(|e| !e.is_mutated()));
}

/// Local `submitblock` of a heavier side chain stays strict while the mode is
/// on. An equal-work sibling is parked, then a child makes that branch win.
/// The parked body's own bit is what connect reads. The process bit does not.
#[test]
fn review_trust_local_side_subsidy_is_not_applied() {
    let (_dir, hub) = tiny_regtest_hub_labeled("review-local-side");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, op_true, vec![]).unwrap();
    let tip = hub.tip_hash().unwrap();
    let tip_h = hub.tip_height().unwrap();
    let tip_block = hub.block_at_height(tip_h).unwrap().unwrap();
    let sibling = mine_distinct(
        tip_block.header.prev_blockhash,
        tip_block.header.time,
        tip_h,
        &[tip],
    );
    let sibling_hash = sibling.block_hash();
    hub.query.set_trust_peer(true);
    let parked = hub.accept_received_block(sibling).unwrap();
    assert_eq!(parked, AcceptOutcome::IgnoredWeaker);
    assert_eq!(hub.tip_hash(), Some(tip));
    assert!(hub.held_body(&sibling_hash).is_some());
    let mut child = mine(
        sibling_hash,
        tip_block.header.time.saturating_add(1),
        tip_h + 1,
    );
    let bumped = child.txdata[0].output[0].value.to_sat() + 1;
    child.txdata[0].output[0].value = Amount::from_sat(bumped);
    child.header.merkle_root = child.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut child.header);
    assert!(child.header.validate_pow(child.header.target()).is_ok());
    let r = hub.accept_received_block(child);
    assert!(r.is_err(), "local side-chain subsidy applied: {r:?}");
    assert_eq!(
        hub.tip_hash(),
        Some(tip),
        "tip moved onto the local side chain"
    );
    assert_eq!(hub.tip_height(), Some(tip_h));
}

/// The mode is on. A side chain the trusted session held still applies an
/// excess coinbase. The process flag alone does not.
#[test]
fn review_trust_session_side_subsidy_is_applied() {
    let (_dir, hub) = tiny_regtest_hub_labeled("review-session-side");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, op_true, vec![]).unwrap();
    let tip = hub.tip_hash().unwrap();
    let tip_h = hub.tip_height().unwrap();
    let tip_block = hub.block_at_height(tip_h).unwrap().unwrap();
    let sibling = mine_distinct(
        tip_block.header.prev_blockhash,
        tip_block.header.time,
        tip_h,
        &[tip],
    );
    let sibling_hash = sibling.block_hash();
    hub.query.set_trust_peer(true);
    let parked =
        rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(sibling, true))
            .unwrap();
    assert_eq!(parked, AcceptOutcome::IgnoredWeaker);
    assert_eq!(hub.tip_hash(), Some(tip));
    let mut child = mine(
        sibling_hash,
        tip_block.header.time.saturating_add(1),
        tip_h + 1,
    );
    let bumped = child.txdata[0].output[0].value.to_sat() + 1;
    child.txdata[0].output[0].value = Amount::from_sat(bumped);
    child.header.merkle_root = child.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut child.header);
    let r =
        rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(child, true));
    assert!(
        matches!(r, Ok(AcceptOutcome::Accepted { .. })),
        "session side-chain subsidy was not applied: {r:?}"
    );
    assert_eq!(hub.tip_height(), Some(tip_h + 1));
    assert_ne!(hub.tip_hash(), Some(tip));
}

/// A tip that connected under the session bit must come back if a later local
/// branch fails. Restore does not read the process flag.
#[test]
fn review_trust_restore_keeps_a_waived_tip() {
    let (_dir, hub) = tiny_regtest_hub_labeled("review-restore-waive");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, op_true.clone(), vec![]).unwrap();
    let parent_h = hub.tip_height().unwrap();
    let parent = hub.tip_hash().unwrap();
    let mut bad = hub.assemble_block_to_script(op_true, vec![]).unwrap();
    let bumped = bad.txdata[0].output[0].value.to_sat() + 1;
    bad.txdata[0].output[0].value = Amount::from_sat(bumped);
    bad.header.merkle_root = bad.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut bad.header);
    let bad_hash = bad.block_hash();
    hub.query.set_trust_peer(true);
    let applied =
        rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(bad, true))
            .unwrap();
    assert_eq!(
        applied,
        AcceptOutcome::Accepted {
            height: parent_h + 1
        }
    );
    let bad_time = hub.tip_header().unwrap().time;
    let sibling = mine_distinct(parent, bad_time, parent_h + 1, &[bad_hash]);
    let sibling_hash = sibling.block_hash();
    assert_eq!(
        hub.accept_received_block(sibling).unwrap(),
        AcceptOutcome::IgnoredWeaker
    );
    let mut child = mine(sibling_hash, bad_time.saturating_add(1), parent_h + 2);
    let bumped = child.txdata[0].output[0].value.to_sat() + 1;
    child.txdata[0].output[0].value = Amount::from_sat(bumped);
    child.header.merkle_root = child.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut child.header);
    let r = hub.accept_received_block(child);
    assert!(r.is_err(), "local child of a waived tip applied: {r:?}");
    let msg = r.unwrap_err().to_string();
    assert!(
        !msg.contains("tip restore failed"),
        "waived tip tore on restore: {msg}"
    );
    assert_eq!(hub.tip_hash(), Some(bad_hash));
    assert_eq!(hub.tip_height(), Some(parent_h + 1));
}

/// `accept_received_block` is local submit and generate. The process bit does
/// not waive an excess coinbase.
#[test]
fn review_trust_local_excess_subsidy_is_not_applied() {
    let (_dir, hub) = tiny_regtest_hub_labeled("review-local-subsidy");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, op_true.clone(), vec![]).unwrap();
    let mut block = hub.assemble_block_to_script(op_true, vec![]).unwrap();
    let bumped = block.txdata[0].output[0].value.to_sat() + 1;
    block.txdata[0].output[0].value = Amount::from_sat(bumped);
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    for _ in 0..10_000 {
        if block.header.validate_pow(block.header.target()).is_ok() {
            break;
        }
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    assert!(block.header.validate_pow(block.header.target()).is_ok());
    let before = hub.tip_height();
    hub.query.set_trust_peer(true);
    let r = hub.accept_received_block(block);
    assert!(r.is_err(), "local excess subsidy applied: {r:?}");
    assert_eq!(hub.tip_height(), before);
}

fn excess_on(prev: BlockHash, time: u32, height: u32) -> Block {
    let mut block = mine(prev, time, height);
    let bumped = block.txdata[0].output[0].value.to_sat() + 1;
    block.txdata[0].output[0].value = Amount::from_sat(bumped);
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    block
}

/// A local warn-and-apply reject does not stick. The trusted session can
/// still connect that block. A high-hash reject still sticks.
#[test]
fn review_trust_local_reject_does_not_stick() {
    let (_dir, hub) = tiny_regtest_hub_labeled("review-reject-stick");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, op_true.clone(), vec![]).unwrap();
    let before = hub.tip_height();
    let tip = hub.tip_hash().unwrap();
    let tip_block = hub.block_at_height(before.unwrap()).unwrap().unwrap();
    let bad = excess_on(
        tip,
        tip_block.header.time.saturating_add(1),
        before.unwrap() + 1,
    );
    let hash = bad.block_hash();
    hub.query.set_trust_peer(true);
    let r = hub.accept_received_block(bad.clone());
    assert!(r.is_err(), "local excess applied: {r:?}");
    assert_eq!(hub.tip_height(), before);
    assert!(
        !hub.is_block_invalid(&hash),
        "warn-and-apply reject stuck: {r:?}"
    );
    let applied =
        rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(bad, true));
    assert!(
        matches!(applied, Ok(AcceptOutcome::Accepted { .. })),
        "trusted session was blocked: {applied:?}"
    );
    assert_eq!(hub.tip_hash(), Some(hash));

    let mut forged = hub.assemble_block_to_script(op_true, vec![]).unwrap();
    forged.header.bits = CompactTarget::from_consensus(0x1d00_ffff);
    forged.header.merkle_root = forged.compute_merkle_root().unwrap();
    while forged.header.validate_pow(forged.header.target()).is_ok() {
        forged.header.nonce = forged.header.nonce.wrapping_add(1);
    }
    let forged_hash = forged.block_hash();
    let work = hub.chain_work().unwrap();
    let pow = hub.accept_received_block(forged);
    assert!(pow.is_err(), "no-PoW block applied: {pow:?}");
    assert_eq!(hub.chain_work().unwrap(), work);
    assert!(
        hub.is_block_invalid(&forged_hash),
        "high-hash reject did not stick"
    );
}

/// A strict hold is upgraded when the trusted session delivers the same body.
/// Until then a local child cannot connect the excess subsidy.
#[test]
fn review_trust_session_upgrades_held_waive() {
    let (_dir, hub) = tiny_regtest_hub_labeled("review-hold-upgrade");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(2, op_true, vec![]).unwrap();
    let tip = hub.tip_hash().unwrap();
    let tip_h = hub.tip_height().unwrap();
    let genesis = hub.block_at_height(0).unwrap().unwrap();
    let excess = excess_on(
        genesis.block_hash(),
        genesis.header.time.saturating_add(1),
        1,
    );
    let excess_hash = excess.block_hash();
    hub.query.set_trust_peer(true);
    let parked = hub.accept_received_block(excess.clone()).unwrap();
    assert_eq!(parked, AcceptOutcome::IgnoredWeaker);
    assert_eq!(hub.tip_hash(), Some(tip));
    assert!(hub.held_body(&excess_hash).is_some());
    assert!(!hub.is_block_invalid(&excess_hash));

    let child = mine(excess_hash, genesis.header.time.saturating_add(2), 2);
    let child_hash = child.block_hash();
    let local = hub.accept_received_block(child);
    assert!(
        local.is_err() || matches!(local, Ok(AcceptOutcome::IgnoredWeaker)),
        "local child connected the strict hold: {local:?}"
    );
    assert_eq!(hub.tip_hash(), Some(tip));

    rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(excess, true))
        .unwrap();
    let child = mine(excess_hash, genesis.header.time.saturating_add(2), 2);
    let grand = mine(child_hash, genesis.header.time.saturating_add(3), 3);
    let session = rbitcoin_net::tip_accept::run_on_tip_accept(|| {
        let _ = hub.accept_received_on_lane(child, true)?;
        hub.accept_received_on_lane(grand, true)
    });
    assert!(
        matches!(session, Ok(AcceptOutcome::Accepted { .. })),
        "session did not connect the upgraded hold: {session:?}"
    );
    assert_ne!(hub.tip_hash(), Some(tip));
    assert!(hub.tip_height().unwrap() > tip_h);
}

/// Median time on the second block of a reorg is warn-and-apply only for the
/// session that held the branch. A local submit of the same blocks stays put.
#[test]
fn review_trust_reorg_mtp_on_second_block() {
    fn branch(hub: &ChainHub, waive: bool) -> Result<AcceptOutcome, NetError> {
        let tip = hub.tip_hash().unwrap();
        let tip_h = hub.tip_height().unwrap();
        let tip_block = hub.block_at_height(tip_h).unwrap().unwrap();
        let sibling = mine_distinct(
            tip_block.header.prev_blockhash,
            tip_block.header.time,
            tip_h,
            &[tip],
        );
        let sibling_hash = sibling.block_hash();
        let child = mine(sibling_hash, sibling.header.time, tip_h + 1);
        let run = |block: Block| {
            rbitcoin_net::tip_accept::run_on_tip_accept(|| {
                hub.accept_received_on_lane(block, waive)
            })
        };
        let parked = if waive {
            run(sibling).unwrap()
        } else {
            hub.accept_received_block(sibling).unwrap()
        };
        assert_eq!(parked, AcceptOutcome::IgnoredWeaker);
        if waive {
            run(child)
        } else {
            hub.accept_received_block(child)
        }
    }

    let (_dir, local) = tiny_regtest_hub_labeled("review-reorg-mtp-local");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    local
        .generate_to_script(1, op_true.clone(), vec![])
        .unwrap();
    let tip = local.tip_hash().unwrap();
    local.query.set_trust_peer(true);
    rbitcoin_log::capture_logs(false);
    rbitcoin_log::capture_logs(true);
    let local_r = branch(&local, false);
    assert!(local_r.is_err(), "local mtp reorg applied: {local_r:?}");
    assert_eq!(local.tip_hash(), Some(tip));

    let (_dir, session) = tiny_regtest_hub_labeled("review-reorg-mtp-session");
    session.generate_to_script(1, op_true, vec![]).unwrap();
    session.query.set_trust_peer(true);
    let session_tip = session.tip_hash().unwrap();
    let session_r = branch(&session, true);
    assert!(
        matches!(session_r, Ok(AcceptOutcome::Accepted { .. })),
        "session mtp reorg rejected: {session_r:?}"
    );
    assert_ne!(session.tip_hash(), Some(session_tip));
}

/// A local block that spends with a marked mempool tx is rejected. The same
/// block from the trusted session is applied. The template omits that tx.
#[test]
fn review_trust_local_block_rechecks_marked_script() {
    use bitcoin::WPubkeyHash;

    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let (dir, hub) = tiny_regtest_hub_labeled("review-marked-block");
    let wpkh = WPubkeyHash::from_byte_array([0x41; 20]);
    hub.generate_to_script(1, ScriptBuf::new_p2wpkh(&wpkh), vec![])
        .unwrap();
    hub.generate_to_script(101, op_true.clone(), vec![])
        .unwrap();
    let cb = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap()
        .txdata[0]
        .clone();
    let value = cb.output[0].value.to_sat();
    let mut bad = mature_spend_tx(&hub, 1);
    bad.output[0].value = Amount::from_sat(value - 1_000);
    bad.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let bad_id = bad.compute_txid();
    let clean = mature_spend_tx(&hub, 2);
    let clean_id = clean.compute_txid();

    hub.query.set_trust_peer(true);
    let mp = attach_mp(dir.path(), &hub);
    let session = 7u64;
    mp.set_trusted_session(Some(session));
    mp.accept_tx_from(&bad, Some(session))
        .expect("trusted script admit");
    mp.accept_tx(&clean).expect("clean spend");
    assert!(mp.lock_read().trust_kept.contains(&bad_id));

    let (_, skip) = mp.tip_script_pres(&[bad.clone(), clean.clone()]);
    assert!(
        !skip.contains(&bad_id.to_byte_array()),
        "a marked tx was treated as script-checked"
    );
    assert!(skip.contains(&clean_id.to_byte_array()));
    let picked = mp.select_block_template(mp.template_budget(0));
    assert!(picked.iter().any(|(tx, _)| tx.compute_txid() == clean_id));
    assert!(picked.iter().all(|(tx, _)| tx.compute_txid() != bad_id));

    let block = hub.assemble_block_to_script(op_true, vec![bad]).unwrap();
    let hash = block.block_hash();
    let tip = hub.tip_hash();
    let local = hub.accept_received_block(block.clone());
    assert!(local.is_err(), "local block kept a bad script: {local:?}");
    assert_eq!(hub.tip_hash(), tip);
    let applied =
        rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(block, true));
    assert!(
        matches!(applied, Ok(AcceptOutcome::Accepted { .. })),
        "trusted session rejected the block: {applied:?}"
    );
    assert_eq!(hub.tip_hash(), Some(hash));
}

/// A sibling that only fails the median check is held for the trusted
/// session, and a valid child of it can move the tip. A local submit of
/// that sibling is rejected and not held. Bad proof-of-work is not stored.
#[test]
fn review_trust_side_header_mtp_is_held() {
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let (_dir, hub) = tiny_regtest_hub_labeled("review-side-mtp");
    hub.generate_to_script(1, op_true, vec![]).unwrap();
    hub.query.set_trust_peer(true);
    let tip = hub.tip_hash().unwrap();
    let genesis = hub.block_at_height(0).unwrap().unwrap();
    let sibling = mine_distinct(genesis.block_hash(), genesis.header.time, 1, &[tip]);
    let sibling_hash = sibling.block_hash();
    let local = hub.accept_received_block(sibling.clone());
    assert!(local.is_err(), "local median sibling applied: {local:?}");
    assert!(hub.held_body(&sibling_hash).is_none());
    assert_eq!(hub.tip_hash(), Some(tip));

    let parked =
        rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(sibling, true));
    assert!(
        matches!(parked, Ok(AcceptOutcome::IgnoredWeaker)),
        "median sibling was not held: {parked:?}"
    );
    assert!(hub.held_body(&sibling_hash).is_some());
    assert_eq!(hub.tip_hash(), Some(tip));

    let child = mine(sibling_hash, genesis.header.time.saturating_add(1), 2);
    let child_hash = child.block_hash();
    let moved =
        rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(child, true));
    assert!(
        matches!(moved, Ok(AcceptOutcome::Accepted { .. })),
        "valid child did not move the tip: {moved:?}"
    );
    assert_eq!(hub.tip_hash(), Some(child_hash));

    let mut forged = mine(
        genesis.block_hash(),
        genesis.header.time.saturating_add(2),
        1,
    );
    forged.header.bits = CompactTarget::from_consensus(0x1d00_ffff);
    forged.header.merkle_root = forged.compute_merkle_root().unwrap();
    while forged.header.validate_pow(forged.header.target()).is_ok() {
        forged.header.nonce = forged.header.nonce.wrapping_add(1);
    }
    let forged_hash = forged.block_hash();
    let work = hub.chain_work().unwrap();
    let pow =
        rbitcoin_net::tip_accept::run_on_tip_accept(|| hub.accept_received_on_lane(forged, true));
    assert!(pow.is_err(), "no-PoW sibling stored: {pow:?}");
    assert!(hub.held_body(&forged_hash).is_none());
    assert_eq!(hub.chain_work().unwrap(), work);
    assert_eq!(hub.tip_hash(), Some(child_hash));
}

/// A proposal error is the error. The mode does not log it.
///
/// Covers a wrong prev, unexpected nBits (even with an excess coinbase),
/// an excess coinbase, a same-block coinbase spend, and a bad script.
#[test]
fn review_trust_proposal_is_silent() {
    let (dir, hub) = tmp_hub();
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, op_true.clone(), vec![]).unwrap();
    let template = hub
        .assemble_block_to_script(op_true.clone(), vec![])
        .unwrap();
    hub.query.set_trust_peer(true);
    rbitcoin_log::capture_logs(false);

    let mut wrong_prev = template.clone();
    wrong_prev.header.prev_blockhash = BlockHash::from_byte_array([0xab; 32]);
    rbitcoin_log::capture_logs(true);
    assert_eq!(
        hub.check_block_proposal(&wrong_prev).unwrap_err(),
        "inconclusive-not-best-prevblk"
    );
    assert_proposal_silent();

    let mut bits = template.clone();
    bits.header.bits = CompactTarget::from_consensus(0x0100_0000);
    bits.txdata[0].output[0].value = Amount::from_sat(bits.txdata[0].output[0].value.to_sat() + 1);
    bits.header.merkle_root = bits.compute_merkle_root().unwrap();
    hub.query.set_trust_peer(false);
    rbitcoin_log::capture_logs(true);
    assert_eq!(hub.check_block_proposal(&bits).unwrap_err(), "bad-diffbits");
    assert_proposal_silent();
    hub.query.set_trust_peer(true);
    rbitcoin_log::capture_logs(true);
    assert_eq!(hub.check_block_proposal(&bits).unwrap_err(), "bad-diffbits");
    assert_proposal_silent();

    let mut excess = template.clone();
    let bumped = excess.txdata[0].output[0].value.to_sat() + 1;
    excess.txdata[0].output[0].value = Amount::from_sat(bumped);
    excess.header.merkle_root = excess.compute_merkle_root().unwrap();
    rbitcoin_log::capture_logs(true);
    assert_eq!(
        hub.check_block_proposal(&excess).unwrap_err(),
        "bad-cb-amount"
    );
    assert_proposal_silent();

    let mut early = template;
    let cb_txid = early.txdata[0].compute_txid();
    let cb_sats = early.txdata[0].output[0].value.to_sat();
    early
        .txdata
        .push(spend_coinbase(cb_txid, cb_sats, op_true.clone()));
    early.header.merkle_root = early.compute_merkle_root().unwrap();
    rbitcoin_log::capture_logs(true);
    let early_err = hub.check_block_proposal(&early).unwrap_err();
    assert!(
        early_err.contains("premature") || early_err.contains("coinbase"),
        "{early_err}"
    );
    assert_proposal_silent();

    hub.generate_to_script(100, op_true.clone(), vec![])
        .unwrap();
    let mut spend = mature_spend_tx(&hub, 1);
    spend.input[0].script_sig = ScriptBuf::from_bytes(vec![0x6a]);
    let script_block = hub.assemble_block_to_script(op_true, vec![spend]).unwrap();
    rbitcoin_log::capture_logs(true);
    let script_err = hub.check_block_proposal(&script_block).unwrap_err();
    assert!(
        script_err.contains("script") || script_err.contains("block-script-verify"),
        "{script_err}"
    );
    assert_proposal_silent();
    rbitcoin_log::capture_logs(false);
    let _ = std::fs::remove_dir_all(dir);
}

fn assert_proposal_silent() {
    let logs = trust_log_text();
    assert!(!logs.contains("trust-peer:"), "{logs}");
}

/// `submitheader` stays strict while the mode is on. A future timestamp is
/// not stored and is not logged as applied.
#[test]
fn review_trust_submitheader_stays_strict() {
    let (_dir, hub) = tiny_regtest_hub_labeled("review-submitheader");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, op_true.clone(), vec![]).unwrap();
    let mut block = hub.assemble_block_to_script(op_true, vec![]).unwrap();
    block.header.time = block.header.time.saturating_add(3 * 60 * 60);
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    let hash = block.header.block_hash();
    hub.query.set_trust_peer(true);
    rbitcoin_log::capture_logs(false);
    rbitcoin_log::capture_logs(true);
    let r = hub.process_submitted_header(&block.header);
    let logs = trust_log_text();
    assert!(r.is_err(), "future submitheader stored: {r:?}");
    assert!(
        hub.header_of(&hash).is_none(),
        "future header row was stored"
    );
    assert!(
        !logs.contains("trust-peer: applied"),
        "submitheader logged applied:\n{logs}"
    );
}

/// A body that does not match its header is not this block. The hash stays
/// refetchable: it is not marked permanently failed.
#[test]
fn review_trust_merkle_mismatch_stays_refetchable() {
    fn mismatched(hub: &ChainHub) -> bitcoin::Block {
        let op_true = ScriptBuf::from_bytes(vec![0x51]);
        hub.generate_to_script(1, op_true.clone(), vec![]).unwrap();
        let mut block = hub.assemble_block_to_script(op_true, vec![]).unwrap();
        block.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x11; 32]);
        for _ in 0..10_000 {
            block.header.nonce = block.header.nonce.wrapping_add(1);
            if block.header.validate_pow(block.header.target()).is_ok() {
                return block;
            }
        }
        panic!("regtest target accepted no nonce");
    }
    let (_d_on, hub) = tiny_regtest_hub_labeled("review-merkle-on");
    let block = mismatched(&hub);
    let hash = block.block_hash();
    let before = hub.chain_work().unwrap();
    hub.query.set_trust_peer(true);
    let r = hub.accept_received_block(block);
    let after = hub.chain_work().unwrap();
    assert!(r.is_err(), "merkle mismatch applied: {r:?}");
    assert_eq!(after, before, "claimed work moved");
    assert!(
        r.as_ref().err().is_some_and(|e| e.is_mutated()),
        "merkle miss must stay refetchable: {r:?}"
    );
    assert!(
        !hub.is_block_invalid(&hash),
        "hash was marked permanently failed"
    );
}

#[test]
fn connect_finishes_while_the_blocking_pool_is_parked() {
    let (_dir, hub) = tmp_hub();
    let hub = ChainHub::into_arc(hub);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    rt.spawn(async move {
        tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        });
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("pool thread did not park");
    let hub_gen = Arc::clone(&hub);
    let generated = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            hub_gen.generate_to_script_for_rpc_async(
                2,
                ScriptBuf::from_bytes(vec![0x51]),
                Vec::new(),
                false,
            ),
        )
        .await
    });
    let bogus = BlockHash::from_byte_array([0x44; 32]);
    let hub_inv = Arc::clone(&hub);
    let invalidated = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            hub_inv.invalidate_block_async(bogus),
        )
        .await
    });
    let hub_re = Arc::clone(&hub);
    let reconsidered = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            hub_re.reconsider_block_async(bogus),
        )
        .await
    });
    let hub_pr = Arc::clone(&hub);
    let precious = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            hub_pr.precious_block_async(bogus),
        )
        .await
    });
    let _ = release_tx.send(());
    let hashes = generated
        .expect("generate timed out while the blocking pool was parked")
        .expect("generate");
    assert_eq!(hashes.len(), 2, "await between two connects");
    let inv = invalidated
        .expect("invalidate timed out")
        .expect_err("unknown hash");
    assert!(
        inv.to_string().contains("Block not found"),
        "invalidate ran on tip-accept: {inv}"
    );
    let re = reconsidered
        .expect("reconsider timed out")
        .expect_err("unknown hash");
    assert!(
        re.to_string().contains("Block not found"),
        "reconsider ran on tip-accept: {re}"
    );
    let pr = precious
        .expect("precious timed out")
        .expect_err("unknown hash");
    assert!(
        pr.to_string().contains("Block not found"),
        "precious ran on tip-accept: {pr}"
    );
}
