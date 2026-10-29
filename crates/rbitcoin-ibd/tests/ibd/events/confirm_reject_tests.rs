//! Tests for rbitcoin_ibd::ibd::events:: events helpers (peeled from events.rs).
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_ibd::ibd::state::IbdWorkState;

use rbitcoin_ibd::ibd::confirm::{ConfirmRejectClass, RejectParent};

use rbitcoin_ibd::ibd::events::apply_confirm_reject as apply_confirm_reject_class;

use rbitcoin_query::Query;

fn h(n: u8) -> BlockHash {
    let mut b = [0u8; 32];
    b[0] = n;
    BlockHash::from_byte_array(b)
}

fn apply_confirm_reject(
    st: &mut IbdWorkState,
    height: u32,
    hash: BlockHash,
    err: &str,
    query: Option<&Query>,
    hub: Option<&rbitcoin_net::chain::ChainHub>,
) {
    let parent = hub
        .map(|h| RejectParent::from_lookup(h, hash))
        .unwrap_or_default();
    apply_confirm_reject_class(
        st,
        height,
        hash,
        ConfirmRejectClass::from_err_str(err),
        err,
        query,
        hub,
        1,
        None,
        None,
        parent,
    );
}

/// A competing fork's BadPrev frees its height and every later block on
/// that download, even when the stamp was a multi-block wave.
/// `isolate_if_batched` turns that wave into a cascade, which leaves the
/// bodies queued and the heights occupied. A parent that is this path's
/// still-committing block stays a retry, and so does the block above it.
#[test]
fn batched_off_path_bad_prev_frees_the_height() {
    let err = "unexpected previous header";
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("off-path-bad-prev");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let parent = h(0xab);
    let child = h(0xcd);
    let sibling = h(0xef);
    assert_ne!(Some(parent), Some(tip));

    let mut off = IbdWorkState::new(Vec::new(), Some(tip), Some(0));
    off.record_height(child, 30);
    off.record_height(sibling, 31);
    off.ordered.push_back(child);
    off.ordered.push_back(sibling);
    off.ordered_set.insert(child);
    off.ordered_set.insert(sibling);
    off.note_path_prev(child, parent);
    hub.query
        .block_queue_enqueue(30, child.to_byte_array(), 0, b"child")
        .unwrap();
    hub.query
        .block_queue_enqueue(31, sibling.to_byte_array(), 0, b"sibling")
        .unwrap();
    apply_confirm_reject_class(
        &mut off,
        30,
        child,
        ConfirmRejectClass::from_err_str(err),
        err,
        Some(hub.query.as_ref()),
        Some(&hub),
        2,
        None,
        None,
        RejectParent {
            hash: Some(parent),
            unreadable: false,
        },
    );
    assert!(
        !off.height_to_hash.contains_key(&30),
        "off-path BadPrev frees the height"
    );
    assert!(
        !off.height_to_hash.contains_key(&31),
        "off-path BadPrev frees the later block"
    );
    assert!(
        !off.ordered_set.contains(&child),
        "off-path BadPrev leaves the work path"
    );
    assert!(
        !off.ordered_set.contains(&sibling),
        "the later block leaves the work path"
    );
    assert!(
        !off.hash_height.contains_key(&sibling),
        "the later block leaves the height index"
    );
    let queued = hub.query.block_queue_queued_heights();
    assert!(
        !queued.contains(&30) && !queued.contains(&31),
        "off-path BadPrev drops the body queue from that height up: {queued:?}"
    );
    assert!(
        !off.body.is_missing(&child),
        "off-path BadPrev is not fetched again"
    );
    assert!(
        !off.body.is_missing(&sibling),
        "the later block is not fetched again"
    );

    let mut committing = IbdWorkState::new(Vec::new(), Some(tip), Some(0));
    committing.record_height(parent, 29);
    committing.record_height(child, 30);
    committing.record_height(sibling, 31);
    committing.ordered.push_back(sibling);
    committing.ordered_set.insert(sibling);
    committing.note_path_prev(child, parent);
    hub.query
        .block_queue_enqueue(30, child.to_byte_array(), 0, b"child")
        .unwrap();
    hub.query
        .block_queue_enqueue(31, sibling.to_byte_array(), 0, b"sibling")
        .unwrap();
    apply_confirm_reject_class(
        &mut committing,
        30,
        child,
        ConfirmRejectClass::from_err_str(err),
        err,
        Some(hub.query.as_ref()),
        Some(&hub),
        2,
        None,
        None,
        RejectParent {
            hash: Some(parent),
            unreadable: false,
        },
    );
    assert_eq!(
        committing.height_to_hash.get(&30),
        Some(&child),
        "a parent still committing stays a retry"
    );
    assert_eq!(
        committing.height_to_hash.get(&31),
        Some(&sibling),
        "a block above a committing parent stays"
    );
    assert!(
        committing.ordered_set.contains(&sibling),
        "a committing parent does not drop the later block"
    );
    let queued = hub.query.block_queue_queued_heights();
    assert!(
        queued.contains(&30) && queued.contains(&31),
        "a committing parent keeps the body queue: {queued:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// SoftWire/Cascade/EngineFault/ConsensusInvalid/Cancelled class map.
#[test]
fn confirm_reject_class_matches_substring_table() {
    use rbitcoin_consensus::ConsensusError;
    use rbitcoin_store::StoreError;

    let cases: &[(&str, ConfirmRejectClass)] = &[
        (
            "consensus: unexpected previous header",
            ConfirmRejectClass::SoftWire,
        ),
        ("unexpected previous header", ConfirmRejectClass::SoftWire),
        ("consensus: unexpected previous", ConfirmRejectClass::SoftWire),
        (
            "consensus: bad block: merkle root mismatch",
            ConfirmRejectClass::SoftWire,
        ),
        (
            "consensus: bad block: unexpected witness before segwit",
            ConfirmRejectClass::SoftWire,
        ),
        (
            "consensus: bad block: block weight too large",
            ConfirmRejectClass::ConsensusInvalid,
        ),
        (
            "consensus: bad header: missing retarget first header",
            ConfirmRejectClass::SoftWire,
        ),
        (
            "consensus: script verification failed: script false",
            ConfirmRejectClass::ConsensusInvalid,
        ),
        (
            "consensus: store: corrupt record: invariant: spend annotate missing pin denserels/abs",
            ConfirmRejectClass::EngineFault,
        ),
        (
            "consensus: store: corrupt record: archive: parent create_fk unresolved (contiguous batch required)",
            ConfirmRejectClass::EngineFault,
        ),
        (
            "invariant: create.loc hole after count",
            ConfirmRejectClass::EngineFault,
        ),
        (
            "consensus: store: corrupt record: tx put_full_batch fk mismatch (plan not committed in order)",
            ConfirmRejectClass::Cascade,
        ),
        (
            "consensus: prevout already spent on best chain",
            ConfirmRejectClass::ConsensusInvalid,
        ),
        (
            "connect height not tip+1",
            ConfirmRejectClass::Cascade,
        ),
        ("confirm cancelled", ConfirmRejectClass::Cancelled),
        (
            "consensus: bad header: timestamp too far in future",
            ConfirmRejectClass::Cascade,
        ),
    ];
    for (s, want) in cases {
        assert_eq!(ConfirmRejectClass::from_err_str(s), *want, "{s}");
    }
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::BadPrev),
        ConfirmRejectClass::SoftWire
    );
    // Core BLOCK_MUTATED: the body, not the hash, is at fault.
    for mutated in [
        "merkle root mismatch",
        "bad-txns-duplicate",
        "merkle mutated by a 64-byte tx",
        "missing witness commitment",
        "witness commitment mismatch",
        "bad-witness-nonce-size",
        "unexpected witness before segwit",
    ] {
        assert_eq!(
            ConfirmRejectClass::from_consensus(&ConsensusError::BadBlock(mutated)),
            ConfirmRejectClass::SoftWire,
            "{mutated}"
        );
    }
    // Past the merkle check the header commits to these txs.
    for invalid in [
        "duplicate txid",
        "coinbase not first",
        "block weight too large",
    ] {
        assert_eq!(
            ConfirmRejectClass::from_consensus(&ConsensusError::BadBlock(invalid)),
            ConfirmRejectClass::ConsensusInvalid,
            "{invalid}"
        );
    }
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::BadHeader(
            "missing retarget first header"
        )),
        ConfirmRejectClass::SoftWire
    );
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::Cancelled),
        ConfirmRejectClass::Cancelled
    );
    // Core BLOCK_TIME_FUTURE: the block may connect once the clock passes it.
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::BadHeader(
            "timestamp too far in future"
        )),
        ConfirmRejectClass::Cascade
    );
    assert_eq!(
        ConfirmRejectClass::from_confirm(&rbitcoin_query::ConfirmError::from(
            StoreError::Cancelled("stop"),
        )),
        ConfirmRejectClass::Cancelled
    );
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::PrevoutSpent),
        ConfirmRejectClass::ConsensusInvalid
    );
    assert_eq!(
        ConfirmRejectClass::from_confirm(&rbitcoin_query::ConfirmError::Store(
            StoreError::Corrupt("tx put_full_batch fk mismatch (plan not committed in order)")
        )),
        ConfirmRejectClass::Cascade
    );
    assert_eq!(
        ConfirmRejectClass::from_confirm(&rbitcoin_query::ConfirmError::Store(
            StoreError::Corrupt("invariant: spend annotate missing pin denserels/abs")
        )),
        ConfirmRejectClass::EngineFault
    );
    assert_eq!(
        ConfirmRejectClass::from_confirm(&rbitcoin_query::ConfirmError::Store(
            StoreError::Corrupt("invariant: io_uring undrained")
        )),
        ConfirmRejectClass::EngineFault
    );
    assert_eq!(
        ConfirmRejectClass::from_err_str("invariant: io_uring undrained"),
        ConfirmRejectClass::EngineFault
    );
    assert_eq!(
        ConfirmRejectClass::from_err_str("invariant: io_uring leftover cqe"),
        ConfirmRejectClass::EngineFault
    );
    assert_eq!(
        ConfirmRejectClass::from_err_str("io_uring submit failed"),
        ConfirmRejectClass::EngineFault
    );
    assert_eq!(
        ConfirmRejectClass::from_err_str("invariant: io_uring held pread failed"),
        ConfirmRejectClass::EngineFault
    );
    assert_eq!(
        ConfirmRejectClass::from_err_str("invariant: held pread failed"),
        ConfirmRejectClass::Cascade
    );
}

/// All-zero is not a sentinel ignore. With no hub the typed class applies,
/// the same as any other hash.
#[test]
fn zero_hash_confirm_reject_follows_its_class() {
    let mut st = IbdWorkState::new(Vec::new(), None, Some(4));
    let zero = BlockHash::all_zeros();
    apply_confirm_reject(
        &mut st,
        5,
        zero,
        "consensus: prevout already spent on best chain",
        None,
        None,
    );
    assert!(st.body.is_rejected(&zero));
    assert!(st.reorg.invalid.contains(zero.to_byte_array()));
}

/// A consensus class against a hash with no header row is an engine fault.
/// It is not blacklisted.
#[test]
fn missing_header_consensus_reject_is_not_blacklisted() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("missing-header-reject");
    hub.ensure_genesis().unwrap();
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let hash = h(0x11);
    apply_confirm_reject(
        &mut st,
        1,
        hash,
        "consensus: prevout already spent on best chain",
        Some(hub.query.as_ref()),
        Some(&hub),
    );
    assert!(!st.body.is_rejected(&hash));
    assert!(!st.reorg.invalid.contains(hash.to_byte_array()));
    assert!(st.engine_fault_seen.contains(&hash));
    assert!(st.halt.is_none());
    let _ = std::fs::remove_dir_all(dir);
}

/// BadPrev on the block that spends the current tip is a missing parent
/// slot, not a fork. The same hash stays on the path and densify walks
/// back to it. Dropping it leaves `asked` empty until the pump deadline.
#[test]
fn bad_prev_on_the_tip_child_is_fetched_again() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("bad-prev-tip-child");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let t = hub.tip_height().unwrap();
    let hash = h(0x44);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(t));
    st.record_height(hash, t + 1);
    st.note_path_prev(hash, tip);
    st.densify_scan_lo = t + 5;
    st.densify_ready_through = t + 5;
    st.body.mark_archived(hash);
    apply_confirm_reject(
        &mut st,
        t + 1,
        hash,
        "consensus: unexpected previous header",
        Some(hub.query.as_ref()),
        Some(&hub),
    );
    assert_eq!(st.height_to_hash.get(&(t + 1)), Some(&hash));
    assert!(st.body.is_missing(&hash));
    assert!(
        !st.body.is_known_archived(&hash),
        "a soft reject drops the hash from known"
    );
    assert!(
        st.densify_scan_lo <= t + 1,
        "scan_lo={}",
        st.densify_scan_lo
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Load can stamp tip+2 while tip+1 is still committing, and its BadPrev
/// can reach IBD before tip+1's `Accepted`. The parent is this path's own
/// block at the height below, so it is not a fork: the hash is fetched
/// again. Dropping it left `asked` empty. The tip does not move during the
/// race, so repeats do not take the tip-child strikes and cannot halt IBD.
#[test]
fn bad_prev_racing_its_parents_commit_is_fetched_again() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("bad-prev-parent-commit");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let t = hub.tip_height().unwrap();
    let (parent, hash) = (h(0x45), h(0x46));
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(t));
    st.record_height(parent, t + 1);
    st.note_path_prev(parent, tip);
    st.record_height(hash, t + 2);
    st.note_path_prev(hash, parent);
    for _ in 0..4 {
        st.densify_scan_lo = t + 5;
        st.densify_ready_through = t + 5;
        apply_confirm_reject(
            &mut st,
            t + 2,
            hash,
            "consensus: unexpected previous header",
            Some(hub.query.as_ref()),
            Some(&hub),
        );
        assert!(st.halt.is_none(), "a committing parent is not a strike");
        assert_eq!(st.height_to_hash.get(&(t + 2)), Some(&hash));
        assert!(st.body.is_missing(&hash));
        assert!(
            st.densify_scan_lo <= t + 2,
            "scan_lo={}",
            st.densify_scan_lo
        );
    }
    assert_eq!(hub.tip_hash(), Some(tip));
    let _ = std::fs::remove_dir_all(dir);
}

/// A tip-child BadPrev that a new body cannot fix stops after three tries.
/// The hash is not fetched again and is not blacklisted.
#[test]
fn tip_child_bad_prev_halts_on_the_third_retry() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("bad-prev-tip-child-halt");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let t = hub.tip_height().unwrap();
    let hash = h(0x45);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(t));
    st.record_height(hash, t + 1);
    st.note_path_prev(hash, tip);
    let err = "consensus: unexpected previous header";
    for _ in 0..3 {
        apply_confirm_reject(
            &mut st,
            t + 1,
            hash,
            err,
            Some(hub.query.as_ref()),
            Some(&hub),
        );
    }
    assert!(
        st.halt
            .as_deref()
            .is_some_and(|s| s.contains("cascade repeated")),
        "halt={:?}",
        st.halt
    );
    assert!(!st.body.is_missing(&hash));
    assert!(!st.body.is_rejected(&hash));
    let _ = std::fs::remove_dir_all(dir);
}

/// Another block's soft reject must not zero the tip-child count.
#[test]
fn tip_child_bad_prev_survives_another_soft_reject() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("bad-prev-tip-child-mixed");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let t = hub.tip_height().unwrap();
    let hash = h(0x47);
    let other = h(0x48);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(t));
    st.record_height(hash, t + 1);
    st.note_path_prev(hash, tip);
    let err = "consensus: unexpected previous header";
    apply_confirm_reject(
        &mut st,
        t + 1,
        hash,
        err,
        Some(hub.query.as_ref()),
        Some(&hub),
    );
    apply_confirm_reject(
        &mut st,
        t + 2,
        other,
        "consensus: bad block: merkle root mismatch",
        Some(hub.query.as_ref()),
        Some(&hub),
    );
    for _ in 0..2 {
        apply_confirm_reject(
            &mut st,
            t + 1,
            hash,
            err,
            Some(hub.query.as_ref()),
            Some(&hub),
        );
    }
    assert!(
        st.halt
            .as_deref()
            .is_some_and(|s| s.contains("cascade repeated")),
        "halt={:?}",
        st.halt
    );
    assert!(!st.body.is_missing(&hash));
    let _ = std::fs::remove_dir_all(dir);
}

/// `body.rejected ⊆ consensus-invalid set` — Cascade / SoftWire / EngineFault
/// / Cancelled never blacklist.
#[test]
fn body_rejected_subset_of_consensus_invalid() {
    let mut st = IbdWorkState::new(Vec::new(), None, Some(10));
    let cases: &[(&str, bool)] = &[
        ("consensus: script verification failed: script false", true),
        ("consensus: prevout already spent on best chain", true),
        ("consensus: pow invalid", true),
        (
            "tx put_full_batch fk mismatch (plan not committed in order)",
            false,
        ),
        ("connect height not tip+1", false),
        ("consensus: bad block: merkle root mismatch", false),
        (
            "consensus: store: corrupt record: invariant: spend annotate missing pin denserels/abs",
            false,
        ),
        ("confirm cancelled", false),
        ("consensus: unexpected previous header", false),
    ];
    for (i, (err, must_reject)) in cases.iter().enumerate() {
        let hash = h(i as u8 + 1);
        apply_confirm_reject(&mut st, 11, hash, err, None, None);
        assert_eq!(
            st.body.is_rejected(&hash),
            *must_reject,
            "rejected({err}) want {must_reject}"
        );
    }
}

/// A coinbase scriptSig swapped under a real header (length outside 2..=100)
/// is a body the header does not commit to: SoftWire re-get, not a
/// blacklisted `bad-cb-length`.
#[test]
fn short_coinbase_under_a_real_header_is_soft_wire() {
    use rbitcoin_consensus::{validate_block_structure, ChainParams, Milestone, ValidationContext};
    let params = ChainParams::regtest();
    let ctx = ValidationContext::at(&params, rbitcoin_primitives::Height(1), Milestone::NONE);
    let honest = mine(h(0), 1, 1, Vec::new());
    validate_block_structure(&honest, &ctx).unwrap();
    let mut swapped = honest.clone();
    swapped.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    assert_eq!(swapped.block_hash(), honest.block_hash());
    let err = validate_block_structure(&swapped, &ctx).unwrap_err();
    assert_eq!(
        ConfirmRejectClass::from_consensus(&err),
        ConfirmRejectClass::SoftWire,
        "{err:?}"
    );
}

/// Multi-hop with all path bodies already loadable → reorg without await.
#[test]
fn multi_hop_bad_prev_applies_when_full_path_bodies_ready() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut,
        Witness,
    };

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("multi-hop-ready");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let coinbase = |height: u32| {
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(0x00);
        }
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    };
    let mine = |prev: BlockHash, time: u32, height: u32| {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = bitcoin::Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(height)],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    };
    let l1 = mine(gen, 1_410_000_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_410_000_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    let mut w1 = mine(gen, 1_410_000_101, 1);
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
    let w2 = mine(w1.block_hash(), 1_410_000_201, 2);
    hub.ensure_header(&w2.header).unwrap();
    let w3 = mine(w2.block_hash(), 1_410_000_301, 3);
    hub.ensure_header(&w3.header).unwrap();
    // Full path bodies available via BQ-by-hash.
    for (ht, b) in [(1u32, &w1), (2, &w2), (3, &w3)] {
        hub.query
            .block_queue_offer(ht, b.block_hash().to_byte_array(), 0, &serialize(b))
            .unwrap();
    }
    let mut st = IbdWorkState::new(Vec::new(), Some(l2.block_hash()), Some(2));
    apply_confirm_reject(
        &mut st,
        3,
        w3.block_hash(),
        "consensus: unexpected previous header",
        Some(hub.query.as_ref()),
        Some(&hub),
    );
    assert_eq!(
        hub.tip_height(),
        Some(0),
        "rewind to LCA, do not accept_branch"
    );
    assert_eq!(st.height_to_hash.get(&1), Some(&w1.block_hash()));
    assert_eq!(st.height_to_hash.get(&3), Some(&w3.block_hash()));

    let _ = std::fs::remove_dir_all(dir);
}

/// Multi-hop fork (log shape): tip already on loser **child**; heavier path
/// needs mid body at fork height, not only wire_prev. BadPrev must densify
/// full LCA path then reorg.
#[test]
fn multi_hop_bad_prev_densifies_full_path_and_reorgs() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut,
        Witness,
    };

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("multi-hop");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let coinbase = |height: u32| {
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(0x00);
        }
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    };
    let mine = |prev: BlockHash, time: u32, height: u32| {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = bitcoin::Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(height)],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    };
    let distinct = |mut b: bitcoin::Block, avoid: BlockHash| {
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
    };

    let l1 = mine(gen, 1_400_000_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_400_000_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(2));
    assert_eq!(hub.tip_hash().unwrap(), l2.block_hash());

    let w1 = distinct(mine(gen, 1_400_000_101, 1), l1.block_hash());
    hub.ensure_header(&w1.header).unwrap();
    let w2 = mine(w1.block_hash(), 1_400_000_201, 2);
    hub.ensure_header(&w2.header).unwrap();
    let w3 = mine(w2.block_hash(), 1_400_000_301, 3);
    hub.ensure_header(&w3.header).unwrap();

    // Only tip+1 body available (W3); mids W1/W2 missing — log shape.
    hub.query
        .block_queue_offer(3, w3.block_hash().to_byte_array(), 0, &serialize(&w3))
        .unwrap();

    let mut st = IbdWorkState::new(Vec::new(), Some(l2.block_hash()), Some(2));
    apply_confirm_reject(
        &mut st,
        3,
        w3.block_hash(),
        "consensus: unexpected previous header",
        Some(hub.query.as_ref()),
        Some(&hub),
    );
    assert_eq!(hub.tip_height(), Some(0), "rewind to LCA");
    assert_eq!(st.height_to_hash.get(&1), Some(&w1.block_hash()));
    assert_eq!(st.height_to_hash.get(&2), Some(&w2.block_hash()));
    assert_eq!(st.height_to_hash.get(&3), Some(&w3.block_hash()));

    assert!(st.reorg.need_getdata().is_empty());
    assert!(
        !st.body.is_missing(&w3.block_hash()),
        "must not mark_missing the winning-path hash"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Wire-path soft budget charged on receive must release on script reject
/// **and** on soft prevout-spent (write emits Reject when has_block is false;
#[test]
fn apply_peer_event_body_and_control_surface() {
    use bitcoin::block::{Header, Version};
    use bitcoin::CompactTarget;
    use rbitcoin_ibd::ibd::events::{
        apply_peer_event, drain_ready_peer_and_body_events, inject_learned_addrs,
    };
    use rbitcoin_ibd::ibd::peer_io::{PeerEvent, PeerSlot};
    use rbitcoin_ibd::ibd::state::InflightReq;
    use rbitcoin_net::seeds::AddrMan;

    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU32, AtomicU64};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn addr(o: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, o)), 18444)
    }
    fn dummy_slot(id: usize, a: SocketAddr) -> PeerSlot {
        let (cmd_tx, _rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        PeerSlot {
            id,
            addr: a,
            net: rbitcoin_net::NetAddr::from_socket(a),
            cmd_tx,
            in_flight: HashSet::new(),
            requested: rbitcoin_ibd::ibd::peer_io::solicit_track().0,
            solicited_bytes: rbitcoin_ibd::ibd::peer_io::solicit_track().1,
            solicited_ms: rbitcoin_ibd::ibd::peer_io::solicit_track().2,
            any_rx_ms: Arc::new(AtomicU64::new(0)),
            getdata_wire: rbitcoin_ibd::ibd::peer_io::GetdataWire::new(),
            peer_height: 10,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            chain: Default::default(),
            alive: true,
            task,
        }
    }
    fn dummy_header(prev: BlockHash, n: u8) -> Header {
        let mut h = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([n; 32]),
            time: 1_300_000_000 + u32::from(n),
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: u32::from(n),
        };
        rbitcoin_consensus::grind_regtest_pow(&mut h);
        h
    }

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ev-apply");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();

    let mut st = IbdWorkState::new(vec![dummy_slot(1, addr(1))], Some(gen), Some(0));
    st.slots[0].in_flight.insert(h(9));
    st.inflight.insert(h(9), InflightReq::new(1));

    let write_next = AtomicU32::new(1);
    let mut book = AddrMan::new();
    let local = addr(99);

    // BlockFramed without known height → missing (re-getdata after height map).
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: h(9),
            payload: vec![0u8; 80],

            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(st.inflight.is_empty());
    assert!(!st.body.is_pending(&h(9)));

    // Class A known (resume seed) without BQ: still accept peer wire into the
    // body queue so claim_ready can become true after tip-hole re-getdata.
    let class_a_hash = h(0xca);
    st.body.mark_archived(class_a_hash);
    st.record_height(class_a_hash, 1);
    st.height_to_hash.insert(1, class_a_hash);
    st.header_fks
        .insert(class_a_hash, rbitcoin_primitives::Fk(1));
    st.slots[0].in_flight.insert(class_a_hash);
    st.inflight.insert(class_a_hash, InflightReq::new(1));
    // Minimal framed payload (header prefix + empty body is enough for offer).
    let mut payload = vec![0u8; 81];
    payload[0..4].copy_from_slice(&1u32.to_le_bytes()); // version-ish
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: class_a_hash,
            payload,

            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(
        st.body.is_pending(&class_a_hash),
        "Class A known must still land in pending after wire offer"
    );
    assert!(
        hub.query.block_queue_has_height(1),
        "Class A known must still enter body queue (claim intake)"
    );

    // Decode fail → missing so re-getdata allowed.
    st.body.mark_pending(h(9));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockDecodeFailed {
            peer: 1,
            hash: h(9),
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(!st.body.is_pending(&h(9)));

    // notfound from the last owner releases both request and pending state.
    let notfound_hash = h(10);
    st.body.mark_pending(notfound_hash);
    st.slots[0].in_flight.insert(notfound_hash);
    st.inflight.insert(notfound_hash, InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::NotFound {
            peer: 1,
            hashes: vec![notfound_hash],
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(!st.body.is_pending(&notfound_hash));
    assert!(st.body.is_missing(&notfound_hash));
    let mut room = 4usize;
    let mut issued = 0u64;
    assert!(
        !rbitcoin_ibd::ibd::assign::issue_one(&mut st, 1, notfound_hash, &mut room, &mut issued),
        "a peer is not asked again for a block it does not have"
    );
    assert!(
        rbitcoin_ibd::ibd::assign::issue_one(&mut st, 1, h(11), &mut room, &mut issued),
        "notfound does not ban the peer"
    );

    // Headers: attach height from tip parent and order.
    let hdr = dummy_header(gen, 1);
    let hash = hdr.block_hash();
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::Headers {
            peer: 1,
            headers: vec![hdr],
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(st.known_headers.contains(&hash));
    assert!(st.ordered_set.contains(&hash) || st.hash_height.contains_key(&hash));
    assert!(
        rbitcoin_ibd::ibd::assign::issue_one(&mut st, 1, notfound_hash, &mut room, &mut issued),
        "a peer that announces again may be asked again"
    );
    assert!(st.slots[0].in_flight.contains(&notfound_hash));

    // Empty headers with lag → keep headers_done false.
    st.max_peer_height = 100;
    st.empty_header_streak = 0;
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::Headers {
            peer: 1,
            headers: vec![],
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(!st.headers_done);

    // NotFound clears peer inflight and reopens the height for densify.
    st.slots[0].in_flight.insert(h(3));
    st.inflight.insert(h(3), InflightReq::new(1));
    st.record_height(h(3), 30);
    st.densify_scan_lo = 50;
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::NotFound {
            peer: 1,
            hashes: vec![h(3)],
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(!st.inflight.contains_key(&h(3)));
    assert_eq!(
        st.densify_scan_lo, 30,
        "notfound hash is below the densify cursor"
    );

    inject_learned_addrs(&mut book, &[], local, 1);
    let routable = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
    inject_learned_addrs(
        &mut book,
        &[
            rbitcoin_net::NetAddr::Ip(addr(2)),
            rbitcoin_net::NetAddr::Ip(routable),
            rbitcoin_net::NetAddr::Ip(local),
            rbitcoin_net::NetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1)),
        ],
        local,
        1,
    );
    assert!(
        book.entry_of(&rbitcoin_net::NetAddr::from_socket(addr(2)))
            .is_none(),
        "gossip drops RFC1918; addpeeraddress still uses add_learned"
    );
    assert!(
        book.entry_of(&rbitcoin_net::NetAddr::from_socket(routable))
            .is_some(),
        "gossip keeps a public address"
    );
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    inject_learned_addrs(&mut book, &[onion], local, 1);
    assert!(
        book.entries().iter().all(|e| e.addr != onion),
        "IBD must not store an onion this process cannot dial"
    );
    book.set_onion_reachable(true);
    inject_learned_addrs(&mut book, &[onion], local, 1);
    assert!(
        book.entries().iter().any(|e| e.addr == onion),
        "IBD addrv2 onion enters the book once SOCKS is configured"
    );

    // Dead releases work and reopens its heights for densify.
    st.slots[0].in_flight.insert(h(4));
    st.inflight.insert(h(4), InflightReq::new(1));
    st.record_height(h(4), 40);
    st.densify_scan_lo = 50;
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::Dead {
            peer: 1,
            reason: "bye".into(),
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(!st.slots[0].alive);
    assert!(!st.inflight.contains_key(&h(4)));
    assert_eq!(
        st.densify_scan_lo, 40,
        "dead peer's hash is below the densify cursor"
    );

    let (body_tx, mut body_rx) = mpsc::unbounded_channel();
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel();
    let stats = rbitcoin_ibd::ibd::status::LoopStats::default();
    let ok = drain_ready_peer_and_body_events(
        &mut st,
        &hub,
        &mut body_rx,
        &mut ctrl_rx,
        &write_next,
        &stats,
        &mut book,
        local,
        None,
    )
    .unwrap();
    assert!(ok);
    drop(body_tx);
    drop(ctrl_tx);

    let _ = std::fs::remove_dir_all(dir);
}

/// Raw BlockFramed → body queue; redelivery keeps one rec; far horizon skipped.
#[test]
fn apply_peer_event_block_framed_bq_horizon_and_headers_done() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::Encodable;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use rbitcoin_ibd::ibd::events::{
        apply_peer_event, drain_ready_peer_and_body_events, inject_learned_addrs,
    };
    use rbitcoin_ibd::ibd::peer_io::{PeerEvent, PeerSlot};
    use rbitcoin_net::seeds::AddrMan;

    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU32, AtomicU64};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn dummy_slot(id: usize) -> PeerSlot {
        let (cmd_tx, _rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        PeerSlot {
            id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18444),
            net: rbitcoin_net::NetAddr::from_socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                18444,
            )),
            cmd_tx,
            in_flight: HashSet::new(),
            requested: rbitcoin_ibd::ibd::peer_io::solicit_track().0,
            solicited_bytes: rbitcoin_ibd::ibd::peer_io::solicit_track().1,
            solicited_ms: rbitcoin_ibd::ibd::peer_io::solicit_track().2,
            any_rx_ms: Arc::new(AtomicU64::new(0)),
            getdata_wire: rbitcoin_ibd::ibd::peer_io::GetdataWire::new(),
            peer_height: 5,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            chain: Default::default(),
            alive: true,
            task,
        }
    }
    fn coinbase(height: u32) -> Transaction {
        let mut ss = if height == 0 {
            vec![0x00]
        } else {
            rbitcoin_consensus::bip34_height_script(height)
        };
        while ss.len() < 2 {
            ss.push(0x00);
        }
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }
    fn shell(prev: BlockHash, height: u32, n: u32) -> Block {
        let header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_000 + n,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: n,
        };
        let mut b = Block {
            header,
            txdata: vec![coinbase(height)],
        };
        b.header.merkle_root = b.compute_merkle_root().unwrap();
        rbitcoin_consensus::grind_regtest_pow(&mut b.header);
        b
    }
    fn ser(b: &Block) -> Vec<u8> {
        let mut v = Vec::new();
        b.consensus_encode(&mut v).unwrap();
        v
    }

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ev-block");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();

    let mut st = IbdWorkState::new(vec![dummy_slot(1)], Some(gen), Some(0));
    let write_next = AtomicU32::new(1);
    let mut book = AddrMan::new();
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1);

    let b1 = shell(gen, 1, 1);
    let h1 = b1.block_hash();
    st.record_height(h1, 1);
    st.header_fks
        .insert(h1, hub.ensure_header_fk(&b1.header).unwrap());
    st.inflight
        .insert(h1, rbitcoin_ibd::ibd::state::InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: h1,
            payload: ser(&b1),

            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(st.body.is_pending(&h1));
    assert!(hub.query.block_queue_has_height(1));

    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: h1,
            payload: ser(&b1),

            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert_eq!(hub.query.block_queue_stats().1, 1);

    let b2 = shell(h1, 2, 2);
    let h2 = b2.block_hash();
    st.record_height(h2, 2);
    st.header_fks
        .insert(h2, hub.ensure_header_fk(&b2.header).unwrap());
    st.inflight
        .insert(h2, rbitcoin_ibd::ibd::state::InflightReq::new(1));
    hub.query.set_lookup_taken_hi(Some(2));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: h2,
            payload: ser(&b2),

            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(
        !st.body.is_pending(&h2),
        "taken height must not mark_pending (zombie re-race)"
    );
    assert!(!hub.query.block_queue_has_height(2));
    hub.query.set_lookup_taken_hi(None);

    let far_h = 1u32 + rbitcoin_ibd::ibd::CONTIG_DENSIFY_AHEAD + 10;
    let far = shell(h1, far_h, far_h);
    let far_hash = far.block_hash();
    st.record_height(far_hash, far_h);
    st.inflight
        .insert(far_hash, rbitcoin_ibd::ibd::state::InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: far_hash,
            payload: ser(&far),

            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(!st.body.is_pending(&far_hash));

    st.max_peer_height = 0;
    st.empty_header_streak = 0;
    st.ordered.clear();
    st.ordered_set.clear();
    st.height_to_hash.clear();
    st.inflight.clear();
    for _ in 0..2 {
        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::Headers {
                peer: 1,
                headers: vec![],
            },
            &write_next,
            &mut book,
            local,
            None,
        );
    }
    assert!(st.headers_done);

    st.headers_done = false;
    st.empty_header_streak = 1;
    st.max_peer_height = 313_000;
    st.ordered.clear();
    st.ordered_set.clear();
    st.height_to_hash.clear();
    st.inflight.clear();
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::Headers {
            peer: 1,
            headers: vec![],
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(
        st.headers_done,
        "empty-EOF latches even when advertised height is far ahead"
    );

    use rbitcoin_ibd::ibd::MAX_PEER_POOL;
    for i in 0..MAX_PEER_POOL {
        book.add(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(11, 0, (i / 256) as u8, (i % 256) as u8)),
            8333,
        ));
    }
    let n0 = book.len();
    inject_learned_addrs(
        &mut book,
        &[rbitcoin_net::NetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            8333,
        ))],
        local,
        1,
    );
    assert_eq!(book.len(), n0);

    let (body_tx, mut body_rx) = mpsc::unbounded_channel();
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel();
    body_tx
        .send(PeerEvent::BlockDecodeFailed {
            peer: 1,
            hash: h(0x88),
        })
        .unwrap();
    ctrl_tx
        .send(PeerEvent::Addrs {
            peer: 1,
            addrs: vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                8333,
            ))],
        })
        .unwrap();
    let stats = rbitcoin_ibd::ibd::status::LoopStats::default();
    drain_ready_peer_and_body_events(
        &mut st,
        &hub,
        &mut body_rx,
        &mut ctrl_rx,
        &write_next,
        &stats,
        &mut book,
        local,
        None,
    )
    .unwrap();
    assert!(
        stats
            .drain_events
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    let _ = std::fs::remove_dir_all(dir);
}
fn coinbase(height: u32) -> bitcoin::Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};
    let mut ss = rbitcoin_consensus::bip34_height_script(height);
    while ss.len() < 2 {
        ss.push(0x00);
    }
    bitcoin::Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// A regtest block at `height` on `prev` holding `txdata` after the coinbase.
fn mine(
    prev: BlockHash,
    time: u32,
    height: u32,
    txdata: Vec<bitcoin::Transaction>,
) -> bitcoin::Block {
    use bitcoin::block::{Header, Version};
    let mut block = bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_000 + time,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: std::iter::once(coinbase(height)).chain(txdata).collect(),
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    block
}

/// One regtest hub through IBD. Headers come in on the work path, confirm
/// rejects arrive in each class, bad-prev forks rewind to the fork point and
/// replant the heavier path, and a heavier fork carries an invalid block in
/// the middle.
#[allow(clippy::cognitive_complexity)] // one chain, many fork and reject arms
#[test]
fn ibd_bad_prev_fork() {
    use super::super::assign::dummy_slot;
    use bitcoin::consensus::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use rbitcoin_ibd::ibd::assign::{assign_work_ordered, AssignDepth};
    use rbitcoin_ibd::ibd::confirm::{ConfirmEvent, ConfirmFeed};
    use rbitcoin_ibd::ibd::events::{
        apply_confirm_events, apply_peer_event, try_apply_exploration,
    };
    use rbitcoin_ibd::ibd::exit::header_lag_behind_peers;
    use rbitcoin_ibd::ibd::path::seed_work_path_from_store;
    use rbitcoin_ibd::ibd::peer_io::PeerEvent;
    use rbitcoin_ibd::ibd::progress::tip_fetch_hole;
    use rbitcoin_ibd::ibd::reorg::maybe_rewind_to_best_work;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use rbitcoin_ibd::ibd::status::LoopStats;
    use rbitcoin_ibd::ibd::IbdConfig;
    use rbitcoin_net::seeds::AddrMan;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU32;
    use std::time::{Duration, Instant};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("bad-prev-fork");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let write_next = AtomicU32::new(1);
    let mut book = AddrMan::new();
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1);
    let q = Some(hub.query.as_ref());
    let bad_prev = "consensus: unexpected previous header";
    let mut serve = |st: &mut IbdWorkState, headers: Vec<bitcoin::block::Header>| {
        apply_peer_event(
            st,
            &hub,
            PeerEvent::Headers { peer: 1, headers },
            &write_next,
            &mut book,
            local,
            None,
        );
    };

    // A peer serves A1. A later sibling B1 does not take its slot: it is
    // known and explored, not on the path. Neither another sibling nor B1's
    // child moves the path horizon.
    let mut st = IbdWorkState::new(vec![dummy_slot(1)], Some(gen), Some(0));
    let a: Vec<bitcoin::Block> = (1..=4u32).fold(Vec::new(), |mut a, ht| {
        let prev = a.last().map_or(gen, |b: &bitcoin::Block| b.block_hash());
        a.push(mine(prev, ht * 10, ht, vec![]));
        a
    });
    let (a1, b1) = (a[0].block_hash(), mine(gen, 11, 1, vec![]));
    serve(&mut st, vec![a[0].header]);
    serve(&mut st, vec![b1.header]);
    assert_eq!(
        st.height_to_hash.get(&1),
        Some(&a1),
        "first header keeps the slot"
    );
    assert!(st.known_headers.contains(&b1.block_hash()));
    assert!(!st.ordered_set.contains(&b1.block_hash()));
    assert!(!st.is_on_path(&b1.block_hash(), 1));
    assert!(st.reorg.explore_need_hashes().contains(&b1.block_hash()));
    let lag = header_lag_behind_peers(&st, 0);
    let horizon = st.max_peer_height;
    serve(&mut st, vec![mine(gen, 12, 1, vec![]).header]);
    assert_eq!(header_lag_behind_peers(&st, 0), lag);
    serve(&mut st, vec![mine(b1.block_hash(), 21, 2, vec![]).header]);
    assert_eq!(
        st.max_peer_height, horizon,
        "an off-path fork does not become the horizon"
    );

    // The path drains at the tip. A1 served again re-enters it, unless its
    // getdata is in flight or its body is pending.
    st.ordered.clear();
    st.ordered_set.clear();
    st.height_to_hash.clear();
    serve(&mut st, vec![a[0].header]);
    assert!(st.ordered_set.contains(&a1) && st.ordered.len() == 1);
    st.ordered.clear();
    st.ordered_set.clear();
    st.inflight.insert(a1, InflightReq::new(1));
    serve(&mut st, vec![a[0].header]);
    assert!(!st.ordered_set.contains(&a1), "inflight hash stays out");
    st.inflight.clear();
    st.body.mark_pending(a1);
    serve(&mut st, vec![a[0].header]);
    assert!(!st.ordered_set.contains(&a1), "pending hash stays out");

    // A2..=A4 are stored once. The same window again adds nothing.
    let before = hub.query.store().header_count();
    let window: Vec<_> = a[1..].iter().map(|b| b.header).collect();
    serve(&mut st, window.clone());
    assert_eq!(hub.query.store().header_count(), before + 3);
    assert!(a[1..]
        .iter()
        .all(|b| st.header_fks.contains_key(&b.block_hash())));
    let fks = st.header_fks.len();
    serve(&mut st, window);
    assert_eq!(st.header_fks.len(), fks);
    assert_eq!(hub.query.store().header_count(), before + 3);

    // IBD restarts. Peer 2 answers A1's getdata with the real header and a
    // tx that does not parse (segwit marker, flag 2). Nothing is queued, A1
    // can be fetched again, and peer 2 is dropped.
    let mut st = IbdWorkState::new(vec![dummy_slot(1), dummy_slot(2)], Some(gen), Some(0));
    let feed = ConfirmFeed::new();
    st.record_height(a1, 1);
    st.header_fks
        .insert(a1, hub.ensure_header_fk(&a[0].header).unwrap());
    let mut junk = serialize(&a[0].header);
    junk.extend_from_slice(&[0x01, 0x01, 0, 0, 0, 0x00, 0x02, 0, 0, 0, 0]);
    st.slots[1].in_flight.insert(a1);
    st.inflight.insert(a1, InflightReq::new(2));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 2,
            hash: a1,
            payload: junk,

            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        Some(&feed),
    );
    assert_eq!(hub.query.block_queue_stats().1, 0, "undecodable wire");
    assert_eq!(feed.size_snap().0, 0);
    assert!(st.inflight.is_empty() && !st.body.is_pending(&a1));
    assert!(!st.body.is_rejected(&a1), "the hash stays fetchable");
    assert!(!st.slots[1].alive, "the sender is dropped");

    // A1's body arrives raw from peer 1 and is redelivered: one body-queue
    // row, one confirm-feed note.
    st.slots[0].in_flight.insert(a1);
    st.inflight.insert(a1, InflightReq::new(1));
    for _ in 0..2 {
        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::BlockFramed {
                peer: 1,
                hash: a1,
                payload: serialize(&a[0]),

                header_fk: None,
            },
            &write_next,
            &mut book,
            local,
            Some(&feed),
        );
        assert!(st.body.is_pending(&a1) && st.inflight.is_empty());
        assert_eq!(hub.query.block_queue_stats().1, 1);
        assert_eq!(feed.size_snap().0, 1);
    }

    // Confirm reports A1 accepted, then another block consensus-invalid.
    st.ordered.push_back(a1);
    st.ordered_set.insert(a1);
    let mut last = Instant::now() - Duration::from_secs(5);
    let mut drain = |st: &mut IbdWorkState, ev: ConfirmEvent| {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(ev).unwrap();
        drop(tx);
        apply_confirm_events(
            st,
            &hub,
            &rx,
            &AtomicU32::new(1),
            &AtomicU32::new(0),
            &mut last,
            None,
        );
    };
    drain(&mut st, ConfirmEvent::Accepted { hash: a1 });
    assert!(!st.ordered_set.contains(&a1) && st.body.is_known_archived(&a1));
    drain(
        &mut st,
        ConfirmEvent::Reject {
            height: 1,
            hash: h(12),
            class: ConfirmRejectClass::ConsensusInvalid,
            err: "consensus: script verification failed: script false".into(),
            batch_len: 1,
            sender: None,

            parent: RejectParent::default(),
        },
    );
    assert!(
        !st.body.is_rejected(&h(12)),
        "a hash with no header row is an engine fault, not a blacklist"
    );
    assert!(st.engine_fault_seen.contains(&h(12)));
    assert!(!st.reorg.invalid.contains(h(12).to_byte_array()));
    assert!(last.elapsed() < Duration::from_secs(1));

    for b in &a {
        hub.accept_block(b.clone()).unwrap();
    }
    for ht in hub.query.block_queue_queued_heights() {
        hub.query.block_queue_dequeue_height(ht).unwrap();
    }
    let t = hub.tip_height().unwrap();
    assert_eq!(t, 4);

    // Rejects at tip+1 by class, without a hub first. A batch-first hash is
    // not blamed for a multi-block consensus failure.
    let fresh = || IbdWorkState::new(Vec::new(), None, Some(t));
    let mut st = fresh();
    apply_confirm_reject_class(
        &mut st,
        t + 1,
        h(7),
        ConfirmRejectClass::ConsensusInvalid,
        "consensus: script verification failed: script false",
        None,
        None,
        8,
        None,
        None,
        RejectParent::default(),
    );
    assert!(!st.body.is_rejected(&h(7)));
    assert!(!st.reorg.invalid.contains(h(7).to_byte_array()));

    // A cascade requeues twice at the same tip, then halts.
    let mut st = fresh();
    for i in 1..=3 {
        apply_confirm_reject(&mut st, t + 1, h(9), "connect height not tip+1", None, None);
        assert_eq!(st.halt.is_some(), i == 3, "cascade {i}");
        assert!(!st.body.is_rejected(&h(9)));
    }

    // Blacklist or not: script failure and a spent prevout are permanent;
    // store invariants are engine faults (halt on the second); fk mismatch
    // requeues; bad wire and a retarget miss re-get.
    let on_path = |n: u8| {
        let mut st = fresh();
        st.body.mark_archived(h(n));
        st.ordered.push_back(h(n));
        st.ordered_set.insert(h(n));
        st
    };
    for (n, err, permanent) in [
        (0x07, "consensus: script verification failed: script false", true),
        (0x29, "consensus: prevout already spent on best chain", true),
        (0x53, "consensus: store: corrupt record: archive: parent create_fk unresolved (contiguous batch required)", false),
        (0x68, "consensus: store: corrupt record: tx put_full_batch fk mismatch (plan not committed in order)", false),
        (0x44, bad_prev, false),
        (0x42, "consensus: bad header: missing retarget first header", false),
    ] {
        let mut st = on_path(n);
        apply_confirm_reject(&mut st, t + 1, h(n), err, None, None);
        assert_eq!(st.body.is_rejected(&h(n)), permanent, "{err}");
        match n {
            0x07 => assert!(!st.ordered_set.contains(&h(n)), "blacklist leaves the path"),
            0x42 => assert!(st.ordered_set.contains(&h(n)), "soft keeps the path"),
            _ => {}
        }
    }
    let mut st = on_path(0x5b);
    let denserels =
        "consensus: store: corrupt record: invariant: spend annotate missing pin denserels/abs";
    apply_confirm_reject(&mut st, t + 1, h(0x5b), denserels, None, None);
    assert!(st.engine_fault_seen.contains(&h(0x5b)) && st.halt.is_none());
    apply_confirm_reject(&mut st, t + 1, h(0x5b), denserels, None, None);
    assert!(st.halt.is_some(), "second engine fault halts IBD");
    assert!(!st.body.is_rejected(&h(0x5b)));

    // With the hub: IBD leaves lookup where it is. The confirm thread
    // re-armed it when it rejected, and lookup may since have taken a body
    // the reject offered back.
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), Some(t));
    st.record_height(h(0x5a), t + 2);
    for err in [
        "consensus: bad block: merkle root mismatch",
        "consensus: store: corrupt record: archive: parent create_fk unresolved (contiguous batch required)",
        "connect height not tip+1",
        "consensus: prevout already spent on best chain",
        "confirm cancelled",
    ] {
        hub.query.set_lookup_taken_hi(Some(t + 2));
        hub.query.set_lookup_started_hi(Some(t + 2));
        apply_confirm_reject(&mut st, t + 2, h(0x5a), err, q, Some(&hub));
        assert_eq!(hub.query.lookup_taken_hi(), Some(t + 2), "{err}");
        assert_eq!(hub.query.lookup_started_hi(), Some(t + 2), "{err}");
    }
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), Some(t));
    st.record_height(h(0x5b), t + 2);
    let feed = ConfirmFeed::new();
    hub.query.set_lookup_taken_hi(Some(t + 2));
    hub.query.set_lookup_started_hi(Some(t + 2));
    apply_confirm_reject_class(
        &mut st,
        t + 2,
        h(0x5b),
        ConfirmRejectClass::EngineFault,
        "invariant: create.loc hole after count",
        q,
        Some(&hub),
        8,
        Some(&feed),
        None,
        RejectParent::default(),
    );
    assert_eq!(feed.isolate_until(), u32::MAX);
    assert_eq!(hub.query.lookup_taken_hi(), Some(t + 2));
    assert_eq!(hub.query.lookup_started_hi(), Some(t + 2));
    assert!(st.halt.is_none());
    hub.query.set_lookup_taken_hi(None);
    hub.query.set_lookup_started_hi(None);

    // Bad-prev forks. The node confirmed a loser at tip+1; the winner W at
    // tip+1 and its child E at tip+2 are headers. E's reject rewinds the hub
    // to the fork point and plants W, E, whether or not W's body is here
    // yet. After each, the node confirms W and E and the next fork starts
    // from there.
    let mut time = 100;
    let mut fork = || {
        time += 10;
        let tip = hub.tip_hash().unwrap();
        let t = hub.tip_height().unwrap();
        let lose = mine(tip, time, t + 1, vec![]);
        hub.accept_block(lose.clone()).unwrap();
        let win = mine(tip, time + 1, t + 1, vec![]);
        hub.ensure_header(&win.header).unwrap();
        let ext = mine(win.block_hash(), time + 2, t + 2, vec![]);
        hub.ensure_header(&ext.header).unwrap();
        (tip, t, lose, win, ext)
    };
    let planted = |st: &IbdWorkState, t: u32, win: &bitcoin::Block, ext: &bitcoin::Block| {
        st.height_to_hash.get(&(t + 1)) == Some(&win.block_hash())
            && st.height_to_hash.get(&(t + 2)) == Some(&ext.block_hash())
    };
    let settle = |win: &bitcoin::Block, ext: &bitcoin::Block| {
        hub.accept_block(win.clone()).unwrap();
        hub.accept_block(ext.clone()).unwrap();
        for ht in hub.query.block_queue_queued_heights() {
            hub.query.block_queue_dequeue_height(ht).unwrap();
        }
        hub.query.set_lookup_taken_hi(None);
    };
    let offer = |ht: u32, b: &bitcoin::Block| {
        hub.query
            .block_queue_offer(ht, b.block_hash().to_byte_array(), 0, &serialize(b))
            .unwrap();
    };

    // E queued, W nowhere: rewind without waiting for W.
    let (tip, t, lose, win, ext) = fork();
    offer(t + 2, &ext);
    let mut st = IbdWorkState::new(Vec::new(), Some(lose.block_hash()), Some(t + 1));
    apply_confirm_reject(&mut st, t + 2, ext.block_hash(), bad_prev, q, Some(&hub));
    assert_eq!(hub.tip_hash(), Some(tip), "rewind does not wait for W");
    assert!(planted(&st, t, &win, &ext) && st.reorg.need_getdata().is_empty());
    settle(&win, &ext);

    // W held as a side body, E queued at tip+1.
    let (tip, t, lose, win, ext) = fork();
    offer(t + 2, &ext);
    let mut st = IbdWorkState::new(Vec::new(), Some(lose.block_hash()), Some(t + 1));
    st.ordered.push_back(ext.block_hash());
    st.ordered_set.insert(ext.block_hash());
    st.reorg.hold_body(win.clone());
    apply_confirm_reject(&mut st, t + 2, ext.block_hash(), bad_prev, q, Some(&hub));
    assert_eq!(hub.tip_hash(), Some(tip));
    assert!(planted(&st, t, &win, &ext));
    assert!(!st.body.is_rejected(&ext.block_hash()));
    settle(&win, &ext);

    // Lookup already took E's row; the reject still classifies.
    let (tip, t, lose, win, ext) = fork();
    offer(t + 2, &ext);
    assert!(hub.query.block_queue_take_raw(t + 2).is_some());
    hub.query.set_lookup_taken_hi(Some(t + 2));
    assert!(hub
        .query
        .block_queue_payload(t + 2)
        .ok()
        .flatten()
        .is_none());
    let mut st = IbdWorkState::new(Vec::new(), Some(lose.block_hash()), Some(t + 1));
    st.reorg.hold_body(win.clone());
    apply_confirm_reject(&mut st, t + 2, ext.block_hash(), bad_prev, q, Some(&hub));
    assert_eq!(hub.tip_hash(), Some(tip), "rewind to the fork point");
    assert!(planted(&st, t, &win, &ext) && st.reorg.need_getdata().is_empty());
    assert!(!st.body.is_rejected(&ext.block_hash()));
    settle(&win, &ext);

    // W and E both only on the body queue, found by hash.
    let (tip, t, lose, win, ext) = fork();
    offer(t + 1, &win);
    offer(t + 2, &ext);
    let mut st = IbdWorkState::new(Vec::new(), Some(lose.block_hash()), Some(t + 1));
    apply_confirm_reject(&mut st, t + 2, ext.block_hash(), bad_prev, q, Some(&hub));
    assert_eq!(hub.tip_hash(), Some(tip));
    assert!(planted(&st, t, &win, &ext) && st.reorg.need_getdata().is_empty());
    settle(&win, &ext);

    // No bodies, lookup took tip+2: taken rewinds to the fork point and E
    // stays wanted.
    let (tip, t, lose, win, ext) = fork();
    hub.query.set_lookup_taken_hi(Some(t + 2));
    let mut st = IbdWorkState::new(Vec::new(), Some(lose.block_hash()), Some(t + 1));
    st.record_height(ext.block_hash(), t + 2);
    st.ordered.push_back(ext.block_hash());
    st.ordered_set.insert(ext.block_hash());
    apply_confirm_reject(&mut st, t + 2, ext.block_hash(), bad_prev, q, Some(&hub));
    assert_eq!(hub.query.lookup_taken_hi(), Some(t));
    assert_eq!(hub.tip_hash(), Some(tip));
    assert!(planted(&st, t, &win, &ext) && st.reorg.need_getdata().is_empty());
    assert!(!st.body.is_missing(&ext.block_hash()));
    settle(&win, &ext);

    // Awaiting an explored reorg: W held, E only queued. Completing it
    // rewinds to the fork point.
    let (tip, t, lose, win, ext) = fork();
    offer(t + 2, &ext);
    assert!(hub
        .query
        .block_queue_payload_by_hash(&win.block_hash().to_byte_array())
        .unwrap()
        .is_none());
    let mut st = IbdWorkState::new(Vec::new(), Some(lose.block_hash()), Some(t + 1));
    for (b, ht) in [(&win, t + 1), (&ext, t + 2)] {
        st.record_height(b.block_hash(), ht);
        st.ordered.push_back(b.block_hash());
        st.ordered_set.insert(b.block_hash());
    }
    st.reorg.hold_body(win.clone());
    st.reorg
        .register_explore([win.block_hash(), ext.block_hash()], Some(ext.block_hash()));
    assert!(st.reorg.need_getdata().contains(&ext.block_hash()));
    assert!(try_apply_exploration(&mut st, &hub));
    assert_eq!(hub.tip_hash(), Some(tip));
    assert!(planted(&st, t, &win, &ext));
    settle(&win, &ext);

    // Loser L1, L2 confirmed; heavier W1..=W5 are headers. The resume seed
    // rewinds to the fork point and plants W. W1 is a fetch hole: a zombie
    // pending flag is demoted and re-got, and its body queues as tip+1.
    let tip = hub.tip_hash().unwrap();
    let t = hub.tip_height().unwrap();
    let l1 = mine(tip, 200, t + 1, vec![]);
    let l2 = mine(l1.block_hash(), 201, t + 2, vec![]);
    hub.accept_block(l1).unwrap();
    hub.accept_block(l2.clone()).unwrap();
    let w: Vec<bitcoin::Block> = (1..=5u32).fold(Vec::new(), |mut w, i| {
        let prev = w.last().map_or(tip, |b: &bitcoin::Block| b.block_hash());
        w.push(mine(prev, 210 + i, t + i, vec![]));
        w
    });
    for b in &w {
        hub.ensure_header(&b.header).unwrap();
    }
    let w1 = w[0].block_hash();
    let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
    seed_work_path_from_store(&mut st, &hub);
    assert_eq!(hub.tip_hash(), Some(tip), "resume seed rewinds the loser");
    for (i, b) in w.iter().enumerate() {
        assert_eq!(
            st.height_to_hash.get(&(t + 1 + i as u32)),
            Some(&b.block_hash())
        );
    }
    assert!(st.reorg.need_getdata().is_empty());
    assert!(!st.body.skip_download(&hub, &w1));
    assert!(tip_fetch_hole(&hub, &st.height_to_hash, &mut st.body) >= 1);
    st.body.mark_pending(w1);
    assert!(st.body.skip_download(&hub, &w1));
    assign_work_ordered(
        &mut st,
        &hub,
        &IbdConfig::for_test(),
        &LoopStats::default(),
        AssignDepth::Full,
        None,
    );
    assert!(st.inflight.contains_key(&w1) && !st.body.is_pending(&w1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 0,
            hash: w1,
            payload: serialize(&w[0]),

            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(
        hub.query.block_queue_has_height(t + 1)
            || hub.query.block_queue_has_hash(&w1.to_byte_array())
    );
    assert_ne!(hub.tip_hash(), Some(l2.block_hash()));
    for b in &w {
        hub.accept_block(b.clone()).unwrap();
    }
    for ht in hub.query.block_queue_queued_heights() {
        hub.query.block_queue_dequeue_height(ht).unwrap();
    }

    // A fully valid heavier fork: rewind, confirm it, blame no one.
    let tip = hub.tip_hash().unwrap();
    let t = hub.tip_height().unwrap();
    let a1 = mine(tip, 300, t + 1, vec![]);
    let a2 = mine(a1.block_hash(), 301, t + 2, vec![]);
    hub.accept_block(a1.clone()).unwrap();
    hub.accept_block(a2.clone()).unwrap();
    let b1 = mine(tip, 310, t + 1, vec![]);
    let b2 = mine(b1.block_hash(), 311, t + 2, vec![]);
    let b3 = mine(b2.block_hash(), 312, t + 3, vec![]);
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    for b in [&b1, &b2, &b3] {
        hub.ensure_header(&b.header).unwrap();
    }
    for (b, ht) in [
        (&a1, t + 1),
        (&a2, t + 2),
        (&b1, t + 1),
        (&b2, t + 2),
        (&b3, t + 3),
    ] {
        st.record_height(b.block_hash(), ht);
    }
    st.reorg
        .register_explore(std::iter::empty::<BlockHash>(), Some(b3.block_hash()));
    drop(hub.query.lock_tip_commit().expect("tip flush"));
    assert!(maybe_rewind_to_best_work(&mut st, &hub).unwrap());
    for b in [&b1, &b2, &b3] {
        hub.accept_block(b.clone()).unwrap();
    }
    assert_eq!(hub.tip_hash(), Some(b3.block_hash()));
    assert!(!st.body.is_rejected(&a1.block_hash()) && !st.body.is_rejected(&a2.block_hash()));
    assert!(st.reorg.invalid.is_empty());

    // Fork A (8 blocks) is confirmed; the heavier fork B (10 headers)
    // spends a missing prevout at its third block. After rewinding onto B
    // and confirming B1, B2, B3's reject blacklists only B3 and replants A.
    let tip = hub.tip_hash().unwrap();
    let t = hub.tip_height().unwrap();
    let a: Vec<bitcoin::Block> = (1..=8u32).fold(Vec::new(), |mut a, i| {
        let prev = a.last().map_or(tip, |b: &bitcoin::Block| b.block_hash());
        let b = mine(prev, 400 + i * 600, t + i, vec![]);
        hub.accept_block(b.clone()).unwrap();
        a.push(b);
        a
    });
    let bad_tx = bitcoin::Transaction {
        version: TxVersion::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
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
    let b: Vec<bitcoin::Block> = (1..=10u32).fold(Vec::new(), |mut f, i| {
        let prev = f.last().map_or(tip, |b: &bitcoin::Block| b.block_hash());
        let txs = if i == 3 { vec![bad_tx.clone()] } else { vec![] };
        let b = mine(prev, 100_400 + i * 600, t + i, txs);
        hub.ensure_header(&b.header).unwrap();
        f.push(b);
        f
    });
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    for (i, blk) in b.iter().enumerate() {
        st.record_height(blk.block_hash(), t + 1 + i as u32);
        st.known_headers.insert(blk.block_hash());
    }
    for (i, blk) in a.iter().enumerate() {
        st.known_headers.insert(blk.block_hash());
        st.hash_height.insert(blk.block_hash(), t + 1 + i as u32);
    }
    st.reorg
        .register_explore(std::iter::empty::<BlockHash>(), Some(b[9].block_hash()));
    drop(hub.query.lock_tip_commit().expect("tip flush"));
    assert!(maybe_rewind_to_best_work(&mut st, &hub).unwrap());
    assert_eq!(hub.tip_hash(), Some(tip), "rewound to the fork point");
    assert!(!st.ordered.is_empty());
    hub.accept_block(b[0].clone()).unwrap();
    hub.accept_block(b[1].clone()).unwrap();
    apply_confirm_reject(
        &mut st,
        t + 3,
        b[2].block_hash(),
        "consensus: script verification failed: script false",
        q,
        Some(&hub),
    );
    assert!(st.body.is_rejected(&b[2].block_hash()));
    assert!(st.reorg.invalid.contains(b[2].block_hash().to_byte_array()));
    for blk in b[..2].iter().chain(&a) {
        assert!(!st.body.is_rejected(&blk.block_hash()));
        assert!(!st.reorg.invalid.contains(blk.block_hash().to_byte_array()));
    }
    assert_eq!(
        hub.tip_hash(),
        Some(tip),
        "invalid mid-path rewinds to the fork point"
    );
    assert_eq!(st.height_to_hash.get(&(t + 1)), Some(&a[0].block_hash()));
    assert_eq!(st.ordered.front(), Some(&a[0].block_hash()));
    assert!(st.confirm_stuck_since.is_none());
    for blk in &a {
        assert!(hub
            .query
            .is_block_archived(&blk.block_hash().to_byte_array())
            .unwrap());
    }

    // Hygiene drops A from the path; the store resume skips the invalid B
    // subtree and replants A.
    for blk in &a {
        st.hash_height.remove(&blk.block_hash());
        st.height_to_hash.retain(|_, h| *h != blk.block_hash());
    }
    seed_work_path_from_store(&mut st, &hub);
    assert_eq!(st.height_to_hash.get(&(t + 1)), Some(&a[0].block_hash()));

    // A1's Class A body fails its merkle root: a soft re-get that drops the
    // stored body association.
    let a1 = a[0].block_hash();
    let hfk = hub.ensure_header_fk(&a[0].header).unwrap();
    assert!(hub.query.store().header_txs.has_body(hfk).unwrap());
    st.body.mark_archived(a1);
    apply_confirm_reject(
        &mut st,
        t + 1,
        a1,
        "consensus: bad block: merkle root mismatch",
        q,
        None,
    );
    assert!(!st.body.is_rejected(&a1) && !st.body.is_known_archived(&a1));
    assert!(!hub.query.store().header_txs.has_body(hfk).unwrap());

    let _ = std::fs::remove_dir_all(dir);
}

type Reject = (BlockHash, ConfirmRejectClass, usize);

/// Regtest hub padded past coinbase maturity, IBD work state, and a confirm
/// engine. Getdata comes from the real assign.
struct WireRig {
    dir: rbitcoin_query::testutil::TempDir,
    hub: std::sync::Arc<rbitcoin_net::chain::ChainHub>,
    feed: std::sync::Arc<rbitcoin_ibd::ibd::confirm::ConfirmFeed>,
    engine: Option<(
        std::thread::JoinHandle<()>,
        std::sync::mpsc::Receiver<rbitcoin_ibd::ibd::confirm::ConfirmEvent>,
    )>,
    /// Operator line of the last confirm reject `pump` applied.
    last_reject_err: Option<String>,
    st: IbdWorkState,
    write_next: std::sync::atomic::AtomicU32,
    book: rbitcoin_net::seeds::AddrMan,
    progress: std::time::Instant,
    cfg: rbitcoin_ibd::ibd::IbdConfig,
    stats: rbitcoin_ibd::ibd::status::LoopStats,
    tip: BlockHash,
    tip_time: u32,
    t: u32,
    cbs: Vec<bitcoin::Txid>,
}

struct WirePad {
    // The confirmed-set seed still reads this store after `WireRig::new` returns.
    _dir: rbitcoin_query::testutil::TempDir,
    _hub: std::sync::Arc<rbitcoin_net::chain::ChainHub>,
    tip: BlockHash,
    tip_time: u32,
    t: u32,
    cbs: Vec<bitcoin::Txid>,
}

fn copy_store_tree(src: &std::path::Path, dst: &std::path::Path) {
    rbitcoin_store::testutil::copy_store_tree(src, dst);
}

/// Direct-index maturity+2 regtest, mined once per process.
fn wire_pad() -> &'static WirePad {
    use std::sync::OnceLock;
    static PAD: OnceLock<WirePad> = OnceLock::new();
    PAD.get_or_init(|| {
        use rbitcoin_consensus::ChainParams;
        use rbitcoin_query::pad_empty_from;
        let (dir, hub0) = rbitcoin_net::chain::tiny_regtest_hub_labeled("wire-pad");
        hub0.query.enter_direct_index_mode().unwrap();
        let hub = std::sync::Arc::new(hub0);
        hub.ensure_genesis().unwrap();
        let params = ChainParams::regtest();
        let gen_time = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .header
            .time;
        let last = params.coinbase_maturity() + 2;
        let (tip, tip_time, cbs) = pad_empty_from(
            &hub.query,
            &params,
            hub.tip_hash().unwrap(),
            gen_time,
            1,
            last,
            2,
        );
        hub.query.flush().expect("flush wire pad");
        let t = hub.tip_height().unwrap();
        WirePad {
            _dir: dir,
            _hub: hub,
            tip,
            tip_time,
            t,
            cbs,
        }
    })
}

impl WireRig {
    fn new(label: &str, peers: usize) -> Self {
        use rbitcoin_consensus::ChainParams;
        let pad = wire_pad();
        let dir = rbitcoin_query::testutil::TempDir::labeled(label).expect("wire copy");
        copy_store_tree(pad._dir.path(), dir.path());
        let q = Query::open_or_create_tiny(dir.path()).unwrap();
        // IndexMode lives on the open Query and defaults to Tip. The pad was
        // connected in Direct; re-enter so later confirms stay on that path.
        q.enter_direct_index_mode().unwrap();
        let hub = std::sync::Arc::new(rbitcoin_net::chain::ChainHub::new(
            q,
            ChainParams::regtest(),
            rbitcoin_consensus::Milestone::NONE,
        ));
        assert_eq!(hub.tip_hash(), Some(pad.tip));
        assert_eq!(hub.tip_height(), Some(pad.t));
        assert!(hub.query.index_mode().expect("index mode cell").is_direct());
        Self::over(dir, hub, peers, (pad.tip, pad.tip_time, pad.cbs.clone()))
    }

    /// A fresh regtest pad like [`wire_pad`], on a store whose `tx.head`
    /// segments roll every 204 creates.
    fn new_small_head(label: &str, peers: usize) -> Self {
        use rbitcoin_consensus::ChainParams;
        use rbitcoin_query::pad_empty_from;
        let dir = rbitcoin_query::testutil::TempDir::labeled(label).expect("small-head dir");
        drop(rbitcoin_store::testutil::create_tiny_with_head_bits(
            dir.path(),
            8,
        ));
        let q = Query::open_or_create_tiny(dir.path()).unwrap();
        q.enter_direct_index_mode().unwrap();
        let params = ChainParams::regtest();
        let hub = std::sync::Arc::new(rbitcoin_net::chain::ChainHub::new(
            q,
            params.clone(),
            rbitcoin_consensus::Milestone::NONE,
        ));
        hub.ensure_genesis().unwrap();
        let gen_time = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .header
            .time;
        let pad = pad_empty_from(
            &hub.query,
            &params,
            hub.tip_hash().unwrap(),
            gen_time,
            1,
            params.coinbase_maturity() + 2,
            2,
        );
        hub.query.flush().unwrap();
        Self::over(dir, hub, peers, pad)
    }

    /// IBD work state and a confirm feed over `hub`, whose tip is `tip`.
    fn over(
        dir: rbitcoin_query::testutil::TempDir,
        hub: std::sync::Arc<rbitcoin_net::chain::ChainHub>,
        peers: usize,
        (tip, tip_time, cbs): (BlockHash, u32, Vec<bitcoin::Txid>),
    ) -> Self {
        use super::super::assign::dummy_slot;
        let t = hub.tip_height().unwrap();
        let mut st = IbdWorkState::new((1..=peers).map(dummy_slot).collect(), Some(tip), Some(t));
        let feed = std::sync::Arc::new(rbitcoin_ibd::ibd::confirm::ConfirmFeed::new());
        st.confirm_feed = Some(std::sync::Arc::clone(&feed));
        Self {
            dir,
            hub,
            feed,
            engine: None,
            last_reject_err: None,
            st,
            write_next: std::sync::atomic::AtomicU32::new(t + 1),
            book: rbitcoin_net::seeds::AddrMan::new(),
            progress: std::time::Instant::now(),
            cfg: rbitcoin_ibd::ibd::IbdConfig::for_test(),
            stats: Default::default(),
            tip,
            tip_time,
            t,
            cbs,
        }
    }

    /// Flush, drop the hub, run `edit` on the datadir, and open the store
    /// again, as a process restart does. `tip` and `tip_time` must name the
    /// store tip. Call before the engine starts.
    fn restart(self, edit: impl FnOnce(&std::path::Path)) -> Self {
        use rbitcoin_consensus::{ChainParams, Milestone};
        assert!(self.engine.is_none(), "restart before the engine starts");
        self.hub.query.flush().unwrap();
        let peers = self.st.slots.len();
        let Self {
            dir,
            hub,
            tip,
            tip_time,
            cbs,
            ..
        } = self;
        drop(std::sync::Arc::into_inner(hub).expect("the rig holds the only hub"));
        edit(dir.path());
        let q = rbitcoin_query::Query::open_or_create_tiny(dir.path()).unwrap();
        let hub = rbitcoin_net::chain::ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.query.enter_direct_index_mode().unwrap();
        Self::over(dir, std::sync::Arc::new(hub), peers, (tip, tip_time, cbs))
    }

    /// A tx spending output 0 of `prev` to OP_TRUE.
    fn spend(prev: bitcoin::Txid) -> bitcoin::Transaction {
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    /// Put `blocks` (tip+1, tip+2, …) on the header path. Every peer is
    /// taller.
    fn plant(&mut self, blocks: &[&bitcoin::Block]) {
        for (i, b) in blocks.iter().enumerate() {
            let (hash, ht) = (b.block_hash(), self.t + 1 + i as u32);
            self.st.record_height(hash, ht);
            self.st.ordered_set.insert(hash);
            self.st.ordered.push_back(hash);
            self.st.max_ordered_height = ht;
            self.st
                .header_fks
                .insert(hash, self.hub.ensure_header_fk(&b.header).unwrap());
        }
        let top = self.st.max_ordered_height;
        for s in &mut self.st.slots {
            s.peer_height = top;
        }
    }

    /// `peer` answers a getdata for `body`'s hash with `body`.
    fn deliver(&mut self, peer: usize, body: &bitcoin::Block) {
        use rbitcoin_ibd::ibd::peer_io::PeerEvent;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1);
        rbitcoin_ibd::ibd::events::apply_peer_event(
            &mut self.st,
            &self.hub,
            PeerEvent::BlockFramed {
                peer,
                hash: body.block_hash(),
                payload: bitcoin::consensus::serialize(body),

                header_fk: None,
            },
            &self.write_next,
            &mut self.book,
            local,
            Some(&self.feed),
        );
    }

    fn start_engine(&mut self) {
        use rbitcoin_ibd::ibd::confirm::spawn_confirm_engine;
        let (ev_tx, ev_rx) = std::sync::mpsc::channel();
        let (engine, _queues) = spawn_confirm_engine(
            std::sync::Arc::clone(&self.hub),
            std::sync::Arc::clone(&self.feed),
            ev_tx,
            std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            std::sync::Arc::new(Default::default()),
        );
        self.engine = Some((engine, ev_rx));
    }

    /// Apply confirm events and run assign. Each getdata to a live peer is
    /// answered with `serve(peer, hash)`. Returns the rejects seen once
    /// `stop` holds after an event. Panics past a deadline: a missing body
    /// that assign never asks for is a stall.
    fn pump(
        &mut self,
        mut serve: impl FnMut(usize, BlockHash) -> bitcoin::Block,
        mut stop: impl FnMut(&IbdWorkState, &rbitcoin_net::chain::ChainHub, &[Reject]) -> bool,
    ) -> Vec<Reject> {
        use rbitcoin_ibd::ibd::assign::{assign_work_ordered, AssignDepth};
        use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
        use std::time::{Duration, Instant};
        let mut rejects = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let path_lo = self.hub.tip_height().unwrap() + 1;
            assert!(
                Instant::now() < deadline,
                "stall: rejects={rejects:?} asked={:?} scan_lo={} path_lo={path_lo}",
                self.st.inflight.keys().collect::<Vec<_>>(),
                self.st.densify_scan_lo,
            );
            let rx = &self.engine.as_ref().expect("engine").1;
            if let Ok(ev) = rx.recv_timeout(Duration::from_millis(5)) {
                if let ConfirmEvent::Reject {
                    hash,
                    class,
                    batch_len,
                    err,
                    ..
                } = &ev
                {
                    rejects.push((*hash, *class, *batch_len));
                    self.last_reject_err = Some(err.clone());
                }
                let (tx, one) = std::sync::mpsc::channel();
                tx.send(ev).unwrap();
                drop(tx);
                rbitcoin_ibd::ibd::events::apply_confirm_events(
                    &mut self.st,
                    &self.hub,
                    &one,
                    &self.write_next,
                    &std::sync::atomic::AtomicU32::new(0),
                    &mut self.progress,
                    Some(&self.feed),
                );
                if stop(&self.st, &self.hub, &rejects) {
                    return rejects;
                }
            }
            assign_work_ordered(
                &mut self.st,
                &self.hub,
                &self.cfg,
                &self.stats,
                AssignDepth::Full,
                None,
            );
            let asks: Vec<(BlockHash, usize)> = self
                .st
                .inflight
                .iter()
                .flat_map(|(h, r)| r.peers.iter().map(move |p| (*h, *p)))
                .filter(|(_, p)| self.st.slots.iter().any(|s| s.id == *p && s.alive))
                .collect();
            for (hash, peer) in asks {
                let body = serve(peer, hash);
                self.deliver(peer, &body);
            }
        }
    }

    /// Cut the store file `name` to zero bytes, so a read of any row in it
    /// is a local IO fault. Returns what [`Self::mend`] writes back.
    fn tear(&self, name: &str) -> (std::path::PathBuf, Vec<u8>) {
        fn find(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
            std::fs::read_dir(dir).ok()?.flatten().find_map(|e| {
                let p = e.path();
                if p.is_dir() {
                    find(&p, name)
                } else {
                    (p.file_name()? == name).then_some(p)
                }
            })
        }
        let path = find(self.dir.path(), name).expect(name);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(0)
            .unwrap();
        (path, bytes)
    }

    fn mend((path, bytes): (std::path::PathBuf, Vec<u8>)) {
        std::fs::write(path, bytes).unwrap();
    }

    /// Run the engine without IBD until its first reject, then hand back
    /// that reject and every event seen, unapplied.
    fn first_reject(
        &self,
    ) -> (
        Reject,
        std::sync::mpsc::Receiver<rbitcoin_ibd::ibd::confirm::ConfirmEvent>,
    ) {
        use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
        use std::time::{Duration, Instant};
        let rx = &self.engine.as_ref().expect("engine").1;
        let (held_tx, held) = std::sync::mpsc::channel();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(Instant::now() < deadline, "no confirm reject");
            let Ok(ev) = rx.recv_timeout(Duration::from_millis(5)) else {
                continue;
            };
            let reject = match &ev {
                ConfirmEvent::Reject {
                    hash,
                    class,
                    batch_len,
                    ..
                } => Some((*hash, *class, *batch_len)),
                _ => None,
            };
            held_tx.send(ev).unwrap();
            if let Some(r) = reject {
                return (r, held);
            }
        }
    }

    fn apply_held(
        &mut self,
        held: &std::sync::mpsc::Receiver<rbitcoin_ibd::ibd::confirm::ConfirmEvent>,
    ) {
        rbitcoin_ibd::ibd::events::apply_confirm_events(
            &mut self.st,
            &self.hub,
            held,
            &self.write_next,
            &std::sync::atomic::AtomicU32::new(0),
            &mut self.progress,
            Some(&self.feed),
        );
    }

    fn finish(mut self) {
        self.feed.request_stop();
        self.feed.notify();
        if let Some((engine, _)) = self.engine.take() {
            let _ = engine.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn wire_pad_copy_keeps_the_other_tip() {
    use bitcoin::ScriptBuf;

    let a = WireRig::new("wire-iso-a", 1);
    let b = WireRig::new("wire-iso-b", 1);
    assert_eq!(a.t, b.t);
    assert!(a.t >= 102);
    assert_eq!(a.tip, b.tip);
    assert_eq!(a.cbs, b.cbs);
    assert!(a
        .hub
        .query
        .index_mode()
        .expect("index mode cell")
        .is_direct());
    assert!(b
        .hub
        .query
        .index_mode()
        .expect("index mode cell")
        .is_direct());
    let block = rbitcoin_consensus::mine_regtest_paying(
        a.tip,
        a.tip_time + 600,
        a.t + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![WireRig::spend(a.cbs[0])],
    );
    a.hub.accept_block(block).unwrap();
    assert_eq!(b.hub.tip_hash(), Some(b.tip));
    assert_ne!(a.hub.tip_hash(), Some(b.tip));
    a.finish();
    b.finish();
}

/// Peers answer the getdata for tip+1 with a body the header does not
/// commit to: no txs, a repeated tail (CVE-2012-2459), or witness the
/// coinbase does not commit to. Each confirm reject is mutated wire: the
/// body leaves the queue, the hash stays off the invalid set, and the
/// sender is dropped and cooled down unless noban (Core
/// `MaybePunishNodeForBlock`). Assign asks for the hash again, and the
/// honest body from another peer connects.
#[test]
fn ibd_mutated_body_is_refetched_not_blacklisted() {
    use bitcoin::{ScriptBuf, Transaction, Witness};
    use std::sync::Arc;

    let mut rig = WireRig::new("mutated-body", 5);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let honest = rbitcoin_consensus::mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![WireRig::spend(cbs[0]), WireRig::spend(cbs[1])],
    );
    let hash = honest.block_hash();
    let raw = hash.to_byte_array();
    let under_header = |txdata: Vec<Transaction>| bitcoin::Block {
        header: honest.header,
        txdata,
    };
    let mut repeated = honest.txdata.clone();
    repeated.push(repeated[2].clone());
    let mut witness = honest.txdata.clone();
    witness[1].input[0].witness = Witness::from_slice(&[[0x01]]);
    rig.plant(&[&honest]);
    rig.start_engine();
    let peers = rbitcoin_net::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let mut noban = rbitcoin_net::net_permissions::NetPermTable::default();
    noban
        .whitelist
        .push(rbitcoin_net::net_permissions::parse_whitelist("noban,out@127.0.0.1").unwrap());
    peers.set_net_perms(noban);

    // One peer is up per round, so assign asks that peer.
    let up = |st: &mut IbdWorkState, peer: usize| {
        for s in &mut st.slots {
            s.alive = s.id == peer;
        }
    };
    for (what, peer, noban, txdata) in [
        ("no txs", 1, false, vec![]),
        ("repeated tail", 2, false, repeated.clone()),
        ("uncommitted witness", 3, false, witness),
        ("noban repeated tail", 4, true, repeated),
    ] {
        up(&mut rig.st, peer);
        rig.st.perms = noban.then(|| Arc::clone(&peers));
        let body = under_header(txdata);
        let rejects = rig.pump(|_, _| body.clone(), |_, _, r| !r.is_empty());
        assert_eq!(rejects, [(hash, ConfirmRejectClass::SoftWire, 1)], "{what}");
        let st = &mut rig.st;
        assert!(!st.body.is_rejected(&hash), "{what}");
        assert!(!st.reorg.invalid.contains(raw), "{what}");
        assert!(
            !rig.hub.query.block_queue_has_hash(&raw),
            "{what}: body dropped"
        );
        assert!(!st.body.skip_download(&rig.hub, &hash), "{what}: re-get");
        assert_eq!(rig.hub.tip_height(), Some(t), "{what}");
        let sender = &st.slots[peer - 1];
        assert_eq!(sender.alive, noban, "{what}: sender dropped");
        assert_eq!(
            st.addr_cooldown.contains_key(&sender.net),
            !noban,
            "{what}: sender cooled down"
        );
    }
    up(&mut rig.st, 5);
    let rejects = rig.pump(
        |_, _| honest.clone(),
        |_, hub, _| hub.tip_hash() == Some(hash),
    );
    assert!(rejects.is_empty(), "{rejects:?}");

    // A soft reject that is not a mutation is not the sender's fault.
    let next = BlockHash::from_byte_array([0x5a; 32]);
    rig.st.body.mark_pending(next);
    let err = "consensus: bad header: missing retarget first header";
    apply_confirm_reject_class(
        &mut rig.st,
        t + 2,
        next,
        ConfirmRejectClass::from_err_str(err),
        err,
        None,
        Some(&rig.hub),
        1,
        None,
        Some(5),
        RejectParent::default(),
    );
    assert!(rig.st.body.is_missing(&next), "re-get");
    assert!(rig.st.slots[4].alive, "retarget miss keeps the sender");
    rig.finish();
}

/// While isolated, lookup takes tip+2 only after tip+1 has connected: no
/// block is claimed while the one before it is still in the pipeline.
#[test]
fn isolation_claims_one_block_at_a_time() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use std::time::{Duration, Instant};

    let mut rig = WireRig::new("isolate-serial", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![WireRig::spend(cbs[0])],
    );
    let b2 = mine_regtest_paying(
        b1.block_hash(),
        rig.tip_time + 1200,
        t + 2,
        spk,
        vec![WireRig::spend(cbs[1])],
    );
    rig.plant(&[&b1, &b2]);
    for b in [&b1, &b2] {
        rig.st.slots[0].in_flight.insert(b.block_hash());
        rig.st.inflight.insert(b.block_hash(), InflightReq::new(1));
        rig.deliver(1, b);
    }
    rig.feed.request_single_block(u32::MAX - 1);
    rig.start_engine();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut ahead = 0;
    while rig.hub.tip_height() != Some(t + 2) {
        assert!(Instant::now() < deadline, "stall");
        let tip = rig.hub.tip_height().unwrap();
        let taken = rig.hub.query.lookup_taken_hi().unwrap_or(tip);
        ahead = ahead.max(taken.saturating_sub(tip));
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(ahead <= 1, "lookup ran {ahead} blocks past the tip");
    rig.finish();
}

/// tip+1 and tip+2 confirm in one wave and peer 2 serves a mutated tip+2.
/// The wave reject names tip+1, so it is isolated and retried one block at
/// a time: tip+2 is rejected under its own hash and only peer 2 is
/// dropped. Assign asks again for every body the rewind dropped, and both
/// honest bodies connect.
#[test]
fn ibd_batched_mutated_body_is_isolated_to_its_block() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::state::InflightReq;

    let mut rig = WireRig::new("batched-mutated", 3);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![WireRig::spend(cbs[0])],
    );
    let b2 = mine_regtest_paying(
        b1.block_hash(),
        rig.tip_time + 1200,
        t + 2,
        spk,
        vec![WireRig::spend(cbs[1])],
    );
    let (h1, h2) = (b1.block_hash(), b2.block_hash());
    let mut repeated = b2.clone();
    repeated.txdata.push(repeated.txdata[1].clone());
    rig.plant(&[&b1, &b2]);
    // Both bodies are queued before the engine starts, so one wave holds them.
    for (peer, body) in [(1, &b1), (2, &repeated)] {
        let hash = body.block_hash();
        rig.st.slots[peer - 1].in_flight.insert(hash);
        rig.st.inflight.insert(hash, InflightReq::new(peer));
        rig.deliver(peer, body);
    }
    rig.start_engine();

    let rejects = rig.pump(
        |peer, hash| match (hash == h1, peer) {
            (true, _) => b1.clone(),
            (false, 2) => repeated.clone(),
            (false, _) => b2.clone(),
        },
        |_, hub, _| hub.tip_hash() == Some(h2),
    );
    assert_eq!(
        rejects[0],
        (h1, ConfirmRejectClass::Cascade, 2),
        "one wave, named by tip+1, is isolated"
    );
    assert_eq!(
        rejects[1..],
        [(h2, ConfirmRejectClass::SoftWire, 1)],
        "only the mutated block is rejected as wire, alone"
    );
    assert_eq!(rig.hub.tip_height(), Some(t + 2));
    assert!(rig.st.slots[0].alive, "tip+1's sender is kept");
    assert!(
        !rig.st.slots[1].alive,
        "the mutated body's sender is dropped"
    );
    rig.finish();
}

/// tip+1 and tip+2 write in one batch and tip+2 breaks its BIP68 relative
/// lock, which only the write phase checks. The write hands the batch back
/// and offers it to the body queue, isolated: tip+1 connects from the
/// offered-back body with no second getdata and no stale-plan retry, and
/// tip+2 alone is rejected as invalid.
#[test]
fn batched_write_reject_offers_the_wave_back() {
    use bitcoin::{ScriptBuf, Sequence};
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use std::time::{Duration, Instant};

    let mut rig = WireRig::new("write-reject", 2);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![WireRig::spend(cbs[0])],
    );
    let mut locked = WireRig::spend(cbs[1]);
    locked.version = bitcoin::transaction::Version::TWO;
    locked.input[0].sequence = Sequence::from_height(1000);
    let b2 = mine_regtest_paying(
        b1.block_hash(),
        rig.tip_time + 1200,
        t + 2,
        spk,
        vec![locked],
    );
    let (h1, h2) = (b1.block_hash(), b2.block_hash());
    rig.plant(&[&b1, &b2]);
    for (peer, body) in [(1, &b1), (2, &b2)] {
        let hash = body.block_hash();
        rig.st.slots[peer - 1].in_flight.insert(hash);
        rig.st.inflight.insert(hash, InflightReq::new(peer));
        rig.deliver(peer, body);
    }
    rig.start_engine();

    // Hold the rejects until tip+1 has connected, so IBD cannot be the
    // one that brings its body back.
    let rx = &rig.engine.as_ref().unwrap().1;
    let (held_tx, held) = std::sync::mpsc::channel();
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while rig.hub.tip_hash() != Some(h1) {
        assert!(Instant::now() < deadline, "tip+1 never connected: {seen:?}");
        let Ok(ev) = rx.recv_timeout(Duration::from_millis(5)) else {
            continue;
        };
        if let ConfirmEvent::Reject {
            hash,
            class,
            batch_len,
            ..
        } = &ev
        {
            seen.push((*hash, *class, *batch_len));
        }
        held_tx.send(ev).unwrap();
    }
    drop(held_tx);
    assert_eq!(
        seen,
        [(h1, ConfirmRejectClass::Cascade, 2)],
        "the retake stamps a fresh plan"
    );
    rbitcoin_ibd::ibd::events::apply_confirm_events(
        &mut rig.st,
        &rig.hub,
        &held,
        &rig.write_next,
        &std::sync::atomic::AtomicU32::new(0),
        &mut rig.progress,
        Some(&rig.feed),
    );

    let mut asked_h1 = false;
    let rejects = rig.pump(
        |_, hash| {
            asked_h1 |= hash == h1;
            if hash == h1 {
                b1.clone()
            } else {
                b2.clone()
            }
        },
        |st, _, _| st.body.is_rejected(&h2),
    );
    assert!(!asked_h1, "tip+1 came back from the reject, not a getdata");
    assert_eq!(
        rejects.last(),
        Some(&(h2, ConfirmRejectClass::ConsensusInvalid, 1))
    );
    assert_eq!(rig.hub.tip_hash(), Some(h1));
    rig.finish();
}

/// tip+1 spends an output that tip+2 creates, and both write in one
/// batch. Core connects one block at a time, so tip+1's input is missing.
/// The batch reject is isolated. tip+1 alone fails its load stamp, and a
/// fresh read at the tip finds the parent off the connected chain (tip+2
/// is archived, not connected): tip+1 is invalid, and tip+2 is not judged.
#[test]
fn batched_spend_of_a_later_block_is_rejected_alone() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::state::InflightReq;

    let mut rig = WireRig::new("forward-spend", 2);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = WireRig::spend(cbs[0]);
    let child = WireRig::spend(parent.compute_txid());
    let b1 = mine_regtest_paying(rig.tip, rig.tip_time + 600, t + 1, spk.clone(), vec![child]);
    let b2 = mine_regtest_paying(
        b1.block_hash(),
        rig.tip_time + 1200,
        t + 2,
        spk,
        vec![parent],
    );
    let (h1, h2) = (b1.block_hash(), b2.block_hash());
    rig.plant(&[&b1, &b2]);
    for (peer, body) in [(1, &b1), (2, &b2)] {
        let hash = body.block_hash();
        rig.st.slots[peer - 1].in_flight.insert(hash);
        rig.st.inflight.insert(hash, InflightReq::new(peer));
        rig.deliver(peer, body);
    }
    rig.start_engine();

    let rejects = rig.pump(
        |_, hash| if hash == h1 { b1.clone() } else { b2.clone() },
        |st, _, _| st.halt.is_some() || st.reorg.invalid.contains(h1.to_byte_array()),
    );
    assert_eq!(
        rejects,
        [
            (h1, ConfirmRejectClass::Cascade, 2),
            (h1, ConfirmRejectClass::ConsensusInvalid, 1)
        ],
        "the batch event is a cascade; the one-block event is the verdict"
    );
    assert_eq!(rig.st.halt, None);
    assert!(rig.st.body.is_rejected(&h1));
    assert!(!rig.st.engine_fault_seen.contains(&h1));
    assert!(!rig.st.reorg.invalid.contains(h2.to_byte_array()));
    assert_eq!(rig.hub.tip_height(), Some(t));
    rig.finish();
}

/// A wave whose first block spends a create from its own block and whose
/// second block is invalid at write. The cascade retries the first block from
/// the archive, and that retry must still pin the same-block parent.
#[test]
fn archived_retry_pins_a_same_block_parent() {
    use bitcoin::{Amount, ScriptBuf};
    use rbitcoin_consensus::{grind_regtest_pow, mine_regtest_paying};
    use rbitcoin_ibd::ibd::state::InflightReq;

    let mut rig = WireRig::new("archived-same-block", 2);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = WireRig::spend(cbs[0]);
    let child = WireRig::spend(parent.compute_txid());
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![parent, child],
    );
    let mut b2 = mine_regtest_paying(b1.block_hash(), rig.tip_time + 1200, t + 2, spk, vec![]);
    b2.txdata[0].output[0].value += Amount::from_sat(1);
    b2.header.merkle_root = b2.compute_merkle_root().unwrap();
    grind_regtest_pow(&mut b2.header);
    let (h1, h2) = (b1.block_hash(), b2.block_hash());
    rig.plant(&[&b1, &b2]);
    for (peer, body) in [(1, &b1), (2, &b2)] {
        let hash = body.block_hash();
        rig.st.slots[peer - 1].in_flight.insert(hash);
        rig.st.inflight.insert(hash, InflightReq::new(peer));
        rig.deliver(peer, body);
    }
    rig.start_engine();

    let rejects = rig.pump(
        |_, hash| if hash == h1 { b1.clone() } else { b2.clone() },
        |st, _, _| st.halt.is_some() || st.reorg.invalid.contains(h2.to_byte_array()),
    );
    assert_eq!(
        rig.st.halt, None,
        "rejects={rejects:?} last={:?}",
        rig.last_reject_err
    );
    assert!(
        rejects.contains(&(h1, ConfirmRejectClass::Cascade, 2)),
        "both blocks in one wave: {rejects:?}"
    );
    assert!(!rig.st.engine_fault_seen.contains(&h1), "{rejects:?}");
    assert!(rig.st.reorg.invalid.contains(h2.to_byte_array()));
    assert_eq!(rig.hub.tip_height(), Some(t + 1), "{rejects:?}");
    rig.finish();
}

/// Archived blocks above the tip, as a crash between the Class A write and
/// the tip advance leaves them. The wave is longer than one load batch, so
/// the last block loads in the next chunk and spends a create from the
/// first, noted in flight with no outs.
#[test]
fn archived_wave_pins_a_parent_from_the_previous_chunk() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::state::InflightReq;

    let mut rig = WireRig::new("archived-cross-chunk", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let n = rbitcoin_ibd::ibd::confirm::CONFIRM_RUN_MAX_BLOCKS as u32 + 1;
    let parent = WireRig::spend(cbs[0]);
    let mut child = Some(WireRig::spend(parent.compute_txid()));
    let mut extra = vec![parent];
    let mut blocks: Vec<bitcoin::Block> = Vec::new();
    for i in 1..=n {
        let prev = blocks.last().map_or(rig.tip, |b| b.block_hash());
        if i == n {
            extra = child.take().into_iter().collect();
        }
        let b = mine_regtest_paying(
            prev,
            rig.tip_time + 600 * i,
            t + i,
            op_true.clone(),
            std::mem::take(&mut extra),
        );
        blocks.push(b);
    }
    // One Class A write for the run, as the write stage does, with no tip advance.
    let bodies: Vec<_> = blocks.iter().cloned().map(std::sync::Arc::new).collect();
    let fks: Vec<_> = bodies
        .iter()
        .map(|b| rig.hub.ensure_header_fk(&b.header).unwrap())
        .collect();
    let txids: Vec<Vec<[u8; 32]>> = bodies
        .iter()
        .map(|b| {
            b.txdata
                .iter()
                .map(|t| t.compute_txid().to_byte_array())
                .collect()
        })
        .collect();
    let items: Vec<_> = bodies
        .iter()
        .zip(&fks)
        .zip(&txids)
        .map(|((b, fk), ids)| (*fk, b, ids.as_slice()))
        .collect();
    rig.hub.query.archive_class_a_from_wire(&items).unwrap();
    assert_eq!(rig.hub.tip_height(), Some(t));
    let refs: Vec<&bitcoin::Block> = blocks.iter().collect();
    rig.plant(&refs);
    for body in &blocks {
        let hash = body.block_hash();
        rig.st.slots[0].in_flight.insert(hash);
        rig.st.inflight.insert(hash, InflightReq::new(1));
        rig.deliver(1, body);
    }
    rig.start_engine();

    let last = blocks.last().unwrap().block_hash();
    let by_hash: std::collections::HashMap<_, _> =
        blocks.iter().map(|b| (b.block_hash(), b.clone())).collect();
    let rejects = rig.pump(
        |_, hash| by_hash[&hash].clone(),
        |st, hub, _| st.halt.is_some() || hub.tip_hash() == Some(last),
    );
    assert_eq!(
        rig.st.halt, None,
        "rejects={rejects:?} last={:?}",
        rig.last_reject_err
    );
    assert_eq!(rig.hub.tip_height(), Some(t + n), "{rejects:?}");
    rig.finish();
}

/// tip+1 is the last block on the path, and load cannot read its header
/// row when it stamps the wave: a local store fault, not a block verdict.
/// The wave goes back to lookup, so once the row reads again tip+1
/// connects with no later wave, disconnect, or reorg to re-arm lookup.
#[test]
fn load_engine_fault_near_the_tip_retakes_the_wave() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::state::InflightReq;

    let mut rig = WireRig::new("load-engine-fault", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![WireRig::spend(cbs[0])],
    );
    let h1 = b1.block_hash();
    rig.plant(&[&b1]);
    rig.st.slots[0].in_flight.insert(h1);
    rig.st.inflight.insert(h1, InflightReq::new(1));
    rig.deliver(1, &b1);
    let torn = rig.tear("header.body");
    rig.start_engine();

    let (reject, held) = rig.first_reject();
    WireRig::mend(torn);
    assert_eq!(reject, (h1, ConfirmRejectClass::EngineFault, 1));
    rig.apply_held(&held);
    rig.pump(|_, _| b1.clone(), |_, hub, _| hub.tip_hash() == Some(h1));
    assert!(!rig.st.body.is_rejected(&h1));
    rig.finish();
}

/// tip+1 and tip+2 load in one wave, and pin cannot read the coinbase
/// outputs they spend. A pin-stage engine fault can be a stale-plan race,
/// so the retry runs one block at a time and names tip+1 alone. Once the
/// outputs read again, both blocks connect. A load reject may drop tip+2
/// for a fetch from peers (`docs/concurrency.md`), so IBD runs after the
/// mend and serves that fetch.
#[test]
fn batched_pin_engine_fault_retries_one_block_at_a_time() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::state::InflightReq;

    let mut rig = WireRig::new("pin-engine-fault", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![WireRig::spend(cbs[0])],
    );
    let b2 = mine_regtest_paying(
        b1.block_hash(),
        rig.tip_time + 1200,
        t + 2,
        spk,
        vec![WireRig::spend(cbs[1])],
    );
    let (h1, h2) = (b1.block_hash(), b2.block_hash());
    rig.plant(&[&b1, &b2]);
    // Both bodies are queued before the engine starts, so one wave holds them.
    for body in [&b1, &b2] {
        let hash = body.block_hash();
        rig.st.slots[0].in_flight.insert(hash);
        rig.st.inflight.insert(hash, InflightReq::new(1));
        rig.deliver(1, body);
    }
    let torn = rig.tear("txout.body");
    rig.start_engine();

    let (wave, _) = rig.first_reject();
    let (retry, _) = rig.first_reject();
    WireRig::mend(torn);
    assert_eq!(
        [wave, retry],
        [
            (h1, ConfirmRejectClass::EngineFault, 2),
            (h1, ConfirmRejectClass::EngineFault, 1)
        ]
    );
    rig.pump(
        |_, hash| if hash == h1 { b1.clone() } else { b2.clone() },
        |_, hub, _| hub.tip_hash() == Some(h2),
    );
    rig.finish();
}

/// A mutated head of a batch is isolated as a cascade and then lands as a
/// one-block soft reject. Repeats at the same tip, one per serving peer, do
/// not reach the cascade halt.
#[test]
fn isolated_soft_reject_does_not_count_toward_cascade_halt() {
    let mut st = IbdWorkState::new(Vec::new(), Some(h(0)), Some(0));
    let hash = h(1);
    st.record_height(hash, 1);
    let err = "consensus: bad block: merkle root mismatch";
    for _ in 0..4 {
        for (class, batch_len) in [
            (ConfirmRejectClass::Cascade, 2),
            (ConfirmRejectClass::SoftWire, 1),
        ] {
            apply_confirm_reject_class(
                &mut st,
                1,
                hash,
                class,
                err,
                None,
                None,
                batch_len,
                None,
                None,
                RejectParent::default(),
            );
        }
    }
    assert!(st.halt.is_none(), "{:?}", st.halt);
}

/// A block too far ahead of the clock is not a stale plan: its rejects at
/// one tip do not halt IBD, while a stale plan at that tip halts on the
/// third.
#[test]
fn a_block_too_far_ahead_does_not_count_toward_the_cascade_halt() {
    let mut st = IbdWorkState::new(Vec::new(), Some(h(0)), Some(0));
    let hash = h(1);
    st.record_height(hash, 1);
    let reject = |st: &mut IbdWorkState, err: &str| {
        apply_confirm_reject_class(
            st,
            1,
            hash,
            ConfirmRejectClass::Cascade,
            err,
            None,
            None,
            1,
            None,
            None,
            RejectParent::default(),
        );
    };
    for _ in 0..5 {
        reject(
            &mut st,
            "consensus: bad header: timestamp too far in future",
        );
        reject(&mut st, "time-too-new");
    }
    assert!(st.halt.is_none(), "{:?}", st.halt);
    for _ in 0..3 {
        reject(&mut st, "fk mismatch");
    }
    assert!(st.halt.is_some());
}

/// tip+1 and tip+2 run scripts in one wave and tip+2's script fails. The
/// scripts reject offers the wave back and isolates it: tip+1 connects from
/// the offered-back body with no second getdata and no stale-plan retry,
/// and tip+2 alone is rejected as invalid.
#[test]
fn batched_scripts_reject_offers_the_wave_back() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use std::time::{Duration, Instant};

    let mut rig = WireRig::new("scripts-reject", 2);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![WireRig::spend(cbs[0])],
    );
    let mut bad = WireRig::spend(cbs[1]);
    bad.input[0].script_sig = ScriptBuf::from_bytes(vec![0x6a]);
    let b2 = mine_regtest_paying(b1.block_hash(), rig.tip_time + 1200, t + 2, spk, vec![bad]);
    let (h1, h2) = (b1.block_hash(), b2.block_hash());
    rig.plant(&[&b1, &b2]);
    for (peer, body) in [(1, &b1), (2, &b2)] {
        let hash = body.block_hash();
        rig.st.slots[peer - 1].in_flight.insert(hash);
        rig.st.inflight.insert(hash, InflightReq::new(peer));
        rig.deliver(peer, body);
    }
    rig.start_engine();

    // Hold the rejects until tip+1 has connected, so IBD cannot be the
    // one that brings its body back.
    let rx = &rig.engine.as_ref().unwrap().1;
    let (held_tx, held) = std::sync::mpsc::channel();
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while rig.hub.tip_hash() != Some(h1) {
        assert!(Instant::now() < deadline, "tip+1 never connected: {seen:?}");
        let Ok(ev) = rx.recv_timeout(Duration::from_millis(5)) else {
            continue;
        };
        if let ConfirmEvent::Reject {
            hash,
            class,
            batch_len,
            ..
        } = &ev
        {
            seen.push((*hash, *class, *batch_len));
        }
        held_tx.send(ev).unwrap();
    }
    drop(held_tx);
    assert_eq!(
        seen,
        [(h1, ConfirmRejectClass::Cascade, 2)],
        "the retake stamps a fresh plan"
    );
    rbitcoin_ibd::ibd::events::apply_confirm_events(
        &mut rig.st,
        &rig.hub,
        &held,
        &rig.write_next,
        &std::sync::atomic::AtomicU32::new(0),
        &mut rig.progress,
        Some(&rig.feed),
    );

    let mut asked_h1 = false;
    rig.pump(
        |_, hash| {
            asked_h1 |= hash == h1;
            if hash == h1 {
                b1.clone()
            } else {
                b2.clone()
            }
        },
        |st, _, _| st.body.is_rejected(&h2),
    );
    assert!(!asked_h1, "tip+1 came back from the reject, not a getdata");
    assert_eq!(rig.hub.tip_hash(), Some(h1));
    rig.finish();
}

/// A mutated clear is handed back before any confirm-write send. The debug
/// lock flag is not set on this path.
#[test]
fn mutated_clear_is_deferred_without_the_debug_lock_flag() {
    use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("clear-deferred-no-flag");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let height = hub.tip_height().unwrap() + 1;
    let hash = h(0x46);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(height - 1));
    st.record_height(hash, height);
    st.body.mark_archived(hash);
    let (tx, rx_clear) = std::sync::mpsc::sync_channel(0);
    hub.query.attach_confirm_write(tx);
    let saw = Arc::new(AtomicBool::new(false));
    let saw_w = Arc::clone(&saw);
    let worker = std::thread::spawn(move || {
        let Ok(msg) = rx_clear.recv_timeout(std::time::Duration::from_secs(2)) else {
            return;
        };
        saw_w.store(true, Ordering::Relaxed);
        let rbitcoin_query::ConfirmWriteMsg::ClearArchived { reply, .. } = msg else {
            return;
        };
        let _ = reply.send(Ok(false));
    });
    let (ev_tx, ev_rx) = std::sync::mpsc::channel();
    ev_tx
        .send(ConfirmEvent::Reject {
            height,
            hash,
            class: ConfirmRejectClass::SoftWire,
            err: "consensus: bad-txnmrklroot".to_string(),
            batch_len: 1,
            sender: None,
            parent: RejectParent::default(),
        })
        .unwrap();
    let write_next = AtomicU32::new(0);
    let max_ready = AtomicU32::new(0);
    let mut progress = Instant::now();
    let pending = rbitcoin_ibd::ibd::events::take_confirm_events(
        &mut st,
        &hub,
        &ev_rx,
        &write_next,
        &max_ready,
        &mut progress,
        None,
    );
    assert_eq!(pending.len(), 1, "mutated clear is deferred");
    assert!(
        !saw.load(Ordering::Relaxed),
        "clear is not sent inside take_confirm_events"
    );
    worker.join().unwrap();
    hub.query.detach_confirm_write();
    let _ = std::fs::remove_dir_all(dir);
}

/// A mutated soft reject clears the archived body without the coordinator
/// lock, and only then marks that hash missing.
#[test]
fn mutated_clear_drops_the_coordinator_lock_before_mark_missing() {
    use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("clear-drops-coord-lock");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let height = hub.tip_height().unwrap() + 1;
    let hash = h(0x44);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(height - 1));
    st.record_height(hash, height);
    st.body.mark_archived(hash);
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    hub.query.attach_confirm_write(tx);
    let shared = Arc::new(Mutex::new(st));
    let missing_during = Arc::new(AtomicBool::new(false));
    let shared_w = Arc::clone(&shared);
    let missing_w = Arc::clone(&missing_during);
    let worker = std::thread::spawn(move || {
        let Ok(msg) = rx.recv_timeout(std::time::Duration::from_secs(2)) else {
            return;
        };
        let rbitcoin_query::ConfirmWriteMsg::ClearArchived { reply, .. } = msg else {
            panic!("clear must be the write-channel item");
        };
        let st = shared_w.lock().unwrap_or_else(|e| e.into_inner());
        missing_w.store(st.body.is_missing(&hash), Ordering::Relaxed);
        drop(st);
        reply.send(Ok(false)).unwrap();
    });
    let (ev_tx, ev_rx) = std::sync::mpsc::channel();
    ev_tx
        .send(ConfirmEvent::Reject {
            height,
            hash,
            class: ConfirmRejectClass::SoftWire,
            err: "consensus: bad-txnmrklroot".to_string(),
            batch_len: 1,
            sender: None,
            parent: RejectParent::default(),
        })
        .unwrap();
    rbitcoin_ibd::apply_confirm_events_for_test(&shared, &hub, &ev_rx);
    worker.join().unwrap();
    let st = shared.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        !missing_during.load(Ordering::Relaxed),
        "mark_missing follows the clear"
    );
    assert!(st.body.is_missing(&hash));
    hub.query.detach_confirm_write();
    let _ = std::fs::remove_dir_all(dir);
}

/// A header that takes the height while the clear waits is not marked missing.
#[test]
fn mutated_clear_skips_mark_missing_when_the_height_changes_hands() {
    use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
    use std::sync::{Arc, Mutex};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("clear-height-replaced");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let height = hub.tip_height().unwrap() + 1;
    let hash = h(0x44);
    let other = h(0x45);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(height - 1));
    st.record_height(hash, height);
    st.body.mark_archived(hash);
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    hub.query.attach_confirm_write(tx);
    let shared = Arc::new(Mutex::new(st));
    let shared_w = Arc::clone(&shared);
    let worker = std::thread::spawn(move || {
        let msg = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("clear");
        let rbitcoin_query::ConfirmWriteMsg::ClearArchived { reply, .. } = msg else {
            panic!("clear must be the write-channel item");
        };
        let mut st = shared_w.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!st.body.is_missing(&hash), "mark_missing follows the clear");
        st.record_height(other, height);
        drop(st);
        reply.send(Ok(false)).unwrap();
    });
    let (ev_tx, ev_rx) = std::sync::mpsc::channel();
    ev_tx
        .send(ConfirmEvent::Reject {
            height,
            hash,
            class: ConfirmRejectClass::SoftWire,
            err: "consensus: bad-txnmrklroot".to_string(),
            batch_len: 1,
            sender: None,
            parent: RejectParent::default(),
        })
        .unwrap();
    rbitcoin_ibd::apply_confirm_events_for_test(&shared, &hub, &ev_rx);
    worker.join().unwrap();
    let st = shared.lock().unwrap_or_else(|e| e.into_inner());
    assert!(!st.body.is_missing(&hash));
    assert!(!st.body.is_missing(&other));
    assert_eq!(st.height_to_hash.get(&height), Some(&other));
    hub.query.detach_confirm_write();
    let _ = std::fs::remove_dir_all(dir);
}

/// Peer 2 serves a mutated tip+1 in one wave with tip+2. The wave reject
/// is isolated, and the confirm engine retakes tip+1 and rejects it alone
/// before IBD applies either reject. Applied together, the mutated sender
/// is still the peer dropped, and both honest bodies then connect.
#[test]
fn isolated_mutated_head_punishes_its_sender_when_lookup_runs_ahead() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use std::time::{Duration, Instant};

    let mut rig = WireRig::new("mutated-head-ahead", 3);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![WireRig::spend(cbs[0])],
    );
    let b2 = mine_regtest_paying(
        b1.block_hash(),
        rig.tip_time + 1200,
        t + 2,
        spk,
        vec![WireRig::spend(cbs[1])],
    );
    let (h1, h2) = (b1.block_hash(), b2.block_hash());
    let mut mutated = b1.clone();
    mutated.txdata.push(mutated.txdata[1].clone());
    rig.plant(&[&b1, &b2]);
    for (peer, body) in [(2, &mutated), (1, &b2)] {
        let hash = body.block_hash();
        rig.st.slots[peer - 1].in_flight.insert(hash);
        rig.st.inflight.insert(hash, InflightReq::new(peer));
        rig.deliver(peer, body);
    }
    rig.start_engine();

    // Hold the rejects until the engine has retaken tip+1 and rejected it
    // alone, then apply them as one drain.
    let rx = &rig.engine.as_ref().unwrap().1;
    let (held_tx, held) = std::sync::mpsc::channel();
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !seen.contains(&(h1, ConfirmRejectClass::SoftWire, 1)) {
        assert!(Instant::now() < deadline, "no isolated reject: {seen:?}");
        let Ok(ev) = rx.recv_timeout(Duration::from_millis(5)) else {
            continue;
        };
        if let ConfirmEvent::Reject {
            hash,
            class,
            batch_len,
            ..
        } = &ev
        {
            seen.push((*hash, *class, *batch_len));
        }
        held_tx.send(ev).unwrap();
    }
    assert_eq!(seen[0], (h1, ConfirmRejectClass::Cascade, 2), "{seen:?}");
    rbitcoin_ibd::ibd::events::apply_confirm_events(
        &mut rig.st,
        &rig.hub,
        &held,
        &rig.write_next,
        &std::sync::atomic::AtomicU32::new(0),
        &mut rig.progress,
        Some(&rig.feed),
    );
    assert!(
        !rig.st.slots[1].alive,
        "the mutated body's sender is dropped"
    );
    assert!(rig.st.slots[0].alive, "tip+2's sender is kept");

    let rejects = rig.pump(
        |_, hash| if hash == h1 { b1.clone() } else { b2.clone() },
        |_, hub, _| hub.tip_hash() == Some(h2),
    );
    assert!(
        rejects.iter().all(|r| r.1 != ConfirmRejectClass::SoftWire),
        "{rejects:?}"
    );
    rig.finish();
}

/// Peer 2 serves a mutated tip+1 alone. Load rejects it and drops the body.
/// Before IBD applies that reject, assign runs: the height is pending with
/// no queue row, so it is asked for again, and peer 3 answers with the
/// honest block. The reject then punishes the peer whose copy failed, not
/// the live sender of the replacement.
#[test]
fn mutated_verdict_punishes_its_copy_not_a_replacement() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::assign::{assign_work_ordered, AssignDepth};
    use rbitcoin_ibd::ibd::confirm::ConfirmEvent;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use std::time::{Duration, Instant};

    let mut rig = WireRig::new("mutated-replaced", 3);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![WireRig::spend(cbs[0])],
    );
    let h1 = b1.block_hash();
    let mut mutated = b1.clone();
    mutated.txdata.push(mutated.txdata[1].clone());
    rig.plant(&[&b1]);
    rig.st.slots[1].in_flight.insert(h1);
    rig.st.inflight.insert(h1, InflightReq::new(2));
    rig.deliver(2, &mutated);
    rig.start_engine();

    let rx = &rig.engine.as_ref().unwrap().1;
    let (held_tx, held) = std::sync::mpsc::channel();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(Instant::now() < deadline, "no reject");
        let Ok(ev) = rx.recv_timeout(Duration::from_millis(5)) else {
            continue;
        };
        let soft = matches!(
            &ev,
            ConfirmEvent::Reject { hash, class, .. }
                if *hash == h1 && *class == ConfirmRejectClass::SoftWire
        );
        held_tx.send(ev).unwrap();
        if soft {
            break;
        }
    }
    assign_work_ordered(
        &mut rig.st,
        &rig.hub,
        &rig.cfg,
        &rig.stats,
        AssignDepth::Full,
        None,
    );
    rig.st.slots[2].in_flight.insert(h1);
    rig.st.inflight.insert(h1, InflightReq::new(3));
    rig.deliver(3, &b1);
    drop(held_tx);
    rbitcoin_ibd::ibd::events::apply_confirm_events(
        &mut rig.st,
        &rig.hub,
        &held,
        &rig.write_next,
        &std::sync::atomic::AtomicU32::new(0),
        &mut rig.progress,
        Some(&rig.feed),
    );
    assert!(
        !rig.st.slots[1].alive,
        "the mutated copy's sender is dropped"
    );
    assert!(rig.st.slots[2].alive, "the replacement's sender is kept");

    rig.pump(|_, _| b1.clone(), |_, hub, _| hub.tip_hash() == Some(h1));
    rig.finish();
}

/// A peer of one IBD run queues a mutated tip+1, and the run ends before
/// confirm reaches it. The body queue keeps the row, so the next run in the
/// same process confirms it and rejects it as mutated. That run's peers
/// did not send it, so none of them is dropped.
#[test]
fn mutated_body_from_an_earlier_run_punishes_no_current_peer() {
    use super::super::assign::dummy_slot;
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::archive::rehydrate_block_queue_into_confirm;
    use rbitcoin_ibd::ibd::dial::next_peer_id;
    use rbitcoin_ibd::ibd::state::InflightReq;

    let mut rig = WireRig::new("sender-across-runs", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![WireRig::spend(cbs[0])],
    );
    let h1 = b1.block_hash();
    let mut mutated = b1.clone();
    mutated.txdata.push(mutated.txdata[1].clone());

    let run1 = next_peer_id();
    rig.st.slots[0].id = run1;
    rig.plant(&[&b1]);
    rig.st.slots[0].in_flight.insert(h1);
    rig.st.inflight.insert(h1, InflightReq::new(run1));
    rig.deliver(run1, &mutated);
    assert!(rig.hub.query.block_queue_has_hash(&h1.to_byte_array()));

    let run2 = next_peer_id();
    rig.st = IbdWorkState::new(vec![dummy_slot(run2)], Some(rig.tip), Some(t));
    rig.st.confirm_feed = Some(std::sync::Arc::clone(&rig.feed));
    rig.plant(&[&b1]);
    rehydrate_block_queue_into_confirm(&rig.hub, &mut rig.st, &rig.feed).unwrap();
    rig.start_engine();
    let rejects = rig.pump(|_, _| b1.clone(), |_, _, r| !r.is_empty());
    assert_eq!(rejects, [(h1, ConfirmRejectClass::SoftWire, 1)]);
    assert!(rig.st.slots[0].alive, "run 2's peer did not send that copy");

    rig.pump(|_, _| b1.clone(), |_, hub, _| hub.tip_hash() == Some(h1));
    rig.finish();
}

/// Core reads `version | 0x00 | 0x00 | locktime` as a tx with no inputs and
/// no outputs (an empty vin, then segwit flag 0) and caches the block
/// invalid. That wire through intake and the confirm engine reaches the same
/// verdict: the hash is blacklisted and its sender stays connected.
#[test]
fn ibd_flag_zero_tx_block_is_consensus_invalid() {
    use super::super::assign::dummy_slot;
    use bitcoin::consensus::serialize;
    use rbitcoin_ibd::ibd::confirm::{spawn_confirm_engine, ConfirmEvent, ConfirmFeed};
    use rbitcoin_ibd::ibd::events::{apply_confirm_events, apply_peer_event};
    use rbitcoin_ibd::ibd::peer_io::PeerEvent;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use rbitcoin_ibd::ibd::status::LoopStats;
    use rbitcoin_net::seeds::AddrMan;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc::{channel, RecvTimeoutError};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("flag-zero-tx");
    hub.query.enter_direct_index_mode().unwrap();
    let hub = Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();

    // The merkle root commits to the dummy's legacy encoding, which is the
    // 10-byte wire. rust-bitcoin would serialize it with a segwit flag of 1.
    let empty = bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let block = mine(gen, 10, 1, vec![empty]);
    let hash = block.block_hash();
    let mut wire = serialize(&block.header);
    wire.push(2);
    wire.extend_from_slice(&serialize(&block.txdata[0]));
    wire.extend_from_slice(&[1, 0, 0, 0, 0x00, 0x00, 0, 0, 0, 0]);

    let mut st = IbdWorkState::new(vec![dummy_slot(1)], Some(gen), Some(0));
    let feed = Arc::new(ConfirmFeed::new());
    st.record_height(hash, 1);
    st.header_fks
        .insert(hash, hub.ensure_header_fk(&block.header).unwrap());
    st.ordered.push_back(hash);
    st.ordered_set.insert(hash);
    st.slots[0].in_flight.insert(hash);
    st.inflight.insert(hash, InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash,
            payload: wire,

            header_fk: None,
        },
        &AtomicU32::new(1),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1),
        Some(feed.as_ref()),
    );
    assert!(st.slots[0].alive, "Core's encoding is not undecodable wire");
    assert!(st.body.is_pending(&hash));
    assert_eq!(hub.query.block_queue_stats().1, 1);

    let (ev_tx, ev_rx) = channel();
    let (engine, _queues) = spawn_confirm_engine(
        Arc::clone(&hub),
        Arc::clone(&feed),
        ev_tx,
        Arc::new(AtomicU32::new(0)),
        Arc::new(LoopStats::default()),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let (height, got, class, err, batch_len) = loop {
        match ev_rx.recv_timeout(Duration::from_millis(5)) {
            Ok(ConfirmEvent::Reject {
                height,
                hash,
                class,
                err,
                batch_len,
                sender: _,
                parent: _,
            }) => break (height, hash, class, err, batch_len),
            Ok(ConfirmEvent::Accepted { .. }) => panic!("a block with an empty tx connected"),
            Err(RecvTimeoutError::Timeout) => {
                assert!(Instant::now() < deadline, "no confirm reject")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("confirm engine exited"),
        }
    };
    feed.request_stop();
    feed.notify();
    let _ = engine.join();
    assert_eq!(
        (height, got, class, batch_len),
        (1, hash, ConfirmRejectClass::ConsensusInvalid, 1),
        "{err}"
    );
    assert!(err.contains("no inputs"), "{err}");

    let (tx, rx) = channel();
    tx.send(ConfirmEvent::Reject {
        height,
        hash,
        class,
        err,
        batch_len,
        sender: None,
        parent: RejectParent::from_lookup(&hub, hash),
    })
    .unwrap();
    drop(tx);
    apply_confirm_events(
        &mut st,
        &hub,
        &rx,
        &AtomicU32::new(1),
        &AtomicU32::new(0),
        &mut Instant::now(),
        Some(feed.as_ref()),
    );
    assert!(st.body.is_rejected(&hash) && st.slots[0].alive);
    assert_eq!(hub.tip_hash(), Some(gen));

    let _ = std::fs::remove_dir_all(dir);
}

/// A block whose header a clock stepped back left more than 2 hours ahead
/// waits. The engine holds before it tries again instead of retrying at
/// once, those rejects do not halt IBD, and the block connects once the
/// clock passes its time.
#[test]
fn a_block_too_far_ahead_waits_and_then_connects() {
    use super::super::assign::dummy_slot;
    use bitcoin::consensus::serialize;
    use rbitcoin_ibd::ibd::confirm::{spawn_confirm_engine, ConfirmEvent, ConfirmFeed};
    use rbitcoin_ibd::ibd::events::{apply_confirm_events, apply_peer_event};
    use rbitcoin_ibd::ibd::peer_io::PeerEvent;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use rbitcoin_ibd::ibd::status::LoopStats;
    use rbitcoin_net::seeds::AddrMan;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc::{channel, RecvTimeoutError};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("too-far-ahead");
    hub.query.enter_direct_index_mode().unwrap();
    let hub = Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let now = rbitcoin_consensus::clock::wall_now();
    let ahead = now + 2 * 3600 + 3;
    let block = mine(gen, (ahead - 1_300_000_000) as u32, 1, vec![]);
    let hash = block.block_hash();
    // Stored while the node clock was ahead. Header checks read that clock,
    // not a bare `with_now` around the call.
    hub.clock.set_mock(i64::try_from(ahead).unwrap());
    let fk = hub.ensure_header_fk(&block.header).unwrap();
    hub.clock.set_mock(0);

    let mut st = IbdWorkState::new(vec![dummy_slot(1)], Some(gen), Some(0));
    let feed = Arc::new(ConfirmFeed::new());
    st.record_height(hash, 1);
    st.header_fks.insert(hash, fk);
    st.ordered.push_back(hash);
    st.ordered_set.insert(hash);
    st.slots[0].in_flight.insert(hash);
    st.inflight.insert(hash, InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash,
            payload: serialize(&block),
            header_fk: None,
        },
        &AtomicU32::new(1),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1),
        Some(feed.as_ref()),
    );

    let (ev_tx, ev_rx) = channel();
    let (engine, _queues) = spawn_confirm_engine(
        Arc::clone(&hub),
        Arc::clone(&feed),
        ev_tx,
        Arc::new(AtomicU32::new(0)),
        Arc::new(LoopStats::default()),
    );
    let started = Instant::now();
    let deadline = started + Duration::from_secs(20);
    let mut rejects = 0u32;
    let connected = loop {
        match ev_rx.recv_timeout(Duration::from_millis(5)) {
            Ok(ev @ ConfirmEvent::Reject { .. }) => {
                rejects += 1;
                let (tx, rx) = channel();
                tx.send(ev).unwrap();
                drop(tx);
                apply_confirm_events(
                    &mut st,
                    &hub,
                    &rx,
                    &AtomicU32::new(1),
                    &AtomicU32::new(0),
                    &mut Instant::now(),
                    Some(feed.as_ref()),
                );
                assert!(st.halt.is_none(), "a block too far ahead does not halt IBD");
            }
            Ok(ConfirmEvent::Accepted { .. }) => break true,
            Err(RecvTimeoutError::Timeout) => {
                if hub.tip_hash() == Some(hash) {
                    break true;
                }
                if Instant::now() > deadline {
                    break false;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break false,
        }
    };
    feed.request_stop();
    feed.notify();
    let _ = engine.join();
    assert!(
        connected,
        "the block connects once the clock passes its time"
    );
    let waited = started.elapsed().as_secs().max(1) as u32;
    assert!(
        rejects <= 3 * waited + 2,
        "{rejects} rejects in {waited}s: the engine waits between tries"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// tip+1 spends a txid no block created. Its body matches its header, so
/// the missing parent is the block's own fault (Core
/// `bad-txns-inputs-missingorspent`): the hash is marked invalid, IBD does
/// not halt, and it follows the other valid tip+1.
#[test]
fn ibd_spend_of_an_unknown_txid_is_invalid() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;

    let mut rig = WireRig::new("unknown-parent", 2);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let ghost = WireRig::spend(bitcoin::Txid::from_byte_array([0xab; 32]));
    let bad = mine_regtest_paying(rig.tip, rig.tip_time + 600, t + 1, spk.clone(), vec![ghost]);
    let good = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 900,
        t + 1,
        spk,
        vec![WireRig::spend(cbs[0])],
    );
    let (hb, hg) = (bad.block_hash(), good.block_hash());
    rig.plant(&[&bad]);
    rig.st.hash_height.insert(hg, t + 1);
    rig.st.known_headers.insert(hg);
    rig.hub.ensure_header_fk(&good.header).unwrap();
    rig.start_engine();

    let rejects = rig.pump(
        |_, hash| {
            if hash == hb {
                bad.clone()
            } else {
                good.clone()
            }
        },
        |st, hub, _| st.halt.is_some() || hub.tip_hash() == Some(hg),
    );
    assert_eq!(rejects, [(hb, ConfirmRejectClass::ConsensusInvalid, 1)]);
    assert_eq!(rig.st.halt, None);
    assert!(rig.st.reorg.invalid.contains(hb.to_byte_array()));
    assert!(rig.st.body.is_rejected(&hb));
    assert_eq!(rig.hub.tip_hash(), Some(hg), "IBD follows the valid tip+1");
    rig.finish();
}

/// The node restarts with the tip right below a block that spends an
/// unknown txid. Open leaves `tx.head` holding every connected create, so
/// the first block after the restart gets the tip path's read and is
/// marked invalid, as it would be without the restart.
#[test]
fn spend_of_an_unknown_txid_after_restart_is_invalid() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;

    let mut rig = WireRig::new("unknown-parent-restart", 1).restart(|_| {});
    let t = rig.t;
    let ghost = WireRig::spend(bitcoin::Txid::from_byte_array([0xcd; 32]));
    let bad = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![ghost],
    );
    let hb = bad.block_hash();
    rig.plant(&[&bad]);
    rig.start_engine();

    let rejects = rig.pump(
        |_, _| bad.clone(),
        |st, _, _| st.halt.is_some() || st.reorg.invalid.contains(hb.to_byte_array()),
    );
    assert_eq!(rejects, [(hb, ConfirmRejectClass::ConsensusInvalid, 1)]);
    assert_eq!(rig.st.halt, None);
    assert!(rig.st.reorg.invalid.contains(hb.to_byte_array()));
    rig.finish();
}

/// tip+1 creates a tx and tip+2 spends it, each confirmed alone. tip+2 is
/// stamped as soon as tip+1 is the tip, while tip+1's `tx.head` insert may
/// still be draining. The parent is on the chain, so tip+2 connects.
#[test]
fn lone_spend_of_the_block_just_written_connects() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::state::InflightReq;

    let mut rig = WireRig::new("spend-just-written", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = WireRig::spend(cbs[0]);
    let child = WireRig::spend(parent.compute_txid());
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![parent],
    );
    let b2 = mine_regtest_paying(
        b1.block_hash(),
        rig.tip_time + 1200,
        t + 2,
        spk,
        vec![child],
    );
    let (h1, h2) = (b1.block_hash(), b2.block_hash());
    rig.plant(&[&b1, &b2]);
    for b in [&b1, &b2] {
        rig.st.slots[0].in_flight.insert(b.block_hash());
        rig.st.inflight.insert(b.block_hash(), InflightReq::new(1));
        rig.deliver(1, b);
    }
    rig.feed.request_single_block(u32::MAX - 1);
    rig.start_engine();

    let rejects = rig.pump(
        |_, hash| if hash == h1 { b1.clone() } else { b2.clone() },
        |st, hub, _| st.halt.is_some() || hub.tip_hash() == Some(h2),
    );
    assert!(rejects.is_empty(), "{rejects:?}");
    assert_eq!(rig.hub.tip_hash(), Some(h2));
    rig.finish();
}

/// A tx exists only in a block that a reorg left. It stays archived and in
/// `tx.head`, but its outputs are not coins on the new chain (Core's UTXO
/// view), so the new chain's block that spends it is invalid.
#[test]
fn spend_of_a_reorged_out_tx_is_invalid() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::reorg::maybe_rewind_to_best_work;

    let mut rig = WireRig::new("reorged-parent", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = WireRig::spend(cbs[0]);
    let left = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![parent.clone()],
    );
    let m = mine_regtest_paying(rig.tip, rig.tip_time + 900, t + 1, spk.clone(), vec![]);
    let b = mine_regtest_paying(
        m.block_hash(),
        rig.tip_time + 1500,
        t + 2,
        spk,
        vec![WireRig::spend(parent.compute_txid())],
    );
    let (hm, hb) = (m.block_hash(), b.block_hash());
    rig.plant(&[&m, &b]);
    rig.hub.accept_block(left.clone()).unwrap();
    assert_eq!(rig.hub.tip_hash(), Some(left.block_hash()));
    rig.st
        .reorg
        .register_explore(std::iter::empty::<BlockHash>(), Some(hb));
    // `accept_block` leaves an IBD tip flush running. Rewind returns false
    // until that flush releases the commit; the live loop retries.
    drop(rig.hub.query.lock_tip_commit().expect("tip flush"));
    assert!(maybe_rewind_to_best_work(&mut rig.st, &rig.hub).unwrap());
    assert_eq!(
        rig.hub.tip_hash(),
        Some(rig.tip),
        "rewound to the fork point"
    );
    // The IBD loop drains events after a rewind, which quiesces the feed.
    rig.apply_held(&std::sync::mpsc::channel().1);
    rig.start_engine();

    let rejects = rig.pump(
        |_, hash| if hash == hm { m.clone() } else { b.clone() },
        |st, _, _| st.halt.is_some() || st.reorg.invalid.contains(hb.to_byte_array()),
    );
    assert_eq!(rig.st.halt, None, "{rejects:?}");
    assert!(rig.st.reorg.invalid.contains(hb.to_byte_array()));
    assert_eq!(rig.hub.tip_hash(), Some(hm));
    rig.finish();
}

/// Load drops the body of a lone block it judges invalid, then sends the
/// reject. Here the IBD thread disconnects the block's parent before it
/// applies that reject, so apply cannot trust the verdict and treats it as
/// a cascade. The body is gone from the queue, so apply must ask for it
/// again: once the parent is the tip again, the block is judged and marked
/// invalid without waiting for its pending mark to go stale.
#[test]
fn verdict_applied_after_the_tip_moved_asks_for_the_body_again() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;
    use rbitcoin_ibd::ibd::reorg::apply_header_rewind;

    let mut rig = WireRig::new("verdict-tip-moved", 1);
    let t = rig.t;
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let ghost = WireRig::spend(bitcoin::Txid::from_byte_array([0xef; 32]));
    let p = mine_regtest_paying(rig.tip, rig.tip_time + 600, t + 1, spk.clone(), vec![]);
    let bad = mine_regtest_paying(p.block_hash(), rig.tip_time + 1200, t + 2, spk, vec![ghost]);
    let (hp, hb) = (p.block_hash(), bad.block_hash());
    rig.plant(&[&p, &bad]);
    rig.start_engine();
    let serve = |_, hash| if hash == hp { p.clone() } else { bad.clone() };
    rig.pump(serve, |_, hub, _| hub.tip_hash() == Some(hp));
    let ((got, class, n), held) = rig.first_reject();
    assert_eq!(
        (got, class, n),
        (hb, ConfirmRejectClass::ConsensusInvalid, 1)
    );

    drop(rig.hub.query.lock_tip_commit().expect("tip flush"));
    assert!(apply_header_rewind(&mut rig.st, &rig.hub, &[hp, hb]).unwrap());
    assert_eq!(rig.hub.tip_hash(), Some(rig.tip), "p is disconnected");
    rig.apply_held(&held);
    assert!(!rig.st.reorg.invalid.contains(hb.to_byte_array()));
    assert!(!rig.st.body.is_rejected(&hb));
    rig.hub.accept_block(p.clone()).unwrap();

    let rejects = rig.pump(serve, |st, _, _| {
        st.halt.is_some() || st.reorg.invalid.contains(hb.to_byte_array())
    });
    assert_eq!(rig.st.halt, None, "{rejects:?}");
    assert!(rig.st.reorg.invalid.contains(hb.to_byte_array()));
    assert_eq!(rig.hub.tip_hash(), Some(hp));
    rig.finish();
}

/// A power loss can drop `tx.head` slot pages that the head's synced count
/// still covers. tip+2 spends a tx whose head row was lost that way. The
/// stamp and the fresh read both miss it, but `txid.body` holds it on the
/// connected chain: a store fault, so IBD halts and the hash stays valid.
#[test]
fn spend_of_a_create_the_head_lost_is_not_invalid() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::mine_regtest_paying;

    let mut rig = WireRig::new("lost-head-row", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = WireRig::spend(cbs[0]);
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![parent.clone()],
    );
    rig.hub.accept_block(b1.clone()).unwrap();
    (rig.tip, rig.tip_time) = (b1.block_hash(), b1.header.time);
    let mut rig = rig.restart(rbitcoin_store::testutil::drop_unsynced_tx_head_pages);
    let b2 = mine_regtest_paying(rig.tip, rig.tip_time + 600, t + 2, spk.clone(), vec![]);
    let b3 = mine_regtest_paying(
        b2.block_hash(),
        rig.tip_time + 1200,
        t + 3,
        spk,
        vec![WireRig::spend(parent.compute_txid())],
    );
    let (h2, h3) = (b2.block_hash(), b3.block_hash());
    rig.plant(&[&b2, &b3]);
    rig.start_engine();

    let rejects = rig.pump(
        |_, hash| if hash == h2 { b2.clone() } else { b3.clone() },
        |st, _, _| st.halt.is_some() || st.reorg.invalid.contains(h3.to_byte_array()),
    );
    assert!(rig.st.halt.is_some(), "{rejects:?}");
    assert!(!rig.st.reorg.invalid.contains(h3.to_byte_array()));
    assert!(!rig.st.body.is_rejected(&h3));
    assert_eq!(rig.hub.tip_hash(), Some(h2));
    rig.finish();
}

/// A power loss drops the open `tx.head` tail's slot pages. After the
/// restart, new creates fill that segment and roll it. Until its background
/// seal publishes, the head still reads its rows from the wiped pages, so a
/// spend of a create there misses. `txid.body` holds the create on the
/// connected chain: a store fault, so the block is not marked invalid.
#[test]
fn spend_of_a_create_the_head_lost_before_a_roll_is_not_invalid() {
    use bitcoin::ScriptBuf;
    use rbitcoin_consensus::{mine_empty_regtest, mine_regtest_paying};

    let mut rig = WireRig::new_small_head("lost-head-row-roll", 1);
    let (t, cbs) = (rig.t, rig.cbs.clone());
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = WireRig::spend(cbs[0]);
    let b1 = mine_regtest_paying(
        rig.tip,
        rig.tip_time + 600,
        t + 1,
        spk.clone(),
        vec![parent.clone()],
    );
    rig.hub.accept_block(b1.clone()).unwrap();
    (rig.tip, rig.tip_time) = (b1.block_hash(), b1.header.time);
    let rig = rig.restart(rbitcoin_store::testutil::drop_unsynced_tx_head_pages);
    let WireRig {
        dir,
        hub,
        mut tip,
        mut tip_time,
        cbs,
        ..
    } = rig;
    let segs = || hub.query.store().txs.head_first_fks_snapshot().len();
    let wiped_segs = segs();
    let mut ht = t + 1;
    while segs() == wiped_segs {
        assert!(ht < t + 400, "the wiped tail never rolled");
        ht += 1;
        let b = mine_empty_regtest(tip, tip_time + 600, ht);
        hub.accept_block(b.clone()).unwrap();
        (tip, tip_time) = (b.block_hash(), b.header.time);
    }
    let store = hub.query.store();
    let lost = [parent.compute_txid().to_byte_array()];
    assert!(
        matches!(
            store.connected_in_unsynced_head(store.head_unsynced_first_fk(), &lost, || true),
            Err(rbitcoin_store::StoreError::Cancelled(_))
        ),
        "IBD exit stops the scan, and a stopped scan is not a clear result"
    );
    let mut rig = WireRig::over(dir, hub, 1, (tip, tip_time, cbs));
    let bad = mine_regtest_paying(
        tip,
        tip_time + 600,
        ht + 1,
        spk,
        vec![WireRig::spend(parent.compute_txid())],
    );
    let hb = bad.block_hash();
    rig.plant(&[&bad]);
    rig.start_engine();

    let rejects = rig.pump(
        |_, _| bad.clone(),
        |st, _, _| st.halt.is_some() || st.reorg.invalid.contains(hb.to_byte_array()),
    );
    assert!(rig.st.halt.is_some(), "{rejects:?}");
    assert!(!rig.st.reorg.invalid.contains(hb.to_byte_array()));
    assert!(!rig.st.body.is_rejected(&hb));
    assert_eq!(rig.hub.tip_hash(), Some(tip));
    rig.finish();
}

/// Densify walks past a height once its body is requested or queued. A body
/// refused at intake, and a queued body lookup rejects as soft wire, both
/// put that hash back to missing below the cursor. The next assign must ask
/// for it again, or confirm waits at that height forever.
#[test]
fn ibd_refused_body_is_asked_again() {
    use super::super::assign::dummy_slot;
    use bitcoin::consensus::serialize;
    use rbitcoin_ibd::ibd::assign::{assign_work_ordered, AssignDepth};
    use rbitcoin_ibd::ibd::confirm::{ConfirmEvent, ConfirmFeed};
    use rbitcoin_ibd::ibd::events::{apply_confirm_events, apply_peer_event};
    use rbitcoin_ibd::ibd::path::seed_work_path_from_store;
    use rbitcoin_ibd::ibd::peer_io::PeerEvent;
    use rbitcoin_ibd::ibd::status::LoopStats;
    use rbitcoin_ibd::ibd::IbdConfig;
    use rbitcoin_net::seeds::AddrMan;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU32;
    use std::time::Instant;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("refused-body-reask");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a: Vec<bitcoin::Block> = (1..=4u32).fold(Vec::new(), |mut a, ht| {
        let prev = a.last().map_or(gen, |b: &bitcoin::Block| b.block_hash());
        a.push(mine(prev, ht * 10, ht, vec![]));
        a
    });
    for b in &a {
        hub.ensure_header(&b.header).unwrap();
    }
    let (a1, a2) = (a[0].block_hash(), a[1].block_hash());
    let mut st = IbdWorkState::new(
        (1..=3).map(dummy_slot).collect(),
        hub.tip_hash(),
        hub.tip_height(),
    );
    seed_work_path_from_store(&mut st, &hub);
    let feed = ConfirmFeed::new();
    let mut book = AddrMan::new();
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1);
    let (cfg, stats) = (IbdConfig::for_test(), LoopStats::default());
    let assign = |st: &mut IbdWorkState| {
        assign_work_ordered(st, &hub, &cfg, &stats, AssignDepth::Full, None);
    };
    let owner = |st: &IbdWorkState, hash| *st.inflight[&hash].peers.iter().next().unwrap();
    let mut framed = |st: &mut IbdWorkState, peer, hash, payload| {
        apply_peer_event(
            st,
            &hub,
            PeerEvent::BlockFramed {
                peer,
                hash,
                payload,
                header_fk: None,
            },
            &AtomicU32::new(1),
            &mut book,
            local,
            Some(&feed),
        );
    };
    assign(&mut st);
    assert!(a.iter().all(|b| st.inflight.contains_key(&b.block_hash())));
    assign(&mut st);
    assert!(
        st.densify_scan_lo > 4,
        "densify walked past the requested path"
    );

    // A1's owner answers with the real header and a tx that does not parse.
    let peer = owner(&st, a1);
    let mut junk = serialize(&a[0].header);
    junk.extend_from_slice(&[0x01, 0x01, 0, 0, 0, 0x00, 0x02, 0, 0, 0, 0]);
    framed(&mut st, peer, a1, junk);
    assert!(!st.inflight.contains_key(&a1) && st.body.is_missing(&a1));
    assign(&mut st);
    assert!(st.inflight.contains_key(&a1), "refused body is asked again");

    // A2's body is queued, then lookup rejects it as soft wire.
    let peer = owner(&st, a2);
    framed(&mut st, peer, a2, serialize(&a[1]));
    assert!(st.body.is_pending(&a2) && !st.inflight.contains_key(&a2));
    assign(&mut st);
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(ConfirmEvent::Reject {
        height: 2,
        hash: a2,
        class: ConfirmRejectClass::SoftWire,
        err: "body queue wire does not decode".into(),
        batch_len: 1,
        sender: None,

        parent: RejectParent::default(),
    })
    .unwrap();
    drop(tx);
    apply_confirm_events(
        &mut st,
        &hub,
        &rx,
        &AtomicU32::new(1),
        &AtomicU32::new(0),
        &mut Instant::now(),
        Some(&feed),
    );
    assert!(!hub.query.block_queue_has_height(2) && st.body.is_missing(&a2));
    assign(&mut st);
    assert!(
        st.inflight.contains_key(&a2),
        "soft-rejected body is asked again"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// A requested body and a confirm reject apply from facts already on the event.
#[test]
fn coord_loop_body_and_reject_do_not_read_headers() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use rbitcoin_ibd::ibd::events::apply_peer_event;
    use rbitcoin_ibd::ibd::peer_io::{PeerEvent, PeerSlot};
    use rbitcoin_net::chain::{ensure_header_fk_count, reset_ensure_header_fk_count};
    use rbitcoin_net::seeds::AddrMan;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU32;
    use tokio::sync::mpsc;

    fn dummy_slot(id: usize) -> PeerSlot {
        let (cmd_tx, _rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        PeerSlot {
            id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18444),
            net: rbitcoin_net::NetAddr::from_socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                18444,
            )),
            cmd_tx,
            in_flight: std::collections::HashSet::new(),
            requested: rbitcoin_ibd::ibd::peer_io::solicit_track().0,
            solicited_bytes: rbitcoin_ibd::ibd::peer_io::solicit_track().1,
            solicited_ms: rbitcoin_ibd::ibd::peer_io::solicit_track().2,
            any_rx_ms: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            getdata_wire: rbitcoin_ibd::ibd::peer_io::GetdataWire::new(),
            peer_height: 5,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            rate: Default::default(),
            chain: Default::default(),
            alive: true,
            task,
        }
    }

    fn coinbase(height: u32) -> Transaction {
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(0x00);
        }
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }
    fn shell(prev: BlockHash, height: u32, n: u32) -> Block {
        let header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_000 + n,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: n,
        };
        let mut b = Block {
            header,
            txdata: vec![coinbase(height)],
        };
        b.header.merkle_root = b.compute_merkle_root().unwrap();
        rbitcoin_consensus::grind_regtest_pow(&mut b.header);
        b
    }
    fn ser(b: &Block) -> Vec<u8> {
        let mut v = Vec::new();
        b.consensus_encode(&mut v).unwrap();
        v
    }

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ev-loop-facts");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = shell(gen, 1, 1);
    let h1 = b1.block_hash();
    reset_ensure_header_fk_count();
    rbitcoin_ibd::ibd::reorg::reset_parent_hash_of_count();
    let fk = hub.ensure_header_fk(&b1.header).unwrap();
    let _ = rbitcoin_ibd::ibd::reorg::parent_hash_of(&hub, h1);
    assert!(ensure_header_fk_count() >= 1);
    assert!(rbitcoin_ibd::ibd::reorg::parent_hash_of_count() >= 1);
    reset_ensure_header_fk_count();
    rbitcoin_ibd::ibd::reorg::reset_parent_hash_of_count();

    let mut st = IbdWorkState::new(vec![dummy_slot(1)], Some(gen), Some(0));
    let write_next = AtomicU32::new(1);
    let mut book = AddrMan::new();
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1);
    st.record_height(h1, 1);
    st.inflight
        .insert(h1, rbitcoin_ibd::ibd::state::InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: h1,
            payload: ser(&b1),
            header_fk: Some(fk),
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(st.body.is_pending(&h1), "fk on the event is stored");
    assert!(hub.query.block_queue_has_height(1));

    let absent = h(0x22);
    st.record_height(absent, 2);
    st.inflight
        .insert(absent, rbitcoin_ibd::ibd::state::InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: absent,
            payload: ser(&b1),
            header_fk: None,
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert!(st.body.is_missing(&absent));
    assert!(!st.body.is_pending(&absent));
    assert!(!hub.query.block_queue_has_height(2));

    let rejected = h(0x44);
    apply_confirm_reject_class(
        &mut st,
        1,
        rejected,
        ConfirmRejectClass::ConsensusInvalid,
        "consensus: script verification failed: script false",
        Some(hub.query.as_ref()),
        Some(&hub),
        1,
        None,
        None,
        RejectParent {
            hash: Some(h(0x99)),
            unreadable: false,
        },
    );
    assert!(
        !st.body.is_rejected(&rejected),
        "a parent that is not the tip is a cascade"
    );
    assert_eq!(ensure_header_fk_count(), 0);
    assert_eq!(rbitcoin_ibd::ibd::reorg::parent_hash_of_count(), 0);
    let _ = std::fs::remove_dir_all(dir);
}
