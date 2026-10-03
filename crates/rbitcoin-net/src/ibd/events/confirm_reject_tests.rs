//! Tests for super:: events helpers (peeled from events.rs).

use super::super::confirm::ConfirmRejectClass;
use super::super::state::IbdWorkState;
use super::apply_confirm_reject as apply_confirm_reject_class;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
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
    hub: Option<&crate::chain::ChainHub>,
) {
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
    );
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
    ];
    for (s, want) in cases {
        assert_eq!(ConfirmRejectClass::from_err_str(s), *want, "{s}");
    }
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::BadPrev),
        ConfirmRejectClass::SoftWire
    );
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::BadBlock("merkle root mismatch")),
        ConfirmRejectClass::SoftWire
    );
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
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::from(StoreError::Cancelled("stop"))),
        ConfirmRejectClass::Cancelled
    );
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::PrevoutSpent),
        ConfirmRejectClass::ConsensusInvalid
    );
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::Store(StoreError::Corrupt(
            "tx put_full_batch fk mismatch (plan not committed in order)"
        ))),
        ConfirmRejectClass::Cascade
    );
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::Store(StoreError::Corrupt(
            "invariant: spend annotate missing pin denserels/abs"
        ))),
        ConfirmRejectClass::EngineFault
    );
    assert_eq!(
        ConfirmRejectClass::from_consensus(&ConsensusError::Store(StoreError::Corrupt(
            "invariant: io_uring undrained"
        ))),
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

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("multi-hop-ready");
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

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("multi-hop");
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

    // Loser path: gen → L1 → L2 (tip).
    let l1 = mine(gen, 1_400_000_100, 1);
    hub.accept_block(l1.clone()).unwrap();
    let l2 = mine(l1.block_hash(), 1_400_000_200, 2);
    hub.accept_block(l2.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(2));
    assert_eq!(hub.tip_hash().unwrap(), l2.block_hash());

    // Heavier path: gen → W1 → W2 → W3 (headers; bodies staged).
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
    use super::super::peer_io::{PeerEvent, PeerSlot};
    use super::super::state::InflightReq;
    use super::{apply_peer_event, drain_ready_peer_and_body_events, inject_learned_addrs};
    use crate::seeds::AddrMan;
    use bitcoin::block::{Header, Version};
    use bitcoin::CompactTarget;

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
            net: crate::NetAddr::from_socket(a),
            cmd_tx,
            in_flight: HashSet::new(),
            peer_height: 10,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
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

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("ev-apply");
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
        super::super::assign::issue_one(&mut st, 1, notfound_hash, &mut room, &mut issued),
        "notfound does not ban the peer"
    );
    assert!(st.slots[0].in_flight.contains(&notfound_hash));

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

    // Addrs + inject filter.
    inject_learned_addrs(&mut book, &[], local, 1);
    inject_learned_addrs(
        &mut book,
        &[
            crate::NetAddr::Ip(addr(2)),
            crate::NetAddr::Ip(local),
            crate::NetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1)),
        ],
        local,
        1,
    );
    assert!(book.entry(&addr(2)).is_some());
    let onion: crate::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    inject_learned_addrs(&mut book, &[onion], local, 1);
    assert!(
        book.entries().iter().any(|e| e.addr == onion),
        "IBD addrv2 onion must enter the dial book"
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

    // Drain empty channels.
    let (body_tx, mut body_rx) = mpsc::unbounded_channel();
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel();
    let stats = super::super::status::LoopStats::default();
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
    use super::super::peer_io::{PeerEvent, PeerSlot};
    use super::{apply_peer_event, drain_ready_peer_and_body_events, inject_learned_addrs};
    use crate::seeds::AddrMan;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::Encodable;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };

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
            net: crate::NetAddr::from_socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                18444,
            )),
            cmd_tx,
            in_flight: HashSet::new(),
            peer_height: 5,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
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

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("ev-block");
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
        .insert(h1, super::super::state::InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: h1,
            payload: ser(&b1),
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
        },
        &write_next,
        &mut book,
        local,
        None,
    );
    assert_eq!(hub.query.block_queue_stats().2, 1);

    let b2 = shell(h1, 2, 2);
    let h2 = b2.block_hash();
    st.record_height(h2, 2);
    st.header_fks
        .insert(h2, hub.ensure_header_fk(&b2.header).unwrap());
    st.inflight
        .insert(h2, super::super::state::InflightReq::new(1));
    hub.query.set_lookup_taken_hi(Some(2));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: h2,
            payload: ser(&b2),
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

    let far_h = 1u32 + super::super::CONTIG_DENSIFY_AHEAD + 10;
    let far = shell(h1, far_h, far_h);
    let far_hash = far.block_hash();
    st.record_height(far_hash, far_h);
    st.inflight
        .insert(far_hash, super::super::state::InflightReq::new(1));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlockFramed {
            peer: 1,
            hash: far_hash,
            payload: ser(&far),
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

    use super::super::MAX_PEER_POOL;
    for i in 0..MAX_PEER_POOL {
        book.add(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(11, 0, (i / 256) as u8, (i % 256) as u8)),
            8333,
        ));
    }
    let n0 = book.len();
    inject_learned_addrs(
        &mut book,
        &[crate::NetAddr::Ip(SocketAddr::new(
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
            addrs: vec![crate::NetAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                8333,
            ))],
        })
        .unwrap();
    let stats = super::super::status::LoopStats::default();
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
    use super::super::assign::tests::{dummy_slot, lock_default_assign_stop};
    use super::super::assign::{assign_work_ordered, AssignDepth};
    use super::super::confirm::{ConfirmEvent, ConfirmFeed};
    use super::super::exit::header_lag_behind_peers;
    use super::super::path::seed_work_path_from_store;
    use super::super::peer_io::PeerEvent;
    use super::super::progress::tip_fetch_hole;
    use super::super::reorg::maybe_rewind_to_best_work;
    use super::super::state::InflightReq;
    use super::super::status::LoopStats;
    use super::super::IbdConfig;
    use super::{apply_confirm_events, apply_peer_event, try_complete_awaiting_reorg};
    use crate::seeds::AddrMan;
    use bitcoin::consensus::serialize;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU32;
    use std::time::{Duration, Instant};

    let _env = lock_default_assign_stop();
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("bad-prev-fork");
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

    // IBD restarts. A1's body arrives raw and is redelivered: one body-queue
    // row, one confirm-feed note.
    let mut st = IbdWorkState::new(vec![dummy_slot(1)], Some(gen), Some(0));
    let feed = ConfirmFeed::new();
    st.record_height(a1, 1);
    st.header_fks
        .insert(a1, hub.ensure_header_fk(&a[0].header).unwrap());
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
            },
            &write_next,
            &mut book,
            local,
            Some(&feed),
        );
        assert!(st.body.is_pending(&a1) && st.inflight.is_empty());
        assert_eq!(hub.query.block_queue_stats().2, 1);
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
        },
    );
    assert!(st.body.is_rejected(&h(12)));
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

    // Blacklist or not: zero hash ignored; script failure and a spent
    // prevout are permanent; store invariants are engine faults (halt on the
    // second); fk mismatch requeues; bad wire and a retarget miss re-get.
    let mut st = fresh();
    let zero = BlockHash::all_zeros();
    apply_confirm_reject(
        &mut st,
        t + 1,
        zero,
        "consensus: prevout already spent on best chain",
        None,
        None,
    );
    assert!(!st.body.is_rejected(&zero));
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

    // With the hub: a post-lookup reject rewinds lookup to the tip, except
    // cancel. An engine fault neither isolates nor rewinds.
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), Some(t));
    st.record_height(h(0x5a), t + 2);
    for (err, rewind) in [
        ("consensus: bad block: merkle root mismatch", true),
        ("consensus: store: corrupt record: archive: parent create_fk unresolved (contiguous batch required)", false),
        ("invariant: create.loc hole after count", false),
        ("connect height not tip+1", true),
        ("consensus: prevout already spent on best chain", true),
        ("confirm cancelled", false),
    ] {
        hub.query.set_lookup_taken_hi(Some(t + 2));
        hub.query.set_lookup_started_hi(Some(t + 2));
        assert!(hub.query.lookup_already_taken(t + 2));
        apply_confirm_reject(&mut st, t + 2, h(0x5a), err, q, Some(&hub));
        let want = if rewind { Some(t) } else { Some(t + 2) };
        assert_eq!(hub.query.lookup_taken_hi(), want, "{err}");
        if rewind {
            assert_eq!(hub.query.lookup_started_hi(), Some(t), "{err}");
            assert!(!hub.query.lookup_already_taken(t + 2), "{err}");
        }
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
    assert!(try_complete_awaiting_reorg(&mut st, &hub));
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
