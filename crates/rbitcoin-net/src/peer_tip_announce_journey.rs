use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::GetBlocksMessage;
use bitcoin::p2p::message_compact_blocks::CmpctBlock;
use tokio::sync::broadcast;

enum Ann {
    Headers,
    Inv,
    Skip,
}

fn op_true() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

fn live_peer(
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    port: u16,
    nonce: u64,
    inbound: bool,
) -> std::sync::Arc<crate::peers::LivePeer> {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let conn = if inbound {
        crate::peers::PeerConnType::Inbound
    } else {
        crate::peers::PeerConnType::OutboundFullRelay
    };
    peers.register(addr, addr, &ver, inbound, conn)
}

fn tip_event(hub: &crate::chain::ChainHub, reorg_branch_len: u32) -> crate::chain::TipEvent {
    crate::chain::TipEvent {
        height: hub.tip_height().unwrap(),
        hash: hub.tip_hash().unwrap(),
        header: hub.tip_header().unwrap(),
        reorg_branch_len,
    }
}

fn mine_on(
    prev: BlockHash,
    time: u32,
    height: u32,
    extra: Vec<bitcoin::Transaction>,
) -> bitcoin::Block {
    rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true(), extra)
}

fn mine_child(
    hub: &crate::chain::ChainHub,
    time_offset: u32,
    extra: Vec<bitcoin::Transaction>,
) -> bitcoin::Block {
    mine_on(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time.saturating_add(time_offset),
        hub.tip_height().unwrap().saturating_add(1),
        extra,
    )
}

struct AnnMarks {
    wants_headers: bool,
    sent: Option<BlockHash>,
    known: Option<BlockHash>,
    from_this_peer: bool,
}

fn marks(
    wants_headers: bool,
    sent: Option<BlockHash>,
    known: Option<BlockHash>,
    from_this_peer: bool,
) -> AnnMarks {
    AnnMarks {
        wants_headers,
        sent,
        known,
        from_this_peer,
    }
}

fn assert_ann(
    hub: &crate::chain::ChainHub,
    ev: &crate::chain::TipEvent,
    marks: AnnMarks,
    want: Ann,
    why: &str,
) {
    let got = tip_announce_decision(
        hub,
        ev,
        marks.wants_headers,
        marks.sent,
        marks.known,
        marks.from_this_peer,
    );
    match (got, want) {
        (TipAnnounce::Headers(hs), Ann::Headers) => {
            assert_eq!(hs.len(), 1, "{why}");
            assert_eq!(hs[0].block_hash(), ev.hash, "{why}");
        }
        (TipAnnounce::Inv(h), Ann::Inv) => {
            assert_eq!(h, ev.hash, "{why}");
            let inv = NetworkMessage::Inv(vec![Inventory::Block(h)]);
            assert!(
                matches!(
                    &inv,
                    NetworkMessage::Inv(v) if matches!(v.as_slice(), [Inventory::Block(_)])
                ),
                "{why}: tip announce inv must be MSG_BLOCK, got {inv:?}"
            );
        }
        (TipAnnounce::Skip, Ann::Skip) => {}
        (got, _) => panic!("{why}: got {got:?}"),
    }
}

fn prefilled_n(msg: &NetworkMessage) -> usize {
    match msg {
        NetworkMessage::CmpctBlock(CmpctBlock { compact_block }) => compact_block.prefilled_txs.len(),
        other => panic!("expected cmpctblock, got {other:?}"),
    }
}

fn cmpct_of(msgs: &[NetworkMessage]) -> Vec<BlockHash> {
    msgs.iter()
        .filter_map(|msg| match msg {
            NetworkMessage::CmpctBlock(cb) => Some(cb.compact_block.header.block_hash()),
            _ => None,
        })
        .collect()
}

/// Genesis is still IBD and relay is off. Fee filter is the IBD amount, and
/// `getblocks` of the tip itself must not invent an empty inv.
fn tip_announce_ibd_feefilter_and_empty_inv(hub: &crate::chain::ChainHub) {
    assert!(hub.in_ibd(), "genesis tip is older than 24h");
    assert_eq!(
        outbound_feefilter_sats(hub, None),
        Some(crate::chain::IBD_FEEFILTER_SAT_KVB as i64),
        "IBD feefilter is sent even when relay is off"
    );
    let tip = hub.tip_hash().unwrap();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    handle_peer_inventory_msg(
        &NetworkMessage::GetBlocks(GetBlocksMessage::new(vec![tip], tip)),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .unwrap();
    assert!(out_rx.try_recv().is_err(), "no headers means no inv");
}

/// Headers peer gets one header. Inv peer gets `MSG_BLOCK`, not a witness inv.
fn tip_announce_headers_versus_inv(hub: &crate::chain::ChainHub) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 1,
    };
    let ev = crate::chain::TipEvent {
        height: 1,
        hash: header.block_hash(),
        header,
        reorg_branch_len: 0,
    };
    assert_ann(
        hub,
        &ev,
        marks(true, None, None, false),
        Ann::Headers,
        "headers peer gets the header",
    );
    assert_ann(
        hub,
        &ev,
        marks(false, None, None, false),
        Ann::Inv,
        "inv peer gets MSG_BLOCK",
    );
}

/// `Lagged` and a queued tip whose hash is no longer the hub tip both
/// announce the current tip.
fn tip_announce_recv_coalesces_to_tip(hub: &crate::chain::ChainHub) {
    use rbitcoin_primitives::Height;
    let want = hub.tip_hash().unwrap();
    let height = hub.tip_height().unwrap();
    let TipRecvAnnounce::Announce(ev) =
        tip_event_for_announce(Err(broadcast::error::RecvError::Lagged(99)), hub)
    else {
        panic!("Lagged must re-announce current tip, not drop");
    };
    assert_eq!(ev.hash, want);
    assert_eq!(ev.height, height);
    assert_eq!(ev.reorg_branch_len, 0);
    let mid = hub.query.wire_header_at_height(Height(5)).unwrap();
    let TipRecvAnnounce::Announce(ev) = tip_event_for_announce(
        Ok(crate::chain::TipEvent {
            height: 5,
            hash: mid.block_hash(),
            header: mid,
            reorg_branch_len: 0,
        }),
        hub,
    ) else {
        panic!("stale TipEvent must coalesce to current tip");
    };
    assert_eq!(ev.hash, want);
    assert_eq!(ev.height, height);
}

/// A stale `TipEvent` compact-announces the current tip, not the lagged hash.
async fn tip_announce_compact_is_current_tip_only(hub: &crate::chain::ChainHub) {
    use rbitcoin_primitives::Height;
    let mid = hub.query.wire_header_at_height(Height(5)).unwrap();
    let tip_hash = hub.tip_hash().unwrap();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    follow.wants_headers = true;
    on_tip_event(
        hub,
        &out_tx,
        &mut follow,
        None,
        Ok(crate::chain::TipEvent {
            height: 5,
            hash: mid.block_hash(),
            header: mid,
            reorg_branch_len: 0,
        }),
    )
    .await
    .unwrap();
    let stale = cmpct_of(&take_msgs(&mut out_rx));
    assert!(
        !stale.contains(&mid.block_hash()),
        "stale tip event must not compact-announce the lagged hash"
    );
    assert!(
        stale.contains(&tip_hash),
        "stale tip event must coalesce to a current-tip compact announce"
    );
    on_tip_event(hub, &out_tx, &mut follow, None, Ok(tip_event(hub, 0)))
        .await
        .unwrap();
    assert!(
        cmpct_of(&take_msgs(&mut out_rx)).contains(&tip_hash),
        "current-tip event to an HB peer must compact-announce"
    );
}

/// Compact is one-block tip relay: the peer must already have `pprev`.
async fn tip_announce_compact_requires_parent(hub: &crate::chain::ChainHub) {
    use rbitcoin_primitives::Height;
    let behind = hub
        .query
        .wire_header_at_height(Height(3))
        .unwrap()
        .block_hash();
    let parent = hub.tip_header().unwrap().prev_blockhash;
    let ev = tip_event(hub, 0);
    let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let sess_behind = live_peer(&peers, 18444, 1, false);
    sess_behind.note_best_known(behind);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    follow.wants_headers = true;
    on_tip_event(hub, &out_tx, &mut follow, Some(&sess_behind), Ok(ev.clone()))
        .await
        .unwrap();
    assert!(
        cmpct_of(&take_msgs(&mut out_rx)).is_empty(),
        "HB compact is tip-relay: a peer behind pprev must get headers, not cmpctblock"
    );
    let sess_parent = live_peer(&peers, 18445, 2, false);
    sess_parent.note_best_known(parent);
    on_tip_event(hub, &out_tx, &mut follow, Some(&sess_parent), Ok(ev))
        .await
        .unwrap();
    assert!(
        cmpct_of(&take_msgs(&mut out_rx)).contains(&hub.tip_hash().unwrap()),
        "peer that has pprev must get the compact tip announce"
    );
}

/// A peer within eight headers gets headers. The same hash is not sent twice.
/// A peer who only has the parent gets one header.
fn tip_announce_near_marks_are_headers(hub: &crate::chain::ChainHub) {
    let parent = hub.tip_header().unwrap().prev_blockhash;
    let ev = tip_event(hub, 0);
    assert_ann(
        hub,
        &ev,
        marks(true, Some(parent), None, false),
        Ann::Headers,
        "tip-extend should be headers",
    );
    assert_ann(
        hub,
        &ev,
        marks(true, Some(parent), None, true),
        Ann::Skip,
        "from-this-peer must skip",
    );
    assert_ann(
        hub,
        &ev,
        marks(true, Some(ev.hash), None, false),
        Ann::Skip,
        "already sent this hash must skip",
    );
    assert_ann(
        hub,
        &ev,
        marks(true, None, Some(parent), false),
        Ann::Headers,
        "known prev must headers",
    );
}

/// Depth 5 is still compact. One deeper is a full block. A full block then
/// releases the pending compact-fill slot.
async fn tip_announce_depth_and_fill_slot(hub: &crate::chain::ChainHub) {
    use rbitcoin_primitives::Height;
    let tip_h = hub.tip_height().unwrap();
    let near = hub
        .query
        .wire_header_at_height(Height(tip_h - 5))
        .unwrap()
        .block_hash();
    let deep = hub
        .query
        .wire_header_at_height(Height(tip_h - 6))
        .unwrap()
        .block_hash();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    serve_getdata(hub, &out_tx, &mut follow, None, &[Inventory::CompactBlock(near)])
        .await
        .unwrap();
    assert!(
        matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::CmpctBlock(_)
        ),
        "depth 5 is still a compact block"
    );
    serve_getdata(hub, &out_tx, &mut follow, None, &[Inventory::CompactBlock(deep)])
        .await
        .unwrap();
    assert!(
        matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::Block(_)
        ),
        "depth 6 is a full block"
    );

    let hash = hub.tip_hash().unwrap();
    let block = hub
        .query
        .reconstruct_block_at_height(Height(tip_h))
        .unwrap();
    let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let session = live_peer(&peers, 18446, 3, true);
    assert!(session.try_cmpct_fill(hash));
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(hash);
    handle_peer_frame(
        frame_for(NetworkMessage::Block(block)),
        hub,
        &out_tx,
        &mut follow,
        Some(&session),
    )
    .await
    .unwrap();
    assert!(
        session.try_cmpct_fill(hash),
        "full block must release the pending compact fill slot"
    );
}

/// Tip announces do not `fetch_add` or `fetch_sub` `serve_inflight`. The
/// writer still saturating-subs every `cmpctblock`, so an unpaired decrement
/// must stay at zero and a burst must not fill the reconstruct cap.
async fn tip_announce_serve_inflight_untouched(hub: &crate::chain::ChainHub) {
    use std::sync::atomic::Ordering;
    let hash = hub.tip_hash().unwrap();
    let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();

    let wrap = live_peer(&peers, 18447, 4, false);
    let msg = cmpct_announce_msg(hub, &hash, 2).expect("cmpct announce");
    queue_cmpct_tip_announce(&out_tx, msg).unwrap();
    note_served_write(&wrap.serve_inflight);
    assert_eq!(
        wrap.serve_inflight.load(Ordering::SeqCst),
        0,
        "unpaired announce write must saturating-sub, not wrap"
    );
    while out_rx.try_recv().is_ok() {}
    let mut follow = hb_follow();
    handle_peer_frame(
        frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(hash)])),
        hub,
        &out_tx,
        &mut follow,
        Some(&wrap),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            out_rx.try_recv().map(PeerOut::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "getdata MSG_CMPCT_BLOCK must still serve after a compact tip announce"
    );

    let slots = live_peer(&peers, 18448, 5, false);
    for _ in 0..MAX_SERVE_BLOCKS {
        let msg = cmpct_announce_msg(hub, &hash, 2).expect("cmpct announce");
        queue_cmpct_tip_announce(&out_tx, msg).unwrap();
    }
    assert_eq!(
        slots.serve_inflight.load(Ordering::SeqCst),
        0,
        "announce must not occupy reconstruct slots"
    );
    while out_rx.try_recv().is_ok() {}
    let mut follow = hb_follow();
    handle_peer_frame(
        frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(hash)])),
        hub,
        &out_tx,
        &mut follow,
        Some(&slots),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            out_rx.try_recv().map(PeerOut::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "getdata MSG_CMPCT_BLOCK must still serve after a burst of compact announces"
    );
}

fn hb_follow() -> PeerFollowState {
    let mut follow = PeerFollowState::new();
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    follow
}

/// `-prefillcompact` packs the remembered indexes on announce and on getdata.
/// A bad index falls back to the coinbase. The send is logged.
async fn tip_announce_prefill_knob(hub: &crate::chain::ChainHub) {
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    let tip = hub.tip_hash().unwrap();
    let cb = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap()
        .txdata[0]
        .compute_txid();
    let extra = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_0000),
            script_pubkey: op_true(),
        }],
    };
    let block = mine_child(hub, 600, vec![extra]);
    let hash = block.block_hash();
    let prev = block.header.prev_blockhash;
    assert_eq!(prev, tip);

    let off = cmpct_announce_from_block(hub, &block, 2).expect("announce");
    assert_eq!(prefilled_n(&off), 1, "default coinbase-only");

    hub.set_prefill_compact(true);
    hub.remember_cmpct_prefill(hash, prev, vec![0, 1]);
    rbitcoin_log::capture_logs(true);
    let on = cmpct_announce_from_block(hub, &block, 2).expect("announce on");
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert_eq!(prefilled_n(&on), 2, "knob on packs extra index");
    let NetworkMessage::CmpctBlock(CmpctBlock {
        compact_block: on_hsi,
    }) = &on
    else {
        panic!("announce on");
    };
    let want = crate::compact::cmpct_send_line(hash, block.txdata.len(), on_hsi);
    assert!(
        logs.iter().any(|(_, m)| m == &want),
        "outbound prefill must be logged at send, got {logs:?}"
    );

    hub.remember_cmpct_prefill(hash, prev, vec![0, 99]);
    let fallback = cmpct_announce_from_block(hub, &block, 2)
        .expect("invalid prefill indexes must not drop announce");
    assert_eq!(prefilled_n(&fallback), 1, "InvalidPrefill falls back to coinbase");
    hub.remember_cmpct_prefill(hash, prev, vec![0, 1]);

    match hub.accept_received_block(block) {
        Ok(crate::chain::AcceptOutcome::Accepted { .. }) => {}
        other => panic!("2-tx block must connect: {other:?}"),
    }

    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = hb_follow();
    handle_peer_frame(
        frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(hash)])),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    let served = out_rx.try_recv().expect("getdata cmpct").expect_msg();
    assert_eq!(prefilled_n(&served), 2, "getdata uses the same plan");

    hub.set_prefill_compact(false);
    let off_again = cmpct_announce_msg(hub, &hash, 2).expect("announce off");
    assert_eq!(prefilled_n(&off_again), 1);
}

/// PoW-valid compact is relayed to other HB peers before connect. An invalid
/// body does not become tip, and the sender is not announced back to.
async fn tip_announce_hb_relays_before_connect(hub: &crate::chain::ChainHub) {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    let cb = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap()
        .txdata[0]
        .compute_txid();
    let bad = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from_height(500_000).unwrap(),
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_0000),
            script_pubkey: op_true(),
        }],
    };
    let block = mine_child(hub, 600, vec![bad]);
    let hash = block.block_hash();
    assert_ne!(hub.tip_hash(), Some(hash), "must not connect before relay");
    let pref: Vec<usize> = (0..block.txdata.len()).collect();
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &pref).expect("hsi");

    let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let a = live_peer(&peers, 18449, 6, false);
    let b = live_peer(&peers, 18450, 7, false);
    b.set_hb_to(true);
    let (a_tx, mut a_rx) = mpsc::unbounded_channel();
    let (b_tx, mut b_rx) = mpsc::unbounded_channel();
    a.attach_out(a_tx.clone());
    b.attach_out(b_tx);
    let mut follow = hb_follow();
    follow.wtxid_relay = true;
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        })),
        hub,
        &a_tx,
        &mut follow,
        Some(&a),
    )
    .await
    .expect("invalid compact must keep the session");
    assert_ne!(hub.tip_hash(), Some(hash), "non-final body must not become tip");
    assert!(
        cmpct_of(&take_msgs(&mut b_rx)).contains(&hash),
        "HB peer must get cmpctblock before/without successful connect"
    );
    assert!(
        cmpct_of(&take_msgs(&mut a_rx)).is_empty(),
        "sender must not receive our compact announce"
    );
}

/// Compact prefills must not feed `extra_compact`. `blocktxn` bodies do.
async fn tip_announce_blocktxn_feeds_extra(hub: &crate::chain::ChainHub) {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
    use bitcoin::block::{Header, Version};
    use bitcoin::p2p::message_compact_blocks::BlockTxn;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    };
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: op_true(),
        }],
    };
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: op_true(),
        }],
    };
    let mut block = bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: hub.tip_hash().unwrap(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase.clone(), spend.clone()],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[0, 1]).unwrap();
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        })),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    let mp = hub.mempool().unwrap();
    let pref = mp
        .try_cmpct_fill_sets(&[coinbase.clone(), spend.clone()])
        .expect("fill");
    assert!(
        !pref.extra.contains(&spend.compute_wtxid()),
        "cmpct prefill must not feed extra_compact"
    );
    assert!(
        !pref.extra.contains(&coinbase.compute_wtxid()),
        "coinbase must not occupy extra_compact"
    );
    let other = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x33; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![2]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: op_true(),
        }],
    };
    handle_peer_frame(
        frame_for(NetworkMessage::BlockTxn(BlockTxn {
            transactions: BlockTransactions {
                block_hash: BlockHash::from_byte_array([0xdd; 32]),
                transactions: vec![other.clone()],
            },
        })),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    let fetched = mp
        .try_cmpct_fill_sets(std::slice::from_ref(&other))
        .expect("fill");
    assert!(
        fetched.extra.contains(&other.compute_wtxid()),
        "blocktxn bodies must feed extra_compact"
    );
}

/// After `sendcmpct` version 2, a header whose parent is the tip is
/// `MSG_CMPCT_BLOCK` getdata.
async fn tip_announce_header_getdata_is_compact(hub: &crate::chain::ChainHub) {
    let block = mine_child(hub, 50, vec![]);
    let hash = block.block_hash();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = hb_follow();
    handle_peer_frame(
        frame_for(NetworkMessage::Headers(vec![block.header])),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    let inv = take_msgs(&mut out_rx).into_iter().find_map(|msg| match msg {
        NetworkMessage::GetData(inv) => Some(inv),
        _ => None,
    });
    let inv = inv.expect("getdata");
    assert!(
        matches!(inv.as_slice(), [Inventory::CompactBlock(h)] if *h == hash),
        "expected MSG_CMPCT_BLOCK getdata, got {inv:?}"
    );
}

/// A headers-only parent is already known. The peer's child header is
/// getdata, not another getheaders.
async fn tip_announce_submitheader_child_getdata(hub: &crate::chain::ChainHub) {
    let parent = mine_child(hub, 70, vec![]);
    hub.process_submitted_header(&parent.header).unwrap();
    assert!(hub.knows_header(&parent.block_hash()));
    assert!(!hub.is_connected(&parent.block_hash()));
    let child = mine_on(
        parent.block_hash(),
        parent.header.time.saturating_add(1),
        hub.tip_height().unwrap().saturating_add(2),
        vec![],
    );
    hub.process_submitted_header(&child.header).unwrap();
    assert!(!hub.is_connected(&child.block_hash()));
    let want = child.block_hash();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    handle_peer_frame(
        frame_for(NetworkMessage::Headers(vec![child.header])),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    let msgs = take_msgs(&mut out_rx);
    assert!(
        msgs.iter().all(|msg| !matches!(msg, NetworkMessage::GetHeaders(_))),
        "headers-only parent must not getheaders"
    );
    let saw = msgs.iter().any(|msg| match msg {
        NetworkMessage::GetData(inv) => inv.iter().any(|i| match i {
            Inventory::WitnessBlock(h) | Inventory::Block(h) | Inventory::CompactBlock(h) => {
                *h == want
            }
            _ => false,
        }),
        _ => false,
    });
    assert!(saw, "expected getdata for submitheader child {want}");
}

/// Unsolicited compact more than two above the validated tip is a header
/// announcement: no reconstruct, no `getblocktxn`.
async fn tip_announce_far_compact_is_header_only(hub: &crate::chain::ChainHub) {
    use bitcoin::bip152::HeaderAndShortIds;
    let tip_h = hub.tip_height().unwrap();
    let mut prev = hub.tip_hash().unwrap();
    let mut time = hub.tip_header().unwrap().time;
    let mut far = None;
    for i in 1..=3u32 {
        time = time.saturating_add(80 + i);
        let block = mine_on(prev, time, tip_h + i, vec![]);
        hub.ensure_header(&block.header).unwrap();
        prev = block.block_hash();
        far = Some(block);
    }
    let far = far.unwrap();
    let far_h = far.block_hash();
    assert_eq!(hub.header_height(&far_h), Some(tip_h + 3));
    let hsi = HeaderAndShortIds::from_block(&far, 1, 2, &[0]).unwrap();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = hb_follow();
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        })),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    assert!(
        follow.pending_cmpct.is_empty(),
        "far compact must not wait on blocktxn"
    );
    assert!(
        hub.held_body(&far_h).is_none(),
        "unsolicited compact 3 above tip must not reconstruct into held"
    );
    assert_eq!(hub.tip_height(), Some(tip_h));
    assert!(
        take_msgs(&mut out_rx)
            .iter()
            .all(|msg| !matches!(msg, NetworkMessage::GetBlockTxn(_))),
        "far compact must not getblocktxn"
    );
}

/// Same-hash cached invalid stays connected. A child of a cached-invalid
/// parent disconnects. An out-of-range prefilled index disconnects.
async fn tip_announce_invalid_compact_disconnects(hub: &crate::chain::ChainHub) {
    use bitcoin::bip152::{HeaderAndShortIds, PrefilledTransaction};
    use rbitcoin_primitives::Height;
    let tip = hub.tip_hash().unwrap();
    let failed = BlockHash::from_byte_array([0x11; 32]);
    hub.note_invalid_block(failed);
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let gen = hub
        .query
        .reconstruct_block_at_height(Height(0))
        .unwrap();
    let mut cached = HeaderAndShortIds::from_block(&gen, 1, 2, &[0]).unwrap();
    cached.header.prev_blockhash = tip;
    hub.note_invalid_block(cached.header.block_hash());
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: cached,
        })),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    assert_eq!(follow.ban_score, 0, "cached invalid compact must stay connected");

    let mut child = HeaderAndShortIds::from_block(&gen, 2, 2, &[0]).unwrap();
    child.header.prev_blockhash = failed;
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: child,
        })),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "child of cached-invalid parent must disconnect"
    );

    follow.ban_score = 0;
    let bad_idx = HeaderAndShortIds {
        header: gen.header,
        nonce: 0,
        short_ids: vec![],
        prefilled_txs: vec![PrefilledTransaction {
            idx: 1,
            tx: gen.txdata[0].clone(),
        }],
    };
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: bad_idx,
        })),
        hub,
        &out_tx,
        &mut follow,
        None,
    )
    .await
    .unwrap();
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "out-of-range prefilled index must disconnect"
    );
}

/// First merkle-mutated unique fill asks for the block and does not
/// `BLOCK_FAILED` the header. The second disconnects.
async fn tip_announce_merkle_second_cmpct_disconnects(hub: &crate::chain::ChainHub) {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let child = mine_child(hub, 90, vec![]);
    let mut hsi = HeaderAndShortIds::from_block(&child, 1, 2, &[0]).unwrap();
    hsi.prefilled_txs[0].tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: op_true(),
        }],
    };
    let hash = hsi.header.block_hash();
    assert!(!hub.has_block(&hash));
    let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let session = live_peer(&peers, 18451, 8, true);
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let frame = frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
        compact_block: hsi,
    }));
    handle_peer_frame(frame.clone(), hub, &out_tx, &mut follow, Some(&session))
        .await
        .unwrap();
    assert_eq!(follow.ban_score, 0, "first merkle-mutated unique fill GetData");
    assert!(
        session.has_failed_cmpct(&hash),
        "unique-fill merkle fail must count as a failed compact"
    );
    assert!(
        !hub.is_block_invalid(&hash),
        "merkle-mutated compact must not BLOCK_FAILED the header"
    );
    handle_peer_frame(frame, hub, &out_tx, &mut follow, Some(&session))
        .await
        .unwrap();
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "second merkle-mutated unique fill must disconnect"
    );
    assert!(
        !hub.is_block_invalid(&hash),
        "still not BLOCK_FAILED after disconnect"
    );
}

/// After a reorg longer than eight blocks, announce inv until the peer's
/// best header is on the new chain.
fn tip_announce_reorg_inv_until_caught_up(hub: &crate::chain::ChainHub) {
    use rbitcoin_primitives::Height;
    let sent_tip = hub.tip_hash().unwrap();
    let fork_h = hub.tip_height().unwrap() - 4;
    let fork = hub.query.wire_header_at_height(Height(fork_h)).unwrap();
    let mut prev = fork.block_hash();
    let mut time = fork.time;
    let mut branch = Vec::with_capacity(9);
    for i in 0..9u32 {
        time = time.saturating_add(1);
        let block = mine_on(prev, time, fork_h + 1 + i, vec![]);
        prev = block.block_hash();
        branch.push(block);
    }
    hub.accept_branch(&branch).unwrap();
    let reorg_ev = tip_event(hub, 9);
    assert_ne!(reorg_ev.hash, sent_tip);
    assert_ann(
        hub,
        &reorg_ev,
        marks(true, Some(sent_tip), None, false),
        Ann::Inv,
        "large reorg must inv tip",
    );
    hub.generate_to_script(1, op_true(), vec![]).unwrap();
    let after = tip_event(hub, 0);
    assert_ann(
        hub,
        &after,
        marks(true, Some(sent_tip), None, false),
        Ann::Inv,
        "still far from sent mark must inv",
    );
    assert_ann(
        hub,
        &after,
        marks(true, Some(after.hash), None, false),
        Ann::Skip,
        "already sent this hash must skip",
    );
    assert_ann(
        hub,
        &after,
        marks(true, None, Some(after.header.prev_blockhash), false),
        Ann::Headers,
        "known prev must headers",
    );
}

/// One peer at the tip. Header/inv announce, compact relay, and HB compact
/// before connect share this hub so a catch-up reorg pad is not paid again.
#[tokio::test]
async fn peer_tip_announce() {
    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("tip-announce");
    hub.ensure_genesis().unwrap();
    let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
        .unwrap();
    mp.set_relay_enabled(false);
    assert!(hub.attach_mempool(mp).is_ok());

    tip_announce_ibd_feefilter_and_empty_inv(&hub);
    hub.mempool().unwrap().set_relay_enabled(true);
    tip_announce_headers_versus_inv(&hub);

    hub.generate_to_script(102, op_true(), vec![]).unwrap();
    tip_announce_recv_coalesces_to_tip(&hub);
    tip_announce_compact_is_current_tip_only(&hub).await;
    tip_announce_compact_requires_parent(&hub).await;
    tip_announce_near_marks_are_headers(&hub);
    tip_announce_depth_and_fill_slot(&hub).await;
    tip_announce_serve_inflight_untouched(&hub).await;
    tip_announce_prefill_knob(&hub).await;
    tip_announce_hb_relays_before_connect(&hub).await;
    tip_announce_blocktxn_feeds_extra(&hub).await;
    tip_announce_header_getdata_is_compact(&hub).await;
    tip_announce_submitheader_child_getdata(&hub).await;
    tip_announce_far_compact_is_header_only(&hub).await;
    tip_announce_invalid_compact_disconnects(&hub).await;
    tip_announce_merkle_second_cmpct_disconnects(&hub).await;
    tip_announce_reorg_inv_until_caught_up(&hub);

    let _ = std::fs::remove_dir_all(dir);
}
