enum Ann {
    Headers,
    Inv,
    Skip,
}

fn op_true() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

struct TipAnnouncePad {
    store: rbitcoin_query::testutil::TempDir,
    // Confirmed-set seed still reads the builder store after that hub drops.
    _built: rbitcoin_query::testutil::TempDir,
}

/// Height-102 regtest, built once. Each announce case opens a private copy.
fn tip_announce_pad() -> &'static TipAnnouncePad {
    use std::sync::OnceLock;
    static PAD: OnceLock<TipAnnouncePad> = OnceLock::new();
    PAD.get_or_init(|| {
        let (built, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tip-announce-build");
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(102, op_true(), vec![]).unwrap();
        hub.query.flush().expect("flush tip-announce pad");
        let store = rbitcoin_query::testutil::TempDir::labeled("tip-announce-pad")
            .expect("tip pad");
        copy_store_tree(built.path(), store.path());
        TipAnnouncePad {
            store,
            _built: built,
        }
    })
}

fn copy_store_tree(src: &std::path::Path, dst: &std::path::Path) {
    rbitcoin_store::testutil::copy_store_tree(src, dst);
}

fn open_tip_announce_hub(
    label: &str,
) -> (rbitcoin_query::testutil::TempDir, rbitcoin_net::chain::ChainHub) {
    let src = tip_announce_pad();
    let dir = rbitcoin_query::testutil::TempDir::labeled(label).expect("tip copy");
    copy_store_tree(src.store.path(), dir.path());
    let q = rbitcoin_query::Query::open_or_create_tiny(dir.path()).expect("open tip copy");
    let hub = rbitcoin_net::chain::ChainHub::new(
        q,
        rbitcoin_consensus::ChainParams::regtest(),
        rbitcoin_consensus::Milestone::NONE,
    );
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
        .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    (dir, hub)
}

fn open_genesis_announce(
    label: &str,
    relay: bool,
) -> (rbitcoin_query::testutil::TempDir, rbitcoin_net::chain::ChainHub) {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
        .unwrap();
    mp.set_relay_enabled(relay);
    assert!(hub.attach_mempool(mp).is_ok());
    (dir, hub)
}


fn live_peer(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
    nonce: u64,
    inbound: bool,
) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
    let conn = if inbound {
        rbitcoin_net::peers::PeerConnType::Inbound
    } else {
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay
    };
    live_peer_as(peers, port, nonce, conn)
}

fn live_peer_as(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
    nonce: u64,
    conn: rbitcoin_net::peers::PeerConnType,
) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
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
    let inbound = conn == rbitcoin_net::peers::PeerConnType::Inbound;
    peers.register(addr, addr, &ver, inbound, conn)
}

fn tip_event(hub: &rbitcoin_net::chain::ChainHub, reorg_branch_len: u32) -> rbitcoin_net::chain::TipEvent {
    rbitcoin_net::chain::TipEvent {
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
    hub: &rbitcoin_net::chain::ChainHub,
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
    hub: &rbitcoin_net::chain::ChainHub,
    ev: &rbitcoin_net::chain::TipEvent,
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
#[test]
fn tip_announce_ibd_feefilter_and_empty_inv() {
    let (_dir, hub) = open_genesis_announce("tip-ibd", false);
    let hub = &hub;
    assert!(hub.in_ibd(), "genesis tip is older than 24h");
    assert_eq!(
        outbound_feefilter_sats(hub, None),
        Some(rbitcoin_net::chain::IBD_FEEFILTER_SAT_KVB as i64),
        "IBD feefilter is sent even when relay is off"
    );
    let tip = hub.tip_hash().unwrap();
    let gb = GetBlocksMessage::new(vec![tip], tip);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let sync = handle_peer_inventory_msg(
        &NetworkMessage::GetBlocks(gb.clone()),
        hub,
        &out_tx,
        &mut follow,
        None,
    );
    assert!(
        sync.is_err(),
        "header work is not on the sync inventory path"
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("getblocks runtime")
        .block_on(on_getblocks(hub, &out_tx, &mut follow, None, &gb))
        .expect("getblocks");
    assert!(out_rx.try_recv().is_err(), "no headers means no inv");
}

/// Headers peer gets one header. Inv peer gets `MSG_BLOCK`, not a witness inv.
#[test]
fn tip_announce_headers_versus_inv() {
    let (_dir, hub) = open_genesis_announce("tip-hdr-inv", true);
    let hub = &hub;
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
    let ev = rbitcoin_net::chain::TipEvent {
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
#[test]
fn tip_announce_recv_coalesces_to_tip() {
    let (_dir, hub) = open_tip_announce_hub("tip-recv-coalesces-to-tip");
    let hub = &hub;
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
        Ok(rbitcoin_net::chain::TipEvent {
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
#[tokio::test]
async fn tip_announce_compact_is_current_tip_only() {
    let (_dir, hub) = open_tip_announce_hub("tip-compact-is-current-tip-only");
    let hub = &hub;
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
        Ok(rbitcoin_net::chain::TipEvent {
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
#[tokio::test]
async fn tip_announce_compact_requires_parent() {
    let (_dir, hub) = open_tip_announce_hub("tip-compact-requires-parent");
    let hub = &hub;
    use rbitcoin_primitives::Height;
    let behind = hub
        .query
        .wire_header_at_height(Height(3))
        .unwrap()
        .block_hash();
    let parent = hub.tip_header().unwrap().prev_blockhash;
    let ev = tip_event(hub, 0);
    let peers = rbitcoin_net::peers::PeerHub::new();
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
#[test]
fn tip_announce_near_marks_are_headers() {
    let (_dir, hub) = open_tip_announce_hub("tip-near-marks-are-headers");
    let hub = &hub;
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
#[tokio::test]
async fn tip_announce_depth_and_fill_slot() {
    let (_dir, hub) = open_tip_announce_hub("tip-depth-and-fill-slot");
    let hub = &hub;
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
    serve_getdata(hub, &out_tx, &mut follow, None, vec![Inventory::CompactBlock(near)])
        .await
        .unwrap();
    assert!(
        matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::CmpctBlock(_)
        ),
        "depth 5 is still a compact block"
    );
    serve_getdata(hub, &out_tx, &mut follow, None, vec![Inventory::CompactBlock(deep)])
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
    let peers = rbitcoin_net::peers::PeerHub::new();
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

/// Tip announces take no `serve_inflight` slot and the writer frees none
/// for them, so a burst must not fill the reconstruct cap. A double free
/// of a getdata slot saturates at zero instead of wrapping.
#[tokio::test]
async fn tip_announce_serve_inflight_untouched() {
    let (_dir, hub) = open_tip_announce_hub("tip-serve-inflight-untouched");
    let hub = &hub;
    use std::sync::atomic::Ordering;
    let hash = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();

    let wrap = live_peer(&peers, 18447, 4, false);
    wrap.serve_inflight.store(1, Ordering::SeqCst);
    let msg = cmpct_announce_msg(hub, &hash, 2).expect("cmpct announce");
    queue_cmpct_tip_announce(&out_tx, msg).unwrap();
    let announce = out_rx.try_recv().unwrap();
    wrap.note_out_written(
        announce.holds_serve_slot(),
        rbitcoin_net::peers::outbound_queued_bytes(&announce),
    );
    assert_eq!(
        wrap.serve_inflight.load(Ordering::SeqCst),
        1,
        "a written announce frees no getdata slot"
    );
    wrap.free_serve_slot();
    wrap.free_serve_slot();
    assert_eq!(
        wrap.serve_inflight.load(Ordering::SeqCst),
        0,
        "a double free saturates, not wraps"
    );
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
#[tokio::test]
async fn tip_announce_prefill_knob() {
    let (_dir, hub) = open_tip_announce_hub("tip-prefill-knob");
    let hub = &hub;
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
    let want = rbitcoin_net::compact::cmpct_send_line(hash, block.txdata.len(), on_hsi);
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
        Ok(rbitcoin_net::chain::AcceptOutcome::Accepted { .. }) => {}
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

/// PoW-valid compact is relayed before connect to peers who asked for it
/// (`sendcmpct` announce=1) and already have the parent. A peer we only
/// selected as a compact source, a peer still missing the parent, and the
/// sender do not get that announce. An invalid body does not become tip.
#[tokio::test]
async fn tip_announce_hb_relays_before_connect() {
    let (_dir, hub) = open_tip_announce_hub("tip-hb-relays-before-connect");
    let hub = &hub;
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

    let parent = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let a = live_peer(&peers, 18449, 6, false);
    a.set_hb_to(true);
    let asked = live_peer(&peers, 18450, 7, false);
    asked.set_hb_from(true);
    asked.note_best_known(parent);
    let selected = live_peer(&peers, 18451, 8, false);
    selected.set_hb_to(true);
    selected.note_best_known(parent);
    let behind = live_peer(&peers, 18452, 9, false);
    behind.set_hb_from(true);
    let (a_tx, mut a_rx) = mpsc::unbounded_channel();
    let (asked_tx, mut asked_rx) = mpsc::unbounded_channel();
    let (selected_tx, mut selected_rx) = mpsc::unbounded_channel();
    let (behind_tx, mut behind_rx) = mpsc::unbounded_channel();
    a.attach_out(a_tx.clone());
    asked.attach_out(asked_tx);
    selected.attach_out(selected_tx);
    behind.attach_out(behind_tx);
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
        cmpct_of(&take_msgs(&mut asked_rx)).contains(&hash),
        "peer who sent sendcmpct(1) and has the parent must get cmpctblock before connect"
    );
    assert!(
        cmpct_of(&take_msgs(&mut selected_rx)).is_empty(),
        "a peer we only selected with sendcmpct(1) is a source, not an announce target"
    );
    assert!(
        cmpct_of(&take_msgs(&mut behind_rx)).is_empty(),
        "sendcmpct(1) without the parent header is not a compact tip announce"
    );
    assert!(
        cmpct_of(&take_msgs(&mut a_rx)).is_empty(),
        "sender must not receive our compact announce"
    );
}

/// Compact prefills must not feed `extra_compact`. `blocktxn` bodies do.
#[tokio::test]
async fn tip_announce_blocktxn_feeds_extra() {
    let (_dir, hub) = open_tip_announce_hub("tip-blocktxn-feeds-extra");
    let hub = &hub;
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
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
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
#[tokio::test]
async fn tip_announce_header_getdata_is_compact() {
    let (_dir, hub) = open_tip_announce_hub("tip-header-getdata-is-compact");
    let hub = &hub;
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
#[tokio::test]
async fn tip_announce_submitheader_child_getdata() {
    let (_dir, hub) = open_tip_announce_hub("tip-submitheader-child-getdata");
    let hub = &hub;
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
#[tokio::test]
async fn tip_announce_far_compact_is_header_only() {
    let (_dir, hub) = open_tip_announce_hub("tip-far-compact-is-header-only");
    let hub = &hub;
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
/// parent disconnects. Every Core `InitData` invalid shape disconnects,
/// requested or unsolicited: an out-of-range prefilled index, no txs at all,
/// a prefilled null tx sent as wire bytes, and differentials whose absolute
/// index passes 65,535. Core's decoder drops more than 65,535 txs, or a
/// witness-flag prefill with no inputs, with no score; so do we. 65,535 txs stays connected and asks for its txs.
#[tokio::test]
async fn tip_announce_invalid_compact_disconnects() {
    let (_dir, hub) = open_tip_announce_hub("tip-invalid-compact-disconnects");
    let hub = &hub;
    use bitcoin::bip152::{HeaderAndShortIds, PrefilledTransaction};
    use rbitcoin_primitives::Height;
    let tip = hub.tip_hash().unwrap();
    let failed = BlockHash::from_byte_array([0x11; 32]);
    hub.note_invalid_block(failed);
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = hb_follow();
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

    let u16_max = usize::from(u16::MAX);
    let zero = bitcoin::bip152::ShortId::from([0u8; 6]);
    let mut offset = 100u32;
    let mut child_hsi = |short_n: usize, prefill_idx: &[u16]| {
        offset += 1;
        let child = mine_child(hub, offset, vec![]);
        HeaderAndShortIds {
            header: child.header,
            nonce: 0,
            short_ids: vec![zero; short_n],
            prefilled_txs: prefill_idx
                .iter()
                .map(|&idx| PrefilledTransaction {
                    idx,
                    tx: child.txdata[0].clone(),
                })
                .collect(),
        }
    };
    for requested in [true, false] {
        let path = if requested { "requested" } else { "unsolicited tip child" };
        let (follow, _) = send_cmpct_once(hub, child_hsi(0, &[]), requested).await;
        assert!(
            follow.ban_score >= BAN_SCORE_THRESHOLD,
            "{path}: no short ids and no prefilled txs must disconnect"
        );
        let (follow, msgs) = send_cmpct_once(hub, child_hsi(u16_max - 1, &[0]), requested).await;
        assert_eq!(follow.ban_score, 0, "{path}: 65,535 txs stays connected");
        assert!(
            msgs.iter().any(|m| matches!(m, NetworkMessage::GetBlockTxn(_))),
            "{path}: 65,535 txs still asks for its missing txs"
        );
        let (follow, msgs) = send_cmpct_once(hub, child_hsi(u16_max, &[0]), requested).await;
        assert_eq!(follow.ban_score, 0, "{path}: 65,536 txs is dropped with no score");
        assert!(msgs.is_empty(), "{path}: 65,536 txs is dropped silently, got {} messages", msgs.len());
    }
    let (follow, msgs) = send_cmpct_once(hub, child_hsi(u16_max + 1, &[0, u16::MAX]), true).await;
    assert_eq!(follow.ban_score, 0, "65,538 txs with a prefill at 65,536 is dropped with no score");
    assert!(msgs.is_empty(), "65,538 txs is dropped silently, got {} messages", msgs.len());
    let (follow, _) = send_cmpct_once(hub, child_hsi(1, &[0, u16::MAX]), true).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "differentials 0 and 65,535 in a 3-tx block decode and must disconnect"
    );

    // Core reads an empty vin, then flags 0, and leaves vout empty: IsNull.
    let null_tx = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let (follow, _) = send_cmpct_raw_first_prefill(hub, child_hsi(1, &[0]), &null_tx, false).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "a prefilled null tx on the wire must disconnect"
    );
    // Flag 1 with an empty vin: Core throws "Superfluous witness record".
    let witness_flag_empty = [2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let (follow, msgs) =
        send_cmpct_raw_first_prefill(hub, child_hsi(1, &[0]), &witness_flag_empty, true).await;
    assert_eq!(follow.ban_score, 0, "flag 1 with no inputs and no outputs is dropped with no score");
    assert!(msgs.is_empty(), "flag 1 with no inputs and no outputs is dropped silently");
    let witness_flag_one_out = [2, 0, 0, 0, 0, 1, 0, 1, 232, 3, 0, 0, 0, 0, 0, 0, 1, 81, 0, 0, 0, 0];
    let (follow, msgs) =
        send_cmpct_raw_first_prefill(hub, child_hsi(1, &[0]), &witness_flag_one_out, true).await;
    assert_eq!(follow.ban_score, 0, "flag 1 with no inputs is dropped with no score");
    assert!(msgs.is_empty(), "flag 1 with no inputs is dropped silently, got {} messages", msgs.len());
}

/// `hsi`'s header and short ids as `cmpctblock` payload bytes on a live
/// session, with `raw` as prefill 0 and `hsi`'s coinbase as prefill 1.
async fn send_cmpct_raw_first_prefill(
    hub: &rbitcoin_net::chain::ChainHub,
    hsi: HeaderAndShortIds,
    raw: &[u8],
    requested: bool,
) -> (PeerFollowState, Vec<NetworkMessage>) {
    let mut payload = bitcoin::consensus::serialize(&HeaderAndShortIds {
        prefilled_txs: vec![],
        ..hsi.clone()
    });
    assert_eq!(payload.pop(), Some(0), "the prefilled count is the last byte");
    payload.extend_from_slice(&[2, 0]);
    payload.extend_from_slice(raw);
    payload.push(0);
    payload.extend(bitcoin::consensus::serialize(&hsi.prefilled_txs[0].tx));
    let peers = rbitcoin_net::peers::PeerHub::new();
    let session = live_peer(&peers, 18631, 71, true);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = hb_follow();
    if requested {
        follow.requested_blocks.insert(hsi.header.block_hash());
    }
    handle_peer_frame(
        FramedMessage {
            magic: Magic::from(Network::Regtest),
            command: *b"cmpctblock\0\0",
            payload,
        },
        hub,
        &out_tx,
        &mut follow,
        Some(&session),
    )
    .await
    .unwrap();
    (follow, take_msgs(&mut out_rx))
}

/// One `cmpctblock` on a fresh follow state. `requested` marks the block as
/// asked for; otherwise it arrives unsolicited.
async fn send_cmpct_once(
    hub: &rbitcoin_net::chain::ChainHub,
    hsi: bitcoin::bip152::HeaderAndShortIds,
    requested: bool,
) -> (PeerFollowState, Vec<NetworkMessage>) {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = hb_follow();
    if requested {
        follow.requested_blocks.insert(hsi.header.block_hash());
    }
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
    (follow, take_msgs(&mut out_rx))
}

/// First merkle-mutated unique fill asks for the block and does not
/// `BLOCK_FAILED` the header. The second disconnects.
#[tokio::test]
async fn tip_announce_merkle_second_cmpct_disconnects() {
    let (_dir, hub) = open_tip_announce_hub("tip-merkle-second-cmpct-disconnects");
    let hub = &hub;
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
    let peers = rbitcoin_net::peers::PeerHub::new();
    let session = live_peer(&peers, 18451, 8, true);
    session.set_hb_to(true);
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = hb_follow();
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

/// A nine-block branch whose last block fails keeps its eight-block valid
/// prefix. That tip is an eight-block reorg: headers, not inv.
#[test]
fn tip_announce_kept_prefix_of_failed_reorg_is_headers() {
    let (_dir, hub) = open_tip_announce_hub("tip-kept-prefix-of-failed-reorg");
    let hub = &hub;
    use rbitcoin_primitives::Height;
    let sent_tip = hub.tip_hash().unwrap();
    let fork_h = hub.tip_height().unwrap() - 4;
    let fork = hub.query.wire_header_at_height(Height(fork_h)).unwrap();
    let mut prev = fork.block_hash();
    let mut time = fork.time;
    let mut branch = Vec::with_capacity(9);
    for i in 0..9u32 {
        time = time.saturating_add(1);
        let bip34_height = fork_h + 1 + i + if i == 8 { 100 } else { 0 };
        // The pad is mined at wall-clock times, so an `op_true` coinbase at
        // `fork.time + 1` can be the main-chain block itself.
        let block = rbitcoin_consensus::mine_regtest_paying(
            prev,
            time,
            bip34_height,
            ScriptBuf::from_bytes(vec![0x52]),
            vec![],
        );
        prev = block.block_hash();
        branch.push(block);
    }
    let mut tips = hub.subscribe_tips();
    let err = hub
        .accept_branch(&branch)
        .expect_err("the last block has a wrong BIP34 height");
    assert_eq!(
        err.failing_block_hash(),
        Some(branch[8].block_hash().to_byte_array())
    );
    let kept = branch[7].block_hash();
    assert_eq!(hub.tip_hash(), Some(kept));
    let mut last = None;
    while let Ok(ev) = tips.try_recv() {
        last = Some(ev);
    }
    let ev = last.expect("the kept prefix emits tip events");
    assert_eq!(ev.hash, kept);
    match tip_announce_decision(hub, &ev, true, Some(sent_tip), None, false) {
        TipAnnounce::Headers(hs) => {
            assert_eq!(hs.len(), 8);
            assert_eq!(hs[0].prev_blockhash, fork.block_hash());
            assert_eq!(hs[7].block_hash(), kept);
        }
        other => panic!("kept eight-block prefix must announce headers: {other:?}"),
    }
}

/// After a reorg longer than eight blocks, announce inv until the peer's
/// best header is on the new chain.
#[test]
fn tip_announce_reorg_inv_until_caught_up() {
    let (_dir, hub) = open_tip_announce_hub("tip-reorg-inv-until-caught-up");
    let hub = &hub;
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

/// A tip child with a tx no mempool holds, so a reconstruct must ask for it.
fn tip_child_missing_tx(hub: &rbitcoin_net::chain::ChainHub, time_offset: u32) -> bitcoin::Block {
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x33; 32]),
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
    mine_child(hub, time_offset, vec![spend])
}

/// One `cmpctblock` (coinbase prefilled) from `peer`. `requested` marks the
/// block as asked for from this session; otherwise it arrives unsolicited.
async fn cmpct_from_peer(
    hub: &rbitcoin_net::chain::ChainHub,
    peer: &rbitcoin_net::peers::LivePeer,
    mut follow: PeerFollowState,
    block: &bitcoin::Block,
    requested: bool,
) -> (PeerFollowState, Vec<NetworkMessage>) {
    use bitcoin::bip152::HeaderAndShortIds;
    let hsi = HeaderAndShortIds::from_block(block, 0xbeef, 2, &[0]).unwrap();
    if requested {
        follow.requested_blocks.insert(block.block_hash());
    }
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        })),
        hub,
        &out_tx,
        &mut follow,
        Some(peer),
    )
    .await
    .unwrap();
    (follow, take_msgs(&mut out_rx))
}

fn asks_blocktxn(msgs: &[NetworkMessage]) -> bool {
    msgs.iter()
        .any(|m| matches!(m, NetworkMessage::GetBlockTxn(_)))
}

/// Core #32606: an unsolicited compact block from a peer we did not send
/// `sendcmpct(1)` is a header announcement. The header is stored and the
/// body is fetched with a full-block `getdata`. Nothing is reconstructed:
/// no `getblocktxn`, and a complete compact block does not connect.
#[tokio::test]
async fn tip_announce_unsolicited_cmpct_from_lb_peer_is_header_announce() {
    let (_dir, hub) = open_tip_announce_hub("tip-unsolicited-cmpct-lb-peer");
    let hub = &hub;
    let tip = hub.tip_hash().unwrap();
    let tip_h = hub.tip_height().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let lb = live_peer(&peers, 18600, 60, false);
    let lb2 = live_peer(&peers, 18608, 68, false);
    assert!(!lb.hb_to.load(Ordering::Relaxed));
    for (why, block) in [
        ("missing tx", tip_child_missing_tx(hub, 61)),
        ("complete", mine_child(hub, 62, vec![])),
    ] {
        let hash = block.block_hash();
        let (follow, msgs) = cmpct_from_peer(hub, &lb, hb_follow(), &block, false).await;
        assert!(!asks_blocktxn(&msgs), "{why}: non-HB unsolicited must not getblocktxn: {msgs:?}");
        assert!(follow.pending_cmpct.is_empty(), "{why}: no partial block kept");
        assert_eq!(hub.tip_hash(), Some(tip), "{why}: the compact block must not connect");
        assert!(hub.held_body(&hash).is_none(), "{why}: no reconstructed body held");
        assert_eq!(
            hub.header_height(&hash),
            Some(tip_h + 1),
            "{why}: the header is stored like a headers announcement"
        );
        assert_eq!(
            getdata_of(&msgs),
            vec![(hash, false)],
            "{why}: the body is a full-block getdata to this peer"
        );
        assert!(follow.requested_blocks.contains(&hash), "{why}: the getdata is in flight");
        assert_eq!(follow.ban_score, 0, "{why}: an unsolicited compact block is not misbehavior");
        let (second, msgs) = cmpct_from_peer(hub, &lb2, hb_follow(), &block, false).await;
        assert!(
            getdata_of(&msgs).is_empty(),
            "{why}: a second peer's copy does not ask again: {msgs:?}"
        );
        assert!(!second.requested_blocks.contains(&hash));
    }
}

/// The full-block ask from an unsolicited compact block is one claim on the
/// hub. A session over its send budget neither sends nor claims it, and a
/// send that fails releases the claim, so the next peer's copy asks.
#[tokio::test]
async fn tip_announce_unsolicited_cmpct_ask_is_one_claim() {
    use bitcoin::bip152::HeaderAndShortIds;
    let (_dir, hub) = open_tip_announce_hub("tip-unsolicited-cmpct-ask-claim");
    let hub = &hub;
    let peers = rbitcoin_net::peers::PeerHub::new();
    let full = live_peer(&peers, 18605, 65, false);
    let closed = live_peer(&peers, 18606, 66, false);
    let open = live_peer(&peers, 18607, 67, false);
    let block = mine_child(hub, 71, vec![]);
    let hash = block.block_hash();

    full.note_send_queued(rbitcoin_net::peers::PEER_SEND_BUDGET + 1);
    assert!(full.send_over_budget());
    let (follow, msgs) = cmpct_from_peer(hub, &full, hb_follow(), &block, false).await;
    assert!(getdata_of(&msgs).is_empty(), "spent send budget sends no getdata: {msgs:?}");
    assert!(!follow.requested_blocks.contains(&hash));
    assert!(!hub.already_have_or_asked_block(&hash), "spent budget claims nothing");
    assert!(hub.knows_header(&hash), "the header is still stored");
    full.note_send_written(full.send_queued());

    let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[0]).unwrap();
    let (closed_tx, closed_rx) = mpsc::unbounded_channel();
    drop(closed_rx);
    let mut follow = hb_follow();
    let sent = handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        })),
        hub,
        &closed_tx,
        &mut follow,
        Some(&closed),
    )
    .await;
    assert!(sent.is_err(), "a closed writer fails the send");
    assert!(!follow.requested_blocks.contains(&hash));
    assert!(!hub.already_have_or_asked_block(&hash), "a failed send releases the claim");

    let (follow, msgs) = cmpct_from_peer(hub, &open, hb_follow(), &block, false).await;
    assert_eq!(getdata_of(&msgs), vec![(hash, false)], "the next peer's copy asks");
    assert!(follow.requested_blocks.contains(&hash));
}

/// A peer we selected with `sendcmpct(1)` still pushes compact blocks we
/// reconstruct: a missing tx is a `getblocktxn`, a complete block connects.
#[tokio::test]
async fn tip_announce_unsolicited_cmpct_from_hb_peer_reconstructs() {
    let (_dir, hub) = open_tip_announce_hub("tip-unsolicited-cmpct-hb-peer");
    let hub = &hub;
    let peers = rbitcoin_net::peers::PeerHub::new();
    let hb = live_peer(&peers, 18601, 61, false);
    hb.set_hb_to(true);
    let missing = tip_child_missing_tx(hub, 63);
    let (follow, msgs) = cmpct_from_peer(hub, &hb, hb_follow(), &missing, false).await;
    assert!(asks_blocktxn(&msgs), "HB unsolicited missing a tx asks for it: {msgs:?}");
    assert!(follow.pending_cmpct.contains_key(&missing.block_hash()));
    let complete = mine_child(hub, 64, vec![]);
    let (_, msgs) = cmpct_from_peer(hub, &hb, hb_follow(), &complete, false).await;
    assert!(getdata_of(&msgs).is_empty(), "a complete HB compact block needs no getdata: {msgs:?}");
    assert_eq!(hub.tip_hash(), Some(complete.block_hash()), "HB compact block connects");
}

/// A compact block this session asked for is reconstructed from any peer,
/// selected for high-bandwidth or not.
#[tokio::test]
async fn tip_announce_requested_cmpct_from_lb_peer_reconstructs() {
    let (_dir, hub) = open_tip_announce_hub("tip-requested-cmpct-lb-peer");
    let hub = &hub;
    let peers = rbitcoin_net::peers::PeerHub::new();
    let lb = live_peer(&peers, 18602, 62, false);
    let missing = tip_child_missing_tx(hub, 65);
    let (follow, msgs) = cmpct_from_peer(hub, &lb, hb_follow(), &missing, true).await;
    assert!(asks_blocktxn(&msgs), "requested compact missing a tx asks for it: {msgs:?}");
    assert!(follow.pending_cmpct.contains_key(&missing.block_hash()));
    let complete = mine_child(hub, 66, vec![]);
    let (_, msgs) = cmpct_from_peer(hub, &lb, hb_follow(), &complete, true).await;
    assert!(getdata_of(&msgs).is_empty(), "a complete requested compact needs no getdata: {msgs:?}");
    assert_eq!(hub.tip_hash(), Some(complete.block_hash()), "requested compact block connects");
}

/// `-blocksonly` ignores every compact block, even a push from a peer
/// marked high-bandwidth and even one this session asked for. The header is
/// not read either (Core returns before header processing).
#[tokio::test]
async fn tip_announce_blocksonly_ignores_hb_cmpct() {
    let (_dir, hub) = open_tip_announce_hub("tip-blocksonly-ignores-hb-cmpct");
    let hub = &hub;
    hub.set_blocks_only(true);
    let tip = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let hb = live_peer(&peers, 18603, 63, false);
    hb.set_hb_to(true);
    for requested in [false, true] {
        for block in [tip_child_missing_tx(hub, 67), mine_child(hub, 68, vec![])] {
            let hash = block.block_hash();
            let (follow, msgs) = cmpct_from_peer(hub, &hb, hb_follow(), &block, requested).await;
            assert!(msgs.is_empty(), "requested={requested}: blocksonly sends nothing: {msgs:?}");
            assert!(follow.pending_cmpct.is_empty());
            assert_eq!(hub.tip_hash(), Some(tip), "requested={requested}: no connect");
            assert!(!hub.knows_header(&hash), "requested={requested}: header not read");
        }
    }
}

/// Core #32606: a peer that never sent `sendcmpct` version 2 gets its
/// `cmpctblock` ignored before the header is read, requested or not, even
/// if it holds a high-bandwidth slot.
#[tokio::test]
async fn tip_announce_cmpct_without_sendcmpct_is_ignored() {
    let (_dir, hub) = open_tip_announce_hub("tip-cmpct-without-sendcmpct");
    let hub = &hub;
    let tip = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let hb = live_peer(&peers, 18604, 64, false);
    hb.set_hb_to(true);
    for requested in [false, true] {
        for block in [tip_child_missing_tx(hub, 69), mine_child(hub, 70, vec![])] {
            let hash = block.block_hash();
            let (follow, msgs) =
                cmpct_from_peer(hub, &hb, PeerFollowState::new(), &block, requested).await;
            assert!(msgs.is_empty(), "requested={requested}: nothing sent: {msgs:?}");
            assert!(follow.pending_cmpct.is_empty());
            assert_eq!(follow.ban_score, 0, "requested={requested}: not misbehavior");
            assert_eq!(hub.tip_hash(), Some(tip), "requested={requested}: no connect");
            assert!(!hub.knows_header(&hash), "requested={requested}: header not read");
        }
    }
}

