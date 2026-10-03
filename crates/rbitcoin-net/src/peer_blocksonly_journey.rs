fn relay_peer(
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    ip: [u8; 4],
    conn: crate::peers::PeerConnType,
) -> std::sync::Arc<crate::peers::LivePeer> {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), 18444);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let inbound = conn == crate::peers::PeerConnType::Inbound;
    peers.register(addr, addr, &ver, inbound, conn)
}

fn writer_of(sess: &crate::peers::LivePeer) -> mpsc::UnboundedReceiver<PeerOut> {
    let (tx, rx) = mpsc::unbounded_channel();
    sess.attach_out(tx);
    rx
}

fn spend_coinbase(hub: &crate::chain::ChainHub, height: u32) -> bitcoin::Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};
    let cb = hub
        .query
        .reconstruct_block_at_height(Height(height))
        .unwrap()
        .txdata[0]
        .compute_txid();
    bitcoin::Transaction {
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
            script_pubkey: op_true(),
        }],
    }
}

fn orphan_of(parents: &[bitcoin::OutPoint]) -> bitcoin::Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Sequence, TxIn, TxOut, Witness};
    bitcoin::Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: parents
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: op_true(),
        }],
    }
}

fn tx_invs(rx: &mut mpsc::UnboundedReceiver<PeerOut>) -> Vec<bitcoin::Wtxid> {
    let mut out = Vec::new();
    for msg in take_msgs(rx) {
        match msg {
            NetworkMessage::Inv(v) => {
                for i in v {
                    match i {
                        Inventory::WTx(w) => out.push(w),
                        other => panic!("expected WTx inv, got {other:?}"),
                    }
                }
            }
            other => panic!("expected tx INV, got {other:?}"),
        }
    }
    out
}

fn getdata_txs(rx: &mut mpsc::UnboundedReceiver<PeerOut>) -> Vec<Inventory> {
    take_msgs(rx)
        .into_iter()
        .filter_map(|m| match m {
            NetworkMessage::GetData(v) => Some(v),
            _ => None,
        })
        .flatten()
        .collect()
}

fn set_relay_clock(hub: &crate::chain::ChainHub, peers: &crate::peers::PeerHub, now: u64) {
    peers.set_mock(now);
    hub.mempool().unwrap().note_mock_now(now);
}

fn wtx_getdata(tx: &bitcoin::Transaction) -> NetworkMessage {
    NetworkMessage::GetData(vec![Inventory::WTx(tx.compute_wtxid())])
}

/// Relay off: a peer without the relay permission that sends a tx or a
/// wtx inv is disconnected (`p2p_blocksonly`).
async fn blocksonly_p2p_tx_disconnects(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
) {
    let sess = relay_peer(peers, [127, 0, 0, 1], crate::peers::PeerConnType::Inbound);
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let tx = orphan_of(&[bitcoin::OutPoint::null()]);
    let mut follow = PeerFollowState::new();
    push(hub, &out_tx, &mut follow, Some(sess.as_ref()), NetworkMessage::Tx(tx)).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "blocksonly tx must disconnect, ban={}",
        follow.ban_score
    );

    let mut follow = PeerFollowState::new();
    let inv = NetworkMessage::Inv(vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array(
        [0x34; 32],
    ))]);
    push(hub, &out_tx, &mut follow, Some(sess.as_ref()), inv).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "blocksonly wtx inv must disconnect, ban={}",
        follow.ban_score
    );
    peers.unregister(sess.id);
}

/// Relay off: an RPC sendraw is announced only once it is unbroadcast.
/// Then a peer with a writer gets the INV at once, an inbound peer on its
/// next tick, a block-relay peer never, and the announced wtx serves.
async fn blocksonly_sendraw_invs_inbound(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    tx: &bitcoin::Transaction,
) {
    let mp = hub.mempool().unwrap();
    let mut ann_rx = mp.subscribe_announces();
    mp.accept_tx(tx).expect("sendraw accept");
    assert_eq!(
        ann_rx.try_recv().expect("accept publishes announce").txid,
        tx.compute_txid()
    );
    assert!(
        !mp.is_unbroadcast(&tx.compute_txid()),
        "unbroadcast is noted only after accept_tx returns (sendraw)"
    );
    mp.note_unbroadcast(tx.compute_txid());

    let first = relay_peer(peers, [127, 0, 0, 1], crate::peers::PeerConnType::Inbound);
    let mut first_rx = writer_of(&first);
    flush_tx_invs(hub, peers.as_ref());
    assert_eq!(
        tx_invs(&mut first_rx),
        vec![tx.compute_wtxid()],
        "unbroadcast INV without clock_due"
    );

    let inbound = relay_peer(peers, [127, 0, 0, 1], crate::peers::PeerConnType::Inbound);
    let block_relay = relay_peer(peers, [127, 0, 0, 1], crate::peers::PeerConnType::BlockRelay);
    peers.request_all_tx_inv();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    queue_due_tx_invs(hub, inbound.as_ref(), &CappedSet::new(), &out_tx);
    assert_eq!(tx_invs(&mut out_rx), vec![tx.compute_wtxid()]);
    queue_due_tx_invs(hub, block_relay.as_ref(), &CappedSet::new(), &out_tx);
    assert!(
        out_rx.try_recv().is_err(),
        "block-relay-only must not get tx INV"
    );

    let mut follow = PeerFollowState::new();
    follow.wtxid_relay = true;
    push(hub, &out_tx, &mut follow, Some(inbound.as_ref()), wtx_getdata(tx)).await;
    match take_msgs(&mut out_rx).as_slice() {
        [NetworkMessage::Tx(got)] => assert_eq!(got.compute_wtxid(), tx.compute_wtxid()),
        other => panic!("getdata must serve tx, got {other:?}"),
    }
    for s in [first, inbound, block_relay] {
        peers.unregister(s.id);
    }
}

/// Relay off: a `relay` whitelisted peer's tx is accepted, not punished,
/// and INV'd to the other inbound peer (`p2p_blocksonly.py:74`).
async fn blocksonly_relay_perm_tx_invs_other_inbound(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    tx: &bitcoin::Transaction,
) {
    let mut table = crate::net_permissions::NetPermTable::default();
    table
        .whitelist
        .push(crate::net_permissions::parse_whitelist("relay@127.0.0.2").unwrap());
    peers.set_net_perms(table);
    let listed = relay_peer(peers, [127, 0, 0, 2], crate::peers::PeerConnType::Inbound);
    let other = relay_peer(peers, [127, 0, 0, 1], crate::peers::PeerConnType::Inbound);
    assert!(listed.session_relay_perm());
    assert!(!other.session_relay_perm());
    let mut other_rx = writer_of(&other);

    let (out_tx, _rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.wtxid_relay = true;
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(listed.as_ref()),
        NetworkMessage::Tx(tx.clone()),
    )
    .await;
    assert_eq!(follow.ban_score, 0, "whitelist relay must not disconnect");
    assert!(hub.mempool().unwrap().is_unbroadcast(&tx.compute_txid()));
    assert!(follow.from_this_peer.contains_key(&tx.compute_txid()));
    assert_eq!(
        tx_invs(&mut other_rx),
        vec![tx.compute_wtxid()],
        "second inbound gets only the unbroadcast wtx"
    );
    peers.unregister(listed.id);
    peers.unregister(other.id);
}

/// `p2p_getdata.py`: inv type 0 is ignored without a reply or a ban, and
/// the tip block still serves after it.
async fn getdata_type0_then_tip_block(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
) {
    let sess = relay_peer(peers, [127, 0, 0, 1], crate::peers::PeerConnType::Inbound);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let type0 = NetworkMessage::GetData(vec![Inventory::Unknown {
        inv_type: 0,
        hash: [0u8; 32],
    }]);
    push(hub, &out_tx, &mut follow, Some(sess.as_ref()), type0).await;
    assert_eq!(follow.ban_score, 0, "type-0 getdata must not disconnect");
    assert!(
        out_rx.try_recv().is_err(),
        "type-0 getdata must not emit a reply"
    );

    let tip = hub.tip_hash().unwrap();
    let block = NetworkMessage::GetData(vec![Inventory::Block(tip)]);
    push(hub, &out_tx, &mut follow, Some(sess.as_ref()), block).await;
    assert_eq!(
        served_block(out_rx.try_recv().expect("tip getdata must serve")).block_hash(),
        tip
    );
    peers.unregister(sess.id);
}

/// A block confirms the relay-off txs, but the mempool keeps them until
/// relay turns on. Tip-mode entry purges them in one pass.
fn relay_on_purges_confirmed(hub: &crate::chain::ChainHub, confirmed: Vec<bitcoin::Transaction>) {
    let mp = hub.mempool().unwrap();
    let n = confirmed.len();
    assert_eq!(mp.live_count(), n);
    hub.generate_to_script(1, op_true(), confirmed).unwrap();
    assert_eq!(mp.live_count(), n, "relay off defers the per-block remove");
    mp.set_relay_enabled(true);
    assert_eq!(mp.live_count(), 0, "relay on purges what the chain confirmed");
}

/// `force_announce_txid` INVs only to a full-relay peer with a writer that
/// has not seen the wtx and whose feefilter the tx clears. Isolated
/// broadcast keeps a local-origin tx off standing peers until it confirms.
fn force_announce_picks_peers(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    heights: [u32; 3],
) {
    use crate::peers::PeerConnType::{BlockRelay, OutboundFullRelay};
    let mp = hub.mempool().unwrap();
    let relayed = spend_coinbase(hub, heights[0]);
    let local = spend_coinbase(hub, heights[1]);
    let from_p2p = spend_coinbase(hub, heights[2]);
    let missing = bitcoin::Txid::from_byte_array([0x11; 32]);

    let block_relay = relay_peer(peers, [127, 0, 0, 1], BlockRelay);
    let mut block_relay_rx = writer_of(&block_relay);
    let no_writer = relay_peer(peers, [127, 0, 0, 1], OutboundFullRelay);
    let seen = relay_peer(peers, [127, 0, 0, 1], OutboundFullRelay);
    let mut seen_rx = writer_of(&seen);
    let pricey = relay_peer(peers, [127, 0, 0, 1], OutboundFullRelay);
    let mut pricey_rx = writer_of(&pricey);
    pricey.note_minfeefilter_sat_kvb(u64::MAX);
    let ok = relay_peer(peers, [127, 0, 0, 1], OutboundFullRelay);
    let mut ok_rx = writer_of(&ok);

    crate::force_announce_txid(hub, peers, missing);
    mp.accept_tx(&relayed).expect("accept");
    seen.note_announced_wtx(relayed.compute_wtxid());
    crate::force_announce_txid(hub, peers, relayed.compute_txid());
    assert!(block_relay_rx.try_recv().is_err(), "block-relay skips INV");
    assert!(seen_rx.try_recv().is_err(), "already-announced skips INV");
    assert!(pricey_rx.try_recv().is_err(), "minfeefilter skips INV");
    assert_eq!(tx_invs(&mut ok_rx), vec![relayed.compute_wtxid()]);

    mp.set_isolated_broadcast(true);
    mp.accept_tx(&local).expect("local");
    mp.mark_local_origin(local.compute_txid());
    mp.accept_tx(&from_p2p).expect("p2p");
    crate::force_announce_txid(hub, peers, local.compute_txid());
    assert!(
        ok_rx.try_recv().is_err(),
        "isolated local-origin must not INV standing peers"
    );
    crate::force_announce_txid(hub, peers, from_p2p.compute_txid());
    assert_eq!(tx_invs(&mut ok_rx), vec![from_p2p.compute_wtxid()]);

    assert!(mp.is_local_origin(&local.compute_txid()));
    hub.generate_to_script(1, op_true(), vec![relayed, local.clone(), from_p2p])
        .unwrap();
    assert_eq!(mp.live_count(), 0);
    assert!(
        !mp.is_local_origin(&local.compute_txid()),
        "confirm must drop the isolated skip"
    );
    for s in [block_relay, no_writer, seen, pricey, ok] {
        peers.unregister(s.id);
    }
}

/// Relay on: inbound waits 30s even for an unbroadcast tx, never gets a tx
/// accepted before it connected, and idle ticks neither clone bodies nor
/// rescan live wtxids once the age cursor caught up (`mempool_reorg.py:71`,
/// `p2p_tx_privacy.py`).
fn relay_on_inbound_age_gate(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    now: u64,
    heights: std::ops::RangeInclusive<u32>,
) {
    use crate::peers::PeerConnType::{Inbound, OutboundFullRelay};
    let mp = hub.mempool().unwrap();
    set_relay_clock(hub, peers, now);
    let inbound = relay_peer(peers, [127, 0, 0, 1], Inbound);
    let txs: Vec<_> = heights.map(|h| spend_coinbase(hub, h)).collect();
    for tx in &txs {
        mp.accept_tx(tx).expect("accept");
    }
    mp.note_unbroadcast(txs[0].compute_txid());
    let late = relay_peer(peers, [127, 0, 0, 1], Inbound);
    late.set_inv_gen_floor(mp.next_accept_gen());

    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let _ = mp.sample_reset_perf();
    for _ in 0..20 {
        queue_due_tx_invs(hub, inbound.as_ref(), &CappedSet::new(), &out_tx);
    }
    let young = mp.sample_reset_perf();
    assert_eq!(young.list_live, 0, "idle INV tick must not clone bodies");
    assert_eq!(young.list_live_wtxids, 0, "young idle must not list wtxids");
    assert_eq!(young.age_scan, 0, "young idle must not scan accept_at");
    assert!(
        out_rx.try_recv().is_err(),
        "relay-on inbound waits 30s even for unbroadcast"
    );

    let outbound = relay_peer(peers, [127, 0, 0, 1], OutboundFullRelay);
    outbound.request_tx_inv();
    queue_due_tx_invs(hub, outbound.as_ref(), &CappedSet::new(), &out_tx);
    assert_eq!(
        mp.sample_reset_perf().list_live,
        0,
        "clock_due INV must use the wtxid index"
    );
    assert_eq!(tx_invs(&mut out_rx).len(), txs.len());

    set_relay_clock(hub, peers, now + 30);
    assert!(mp.tx_inv_due(&txs[0].compute_wtxid()), "age elapsed");
    queue_due_tx_invs(hub, late.as_ref(), &CappedSet::new(), &out_tx);
    assert!(
        out_rx.try_recv().is_err(),
        "must not INV a tx accepted before this peer connected"
    );
    queue_due_tx_invs(hub, inbound.as_ref(), &CappedSet::new(), &out_tx);
    assert_eq!(
        tx_invs(&mut out_rx).len(),
        txs.len(),
        "inbound must INV every tx once it is 30s old"
    );
    let _ = mp.sample_reset_perf();
    for _ in 0..20 {
        queue_due_tx_invs(hub, inbound.as_ref(), &CappedSet::new(), &out_tx);
    }
    let idle = mp.sample_reset_perf();
    assert_eq!(
        idle.list_live_wtxids, 0,
        "age-only tick after cursor catch-up must not list_live_wtxids"
    );
    assert_eq!(
        idle.age_scan, 0,
        "age-only tick after cursor catch-up must not scan accept_at"
    );
    assert!(out_rx.try_recv().is_err(), "second age tick must not re-INV");

    hub.generate_to_script(1, op_true(), txs).unwrap();
    assert_eq!(mp.live_count(), 0);
    for s in [inbound, late, outbound] {
        peers.unregister(s.id);
    }
}

/// `mempool_reorg.py`: GetData serves a tx only after we INV'd it or when
/// a disconnected block put it back. After a +300s jump announces the old
/// txs, a new sendraw is neither INV'd nor served to inbound.
async fn getdata_until_announced_or_reorg(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    now: u64,
    heights: [u32; 4],
) {
    let mp = hub.mempool().unwrap();
    set_relay_clock(hub, peers, now);
    let [old_a, old_b, disconnected, fresh] = heights.map(|h| spend_coinbase(hub, h));
    mp.accept_tx(&old_a).expect("old_a");
    mp.accept_tx(&old_b).expect("old_b");
    let stale = hub
        .generate_to_script(1, op_true(), vec![disconnected.clone()])
        .unwrap()[0];
    hub.invalidate_block(stale).unwrap();
    assert!(
        mp.try_contains(&disconnected.compute_txid()),
        "disconnect puts the block's tx back"
    );

    let sess = relay_peer(peers, [127, 0, 0, 1], crate::peers::PeerConnType::Inbound);
    assert!(!sess.session_noban());
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.wtxid_relay = true;
    push(hub, &out_tx, &mut follow, Some(sess.as_ref()), wtx_getdata(&old_a)).await;
    match take_msgs(&mut out_rx).as_slice() {
        [NetworkMessage::NotFound(v)] => assert_eq!(v, &[Inventory::WTx(old_a.compute_wtxid())]),
        other => panic!("unannounced tx must notfound, got {other:?}"),
    }
    push(hub, &out_tx, &mut follow, Some(sess.as_ref()), wtx_getdata(&disconnected)).await;
    match take_msgs(&mut out_rx).as_slice() {
        [NetworkMessage::Tx(tx)] => assert_eq!(tx.compute_wtxid(), disconnected.compute_wtxid()),
        other => panic!("reorg-servable must serve without INV, got {other:?}"),
    }

    set_relay_clock(hub, peers, now + 300);
    queue_due_tx_invs(hub, sess.as_ref(), &CappedSet::new(), &out_tx);
    assert_eq!(tx_invs(&mut out_rx).len(), 3, "three aged txs INV after +300");
    push(hub, &out_tx, &mut follow, Some(sess.as_ref()), wtx_getdata(&old_a)).await;
    match take_msgs(&mut out_rx).as_slice() {
        [NetworkMessage::Tx(tx)] => assert_eq!(tx.compute_wtxid(), old_a.compute_wtxid()),
        other => panic!("announced tx must serve, got {other:?}"),
    }

    mp.accept_tx(&fresh).expect("fresh sendraw");
    mp.note_unbroadcast(fresh.compute_txid());
    sess.request_tx_inv();
    queue_due_tx_invs(hub, sess.as_ref(), &CappedSet::new(), &out_tx);
    assert!(
        out_rx.try_recv().is_err(),
        "new sendraw must not INV inbound after mocktime jump"
    );
    push(hub, &out_tx, &mut follow, Some(sess.as_ref()), wtx_getdata(&fresh)).await;
    match take_msgs(&mut out_rx).as_slice() {
        [NetworkMessage::NotFound(v)] => assert_eq!(v, &[Inventory::WTx(fresh.compute_wtxid())]),
        other => panic!("fresh sendraw must notfound, got {other:?}"),
    }

    hub.generate_to_script(1, op_true(), vec![old_a, old_b, disconnected, fresh])
        .unwrap();
    assert_eq!(mp.live_count(), 0);
    peers.unregister(sess.id);
}

/// An orphan parks on a tokio worker without a same-tick parent GETDATA. A
/// second parks without a reject log and logs the park once. The inbound
/// parent GETDATA waits NONPREF+TXID and skips a parent that entered the
/// mempool (`p2p_orphan_handling.py` `test_arrival_timing_orphan`).
async fn orphan_parks_then_asks_missing_parent(
    hub: &std::sync::Arc<crate::chain::ChainHub>,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    now: u64,
    parent_height: u32,
) {
    use bitcoin::OutPoint;
    let mp = hub.mempool().unwrap();
    set_relay_clock(hub, peers, now);
    let spy = relay_peer(peers, [127, 0, 0, 1], crate::peers::PeerConnType::Inbound);
    let parent_arrives = spend_coinbase(hub, parent_height);
    let parent_missing = bitcoin::Txid::from_byte_array([0x22; 32]);
    let orphan = orphan_of(&[
        OutPoint {
            txid: parent_arrives.compute_txid(),
            vout: 10,
        },
        OutPoint {
            txid: parent_missing,
            vout: 0,
        },
    ]);

    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let worker = {
        let hub = Arc::clone(hub);
        let spy = Arc::clone(&spy);
        let out_tx = out_tx.clone();
        tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            let mut follow = PeerFollowState::new();
            follow.wtxid_relay = true;
            let frame = NetworkMessage::Tx(orphan);
            push(&hub, &out_tx, &mut follow, Some(spy.as_ref()), frame).await;
            (name, follow)
        })
    };
    let (name, mut follow) = worker.await.expect("park on a tokio worker");
    assert!(name.starts_with("tokio-rt-worker"), "ran on {name:?}");
    assert_eq!(mp.orphan_count(), 1);

    let lone = orphan_of(&[OutPoint {
        txid: parent_missing,
        vout: 1,
    }]);
    let park = |logs: &[(rbitcoin_log::Level, String)]| {
        logs.iter()
            .any(|(l, m)| *l == rbitcoin_log::Level::Debug && m.contains("txrelay: park"))
    };
    rbitcoin_log::capture_logs(true);
    let frame = NetworkMessage::Tx(lone.clone());
    push(hub, &out_tx, &mut follow, Some(spy.as_ref()), frame).await;
    let first = rbitcoin_log::take_logs();
    push(hub, &out_tx, &mut follow, Some(spy.as_ref()), NetworkMessage::Tx(lone)).await;
    let again = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert_eq!(mp.orphan_count(), 2);
    assert!(
        !first
            .iter()
            .any(|(_, m)| m.contains("was not accepted") || m.contains("txrelay: reject")),
        "parked orphan must not log as reject, got {first:?}"
    );
    assert!(park(&first), "expected debug park line, got {first:?}");
    assert!(
        !park(&again),
        "re-delivery of a parked orphan must not log park again, got {again:?}"
    );
    assert!(
        getdata_txs(&mut out_rx).is_empty(),
        "inbound must not GETDATA orphan parents before NONPREF+TXID"
    );

    push(hub, &out_tx, &mut follow, Some(spy.as_ref()), NetworkMessage::Ping(1)).await;
    assert!(getdata_txs(&mut out_rx).is_empty(), "ping at park time");
    set_relay_clock(hub, peers, now + 2);
    push(hub, &out_tx, &mut follow, Some(spy.as_ref()), NetworkMessage::Ping(2)).await;
    assert!(
        getdata_txs(&mut out_rx).is_empty(),
        "NONPREF alone must not GETDATA by txid"
    );
    mp.accept_tx(&parent_arrives).expect("parent arrives");
    set_relay_clock(hub, peers, now + 4);
    push(hub, &out_tx, &mut follow, Some(spy.as_ref()), NetworkMessage::Ping(3)).await;
    assert_eq!(
        getdata_txs(&mut out_rx),
        vec![Inventory::WitnessTransaction(parent_missing)],
        "after NONPREF+TXID ask only the still-missing parent"
    );
    peers.unregister(spy.id);
    assert_eq!(mp.orphan_count(), 0, "disconnect erases the peer's orphans");
}

/// One node on one chain. Blocks-only (relay off) first, then tip-mode
/// relay: tx punishment and the relay whitelist, sendraw and forced INVs,
/// the inbound age gate, GetData privacy across a reorg, and orphan parents.
#[test]
fn peer_blocksonly_and_orphan_tx() {
    // Orphan parking must run on a thread the reactor guard names.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .build()
        .unwrap();
    rt.block_on(async {
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("blocksonly-orphan");
        let hub = Arc::new(hub);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(130, op_true(), vec![]).unwrap();
        let t = hub.tip_header().unwrap().time;
        hub.clock.set_mock(i64::from(t) + 1);
        assert!(!hub.in_ibd(), "blocksonly is not IBD");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(false);
        let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
        peers.attach_mempool(&mp);
        assert!(hub.attach_mempool(mp).is_ok());
        let t0 = 1_700_000_000u64;
        set_relay_clock(&hub, &peers, t0);

        blocksonly_p2p_tx_disconnects(&hub, &peers).await;
        let sendraw = spend_coinbase(&hub, 1);
        blocksonly_sendraw_invs_inbound(&hub, &peers, &sendraw).await;
        let whitelisted = spend_coinbase(&hub, 2);
        blocksonly_relay_perm_tx_invs_other_inbound(&hub, &peers, &whitelisted).await;
        getdata_type0_then_tip_block(&hub, &peers).await;

        relay_on_purges_confirmed(&hub, vec![sendraw, whitelisted]);
        force_announce_picks_peers(&hub, &peers, [3, 4, 5]);
        relay_on_inbound_age_gate(&hub, &peers, t0 + 100, 6..=21);
        getdata_until_announced_or_reorg(&hub, &peers, t0 + 200, [22, 23, 24, 25]).await;
        orphan_parks_then_asks_missing_parent(&hub, &peers, t0 + 600, 26).await;

        let _ = std::fs::remove_dir_all(dir);
    });
}
