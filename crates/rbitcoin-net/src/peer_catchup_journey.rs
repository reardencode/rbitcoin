use bitcoin::consensus::encode::serialize;
use bitcoin::p2p::message::RawNetworkMessage;
use bitcoin::Network;
use rbitcoin_primitives::Height;

fn frame_for(msg: NetworkMessage) -> FramedMessage {
    let magic = Magic::from(Network::Regtest);
    let raw = RawNetworkMessage::new(magic, msg);
    let full = serialize(&raw);
    let command: [u8; 12] = full[4..16].try_into().unwrap();
    FramedMessage {
        magic,
        command,
        payload: full[24..].to_vec(),
    }
}

fn take_msgs(rx: &mut mpsc::UnboundedReceiver<PeerOut>) -> Vec<NetworkMessage> {
    let mut out = Vec::new();
    while let Ok(item) = rx.try_recv() {
        out.push(item.expect_msg());
    }
    out
}

fn getdata_of(msgs: &[NetworkMessage]) -> Vec<(BlockHash, bool)> {
    let mut out = Vec::new();
    for msg in msgs {
        if let NetworkMessage::GetData(inv) = msg {
            for i in inv {
                match i {
                    Inventory::CompactBlock(h) => out.push((*h, true)),
                    Inventory::Block(h) | Inventory::WitnessBlock(h) => out.push((*h, false)),
                    _ => {}
                }
            }
        }
    }
    out
}

fn block_at(src: &crate::chain::ChainHub, height: u32) -> bitcoin::Block {
    src.query
        .reconstruct_block_at_height(Height(height))
        .unwrap()
}

fn header_at(src: &crate::chain::ChainHub, height: u32) -> bitcoin::block::Header {
    src.query.wire_header_at_height(Height(height)).unwrap()
}

#[tokio::test]
async fn peer_catchup_compact_reorg() {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxMerkleNode,
        TxOut, Witness,
    };
    use rbitcoin_primitives::Height;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};


    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let (src_dir, src) = crate::chain::tiny_regtest_hub_labeled("catchup-journey-src");
    src.ensure_genesis().unwrap();
    src.generate_to_script(160, op_true.clone(), vec![]).unwrap();

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("catchup-journey-dst");
    hub.ensure_genesis().unwrap();
    let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());

    let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let live = peers.register(
        addr,
        addr,
        &ver,
        false,
        crate::peers::PeerConnType::OutboundFullRelay,
    );
    live.note_awaiting_headers();

    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();

    // Pending child of a better fork connects while we still sit on one private block.
    let gen = hub.tip_hash().unwrap();
    let coinbase = |height: u32, tag: u8| {
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(tag);
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
                script_pubkey: op_true.clone(),
            }],
        }
    };
    let mine = |prev: BlockHash, time: u32, height: u32| {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = bitcoin::Block {
            header: Header {
                version: BlockVersion::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(height, 0x01)],
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
    let private = mine(gen, 1_300_000_100, 1);
    hub.accept_block(private).unwrap();
    assert_eq!(hub.tip_height(), Some(1));
    let peer_1 = block_at(&src, 1);
    let peer_2 = block_at(&src, 2);
    let mut pb = PendingBlocks::new();
    pb.insert(peer_1.block_hash(), peer_1.clone());
    pb.insert(peer_2.block_hash(), peer_2.clone());
    let mut ph = HashMap::new();
    drain_pending(
        &hub,
        &out_tx,
        &mut pb,
        &mut ph,
        &mut HashSet::new(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(hub.tip_height(), Some(2), "reorg plus child must connect");
    assert_eq!(hub.tip_hash().unwrap(), peer_2.block_hash());
    assert!(hub.is_connected(&peer_1.block_hash()));
    assert!(hub.is_connected(&peer_2.block_hash()));
    let _ = take_msgs(&mut out_rx);

    // Peer is ahead. Catch-up getdata stays inside the serve window, and a
    // child delivered before its parent still connects.
    let headers: Vec<Header> = (3..=34).map(|h| header_at(&src, h)).collect();
    let parent = headers[0].block_hash();
    let child = headers[1].block_hash();
    handle_peer_frame(
        frame_for(NetworkMessage::Headers(headers.clone())),
        &hub,
        &out_tx,
        &mut follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let first_msgs = take_msgs(&mut out_rx);
    let first = getdata_of(&first_msgs);
    assert_eq!(
        first.len(),
        MAX_SERVE_BLOCKS,
        "catch-up getdata must match serve window, got {}",
        first.len()
    );
    assert_eq!(follow.requested_blocks.len(), MAX_SERVE_BLOCKS);
    assert!(
        follow.requested_blocks.contains(&parent) && follow.requested_blocks.contains(&child)
    );
    let mut deliver = vec![child, parent];
    for (h, _) in &first {
        if *h != parent && *h != child {
            deliver.push(*h);
        }
    }
    let mut rest = Vec::new();
    for hash in deliver {
        let block = src
            .query
            .reconstruct_archived_block(&hash.to_byte_array())
            .unwrap()
            .expect("window body");
        handle_peer_frame(
            frame_for(NetworkMessage::Block(block)),
            &hub,
            &out_tx,
            &mut follow,
            Some(live.as_ref()),
        )
        .await
        .unwrap();
        rest.extend(getdata_of(&take_msgs(&mut out_rx)));
        if hash == parent {
            assert_eq!(
                hub.tip_hash(),
                Some(child),
                "child delivered before parent must connect once the parent does"
            );
        }
    }
    let rest_set: HashSet<_> = rest.into_iter().map(|(h, _)| h).collect();
    let want_rest: HashSet<_> = headers[MAX_SERVE_BLOCKS..MAX_SERVE_BLOCKS * 2]
        .iter()
        .map(|h| h.block_hash())
        .collect();
    assert_eq!(
        rest_set, want_rest,
        "second catch-up getdata must stay in the serve window"
    );

    for hash in want_rest {
        let block = src
            .query
            .reconstruct_archived_block(&hash.to_byte_array())
            .unwrap()
            .expect("second window");
        handle_peer_frame(
            frame_for(NetworkMessage::Block(block)),
            &hub,
            &out_tx,
            &mut follow,
            Some(live.as_ref()),
        )
        .await
        .unwrap();
    }
    let _ = take_msgs(&mut out_rx);
    assert_eq!(hub.tip_height(), Some(2 + (MAX_SERVE_BLOCKS as u32) * 2));

    // Tip's child is compact; the blocks behind it are witness.
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    let tip_child_headers: Vec<Header> = (35..=42).map(|h| header_at(&src, h)).collect();
    let tip_child = tip_child_headers[0].block_hash();
    handle_peer_frame(
        frame_for(NetworkMessage::Headers(tip_child_headers.clone())),
        &hub,
        &out_tx,
        &mut follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let announced = take_msgs(&mut out_rx);
    let inv = announced.iter().find_map(|m| match m {
        NetworkMessage::GetData(inv) => Some(inv.clone()),
        _ => None,
    });
    let inv = inv.expect("getdata for tip child");
    assert!(
        matches!(inv.first(), Some(Inventory::CompactBlock(h)) if *h == tip_child),
        "tip-child must stay MSG_CMPCT_BLOCK, got {inv:?}"
    );
    assert!(
        inv.iter()
            .skip(1)
            .all(|i| matches!(i, Inventory::WitnessBlock(_))),
        "catch-up beyond the tip child must be MSG_WITNESS_BLOCK, got {inv:?}"
    );
    assert_eq!(inv.len(), tip_child_headers.len());
    for (hash, _) in getdata_of(&announced) {
        let block = src
            .query
            .reconstruct_archived_block(&hash.to_byte_array())
            .unwrap()
            .expect("tip-child body");
        handle_peer_frame(
            frame_for(NetworkMessage::Block(block)),
            &hub,
            &out_tx,
            &mut follow,
            Some(live.as_ref()),
        )
        .await
        .unwrap();
    }
    let _ = take_msgs(&mut out_rx);

    // Compact delivery frees requested slots, so the next window is asked.
    let n = MAX_SERVE_BLOCKS + 4;
    let base = hub.tip_height().unwrap();
    let more: Vec<Header> = ((base + 1)..=(base + n as u32))
        .map(|h| header_at(&src, h))
        .collect();
    handle_peer_frame(
        frame_for(NetworkMessage::Headers(more.clone())),
        &hub,
        &out_tx,
        &mut follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let window = getdata_of(&take_msgs(&mut out_rx));
    assert_eq!(window.len(), MAX_SERVE_BLOCKS);
    assert_eq!(follow.requested_blocks.len(), MAX_SERVE_BLOCKS);
    for (hash, _) in &window {
        let block = src
            .query
            .reconstruct_archived_block(&hash.to_byte_array())
            .unwrap()
            .expect("compact window body");
        let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi,
            })),
            &hub,
            &out_tx,
            &mut follow,
            Some(live.as_ref()),
        )
        .await
        .unwrap();
    }
    let after_compact = take_msgs(&mut out_rx);
    assert!(
        follow.requested_blocks.len() < MAX_SERVE_BLOCKS,
        "compact accept must free requested slots, still {}",
        follow.requested_blocks.len()
    );
    let rest = getdata_of(&after_compact);
    assert_eq!(
        rest.len(),
        n - MAX_SERVE_BLOCKS,
        "after compact window fills, remaining header-path bodies must be asked, got {}",
        rest.len()
    );
    let want: HashSet<_> = more[MAX_SERVE_BLOCKS..]
        .iter()
        .map(|h| h.block_hash())
        .collect();
    let got: HashSet<_> = rest.into_iter().map(|(h, _)| h).collect();
    assert_eq!(got, want);
    for hash in want {
        let block = src
            .query
            .reconstruct_archived_block(&hash.to_byte_array())
            .unwrap()
            .expect("rest body");
        handle_peer_frame(
            frame_for(NetworkMessage::Block(block)),
            &hub,
            &out_tx,
            &mut follow,
            Some(live.as_ref()),
        )
        .await
        .unwrap();
    }
    let _ = take_msgs(&mut out_rx);

    // A side-fork compact with less work than the tip is ignored.
    let prev = hub
        .query
        .header_at_height(Height(1))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x44; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: op_true.clone(),
        }],
    };
    let mut side = bitcoin::Block {
        header: Header {
            version: BlockVersion::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: hub.tip_header().unwrap().time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase(2, 0x02), spend.clone()],
    };
    side.header.merkle_root = side.compute_merkle_root().unwrap();
    let side_hash = side.block_hash();
    let side_hsi = HeaderAndShortIds::from_block(&side, 0xbeef, 2, &[]).unwrap();
    let tip_before_side = hub.tip_hash();
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: side_hsi,
        })),
        &hub,
        &out_tx,
        &mut follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let side_msgs = take_msgs(&mut out_rx);
    assert!(
        !side_msgs
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetData(_) | NetworkMessage::GetBlockTxn(_))),
        "unsolicited compact with work <= tip is ignored (Core nChainWork <= tip)"
    );
    assert!(
        follow.pending_cmpct.is_empty(),
        "weaker side-fork compact must not wait on blocktxn"
    );
    assert!(
        hub.held_body(&side_hash).is_none(),
        "weaker unsolicited compact must not reconstruct into held"
    );
    assert_eq!(hub.tip_hash(), tip_before_side);

    while hub.tip_height().unwrap() < 160 {
        let next = hub.tip_height().unwrap() + 1;
        hub.accept_block(block_at(&src, next)).unwrap();
    }
    assert_eq!(hub.tip_height(), Some(160));

    // Compact hanging 150 below the tip is under the anti-DoS threshold.
    let low_prev = hub
        .query
        .header_at_height(Height(10))
        .unwrap()
        .unwrap()
        .1
        .hash;
    let low = rbitcoin_consensus::mine_regtest_paying(
        BlockHash::from_byte_array(low_prev),
        hub.tip_header().unwrap().time + 600,
        11,
        op_true.clone(),
        vec![],
    );
    let low_hash = low.block_hash();
    assert!(
        hub.header_below_anti_dos(&low.header),
        "compact hanging 150 below tip must be under the anti-DoS threshold"
    );
    let low_hsi = HeaderAndShortIds::from_block(&low, 1, 2, &[0]).unwrap();
    let tip_before_low = hub.tip_hash();
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: low_hsi,
        })),
        &hub,
        &out_tx,
        &mut follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let _ = take_msgs(&mut out_rx);
    assert!(
        hub.held_body(&low_hash).is_none(),
        "150-below compact must not enter held"
    );
    assert_eq!(hub.tip_hash(), tip_before_low);

    // Mock time: a stale getdata can be asked again.
    let stale_hash = BlockHash::from_byte_array([0x11; 32]);
    let mut requested = HashSet::new();
    requested.insert(stale_hash);
    hub.note_asked_block(stale_hash);
    assert!(hub.already_have_or_asked_block(&stale_hash));
    let t0 = Instant::now();
    let mut since = Some(t0);
    assert!(
        !maybe_expire_block_requests(
            &hub,
            &mut requested,
            &mut since,
            t0 + BLOCK_GETDATA_TIMEOUT - Duration::from_secs(1),
            None,
        ),
        "must not expire before BLOCK_GETDATA_TIMEOUT"
    );
    assert_eq!(requested.len(), 1);
    assert!(maybe_expire_block_requests(
        &hub,
        &mut requested,
        &mut since,
        t0 + BLOCK_GETDATA_TIMEOUT + Duration::from_millis(1),
        None,
    ));
    assert!(requested.is_empty());
    assert!(
        !hub.already_have_or_asked_block(&stale_hash),
        "expired getdata must leave asked_blocks so the same hashes can be re-asked"
    );

    // A pending compact that cannot be filled expires into a full getdata.
    let mut pending_block = bitcoin::Block {
        header: Header {
            version: BlockVersion::from_consensus(4),
            prev_blockhash: hub.tip_hash().unwrap(),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase(161, 0x03), spend],
    };
    pending_block.header.merkle_root = pending_block.compute_merkle_root().unwrap();
    let pending_hash = pending_block.block_hash();
    let pending_hsi = HeaderAndShortIds::from_block(&pending_block, 0xbeef, 2, &[]).unwrap();
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: pending_hsi,
        })),
        &hub,
        &out_tx,
        &mut follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    match take_msgs(&mut out_rx)
        .into_iter()
        .find(|m| matches!(m, NetworkMessage::GetBlockTxn(_)))
    {
        Some(NetworkMessage::GetBlockTxn(_)) => {}
        other => panic!("expected getblocktxn, got {other:?}"),
    }
    let pending_since = follow.pending_cmpct.get(&pending_hash).expect("pending").since;
    assert!(
        !maybe_expire_pending_cmpct(
            &hub,
            &mut follow,
            Some(live.as_ref()),
            &out_tx,
            pending_since + BLOCK_GETDATA_TIMEOUT - Duration::from_secs(1),
        )
        .unwrap(),
        "must not expire pending compact before BLOCK_GETDATA_TIMEOUT"
    );
    assert!(follow.pending_cmpct.contains_key(&pending_hash));
    assert!(maybe_expire_pending_cmpct(
        &hub,
        &mut follow,
        Some(live.as_ref()),
        &out_tx,
        pending_since + BLOCK_GETDATA_TIMEOUT + Duration::from_millis(1),
    )
    .unwrap());
    assert!(
        follow.pending_cmpct.is_empty(),
        "expired compact must leave pending_cmpct"
    );
    let fallback = take_msgs(&mut out_rx);
    let fallback_inv = fallback.iter().find_map(|m| match m {
        NetworkMessage::GetData(inv) => Some(inv.clone()),
        _ => None,
    });
    assert_eq!(
        fallback_inv.expect("fallback getdata"),
        vec![Inventory::WitnessBlock(pending_hash)]
    );
    assert!(
        follow.requested_blocks.contains(&pending_hash),
        "expired compact fallback must be a requested body so weaker-than-tip is not dropped"
    );

    // Expiring that getdata releases the compact fill slot.
    assert!(live.try_cmpct_fill(pending_hash));
    let t1 = Instant::now();
    let mut since = Some(t1);
    let mut fill_req = HashSet::new();
    fill_req.insert(pending_hash);
    assert!(maybe_expire_block_requests(
        &hub,
        &mut fill_req,
        &mut since,
        t1 + BLOCK_GETDATA_TIMEOUT + Duration::from_millis(1),
        Some(live.as_ref()),
    ));
    follow.requested_blocks.remove(&pending_hash);
    assert!(peers.try_cmpct_fill_slot(pending_hash, true));
    assert!(peers.try_cmpct_fill_slot(pending_hash, true));
    assert!(!peers.try_cmpct_fill_slot(pending_hash, true));

    catchup_reorg_and_drain(&src, &hub, &live, &out_tx, &mut out_rx, &mut follow).await;
    let _ = std::fs::remove_dir_all(src_dir);
    let _ = std::fs::remove_dir_all(dir);
}

#[allow(clippy::cognitive_complexity)] // one reorg chapter; the tokio test owns the story
async fn catchup_reorg_and_drain(
    src: &crate::chain::ChainHub,
    hub: &crate::chain::ChainHub,
    live: &std::sync::Arc<crate::peers::LivePeer>,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    out_rx: &mut mpsc::UnboundedReceiver<PeerOut>,
    follow: &mut PeerFollowState,
) {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxMerkleNode, TxOut,
        Witness,
    };
    use std::time::{Duration, Instant};

    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let coinbase = |height: u32, tag: u8| {
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(tag);
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
                script_pubkey: op_true.clone(),
            }],
        }
    };
    // Weaker connecting headers drop the stale fork's outstanding asks.
    const FORK_PARENT: u32 = 144;
    let stale_asks: Vec<BlockHash> = ((FORK_PARENT + 1)..=160)
        .map(|h| block_at(src, h).block_hash())
        .collect();
    assert_eq!(stale_asks.len(), MAX_SERVE_BLOCKS);
    let stale_first = stale_asks[0];
    src.invalidate_block(stale_first).unwrap();
    src.generate_to_script(MAX_SERVE_BLOCKS as u32 - 2, ScriptBuf::from_bytes(vec![0x52]), vec![])
        .unwrap();
    let weak_headers: Vec<Header> = ((FORK_PARENT + 1)..=(FORK_PARENT + MAX_SERVE_BLOCKS as u32 - 2))
        .map(|h| header_at(src, h))
        .collect();
    assert!(weak_headers.len() as u32 + FORK_PARENT < 160);
    for hash in &stale_asks {
        follow.requested_blocks.insert(*hash);
        hub.note_asked_block(*hash);
    }
    handle_peer_frame(
        frame_for(NetworkMessage::Headers(weak_headers)),
        hub,
        out_tx,
        follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let _ = take_msgs(out_rx);
    assert!(
        stale_asks
            .iter()
            .all(|h| !follow.requested_blocks.contains(h)),
        "weaker connecting headers must drop stale-fork asks, still {:?}",
        follow.requested_blocks
    );
    assert_ne!(hub.tip_hash(), Some(src.tip_hash().unwrap()));

    src.generate_to_script(10, ScriptBuf::from_bytes(vec![0x52]), vec![]).unwrap();
    let heavy_tip = src.tip_height().unwrap();
    let stem = block_at(src, FORK_PARENT + 1);
    let want = src.tip_hash().unwrap();
    assert!(
        hub.tip_height().unwrap().saturating_sub(FORK_PARENT) > 6,
        "stem must sit more than 6 below the stale tip"
    );
    assert!(
        !hub.header_below_anti_dos(&stem.header),
        "stem inside the 144-block anti-DoS window must not be treated as low work"
    );

    // A full getdata window must not starve the better header path.
    let mut fork_headers = HashMap::new();
    for h in (FORK_PARENT + 1)..=heavy_tip {
        let block = block_at(src, h);
        fork_headers.insert(block.block_hash(), block.header);
    }
    let mut dummy_req = HashSet::new();
    for i in 0..MAX_SERVE_BLOCKS {
        let dummy = BlockHash::from_byte_array([i as u8 + 1; 32]);
        dummy_req.insert(dummy);
        hub.note_asked_block(dummy);
    }
    let (drain_tx, mut drain_rx) = mpsc::unbounded_channel();
    let mut drain_blocks = PendingBlocks::new();
    drain_pending(
        hub,
        &drain_tx,
        &mut drain_blocks,
        &mut fork_headers,
        &mut dummy_req,
        false,
        None,
    )
    .await
    .unwrap();
    let drained = getdata_of(&take_msgs(&mut drain_rx));
    assert!(
        drained.iter().any(|(h, _)| *h == stem.block_hash()),
        "headers path must getdata the fork stem even when the serve window is full (got {drained:?})"
    );
    assert!(dummy_req.contains(&stem.block_hash()));
    drain_pending(
        hub,
        &drain_tx,
        &mut drain_blocks,
        &mut fork_headers,
        &mut dummy_req,
        false,
        None,
    )
    .await
    .unwrap();
    assert!(
        dummy_req.contains(&stem.block_hash()),
        "a later drain must not forget in-flight stem getdata"
    );
    let t2 = Instant::now();
    let mut since = Some(t2);
    assert!(maybe_expire_block_requests(
        hub,
        &mut dummy_req,
        &mut since,
        t2 + BLOCK_GETDATA_TIMEOUT + Duration::from_millis(1),
        None,
    ));

    // Stem compact does not switch. Lagged compact of the better tip asks
    // headers and still does not switch until bodies arrive.
    let stem_hsi = HeaderAndShortIds::from_block(&stem, 1, 2, &[0]).unwrap();
    let stale_tip = hub.tip_hash();
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: stem_hsi,
        })),
        hub,
        out_tx,
        follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let _ = take_msgs(out_rx);
    assert!(
        follow.pending_cmpct.is_empty()
            && hub.held_body(&stem.block_hash()).is_none()
            && hub.tip_hash() == stale_tip,
        "weaker-than-tip stem compact is a header, not a reconstruct"
    );
    let tip_block = block_at(src, heavy_tip);
    let tip_hsi = HeaderAndShortIds::from_block(&tip_block, 1, 2, &[0]).unwrap();
    handle_peer_frame(
        frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: tip_hsi,
        })),
        hub,
        out_tx,
        follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let lagged = take_msgs(out_rx);
    assert!(
        lagged
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
        "lagged compact of a better fork must getheaders"
    );
    assert_eq!(
        hub.tip_hash(), stale_tip,
        "lagged compact alone must not switch off the stale fork"
    );

    // Compact flood of the new chain does not move the hub. Stem stays a
    // witness ask. Delayed witness bodies are what reorg.
    let mut asked: Vec<(BlockHash, bool)> = getdata_of(&lagged);
    for h in (FORK_PARENT + 1)..=heavy_tip {
        let body = block_at(src, h);
        let hsi = HeaderAndShortIds::from_block(&body, 1, 2, &[0]).unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi,
            })),
            hub,
            out_tx,
            follow,
            Some(live.as_ref()),
        )
        .await
        .unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![body.header])),
            hub,
            out_tx,
            follow,
            Some(live.as_ref()),
        )
        .await
        .unwrap();
        for item in getdata_of(&take_msgs(out_rx)) {
            if !asked.iter().any(|(hash, _)| *hash == item.0) {
                asked.push(item);
            }
        }
    }
    assert_eq!(hub.tip_hash(), stale_tip, "compact flood must not move the hub");
    assert!(
        asked
            .iter()
            .any(|(h, compact)| *h == stem.block_hash() && !*compact),
        "better-fork stem must be MSG_WITNESS_BLOCK, got {asked:?}"
    );
    assert!(
        follow.requested_blocks.contains(&stem.block_hash())
            || hub.held_body(&stem.block_hash()).is_some()
            || hub.is_connected(&stem.block_hash()),
        "stem getdata must survive the compact flood"
    );
    let mut asks = asked;
    for _ in 0..64 {
        if hub.tip_hash() == Some(want) {
            break;
        }
        if asks.is_empty() {
            asks = getdata_of(&take_msgs(out_rx));
            if asks.is_empty() {
                break;
            }
        }
        for (ask, compact) in asks {
            let Some(body) = src
                .query
                .reconstruct_archived_block(&ask.to_byte_array())
                .unwrap()
            else {
                continue;
            };
            let msg = if compact {
                let hsi = HeaderAndShortIds::from_block(&body, 1, 2, &[0]).unwrap();
                NetworkMessage::CmpctBlock(CmpctBlock { compact_block: hsi })
            } else {
                NetworkMessage::Block(body)
            };
            handle_peer_frame(
                frame_for(msg),
                hub,
                out_tx,
                follow,
                Some(live.as_ref()),
            )
            .await
            .unwrap();
        }
        asks = getdata_of(&take_msgs(out_rx));
    }
    assert_eq!(
        hub.tip_hash(),
        Some(want),
        "delayed witness bodies must reorg onto the heavier fork (have {} want {heavy_tip})",
        hub.tip_height().unwrap_or(0)
    );

    // A later stem that sits two below the tip is still witness, not compact.
    let shallow_tip = hub.tip_height().unwrap();
    let shallow_parent = shallow_tip - 2;
    let shallow_stale = block_at(src, shallow_parent + 1).block_hash();
    src.invalidate_block(shallow_stale).unwrap();
    src.generate_to_script(6, ScriptBuf::from_bytes(vec![0x53]), vec![]).unwrap();
    let shallow_stem = block_at(src, shallow_parent + 1);
    let shallow_want = src.tip_hash().unwrap();
    let shallow_headers: Vec<Header> = ((shallow_parent + 1)..=src.tip_height().unwrap())
        .map(|h| header_at(src, h))
        .collect();
    handle_peer_frame(
        frame_for(NetworkMessage::Headers(shallow_headers)),
        hub,
        out_tx,
        follow,
        Some(live.as_ref()),
    )
    .await
    .unwrap();
    let mut shallow_asks = getdata_of(&take_msgs(out_rx));
    assert!(
        shallow_asks
            .iter()
            .any(|(h, compact)| *h == shallow_stem.block_hash() && !*compact),
        "stem 2 below the stale tip must be MSG_WITNESS_BLOCK, got {shallow_asks:?}"
    );
    for _ in 0..16 {
        if shallow_asks.is_empty() {
            break;
        }
        for (ask, _) in shallow_asks {
            let Some(body) = src
                .query
                .reconstruct_archived_block(&ask.to_byte_array())
                .unwrap()
            else {
                continue;
            };
            handle_peer_frame(
                frame_for(NetworkMessage::Block(body)),
                hub,
                out_tx,
                follow,
                Some(live.as_ref()),
            )
            .await
            .unwrap();
        }
        shallow_asks = getdata_of(&take_msgs(out_rx));
    }
    assert_eq!(hub.tip_hash(), Some(shallow_want));

    // Drain asks for the parent our pending branch does not have.
    let missing_parent = BlockHash::from_byte_array([0x42; 32]);
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut orphan = bitcoin::Block {
        header: Header {
            version: BlockVersion::from_consensus(4),
            prev_blockhash: missing_parent,
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_100,
            bits,
            nonce: 0,
        },
        txdata: vec![coinbase(1, 0x07)],
    };
    orphan.header.merkle_root = orphan.compute_merkle_root().unwrap();
    let target = Target::from_compact(bits);
    for nonce in 0..u32::MAX {
        orphan.header.nonce = nonce;
        if orphan.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let (miss_tx, mut miss_rx) = mpsc::unbounded_channel();
    let mut miss_blocks = PendingBlocks::new();
    miss_blocks.insert(orphan.block_hash(), orphan);
    let mut miss_headers = HashMap::new();
    drain_pending(
        hub,
        &miss_tx,
        &mut miss_blocks,
        &mut miss_headers,
        &mut HashSet::new(),
        false,
        None,
    )
    .await
    .unwrap();
    let miss = miss_rx.try_recv().expect("getdata for missing parent").expect_msg();
    match miss {
        NetworkMessage::GetData(inv) => {
            assert!(
                inv.iter()
                    .any(|i| matches!(i, Inventory::WitnessBlock(h) if *h == missing_parent)),
                "expected getdata for {missing_parent}, got {inv:?}"
            );
        }
        other => panic!("expected GetData, got {other:?}"),
    }
    assert!(!hub.is_connected(&missing_parent));

}
