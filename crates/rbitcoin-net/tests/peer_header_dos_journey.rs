fn work_floor(low: u8) -> [u8; 32] {
    let mut min = [0u8; 32];
    min[31] = low;
    min
}

fn side_tips(hub: &rbitcoin_net::chain::ChainHub) -> usize {
    hub.chaintips()
        .iter()
        .filter(|t| t.status != "active")
        .count()
}

fn asked_blocks(rx: &mut mpsc::UnboundedReceiver<PeerOut>) -> Vec<BlockHash> {
    getdata_of(&take_msgs(rx))
        .into_iter()
        .map(|(hash, _)| hash)
        .collect()
}

fn zero_stop() -> BlockHash {
    BlockHash::from_byte_array([0u8; 32])
}

async fn push(
    hub: &rbitcoin_net::chain::ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&rbitcoin_net::peers::LivePeer>,
    msg: NetworkMessage,
) {
    handle_peer_frame(frame_for(msg), hub, out_tx, follow, session)
        .await
        .unwrap();
}

fn orphan_body(prev: BlockHash, nonce: u32) -> bitcoin::Block {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::from_bytes(vec![0x01, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: op_true(),
        }],
    };
    let mut block = bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block
}

fn logs_have(needle: &str) -> bool {
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    logs.iter().any(|(_, msg)| msg.contains(needle))
}

/// wtxidrelay and sendaddrv2 before verack stick. Ping is logged. A second
/// verack is ignored. sendaddrv2 and an oversized addrv2 after verack disconnect.
async fn handshake_verack_and_addrv2(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::p2p::address::AddrV2;
    assert_eq!(
        rbitcoin_net::peer::sendaddrv2_after_verack_log(0),
        "p2p: sendaddrv2 received after verack, disconnecting peer=0"
    );
    assert_eq!(
        rbitcoin_net::peer::addrv2_message_size_log(1010),
        "p2p: addrv2 message size = 1010"
    );

    let sess = live_peer(peers, 18444, 1, true);
    assert_eq!(sess.id, 0, "first peer is the verack log's peer=0");

    rbitcoin_log::capture_logs(true);
    let done = apply_pre_verack(
        Some(sess.as_ref()),
        &NetworkMessage::WtxidRelay,
        "wtxidrelay",
    );
    assert!(!done, "wtxidrelay is not verack");
    assert!(sess.wtxid_relay(), "wtxidrelay before verack must stick");
    assert!(
        !logs_have("Unsupported message \"wtxidrelay\""),
        "wtxidrelay before verack stays silent"
    );

    rbitcoin_log::capture_logs(true);
    let done = apply_pre_verack(
        Some(sess.as_ref()),
        &NetworkMessage::SendAddrV2,
        "sendaddrv2",
    );
    assert!(!done);
    assert!(sess.wants_addrv2());
    assert!(
        !logs_have("Unsupported message \"sendaddrv2\""),
        "sendaddrv2 before verack stays silent"
    );

    rbitcoin_log::capture_logs(true);
    let done = apply_pre_verack(Some(sess.as_ref()), &NetworkMessage::Ping(1), "ping");
    assert!(!done);
    assert!(
        logs_have("Unsupported message \"ping\" prior to verack"),
        "ping before verack still logs"
    );
    assert!(apply_pre_verack(
        Some(sess.as_ref()),
        &NetworkMessage::Verack,
        "verack"
    ));

    let (out_tx, _rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    rbitcoin_log::capture_logs(true);
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::Verack,
    )
    .await;
    assert!(
        logs_have("ignoring redundant verack message"),
        "redundant verack is ignored"
    );
    assert_eq!(follow.ban_score, 0, "redundant verack must not disconnect");

    rbitcoin_log::capture_logs(true);
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::SendAddrV2,
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "post-verack sendaddrv2 must disconnect"
    );
    assert!(
        logs_have("sendaddrv2 received after verack, disconnecting peer=0"),
        "sendaddrv2 after verack names the peer"
    );

    let addrs = (0..1010u16)
        .map(|i| bitcoin::p2p::address::AddrV2Message {
            time: 1_700_000_000,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(123, 123, 123, 1)),
            port: 8333 + i,
        })
        .collect();
    follow.ban_score = 0;
    rbitcoin_log::capture_logs(true);
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::AddrV2(addrs),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "oversized addrv2 must disconnect"
    );
    assert!(
        logs_have("addrv2 message size = 1010"),
        "oversized addrv2 logs the count"
    );
}

/// Unknown-parent bodies and compacts stay header-only. A requested body is parked.
async fn unknown_parent_bodies(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    let peer = live_peer(peers, 18450, 2, false);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let block = orphan_body(BlockHash::from_byte_array([0xab; 32]), 0);
    let hash = block.block_hash();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Block(block),
    )
    .await;
    assert!(
        peer.stop.load(Ordering::SeqCst),
        "unsolicited unknown-parent body must disconnect"
    );
    assert!(
        !hub.knows_header(&hash),
        "unsolicited unknown-parent must not persist"
    );
    assert!(
        out_rx.try_recv().is_err(),
        "unsolicited unknown-parent must not getheaders"
    );

    let peer = live_peer(peers, 18451, 3, false);
    peer.note_awaiting_headers();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let block = orphan_body(BlockHash::from_byte_array([0xab; 32]), 0);
    let hash = block.block_hash();
    follow.requested_blocks.insert(hash);
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Block(block),
    )
    .await;
    assert!(
        !peer.stop.load(Ordering::SeqCst),
        "requested unknown-parent body must keep the session"
    );
    assert!(!hub.knows_header(&hash));
    let msg = out_rx.try_recv().expect("getheaders").expect_msg();
    assert!(
        matches!(msg, NetworkMessage::GetHeaders(_)),
        "requested unknown-parent body must getheaders, got {msg:?}"
    );
    assert!(
        follow.pending_blocks.contains_key(&hash),
        "requested unknown-parent body stays parked"
    );

    let peer = live_peer(peers, 18452, 4, false);
    peer.note_awaiting_headers();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    let mut block = orphan_body(BlockHash::from_byte_array([0xcd; 32]), 0);
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        }),
    )
    .await;
    assert!(!peer.stop.load(Ordering::SeqCst));
    assert!(hub
        .query
        .get_header_by_hash(&block.block_hash().to_byte_array())
        .unwrap()
        .is_none());
    assert!(
        hub.held_body(&block.block_hash()).is_none()
            && !follow.pending_blocks.contains_key(&block.block_hash()),
        "unknown-parent compact is header-only"
    );
    assert!(follow.pending_headers.contains_key(&block.block_hash()));
    let msgs = take_msgs(&mut out_rx);
    assert!(
        msgs.iter()
            .any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
        "unknown-parent compact must getheaders despite awaiting, got {msgs:?}"
    );
    peer.note_awaiting_headers();
    let mut child = block.clone();
    child.header.prev_blockhash = block.block_hash();
    child.header.merkle_root = child.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut child.header);
    let child_hsi = HeaderAndShortIds::from_block(&child, 1, 2, &[0]).unwrap();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: child_hsi,
        }),
    )
    .await;
    assert!(hub
        .query
        .get_header_by_hash(&child.block_hash().to_byte_array())
        .unwrap()
        .is_none());
    assert!(follow.pending_headers.contains_key(&child.block_hash()));
}

/// An unconnecting header still asks for headers. A full batch continues from
/// its last hash. A long pending chain is walked from RAM back to genesis.
async fn header_flood_and_pending_walk(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};

    let peer = live_peer(peers, 18453, 5, false);
    peer.note_awaiting_headers();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let unknown = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0xab; 32]),
        merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![unknown]),
    )
    .await;
    let msg = out_rx.try_recv().expect("getheaders").expect_msg();
    assert!(
        matches!(msg, NetworkMessage::GetHeaders(_)),
        "unconnecting header must getheaders despite awaiting, got {msg:?}"
    );

    let mut headers = Vec::with_capacity(MAX_HEADERS_RESULTS);
    let mut prev = BlockHash::from_byte_array([0x11; 32]);
    for i in 0..MAX_HEADERS_RESULTS {
        let mut merkle = [0u8; 32];
        merkle[0] = (i >> 8) as u8;
        merkle[1] = i as u8;
        let hdr = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(merkle),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: i as u32,
        };
        prev = hdr.block_hash();
        headers.push(hdr);
    }
    let last = headers.last().unwrap().block_hash();
    let our_tip = hub.tip_hash().unwrap();
    let peer = live_peer(peers, 18454, 6, false);
    let mut follow = PeerFollowState::new();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(headers),
    )
    .await;
    let mut locators = Vec::new();
    for msg in take_msgs(&mut out_rx) {
        if let NetworkMessage::GetHeaders(gh) = msg {
            locators.push(gh.locator_hashes);
        }
    }
    assert_eq!(
        locators.len(),
        1,
        "a full unconnected batch continues once, from the last header"
    );
    assert_eq!(locators[0].first().copied(), Some(last));
    assert_ne!(locators[0].first().copied(), Some(our_tip));

    let genesis = hub.tip_hash().unwrap();
    let n = 2_500u32;
    let mut pending = HashMap::new();
    let mut prev = genesis;
    let mut tip = genesis;
    for i in 0..n {
        let mut merkle = [0u8; 32];
        merkle[..4].copy_from_slice(&(i + 1).to_le_bytes());
        let hdr = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(merkle),
            time: 1 + i,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: i,
        };
        tip = hdr.block_hash();
        pending.insert(tip, hdr);
        prev = tip;
    }
    assert!(
        !hub.knows_header(&tip),
        "the pending walk's tip is not stored"
    );
    assert_eq!(
        announced_headers_height(hub, &pending, tip),
        n,
        "height comes from the pending map, then the stored genesis"
    );
    assert_eq!(
        header_branch_vs_tip(hub, &pending, tip),
        Some(std::cmp::Ordering::Greater)
    );
    assert!(header_announcement_connects(hub, &pending, genesis));
}

/// Claimed mainnet nBits without PoW does not fetch. A header whose parent
/// is missing does not fetch either.
async fn header_getdata_decisions(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};

    let gen = header_at(hub, 0);
    let hard = Header {
        version: Version::from_consensus(4),
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array([0x5a; 32]),
        time: gen.time.saturating_add(600),
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: 0,
    };
    let hard_hash = hard.block_hash();
    let mut pending = HashMap::new();
    pending.insert(hard_hash, hard);
    assert_ne!(
        announced_work_cmp(hub, &pending, hard_hash),
        Some(std::cmp::Ordering::Greater),
        "claimed nBits without PoW must not outwork the tip"
    );
    let peer = live_peer(peers, 18455, 7, false);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![hard]),
    )
    .await;
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "must not getdata a header that only claims hard nBits"
    );
    assert!(!hub.is_connected(&hard_hash));

    let orphan = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0x5b; 32]),
        time: 1_300_000_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let orphan_hash = orphan.block_hash();
    let mut pending = HashMap::new();
    pending.insert(orphan_hash, orphan);
    let want = fetchable_header_path_bodies(
        hub,
        &pending,
        orphan_hash,
        &PendingBlocks::new(),
        &HashSet::new(),
    );
    assert!(
        want.is_empty(),
        "a header path we cannot walk must not getdata"
    );
}

/// Below the floor a peer's headers are not stored and not fetched. The
/// batch that crosses the floor is fetched from height 1.
async fn minchainwork_while_tip_is_short(
    hub: &rbitcoin_net::chain::ChainHub,
    src: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip_before = hub.tip_height();
    hub.set_minimum_chain_work(Some(work_floor(0x1f)));
    let hdrs14: Vec<_> = (1..=14u32).map(|h| header_at(src, h)).collect();
    let peer = live_peer(peers, 18456, 8, false);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    for hdr in &hdrs14 {
        push(
            hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(vec![*hdr]),
        )
        .await;
    }
    let _ = take_msgs(&mut out_rx);
    let last = hdrs14[13].block_hash();
    assert_eq!(
        announced_headers_height(hub, &follow.pending_headers, last),
        14,
        "14 one-header announces report height 14"
    );
    assert_eq!(hub.tip_height(), tip_before);
    assert_eq!(side_tips(hub), 0, "low-work headers are not stored");

    hub.set_minimum_chain_work(Some(work_floor(0x65)));
    let hdrs50: Vec<_> = (1..=50u32).map(|h| header_at(src, h)).collect();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(hdrs50[..49].to_vec()),
    )
    .await;
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "49 headers stay under the floor"
    );
    assert_eq!(hub.tip_height(), tip_before);
    assert_eq!(side_tips(hub), 0, "low-work headers are not stored");

    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(hdrs50.clone()),
    )
    .await;
    let got = asked_blocks(&mut out_rx);
    assert_eq!(got.len(), MAX_SERVE_BLOCKS, "crossing the floor fetches");
    assert_eq!(got[0], hdrs50[0].block_hash());
    assert_eq!(
        got[MAX_SERVE_BLOCKS - 1],
        hdrs50[MAX_SERVE_BLOCKS - 1].block_hash()
    );
}

/// One header with real PoW harder than regtest still outworks a short tip.
async fn shorter_higher_work_still_fetches(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};

    let gen = header_at(hub, 0);
    let mut hard = Header {
        version: Version::from_consensus(4),
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array([0x5c; 32]),
        time: gen.time.saturating_add(600),
        bits: CompactTarget::from_consensus(0x1f7f_ffff),
        nonce: 0,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut hard);
    let hash = hard.block_hash();
    let mut pending = HashMap::new();
    pending.insert(hash, hard);
    assert_eq!(
        announced_work_cmp(hub, &pending, hash),
        Some(std::cmp::Ordering::Greater),
        "one harder header must outwork the short tip"
    );
    let peer = live_peer(peers, 18457, 9, false);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![hard]),
    )
    .await;
    assert_eq!(
        asked_blocks(&mut out_rx),
        vec![hash],
        "a shorter higher-work header is fetched"
    );
}

/// Tip work below 0x65 serves nothing. The next block crosses and is served.
fn mine_across_the_work_floor(hub: &rbitcoin_net::chain::ChainHub) {
    let height = hub.tip_height().unwrap();
    assert!(height < 49, "floor cross starts below height 49");
    hub.generate_to_script(49 - height, op_true(), vec![])
        .unwrap();
    assert_eq!(hub.tip_height(), Some(49));
    assert!(!hub.meets_minimum_chain_work());
    let h49 = hub.tip_hash().unwrap();
    let below =
        headers_reply_for_getheaders(hub, &GetHeadersMessage::new(vec![h49], zero_stop())).unwrap();
    assert!(
        below.is_empty(),
        "getheaders below minchainwork must be empty"
    );
    let mined = hub.generate_to_script(1, op_true(), vec![]).unwrap();
    assert_eq!(hub.tip_height(), Some(50));
    assert!(hub.meets_minimum_chain_work());
    let above =
        headers_reply_for_getheaders(hub, &GetHeadersMessage::new(vec![h49], zero_stop())).unwrap();
    assert_eq!(above.len(), 1, "getheaders at the floor serves the new header");
    assert_eq!(above[0].block_hash(), mined[0]);
}

/// A tall tip does not reconstruct an unknown-parent compact. It asks for headers.
async fn tall_unknown_parent_skips_reconstruct(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    assert!(hub.tip_height().unwrap() >= 20);
    let peer = live_peer(peers, 18458, 10, false);
    peer.note_awaiting_headers();
    let block = orphan_body(BlockHash::from_byte_array([0xcd; 32]), 0);
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        }),
    )
    .await;
    assert!(
        hub.held_body(&block.block_hash()).is_none()
            && !follow.pending_blocks.contains_key(&block.block_hash()),
        "tall-tip unknown-parent compact must not reconstruct"
    );
    assert!(follow.pending_headers.contains_key(&block.block_hash()));
    let msgs = take_msgs(&mut out_rx);
    assert!(
        msgs.iter()
            .any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
        "tall-tip unknown-parent compact must getheaders, got {msgs:?}"
    );
}

/// Bad proof-of-work disconnects. A stamp past the two-hour window does not.
async fn header_reject_punishes_except_time(hub: &rbitcoin_net::chain::ChainHub) {
    let gen = hub.tip_hash().unwrap();
    let tip_time = hub.tip_header().unwrap().time;
    let next_h = hub.tip_height().unwrap().saturating_add(1);
    let mut bad_pow = rbitcoin_consensus::mine_regtest_paying(
        gen,
        tip_time.saturating_add(1),
        next_h,
        op_true(),
        vec![],
    );
    let target = bitcoin::Target::from_compact(bad_pow.header.bits);
    loop {
        bad_pow.header.nonce = bad_pow.header.nonce.wrapping_add(1);
        if bad_pow.header.validate_pow(target).is_err() {
            break;
        }
    }
    let pow_err = hub.ensure_header(&bad_pow.header).unwrap_err();
    assert!(
        !rbitcoin_net::chain::accept_err_is_temporary_time(&pow_err),
        "bad pow is not a temporary stamp: {pow_err}"
    );
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(bad_pow.block_hash());
    push(hub, &out_tx, &mut follow, None, NetworkMessage::Block(bad_pow.clone())).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "a requested header with bad pow must disconnect"
    );
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        None,
        NetworkMessage::Block(bad_pow),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "an unrequested header with bad pow must disconnect"
    );

    // Core: a missing parent is `prev-blk-not-found` and Misbehaving. An
    // all-zero parent is missing too unless the block is genesis.
    let mut zero_prev = rbitcoin_consensus::mine_regtest_paying(
        gen,
        tip_time.saturating_add(2),
        next_h,
        op_true(),
        vec![],
    );
    zero_prev.header.prev_blockhash = zero_stop();
    rbitcoin_consensus::grind_regtest_pow(&mut zero_prev.header);
    let mut follow = PeerFollowState::new();
    push(hub, &out_tx, &mut follow, None, NetworkMessage::Block(zero_prev.clone())).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "an unrequested block with an all-zero parent must disconnect"
    );
    assert!(!hub.knows_header(&zero_prev.block_hash()));

    let now = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let future = rbitcoin_consensus::mine_regtest_paying(gen, now + 3 * 3600, 1, op_true(), vec![]);
    let time_err = hub.ensure_header(&future.header).unwrap_err();
    assert!(
        rbitcoin_net::chain::accept_err_is_temporary_time(&time_err),
        "a stamp past the two-hour window is temporary: {time_err}"
    );
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(future.block_hash());
    push(
        hub,
        &out_tx,
        &mut follow,
        None,
        NetworkMessage::Block(future.clone()),
    )
    .await;
    assert_eq!(
        follow.ban_score, 0,
        "time-too-new must not disconnect a requested block"
    );
    let mut follow = PeerFollowState::new();
    push(hub, &out_tx, &mut follow, None, NetworkMessage::Block(future)).await;
    assert_eq!(
        follow.ban_score, 0,
        "time-too-new must not disconnect an unrequested block"
    );
}

/// Empty locator returns a header only when that hash has a body.
fn empty_locator_needs_a_body(hub: &rbitcoin_net::chain::ChainHub) {
    let tip = hub.tip_hash().unwrap();
    let connected =
        headers_reply_for_getheaders(hub, &GetHeadersMessage::new(vec![], tip)).unwrap();
    assert_eq!(connected.len(), 1, "connected hashstop is served");

    let t0 = hub.header_of(&tip).unwrap().time;
    let height = hub.tip_height().unwrap();
    let pending =
        rbitcoin_consensus::mine_regtest_paying(tip, t0 + 1, height + 1, op_true(), vec![]);
    hub.process_submitted_header(&pending.header).unwrap();
    assert!(!hub.is_connected(&pending.block_hash()));
    let header_only = headers_reply_for_getheaders(
        hub,
        &GetHeadersMessage::new(vec![], pending.block_hash()),
    )
    .unwrap();
    assert!(
        header_only.is_empty(),
        "header-only hashstop is not served"
    );

    hub.generate_to_script(1, op_true(), vec![]).unwrap();
    let stale = hub.tip_hash().unwrap();
    hub.invalidate_block(stale).unwrap();
    assert!(!hub.is_connected(&stale));
    assert!(
        hub.query.is_block_archived(&stale.to_byte_array()).unwrap(),
        "invalidated tip still has a body"
    );
    let with_body =
        headers_reply_for_getheaders(hub, &GetHeadersMessage::new(vec![], stale)).unwrap();
    assert_eq!(
        with_body.len(),
        1,
        "disconnected hashstop with a body is served"
    );
}

/// A bad block disconnects a plain peer. noban and manual peers keep the
/// session and score nothing (Core `MaybeDiscourageAndDisconnect`).
async fn noban_and_manual_bad_block_is_not_punished(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let mut bad_pow =
        rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true(), vec![]);
    // Regtest accepts about half of nonces, so +1 is often still valid work.
    let target = bitcoin::Target::from_compact(bad_pow.header.bits);
    loop {
        bad_pow.header.nonce = bad_pow.header.nonce.wrapping_add(1);
        if bad_pow.header.validate_pow(target).is_err() {
            break;
        }
    }
    let (out_tx, _rx) = mpsc::unbounded_channel();

    let plain = live_peer(peers, 18472, 21, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(bad_pow.block_hash());
    on_block(
        hub,
        &out_tx,
        &mut follow,
        Some(plain.as_ref()),
        &bad_pow,
    )
    .await
    .unwrap();
    assert!(
        plain.stop.load(Ordering::SeqCst),
        "a plain peer is disconnected"
    );
    assert!(misbehavior_disconnects(
        follow.ban_score,
        Some(plain.as_ref())
    ));

    peers.set_noban(true);
    let kept = live_peer(peers, 18473, 22, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(bad_pow.block_hash());
    on_block(hub, &out_tx, &mut follow, Some(kept.as_ref()), &bad_pow)
        .await
        .unwrap();
    assert!(
        !kept.stop.load(Ordering::SeqCst),
        "Core never disconnects a noban peer for misbehavior"
    );
    assert_eq!(follow.ban_score, 0, "a noban peer gathers no score");
    assert!(
        !misbehavior_disconnects(BAN_SCORE_THRESHOLD, Some(kept.as_ref())),
        "a noban peer at the threshold stays connected"
    );
    assert!(misbehavior_disconnects(BAN_SCORE_THRESHOLD, None));
    assert!(!misbehavior_disconnects(BAN_SCORE_THRESHOLD - 1, None));
    peers.set_noban(false);

    // `--connect` and `addnode` peers are `manual`.
    let manual = live_peer_as(peers, 18477, 26, rbitcoin_net::peers::PeerConnType::Manual);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(bad_pow.block_hash());
    on_block(hub, &out_tx, &mut follow, Some(manual.as_ref()), &bad_pow)
        .await
        .unwrap();
    assert!(
        !manual.stop.load(Ordering::SeqCst),
        "Core never disconnects a manual peer for misbehavior"
    );
    assert_eq!(follow.ban_score, 0, "a manual peer gathers no score");
    assert!(
        !misbehavior_disconnects(BAN_SCORE_THRESHOLD, Some(manual.as_ref())),
        "a manual peer at the threshold stays connected"
    );
    // Core answers `sendaddrv2` after `verack` with `fDisconnect`, not
    // `Misbehaving`, so a manual peer is still dropped.
    on_sendaddrv2(&mut follow, Some(manual.as_ref()));
    assert!(
        manual.stop.load(Ordering::SeqCst),
        "a protocol violation still drops a manual peer"
    );
}

/// Core `IsBlockMutated`: a coinbase-less body with a 64-byte tx is dropped
/// and punished before relay or accept. Its hash is not cached as failed.
async fn sixty_four_byte_body_is_mutated(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let inner = rbitcoin_net::chain::sixty_four_byte_body(tip, time);
    let hash = inner.block_hash();
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let sender = live_peer(peers, 18474, 23, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(hash);
    hub.note_asked_block(hash);
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, Some(sender.as_ref()), &inner)
        .await
        .unwrap();
    assert!(
        logs_have("Block mutated: 64-byte transaction without a coinbase"),
        "the drop names the mutation"
    );
    assert!(
        sender.stop.load(Ordering::SeqCst),
        "Core punishes a mutated block"
    );
    assert!(
        !hub.is_block_invalid(&hash),
        "the header's real body must stay acceptable"
    );
    assert!(!hub.knows_header(&hash), "a mutated body adds no header");
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "a mutated drop forgets the ask so another peer can serve the real body"
    );
    assert!(!follow.requested_blocks.contains(&hash));
    assert_eq!(hub.tip_hash(), Some(tip));
}

/// An empty body has no merkle root. A header root of all zeros must not
/// pass that check and must not be stored.
async fn empty_body_null_merkle_bans_before_the_header(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip = hub.tip_hash().unwrap();
    let block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: tip,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: hub.tip_header().unwrap().time.saturating_add(4),
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: Vec::new(),
    };
    assert!(
        !block.check_merkle_root(),
        "an empty list has no merkle root"
    );
    let hash = block.block_hash();
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let sender = live_peer(peers, 18478, 27, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(hash);
    hub.note_asked_block(hash);
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, Some(sender.as_ref()), &block)
        .await
        .unwrap();
    assert!(
        logs_have("Block mutated: bad-txnmrklroot, hashMerkleRoot mismatch"),
        "the drop names the missing root"
    );
    assert!(
        sender.stop.load(Ordering::SeqCst),
        "Core punishes a mutated block"
    );
    assert!(!hub.knows_header(&hash), "a mutated body adds no header");
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "a mutated drop forgets the ask so another peer can serve the real body"
    );
    assert!(!follow.requested_blocks.contains(&hash));
    assert_eq!(hub.tip_hash(), Some(tip));
}

/// Core `RemoveBlockRequest` on a merkle-mismatch drop: the body is not the
/// header's, so another peer must be free to serve the real one.
async fn merkle_mismatch_forgets_the_ask(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(2);
    let mut wrong = rbitcoin_net::chain::sixty_four_byte_body(tip, time);
    let hash = wrong.block_hash();
    wrong.txdata[0].output[0].value = bitcoin::Amount::from_sat(1);
    assert!(!wrong.check_merkle_root());
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let sender = live_peer(peers, 18475, 24, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(hash);
    hub.note_asked_block(hash);
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, Some(sender.as_ref()), &wrong)
        .await
        .unwrap();
    assert!(
        logs_have("Block mutated: bad-txnmrklroot, hashMerkleRoot mismatch"),
        "the drop names the mutation"
    );
    assert!(
        sender.stop.load(Ordering::SeqCst),
        "Core punishes a mutated block"
    );
    assert!(!hub.is_block_invalid(&hash));
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "a mutated drop forgets the ask so another peer can serve the real body"
    );
    assert!(!follow.requested_blocks.contains(&hash));
    assert_eq!(hub.tip_hash(), Some(tip));
}

/// CVE-2012-2459: two identical transactions keep `check_merkle_root` and are
/// still not a block. Tip follow disconnects and does not cache the hash.
async fn duplicate_pair_disconnects(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::{OutPoint, Sequence, TxIn, TxOut, Version};
    use bitcoin::{Amount, ScriptBuf, Transaction, Witness};

    let cb = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: hub.tip_hash().unwrap(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: hub.tip_header().unwrap().time.saturating_add(3),
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![cb.clone(), cb],
    };
    block.header.merkle_root = block.compute_merkle_root().expect("pair");
    assert!(
        block.check_merkle_root(),
        "the duplicated pair still matches the header root"
    );
    let hash = block.block_hash();
    let tip = hub.tip_hash().unwrap();
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let sender = live_peer(peers, 18476, 25, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(hash);
    hub.note_asked_block(hash);
    rbitcoin_log::capture_logs(true);
    on_block(
        hub,
        &out_tx,
        &mut follow,
        Some(sender.as_ref()),
        &block,
    )
    .await
    .unwrap();
    assert!(
        logs_have("Block mutated: bad-txns-duplicate"),
        "the drop names the duplicate pair"
    );
    assert!(
        sender.stop.load(Ordering::SeqCst),
        "tip follow disconnects a duplicate-pair body"
    );
    assert!(
        !hub.is_block_invalid(&hash),
        "the real body for this hash must stay acceptable"
    );
    assert!(!follow.requested_blocks.contains(&hash));
    assert_eq!(hub.tip_hash(), Some(tip));
}

/// A block whose header fails contextual checks still logs Core's reject reason.
async fn rejected_header_logs_core_reason(hub: &rbitcoin_net::chain::ChainHub) {
    use bitcoin::block::Version;
    use bitcoin::Target;
    let tip = hub.tip_height().unwrap();
    assert!(
        tip < 111,
        "the CLTV beat starts below activation, tip={tip}"
    );
    if tip < 110 {
        hub.generate_to_script(110 - tip, op_true(), vec![])
            .unwrap();
    }
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let mut v3 = rbitcoin_consensus::mine_regtest_paying(prev, time, 111, op_true(), vec![]);
    v3.header.version = Version::from_consensus(3);
    let target = Target::from_compact(v3.header.bits);
    while v3.header.validate_pow(target).is_err() {
        v3.header.nonce = v3.header.nonce.wrapping_add(1);
    }
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(v3.block_hash());
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, None, &v3)
        .await
        .unwrap();
    let lines = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let want = format!("{}, bad-version(0x00000003)", v3.block_hash());
    assert!(
        lines.iter().any(|(_, l)| l == &want),
        "missing {want:?} in {lines:?}"
    );

    let now = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let future = rbitcoin_consensus::mine_regtest_paying(prev, now + 3 * 3600, 111, op_true(), vec![]);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.insert(future.block_hash());
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, None, &future)
        .await
        .unwrap();
    let lines = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        lines
            .iter()
            .any(|(_, l)| l == "Block validation error: time-too-new"),
        "missing time-too-new in {lines:?}"
    );
}

/// A connecting header more than 288 below the tip disconnects. noban stays.
async fn ancient_weaker_fork_disconnects(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};

    assert!(hub.tip_height().unwrap() >= 300);
    let gen = header_at(hub, 0);
    let mut side = Header {
        version: Version::from_consensus(4),
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array([0x9e; 32]),
        time: gen.time.saturating_add(600),
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut side);

    let peer = live_peer(peers, 18470, 11, false);
    let (out_tx, _rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![side]),
    )
    .await;
    assert_eq!(follow.ban_score, 0, "an ancient fork is not a ban");
    assert!(
        peer.stop.load(Ordering::SeqCst),
        "an ancient weaker header disconnects"
    );

    peers.set_noban(true);
    let kept = live_peer(peers, 18471, 12, false);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(kept.as_ref()),
        NetworkMessage::Headers(vec![side]),
    )
    .await;
    assert!(
        !kept.stop.load(Ordering::SeqCst),
        "noban keeps the session on an ancient weaker fork"
    );
}

/// Clearnet externalip, then onion and i2p on the same address book.
/// `--no-discover` and the external address set here are what the overlay
/// beat checks, and the onion address stays set for the i2p beat.
#[test]
fn self_announce_clearnet_then_overlay() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    self_announce_clearnet(&peers);
    self_announce_overlay(&peers);
}

/// externalip is sent once, again after a day, and not when it is loopback
/// or `--no-discover` is set.
fn self_announce_clearnet(peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>) {
    use std::net::{IpAddr, Ipv4Addr};

    let peer = live_peer(peers, 18480, 13, false);
    assert!(peer.take_local_addr_due(1_000).is_none());
    peers.set_listen_port(18445);
    peers.set_external_ips(vec![IpAddr::V4(Ipv4Addr::new(42, 42, 42, 42))]);
    let first = peer
        .take_local_addr_due(1_000)
        .expect("initial self-announce");
    assert_eq!(first.to_string(), "42.42.42.42:18445");
    assert!(peer.take_local_addr_due(1_000).is_none());
    assert!(peer.take_local_addr_due(1_000 + 24 * 3600 - 1).is_none());
    let again = peer
        .take_local_addr_due(1_000 + 24 * 3600)
        .expect("daily self-announce");
    assert_eq!(again.to_string(), "42.42.42.42:18445");
    peers.set_external_ips(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    assert!(
        peer.take_local_addr_due(1_000 + 48 * 3600).is_none(),
        "loopback must not be advertised"
    );

    peers.set_external_ips(vec![IpAddr::V4(Ipv4Addr::new(42, 42, 42, 42))]);
    peers.set_discover(false);
    assert!(
        peer.take_local_addr_due(1_000 + 72 * 3600).is_none(),
        "--no-discover must suppress self-announce"
    );
    assert!(peer.take_self_announce_msg().is_none());
    assert!(peers.rpc_local_addresses().is_empty());
}

/// Onion and i2p are advertised instead of `--externalip`. v1 ADDR cannot
/// carry an i2p destination. Onion stays set: the i2p beat is the same book.
fn self_announce_overlay(peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>) {
    use bitcoin::p2p::address::AddrV2;

    let onion_peer = live_peer(peers, 18481, 14, false);
    onion_peer.set_wants_addrv2();
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:18444"
            .parse()
            .unwrap();
    peers.set_p2p_onion(onion.host_str(), onion.port());
    peers.set_clearnet_listen(false);
    peers.set_listen_port(18445);
    assert!(peers.advertise_local_socket().is_none());
    match onion_peer.take_self_announce_msg().expect("onion announce") {
        NetworkMessage::AddrV2(v) => {
            assert_eq!(v.len(), 1, "{v:?}");
            assert!(matches!(v[0].addr, AddrV2::TorV3(_)));
            assert_eq!(v[0].port, 18444);
        }
        other => panic!("expected AddrV2 onion, got {other:?}"),
    }
    let rows = peers.rpc_local_addresses();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].0.ends_with(".onion"));
    assert_eq!(rows[0].1, 18444);
    peers.set_discover(true);
    assert!(
        peers.advertise_local_socket().is_none(),
        "onion-only must not gossip --external-ip"
    );

    peers.set_discover(false);
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    };
    peers.set_p2p_i2p(i2p);
    let i2p_peer = live_peer(peers, 18482, 15, false);
    i2p_peer.set_wants_addrv2();
    match i2p_peer.take_self_announce_msg().expect("i2p announce") {
        NetworkMessage::AddrV2(v) => {
            assert!(
                v.iter()
                    .any(|a| matches!(a.addr, AddrV2::I2p(d) if d == [0x11; 32]) && a.port == 0),
                "i2p destination is advertised, got {v:?}"
            );
            assert!(
                v.iter().all(|a| !matches!(a.addr, AddrV2::Ipv4(_))),
                "i2p announce must not fall back to externalip, got {v:?}"
            );
        }
        other => panic!("expected AddrV2 i2p, got {other:?}"),
    }
    let rows = peers.rpc_local_addresses();
    assert!(
        rows.iter().any(|row| row.0 == i2p.host_str() && row.1 == 0),
        "local addresses include the i2p destination, got {rows:?}"
    );
    assert!(
        rows.iter().all(|row| row.0 != "42.42.42.42"),
        "no-discover must not publish externalip, got {rows:?}"
    );
    let v1 = live_peer(peers, 18483, 16, false);
    assert!(
        v1.take_self_announce_msg().is_none(),
        "v1 ADDR cannot carry an I2P destination"
    );
}

/// One peer. Verack order, unknown parents, header floods, and minchainwork
/// share this hub. CLTV activates at 111 so a rejected header can log Core's
/// reason on the same chain.
#[tokio::test]
async fn peer_header_dos_and_self_announce() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("hdr-dos");
    let mut params = ChainParams::regtest();
    params.apply_test_activation_height("cltv", 111).unwrap();
    let hub = ChainHub::new(q, params, Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();

    handshake_verack_and_addrv2(&hub, &peers).await;
    unknown_parent_bodies(&hub, &peers).await;
    header_flood_and_pending_walk(&hub, &peers).await;

    let (src_dir, src) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-dos-src");
    src.ensure_genesis().unwrap();
    src.generate_to_script(50, op_true(), vec![]).unwrap();
    minchainwork_while_tip_is_short(&hub, &src, &peers).await;

    hub.generate_to_script(5, op_true(), vec![]).unwrap();
    assert_eq!(hub.tip_height(), Some(5));
    header_getdata_decisions(&hub, &peers).await;
    shorter_higher_work_still_fetches(&hub, &peers).await;

    mine_across_the_work_floor(&hub);
    hub.set_minimum_chain_work(None);

    tall_unknown_parent_skips_reconstruct(&hub, &peers).await;
    header_reject_punishes_except_time(&hub).await;
    noban_and_manual_bad_block_is_not_punished(&hub, &peers).await;
    sixty_four_byte_body_is_mutated(&hub, &peers).await;
    empty_body_null_merkle_bans_before_the_header(&hub, &peers).await;
    merkle_mismatch_forgets_the_ask(&hub, &peers).await;
    duplicate_pair_disconnects(&hub, &peers).await;
    rejected_header_logs_core_reason(&hub).await;

    let tip = hub.tip_height().unwrap();
    if tip < 300 {
        hub.generate_to_script(300 - tip, op_true(), vec![]).unwrap();
    }
    ancient_weaker_fork_disconnects(&hub, &peers).await;
    empty_locator_needs_a_body(&hub);

    let _ = std::fs::remove_dir_all(src_dir);
    let _ = std::fs::remove_dir_all(dir);
}

/// Tip work meets the floor. A bad-proof-of-work compact whose parent is the
/// tip must not walk the mempool, and it scores like a bad `block`. A valid
/// compact of the next block still fills from the mempool.
#[tokio::test]
async fn bad_pow_cmpct_does_not_scan_mempool() {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-pow");
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(1, op_true(), vec![]).unwrap();
    let floor = hub.chain_work().unwrap().to_be_bytes();
    hub.set_minimum_chain_work(Some(floor));
    assert!(hub.meets_minimum_chain_work());
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
        .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();

    let bad = bad_pow_cmpct_on_tip(&hub);
    assert_eq!(bad.short_ids.len(), 1);
    assert!(!hub.header_claimed_pow_ok(&bad.header));
    let scans = mp.cmpct_avail_scans();
    let plain = live_peer(&peers, 18510, 30, true);
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(plain.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: bad.clone(),
        }),
    )
    .await;
    assert_eq!(
        mp.cmpct_avail_scans(),
        scans,
        "bad proof of work must not walk the mempool"
    );
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "bad compact proof of work scores like a bad block"
    );
    assert!(
        plain.stop.load(Ordering::SeqCst),
        "a plain peer is disconnected"
    );
    assert!(
        follow.pending_headers.is_empty(),
        "bad proof of work must not enter pending headers"
    );
    assert!(
        plain.best_known().is_none(),
        "bad proof of work must not update best known"
    );
    let rejected = take_msgs(&mut out_rx);
    assert!(
        !rejected
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetBlockTxn(_))),
        "a rejected compact must not ask for blocktxn"
    );
    assert!(
        !rejected
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
        "a rejected compact must not ask for headers"
    );

    peers.set_noban(true);
    let noban = live_peer(&peers, 18511, 31, true);
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    let scans = mp.cmpct_avail_scans();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(noban.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: bad.clone(),
        }),
    )
    .await;
    assert_eq!(mp.cmpct_avail_scans(), scans);
    assert_eq!(follow.ban_score, 0, "a noban peer gathers no score");
    assert!(!noban.stop.load(Ordering::SeqCst));
    peers.set_noban(false);

    let manual = live_peer_as(&peers, 18512, 32, rbitcoin_net::peers::PeerConnType::Manual);
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    let scans = mp.cmpct_avail_scans();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(manual.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock { compact_block: bad }),
    )
    .await;
    assert_eq!(mp.cmpct_avail_scans(), scans);
    assert_eq!(follow.ban_score, 0, "a manual peer gathers no score");
    assert!(!manual.stop.load(Ordering::SeqCst));

    hub.generate_to_script(100, op_true(), vec![]).unwrap();
    assert_eq!(hub.tip_height(), Some(101));
    let cb = hub
        .query
        .reconstruct_block_at_height(rbitcoin_primitives::Height(1))
        .unwrap()
        .txdata
        .into_iter()
        .next()
        .unwrap();
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cb.compute_txid(),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_9000),
            script_pubkey: op_true(),
        }],
    };
    let spend_id = spend.compute_txid();
    mp.accept_tx(&spend).expect("mature coinbase spend");
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let block =
        rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true(), vec![spend]);
    let hsi = HeaderAndShortIds::from_block(&block, 7, 2, &[0]).unwrap();
    assert_eq!(hsi.short_ids.len(), 1);
    assert!(hub.header_claimed_pow_ok(&hsi.header));
    let scans = mp.cmpct_avail_scans();
    let peer = live_peer(&peers, 18513, 33, true);
    peer.set_hb_to(true);
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock { compact_block: hsi }),
    )
    .await;
    assert_eq!(
        mp.cmpct_avail_scans(),
        scans + 1,
        "a valid compact of the next tip still reads the mempool"
    );
    assert_eq!(hub.tip_height(), Some(102));
    assert!(!mp.contains(&spend_id));
    assert_eq!(follow.ban_score, 0);
    let _ = std::fs::remove_dir_all(dir);
}

/// Next-tip compact with one short id and a nonce that fails proof of work.
fn bad_pow_cmpct_on_tip(hub: &rbitcoin_net::chain::ChainHub) -> bitcoin::bip152::HeaderAndShortIds {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let extra = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x44; 32]),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: op_true(),
        }],
    };
    let block = rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true(), vec![extra]);
    let mut hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    let target = bitcoin::Target::from_compact(hsi.header.bits);
    loop {
        hsi.header.nonce = hsi.header.nonce.wrapping_add(1);
        if hsi.header.validate_pow(target).is_err() {
            break;
        }
    }
    hsi
}

/// A connecting batch under the floor is ignored without reading parent headers.
#[tokio::test]
async fn below_floor_headers_do_not_walk_parents() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("below-floor");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (src_dir, src) = rbitcoin_net::chain::tiny_regtest_hub_labeled("below-floor-src");
    src.ensure_genesis().unwrap();
    src.generate_to_script(3, op_true(), vec![]).unwrap();
    hub.set_minimum_chain_work(Some(work_floor(0xff)));
    assert!(!hub.meets_minimum_chain_work());
    let hdrs: Vec<_> = (1..=3u32).map(|h| header_at(&src, h)).collect();
    let peer = live_peer(&peers, 18601, 41, false);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    // Warm the tip-work prefix so the floor check itself is not the lookup.
    let _ = hub.meets_minimum_chain_work();
    rbitcoin_net::chain::reset_header_store_counts();
    let before = rbitcoin_query::header_lookup_count();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(hdrs.clone()),
    )
    .await;
    let looked = rbitcoin_query::header_lookup_count().saturating_sub(before);
    assert_eq!(
        looked, 0,
        "below-floor ignore must not read parent headers, looked={looked}"
    );
    assert_eq!(
        rbitcoin_net::chain::header_store_counts().2,
        0,
        "below-floor ignore uses the cached tip work"
    );
    assert!(
        peer.best_known().is_none(),
        "a low-work batch does not become the peer's best known"
    );
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "below-floor headers are not fetched"
    );
    assert_eq!(side_tips(&hub), 0, "below-floor headers are not stored");
    peers.set_noban(true);
    let noban = live_peer(&peers, 18602, 42, false);
    let mut follow_nb = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow_nb,
        Some(noban.as_ref()),
        NetworkMessage::Headers(hdrs),
    )
    .await;
    assert!(
        side_tips(&hub) > 0,
        "a noban peer still persists a below-floor chain"
    );
    peers.set_noban(false);
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(src_dir);
}

/// A lagging height index is not connected. Filling that gap reads every
/// missing header, so the peer and IBD checks must not do it.
#[tokio::test]
async fn connected_check_does_not_catch_up_the_height_index() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("idx-lag-conn");
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(4, op_true(), vec![]).unwrap();
    let tip = hub.tip_hash().unwrap();
    assert!(hub.is_connected(&tip));
    hub.query.invalidate_height_by_hash_index();
    rbitcoin_net::chain::reset_header_store_counts();
    let before = rbitcoin_query::header_lookup_count();
    assert!(
        !hub.is_connected(&tip),
        "a hash above the indexed tip is not connected until the index catches up on its own"
    );
    let looked = rbitcoin_query::header_lookup_count().saturating_sub(before);
    assert_eq!(
        looked, 0,
        "the connected check must not read headers to fill the index, looked={looked}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A header that does not connect through pending headers is still ignored
/// while our chain is under the floor. Summing that path used to give up
/// and read parent headers.
#[tokio::test]
async fn below_floor_disconnected_header_does_not_walk_parents() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("below-floor-disc");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    hub.set_minimum_chain_work(Some(work_floor(0xff)));
    assert!(!hub.meets_minimum_chain_work());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18621, 61, false);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let orphan = regtest_header_chain(BlockHash::from_byte_array([0x11; 32]), 1);
    rbitcoin_net::chain::reset_header_store_counts();
    let before = rbitcoin_query::header_lookup_count();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(orphan),
    )
    .await;
    let looked = rbitcoin_query::header_lookup_count().saturating_sub(before);
    assert_eq!(
        looked, 0,
        "a below-floor header with no pending parent must not read the store, looked={looked}"
    );
    assert_eq!(side_tips(&hub), 0);
    assert!(asked_blocks(&mut out_rx).is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

/// Pending already holds the cap, and the next full batch still connects.
/// That is 8_000 + 2_000 headers. The walk used to stop on the last step
/// and then read parents.
#[tokio::test]
async fn full_pending_below_floor_does_not_walk_parents() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("below-floor-cap");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    hub.set_minimum_chain_work(Some([0xff; 32]));
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18622, 62, false);
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    let batch = MAX_HEADERS_RESULTS as u32;
    let mut prev = hub.tip_hash().unwrap();
    for _ in 0..(MAX_PENDING_HEADERS as u32 / batch) {
        let chain = regtest_header_chain(prev, batch);
        prev = chain.last().unwrap().block_hash();
        push(
            &hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(chain),
        )
        .await;
    }
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    rbitcoin_net::chain::reset_header_store_counts();
    let before = rbitcoin_query::header_lookup_count();
    let chain = regtest_header_chain(prev, batch);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(chain),
    )
    .await;
    let looked = rbitcoin_query::header_lookup_count().saturating_sub(before);
    assert_eq!(
        looked, 0,
        "a full pending map plus one batch must not read parent headers, looked={looked}"
    );
    assert_eq!(side_tips(&hub), 0, "the batch stays under the floor");
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    let _ = std::fs::remove_dir_all(dir);
}

/// Headers with real regtest proof-of-work, not accepted blocks. Accepting
/// two thousand blocks is a full connect per height.
fn regtest_header_chain(prev: BlockHash, n: u32) -> Vec<bitcoin::block::Header> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = prev;
    for i in 1..=n {
        let mut header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([i as u8; 32]),
            time: 1_600_000_000 + i * 600,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        rbitcoin_consensus::grind_regtest_pow(&mut header);
        prev = header.block_hash();
        out.push(header);
    }
    out
}

/// A full batch under minimum chain work is ignored and not paged.
/// The next header, sent on its own, is stored once the path crosses the floor.
#[tokio::test]
async fn below_floor_full_batch_does_not_page() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("below-floor-full");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let n = MAX_HEADERS_RESULTS as u32;
    let chain = regtest_header_chain(hub.tip_hash().unwrap(), n + 1);
    let base = hub.chain_work().unwrap();
    let below = rbitcoin_net::most_work::sum_work(
        std::iter::once(base).chain(chain[..n as usize].iter().map(|h| h.work())),
    )
    .unwrap()
    .to_be_bytes();
    let floor = rbitcoin_net::most_work::sum_work(std::iter::once(base).chain(chain.iter().map(|h| h.work())))
        .unwrap()
        .to_be_bytes();
    assert!(below < floor, "the full batch is still under the next header");
    hub.set_minimum_chain_work(Some(floor));
    let first = chain[..n as usize].to_vec();
    let peer = live_peer(&peers, 18611, 51, false);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(first),
    )
    .await;
    assert!(peer.best_known().is_none());
    assert_eq!(side_tips(&hub), 0, "the below-floor batch is not stored");
    let mut locators = Vec::new();
    for msg in take_msgs(&mut out_rx) {
        if let NetworkMessage::GetHeaders(gh) = msg {
            locators.push(gh.locator_hashes);
        }
    }
    assert!(
        locators.is_empty(),
        "a refused below-floor batch does not ask for the next page"
    );
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![chain[n as usize]]),
    )
    .await;
    assert!(
        side_tips(&hub) > 0,
        "the chain is stored once pending work crosses the floor"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A side block three days behind the best header is still served. Every
/// `+` and `/` rewrite of the 30-day limit is shorter than three days.
#[test]
fn three_day_side_block_is_served() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("stale-serve");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = 1_700_000_000u32;
    hub.clock.set_mock(i64::from(t0));
    let old = rbitcoin_consensus::mine_regtest_paying(gen, t0, 1, op_true(), vec![]);
    hub.accept_block(old.clone()).unwrap();
    let old_hash = old.block_hash();
    hub.invalidate_block(old_hash).unwrap();
    let t1 = t0 + 3 * 24 * 60 * 60;
    hub.clock.set_mock(i64::from(t1));
    let tip = rbitcoin_consensus::mine_regtest_paying(gen, t1, 1, op_true(), vec![]);
    hub.accept_block(tip).unwrap();
    assert!(!hub.is_connected(&old_hash));
    let served =
        headers_reply_for_getheaders(&hub, &GetHeadersMessage::new(vec![], old_hash)).unwrap();
    assert_eq!(
        served.len(),
        1,
        "a side block three days behind the tip is served"
    );
    assert_eq!(served[0].block_hash(), old_hash);
    let _ = std::fs::remove_dir_all(dir);
}

/// The store has no tip. `getheaders` is answered from the recent body cache.
#[test]
fn getheaders_serves_cached_bodies_when_the_store_has_no_tip() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cache-serve");
    assert!(hub.tip_height().is_none());
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    hub.cache.push_best(genesis.clone()).unwrap();
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    let mut hashes = vec![prev];
    for h in 1..=3u32 {
        time = time.saturating_add(600);
        let block = rbitcoin_consensus::mine_regtest_paying(prev, time, h, op_true(), vec![]);
        prev = block.block_hash();
        hashes.push(prev);
        hub.cache.push_best(block).unwrap();
    }
    let stop = hashes[2];
    let served = headers_reply_for_getheaders(
        &hub,
        &GetHeadersMessage::new(vec![hashes[0]], stop),
    )
    .unwrap();
    assert_eq!(served.len(), 2, "headers start after the locator and stop at the hash");
    assert_eq!(served[0].block_hash(), hashes[1]);
    assert_eq!(served[1].block_hash(), stop);
    let _ = std::fs::remove_dir_all(dir);
}

/// Noting a later block must not forget the earlier ask. A second peer
/// announcing the same headers does not fetch the first body again.
#[tokio::test]
async fn a_later_ask_keeps_the_earlier_block() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("asked-keep");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let gen = hub.tip_hash().unwrap();
    let t = hub.tip_header().unwrap().time.saturating_add(1);
    let a = rbitcoin_consensus::mine_regtest_paying(gen, t, 1, op_true(), vec![]);
    let b = rbitcoin_consensus::mine_regtest_paying(a.block_hash(), t.saturating_add(1), 2, op_true(), vec![]);
    let peer = live_peer(&peers, 18601, 40, false);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![a.header, b.header]),
    )
    .await;
    let first = asked_blocks(&mut out_rx);
    assert!(
        first.contains(&a.block_hash()) && first.contains(&b.block_hash()),
        "both bodies are fetched once, got {first:?}"
    );

    let peer2 = live_peer(&peers, 18602, 41, false);
    let (out2, mut rx2) = mpsc::unbounded_channel();
    let mut follow2 = PeerFollowState::new();
    push(
        &hub,
        &out2,
        &mut follow2,
        Some(peer2.as_ref()),
        NetworkMessage::Headers(vec![a.header, b.header]),
    )
    .await;
    let second = asked_blocks(&mut rx2);
    assert!(
        !second.contains(&a.block_hash()),
        "the first body stays asked after the later one is noted, got {second:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
