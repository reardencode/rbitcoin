use std::sync::atomic::Ordering;

fn work_floor(low: u8) -> [u8; 32] {
    let mut min = [0u8; 32];
    min[31] = low;
    min
}

fn side_tips(hub: &crate::chain::ChainHub) -> usize {
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
    hub: &crate::chain::ChainHub,
    out_tx: &mpsc::UnboundedSender<PeerOut>,
    follow: &mut PeerFollowState,
    session: Option<&crate::peers::LivePeer>,
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
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
) {
    use bitcoin::p2p::address::AddrV2;
    assert_eq!(
        crate::peer::sendaddrv2_after_verack_log(0),
        "p2p: sendaddrv2 received after verack, disconnecting peer=0"
    );
    assert_eq!(
        crate::peer::addrv2_message_size_log(1010),
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
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
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
    let block = orphan_body(BlockHash::from_byte_array([0xcd; 32]), 0);
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
    child.header.nonce = 1;
    child.header.merkle_root = child.compute_merkle_root().unwrap();
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
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
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
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
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
    hub: &crate::chain::ChainHub,
    src: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
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
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
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
fn mine_across_the_work_floor(hub: &crate::chain::ChainHub) {
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
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
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
async fn header_reject_punishes_except_time(hub: &crate::chain::ChainHub) {
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
        !crate::chain::accept_err_is_temporary_time(&pow_err),
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
        crate::chain::accept_err_is_temporary_time(&time_err),
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
fn empty_locator_needs_a_body(hub: &crate::chain::ChainHub) {
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

/// A bad block disconnects a plain peer. noban keeps the session and scores nothing.
async fn noban_bad_block_is_not_punished(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
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
}

/// Core `IsBlockMutated`: a coinbase-less body with a 64-byte tx is dropped
/// and punished before relay or accept. Its hash is not cached as failed.
async fn sixty_four_byte_body_is_mutated(
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
) {
    let tip = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let inner = crate::chain::sixty_four_byte_body(tip, time);
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

/// A block whose header fails contextual checks still logs Core's reject reason.
async fn rejected_header_logs_core_reason(hub: &crate::chain::ChainHub) {
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
    hub: &crate::chain::ChainHub,
    peers: &std::sync::Arc<crate::peers::PeerHub>,
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

/// externalip is sent once, again after a day, and not when it is loopback
/// or `--no-discover` is set.
fn self_announce_clearnet(peers: &std::sync::Arc<crate::peers::PeerHub>) {
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
fn self_announce_overlay(peers: &std::sync::Arc<crate::peers::PeerHub>) {
    use bitcoin::p2p::address::AddrV2;

    let onion_peer = live_peer(peers, 18481, 14, false);
    onion_peer.set_wants_addrv2();
    let onion: crate::NetAddr =
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
    let i2p = crate::NetAddr::I2p {
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

/// One peer. Verack order, unknown parents, header floods, minchainwork,
/// and self-announce share this hub. CLTV activates at 111 so a rejected
/// header can log Core's reason on the same chain.
#[tokio::test]
async fn peer_header_dos_and_self_announce() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("hdr-dos");
    let mut params = ChainParams::regtest();
    params.apply_test_activation_height("cltv", 111).unwrap();
    let hub = ChainHub::new(q, params, Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = crate::peers::PeerHub::new();

    handshake_verack_and_addrv2(&hub, &peers).await;
    unknown_parent_bodies(&hub, &peers).await;
    header_flood_and_pending_walk(&hub, &peers).await;

    let (src_dir, src) = crate::chain::tiny_regtest_hub_labeled("hdr-dos-src");
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
    noban_bad_block_is_not_punished(&hub, &peers).await;
    sixty_four_byte_body_is_mutated(&hub, &peers).await;
    rejected_header_logs_core_reason(&hub).await;

    let tip = hub.tip_height().unwrap();
    if tip < 300 {
        hub.generate_to_script(300 - tip, op_true(), vec![]).unwrap();
    }
    ancient_weaker_fork_disconnects(&hub, &peers).await;
    empty_locator_needs_a_body(&hub);
    self_announce_clearnet(&peers);
    self_announce_overlay(&peers);

    let _ = std::fs::remove_dir_all(src_dir);
    let _ = std::fs::remove_dir_all(dir);
}
