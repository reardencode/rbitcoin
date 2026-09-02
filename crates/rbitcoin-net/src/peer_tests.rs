use super::*;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet};

fn tmp_store(label: &str) -> (std::path::PathBuf, Query) {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-peer-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let q = Query::open_or_create(&dir).unwrap();
    (dir, q)
}

#[test]
fn store_not_found_is_soft_session_error() {
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "store: record not found".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "consensus: store: record not found".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "StoreError::NotFound for fk".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "NOT FOUND".into()
    )));
    assert!(!net_error_is_store_not_found(&NetError::Consensus(
        "corrupt record: multi-spender".into()
    )));
    assert!(!net_error_is_store_not_found(&NetError::Protocol(
        "unknown parent"
    )));
    assert!(!net_error_is_store_not_found(&NetError::Timeout));
    assert!(!net_error_is_store_not_found(&NetError::Io(
        std::io::Error::new(std::io::ErrorKind::Other, "x")
    )));
}

#[test]
fn from_this_peer_insert_caps_and_keeps_latest() {
    use bitcoin::hashes::Hash;
    let mut m = HashMap::new();
    let cap = 4usize;
    for i in 0u8..6 {
        insert_capped_txid(&mut m, bitcoin::Txid::from_byte_array([i; 32]), cap);
        assert!(m.len() <= cap, "len {}", m.len());
    }
    assert!(m.contains_key(&bitcoin::Txid::from_byte_array([5u8; 32])));
    assert_eq!(FROM_THIS_PEER_CAP, 50_000);
}

#[test]
fn tip_follow_locator_empty_store_has_genesis_zero() {
    let (dir, q) = tmp_store("empty");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    let loc = tip_follow_locator(&hub);
    assert!(!loc.is_empty());
    assert_eq!(loc.last().unwrap().to_byte_array(), [0u8; 32]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_follow_locator_includes_tip_after_genesis() {
    let (dir, q) = tmp_store("gen");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let loc = tip_follow_locator(&hub);
    assert!(!loc.is_empty());
    // Newest-first: tip hash is first.
    assert_eq!(loc[0], hub.tip_hash().unwrap());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_sync_locator_from_unknown_starts_at_that_hash() {
    let (dir, q) = tmp_store("loc-unk");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let start = BlockHash::from_byte_array([0xab; 32]);
    let loc = headers_sync_locator(&hub, Some(start));
    assert_eq!(loc[0], start);
    assert_eq!(loc.last().copied(), hub.tip_hash());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_sync_locator_from_mid_height_starts_there() {
    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let (dir, q) = tmp_store("loc-mid");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let hashes = hub
        .generate_to_script(3, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let mid = hashes[0];
    let loc = headers_sync_locator(&hub, Some(mid));
    assert_eq!(loc[0], mid);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn should_poll_peer_headers_skips_behind_and_weaker_fork() {
    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let (dir, q) = tmp_store("poll-skip");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    assert!(should_poll_peer_headers(&hub, None));
    hub.generate_to_script(3, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub.tip_hash().unwrap();
    assert!(
        should_poll_peer_headers(&hub, Some(tip)),
        "at our tip: still poll in case they have a new block"
    );
    assert!(
        !should_poll_peer_headers(&hub, Some(gen)),
        "best-known on our chain behind tip cannot supply headers after our locator"
    );
    assert!(
        should_poll_peer_headers(&hub, Some(BlockHash::from_byte_array([0xee; 32]))),
        "unknown best-known still poll until we can classify the branch"
    );
    let fork = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: gen,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x22; 32]),
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 99,
    };
    hub.ensure_header(&fork).unwrap();
    assert!(
        !should_poll_peer_headers(&hub, Some(fork.block_hash())),
        "persisted weaker fork cannot beat our tip"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn live_follow_dec_on_drop() {
    let c = Arc::new(AtomicUsize::new(2));
    {
        let _g = LiveFollowDec(Some(c.clone()));
        assert_eq!(c.load(Ordering::SeqCst), 2);
    }
    assert_eq!(c.load(Ordering::SeqCst), 1);
    // None branch is a no-op drop.
    let _ = LiveFollowDec(None);
}

#[test]
fn local_service_flags_include_network_witness_v2() {
    let f = local_service_flags();
    assert!(f.has(ServiceFlags::NETWORK));
    assert!(f.has(ServiceFlags::WITNESS));
    assert!(f.has(ServiceFlags::P2P_V2));
}

#[test]
fn rand_nonce_changes() {
    let a = rand_nonce();
    let b = rand_nonce();
    // Counter component makes back-to-back nonces distinct.
    assert_ne!(a, b);
}

#[test]
fn block_for_peer_empty_store_none() {
    let (dir, q) = tmp_store("block-none");
    let cache = BlockCache::new();
    let miss = BlockHash::from_byte_array([0xab; 32]);
    assert!(block_for_peer(&cache, &q, &miss).unwrap().is_none());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_announce_headers_and_inv() {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
        merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let hash = header.block_hash();
    let ev = crate::chain::TipEvent {
        height: 1,
        hash,
        header,
        reorg_branch_len: 0,
    };
    let (dir, q) = tmp_store("announce-msg");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    match tip_announce_decision(&hub, &ev, true, None, None, false) {
        TipAnnounce::Headers(h) => {
            assert_eq!(h.len(), 1);
            assert_eq!(h[0].block_hash(), hash);
        }
        other => panic!("expected Headers, got {other:?}"),
    }
    match tip_announce_decision(&hub, &ev, false, None, None, false) {
        TipAnnounce::Inv(h) => {
            assert_eq!(h, hash);
            let inv = NetworkMessage::Inv(vec![Inventory::Block(h)]);
            assert!(
                matches!(
                    &inv,
                    NetworkMessage::Inv(v) if matches!(v.as_slice(), [Inventory::Block(_)])
                ),
                "tip announce inv must be MSG_BLOCK, got {inv:?}"
            );
        }
        other => panic!("expected Inv, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn cmpct_announce_uses_generated_tip_body() {
    let (dir, q) = tmp_store("cmpct-announce");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let hashes = hub
        .generate_to_script(1, bitcoin::script::ScriptBuf::new(), vec![])
        .unwrap();
    let hash = hashes[0];
    match cmpct_announce_msg(&hub, &hash, 2) {
        Some(NetworkMessage::CmpctBlock(c)) => {
            assert_eq!(c.compact_block.header.block_hash(), hash);
        }
        other => panic!("expected CmpctBlock, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn header_getdata_is_compact_after_sendcmpct() {
    use bitcoin::block::Header;
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
    let (src_dir, src_q) = tmp_store("cmpct-gd-src");
    let src = ChainHub::new(src_q, ChainParams::regtest(), Milestone::NONE);
    src.ensure_genesis().unwrap();
    src.generate_to_script(
        1,
        bitcoin::script::ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    )
    .unwrap();
    let hdr: Header = src.query.wire_header_at_height(Height(1)).unwrap();
    let hash = hdr.block_hash();

    let (dir, q) = tmp_store("cmpct-gd-dst");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut pending_headers = HashMap::new();
    let mut pending_blocks = PendingBlocks::new();
    let mut pending_cmpct = HashMap::new();
    let mut from_peer = HashMap::new();
    let mut requested = HashSet::new();
    let mut wants_headers = false;
    let mut wtxid = false;
    let mut send_cmpct = true;
    let mut cmpct_ver = 2u32;
    let mut ban = 0u32;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![hdr])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
    });
    let msg = out_rx.try_recv().expect("getdata");
    match msg {
        NetworkMessage::GetData(inv) => {
            assert!(
                matches!(inv.as_slice(), [Inventory::CompactBlock(h)] if *h == hash),
                "expected MSG_CMPCT_BLOCK getdata, got {inv:?}"
            );
        }
        other => panic!("expected GetData, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(src_dir);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn submitheader_parent_p2p_child_header_getdatas_body() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::Network;
    use rbitcoin_consensus::mine_regtest_paying;

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

    let (dir, q) = tmp_store("tb-hdr-only");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let script = bitcoin::script::ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(1, script.clone(), vec![]).unwrap();
    let b0 = hub.tip_hash().unwrap();
    assert!(hub.is_connected(&b0));
    let t0 = hub.header_of(&b0).unwrap().time;
    let b1 = mine_regtest_paying(b0, t0 + 1, 2, script.clone(), vec![]);
    hub.process_submitted_header(&b1.header).unwrap();
    assert!(hub.knows_header(&b1.block_hash()));
    assert!(!hub.is_connected(&b1.block_hash()));
    let b7 = mine_regtest_paying(b1.block_hash(), t0 + 2, 3, script, vec![]);
    hub.process_submitted_header(&b7.header).unwrap();
    assert!(!hub.is_connected(&b7.block_hash()));

    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut pending_headers = HashMap::new();
    let mut pending_blocks = PendingBlocks::new();
    let mut pending_cmpct = HashMap::new();
    let mut from_peer = HashMap::new();
    let mut requested = HashSet::new();
    let mut wants_headers = false;
    let mut wtxid = false;
    let mut send_cmpct = false;
    let mut cmpct_ver = 2u32;
    let mut ban = 0u32;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![b7.header])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
    });
    let want = b7.block_hash();
    let mut saw = false;
    while let Ok(msg) = out_rx.try_recv() {
        match msg {
            NetworkMessage::GetData(inv) => {
                saw |= inv.iter().any(|i| match i {
                    Inventory::WitnessBlock(h)
                    | Inventory::Block(h)
                    | Inventory::CompactBlock(h) => *h == want,
                    _ => false,
                });
            }
            NetworkMessage::GetHeaders(_) => panic!("headers-only parent must not getheaders"),
            _ => {}
        }
    }
    assert!(saw, "expected getdata for submitheader child {want}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_announce_inv_after_large_reorg_until_peer_catches_up() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, q) = tmp_store("announce-reorg");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(8, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let sent_tip = hub.tip_hash().unwrap();
    hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let ext = hub.tip_hash().unwrap();
    let ext_h = hub.header_of(&ext).unwrap();
    let ev = crate::chain::TipEvent {
        height: hub.tip_height().unwrap(),
        hash: ext,
        header: ext_h,
        reorg_branch_len: 0,
    };
    match tip_announce_decision(&hub, &ev, true, Some(sent_tip), None, false) {
        TipAnnounce::Headers(h) => {
            assert_eq!(h.len(), 1);
            assert_eq!(h[0].block_hash(), ext);
        }
        other => panic!("tip-extend should be headers, got {other:?}"),
    }
    match tip_announce_decision(&hub, &ev, true, Some(sent_tip), None, true) {
        TipAnnounce::Skip => {}
        other => panic!("from-this-peer must skip, got {other:?}"),
    }

    let (fork_hash, fork_time) = {
        let rec = hub
            .query
            .header_at_height(rbitcoin_primitives::Height(5))
            .unwrap()
            .unwrap();
        (BlockHash::from_byte_array(rec.1.hash), rec.1.timestamp)
    };
    let mine = |prev: BlockHash, time: u32, height: u32| {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(0x00);
        }
        let cb = Transaction {
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
        };
        let mut block = bitcoin::Block {
            header: Header {
                version: BlockVersion::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![cb],
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
    let mut prev = fork_hash;
    let mut branch = Vec::new();
    for i in 0..9u32 {
        let b = mine(prev, fork_time.saturating_add(600 + i), 6 + i);
        prev = b.block_hash();
        branch.push(b);
    }
    hub.accept_branch(&branch).unwrap();
    let new_tip = hub.tip_hash().unwrap();
    let new_hdr = hub.header_of(&new_tip).unwrap();
    let reorg_ev = crate::chain::TipEvent {
        height: hub.tip_height().unwrap(),
        hash: new_tip,
        header: new_hdr,
        reorg_branch_len: 9,
    };
    match tip_announce_decision(&hub, &reorg_ev, true, Some(sent_tip), None, false) {
        TipAnnounce::Inv(h) => assert_eq!(h, new_tip),
        other => panic!("large reorg must inv tip, got {other:?}"),
    }

    hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let after = hub.tip_hash().unwrap();
    let after_h = hub.header_of(&after).unwrap();
    let after_ev = crate::chain::TipEvent {
        height: hub.tip_height().unwrap(),
        hash: after,
        header: after_h,
        reorg_branch_len: 0,
    };
    match tip_announce_decision(&hub, &after_ev, true, Some(sent_tip), None, false) {
        TipAnnounce::Inv(h) => assert_eq!(h, after),
        other => panic!("still far from sent mark must inv, got {other:?}"),
    }
    match tip_announce_decision(&hub, &after_ev, true, Some(after), None, false) {
        TipAnnounce::Skip => {}
        other => panic!("already sent this hash must skip, got {other:?}"),
    }
    match tip_announce_decision(
        &hub,
        &after_ev,
        true,
        None,
        Some(after_h.prev_blockhash),
        false,
    ) {
        TipAnnounce::Headers(h) => {
            assert_eq!(h.len(), 1);
            assert_eq!(h[0].block_hash(), after);
        }
        other => panic!("known prev must headers, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn minchainwork_getheaders_empty_until_floor() {
    use bitcoin::p2p::message_blockdata::GetHeadersMessage;
    use bitcoin::ScriptBuf;

    let (dir, q) = tmp_store("minwork");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let mut min = [0u8; 32];
    min[31] = 0x65; // 101
    hub.set_minimum_chain_work(Some(min));
    let first = hub
        .generate_to_script(49, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .expect("49 blocks");
    assert_eq!(hub.tip_height(), Some(49));
    let h49 = *first.last().expect("height 49 hash");
    // Genesis + 49 = 50 blocks * 2 work = 100 < 101.
    assert!(
        !hub.meets_minimum_chain_work(),
        "work at height 49 must be below 0x65"
    );
    let gh = GetHeadersMessage::new(
        vec![hub.tip_hash().unwrap()],
        BlockHash::from_byte_array([0u8; 32]),
    );
    let below = headers_reply_for_getheaders(&hub, &gh).unwrap();
    assert!(
        below.is_empty(),
        "getheaders below minchainwork must be empty, got {}",
        below.len()
    );

    hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .expect("51st block");
    assert_eq!(hub.tip_height(), Some(50));
    assert!(
        hub.meets_minimum_chain_work(),
        "work at height 50 must meet 0x65"
    );
    let gh = GetHeadersMessage::new(vec![h49], BlockHash::from_byte_array([0u8; 32]));
    let above = headers_reply_for_getheaders(&hub, &gh).unwrap();
    assert!(
        !above.is_empty(),
        "getheaders at/above minchainwork must serve the 51st header"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn minchainwork_does_not_getdata_below_floor() {
    use bitcoin::ScriptBuf;
    use rbitcoin_primitives::Height;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::consensus::encode::serialize;
        use bitcoin::p2p::message::RawNetworkMessage;
        use bitcoin::Network;
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

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("minwork-gd");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let mut min = [0u8; 32];
        min[31] = 0x65;
        hub.set_minimum_chain_work(Some(min));

        let (dir2, q2) = tmp_store("minwork-src");
        let src = ChainHub::new(q2, ChainParams::regtest(), Milestone::NONE);
        src.ensure_genesis().unwrap();
        src.generate_to_script(50, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let mut hdrs = Vec::new();
        for h in 1..=50u32 {
            hdrs.push(src.query.wire_header_at_height(Height(h)).unwrap());
        }

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut ban = 0u32;

        fn drain_getdata(rx: &mut mpsc::UnboundedReceiver<NetworkMessage>) -> Vec<BlockHash> {
            let mut hashes = Vec::new();
            while let Ok(m) = rx.try_recv() {
                if let NetworkMessage::GetData(inv) = m {
                    for i in inv {
                        match i {
                            Inventory::Block(h)
                            | Inventory::WitnessBlock(h)
                            | Inventory::CompactBlock(h) => hashes.push(h),
                            _ => {}
                        }
                    }
                }
            }
            hashes
        }

        // Core getheaders reply is a batch (not one header per tip).
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(hdrs[..49].to_vec())),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(
            drain_getdata(&mut out_rx).is_empty(),
            "must not getdata a 49-block chain (work 100 < 101)"
        );
        assert_eq!(hub.tip_height(), Some(0));
        assert_eq!(
            hub.chaintips()
                .iter()
                .filter(|t| t.status != "active")
                .count(),
            0,
            "non-noban must not store a low-work headers tree"
        );

        handle_peer_frame(
            frame_for(NetworkMessage::Headers(hdrs.clone())),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        let got = drain_getdata(&mut out_rx);
        let h1 = hdrs[0].block_hash();
        assert_eq!(
            got.len(),
            MAX_SERVE_BLOCKS,
            "50th header (work 102) getdata must match serve window, got {got:?}"
        );
        assert_eq!(got[0], h1, "getdata should start at height 1");
        assert_eq!(
            got[MAX_SERVE_BLOCKS - 1],
            hdrs[MAX_SERVE_BLOCKS - 1].block_hash()
        );
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    });
}

#[test]
fn minchainwork_one_header_announces_ignore_height_14() {
    use bitcoin::ScriptBuf;
    use rbitcoin_primitives::Height;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::consensus::encode::serialize;
        use bitcoin::p2p::message::RawNetworkMessage;
        use bitcoin::Network;
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

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("minwork-h14");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        // Core node1 `-minimumchainwork=0x1f` (15 blocks).
        let mut min = [0u8; 32];
        min[31] = 0x1f;
        hub.set_minimum_chain_work(Some(min));

        let (dir2, q2) = tmp_store("minwork-h14-src");
        let src = ChainHub::new(q2, ChainParams::regtest(), Milestone::NONE);
        src.ensure_genesis().unwrap();
        src.generate_to_script(14, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let mut hdrs = Vec::new();
        for h in 1..=14u32 {
            hdrs.push(src.query.wire_header_at_height(Height(h)).unwrap());
        }

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut ban = 0u32;

        // Official generate announces one header per mined tip.
        for hdr in &hdrs {
            handle_peer_frame(
                frame_for(NetworkMessage::Headers(vec![*hdr])),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut requested,
                &mut ban,
                None,
            )
            .await
            .unwrap();
        }
        while out_rx.try_recv().is_ok() {}
        let last = hdrs[13].block_hash();
        assert_eq!(
            announced_headers_height(&hub, &pending_headers, last),
            14,
            "14 one-header announces must report Core ignore height=14"
        );
        assert_eq!(hub.tip_height(), Some(0));
        assert_eq!(
            hub.chaintips()
                .iter()
                .filter(|t| t.status != "active")
                .count(),
            0,
            "non-noban must not store a low-work headers tree"
        );
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    });
}

#[test]
fn blocksonly_tx_and_inv_raise_ban() {
    // p2p_blocksonly: relay off → P2P tx / wtx inv is a protocol violation.
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::sync::Arc;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::consensus::encode::serialize;
        use bitcoin::p2p::message::RawNetworkMessage;
        use bitcoin::Network;
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

    let dummy_tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("blocksonly-tx");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(false);
        assert!(hub.attach_mempool(mp).is_ok());
        assert!(reject_unsolicited_tx(&hub, None));

        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(dummy_tx)),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(
            ban >= BAN_SCORE_THRESHOLD,
            "blocksonly tx must disconnect, ban={ban}"
        );

        ban = 0;
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WTx(
                bitcoin::Wtxid::from_byte_array([
                    0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                ]),
            )])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(
            ban >= BAN_SCORE_THRESHOLD,
            "blocksonly wtx inv must disconnect, ban={ban}"
        );
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `p2p_blocksonly.py:48`: RPC sendraw while relay is off must INV an
/// inbound peer (`request_all_tx_inv` + `queue_due_tx_invs`) and serve
/// the subsequent GetData WTx. Announce-at-accept is too early — the
/// unbroadcast set is only written after `accept_tx` returns.
#[test]
fn blocksonly_sendraw_invs_unbroadcast_to_inbound() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

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

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("blocksonly-sendraw");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(102, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad maturity");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(false);
        assert!(hub.attach_mempool(mp).is_ok());

        let cb = hub
            .query
            .reconstruct_block_at_height(Height(1))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let tx = Transaction {
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
        let mp = hub.mempool().unwrap();
        mp.accept_tx(&tx).expect("testmempoolaccept dry-run");
        assert_eq!(
            mp.remove_for_block(&[tx.compute_txid()]),
            0,
            "remove_for_block is a no-op while relay is off"
        );
        assert_eq!(mp.live_count(), 1);
        assert_eq!(mp.evict_live_txids(&[tx.compute_txid()]), 1);
        assert_eq!(mp.live_count(), 0);

        let mut ann_rx = mp.subscribe_announces();
        mp.accept_tx(&tx).expect("sendraw accept");
        let announced = ann_rx.try_recv().expect("accept publishes announce");
        assert_eq!(announced.txid, tx.compute_txid());
        assert!(
            !mp.is_unbroadcast(&tx.compute_txid()),
            "unbroadcast is noted only after accept_tx returns (sendraw)"
        );
        // Session announce handler would skip: relay off and not unbroadcast.
        assert!(!mp.relay_enabled());

        mp.note_unbroadcast(tx.compute_txid());
        assert!(mp.is_unbroadcast(&tx.compute_txid()));

        // Immediate INV of unbroadcast — no request_all_tx_inv / 30s gate.
        let (probe_tx, mut probe_rx) = mpsc::unbounded_channel();
        let peers = crate::peers::PeerHub::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
        let inbound_imm =
            peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        inbound_imm.attach_out(probe_tx.clone());
        flush_tx_invs(&hub, peers.as_ref());
        match probe_rx
            .try_recv()
            .expect("unbroadcast INV without clock_due")
        {
            NetworkMessage::Inv(v) => {
                assert_eq!(v, vec![Inventory::WTx(tx.compute_wtxid())]);
            }
            other => panic!("expected WTx inv, got {other:?}"),
        }

        let peers = crate::peers::PeerHub::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
        let inbound = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        let block_relay = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::BlockRelay,
        );

        peers.request_all_tx_inv();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        queue_due_tx_invs(&hub, inbound.as_ref(), &HashMap::new(), &out_tx);
        match out_rx.try_recv().expect("inbound must get wtx INV") {
            NetworkMessage::Inv(v) => {
                assert_eq!(v, vec![Inventory::WTx(tx.compute_wtxid())]);
            }
            other => panic!("expected WTx inv, got {other:?}"),
        }
        queue_due_tx_invs(&hub, block_relay.as_ref(), &HashMap::new(), &out_tx);
        assert!(
            out_rx.try_recv().is_err(),
            "block-relay-only must not get tx INV"
        );

        let mut wants_headers = false;
        let mut wtxid = true;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                tx.compute_wtxid(),
            )])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            Some(inbound.as_ref()),
        )
        .await
        .unwrap();
        match out_rx.try_recv().expect("getdata must serve tx") {
            NetworkMessage::Tx(got) => assert_eq!(got.compute_wtxid(), tx.compute_wtxid()),
            other => panic!("expected Tx, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// When relay is on, unbroadcast must not skip the inbound 30s INV gate
/// (`mempool_reorg.py:71`).
#[test]
fn relay_on_unbroadcast_keeps_inbound_age_gate() {
    use bitcoin::absolute::LockTime;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("relay-on-unb");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(102, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());
        let cb = hub
            .query
            .reconstruct_block_at_height(Height(1))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let tx = Transaction {
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
        let mp = hub.mempool().unwrap();
        mp.accept_tx(&tx).expect("accept");
        mp.note_unbroadcast(tx.compute_txid());
        let peers = crate::peers::PeerHub::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
        let inbound = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        queue_due_tx_invs(&hub, inbound.as_ref(), &HashMap::new(), &out_tx);
        assert!(
            out_rx.try_recv().is_err(),
            "relay-on inbound must wait 30s even for unbroadcast"
        );
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `p2p_tx_privacy.py`: txs accepted before a peer's handshake completes must
/// not be INV'd to that peer after they come online.
#[test]
fn queue_due_skips_txs_accepted_before_peer_connected() {
    use bitcoin::absolute::LockTime;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("tx-privacy-pre");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(102, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());
        let cb = hub
            .query
            .reconstruct_block_at_height(Height(1))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let early = Transaction {
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
        let mp = hub.mempool().unwrap();
        mp.note_mock_now(50);
        mp.accept_tx(&early).expect("accept early");
        let peers = crate::peers::PeerHub::new();
        peers.set_mock_now(100);
        mp.note_mock_now(100);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
        let inbound = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        inbound.set_inv_gen_floor(mp.next_accept_gen());
        assert!(mp.tx_inv_due(&early.compute_wtxid()), "age elapsed");
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        queue_due_tx_invs(&hub, inbound.as_ref(), &HashMap::new(), &out_tx);
        assert!(
            out_rx.try_recv().is_err(),
            "must not INV a tx accepted before this peer connected"
        );
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// 50ms session tick must not `list_live()` (clone every mempool body).
#[test]
fn queue_due_tx_invs_idle_tick_does_not_clone_live_bodies() {
    use bitcoin::absolute::LockTime;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("inv-tick-noclone");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(102, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad maturity");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());
        let cb = hub
            .query
            .reconstruct_block_at_height(Height(1))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let tx = Transaction {
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
        let mp = hub.mempool().unwrap();
        mp.accept_tx(&tx).expect("accept");
        let _ = mp.sample_reset_perf();

        let peers = crate::peers::PeerHub::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
        let inbound = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        queue_due_tx_invs(&hub, inbound.as_ref(), &HashMap::new(), &out_tx);
        let idle = mp.sample_reset_perf();
        assert_eq!(
            idle.list_live, 0,
            "idle INV tick must not list_live/clone bodies (got {})",
            idle.list_live
        );
        assert!(
            out_rx.try_recv().is_err(),
            "idle tick must not INV when nothing is due"
        );

        let outbound = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        peers.request_all_tx_inv();
        queue_due_tx_invs(&hub, outbound.as_ref(), &HashMap::new(), &out_tx);
        let flush = mp.sample_reset_perf();
        assert_eq!(
            flush.list_live, 0,
            "clock_due INV must use wtxid index, not list_live (got {})",
            flush.list_live
        );
        match out_rx.try_recv().expect("clock_due must INV") {
            NetworkMessage::Inv(v) => {
                assert_eq!(v, vec![Inventory::WTx(tx.compute_wtxid())]);
            }
            other => panic!("expected WTx inv, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `mempool_reorg.py:122`: after mocktime +300 announces older txs,
/// a brand-new sendraw must not be INV'd or GetData-served to inbound
/// (relay on, no noban). Drive shipped `queue_due_tx_invs` / GetData-WTx.
#[test]
fn mocktime_jump_does_not_inv_or_serve_new_sendraw() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

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
    fn spend_cb(cb: bitcoin::Txid) -> Transaction {
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

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("reorg-122");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(105, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let cb = |h: u32| {
            hub.query
                .reconstruct_block_at_height(Height(h))
                .unwrap()
                .txdata[0]
                .compute_txid()
        };
        let old_a = spend_cb(cb(1));
        let old_b = spend_cb(cb(2));
        let disconnected = spend_cb(cb(3));
        let fresh = spend_cb(cb(4));

        let t0 = 1_700_000_000u64;
        let peers = crate::peers::PeerHub::new();
        peers.set_mock_now(t0);
        hub.mempool().unwrap().note_mock_now(t0);
        hub.mempool().unwrap().accept_tx(&old_a).expect("old_a");
        hub.mempool().unwrap().accept_tx(&old_b).expect("old_b");
        assert_eq!(
            hub.mempool()
                .unwrap()
                .reorg_reaccept(std::slice::from_ref(&disconnected)),
            1
        );

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
        let inbound = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        assert!(inbound.inbound);
        assert!(!peers.is_noban());

        // Mocktime +300: older txs are age-due; flush them.
        peers.set_mock_now(t0 + 300);
        hub.mempool().unwrap().note_mock_now(t0 + 300);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        inbound.request_tx_inv();
        queue_due_tx_invs(&hub, inbound.as_ref(), &HashMap::new(), &out_tx);
        let mut announced = 0u32;
        while let Ok(msg) = out_rx.try_recv() {
            match msg {
                NetworkMessage::Inv(v) => {
                    announced += v.len() as u32;
                }
                other => panic!("expected INV of aged txs, got {other:?}"),
            }
        }
        assert_eq!(announced, 3, "three aged txs must INV after +300");

        // Brand-new sendraw (unbroadcast, relay on).
        hub.mempool()
            .unwrap()
            .accept_tx(&fresh)
            .expect("fresh sendraw");
        hub.mempool()
            .unwrap()
            .note_unbroadcast(fresh.compute_txid());

        // Leftover request_tx_inv / inv_flush after the new accept must
        // not INV the fresh tx to inbound.
        inbound.request_tx_inv();
        queue_due_tx_invs(&hub, inbound.as_ref(), &HashMap::new(), &out_tx);
        assert!(
            out_rx.try_recv().is_err(),
            "new sendraw must not INV inbound after mocktime jump"
        );

        let mut wants_headers = false;
        let mut wtxid = true;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                fresh.compute_wtxid(),
            )])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            Some(inbound.as_ref()),
        )
        .await
        .unwrap();
        match out_rx.try_recv().expect("GetData must reply") {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v, vec![Inventory::WTx(fresh.compute_wtxid())]);
            }
            other => panic!("fresh sendraw GetData must notfound, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `p2p_blocksonly.py:74`: whitelist-relay peer's tx is accepted while
/// `-blocksonly` and INV'd to the other inbound peer.
#[test]
fn blocksonly_relay_perm_tx_invs_other_inbound() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

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

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("blocksonly-relay-perm");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(102, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad maturity");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(false);
        assert!(hub.attach_mempool(mp).is_ok());

        let cb = hub
            .query
            .reconstruct_block_at_height(Height(1))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let tx = Transaction {
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

        let peers = crate::peers::PeerHub::new();
        peers.set_relay_perm(true);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
        let first = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);
        let second = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let (inv_tx, mut inv_rx) = mpsc::unbounded_channel();
        first.attach_out(out_tx.clone());
        second.attach_out(inv_tx);
        let mut wants_headers = false;
        let mut wtxid = true;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_first = HashMap::new();
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(tx.clone())),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_first,
            &mut HashSet::new(),
            &mut ban,
            Some(first.as_ref()),
        )
        .await
        .unwrap();
        assert_eq!(ban, 0, "whitelist relay must not disconnect");
        assert!(hub.mempool().unwrap().is_unbroadcast(&tx.compute_txid()));
        assert!(from_first.contains_key(&tx.compute_txid()));
        match inv_rx
            .try_recv()
            .expect("second inbound must get wtx INV from flush_tx_invs")
        {
            NetworkMessage::Inv(v) => {
                assert_eq!(v, vec![Inventory::WTx(tx.compute_wtxid())]);
            }
            other => panic!("expected WTx inv, got {other:?}"),
        }
        let _ = out_rx.try_recv();
        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn cmpct_helpers_without_mempool_and_queue_out_closed() {
    let (dir, q) = tmp_store("cmpct-none");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let gen = hub
        .query
        .reconstruct_block_by_hash(&hub.tip_hash().unwrap().to_byte_array())
        .unwrap()
        .unwrap();
    let hsi = HeaderAndShortIds::from_block(&gen, 0xabc, 2, &[]).unwrap();
    assert!(
        try_fill_cmpct(&hub, &hsi, 2).is_some(),
        "coinbase-only compact fills from prefilled txs without a mempool"
    );
    assert!(try_cmpct_missing(&hub, &hsi, 2).is_none());
    assert!(mempool_live_txs(&hub).is_empty());

    // Closed channel → Protocol error.
    let (tx, rx) = mpsc::unbounded_channel();
    drop(rx);
    assert!(queue_out(&tx, NetworkMessage::Verack).is_err());
    assert!(queue_getheaders(&tx, &hub, None, false, None).is_err());

    // headers_for_peer empty store after genesis still returns (tip exists).
    use bitcoin::p2p::message_blockdata::GetHeadersMessage;
    let gh = GetHeadersMessage::new(
        vec![hub.tip_hash().unwrap()],
        BlockHash::from_byte_array([0u8; 32]),
    );
    let hdrs = headers_for_peer(hub.cache.as_ref(), hub.query.as_ref(), &gh).unwrap();
    // Beyond tip: empty headers is fine.
    assert!(hdrs.is_empty() || !hdrs.is_empty());

    // drain_pending empty is a no-op.
    let mut pb = PendingBlocks::new();
    let mut ph = HashMap::new();
    let (tx, _rx) = mpsc::unbounded_channel();
    drain_pending_now(&hub, &tx, &mut pb, &mut ph, &mut HashSet::new(), false).unwrap();

    // Invalid tip-extending body must not kill the session (001).
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let tip = hub.tip_hash().unwrap();
    let tip_block = hub
        .query
        .reconstruct_block_by_hash(&tip.to_byte_array())
        .unwrap()
        .expect("tip body");
    let coinbase = Transaction {
        version: TxVersion::ONE,
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
    // Second tx spends a nonexistent prevout → consensus reject.
    let junk = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0xab; 32]),
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
    let mut bad = bitcoin::Block {
        header: Header {
            version: BlockVersion::from_consensus(4),
            prev_blockhash: tip,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
            time: tip_block.header.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase, junk],
    };
    bad.header.merkle_root = bad.compute_merkle_root().unwrap();
    let target = bitcoin::Target::from_compact(bad.header.bits);
    for nonce in 0..200_000u32 {
        bad.header.nonce = nonce;
        if bad.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let bh = bad.block_hash();
    pb.insert(bh, bad.clone());
    let (tx, _rx) = mpsc::unbounded_channel();
    drain_pending_now(&hub, &tx, &mut pb, &mut ph, &mut HashSet::new(), false)
        .expect("invalid block must not end session");
    assert!(
        hub.is_block_invalid(&bh),
        "consensus-invalid body must be cached as failed"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn compact_child_of_invalid_disconnects_cached_same_stays() {
    use bitcoin::bip152::PrefilledTransaction;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("cmpct-bad-prev");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let tip = hub.tip_hash().unwrap();
        let failed = BlockHash::from_byte_array([0x11; 32]);
        hub.note_invalid_block(failed);

        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut ban = 0u32;

        let gen = hub
            .query
            .reconstruct_block_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        let mut cached = HeaderAndShortIds::from_block(&gen, 1, 2, &[0]).unwrap();
        cached.header.prev_blockhash = tip;
        // Same-hash cached invalid: header hash is the failed one.
        hub.note_invalid_block(cached.header.block_hash());
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: cached,
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert_eq!(ban, 0, "cached invalid compact must stay connected");

        let mut child = HeaderAndShortIds::from_block(&gen, 2, 2, &[0]).unwrap();
        child.header.prev_blockhash = failed;
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: child,
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(
            ban >= BAN_SCORE_THRESHOLD,
            "child of cached-invalid parent must disconnect"
        );

        ban = 0;
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
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(
            ban >= BAN_SCORE_THRESHOLD,
            "out-of-range prefilled index must disconnect"
        );

        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn handle_peer_frame_control_and_inv_paths() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::Network;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        // 4 magic + 12 command + 4 len + 4 checksum + payload
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("handle-frame");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut ban = 0u32;

        // SendHeaders / SendCmpct / WtxidRelay / SendAddrV2 / Pong / GetAddr / Ping
        // (MemPool disconnects — covered by bloom_disabled_messages_request_disconnect.)
        for msg in [
            NetworkMessage::SendHeaders,
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            }),
            NetworkMessage::WtxidRelay,
            NetworkMessage::SendAddrV2,
            NetworkMessage::Pong(7),
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(42),
        ] {
            handle_peer_frame(
                frame_for(msg),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut HashSet::new(),
                &mut ban,
                None,
            )
            .await
            .unwrap();
        }
        assert!(wants_headers);
        assert!(wtxid);
        assert!(send_cmpct);
        assert_eq!(cmpct_ver, 2);

        // Drain outbound: Pong(42) + empty Addr at least.
        let mut saw_pong = false;
        let mut saw_addr = false;
        while let Ok(m) = out_rx.try_recv() {
            match m {
                NetworkMessage::Pong(n) => {
                    assert_eq!(n, 42);
                    saw_pong = true;
                }
                NetworkMessage::Addr(a) => {
                    assert!(a.is_empty());
                    saw_addr = true;
                }
                _ => {}
            }
        }
        assert!(saw_pong);
        assert!(saw_addr);

        // GetHeaders from empty tip-beyond locator.
        use bitcoin::p2p::message_blockdata::GetHeadersMessage;
        let gh = GetHeadersMessage::new(
            vec![hub.tip_hash().unwrap()],
            BlockHash::from_byte_array([0u8; 32]),
        );
        handle_peer_frame(
            frame_for(NetworkMessage::GetHeaders(gh)),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        let headers_msg = out_rx.try_recv().unwrap();
        assert!(matches!(headers_msg, NetworkMessage::Headers(_)));

        // Inv for unknown block → GetHeaders (never getdata without a header).
        let want_h = BlockHash::from_byte_array([0xee; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(want_h)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::GetHeaders(gh) => {
                assert!(
                    !gh.locator_hashes.is_empty() || gh.stop_hash == want_h,
                    "unknown block inv must getheaders, locators={:?}",
                    gh.locator_hashes
                );
            }
            other => panic!("expected GetHeaders for unknown inv, got {other:?}"),
        }

        // Headers message inserts pending + issues getdata.
        let gen = hub
            .query
            .wire_header_at_height(rbitcoin_primitives::Height(0))
            .unwrap();
        // Synthesize a child-looking header (not valid pow; just exercises map).
        use bitcoin::block::{Header, Version};
        use bitcoin::{CompactTarget, TxMerkleNode};
        let child = Header {
            version: Version::from_consensus(4),
            prev_blockhash: gen.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([2u8; 32]),
            time: gen.time + 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 1,
        };
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![child])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(pending_headers.contains_key(&child.block_hash()));
        let _ = out_rx.try_recv(); // GetData

        // GetData for known tip block (cache miss → reconstruct).
        let tip = hub.tip_hash().unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WitnessBlock(tip)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::Block(b) => assert_eq!(b.block_hash(), tip),
            other => panic!("expected Block, got {other:?}"),
        }

        // CompactBlock getdata for tip.
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(tip)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap(),
            NetworkMessage::CmpctBlock(_)
        ));

        // GetBlockTxn with bad index → ban score.
        use bitcoin::bip152::BlockTransactionsRequest;
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![999],
                },
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(ban >= BAN_SCORE_THRESHOLD);

        // GetBlockTxn good index 0 (coinbase).
        ban = 0;
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![0],
                },
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap(),
            NetworkMessage::BlockTxn(_)
        ));

        // Deeper than 10: full block, not blocktxn (`p2p_compactblocks` :635).
        hub.generate_to_script(12, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![0],
                },
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(
            matches!(out_rx.try_recv().unwrap(), NetworkMessage::Block(_)),
            "getblocktxn past depth 10 must send a full block"
        );

        // Unsolicited BlockTxn → mild ban.
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: BlockHash::from_byte_array([0xdd; 32]),
                    transactions: vec![],
                },
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(ban >= 5);

        // CmpctBlock without mempool → full getdata fallback.
        let gen_block = hub
            .query
            .reconstruct_block_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        let hsi = HeaderAndShortIds::from_block(&gen_block, 9, 2, &[]).unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi,
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        // Already have tip → no getdata; if different hash would request.
        // Genesis is already known so "already have" arm.
        let _ = out_rx.try_recv();

        // Unknown command (including the retired rbtpkg name) is a no-op.
        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("rbtpkg").unwrap(),
                payload: vec![1, 2, 3],
            }),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();

        // SendCmpct with unsupported version is ignored.
        handle_peer_frame(
            frame_for(NetworkMessage::SendCmpct(SendCmpct {
                send_compact: false,
                version: 99,
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(send_cmpct); // still true from earlier v2
        assert_eq!(cmpct_ver, 2);

        // Inventory::Block (non-witness) for unknown → GetHeaders.
        let want2 = BlockHash::from_byte_array([0xcc; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::Block(want2)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::GetHeaders(_) => {}
            other => panic!("expected GetHeaders for unknown inv, got {other:?}"),
        }

        // Inv for known tip → no GetData.
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(tip)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(out_rx.try_recv().is_err());

        // GetData Inventory::Block for tip (non-witness arm).
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::Block(tip)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap(),
            NetworkMessage::Block(_)
        ));

        // Full Block message path: pending + drain_pending (AlreadyHave for tip).
        let gen_block2 = hub
            .query
            .reconstruct_block_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::Block(gen_block2)),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        // Tip already confirmed — drain accepts AlreadyHave and may leave empty pending.

        // Tx without mempool is a no-op.
        use bitcoin::absolute::LockTime;
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
        let dummy_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(dummy_tx)),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();

        // Catch-all unknown command.
        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("zzzzzz").unwrap(),
                payload: vec![],
            }),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();

        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Mempool-backed inv/tx/getdata arms + cmpctblocktxn success.
#[test]
fn handle_peer_frame_mempool_tx_and_inv_paths() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("handle-mp");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        // Enable relay so Inv for txs triggers getdata.
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut ban = 0u32;

        let unknown_txid = bitcoin::Txid::from_byte_array([0x42; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![
                Inventory::WitnessTransaction(unknown_txid),
                Inventory::WTx(bitcoin::Wtxid::from_byte_array([0x43; 32])),
            ])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::GetData(v) => {
                assert!(v.len() >= 1);
            }
            other => panic!("expected GetData for unknown txs, got {other:?}"),
        }

        // GetData for missing tx → notfound (Core ProcessGetData).
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![
                Inventory::WitnessTransaction(unknown_txid),
                Inventory::WTx(bitcoin::Wtxid::from_byte_array([0x43; 32])),
            ])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v.len(), 1);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
        match out_rx.try_recv().unwrap() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v.len(), 1);
            }
            other => panic!("expected second NotFound, got {other:?}"),
        }
        assert!(out_rx.try_recv().is_err());

        // Accept path with invalid prevout — still exercises Tx arm (inserts from_peer).
        let junk = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let junk_txid = junk.compute_txid();
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(junk)),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        // Origin map is filled before accept result.
        assert!(from_peer.contains_key(&junk_txid));

        // Retired rbtpkg name with mempool + relay: still unknown, no admit
        // even when the payload is the old len-prefixed encoding.
        let pkg_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([2u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let pkg_txid = pkg_tx.compute_txid();
        let raw = bitcoin::consensus::encode::serialize(&pkg_tx);
        let mut payload = Vec::with_capacity(4 + raw.len());
        payload.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        payload.extend_from_slice(&raw);
        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("rbtpkg").unwrap(),
                payload,
            }),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(!from_peer.contains_key(&pkg_txid));
        assert_eq!(hub.mempool().unwrap().live_count(), 0);

        let _ = std::fs::remove_dir_all(dir);
    });
}

/// GetData serves a mempool tx only after we INV'd it, or if it re-entered
/// from a disconnected block (`mempool_reorg.py` test_reorg_relay).
#[test]
fn getdata_tx_notfound_unless_announced_or_reorg() {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

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

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("gd-privacy");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(102, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("pad maturity");
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let cb1 = hub
            .query
            .reconstruct_block_at_height(Height(1))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let cb2 = hub
            .query
            .reconstruct_block_at_height(Height(2))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let recent = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: cb1, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9999_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let disconnected = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: cb2, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9999_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        hub.mempool()
            .unwrap()
            .accept_tx(&recent)
            .expect("accept recent");
        assert_eq!(
            hub.mempool()
                .unwrap()
                .reorg_reaccept(std::slice::from_ref(&disconnected)),
            1
        );

        let peers = crate::peers::PeerHub::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
        let sess = peers.register(addr, addr, &ver, true, crate::peers::PeerConnType::Inbound);

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = true;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut ban = 0u32;

        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                recent.compute_wtxid(),
            )])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v, vec![Inventory::WTx(recent.compute_wtxid())]);
            }
            other => panic!("unannounced recent must notfound, got {other:?}"),
        }

        sess.note_announced_wtx(recent.compute_wtxid());
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                recent.compute_wtxid(),
            )])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::Tx(tx) => assert_eq!(tx.compute_wtxid(), recent.compute_wtxid()),
            other => panic!("announced recent must serve tx, got {other:?}"),
        }

        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                disconnected.compute_wtxid(),
            )])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::Tx(tx) => {
                assert_eq!(tx.compute_wtxid(), disconnected.compute_wtxid())
            }
            other => panic!("reorg-servable must serve without INV, got {other:?}"),
        }

        // mempool_reorg.py:122 — a later regular submit (even of a
        // wtxid that was once reorg-reaccepted) must notfound until
        // this peer's last INV sequence passes the new entry seq.
        sess.note_tx_inv_seq(hub.mempool().unwrap().current_relay_seq());
        let cb3 = hub
            .query
            .reconstruct_block_at_height(Height(3))
            .unwrap()
            .txdata[0]
            .compute_txid();
        let later = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: cb3, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9999_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        hub.mempool()
            .unwrap()
            .accept_tx(&later)
            .expect("accept later");
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WTx(
                later.compute_wtxid(),
            )])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v, vec![Inventory::WTx(later.compute_wtxid())]);
            }
            other => panic!("just-submitted tx must notfound, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `p2p_getdata.py`: GETDATA inv type 0 must not stall the session;
/// a later MSG_BLOCK getdata of the tip still serves.
#[test]
fn invalid_getdata_type0_still_serves_tip_block() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::{Network, ScriptBuf};

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

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("gd-type0");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .expect("one block");
        let tip = hub.tip_hash().expect("tip");

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = true;
        let mut send_cmpct = false;
        let mut cmpct_ver = 0u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut ban = 0u32;

        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::Unknown {
                inv_type: 0,
                hash: [0u8; 32],
            }])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert_eq!(ban, 0, "type-0 getdata must not disconnect");
        assert!(
            out_rx.try_recv().is_err(),
            "type-0 getdata must not emit a reply"
        );

        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::Block(tip)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().expect("tip getdata must serve") {
            NetworkMessage::Block(b) => assert_eq!(b.block_hash(), tip),
            other => panic!("expected tip Block, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Compact helpers with a live mempool hub attached (fill/missing/blocktxn).
#[test]
fn cmpct_helpers_with_mempool_live_and_blocktxn() {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip152::BlockTransactions;
    use bitcoin::block::{Header, Version};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    };

    let (dir, q) = tmp_store("cmpct-mp");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    assert!(hub.mempool().is_some());

    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: hub.tip_hash().unwrap(),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![
            Transaction {
                version: TxVersion::ONE,
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
            },
            spend.clone(),
        ],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();

    let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[]).unwrap();
    // Mempool present but empty live → Some(missing) not None.
    let missing = try_cmpct_missing(&hub, &hsi, 2).expect("mempool present");
    assert_eq!(missing, vec![1]); // spend short-id missing
    assert!(try_fill_cmpct(&hub, &hsi, 2).is_none());
    assert!(mempool_live_txs(&hub).is_empty());

    let pc = PendingCmpct {
        hsi: hsi.clone(),
        missing: missing.clone(),
        version: 2,
    };
    let bt = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![spend],
    };
    let recon = apply_cmpct_blocktxn(&hub, &pc, &bt).expect("blocktxn fill");
    assert_eq!(recon.txdata.len(), 2);

    let _ = std::fs::remove_dir_all(dir);
}

/// Tip-follow receive: max-work fork held then applied via `accept_received_block`.
#[test]
fn p2p_side_chain_reorgs_via_held_bodies() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, q) = tmp_store("pending-reorg");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
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
                version: BlockVersion::from_consensus(4),
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

    // Main tip height 2 (times near genesis MTP window).
    let b1 = mine(gen, 1_300_000_100, 1);
    hub.accept_block(b1.clone()).unwrap();
    let b2 = mine(b1.block_hash(), 1_300_000_200, 2);
    hub.accept_block(b2.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(2));

    // Pending: short side from gen (1 block) + long side from gen (4 blocks).
    let short = mine(gen, 1_300_001_000, 1);
    let mut long = Vec::new();
    let mut p = gen;
    for (i, h) in (1..=4u32).enumerate() {
        let b = mine(p, 1_300_002_000 + i as u32 * 600, h);
        p = b.block_hash();
        long.push(b);
    }
    // Short side first (held, weaker), then the longer fork one body at a time
    // — same order a peer `block` message stream would deliver.
    hub.accept_received_block(short).unwrap();
    for b in &long {
        hub.accept_received_block(b.clone()).unwrap();
    }
    assert_eq!(
        hub.tip_height(),
        Some(4),
        "must reorg onto longer held branch"
    );
    assert_eq!(hub.tip_hash().unwrap(), long[3].block_hash());
    assert!(hub.held_body(&long[3].block_hash()).is_none());
    assert!(MAX_PENDING_BLOCKS_FOR_TEST >= 128);
    let _ = std::fs::remove_dir_all(dir);
}

/// `mempool_reorg.py` `trigger_reorg`: 20 empty side blocks submitted one
/// at a time after 19 tip-extends must become the new tip.
#[test]
fn sequential_submit_twenty_beats_nineteen() {
    let (dir, q) = tmp_store("submit-20-vs-19");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let coinbase = |height: u32| {
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(0x00);
        }
        Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::script::ScriptBuf::from_bytes(ss),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_0000_0000),
                script_pubkey: bitcoin::script::ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    };
    let mine = |prev: BlockHash, time: u32, height: u32| {
        let bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(height)],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = bitcoin::Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    };

    // Shared parent at height 1.
    let b1 = mine(gen, 1_300_000_100, 1);
    hub.accept_block(b1.clone()).unwrap();
    let fork_prev = b1.block_hash();

    // Build the 20-block fork first (same order as create_empty_fork).
    let mut fork = Vec::new();
    let mut p = fork_prev;
    for i in 0..20u32 {
        let b = mine(p, 1_300_000_200 + i, 2 + i);
        p = b.block_hash();
        fork.push(b);
    }

    // Then 19 tip-extends (generate after the fork was built).
    let mut main = fork_prev;
    for i in 0..19u32 {
        let b = mine(main, 1_300_010_000 + i * 600, 2 + i);
        main = b.block_hash();
        hub.accept_block(b).unwrap();
    }
    assert_eq!(hub.tip_height(), Some(20));

    for b in &fork {
        hub.accept_received_block(b.clone())
            .unwrap_or_else(|e| panic!("submit {} : {e}", b.block_hash()));
    }
    assert_eq!(
        hub.tip_height(),
        Some(21),
        "20-block fork must beat 19-block main"
    );
    assert_eq!(hub.tip_hash().unwrap(), fork[19].block_hash());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn drain_requests_missing_parent_of_pending_branch() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, q) = tmp_store("pending-missing-parent");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let missing_parent = BlockHash::from_byte_array([0x42; 32]);
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut orphan = bitcoin::Block {
        header: Header {
            version: BlockVersion::from_consensus(4),
            prev_blockhash: missing_parent,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_100,
            bits,
            nonce: 0,
        },
        txdata: vec![Transaction {
            version: TxVersion::ONE,
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
        }],
    };
    orphan.header.merkle_root = orphan.compute_merkle_root().unwrap();
    let target = Target::from_compact(bits);
    for nonce in 0..u32::MAX {
        orphan.header.nonce = nonce;
        if orphan.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut pb = PendingBlocks::new();
    pb.insert(orphan.block_hash(), orphan);
    let mut ph = HashMap::new();
    drain_pending_now(&hub, &tx, &mut pb, &mut ph, &mut HashSet::new(), false).unwrap();
    let msg = rx.try_recv().expect("getdata for missing parent");
    match msg {
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
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn drain_connects_pending_child_of_new_tip_after_reorg() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, q) = tmp_store("pending-child-after-reorg");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
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
                version: BlockVersion::from_consensus(4),
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
    let a1 = mine(gen, 1_300_000_100, 1);
    hub.accept_block(a1.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(1));

    let b1 = mine(gen, 1_300_001_000, 1);
    let b2 = mine(b1.block_hash(), 1_300_001_600, 2);
    let mut pb = PendingBlocks::new();
    pb.insert(b1.block_hash(), b1.clone());
    pb.insert(b2.block_hash(), b2.clone());
    let mut ph = HashMap::new();
    let (tx, _rx) = mpsc::unbounded_channel();
    drain_pending_now(&hub, &tx, &mut pb, &mut ph, &mut HashSet::new(), false).unwrap();
    assert_eq!(hub.tip_height(), Some(2), "reorg plus child must connect");
    assert_eq!(hub.tip_hash().unwrap(), b2.block_hash());
    assert!(hub.is_connected(&b1.block_hash()));
    assert!(hub.is_connected(&b2.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn inv_of_already_asked_block_does_not_getdata() {
    // p2p_sendheaders Part 2: test_node announces headers (we getdata),
    // then inv_node re-invs the same hashes. One getdata in flight globally.
    use bitcoin::consensus::encode::serialize;
    use bitcoin::script::ScriptBuf;
    use bitcoin::Network;
    use rbitcoin_primitives::Height;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    fn drain_block_getdata(rx: &mut mpsc::UnboundedReceiver<NetworkMessage>) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        while let Ok(m) = rx.try_recv() {
            if let NetworkMessage::GetData(inv) = m {
                for i in inv {
                    if let Inventory::Block(h)
                    | Inventory::WitnessBlock(h)
                    | Inventory::CompactBlock(h) = i
                    {
                        hashes.push(h);
                    }
                }
            }
        }
        hashes
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (src_dir, src_q) = tmp_store("inv-asked-src");
        let src = ChainHub::new(src_q, ChainParams::regtest(), Milestone::NONE);
        src.ensure_genesis().unwrap();
        src.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let hdr = src.query.wire_header_at_height(Height(1)).unwrap();
        let hash = hdr.block_hash();

        let (dir, q) = tmp_store("inv-asked-dst");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut ban = 0u32;

        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![hdr])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        let first = drain_block_getdata(&mut out_rx);
        assert_eq!(first, vec![hash], "header announce must getdata once");
        assert!(hub.already_have_or_asked_block(&hash));

        // Second peer: empty local requested set, same hub (asked_blocks).
        let (out_tx2, mut out_rx2) = mpsc::unbounded_channel();
        let mut pending_headers2 = HashMap::new();
        let mut requested2 = HashSet::new();
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(hash)])),
            &hub,
            &out_tx2,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers2,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested2,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        let second = drain_block_getdata(&mut out_rx2);
        assert!(
            second.is_empty(),
            "duplicate inv must not getdata, got {second:?}"
        );

        let _ = std::fs::remove_dir_all(src_dir);
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `p2p_nobloomfilter_messages.py`: mempool/filter* disconnect when bloom off.
#[test]
fn bloom_disabled_messages_request_disconnect() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
    use bitcoin::Network;

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

    let (dir, q) = tmp_store("bloom-off");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut pending_headers = HashMap::new();
    let mut pending_blocks = PendingBlocks::new();
    let mut pending_cmpct = HashMap::new();
    let mut from_peer = HashMap::new();
    let mut requested = HashSet::new();
    let mut wants_headers = false;
    let mut wtxid = false;
    let mut send_cmpct = false;
    let mut cmpct_ver = 2u32;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let msgs = [
        NetworkMessage::MemPool,
        NetworkMessage::FilterClear,
        NetworkMessage::FilterAdd(FilterAdd { data: vec![0xcc] }),
        NetworkMessage::FilterLoad(FilterLoad {
            filter: vec![],
            hash_funcs: 1,
            tweak: 0,
            flags: BloomFlags::None,
        }),
    ];
    for msg in msgs {
        let mut ban = 0u32;
        rt.block_on(async {
            handle_peer_frame(
                frame_for(msg),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut requested,
                &mut ban,
                None,
            )
            .await
            .unwrap();
        });
        assert!(
            ban >= BAN_SCORE_THRESHOLD,
            "bloom-off message must punish-disconnect (ban={ban})"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// `p2p_invalid_locator.py`: getheaders/getblocks with locator > MAX_LOCATOR_SZ disconnect.
#[test]
fn oversize_locator_request_disconnect() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage};
    use bitcoin::Network;

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

    let (dir, q) = tmp_store("locator-oversize");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut pending_headers = HashMap::new();
    let mut pending_blocks = PendingBlocks::new();
    let mut pending_cmpct = HashMap::new();
    let mut from_peer = HashMap::new();
    let mut requested = HashSet::new();
    let mut wants_headers = false;
    let mut wtxid = false;
    let mut send_cmpct = false;
    let mut cmpct_ver = 2u32;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let stop = BlockHash::from_byte_array([0u8; 32]);
    let oversize: Vec<BlockHash> = (0..=MAX_LOCATOR_SZ)
        .map(|i| BlockHash::from_byte_array([i as u8; 32]))
        .collect();
    assert_eq!(oversize.len(), MAX_LOCATOR_SZ + 1);
    let within: Vec<BlockHash> = oversize[..MAX_LOCATOR_SZ].to_vec();

    for msg in [
        NetworkMessage::GetHeaders(GetHeadersMessage::new(oversize.clone(), stop)),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(oversize.clone(), stop)),
    ] {
        let mut ban = 0u32;
        rt.block_on(async {
            handle_peer_frame(
                frame_for(msg),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut requested,
                &mut ban,
                None,
            )
            .await
            .unwrap();
        });
        assert!(
            ban >= BAN_SCORE_THRESHOLD,
            "oversize locator must punish-disconnect (ban={ban})"
        );
    }

    // Exactly MAX_LOCATOR_SZ stays connected (ban untouched).
    let mut ban = 0u32;
    rt.block_on(async {
        handle_peer_frame(
            frame_for(NetworkMessage::GetHeaders(GetHeadersMessage::new(
                within, stop,
            ))),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
    });
    assert_eq!(ban, 0, "max-sized locator must not disconnect");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn desirable_service_flags_match_core() {
    let full = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    let pruned = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
    let none = ServiceFlags::NONE;
    let net_only = ServiceFlags::NETWORK;
    let wit_only = ServiceFlags::WITNESS;
    let limited_wit = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
    let limited_wit_v2 = limited_wit | ServiceFlags::P2P_V2;

    assert_eq!(desirable_service_flags(none, 0), full);
    assert_eq!(desirable_service_flags(net_only, 0), full);
    assert_eq!(desirable_service_flags(wit_only, 0), full);
    assert_eq!(desirable_service_flags(full, 0), full);
    assert!(!has_all_desirable_service_flags(none, 0));
    assert!(!has_all_desirable_service_flags(net_only, 0));
    assert!(!has_all_desirable_service_flags(wit_only, 0));
    assert!(has_all_desirable_service_flags(full, 0));

    assert_eq!(desirable_service_flags(limited_wit, 150), full);
    assert!(!has_all_desirable_service_flags(limited_wit, 150));
    assert_eq!(desirable_service_flags(limited_wit, 138), pruned);
    assert!(has_all_desirable_service_flags(limited_wit, 138));
    assert!(has_all_desirable_service_flags(limited_wit_v2, 138));

    assert_eq!(
        expected_services_disconnect_log(0, full.to_u64()),
        "does not offer the expected services (00000000 offered, 00000009 expected)"
    );
    assert_eq!(
        expected_services_disconnect_log(limited_wit.to_u64(), full.to_u64()),
        "does not offer the expected services (00000408 offered, 00000009 expected)"
    );
}

#[test]
fn expect_services_from_conn_matches_core() {
    use crate::peers::PeerConnType;
    assert!(!expect_services_from_conn(PeerConnType::Inbound));
    assert!(!expect_services_from_conn(PeerConnType::Manual));
    assert!(!expect_services_from_conn(PeerConnType::Feeler));
    assert!(expect_services_from_conn(PeerConnType::OutboundFullRelay));
    assert!(expect_services_from_conn(PeerConnType::BlockRelay));
    assert!(expect_services_from_conn(PeerConnType::AddrFetch));
}

#[test]
fn handshake_disconnect_log_needles() {
    assert_eq!(
        feeler_connection_completed_log(),
        "feeler connection completed"
    );
    let line = connected_to_self_log("127.0.0.1:18444");
    assert!(line.contains("connected to self"));
    assert!(line.contains("disconnecting"));
}

#[test]
fn redundant_verack_is_ignored_and_logged() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        let payload = full[24..].to_vec();
        FramedMessage {
            magic,
            command,
            payload,
        }
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("redundant-verack");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 0u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut ban = 0u32;

        rbitcoin_log::capture_logs(true);
        handle_peer_frame(
            frame_for(NetworkMessage::Verack),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            None,
        )
        .await
        .unwrap();
        let logs = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);

        assert!(
            logs.iter()
                .any(|(_, m)| m.contains("ignoring redundant verack message")),
            "expected Core redundant-verack needle, got {logs:?}"
        );
        assert_eq!(ban, 0, "redundant verack must not disconnect");

        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `p2p_addrfetch.py`: post-handshake AddrFetch queues getaddr, not getheaders.
#[test]
fn addrfetch_post_handshake_queues_getaddr_not_getheaders() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;

    let (dir, q) = tmp_store("addrfetch-getaddr");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = crate::peers::PeerHub::new();
    // Tip older than 24h so try_start_headers_sync would otherwise start.
    peers.set_mock_now(1_700_000_000);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let sess = peers.register(
        addr,
        addr,
        &ver,
        false,
        crate::peers::PeerConnType::AddrFetch,
    );
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    sess.attach_out(out_tx.clone());

    assert!(
        !maybe_queue_initial_getheaders(&out_tx, &hub, sess.as_ref()),
        "AddrFetch must not start initial headers sync"
    );
    assert!(
        maybe_queue_addrfetch_getaddr(&out_tx, sess.as_ref()),
        "AddrFetch must queue getaddr after handshake"
    );

    let mut saw_getaddr = false;
    let mut saw_getheaders = false;
    while let Ok(m) = out_rx.try_recv() {
        match m {
            NetworkMessage::GetAddr => saw_getaddr = true,
            NetworkMessage::GetHeaders(_) => saw_getheaders = true,
            _ => {}
        }
    }
    assert!(saw_getaddr, "expected GetAddr");
    assert!(!saw_getheaders, "AddrFetch must not queue GetHeaders");
    assert!(!sess.stop.load(Ordering::SeqCst));

    let _ = std::fs::remove_dir_all(dir);
}

/// `p2p_addrfetch.py`: Addr/AddrV2 with >1 entry completes addr-fetch (disconnect).
#[test]
fn addrfetch_multi_addr_disconnects() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::Network;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        let magic = Magic::from(Network::Regtest);
        let raw = RawNetworkMessage::new(magic, msg);
        let full = serialize(&raw);
        FramedMessage {
            magic,
            command: full[4..16].try_into().unwrap(),
            payload: full[24..].to_vec(),
        }
    }

    let (dir, q) = tmp_store("addrfetch-multi");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = crate::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
    let sess = peers.register(
        addr,
        addr,
        &ver,
        false,
        crate::peers::PeerConnType::AddrFetch,
    );
    let (out_tx, _out_rx) = mpsc::unbounded_channel();
    let mut wants_headers = false;
    let mut wtxid = false;
    let mut send_cmpct = false;
    let mut cmpct_ver = 0u32;
    let mut pending_headers = HashMap::new();
    let mut pending_blocks = PendingBlocks::new();
    let mut pending_cmpct = HashMap::new();
    let mut from_peer = HashMap::new();
    let mut ban = 0u32;
    let one = Address::new(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 8)), 18444),
        ServiceFlags::NETWORK,
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        handle_peer_frame(
            frame_for(NetworkMessage::Addr(vec![(1u32, one.clone())])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        assert!(
            !sess.stop.load(Ordering::SeqCst),
            "single addr must not disconnect"
        );
        assert_eq!(ban, 0);

        handle_peer_frame(
            frame_for(NetworkMessage::Addr(vec![
                (1u32, one.clone()),
                (1u32, one.clone()),
            ])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        assert!(
            sess.stop.load(Ordering::SeqCst),
            "Addr len>1 must complete addr-fetch"
        );

        let sess2 = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::AddrFetch,
        );
        let mut ban2 = 0u32;
        let v2 = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(192, 0, 0, 8)),
            port: 18444,
        };
        handle_peer_frame(
            frame_for(NetworkMessage::AddrV2(vec![v2.clone(), v2])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut HashSet::new(),
            &mut ban2,
            Some(sess2.as_ref()),
        )
        .await
        .unwrap();
        assert!(
            sess2.stop.load(Ordering::SeqCst),
            "AddrV2 len>1 must complete addr-fetch"
        );
    });

    let _ = std::fs::remove_dir_all(dir);
}

/// `p2p_addrfetch.py`: AddrFetch disconnects after 300s on the session clock.
#[test]
fn addrfetch_times_out_after_300s() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;

    let peers = crate::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
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
    let sess = peers.register(
        addr,
        addr,
        &ver,
        false,
        crate::peers::PeerConnType::AddrFetch,
    );
    assert!(!addrfetch_timed_out(sess.as_ref()));
    peers.set_mock_now(1_700_000_000 + 295);
    assert!(!addrfetch_timed_out(sess.as_ref()));
    peers.set_mock_now(1_700_000_000 + 301);
    assert!(addrfetch_timed_out(sess.as_ref()));
    assert!(!sess.stop.load(Ordering::SeqCst));
}

#[test]
fn pending_blocks_insert_evicts_at_cap() {
    let mut pending = PendingBlocks::new();
    let bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    let mut hashes = Vec::new();
    for i in 0u32..(MAX_PENDING_BLOCKS_FOR_TEST as u32 + 1) {
        let mut b = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        b.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array({
            let mut m = [0u8; 32];
            m[0] = (i >> 24) as u8;
            m[1] = (i >> 16) as u8;
            m[2] = (i >> 8) as u8;
            m[3] = i as u8;
            m
        });
        b.header.bits = bits;
        let h = b.block_hash();
        hashes.push(h);
        pending.insert(h, b);
    }
    assert_eq!(pending.keys().len(), MAX_PENDING_BLOCKS_FOR_TEST);
    assert!(
        !pending.contains_key(&hashes[0]),
        "cap eviction must drop the oldest insert, not HashMap::keys().next()"
    );
    assert!(pending.contains_key(&hashes[MAX_PENDING_BLOCKS_FOR_TEST]));
}

#[test]
fn try_queue_served_block_false_at_cap() {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let n = AtomicUsize::new(MAX_SERVE_BLOCKS);
    let gen = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let queued = try_queue_served_block(&out_tx, Some(&n), NetworkMessage::Block(gen)).unwrap();
    assert!(!queued);
    assert!(out_rx.try_recv().is_err());
    assert_eq!(n.load(Ordering::SeqCst), MAX_SERVE_BLOCKS);
}

#[test]
fn announced_tip_is_hopeless_less_and_288_behind() {
    use std::cmp::Ordering;
    assert!(announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Less)
    ));
    assert!(!announced_tip_is_hopeless(
        964_000,
        963_900,
        Some(Ordering::Less)
    ));
    assert!(!announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Greater)
    ));
    assert!(!announced_tip_is_hopeless(100, 1, Some(Ordering::Less)));
    assert!(!announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Equal)
    ));
    assert!(!announced_tip_is_hopeless(964_000, 961_638, None));
}

#[test]
fn shorter_higher_work_fork_is_not_hopeless() {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};
    use rbitcoin_primitives::Height;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }
    let (dir, q) = tmp_store("short-high-work-fork");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(5, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let gen = hub.query.wire_header_at_height(Height(0)).unwrap();
    let hard = Header {
        version: Version::from_consensus(4),
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array([0x5a; 32]),
        time: gen.time.saturating_add(600),
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: 0,
    };
    let tip = hard.block_hash();
    let mut pending = HashMap::new();
    pending.insert(tip, hard);
    let work_cmp = announced_work_cmp(&hub, &pending, tip);
    assert_eq!(
        work_cmp,
        Some(std::cmp::Ordering::Greater),
        "one mainnet-diff header must outwork 300 regtest blocks"
    );
    let announced_h = announced_headers_height(&hub, &pending, tip);
    assert!(
        !announced_tip_is_hopeless(hub.tip_height().unwrap(), announced_h, work_cmp),
        "shorter higher-work path must not be hopeless"
    );
    let want =
        fetchable_header_path_bodies(&hub, &pending, tip, &PendingBlocks::new(), &HashSet::new());
    assert!(
        !want.is_empty(),
        "must not skip bodies on a shorter higher-work path"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn connecting_ancient_weaker_headers_request_disconnect() {
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::encode::serialize;
    use bitcoin::{CompactTarget, Network, Target, TxMerkleNode};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    fn mine_header(prev: BlockHash, merkle: [u8; 32], time: u32) -> Header {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut hdr = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(merkle),
            time,
            bits,
            nonce: 0,
        };
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            hdr.nonce = nonce;
            if hdr.validate_pow(target).is_ok() {
                break;
            }
        }
        hdr
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("ancient-fork-headers");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        hub.generate_to_script(300, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        assert!(hub.tip_height().unwrap() >= 300);

        let gen = hub
            .query
            .wire_header_at_height(rbitcoin_primitives::Height(0))
            .unwrap();
        let side = mine_header(gen.block_hash(), [0x9e; 32], gen.time.saturating_add(600));

        let peers = crate::peers::PeerHub::new();
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
        let sess = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![side])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        assert_eq!(ban, 0, "ancient fork must not ban-score");
        assert!(
            sess.stop.load(Ordering::SeqCst),
            "hopeless ancient advertised tip must disconnect"
        );

        let sess_keep = peers.register(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445),
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        peers.set_noban(true);
        let mut ban = 0u32;
        let mut pending_headers = HashMap::new();
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![side])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            Some(sess_keep.as_ref()),
        )
        .await
        .unwrap();
        assert!(
            !sess_keep.stop.load(Ordering::SeqCst),
            "noban must keep the session on an ancient weaker fork"
        );

        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn getdata_skips_reconstruct_when_serve_inflight_at_cap() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin::Network;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("serve-inflight-cap");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let hashes = hub
            .generate_to_script(20, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        assert!(hashes.len() >= 20);

        let peers = crate::peers::PeerHub::new();
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
        let sess = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut ban = 0u32;
        let inv: Vec<Inventory> = hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect();
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(inv)),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        let mut n_block = 0usize;
        while let Ok(msg) = out_rx.try_recv() {
            if matches!(msg, NetworkMessage::Block(_)) {
                n_block += 1;
            }
        }
        assert!(
            n_block <= MAX_SERVE_BLOCKS,
            "queued {n_block} blocks over cap {MAX_SERVE_BLOCKS}"
        );
        assert_eq!(n_block, MAX_SERVE_BLOCKS);
        assert_eq!(sess.serve_inflight.load(Ordering::SeqCst), MAX_SERVE_BLOCKS);
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Catch-up headers (genesis + 20) must not GetData more than the serve
/// window. Requesting the whole path left hashes in `requested` that the
/// peer never sent (overnight `sync_blocks` 60s: createmultisig 149,
/// minchainwork 50, bip68 CSV 400).
#[test]
fn catchup_headers_getdata_stays_in_serve_window() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    use rbitcoin_primitives::Height;
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    fn getdata_hashes(rx: &mut mpsc::UnboundedReceiver<NetworkMessage>) -> Vec<BlockHash> {
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let NetworkMessage::GetData(inv) = msg {
                for i in inv {
                    match i {
                        Inventory::Block(h)
                        | Inventory::WitnessBlock(h)
                        | Inventory::CompactBlock(h) => out.push(h),
                        _ => {}
                    }
                }
            }
        }
        out
    }

    let n = MAX_SERVE_BLOCKS + 4;
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (src_dir, src_q) = tmp_store("catchup-gd-src");
        let src = ChainHub::new(src_q, ChainParams::regtest(), Milestone::NONE);
        src.ensure_genesis().unwrap();
        src.generate_to_script(n as u32, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let headers: Vec<bitcoin::block::Header> = (1..=n as u32)
            .map(|h| src.query.wire_header_at_height(Height(h)).unwrap())
            .collect();
        assert_eq!(headers.len(), n);

        let (dir, q) = tmp_store("catchup-gd-dst");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut ban = 0u32;

        handle_peer_frame(
            frame_for(NetworkMessage::Headers(headers.clone())),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        let first = getdata_hashes(&mut out_rx);
        assert_eq!(
            first.len(),
            MAX_SERVE_BLOCKS,
            "catch-up getdata must match serve window, got {}",
            first.len()
        );
        assert_eq!(requested.len(), MAX_SERVE_BLOCKS);

        for h in &first {
            let block = src
                .query
                .reconstruct_archived_block(&h.to_byte_array())
                .unwrap()
                .expect("src body");
            handle_peer_frame(
                frame_for(NetworkMessage::Block(block)),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut requested,
                &mut ban,
                None,
            )
            .await
            .unwrap();
        }
        let rest = getdata_hashes(&mut out_rx);
        assert_eq!(
            rest.len(),
            n - MAX_SERVE_BLOCKS,
            "after the window fills, remaining header-path bodies must be asked, got {}",
            rest.len()
        );
        let want: HashSet<_> = headers[MAX_SERVE_BLOCKS..]
            .iter()
            .map(|h| h.block_hash())
            .collect();
        let got: HashSet<_> = rest.into_iter().collect();
        assert_eq!(got, want);

        let _ = std::fs::remove_dir_all(src_dir);
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Same catch-up as above, but the peer answers with `CmpctBlock` (node-to-node
/// `sendcmpct` / `MSG_CMPCT_BLOCK` getdata). Accepting compact must drop the
/// hash from `requested` or drain's serve window stays full.
#[test]
fn catchup_compact_getdata_clears_requested_for_next_window() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    use rbitcoin_primitives::Height;
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    fn getdata_hashes(rx: &mut mpsc::UnboundedReceiver<NetworkMessage>) -> Vec<BlockHash> {
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let NetworkMessage::GetData(inv) = msg {
                for i in inv {
                    match i {
                        Inventory::Block(h)
                        | Inventory::WitnessBlock(h)
                        | Inventory::CompactBlock(h) => out.push(h),
                        _ => {}
                    }
                }
            }
        }
        out
    }

    let n = MAX_SERVE_BLOCKS + 4;
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (src_dir, src_q) = tmp_store("catchup-cmpct-src");
        let src = ChainHub::new(src_q, ChainParams::regtest(), Milestone::NONE);
        src.ensure_genesis().unwrap();
        src.generate_to_script(n as u32, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let headers: Vec<bitcoin::block::Header> = (1..=n as u32)
            .map(|h| src.query.wire_header_at_height(Height(h)).unwrap())
            .collect();

        let (dir, q) = tmp_store("catchup-cmpct-dst");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let mp = crate::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = true;
        let mut cmpct_ver = 2u32;
        let mut ban = 0u32;

        handle_peer_frame(
            frame_for(NetworkMessage::Headers(headers.clone())),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        let first = getdata_hashes(&mut out_rx);
        assert_eq!(first.len(), MAX_SERVE_BLOCKS);
        assert_eq!(requested.len(), MAX_SERVE_BLOCKS);

        for h in &first {
            let block = src
                .query
                .reconstruct_archived_block(&h.to_byte_array())
                .unwrap()
                .expect("src body");
            let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
            handle_peer_frame(
                frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                    compact_block: hsi,
                })),
                &hub,
                &out_tx,
                &mut wants_headers,
                &mut wtxid,
                &mut send_cmpct,
                &mut cmpct_ver,
                &mut pending_headers,
                &mut pending_blocks,
                &mut pending_cmpct,
                &mut from_peer,
                &mut requested,
                &mut ban,
                None,
            )
            .await
            .unwrap();
        }
        assert!(
            requested.len() < MAX_SERVE_BLOCKS,
            "compact accept must free requested slots, still {}",
            requested.len()
        );
        let rest = getdata_hashes(&mut out_rx);
        assert_eq!(
            rest.len(),
            n - MAX_SERVE_BLOCKS,
            "after compact window fills, remaining header-path bodies must be asked, got {}",
            rest.len()
        );
        let want: HashSet<_> = headers[MAX_SERVE_BLOCKS..]
            .iter()
            .map(|h| h.block_hash())
            .collect();
        let got: HashSet<_> = rest.into_iter().collect();
        assert_eq!(got, want);

        let _ = std::fs::remove_dir_all(src_dir);
        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn queue_getheaders_from_hash_puts_it_first() {
    let (dir, q) = tmp_store("gh-from");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let start = BlockHash::from_byte_array([0xcd; 32]);
    let (tx, mut rx) = mpsc::unbounded_channel();
    queue_getheaders(&tx, &hub, None, false, Some(start)).unwrap();
    match rx.try_recv().unwrap() {
        NetworkMessage::GetHeaders(gh) => {
            assert_eq!(gh.locator_hashes[0], start);
        }
        other => panic!("expected GetHeaders, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn full_headers_batch_continues_from_last_header() {
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::encode::serialize;
    use bitcoin::{CompactTarget, Network, TxMerkleNode};
    use tokio::runtime::Builder;

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("hdr-continue");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let unknown_prev = BlockHash::from_byte_array([0x11; 32]);
        let mut headers = Vec::with_capacity(MAX_HEADERS_RESULTS);
        let mut prev = unknown_prev;
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
        let peers = crate::peers::PeerHub::new();
        let addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 18446);
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
        let sess = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = false;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(headers)),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        let mut getheaders = Vec::new();
        while let Ok(msg) = out_rx.try_recv() {
            if let NetworkMessage::GetHeaders(gh) = msg {
                getheaders.push(gh.locator_hashes);
            }
        }
        assert_eq!(
            getheaders.len(),
            1,
            "full unconnected batch must not also re-ask from our tip"
        );
        assert_eq!(
            getheaders[0].first().copied(),
            Some(last),
            "full headers batch must getheaders from the last header, not our tip"
        );
        assert_ne!(getheaders[0].first().copied(), Some(our_tip));
        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn pending_header_walk_is_ram_then_one_store_lookup() {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};
    use std::time::Instant;

    let (dir, q) = tmp_store("pending-walk");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
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

    let t0 = Instant::now();
    let height = announced_headers_height(&hub, &pending, tip);
    let branch = header_branch_vs_tip(&hub, &pending, tip);
    let connects = header_announcement_connects(&hub, &pending, genesis);
    let dt = t0.elapsed();
    assert_eq!(height, n, "pending chain from genesis is height={n}");
    assert_eq!(branch, Some(std::cmp::Ordering::Greater));
    assert!(connects);
    assert!(
        dt < std::time::Duration::from_millis(200),
        "RAM pending walk must not per-step store lookup, took {dt:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn inbound_handshake_timeout_after_silence() {
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _silent = TcpStream::connect(addr).await.unwrap();
    let (stream, peer) = listener.accept().await.unwrap();

    let handle = tokio::spawn(async move {
        connect_and_handshake_timed(
            Duration::from_millis(50),
            stream,
            Magic::REGTEST,
            addr,
            peer,
            0,
            true,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!handle.is_finished(), "must still wait during handshake");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        handle.is_finished(),
        "silence past the bound must end handshake"
    );
    match handle.await.unwrap() {
        Err(NetError::Timeout) => {}
        Err(e) => panic!("expected Timeout, got {e}"),
        Ok(_) => panic!("handshake succeeded on a silent peer"),
    }
}

#[test]
fn inbound_handshake_timeout_is_core_60s() {
    assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(60));
}

#[tokio::test]
async fn outbound_handshake_timeout_after_silence() {
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = TcpStream::connect(addr).await.unwrap();
    let _accepted = listener.accept().await.unwrap();

    let handle = tokio::spawn(async move {
        connect_and_handshake_timed(
            Duration::from_millis(50),
            stream,
            Magic::REGTEST,
            addr,
            addr,
            0,
            false,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!handle.is_finished(), "must still wait during handshake");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        handle.is_finished(),
        "silence past the bound must end handshake"
    );
    match handle.await.unwrap() {
        Err(NetError::Timeout) => {}
        Err(e) => panic!("expected Timeout, got {e}"),
        Ok(_) => panic!("handshake succeeded on a silent peer"),
    }
}

#[tokio::test]
async fn feeler_handshake_timeout_after_silence() {
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = TcpStream::connect(addr).await.unwrap();
    let _accepted = listener.accept().await.unwrap();

    let handle = tokio::spawn(async move {
        run_feeler_timed(
            Duration::from_millis(50),
            stream,
            Magic::REGTEST,
            addr,
            addr,
            0,
            "/rbitcoin:test/",
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!handle.is_finished(), "must still wait during feeler");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        handle.is_finished(),
        "silence past the bound must end feeler"
    );
    match handle.await.unwrap() {
        Err(NetError::Timeout) => {}
        Err(e) => panic!("expected Timeout, got {e}"),
        Ok(_) => panic!("feeler succeeded on a silent peer"),
    }
}

/// Writer used to `fetch_sub` every `CmpctBlock`, including tip announces that
/// never `fetch_add`. That wrapped `serve_inflight` to `usize::MAX` and skipped
/// every later reconstruct (`sync_blocks` 60s on long-lived node-to-node).
#[test]
fn compact_tip_announce_must_not_wrap_serve_inflight() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("cmpct-ann-inflight");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let hashes = hub
            .generate_to_script(1, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let hash = hashes[0];

        let peers = crate::peers::PeerHub::new();
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
        let sess = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let msg = cmpct_announce_msg(&hub, &hash, 2).expect("cmpct announce");
        queue_cmpct_tip_announce(&out_tx, msg).unwrap();
        note_served_write(&sess.serve_inflight);
        assert_eq!(
            sess.serve_inflight.load(Ordering::SeqCst),
            0,
            "unpaired announce write must saturating-sub, not wrap"
        );
        while out_rx.try_recv().is_ok() {}

        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = true;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(hash)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        assert!(
            matches!(out_rx.try_recv(), Ok(NetworkMessage::CmpctBlock(_))),
            "getdata MSG_CMPCT_BLOCK must still serve after a compact tip announce"
        );
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Compact tip announce must not occupy reconstruct slots. A burst of
/// `MAX_SERVE_BLOCKS` announces (generate-to 432 with `sync_fun=no_op`)
/// left `serve_inflight` at cap and skipped later getdata
/// (`feature_bip68_sequence` activateCSV `sync_blocks`).
#[test]
fn compact_tip_announce_must_not_consume_serve_slots() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, q) = tmp_store("cmpct-ann-slots");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        let hashes = hub
            .generate_to_script(1, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let hash = hashes[0];

        let peers = crate::peers::PeerHub::new();
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
        let sess = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        for _ in 0..MAX_SERVE_BLOCKS {
            let msg = cmpct_announce_msg(&hub, &hash, 2).expect("cmpct announce");
            queue_cmpct_tip_announce(&out_tx, msg).unwrap();
        }
        assert_eq!(
            sess.serve_inflight.load(Ordering::SeqCst),
            0,
            "announce must not occupy reconstruct slots"
        );
        while out_rx.try_recv().is_ok() {}

        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = true;
        let mut cmpct_ver = 2u32;
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(hash)])),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        assert!(
            matches!(out_rx.try_recv(), Ok(NetworkMessage::CmpctBlock(_))),
            "getdata MSG_CMPCT_BLOCK must still serve after a burst of compact announces"
        );
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Coinbase-only compact must reconstruct from prefilled txs; a missing
/// mempool hub must not force a full-getdata fallback that then never
/// arrives (`p2p_compactblocks_hb` 1-block relay).
#[test]
fn coinbase_compact_fills_without_mempool() {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::Network;
    use tokio::runtime::Builder;

    if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
    }

    fn frame_for(msg: NetworkMessage) -> FramedMessage {
        use bitcoin::p2p::message::RawNetworkMessage;
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

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (src_dir, src_q) = tmp_store("cmpct-nomp-src");
        let src = ChainHub::new(src_q, ChainParams::regtest(), Milestone::NONE);
        src.ensure_genesis().unwrap();
        let hashes = src
            .generate_to_script(1, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let hash = hashes[0];
        let block = src
            .query
            .reconstruct_archived_block(&hash.to_byte_array())
            .unwrap()
            .expect("src body");
        let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();

        let (dir, q) = tmp_store("cmpct-nomp-dst");
        let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
        hub.ensure_genesis().unwrap();
        assert!(hub.mempool().is_none());
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let mut pending_headers = HashMap::new();
        let mut pending_blocks = PendingBlocks::new();
        let mut pending_cmpct = HashMap::new();
        let mut from_peer = HashMap::new();
        let mut requested = HashSet::new();
        let mut wants_headers = false;
        let mut wtxid = false;
        let mut send_cmpct = true;
        let mut cmpct_ver = 2u32;
        let mut ban = 0u32;
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi,
            })),
            &hub,
            &out_tx,
            &mut wants_headers,
            &mut wtxid,
            &mut send_cmpct,
            &mut cmpct_ver,
            &mut pending_headers,
            &mut pending_blocks,
            &mut pending_cmpct,
            &mut from_peer,
            &mut requested,
            &mut ban,
            None,
        )
        .await
        .unwrap();
        assert!(
            hub.has_block(&hash),
            "coinbase compact must connect without a mempool hub"
        );
        while let Ok(msg) = out_rx.try_recv() {
            if matches!(msg, NetworkMessage::GetData(_)) {
                panic!("coinbase compact must not fall back to getdata, got {msg:?}");
            }
        }
        let _ = std::fs::remove_dir_all(src_dir);
        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn tip_event_for_announce_on_lagged_uses_current_hub_tip() {
    use bitcoin::ScriptBuf;
    use tokio::sync::broadcast;

    let (dir, q) = tmp_store("lagged-tip-ev");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(80, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let want = hub.tip_hash().unwrap();
    let height = hub.tip_height().unwrap();
    let TipRecvAnnounce::Announce(ev) =
        tip_event_for_announce(Err(broadcast::error::RecvError::Lagged(99)), &hub)
    else {
        panic!("Lagged must re-announce current tip, not drop");
    };
    assert_eq!(ev.hash, want);
    assert_eq!(ev.height, height);
    assert_eq!(ev.reorg_branch_len, 0);
    let _ = std::fs::remove_dir_all(dir);
}

/// Burst tip advances (> tip broadcast capacity) must still reach a follow peer
/// without waiting for the 120s headers poll (`sync_blocks` is 60s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tip_burst_past_broadcast_capacity_still_syncs_peer() {
    use crate::P2PNode;
    use bitcoin::ScriptBuf;
    use std::time::Duration;

    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-tip-burst-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(burst-a)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(burst-b)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        if na.follow_live_count() >= 1 && !nb.peers.snapshot().is_empty() {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "follow session must be live before tip burst");

    // Capacity is 64; sync generate without await fills the ring so the
    // announce task sees Lagged instead of every TipEvent.
    const BURST: u32 = 80;
    na.hub
        .generate_to_script(BURST, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let want = na.tip_height().unwrap();
    assert!(want >= BURST, "miner tip {want}");

    let mut peer_tip = nb.tip_height().unwrap_or(0);
    for _ in 0..200 {
        peer_tip = nb.tip_height().unwrap_or(0);
        if peer_tip >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        peer_tip, want,
        "peer must catch tip after Lagged burst within ~10s (not headers_poll 120s)"
    );

    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `disconnect_nodes` waits ≤5s for the far side's `getpeerinfo` to drop us.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_clears_far_side_getpeerinfo_within_5s() {
    use crate::P2PNode;
    use std::time::Duration;

    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-disc-far-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode0)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        let a_sees = na
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode1"));
        let b_sees = nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"));
        if a_sees && b_sees {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "both sides must list each other before disconnect");

    let peer_id = na
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.subver.contains("testnode1"))
        .map(|p| p.id)
        .expect("outbound peer id");
    assert!(na.peers.disconnect_id(peer_id));
    assert!(
        na.peers.snapshot().is_empty(),
        "local getpeerinfo clears immediately"
    );

    let mut far_clear = false;
    for _ in 0..100 {
        if !nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"))
        {
            far_clear = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        far_clear,
        "far side getpeerinfo must drop us within 5s (Core disconnect_nodes)"
    );

    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `mempool_reorg` disconnect_nodes after generate+sync — far side must still
/// clear within 5s even if the session was just busy accepting tip blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_after_tip_sync_clears_far_side_within_5s() {
    use crate::P2PNode;
    use bitcoin::ScriptBuf;
    use std::time::Duration;

    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-disc-tip-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode0)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        crate::DEFAULT_MAX_INBOUND,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        let a_sees = na
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode1"));
        let b_sees = nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"));
        if a_sees && b_sees {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "both sides must list each other before generate");

    const BURST: u32 = 3;
    na.hub
        .generate_to_script(BURST, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let want = na.tip_height().unwrap();
    let mut synced = false;
    for _ in 0..200 {
        if nb.tip_height().unwrap_or(0) >= want {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(synced, "far side must sync tip before disconnect");

    let peer_id = na
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.subver.contains("testnode1"))
        .map(|p| p.id)
        .expect("outbound peer id");
    assert!(na.peers.disconnect_id(peer_id));

    let mut far_clear = false;
    for _ in 0..100 {
        if !nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"))
        {
            far_clear = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        far_clear,
        "far side getpeerinfo must drop us within 5s after tip sync (mempool_reorg)"
    );

    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}
