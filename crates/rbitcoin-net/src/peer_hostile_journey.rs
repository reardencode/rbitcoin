use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use bitcoin::ScriptBuf;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn hostile_ver(addr: SocketAddr) -> VersionMessage {
    VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 7,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    }
}

fn hostile_addr(port: u16) -> AddrV2Message {
    AddrV2Message {
        time: 1_700_000_000,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)),
        port,
    }
}

#[tokio::test]
async fn hostile_peer_session() {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::block::Header;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use rbitcoin_mempool::AcceptError;

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("hostile-session");
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(200, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let genesis = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(0))
        .unwrap()
        .block_hash();

    let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        crate::peers::PeerConnType::Inbound,
    );
    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    let mut follow = PeerFollowState::new();

    let hdr = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    for batch in 0..4u32 {
        let headers: Vec<Header> = (0..2_000u32)
            .map(|i| {
                let mut h = hdr;
                h.nonce = batch * 2_000 + i;
                h
            })
            .collect();
        handle_peer_inventory_msg(
            &NetworkMessage::Headers(headers),
            &hub,
            &out_tx,
            &mut follow,
            Some(&peer),
        )
        .unwrap();
    }
    assert_eq!(follow.pending_headers.len(), super::MAX_PENDING_HEADERS);
    let kept = *follow.pending_headers.keys().next().unwrap();
    let kept_hdr = follow.pending_headers[&kept];
    handle_peer_inventory_msg(
        &NetworkMessage::Headers(vec![kept_hdr]),
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
    )
    .unwrap();
    assert_eq!(follow.pending_headers.len(), super::MAX_PENDING_HEADERS);
    assert!(follow.pending_headers.contains_key(&kept));
    let mut extra = hdr;
    extra.nonce = 9_000_000;
    let extra_hash = extra.block_hash();
    handle_peer_inventory_msg(
        &NetworkMessage::Headers(vec![extra]),
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
    )
    .unwrap();
    assert_eq!(follow.pending_headers.len(), super::MAX_PENDING_HEADERS);
    assert!(!follow.pending_headers.contains_key(&extra_hash));
    while out_rx.try_recv().is_ok() {}

    let gh = GetHeadersMessage::new(vec![genesis], BlockHash::from_byte_array([0u8; 32]));
    handle_peer_inventory_msg(
        &NetworkMessage::GetHeaders(gh.clone()),
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
    )
    .unwrap();
    let NetworkMessage::Headers(first) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("one getheaders under the budget must be answered");
    };
    assert_eq!(first.len(), 200, "locator after genesis walks the tip");
    let mut queued = 1usize;
    for _ in 0..400 {
        handle_peer_inventory_msg(
            &NetworkMessage::GetHeaders(gh.clone()),
            &hub,
            &out_tx,
            &mut follow,
            Some(&peer),
        )
        .unwrap();
        match out_rx.try_recv() {
            Ok(_) => queued += 1,
            Err(_) => break,
        }
    }
    let batch = first.len().saturating_mul(81);
    let room = crate::peers::PEER_SEND_BUDGET / batch;
    assert!(
        queued <= room + 2,
        "queued {queued} header batches while the peer read nothing (room {room})"
    );
    assert!(queued > 1, "a getheaders under the budget produced no further reply");

    peer.note_send_written(peer.send_queued());
    assert!(!peer.send_over_budget());
    let before = peer.send_queued();
    queue_accounted(
        Some(&peer),
        &out_tx,
        NetworkMessage::Inv(vec![Inventory::Block(genesis)]),
    )
    .unwrap();
    queue_accounted(
        Some(&peer),
        &out_tx,
        NetworkMessage::NotFound(vec![Inventory::Block(genesis)]),
    )
    .unwrap();
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let tx_n = tx.total_size();
    queue_accounted(Some(&peer), &out_tx, NetworkMessage::Tx(tx)).unwrap();
    queue_accounted(
        Some(&peer),
        &out_tx,
        NetworkMessage::Addr(vec![(0, Address::new(&bind, ServiceFlags::NONE))]),
    )
    .unwrap();
    assert_eq!(
        peer.send_queued() - before,
        36 + 36 + tx_n + 30,
        "inv, notfound, tx, and addr share the send budget"
    );

    let block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
    let block_n = block.total_size();
    assert!(block_n > 64, "a block is not the fallback size");
    assert_eq!(
        crate::peers::outbound_msg_bytes(&NetworkMessage::Block(block.clone())),
        block_n
    );
    let v2 = NetworkMessage::AddrV2(vec![AddrV2Message {
        time: 1,
        services: ServiceFlags::NONE,
        addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
        port: 1,
    }]);
    assert_eq!(crate::peers::outbound_msg_bytes(&v2), 61);
    let hsi = HeaderAndShortIds::from_block(&block, 1, 1, &[0]).unwrap();
    assert_eq!(
        crate::peers::outbound_msg_bytes(&NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi
        })),
        1024
    );
    assert_eq!(crate::peers::PEER_SEND_BUDGET, 4 * 1024 * 1024);
    peer.note_send_written(peer.send_queued());
    peer.note_send_queued(crate::peers::PEER_SEND_BUDGET);
    assert!(
        !peer.send_over_budget(),
        "the cap itself is still inside the budget"
    );
    peer.note_send_queued(1);
    assert!(peer.send_over_budget());
    peer.note_send_written(peer.send_queued());

    while out_rx.try_recv().is_ok() {}
    handle_peer_inventory_msg(
        &NetworkMessage::GetAddr,
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
    )
    .unwrap();
    let mut addrs = 0usize;
    while let Ok(msg) = out_rx.try_recv() {
        if matches!(
            msg.expect_msg(),
            NetworkMessage::Addr(_) | NetworkMessage::AddrV2(_)
        ) {
            addrs += 1;
        }
    }
    assert_eq!(addrs, 1, "the first getaddr is answered");
    handle_peer_inventory_msg(
        &NetworkMessage::GetAddr,
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
    )
    .unwrap();
    assert!(
        out_rx.try_recv().is_err(),
        "a second getaddr is not answered"
    );

    hostile_addr_relay(&peers, &peer, &ver, &mut follow).await;

    follow.ban_score = follow
        .ban_score
        .saturating_add(tx_reject_ban_score(&AcceptError::Script(
            "script false".into(),
        )));
    assert_eq!(follow.ban_score, 10, "an invalid script raises ban score");
    follow.ban_score = follow.ban_score.saturating_add(tx_reject_ban_score(
        &AcceptError::Policy("bad-txns-too-many-sigops"),
    ));
    assert_eq!(follow.ban_score, 10, "a policy reject does not raise ban score");

    let _ = std::fs::remove_dir_all(dir);
}


#[allow(clippy::cognitive_complexity)] // address-relay chapter of the same session
async fn hostile_addr_relay(
    peers: &std::sync::Arc<crate::peers::PeerHub>,
    peer: &std::sync::Arc<crate::peers::LivePeer>,
    ver: &VersionMessage,
    follow: &mut PeerFollowState,
) {
        peer.set_wants_addrv2();
        let (src_tx, mut src_rx) = mpsc::unbounded_channel();
        peer.attach_out(src_tx);
        let mut neigh = Vec::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22000);
        let dst = peers.register(a, a, ver, true, crate::peers::PeerConnType::Inbound);
        dst.set_wants_addrv2();
        let (tx, rx) = mpsc::unbounded_channel();
        dst.attach_out(tx);
        neigh.push((dst.id, rx));
        let quiet_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 23000);
        let quiet = peers.register(
            quiet_addr,
            quiet_addr,
            ver,
            true,
            crate::peers::PeerConnType::Inbound,
        );
        let (quiet_tx, mut quiet_rx) = mpsc::unbounded_channel();
        quiet.attach_out(quiet_tx);

        assert_eq!(addr_relay_tokens(0.0, 1_000, 11_000), 1.0);
        assert!(addr_relay_tokens(0.0, 1_000, 1_000) < 1.0);

        let list: Vec<AddrV2Message> = (1..=3u8)
            .map(|i| AddrV2Message {
                time: 1_700_000_000,
                services: ServiceFlags::NETWORK,
                addr: AddrV2::Ipv4(Ipv4Addr::new(123, 123, 123, i)),
                port: 8333,
            })
            .collect();
        rbitcoin_log::capture_logs(true);
        on_addrv2(follow, Some(peer.as_ref()), &list).unwrap();
        let lines = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let mut batched = None;
        let mut batched_id = None;
        for (id, rx) in &mut neigh {
            if let Ok(msg) = rx.try_recv() {
                assert!(rx.try_recv().is_err(), "the neighbor gets a single message");
                batched_id = Some(*id);
                batched = Some(msg.expect_msg());
            }
        }
        let got = batched.expect("one addrv2");
        let NetworkMessage::AddrV2(sent) = &got else {
            panic!("expected addrv2, got {got:?}");
        };
        assert_eq!(sent, &list);
        let nbytes = serialize(&got).len();
        let want = sending_addrv2_log(nbytes, batched_id.expect("neighbor id"));
        assert!(
            lines.iter().any(|(_, l)| l == &want),
            "missing {want:?} in {lines:?}"
        );

        for i in 1..4u16 {
            let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22000 + i);
            let p = peers.register(a, a, ver, true, crate::peers::PeerConnType::Inbound);
            p.set_wants_addrv2();
            let (tx, rx) = mpsc::unbounded_channel();
            p.attach_out(tx);
            neigh.push((p.id, rx));
        }

        let n = neigh.len();
        let mut even_port = None;
        let mut odd_port = None;
        let mut wrap_port = None;
        for port in 1..20_000u16 {
            let key = addr_key_oracle(&hostile_addr(port));
            if (key as usize) < n * n {
                continue;
            }
            let start = (key as usize) % n;
            if key & 1 == 0 {
                even_port.get_or_insert(port);
            } else if start + 1 == n {
                wrap_port.get_or_insert(port);
            } else if start != 0 {
                odd_port.get_or_insert(port);
            }
            if even_port.is_some() && odd_port.is_some() && wrap_port.is_some() {
                break;
            }
        }
        let ports = [
            even_port.expect("an even relay key"),
            odd_port.expect("an odd relay key whose next neighbor does not wrap"),
            wrap_port.expect("an odd relay key whose next neighbor wraps"),
        ];
        for port in ports {
            let msg = hostile_addr(port);
            on_addrv2(follow, Some(peer.as_ref()), std::slice::from_ref(&msg)).unwrap();
            let key = addr_key_oracle(&msg);
            let n_dest = if key & 1 == 0 { 1 } else { 2 };
            let start = (key as usize) % n;
            let mut expect = Vec::new();
            for step in 0..n_dest {
                let idx = if step == 0 {
                    start
                } else if start + 1 == n {
                    0
                } else {
                    start + 1
                };
                expect.push(neigh[idx].0);
            }
            expect.sort_unstable();
            let mut got_ids = Vec::new();
            for (id, rx) in &mut neigh {
                while rx.try_recv().is_ok() {
                    got_ids.push(*id);
                }
            }
            got_ids.sort_unstable();
            assert_eq!(
                got_ids, expect,
                "port {port} key {key:#x} start {start} must select those neighbors"
            );
            assert!(src_rx.try_recv().is_err(), "a peer does not relay to itself");
            assert!(
                quiet_rx.try_recv().is_err(),
                "a peer that did not ask for addrv2 is skipped"
            );
        }

        on_addrv2(follow, Some(peer.as_ref()), &[hostile_addr(8333)]).unwrap();
        let mut reached = 0usize;
        for (_, rx) in &mut neigh {
            if rx.try_recv().is_ok() {
                reached += 1;
            }
        }
        assert!(
            (1..=2).contains(&reached),
            "one address reached {reached} neighbors"
        );
        let burst: Vec<_> = (1..1000u16).map(hostile_addr).collect();
        on_addrv2(follow, Some(peer.as_ref()), &burst).unwrap();
        for (_, rx) in &mut neigh {
            while rx.try_recv().is_ok() {}
        }
        on_addrv2(follow, Some(peer.as_ref()), &[hostile_addr(9_000)]).unwrap();
        let mut extra_relay = 0usize;
        for (_, rx) in &mut neigh {
            if rx.try_recv().is_ok() {
                extra_relay += 1;
            }
        }
        assert_eq!(extra_relay, 0, "past the 1000-address burst nothing is relayed");

}
