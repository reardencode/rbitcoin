use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::BlockHash;
use rbitcoin_ibd::ibd::peer_io::*;
use rbitcoin_ibd::ibd::rate::PeerRate;
use rbitcoin_net::codec::FramedMessage;
use rbitcoin_net::error::NetError;
use rbitcoin_net::peer_dos::{PeerRateLimiter, RATE_LIMIT_BAN_SCORE};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, Semaphore};

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
        requested: Arc::new(Mutex::new(HashSet::new())),
        solicited_bytes: Arc::new(AtomicU64::new(0)),
        solicited_ms: Arc::new(AtomicU64::new(0)),
        any_rx_ms: Arc::new(AtomicU64::new(0)),
        getdata_wire: GetdataWire::new(),
        peer_height: 100,
        connected_ms: 1,
        first_data_ms: 0,
        bytes_rx_total: Arc::new(AtomicU64::new(0)),
        rate: Default::default(),
        chain: Default::default(),
        alive: true,
        task,
    }
}

#[test]
fn usable_dial_and_services_filters() {
    assert!(!services_useful_for_ibd(ServiceFlags::NETWORK));
    assert!(!services_useful_for_ibd(ServiceFlags::NETWORK_LIMITED));
    assert!(!services_useful_for_ibd(ServiceFlags::P2P_V2));
    assert!(!services_useful_for_ibd(ServiceFlags::NONE));
    assert!(services_useful_for_ibd(
        ServiceFlags::NETWORK | ServiceFlags::P2P_V2
    ));
    assert!(services_useful_for_ibd(
        ServiceFlags::NETWORK_LIMITED | ServiceFlags::P2P_V2
    ));

    let good = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
    assert!(usable_dial_addr(&good));
    let zero_port = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0);
    assert!(!usable_dial_addr(&zero_port));
    let unspec = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8333);
    assert!(!usable_dial_addr(&unspec));
    let bcast = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 8333);
    assert!(!usable_dial_addr(&bcast));
    let multi = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 8333);
    assert!(!usable_dial_addr(&multi));
    let v6_good = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333);
    assert!(usable_dial_addr(&v6_good));
    let v6_unspec = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8333);
    assert!(!usable_dial_addr(&v6_unspec));
}

#[test]
fn stream_bytes_sample_and_first_data() {
    let mut s = dummy_slot(7);
    note_stream_bytes(&s.bytes_rx_total, 0);
    assert_eq!(s.bytes_rx_total.load(Ordering::Relaxed), 0);
    note_stream_bytes(&s.bytes_rx_total, 100);
    note_stream_bytes(&s.bytes_rx_total, 50);
    assert_eq!(s.bytes_rx_total.load(Ordering::Relaxed), 150);

    s.in_flight.insert(BlockHash::from_byte_array([1u8; 32]));
    sample_peer_rates(std::slice::from_mut(&mut s), 0);
    sample_peer_rates(std::slice::from_mut(&mut s), 5_000);
    assert!(s.rate.bps().is_some());

    while ibd_mono_ms() == 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    note_block_rx(std::slice::from_mut(&mut s), 7, 0);
    assert_eq!(s.first_data_ms, 0);
    note_block_progress(std::slice::from_mut(&mut s), 7);
    note_block_rx(std::slice::from_mut(&mut s), 7, 1000);
    assert!(s.first_data_ms > 0);
    note_block_progress(std::slice::from_mut(&mut s), 99);
    note_block_rx(std::slice::from_mut(&mut s), 99, 1);
    assert!(ibd_mono_ms() > 0);
}

#[test]
fn track_retain_judges_each_hash_once() {
    let mut slot = dummy_slot(3);
    let keep_hash = BlockHash::from_byte_array([1u8; 32]);
    let drop_hash = BlockHash::from_byte_array([2u8; 32]);
    slot.track_insert(keep_hash);
    slot.track_insert(drop_hash);
    let mut calls = 0usize;
    slot.track_retain(|hash| {
        calls += 1;
        *hash != drop_hash
    });
    assert_eq!(calls, 2, "one judgment per in-flight hash");
    assert!(slot.in_flight.contains(&keep_hash));
    assert!(!slot.in_flight.contains(&drop_hash));
    let requested = slot.requested.lock().unwrap().clone();
    assert_eq!(requested, slot.in_flight);
}

#[test]
fn unsolicited_block_does_not_refresh_progress() {
    let hash = BlockHash::from_byte_array([7u8; 32]);
    let requested = Mutex::new(HashSet::new());
    let bytes = AtomicU64::new(0);
    let ms = AtomicU64::new(0);
    assert!(
        !note_solicited_block(&requested, &bytes, &ms, &hash, 80),
        "an unsolicited block does not count"
    );
    assert_eq!(bytes.load(Ordering::Relaxed), 0);
    assert_eq!(ms.load(Ordering::Relaxed), 0);

    while ibd_mono_ms() == 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    requested.lock().unwrap().insert(hash);
    let len = rbitcoin_ibd::ibd::rate::PROGRESS_STEP as usize;
    assert!(
        note_solicited_block(&requested, &bytes, &ms, &hash, len),
        "a requested block records its bytes"
    );
    assert_eq!(bytes.load(Ordering::Relaxed), len as u64);
    let marked = ms.load(Ordering::Relaxed);
    assert!(marked > 0, "a requested block stamps the read time");

    let mut quiet = PeerRate::default();
    quiet.sample(0, 0, true);
    quiet.sample(10_000, 0, true);
    assert_eq!(
        quiet.progress_ms, 0,
        "zero solicited bytes over 10s leave the stall clock"
    );
    let mut moved = PeerRate::default();
    moved.sample(0, 0, true);
    moved.sample(1_000, bytes.load(Ordering::Relaxed), true);
    assert_eq!(moved.progress_ms, 1_000);

    let mut slot = dummy_slot(4);
    slot.in_flight.insert(hash);
    assert_eq!(slot.solicited_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(slot.solicited_ms.load(Ordering::Relaxed), 0);
    sample_peer_rates(std::slice::from_mut(&mut slot), 0);
    note_stream_bytes(&slot.bytes_rx_total, 8_000_000);
    sample_peer_rates(std::slice::from_mut(&mut slot), 10_000);
    assert_eq!(
        slot.rate.progress_ms, 0,
        "unsolicited stream bytes do not refresh progress"
    );

    slot.solicited_ms.store(marked, Ordering::Relaxed);
    sample_peer_rates(std::slice::from_mut(&mut slot), 0);
    assert_eq!(slot.rate.progress_ms, marked);
}

#[test]
fn socket_bytes_refresh_the_quiet_clock_only() {
    let mut slot = dummy_slot(4);
    let hash = BlockHash::from_byte_array([4u8; 32]);
    slot.in_flight.insert(hash);
    slot.rate.note_connected(0);
    while ibd_mono_ms() == 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let mut mark = 0usize;
    note_read_progress(&slot.bytes_rx_total, &slot.any_rx_ms, &mut mark, 32);
    sample_peer_rates(std::slice::from_mut(&mut slot), 5_000);
    assert!(slot.rate.any_rx_ms > 0);
    assert_eq!(slot.rate.progress_ms, 0);
    assert_eq!(slot.solicited_ms.load(Ordering::Relaxed), 0);
}

#[test]
fn on_wire_window_owns_stall_and_quiet() {
    let mut idle = dummy_slot(1);
    idle.rate.note_rx(0);
    idle.rate.note_any_rx(0);
    assert!(!getdata_on_wire_stalled(&idle, 100_000, 30_000));
    assert!(!getdata_on_wire_quiet(&idle, 100_000, 30_000));

    let mut asked = dummy_slot(2);
    asked
        .in_flight
        .insert(BlockHash::from_byte_array([9u8; 32]));
    asked.getdata_wire.queue(1);
    asked.getdata_wire.wrote(1, 0);
    asked.rate.note_rx(0);
    asked.rate.note_any_rx(0);
    assert!(!getdata_on_wire_stalled(&asked, 30_000, 30_000));
    assert!(!getdata_on_wire_quiet(&asked, 30_000, 30_000));
    assert!(getdata_on_wire_stalled(&asked, 30_001, 30_000));
    assert!(getdata_on_wire_quiet(&asked, 30_001, 30_000));
}

#[test]
fn light_decode_permit_does_not_wait() {
    let sem = Arc::new(Semaphore::new(1));
    let first = try_light_decode_permit(&sem);
    assert!(first.is_some(), "one permit is available immediately");
    assert!(
        try_light_decode_permit(&sem).is_none(),
        "a second permit does not wait"
    );
    drop(first);
    assert!(try_light_decode_permit(&sem).is_some());
}

#[test]
fn solicited_replay_does_not_refresh_progress() {
    let (req, bytes, ms) = solicit_track();
    let hash = BlockHash::from_byte_array([9u8; 32]);
    req.lock().unwrap().insert(hash);
    assert!(note_solicited_block(&req, &bytes, &ms, &hash, 100));
    let stamped = ms.load(Ordering::Relaxed);
    assert_eq!(bytes.load(Ordering::Relaxed), 100);
    assert!(!req.lock().unwrap().contains(&hash));
    assert!(
        !note_solicited_block(&req, &bytes, &ms, &hash, 50),
        "a resend of a solicited block is not another request"
    );
    assert_eq!(bytes.load(Ordering::Relaxed), 100);
    assert_eq!(ms.load(Ordering::Relaxed), stamped);
}

fn framed(command: [u8; 12], payload: Vec<u8>) -> FramedMessage {
    FramedMessage {
        magic: Magic::from(bitcoin::Network::Regtest),
        command,
        payload,
    }
}

fn test_ctx(
    permits: usize,
) -> (
    IbdReadCtx,
    mpsc::UnboundedReceiver<NetworkMessage>,
    mpsc::UnboundedReceiver<PeerEvent>,
    mpsc::UnboundedReceiver<PeerEvent>,
) {
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    let (body_tx, body_rx) = mpsc::unbounded_channel();
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
    let ctx = IbdReadCtx {
        id: 3,
        out_tx,
        sinks: PeerEventSinks {
            body: body_tx,
            ctrl: ctrl_tx,

            header_fks: empty_header_fk_bus(),
        },
        requested: Arc::new(Mutex::new(HashSet::new())),
        solicited_bytes: Arc::new(AtomicU64::new(0)),
        solicited_ms: Arc::new(AtomicU64::new(0)),
        light_decode: Arc::new(Semaphore::new(permits)),
        light: LightDecodes { tasks: Vec::new() },
        rate: PeerRateLimiter::default_limits(),
        logged_invalid_v2: false,
        ban_score: 0,
    };
    (ctx, out_rx, body_rx, ctrl_rx)
}

fn oversized_block() -> FramedMessage {
    let n = (rbitcoin_net::peer_dos::DEFAULT_MAX_BYTES_PER_SEC as usize) + 1;
    framed(*b"block\0\0\0\0\0\0\0", vec![0u8; n])
}

fn one_header() -> Header {
    use bitcoin::block::Version;
    use bitcoin::CompactTarget;
    Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 1,
    }
}

fn recv_body(rx: &mut mpsc::UnboundedReceiver<PeerEvent>) -> PeerEvent {
    rx.try_recv().expect("body event")
}

#[test]
fn read_progress_counts_the_delta_from_the_mark() {
    let bytes = AtomicU64::new(0);
    let mut mark = 0usize;
    let rx_ms = AtomicU64::new(0);
    // The process clock starts at 0. Wait so a stamp is distinguishable.
    std::thread::sleep(std::time::Duration::from_millis(2));
    note_read_progress(&bytes, &rx_ms, &mut mark, 10);
    note_read_progress(&bytes, &rx_ms, &mut mark, 25);
    assert_eq!(bytes.load(Ordering::Relaxed), 25);
    assert_eq!(mark, 25);
    assert!(rx_ms.load(Ordering::Relaxed) > 0);
    let stamped = rx_ms.load(Ordering::Relaxed);
    // The reader stores the latest buffered size, even when it shrinks.
    note_read_progress(&bytes, &rx_ms, &mut mark, 4);
    assert_eq!(bytes.load(Ordering::Relaxed), 25);
    assert_eq!(mark, 4);
    assert_eq!(rx_ms.load(Ordering::Relaxed), stamped);
}

#[test]
fn second_decoy_past_the_window_is_the_threshold() {
    let mut rate = PeerRateLimiter::default_limits();
    let mut score = 0u32;
    let n = (rbitcoin_net::peer_dos::DEFAULT_MAX_BYTES_PER_SEC as usize) + 1;
    assert!(decoy_hook(&mut rate, &mut score, n).is_ok());
    assert_eq!(score, RATE_LIMIT_BAN_SCORE);
    let err = decoy_hook(&mut rate, &mut score, n).unwrap_err();
    assert!(matches!(
        err,
        NetError::Protocol("peer misbehavior threshold")
    ));
}

#[test]
fn ping_and_solicited_block_stay_on_their_channels() {
    let (mut ctx, mut out_rx, mut body_rx, mut ctrl_rx) = test_ctx(1);
    let nonce = 0x0102_0304_0506_0708u64;
    assert!(!ctx.handle(Ok(framed(
        *b"ping\0\0\0\0\0\0\0\0",
        nonce.to_le_bytes().to_vec()
    ))));
    assert!(matches!(out_rx.try_recv(), Ok(NetworkMessage::Pong(n)) if n == nonce));
    assert!(!ctx.handle(Ok(framed(*b"ping\0\0\0\0\0\0\0\0", vec![1, 2, 3]))));
    assert!(out_rx.try_recv().is_err());

    let block = framed(*b"block\0\0\0\0\0\0\0", vec![7u8; 80]);
    let hash = block.block_hash_from_header().expect("80-byte header");
    ctx.requested.lock().unwrap().insert(hash);
    assert!(!ctx.handle(Ok(block)));
    match recv_body(&mut body_rx) {
        PeerEvent::BlockFramed {
            peer,
            hash: got,
            payload,

            header_fk: _,
        } => {
            assert_eq!(peer, 3);
            assert_eq!(got, hash);
            assert_eq!(payload.len(), 80);
        }
        _ => panic!("solicited block must be framed"),
    }
    assert_eq!(ctx.solicited_bytes.load(Ordering::Relaxed), 80);
    assert!(ctrl_rx.try_recv().is_err());

    let again = framed(*b"block\0\0\0\0\0\0\0", vec![7u8; 80]);
    assert!(!ctx.handle(Ok(again)), "one resend still fits the window");
    assert!(body_rx.try_recv().is_err(), "a resend is not a second body");
    assert_eq!(ctx.solicited_bytes.load(Ordering::Relaxed), 80);

    assert!(!ctx.handle(Ok(framed(*b"block\0\0\0\0\0\0\0", vec![1, 2, 3]))));
    assert!(body_rx.try_recv().is_err(), "a short block has no hash");
}

#[test]
fn second_unsolicited_block_past_the_window_stops_the_reader() {
    let (mut ctx, _out, mut body_rx, _ctrl) = test_ctx(1);
    assert!(!ctx.handle(Ok(oversized_block())));
    assert!(body_rx.try_recv().is_err(), "the first overflow stays");
    assert!(ctx.handle(Ok(oversized_block())));
    match recv_body(&mut body_rx) {
        PeerEvent::Dead { peer, reason } => {
            assert_eq!(peer, 3);
            assert_eq!(reason, "peer misbehavior threshold");
        }
        _ => panic!("second overflow must stop"),
    }
}

#[test]
fn light_permit_exhaustion_scores_like_other_frames() {
    let (mut ctx, _out, mut body_rx, _ctrl) = test_ctx(0);
    let n = (rbitcoin_net::peer_dos::DEFAULT_MAX_BYTES_PER_SEC as usize) + 1;
    let frame = framed(*b"inv\0\0\0\0\0\0\0\0\0", vec![0u8; n]);
    assert!(!ctx.handle(Ok(frame)));
    assert!(body_rx.try_recv().is_err());
    let frame = framed(*b"inv\0\0\0\0\0\0\0\0\0", vec![0u8; n]);
    assert!(ctx.handle(Ok(frame)));
    match recv_body(&mut body_rx) {
        PeerEvent::Dead { reason, .. } => assert_eq!(reason, "peer misbehavior threshold"),
        _ => panic!("a second permit miss past the window must stop"),
    }
}

#[test]
fn invalid_v2_and_io_errors_stop_on_the_shipped_reasons() {
    let (mut ctx, _out, mut body_rx, _ctrl) = test_ctx(1);
    let n = (rbitcoin_net::peer_dos::DEFAULT_MAX_BYTES_PER_SEC as usize) + 1;
    assert!(!ctx.handle(Err(NetError::InvalidV2Type { contents_len: n })));
    assert!(ctx.handle(Err(NetError::InvalidV2Type { contents_len: n })));
    match recv_body(&mut body_rx) {
        PeerEvent::Dead { reason, .. } => assert_eq!(reason, "peer misbehavior threshold"),
        _ => panic!("second invalid type must stop"),
    }

    let (mut ctx, _out, mut body_rx, _ctrl) = test_ctx(1);
    let eof = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed");
    assert!(ctx.handle(Err(NetError::Io(eof))));
    match recv_body(&mut body_rx) {
        PeerEvent::Dead { reason, .. } => assert!(reason.starts_with("eof:"), "{reason}"),
        _ => panic!("eof must be a dead peer"),
    }

    let (mut ctx, _out, mut body_rx, _ctrl) = test_ctx(1);
    let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
    assert!(ctx.handle(Err(NetError::Io(reset))));
    match recv_body(&mut body_rx) {
        PeerEvent::Dead { reason, .. } => assert!(reason.starts_with("eof:"), "{reason}"),
        _ => panic!("reset must be a dead peer"),
    }

    let (mut ctx, _out, mut body_rx, _ctrl) = test_ctx(1);
    assert!(ctx.handle(Err(NetError::Protocol("bye"))));
    match recv_body(&mut body_rx) {
        PeerEvent::Dead { reason, .. } => assert!(reason.contains("bye"), "{reason}"),
        _ => panic!("protocol error must be a dead peer"),
    }
}

#[test]
fn light_and_heavy_frames_deliver_or_die_without_stopping_the_read() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        use bitcoin::consensus::encode::Encodable;
        let (mut ctx, _out, mut body_rx, mut ctrl_rx) = test_ctx(2);
        let hash = BlockHash::from_byte_array([4u8; 32]);
        let inv = bitcoin::consensus::encode::serialize(&vec![Inventory::Block(hash)]);
        assert!(!ctx.handle(Ok(framed(*b"inv\0\0\0\0\0\0\0\0\0", inv))));
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), ctrl_rx.recv())
            .await
            .expect("light inv")
            .expect("ctrl open");
        match ev {
            PeerEvent::BlocksInv { peer, hashes } => {
                assert_eq!(peer, 3);
                assert_eq!(hashes, vec![hash]);
            }
            _ => panic!("block inv must reach ctrl"),
        }

        let mut over = Vec::new();
        bitcoin::consensus::encode::VarInt((rbitcoin_net::codec::MAX_INV_SIZE as u64) + 1)
            .consensus_encode(&mut over)
            .unwrap();
        assert!(!ctx.handle(Ok(framed(*b"inv\0\0\0\0\0\0\0\0\0", over))));
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), body_rx.recv())
            .await
            .expect("oversize inv")
            .expect("body open");
        match ev {
            PeerEvent::Dead { reason, .. } => {
                assert!(reason.contains("message too large"), "{reason}")
            }
            _ => panic!("oversize inv must die in the decoder"),
        }

        // Core's headers payload is count, then each 80-byte header and a 0 tx count.
        let mut headers = Vec::new();
        bitcoin::consensus::encode::VarInt(1)
            .consensus_encode(&mut headers)
            .unwrap();
        one_header().consensus_encode(&mut headers).unwrap();
        headers.push(0);
        let headers_frame = framed(*b"headers\0\0\0\0\0", headers);
        match headers_frame.clone().try_decode() {
            Ok(msg) => {
                assert!(matches!(msg.payload(), NetworkMessage::Headers(h) if h.len() == 1))
            }
            Err(e) => panic!("headers fixture must decode, got {e}"),
        }
        assert!(!ctx.handle(Ok(headers_frame)));
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), ctrl_rx.recv())
            .await
            .expect("headers")
            .expect("ctrl open");
        match ev {
            PeerEvent::Headers { headers, .. } => assert_eq!(headers.len(), 1),
            _ => panic!("headers must reach ctrl"),
        }

        let mut too_many = Vec::new();
        bitcoin::consensus::encode::VarInt((rbitcoin_net::codec::MAX_HEADERS_RESULTS as u64) + 1)
            .consensus_encode(&mut too_many)
            .unwrap();
        assert!(!ctx.handle(Ok(framed(*b"headers\0\0\0\0\0", too_many))));
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), body_rx.recv())
            .await
            .expect("oversize headers")
            .expect("body open");
        match ev {
            PeerEvent::Dead { reason, .. } => {
                assert!(reason.contains("message too large"), "{reason}")
            }
            _ => panic!("oversize headers must die in the decoder"),
        }
    });
}

fn sinks() -> (
    PeerEventSinks,
    mpsc::UnboundedReceiver<PeerEvent>,
    mpsc::UnboundedReceiver<PeerEvent>,
) {
    let (body_tx, body_rx) = mpsc::unbounded_channel();
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
    (
        PeerEventSinks {
            body: body_tx,
            ctrl: ctrl_tx,

            header_fks: empty_header_fk_bus(),
        },
        body_rx,
        ctrl_rx,
    )
}

fn apply(msg: NetworkMessage, sinks: &PeerEventSinks) {
    apply_decoded_message(
        3,
        sinks,
        bitcoin::p2p::message::RawNetworkMessage::new(Magic::from(bitcoin::Network::Regtest), msg),
    );
}

#[test]
fn decoded_messages_fan_out_blocks_and_addrs_only() {
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};

    let (sinks, mut body_rx, mut ctrl_rx) = sinks();
    apply(NetworkMessage::Headers(vec![one_header()]), &sinks);
    assert!(matches!(
        ctrl_rx.try_recv(),
        Ok(PeerEvent::Headers { headers, .. }) if headers.len() == 1
    ));
    apply(NetworkMessage::Headers(vec![]), &sinks);
    assert!(matches!(ctrl_rx.try_recv(), Ok(PeerEvent::Headers { .. })));

    apply(NetworkMessage::NotFound(vec![]), &sinks);
    apply(
        NetworkMessage::NotFound(vec![Inventory::Transaction(
            bitcoin::Txid::from_byte_array([3u8; 32]),
        )]),
        &sinks,
    );
    assert!(body_rx.try_recv().is_err());
    let block = BlockHash::from_byte_array([1u8; 32]);
    apply(
        NetworkMessage::NotFound(vec![Inventory::Block(block)]),
        &sinks,
    );
    assert!(matches!(
        body_rx.try_recv(),
        Ok(PeerEvent::NotFound { hashes, .. }) if hashes == vec![block]
    ));

    apply(NetworkMessage::Inv(vec![]), &sinks);
    assert!(ctrl_rx.try_recv().is_err());
    apply(NetworkMessage::Inv(vec![Inventory::Block(block)]), &sinks);
    assert!(matches!(
        ctrl_rx.try_recv(),
        Ok(PeerEvent::BlocksInv { hashes, .. }) if hashes == vec![block]
    ));

    let good = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
    let flags = ServiceFlags::NETWORK | ServiceFlags::P2P_V2;
    apply(NetworkMessage::Addr(vec![]), &sinks);
    assert!(ctrl_rx.try_recv().is_err());
    apply(
        NetworkMessage::Addr(vec![(1, Address::new(&good, flags))]),
        &sinks,
    );
    assert!(matches!(ctrl_rx.try_recv(), Ok(PeerEvent::Addrs { .. })));

    apply(NetworkMessage::AddrV2(vec![]), &sinks);
    assert!(ctrl_rx.try_recv().is_err());
    apply(
        NetworkMessage::AddrV2(vec![AddrV2Message {
            time: 1,
            services: flags,
            addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)),
            port: 8333,
        }]),
        &sinks,
    );
    assert!(matches!(ctrl_rx.try_recv(), Ok(PeerEvent::Addrs { .. })));

    apply(NetworkMessage::SendAddrV2, &sinks);
    apply(
        NetworkMessage::Block(bitcoin::Block {
            header: one_header(),
            txdata: vec![],
        }),
        &sinks,
    );
    apply(NetworkMessage::Verack, &sinks);
    assert!(body_rx.try_recv().is_err());
    assert!(ctrl_rx.try_recv().is_err());
}

#[test]
fn block_inventory_hashes_keeps_blocks_only() {
    let block = BlockHash::from_byte_array([1u8; 32]);
    let witness = BlockHash::from_byte_array([2u8; 32]);
    let tx = bitcoin::Txid::from_byte_array([3u8; 32]);
    let inv = vec![
        Inventory::Transaction(tx),
        Inventory::Block(block),
        Inventory::WitnessBlock(witness),
    ];
    assert_eq!(block_inventory_hashes(&inv), vec![block, witness]);
}

#[test]
fn event_sinks_send_body_and_ctrl() {
    let (body_tx, mut body_rx) = mpsc::unbounded_channel();
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel();
    let sinks = PeerEventSinks {
        body: body_tx,
        ctrl: ctrl_tx,

        header_fks: empty_header_fk_bus(),
    };
    sinks.send_body(PeerEvent::Dead {
        peer: 1,
        reason: "x".into(),
    });
    sinks.send_ctrl(PeerEvent::Headers {
        peer: 1,
        headers: vec![],
    });
    assert!(matches!(
        body_rx.try_recv().unwrap(),
        PeerEvent::Dead { .. }
    ));
    assert!(matches!(
        ctrl_rx.try_recv().unwrap(),
        PeerEvent::Headers { .. }
    ));
}

#[test]
fn socket_addrs_from_addr_and_addrv2_filter() {
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
    use bitcoin::p2p::ServiceFlags;

    let v2_net = ServiceFlags::NETWORK | ServiceFlags::P2P_V2;
    let v2_limited = ServiceFlags::NETWORK_LIMITED | ServiceFlags::P2P_V2;
    let good = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
    let limited_sa = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 8333);
    let no_svc = Address::new(&good, ServiceFlags::NONE);
    let net_only = Address::new(&good, ServiceFlags::NETWORK);
    let net_v2 = Address::new(&good, v2_net);
    let limited_only = Address::new(&limited_sa, ServiceFlags::NETWORK_LIMITED);
    let limited_v2 = Address::new(&limited_sa, v2_limited);
    let unusable = Address::new(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8333),
        v2_net,
    );
    let out = socket_addrs_from_addr(&[
        (1, no_svc),
        (2, net_only),
        (3, net_v2),
        (4, limited_only),
        (5, limited_v2),
        (6, unusable),
    ]);
    assert_eq!(out, vec![good, limited_sa]);

    let v2_good = AddrV2Message {
        time: 1,
        services: v2_net,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)),
        port: 18444,
    };
    let v2_net_only = AddrV2Message {
        time: 1,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 8)),
        port: 18444,
    };
    let v2_bad_svc = AddrV2Message {
        time: 1,
        services: ServiceFlags::NONE,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 10)),
        port: 18444,
    };
    let v2_zero_port = AddrV2Message {
        time: 1,
        services: v2_net,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 11)),
        port: 0,
    };
    let out2 = net_addrs_from_addrv2(&[v2_good, v2_net_only, v2_bad_svc, v2_zero_port]);
    assert_eq!(
        out2,
        vec![rbitcoin_net::NetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            18444
        ))]
    );

    let v6_multi = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)), 8333);
    assert!(!usable_dial_addr(&v6_multi));
    let v6_net = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333);
    let v2_v6 = AddrV2Message {
        time: 1,
        services: v2_limited,
        addr: AddrV2::Ipv6(Ipv6Addr::LOCALHOST),
        port: 8333,
    };
    let out3 = net_addrs_from_addrv2(&[v2_v6]);
    assert_eq!(out3, vec![rbitcoin_net::NetAddr::Ip(v6_net)]);

    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let rbitcoin_net::NetAddr::Onion { pk, port } = onion else {
        panic!("fixture");
    };
    let v2_onion = AddrV2Message {
        time: 1,
        services: v2_net,
        addr: AddrV2::TorV3(pk),
        port,
    };
    let nets = net_addrs_from_addrv2(&[v2_onion]);
    assert_eq!(nets, vec![onion]);
}

/// Legacy `addr` has no BIP155 network id. `fc00::/8` is CJDNS, not a
/// clearnet socket the dial book can fill.
#[test]
fn v1_addr_fc00_is_cjdns_not_clearnet() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::ServiceFlags;

    let fc_ip = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);
    let fc = SocketAddr::new(IpAddr::V6(fc_ip), 8333);
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
    let flags = ServiceFlags::NETWORK | ServiceFlags::P2P_V2;
    let rows = net_addrs_from_addr(&[(1, Address::new(&fc, flags)), (2, Address::new(&v4, flags))]);
    assert!(
        rows.iter()
            .any(|a| matches!(a, rbitcoin_net::NetAddr::Cjdns { ip, port: 8333 } if *ip == fc_ip)),
        "fc00 must be CJDNS, got {rows:?}"
    );
    assert!(rows
        .iter()
        .any(|a| matches!(a, rbitcoin_net::NetAddr::Ip(s) if *s == v4)));
    assert!(
        !rows
            .iter()
            .any(|a| matches!(a, rbitcoin_net::NetAddr::Ip(s) if s.ip() == IpAddr::V6(fc_ip))),
        "fc00 must not stay a clearnet Ip"
    );

    let local = SocketAddr::from(([127, 0, 0, 1], 18444));
    let mut off = rbitcoin_net::seeds::AddrMan::new();
    rbitcoin_ibd::ibd::events::inject_learned_addrs(&mut off, &rows, local, 1);
    assert!(
        off.entries()
            .iter()
            .all(|e| !matches!(e.addr, rbitcoin_net::NetAddr::Cjdns { .. })),
        "CJDNS stays out of the book until the overlay is reachable: {:?}",
        off.entries()
    );
    assert!(off
        .entries()
        .iter()
        .any(|e| e.addr == rbitcoin_net::NetAddr::Ip(v4)));

    let mut on = rbitcoin_net::seeds::AddrMan::new();
    on.set_cjdns_reachable(true);
    rbitcoin_ibd::ibd::events::inject_learned_addrs(&mut on, &rows, local, 1);
    assert!(
        on.entries().iter().any(|e| matches!(
            e.addr,
            rbitcoin_net::NetAddr::Cjdns { ip, port: 8333 } if ip == fc_ip
        )),
        "reachable CJDNS is learned as CJDNS: {:?}",
        on.entries()
    );
}
