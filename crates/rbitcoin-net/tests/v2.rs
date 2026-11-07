use bip324::futures::Protocol;
use bip324::io::Payload;
use bip324::{PacketType, Role};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::Network;
use rbitcoin_net::error::NetError;
use rbitcoin_net::v2::*;
use tokio::io::duplex;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncReadExt, BufReader};

fn signet_magic() -> Magic {
    Magic::from(Network::Signet)
}

#[test]
fn short_id_roundtrip_common() {
    assert_eq!(short_id_for_command("block"), Some(2));
    assert_eq!(short_id_for_command("ping"), Some(18));
    assert_eq!(short_id_for_command("version"), None); // long form
    assert_eq!(command_for_short_id(2), Some("block"));
    assert_eq!(command_for_short_id(18), Some("ping"));
}

/// Live IBD + tip-follow + tip-tx command set must map to Core BIP324 short IDs.
#[test]
fn short_ids_cover_live_ibd_tip_commands() {
    let live = [
        ("addr", 1u8),
        ("block", 2),
        ("blocktxn", 3),
        ("cmpctblock", 4),
        ("feefilter", 5),
        ("getblocks", 9),
        ("getblocktxn", 10),
        ("getdata", 11),
        ("getheaders", 12),
        ("headers", 13),
        ("inv", 14),
        ("mempool", 15),
        ("notfound", 17),
        ("ping", 18),
        ("pong", 19),
        ("sendcmpct", 20),
        ("tx", 21),
        ("addrv2", 28),
    ];
    for (cmd, id) in live {
        assert_eq!(short_id_for_command(cmd), Some(id), "short id for {cmd}");
        assert_eq!(command_for_short_id(id), Some(cmd));
    }
    // Application handshake uses long form (not short-id).
    assert!(short_id_for_command("version").is_none());
    assert!(short_id_for_command("verack").is_none());
    assert_eq!(
        v2_invalid_message_type_log(),
        "p2p: v2 peer sent a message type we do not know"
    );
    assert_eq!(MAX_V2_CONTENTS_LEN, 4_000_013);
    assert_eq!(
        v2_packet_too_large_log(4_000_014),
        "p2p: v2 packet is longer than the cap (4000014 bytes)"
    );
    assert_eq!(V2_CIPHER_EXPANSION, 20);
    assert_eq!(v2_other_recv_bytes(3), 23);
    assert!(short_id_for_command("wtxidrelay").is_none());
    assert!(short_id_for_command("sendheaders").is_none());
    assert!(short_id_for_command("sendaddrv2").is_none());
    assert_eq!(
        v2_handshake_timeout_log(0),
        "p2p: v2 handshake timed out, disconnecting peer=0"
    );
    assert_eq!(
        v2_missing_garbage_terminator_log(),
        "p2p: v2 handshake had no garbage terminator"
    );
    assert_eq!(
        v2_packet_decryption_failure_log(),
        "p2p: v2 packet did not decrypt"
    );
    // Placeholder slots 29–36 stay empty (unknown short id → protocol error).
    for id in 29u8..=36 {
        assert!(command_for_short_id(id).is_none(), "slot {id} empty");
    }
    assert_eq!(command_for_short_id(37), Some("feature"));
}

#[test]
fn encode_parse_live_short_id_messages() {
    let magic = signet_magic();
    for payload in [
        NetworkMessage::Ping(1),
        NetworkMessage::Pong(1),
        NetworkMessage::MemPool,
        NetworkMessage::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct {
            send_compact: true,
            version: 2,
        }),
    ] {
        let contents = encode_v2_contents(payload.clone()).unwrap();
        assert_ne!(contents[0], 0, "expected short id for {:?}", payload.cmd());
        let frame = parse_v2_contents(magic, &contents).unwrap();
        assert_eq!(frame.decode().payload().cmd(), payload.cmd());
    }
}

#[test]
fn parse_v2_regtest_named_junk_does_not_panic() {
    for cmd in ["addrv2", "inv", "getdata"] {
        let _ = parse_v2_regtest_named(cmd, &[]);
        let _ = parse_v2_regtest_named(cmd, &[0xff; 64]);
        let _ = parse_v2_regtest_named(cmd, &[0x00, 0x01, 0x02]);
    }
}

#[test]
fn encode_parse_verack_long_form() {
    let magic = signet_magic();
    let contents = encode_v2_contents(NetworkMessage::Verack).unwrap();
    assert_eq!(contents[0], 0);
    assert_eq!(&contents[1..7], b"verack");
    let frame = parse_v2_contents(magic, &contents).unwrap();
    assert!(matches!(frame.decode().payload(), NetworkMessage::Verack));
}

/// Regression: `sendaddrv2` contains a digit — long-form parse must accept it
/// (Core IsCommandValid allows printable ASCII). Rejecting digits killed
/// post-handshake IBD peers that advertise BIP155.
#[test]
fn encode_parse_sendaddrv2_long_form_with_digit() {
    let magic = signet_magic();
    let contents = encode_v2_contents(NetworkMessage::SendAddrV2).unwrap();
    assert_eq!(contents[0], 0); // long form
    assert_eq!(&contents[1..11], b"sendaddrv2");
    let frame = parse_v2_contents(magic, &contents).expect("digit in command ok");
    assert!(matches!(
        frame.decode().payload(),
        NetworkMessage::SendAddrV2
    ));
}

/// `test_msgtype`: unknown short id logs and is not a hard disconnect.
#[test]
fn unknown_short_id_is_invalid_type_not_protocol() {
    let magic = signet_magic();
    // short id 99 + compact-size string "d" (Core `msg_unrecognized`).
    let contents = vec![99u8, 1, b'd'];
    match parse_v2_contents(magic, &contents) {
        Err(NetError::InvalidV2Type { contents_len }) => {
            assert_eq!(contents_len, 3);
            assert_eq!(v2_other_recv_bytes(contents_len), 23);
        }
        other => panic!("expected InvalidV2Type, got {other:?}"),
    }
}

#[test]
fn encode_parse_ping_short_id() {
    let magic = signet_magic();
    let contents = encode_v2_contents(NetworkMessage::Ping(0xdead_beef)).unwrap();
    assert_eq!(contents[0], 18); // ping short id
    assert_eq!(contents.len(), 1 + 8);
    let frame = parse_v2_contents(magic, &contents).unwrap();
    assert!(frame.is_ping());
    assert_eq!(frame.ping_nonce(), Some(0xdead_beef));
}

/// v2 has no checksum; decode must not require sha256d of the payload.
#[test]
fn parse_v2_block_zero_checksum_decodes() {
    use bitcoin::blockdata::constants::genesis_block;
    let magic = Magic::from(Network::Bitcoin);
    let genesis = genesis_block(Network::Bitcoin);
    let want = genesis.block_hash();
    let contents = encode_v2_contents(NetworkMessage::Block(genesis)).unwrap();
    let frame = parse_v2_contents(magic, &contents).unwrap();
    match frame.decode().payload() {
        NetworkMessage::Block(b) => assert_eq!(b.block_hash(), want),
        other => panic!("expected block, got {other:?}"),
    }
}

/// Two ends of a tokio duplex complete BIP324 + application ping/pong.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bip324_duplex_ping_pong() {
    let magic = signet_magic();
    let magic_b = magic.to_bytes();
    let (client, server) = duplex(64 * 1024);

    let server_task = tokio::spawn(async move {
        let (rh, wh) = tokio::io::split(server);
        let reader = BufReader::new(rh);
        let protocol = Protocol::new(magic_b, Role::Responder, None, None, reader, wh)
            .await
            .expect("server handshake");
        let (mut r, mut w) = protocol.into_split();
        loop {
            let p = r.read().await.expect("server read");
            if p.packet_type() == PacketType::Genuine {
                let frame = parse_v2_contents(magic, p.contents()).unwrap();
                assert!(frame.is_ping());
                let n = frame.ping_nonce().unwrap();
                let contents = encode_v2_contents(NetworkMessage::Pong(n)).unwrap();
                w.write(&Payload::genuine(contents)).await.unwrap();
                break;
            }
        }
    });

    let client_task = async move {
        let (rh, wh) = tokio::io::split(client);
        let reader = BufReader::new(rh);
        let protocol = Protocol::new(magic_b, Role::Initiator, None, None, reader, wh)
            .await
            .expect("client handshake");
        let (r, mut w) = protocol.into_split();
        let contents = encode_v2_contents(NetworkMessage::Ping(42)).unwrap();
        write_v2_contents(&mut w, contents).await.unwrap();
        let mut reader = V2SessionReader::from_protocol_reader(r);
        let got = read_v2_contents(&mut reader).await.unwrap();
        let frame = parse_v2_contents(magic, &got).unwrap();
        assert!(matches!(frame.decode().payload(), NetworkMessage::Pong(42)));
        server_task.await.unwrap();
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), client_task)
        .await
        .expect("bip324 duplex timed out");
}

/// IBD readers keep one 4 MiB ciphertext buffer and decrypt into a payload-sized
/// vec. Tip-follow readers leave that buffer off and still return a small payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_reader_reuses_one_ciphertext_buffer() {
    let magic = signet_magic();
    let magic_b = magic.to_bytes();
    let (client, server) = duplex(64 * 1024);

    let server_task = tokio::spawn(async move {
        let (rh, wh) = tokio::io::split(server);
        let reader = BufReader::new(rh);
        let protocol = Protocol::new(magic_b, Role::Responder, None, None, reader, wh)
            .await
            .expect("server handshake");
        let (_r, mut w) = protocol.into_split();
        for n in [1u64, 2, 3] {
            let contents = encode_v2_contents(NetworkMessage::Pong(n)).unwrap();
            w.write(&Payload::genuine(contents)).await.unwrap();
        }
    });

    let client_task = async move {
        let (rh, wh) = tokio::io::split(client);
        let reader = BufReader::new(rh);
        let protocol = Protocol::new(magic_b, Role::Initiator, None, None, reader, wh)
            .await
            .expect("client handshake");
        let (r, _w) = protocol.into_split();
        let mut reader = V2SessionReader::from_protocol_reader(r);
        assert!(reader.ibd_ciphertext_buf().is_none());

        let first = read_v2_frame(&mut reader, magic).await.unwrap();
        assert!(
            first.payload.capacity() < 64,
            "tip payload cap {}",
            first.payload.capacity()
        );
        assert!(matches!(first.decode().payload(), NetworkMessage::Pong(1)));
        assert!(reader.ibd_ciphertext_buf().is_none());

        reader.enable_ibd_ciphertext_buf();
        let ptr = reader.ibd_ciphertext_buf().expect("scratch").as_ptr();
        assert_eq!(
            reader.ibd_ciphertext_buf().unwrap().len(),
            IBD_CIPHERTEXT_BUF_LEN
        );
        for n in [2u64, 3] {
            let frame = read_v2_frame(&mut reader, magic).await.unwrap();
            assert!(
                frame.payload.capacity() < 64,
                "ibd payload cap {}",
                frame.payload.capacity()
            );
            assert!(matches!(frame.decode().payload(), NetworkMessage::Pong(got) if *got == n));
            let buf = reader.ibd_ciphertext_buf().unwrap();
            assert_eq!(buf.len(), IBD_CIPHERTEXT_BUF_LEN);
            assert_eq!(buf.as_ptr(), ptr);
            // Pong packet: 1 header, 1 short id, 8 nonce, 16 tag.
            assert!(
                buf[..26].iter().any(|&b| b != 0),
                "scratch must hold this packet's ciphertext"
            );
        }
        server_task.await.unwrap();
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), client_task)
        .await
        .expect("ibd ciphertext scratch timed out");
}

/// V1-looking ellswift slot (network magic in first 4 of 64 bytes) → V1Peer.
///
/// bip324 detects this only after a full 64-byte key read — sending fewer
/// bytes would hang on `read_exact`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v1_peer_rejected() {
    let magic = signet_magic();
    let (mut client, server) = duplex(8 * 1024);

    let server_task = tokio::spawn(async move {
        let (rh, wh) = tokio::io::split(server);
        let reader = BufReader::new(rh);
        Protocol::new(magic.to_bytes(), Role::Responder, None, None, reader, wh).await
    });

    // Drain responder's ellswift key first so its write does not block.
    let mut their_key = [0u8; 64];
    client.read_exact(&mut their_key).await.unwrap();

    // Fake "key" whose first 4 bytes are network magic (Core/bip324 V1 probe).
    let mut v1_key = [0u8; 64];
    v1_key[..4].copy_from_slice(&magic.to_bytes());
    client.write_all(&v1_key).await.unwrap();
    client.flush().await.unwrap();

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("v1 detect timed out")
        .expect("server task join");
    let err = match result {
        Ok(_) => panic!("v1-looking peer must fail BIP324 handshake"),
        Err(e) => e,
    };
    let mapped = map_protocol_error(err);
    assert!(
        matches!(mapped, NetError::V1Peer),
        "expected V1Peer, got {mapped}"
    );
}

/// `p2p_v2_misbehaving.py` EARLY_KEY_RESPONSE: inbound responder must not
/// send ellswift while the first inbound bytes still match v1 prefix
/// (network magic + `"version\x00\x00\x00\x00\x00"`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_holds_ellswift_until_v1_prefix_mismatch() {
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{timeout, Duration};

    let magic = Magic::from(Network::Regtest);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        open_v2(stream, magic, true).await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&magic.to_bytes()).await.unwrap();
    client.flush().await.unwrap();

    let mut probe = [0u8; 8];
    let early = timeout(Duration::from_millis(250), client.read(&mut probe)).await;
    assert!(
        early.is_err(),
        "responder must not send ellswift while inbound still matches v1 magic"
    );

    client.write_all(&[0xff]).await.unwrap();
    client.flush().await.unwrap();
    let mut key = [0u8; 64];
    timeout(Duration::from_secs(2), client.read_exact(&mut key))
        .await
        .expect("ellswift after v1-prefix mismatch")
        .unwrap();
    server.abort();
}

/// A BIP324 peer on the far end of `stream` runs its half of the handshake
/// and returns how many garbage bytes our node sent before its terminator.
/// The node's version packet must then authenticate with that garbage as AAD.
async fn garbage_read_by_v2_peer(
    stream: &mut tokio::net::TcpStream,
    role: Role,
    magic: Magic,
) -> usize {
    use bip324::{GarbageResult, Handshake, Initialized, ReceivedKey, VersionResult};

    let mut key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let peer = Handshake::<Initialized>::new(magic.to_bytes(), role)
        .unwrap()
        .send_key(None, &mut key)
        .unwrap();
    stream.write_all(&key).await.unwrap();
    let mut node_key = [0u8; 64];
    stream.read_exact(&mut node_key).await.unwrap();
    let mut version = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let mut peer = peer
        .receive_key(node_key)
        .unwrap()
        .send_version(&mut version, None)
        .unwrap();
    stream.write_all(&version).await.unwrap();

    let mut received = Vec::new();
    loop {
        let mut chunk = [0u8; 512];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "node closed before its garbage terminator");
        received.extend_from_slice(&chunk[..n]);
        match peer.receive_garbage(&received).unwrap() {
            GarbageResult::NeedMoreData(waiting) => peer = waiting,
            GarbageResult::FoundGarbage {
                mut handshake,
                consumed_bytes,
            } => {
                let mut packet = received[consumed_bytes..].to_vec();
                let mut len = [0u8; 3];
                while packet.len() < len.len() {
                    let n = stream.read(&mut chunk).await.unwrap();
                    packet.extend_from_slice(&chunk[..n]);
                }
                len.copy_from_slice(&packet[..3]);
                let body_len = handshake.decrypt_packet_len(len).unwrap();
                while packet.len() < 3 + body_len {
                    let n = stream.read(&mut chunk).await.unwrap();
                    packet.extend_from_slice(&chunk[..n]);
                }
                assert!(matches!(
                    handshake.receive_version(&mut packet[3..3 + body_len]),
                    Ok(VersionResult::Complete { .. })
                ));
                return consumed_bytes - 16;
            }
        }
    }
}

fn assert_garbage_lengths_vary(direction: &str, mut samples: Vec<usize>) {
    assert!(
        samples.iter().all(|&n| n <= 4095),
        "{direction} garbage lengths {samples:?}"
    );
    samples.sort_unstable();
    samples.dedup();
    assert!(
        samples.len() > 1,
        "{direction} sent one garbage length: {samples:?}"
    );
}

/// Core `GenerateRandomGarbage`: each side sends 0..=4095 random garbage
/// bytes after its ellswift key, so a v2 handshake has no fixed length. A v2
/// peer reads that garbage from us whether we dial out or it dials in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_peer_reads_random_length_garbage_from_us() {
    use tokio::net::{TcpListener, TcpStream};

    let magic = Magic::from(Network::Regtest);
    let mut outbound = Vec::new();
    let mut inbound = Vec::new();
    for _ in 0..4 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dial_out = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            open_v2(stream, magic, false).await.map(|_| ())
        });
        let (mut peer, _) = listener.accept().await.unwrap();
        outbound.push(garbage_read_by_v2_peer(&mut peer, Role::Responder, magic).await);
        dial_out.await.unwrap().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dial_in = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            open_v2(stream, magic, true).await.map(|_| ())
        });
        let mut peer = TcpStream::connect(addr).await.unwrap();
        inbound.push(garbage_read_by_v2_peer(&mut peer, Role::Initiator, magic).await);
        dial_in.await.unwrap().unwrap();
    }
    assert_garbage_lengths_vary("outbound", outbound);
    assert_garbage_lengths_vary("inbound", inbound);
}

/// Core `test_size`: reject on the decrypted length prefix — do not wait
/// for the 4 MiB ciphertext. Only the 3-byte length is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_v2_length_prefix_rejects_before_body() {
    use bip324::OutboundCipher;
    use tokio::io::AsyncWriteExt;

    let magic = signet_magic();
    let magic_b = magic.to_bytes();
    let (client, server) = duplex(8 * 1024);

    let server_task = tokio::spawn(async move {
        let (rh, wh) = tokio::io::split(server);
        let reader = BufReader::new(rh);
        let protocol = Protocol::new(magic_b, Role::Responder, None, None, reader, wh)
            .await
            .expect("server handshake");
        let (r, _w) = protocol.into_split();
        let mut reader = V2SessionReader::from_protocol_reader(r);
        read_v2_frame(&mut reader, magic).await
    });

    let (rh, wh) = tokio::io::split(client);
    let reader = BufReader::new(rh);
    let protocol = Protocol::new(magic_b, Role::Initiator, None, None, reader, wh)
        .await
        .expect("client handshake");
    let (_r, w) = protocol.into_split();
    let (mut cipher, mut raw_w) = w.into_inner();
    let too_big = MAX_V2_CONTENTS_LEN + 1;
    let mut packet = vec![0u8; OutboundCipher::encryption_buffer_len(too_big)];
    let plaintext = vec![0u8; too_big];
    cipher
        .encrypt(&plaintext, &mut packet, PacketType::Genuine, None)
        .expect("encrypt oversized length");
    raw_w.write_all(&packet[..3]).await.unwrap();
    raw_w.flush().await.unwrap();

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("oversize detect timed out")
        .expect("server task join");
    match result {
        Err(NetError::MessageTooLarge(n)) => assert_eq!(n, too_big),
        other => panic!("expected MessageTooLarge({too_big}), got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decoy_packet_is_handed_to_the_rate_hook() {
    use bip324::OutboundCipher;
    use tokio::io::AsyncWriteExt;

    let magic = signet_magic();
    let magic_b = magic.to_bytes();
    let (client, server) = duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let (rh, wh) = tokio::io::split(server);
        let reader = BufReader::new(rh);
        let protocol = Protocol::new(magic_b, Role::Responder, None, None, reader, wh)
            .await
            .expect("server handshake");
        let (r, _w) = protocol.into_split();
        let mut reader = V2SessionReader::from_protocol_reader(r);
        let mut seen = Vec::new();
        let frame = read_v2_frame_with_progress(
            &mut reader,
            magic,
            |_| {},
            |n| {
                seen.push(n);
                Ok(())
            },
        )
        .await
        .expect("genuine frame after decoy");
        (seen, frame.is_ping())
    });

    let (rh, wh) = tokio::io::split(client);
    let reader = BufReader::new(rh);
    let protocol = Protocol::new(magic_b, Role::Initiator, None, None, reader, wh)
        .await
        .expect("client handshake");
    let (_r, w) = protocol.into_split();
    let (mut cipher, mut raw_w) = w.into_inner();
    let decoy_plain = vec![0u8; 32];
    let mut packet = vec![0u8; OutboundCipher::encryption_buffer_len(decoy_plain.len())];
    cipher
        .encrypt(&decoy_plain, &mut packet, PacketType::Decoy, None)
        .expect("encrypt decoy");
    raw_w.write_all(&packet).await.unwrap();
    let ping = encode_v2_contents(NetworkMessage::Ping(7)).unwrap();
    let mut packet = vec![0u8; OutboundCipher::encryption_buffer_len(ping.len())];
    cipher
        .encrypt(&ping, &mut packet, PacketType::Genuine, None)
        .expect("encrypt ping");
    raw_w.write_all(&packet).await.unwrap();
    raw_w.flush().await.unwrap();

    let (seen, is_ping) = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("decoy read timed out")
        .expect("server task join");
    assert!(!seen.is_empty(), "a decoy must reach the rate hook");
    assert!(is_ping, "the genuine packet after the decoy is the ping");
}

/// Tip-follow and the IBD reader both call [`rbitcoin_net::peer_dos::decoy_stays`].
/// One decoy that does not fit scores and the following frame is still read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decoy_over_the_window_scores_like_other_frames() {
    use bip324::OutboundCipher;
    use rbitcoin_net::peer::BAN_SCORE_THRESHOLD;
    use rbitcoin_net::peer_dos::{decoy_stays, PeerRateLimiter, RATE_LIMIT_BAN_SCORE};
    use tokio::io::AsyncWriteExt;

    let magic = signet_magic();
    let magic_b = magic.to_bytes();
    let (client, server) = duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let (rh, wh) = tokio::io::split(server);
        let reader = BufReader::new(rh);
        let protocol = Protocol::new(magic_b, Role::Responder, None, None, reader, wh)
            .await
            .expect("server handshake");
        let (r, _w) = protocol.into_split();
        let mut reader = V2SessionReader::from_protocol_reader(r);
        let mut rate = PeerRateLimiter::new(1, 10_000);
        let mut score = 0u32;
        assert!(rate.note(1), "the window is already full");
        let frame = read_v2_frame_with_progress(
            &mut reader,
            magic,
            |_| {},
            |n| {
                if decoy_stays(&mut rate, &mut score, n, BAN_SCORE_THRESHOLD) {
                    Ok(())
                } else {
                    Err(NetError::Protocol("peer misbehavior threshold"))
                }
            },
        )
        .await
        .expect("one decoy over the window must not abort the read");
        (score, frame.is_ping())
    });

    let (rh, wh) = tokio::io::split(client);
    let reader = BufReader::new(rh);
    let protocol = Protocol::new(magic_b, Role::Initiator, None, None, reader, wh)
        .await
        .expect("client handshake");
    let (_r, w) = protocol.into_split();
    let (mut cipher, mut raw_w) = w.into_inner();
    let decoy_plain = vec![0u8; 32];
    let mut packet = vec![0u8; OutboundCipher::encryption_buffer_len(decoy_plain.len())];
    cipher
        .encrypt(&decoy_plain, &mut packet, PacketType::Decoy, None)
        .expect("encrypt decoy");
    raw_w.write_all(&packet).await.unwrap();
    let ping = encode_v2_contents(NetworkMessage::Ping(7)).unwrap();
    let mut packet = vec![0u8; OutboundCipher::encryption_buffer_len(ping.len())];
    cipher
        .encrypt(&ping, &mut packet, PacketType::Genuine, None)
        .expect("encrypt ping");
    raw_w.write_all(&packet).await.unwrap();
    raw_w.flush().await.unwrap();

    let (score, is_ping) = tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("decoy overflow read timed out")
        .expect("server task join");
    assert_eq!(score, RATE_LIMIT_BAN_SCORE);
    assert!(
        is_ping,
        "the genuine packet after the over-window decoy is the ping"
    );
}

#[test]
fn truncated_v2_long_command_is_protocol() {
    assert!(matches!(
        parse_v2_contents(signet_magic(), &[0u8, b'v', b'e']),
        Err(NetError::Protocol("truncated v2 long command"))
    ));
}

fn v2_fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn v2_ping_fixture_matches_encode() {
    let expected = encode_v2_contents(NetworkMessage::Ping(0xdead_beef)).unwrap();
    let path = v2_fixture_path("v2_ping.bin");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(raw, expected);
    parse_v2_regtest(&raw).unwrap();
}

#[test]
fn v2_verack_fixture_matches_encode() {
    let expected = encode_v2_contents(NetworkMessage::Verack).unwrap();
    let path = v2_fixture_path("v2_verack.bin");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(raw, expected);
    parse_v2_regtest(&raw).unwrap();
}

#[test]
fn v2_sendaddrv2_fixture_matches_encode() {
    let expected = encode_v2_contents(NetworkMessage::SendAddrV2).unwrap();
    let path = v2_fixture_path("v2_sendaddrv2.bin");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(raw, expected);
    parse_v2_regtest(&raw).unwrap();
}

#[test]
fn v2_sendcmpct_fixture_matches_encode() {
    let expected = encode_v2_contents(NetworkMessage::SendCmpct(
        bitcoin::p2p::message_compact_blocks::SendCmpct {
            send_compact: true,
            version: 2,
        },
    ))
    .unwrap();
    let path = v2_fixture_path("v2_sendcmpct.bin");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(raw, expected);
    parse_v2_regtest(&raw).unwrap();
}

#[test]
fn v2_getheaders_fixture_matches_encode() {
    use bitcoin::hashes::Hash;
    let expected = encode_v2_contents(NetworkMessage::GetHeaders(
        bitcoin::p2p::message_blockdata::GetHeadersMessage::new(
            Vec::new(),
            bitcoin::BlockHash::from_byte_array([0; 32]),
        ),
    ))
    .unwrap();
    let path = v2_fixture_path("v2_getheaders.bin");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(raw, expected);
    parse_v2_regtest(&raw).unwrap();
}

#[test]
fn addrv2_empty_and_inv_one_seeds_parse() {
    let addr = v2_fixture_path("addrv2_empty.bin");
    let inv = v2_fixture_path("inv_one.bin");
    let a = std::fs::read(&addr).unwrap_or_else(|e| panic!("read {}: {e}", addr.display()));
    let i = std::fs::read(&inv).unwrap_or_else(|e| panic!("read {}: {e}", inv.display()));
    assert_eq!(a, [0u8]);
    parse_v2_regtest_named("addrv2", &a).unwrap();
    parse_v2_regtest_named("inv", &i).unwrap();
    parse_v2_regtest_named("getdata", &i).unwrap();
}

#[test]
fn parse_v2_regtest_rejects_empty_and_unknown_short_id() {
    assert!(parse_v2_regtest(&[]).is_err());
    assert!(parse_v2_regtest(&[99u8, 1, b'd']).is_err());
}

/// Park every `rbtc-scripts-*` worker inside a detached job.
struct ScriptHold {
    gate: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl ScriptHold {
    fn all() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::{Duration, Instant};
        let n = rbitcoin_consensus::script_pool::worker_spawn_count();
        assert!(n >= 1, "script pool did not start");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let entered = Arc::new(AtomicUsize::new(0));
        for _ in 0..n {
            let entered = Arc::clone(&entered);
            let gate = Arc::clone(&gate);
            rbitcoin_consensus::script_pool::spawn_detached(move || {
                entered.fetch_add(1, Ordering::SeqCst);
                let (lock, cv) = &*gate;
                let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
                while !*g {
                    g = cv.wait(g).unwrap_or_else(|p| p.into_inner());
                }
            });
        }
        let start = Instant::now();
        while entered.load(Ordering::SeqCst) < n {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "script workers did not park"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        Self { gate }
    }
}

impl Drop for ScriptHold {
    fn drop(&mut self) {
        let (lock, cv) = &*self.gate;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
    }
}

fn poll_until<T, F>(mut fut: std::pin::Pin<Box<F>>, limit: std::time::Duration) -> T
where
    F: std::future::Future<Output = T>,
{
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;
    use std::time::Instant;
    struct Unpark(thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let start = Instant::now();
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => {
                assert!(
                    start.elapsed() < limit,
                    "encode waited on rbtc-scripts for a short payload"
                );
                thread::park_timeout(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// A short payload encodes on the caller while every script worker is parked.
/// A block encode stays pending until those workers are released, and the
/// bytes match `encode_v2_contents`.
#[test]
fn encode_v2_payload_keeps_a_short_message_on_the_caller() {
    use bitcoin::blockdata::constants::genesis_block;
    use std::time::Duration;
    let hold = ScriptHold::all();
    let short = poll_until(
        Box::pin(encode_v2_payload(NetworkMessage::Verack)),
        Duration::from_millis(200),
    )
    .unwrap();
    assert_eq!(short, encode_v2_contents(NetworkMessage::Verack).unwrap());
    let one = genesis_block(Network::Regtest).header;
    let headers = poll_until(
        Box::pin(encode_v2_payload(NetworkMessage::Headers(vec![one; 8]))),
        Duration::from_millis(200),
    )
    .unwrap();
    assert_eq!(
        headers,
        encode_v2_contents(NetworkMessage::Headers(vec![one; 8])).unwrap()
    );

    let mut heavy = Box::pin(encode_v2_payload(NetworkMessage::Block(genesis_block(
        Network::Regtest,
    ))));
    use std::future::Future;
    let waker = {
        use std::sync::Arc;
        use std::task::{Wake, Waker};
        struct Unpark(std::thread::Thread);
        impl Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        Waker::from(Arc::new(Unpark(std::thread::current())))
    };
    let mut cx = std::task::Context::from_waker(&waker);
    assert!(
        matches!(heavy.as_mut().poll(&mut cx), std::task::Poll::Pending),
        "block encode ran while rbtc-scripts workers were held"
    );
    drop(hold);
    let got = poll_until(heavy, Duration::from_secs(2)).unwrap();
    assert_eq!(
        got,
        encode_v2_contents(NetworkMessage::Block(genesis_block(Network::Regtest))).unwrap()
    );
}
