use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::BlockHash;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_net::net_permissions::{parse_whitebind, NetPermTable};
use rbitcoin_net::peer::V2PlainSession;
use rbitcoin_query::Query;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const AGENT: &str = "/v1-wallet:0.1/";

fn v1_frame(magic: Magic, msg: NetworkMessage) -> Vec<u8> {
    serialize(&RawNetworkMessage::new(magic, msg))
}

fn v1_version(to: SocketAddr, from: SocketAddr) -> NetworkMessage {
    NetworkMessage::Version(VersionMessage {
        version: 70016,
        services: ServiceFlags::NONE,
        timestamp: 0,
        receiver: Address::new(&to, ServiceFlags::NONE),
        sender: Address::new(&from, ServiceFlags::NONE),
        nonce: 0x5eed,
        user_agent: AGENT.into(),
        start_height: 0,
        relay: true,
    })
}

async fn v1_read(s: &mut TcpStream) -> std::io::Result<NetworkMessage> {
    let mut whole = vec![0u8; 24];
    s.read_exact(&mut whole).await?;
    let len = u32::from_le_bytes([whole[16], whole[17], whole[18], whole[19]]) as usize;
    whole.resize(24 + len, 0);
    s.read_exact(&mut whole[24..]).await?;
    let raw: RawNetworkMessage = deserialize(&whole).expect("a v1 frame rust-bitcoin accepts");
    assert_eq!(*raw.magic(), Magic::REGTEST);
    Ok(raw.payload().clone())
}

/// Next message `keep` accepts. Every message passed over is returned too.
async fn v1_until(
    s: &mut TcpStream,
    keep: impl Fn(&NetworkMessage) -> bool,
) -> (NetworkMessage, Vec<NetworkMessage>) {
    let mut skipped = Vec::new();
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), v1_read(s))
            .await
            .unwrap_or_else(|_| panic!("no wanted v1 message after {skipped:?}"))
            .unwrap_or_else(|e| panic!("v1 read failed after {skipped:?}: {e}"));
        if keep(&msg) {
            return (msg, skipped);
        }
        skipped.push(msg);
    }
}

/// The node closes without sending a byte.
async fn closed_silently(s: &mut TcpStream) {
    let mut got = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut got)).await;
    let read = read.expect("the node must close the socket");
    if let Err(e) = read {
        assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}");
    }
    assert!(got.is_empty(), "the node sent {} bytes", got.len());
}

/// The node closes, after anything it had already queued.
async fn closed(s: &mut TcpStream) {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), v1_read(s))
            .await
            .expect("the node must close the socket")
        {
            Ok(_) => continue,
            Err(e) => {
                assert!(
                    matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ),
                    "{e}"
                );
                return;
            }
        }
    }
}

async fn v1_handshake(v1_bind: SocketAddr) -> TcpStream {
    v1_handshake_split(v1_bind, &[]).await
}

/// A v1 handshake whose `version` frame is cut at `cuts`, with a pause longer
/// than the handshake read's 50 ms poll after each piece but the last.
async fn v1_handshake_split(v1_bind: SocketAddr, cuts: &[usize]) -> TcpStream {
    let mut s = TcpStream::connect(v1_bind).await.unwrap();
    let ours = s.local_addr().unwrap();
    let version = v1_frame(Magic::REGTEST, v1_version(v1_bind, ours));
    let mut from = 0;
    for &cut in cuts {
        s.write_all(&version[from..cut]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        from = cut;
    }
    s.write_all(&version[from..]).await.unwrap();
    let (theirs, _) = v1_until(&mut s, |m| matches!(m, NetworkMessage::Version(_))).await;
    let NetworkMessage::Version(theirs) = theirs else {
        unreachable!()
    };
    assert_eq!(theirs.version, 70016);
    let (_, between) = v1_until(&mut s, |m| matches!(m, NetworkMessage::Verack)).await;
    assert!(
        between
            .iter()
            .all(|m| matches!(m, NetworkMessage::WtxidRelay | NetworkMessage::SendAddrV2)),
        "{between:?}"
    );
    s.write_all(&v1_frame(Magic::REGTEST, NetworkMessage::Verack))
        .await
        .unwrap();
    s
}

/// A wallet indexer on a `v1@` listener. One node, its primary listener and
/// one extra listener that carries the grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_v1_wallet_sync_listener() {
    let fut = async {
        let dir = rbitcoin_query::testutil::TempDir::labeled("v1-wallet-sync").unwrap();
        let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
        let mut node = rbitcoin_net::P2PNode::start_with_agent(
            "127.0.0.1:0".parse().unwrap(),
            q,
            ChainParams::regtest(),
            Milestone::NONE,
            "/rbitcoin:test/".into(),
            rbitcoin_net::DEFAULT_MAX_INBOUND,
            rbitcoin_net::REDIAL_INTERVAL_TEST,
        )
        .await
        .unwrap();
        node.hub.set_max_tip_age_secs(u64::MAX);
        let v1_bind = node
            .add_listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut perms = NetPermTable::default();
        perms.whitebind.push(
            parse_whitebind(&format!("v1,noban@{v1_bind}")).expect("v1 is a bind permission"),
        );
        node.peers.set_net_perms(perms);

        // The primary listener stays v2-only: a whole v1 version gets no reply.
        let mut primary = TcpStream::connect(node.local_addr).await.unwrap();
        let ours = primary.local_addr().unwrap();
        primary
            .write_all(&v1_frame(Magic::REGTEST, v1_version(node.local_addr, ours)))
            .await
            .unwrap();
        closed_silently(&mut primary).await;

        // Cut inside the header and inside the body.
        let mut wallet = v1_handshake_split(v1_bind, &[20, 34]).await;
        let (pong, _) = {
            wallet
                .write_all(&v1_frame(Magic::REGTEST, NetworkMessage::Ping(7)))
                .await
                .unwrap();
            v1_until(&mut wallet, |m| matches!(m, NetworkMessage::Pong(_))).await
        };
        assert!(matches!(pong, NetworkMessage::Pong(7)), "{pong:?}");

        let row = node
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.subver == AGENT)
            .expect("the wallet is a live peer");
        assert!(row.inbound);
        assert_eq!(row.addrbind, v1_bind);
        assert_eq!(row.transport, rbitcoin_net::v1::Transport::V1);
        assert!(
            row.permissions.iter().any(|p| p == "v1")
                && row.permissions.iter().any(|p| p == "noban"),
            "{:?}",
            row.permissions
        );

        // A bad checksum drops that message only. The next one is answered.
        let mut bad = v1_frame(Magic::REGTEST, NetworkMessage::Ping(8));
        bad[20] ^= 0xff;
        wallet.write_all(&bad).await.unwrap();
        wallet
            .write_all(&v1_frame(Magic::REGTEST, NetworkMessage::Ping(9)))
            .await
            .unwrap();
        let (pong, skipped) = v1_until(&mut wallet, |m| matches!(m, NetworkMessage::Pong(_))).await;
        assert!(
            matches!(pong, NetworkMessage::Pong(9)),
            "{pong:?} after {skipped:?}"
        );

        // A new block reaches the wallet, and getdata serves its body.
        let hash: BlockHash = node
            .hub
            .generate_to_script(1, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap()[0];
        let (announce, _) = v1_until(&mut wallet, |m| match m {
            NetworkMessage::Inv(inv) => inv.iter().any(
                |i| matches!(i, Inventory::Block(h) | Inventory::WitnessBlock(h) if *h == hash),
            ),
            NetworkMessage::Headers(h) => h.iter().any(|h| h.block_hash() == hash),
            _ => false,
        })
        .await;
        assert!(
            matches!(
                announce,
                NetworkMessage::Inv(_) | NetworkMessage::Headers(_)
            ),
            "{announce:?}"
        );
        wallet
            .write_all(&v1_frame(
                Magic::REGTEST,
                NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
            ))
            .await
            .unwrap();
        let (block, _) = v1_until(&mut wallet, |m| matches!(m, NetworkMessage::Block(_))).await;
        let NetworkMessage::Block(block) = block else {
            unreachable!()
        };
        assert_eq!(block.block_hash(), hash);

        // A v2 client may still use the v1 listener.
        let v2 = V2PlainSession::outbound_regtest(
            TcpStream::connect(v1_bind).await.unwrap(),
            "/v2-on-v1-listener/",
            Duration::from_secs(5),
        )
        .await;
        assert!(v2.is_ok(), "{:?}", v2.err());

        // Another network's magic ends the session.
        let mut other = v1_frame(Magic::BITCOIN, NetworkMessage::Ping(10));
        other.truncate(24);
        wallet.write_all(&other).await.unwrap();
        closed(&mut wallet).await;

        // A length past 4,000,000 ends the session before any payload.
        let mut big = v1_handshake(v1_bind).await;
        let mut head = v1_frame(Magic::REGTEST, NetworkMessage::Ping(11));
        head.truncate(24);
        head[16..20].copy_from_slice(&4_000_001u32.to_le_bytes());
        big.write_all(&head).await.unwrap();
        closed(&mut big).await;

        // A command with a control byte ends the session.
        let mut junk = v1_handshake(v1_bind).await;
        let mut frame = v1_frame(Magic::REGTEST, NetworkMessage::Ping(12));
        frame[4] = 0x01;
        junk.write_all(&frame).await.unwrap();
        closed(&mut junk).await;

        // Dropped frames count like v2 decoys: a flood of them ends the
        // session, noban or not.
        let mut flood = v1_handshake(v1_bind).await;
        let mut empty = v1_frame(Magic::REGTEST, NetworkMessage::Ping(13));
        empty.truncate(24);
        empty[16..24].fill(0);
        let burst: Vec<u8> = empty.iter().copied().cycle().take(24 * 9_000).collect();
        let _ = flood.write_all(&burst).await;
        closed(&mut flood).await;

        // `--listen=0` starts the node outbound-only, and the v1 bind is its
        // only listener. A relaying wallet there must outlive the handshake.
        let quiet_dir = rbitcoin_query::testutil::TempDir::labeled("v1-no-listen").unwrap();
        let quiet_q = Query::open_or_create_tiny(quiet_dir.path().join("store")).unwrap();
        let mut quiet = rbitcoin_net::P2PNode::start_outbound_only(
            quiet_q,
            ChainParams::regtest(),
            Milestone::NONE,
            "/rbitcoin:test/".into(),
            rbitcoin_net::DEFAULT_MAX_INBOUND,
            rbitcoin_net::socks::Dialer::Direct,
            rbitcoin_net::REDIAL_INTERVAL_TEST,
        )
        .await
        .unwrap();
        let only = quiet
            .add_listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut perms = NetPermTable::default();
        perms
            .whitebind
            .push(parse_whitebind(&format!("v1,noban@{only}")).unwrap());
        quiet.peers.set_net_perms(perms);
        let mut kept = v1_handshake(only).await;
        kept.write_all(&v1_frame(Magic::REGTEST, NetworkMessage::Ping(14)))
            .await
            .unwrap();
        let (pong, _) = v1_until(&mut kept, |m| matches!(m, NetworkMessage::Pong(_))).await;
        assert!(matches!(pong, NetworkMessage::Pong(14)), "{pong:?}");
    };
    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .expect("p2p_v1_wallet_sync_listener wall");
}
