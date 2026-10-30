use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::Transaction;
use rbitcoin_net::ephemeral::*;
use rbitcoin_net::msg_decode::decode_framed_offload;
use rbitcoin_net::peer::{connect_and_handshake_timed, HandshakePolicy};
use rbitcoin_net::seeds::AddrMan;
use rbitcoin_net::socks::Dialer;
use rbitcoin_net::tx_relay::MempoolHub;
use rbitcoin_net::NetAddr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::absolute::LockTime;
use rbitcoin_net::v2::read_v2_frame;

use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Amount, TxOut};
use bitcoin::{ScriptBuf, Sequence, TxIn, Witness};
use std::net::{IpAddr, Ipv4Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn dummy_tx() -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

async fn socks_userpass(s: &mut TcpStream) -> Vec<u8> {
    let mut ver_n = [0u8; 2];
    s.read_exact(&mut ver_n).await.unwrap();
    let nmethods = ver_n[1] as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await.unwrap();
    assert!(methods.contains(&0x02));
    s.write_all(&[5, 0x02]).await.unwrap();
    let mut ver = [0u8; 1];
    s.read_exact(&mut ver).await.unwrap();
    let mut ulen = [0u8; 1];
    s.read_exact(&mut ulen).await.unwrap();
    let mut user = vec![0u8; ulen[0] as usize];
    s.read_exact(&mut user).await.unwrap();
    let mut plen = [0u8; 1];
    s.read_exact(&mut plen).await.unwrap();
    let mut pass = vec![0u8; plen[0] as usize];
    s.read_exact(&mut pass).await.unwrap();
    s.write_all(&[1, 0]).await.unwrap();
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    match hdr[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await.unwrap();
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.unwrap();
        }
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await.unwrap();
            let mut host = vec![0u8; n[0] as usize];
            s.read_exact(&mut host).await.unwrap();
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.unwrap();
        }
        _ => panic!("unexpected ATYP {}", hdr[3]),
    }
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    user
}

async fn splice_after_userpass(mut c: TcpStream, dest: SocketAddr) -> Vec<u8> {
    let user = socks_userpass(&mut c).await;
    let mut peer = TcpStream::connect(dest).await.unwrap();
    let _ = tokio::io::copy_bidirectional(&mut c, &mut peer).await;
    user
}

/// A SOCKS proxy that is itself the one peer: every circuit handshakes and
/// reports the tx it carries on `got`. The first circuit stops after SOCKS,
/// says so on `busy`, and holds the sender until `gate` fires.
async fn gated_recipient(
    socks: TcpListener,
    busy: tokio::sync::oneshot::Sender<()>,
    gate: tokio::sync::oneshot::Receiver<()>,
    got: tokio::sync::mpsc::UnboundedSender<bitcoin::Txid>,
) {
    let mut first = Some((busy, gate));
    loop {
        let (mut s, from) = socks.accept().await.unwrap();
        socks_userpass(&mut s).await;
        if let Some((busy, gate)) = first.take() {
            busy.send(()).unwrap();
            gate.await.unwrap();
        }
        let here = s.local_addr().unwrap();
        let (_ver, mut reader, _writer, _wire, _tcp) = connect_and_handshake_timed(
            Duration::from_secs(5),
            s,
            Magic::REGTEST,
            here,
            from,
            0,
            true,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
        .unwrap();
        let frame = read_v2_frame(&mut reader, Magic::REGTEST).await.unwrap();
        let msg = decode_framed_offload(frame).await.unwrap();
        let NetworkMessage::Tx(tx) = msg.payload() else {
            panic!("expected tx, got {:?}", msg.payload());
        };
        got.send(tx.compute_txid()).unwrap();
    }
}

async fn next_sent(rx: &mut tokio::sync::mpsc::UnboundedReceiver<bitcoin::Txid>) -> bitcoin::Txid {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("the isolated loop stopped sending")
        .expect("recipient alive")
}

#[test]
fn isolated_broadcast_targets_prefers_onion() {
    let mut am = AddrMan::new();
    am.add(SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 8333)));
    let onion: NetAddr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
        .parse()
        .unwrap();
    am.set_onion_reachable(true);
    am.add_addr(onion);
    let got = isolated_broadcast_targets(&am, 1);
    assert_eq!(got, vec![onion]);
    let got = isolated_broadcast_targets(&am, 2);
    assert_eq!(got[0], onion);
    assert!(matches!(got[1], NetAddr::Ip(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ephemeral_broadcast_one_shot_tx_and_new_socks_creds() {
    let bitcoin_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = bitcoin_l.local_addr().unwrap();
    let inbound = tokio::spawn(async move {
        let (stream, from) = bitcoin_l.accept().await.unwrap();
        let (_ver, mut reader, _writer, _wire, _tcp) = connect_and_handshake_timed(
            Duration::from_secs(5),
            stream,
            Magic::REGTEST,
            peer_addr,
            from,
            0,
            true,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
        .unwrap();
        let frame = tokio::time::timeout(
            Duration::from_secs(5),
            read_v2_frame(&mut reader, Magic::REGTEST),
        )
        .await
        .expect("tx frame")
        .expect("tx decrypt");
        let msg = decode_framed_offload(frame).await.unwrap();
        assert!(
            matches!(msg.payload(), NetworkMessage::Tx(_)),
            "expected tx, got {:?}",
            msg.payload()
        );
        let eof = tokio::time::timeout(
            Duration::from_secs(5),
            read_v2_frame(&mut reader, Magic::REGTEST),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .is_none();
        eof
    });

    let socks_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = socks_l.local_addr().unwrap();
    let (cred_tx, mut cred_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(2);
    let splice = tokio::spawn(async move {
        let (mut s, _) = socks_l.accept().await.unwrap();
        let u = socks_userpass(&mut s).await;
        cred_tx.send(u).await.unwrap();
        let (s, _) = socks_l.accept().await.unwrap();
        let u = splice_after_userpass(s, peer_addr).await;
        cred_tx.send(u).await.unwrap();
    });

    let dialer = Dialer::socks(proxy, true);
    let _standing = dialer.connect(peer_addr).await.unwrap();
    let standing_user = cred_rx.recv().await.unwrap();

    let tx = dummy_tx();
    let want = tx.compute_txid();
    send_tx_isolated_timed(
        &dialer,
        NetAddr::Ip(peer_addr),
        Magic::REGTEST,
        tx,
        "/rbitcoin:test/",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let iso_user = cred_rx.recv().await.unwrap();
    assert_ne!(
        standing_user, iso_user,
        "isolated dial must use fresh SOCKS creds"
    );
    assert!(!standing_user.is_empty() && !iso_user.is_empty());

    let eof = inbound.await.unwrap();
    assert!(eof, "one-shot must disconnect after tx ({want})");
    splice.abort();
}

/// One hub with a mempool and a local tx. The isolated-broadcast loop is
/// idle until isolation is on, then survives unknown txids read off the
/// reactor, a burst that lags its kick channel, and a local tx with no
/// address to send to. A one-shot send that fails does not fall back to
/// INV on a standing peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ephemeral_broadcast() {
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::{OutPoint, Txid};
    use rbitcoin_primitives::Height;
    use tokio::sync::mpsc;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ephemeral-broadcast");
    hub.ensure_genesis().unwrap();
    hub.generate_to_script(102, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .expect("pad");
    let mp = MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp.clone()).is_ok());
    let spawn_loop = |am: AddrMan| {
        spawn_isolated_broadcast_loop(
            mp.clone(),
            Dialer::Direct,
            Arc::new(Mutex::new(am)),
            Magic::REGTEST,
            "/rbitcoin:test/".into(),
        )
    };

    spawn_loop(AddrMan::new())
        .await
        .expect("idle loop returns while isolation is off");

    mp.set_isolated_broadcast(true);

    // More local txs than the loop can send while one send is stuck. One
    // block fans a mature coinbase out to a coin per tx.
    let spend = |prev: OutPoint, sats: u64| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    const BURST: u32 = 44;
    let cb2 = hub
        .query
        .reconstruct_block_at_height(Height(2))
        .unwrap()
        .txdata[0]
        .compute_txid();
    let mut fan = spend(OutPoint { txid: cb2, vout: 0 }, 100_000_000);
    fan.output = vec![fan.output[0].clone(); BURST as usize + 3];
    let fan_id = fan.compute_txid();
    hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![fan])
        .expect("fan-out block");
    let locals: Vec<Transaction> = (0..BURST + 3)
        .map(|vout| spend(OutPoint { txid: fan_id, vout }, 99_990_000))
        .collect();
    let submit = |tx: &Transaction| {
        mp.accept_tx(tx).expect("local");
        mp.mark_local_origin(tx.compute_txid());
    };

    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = socks.local_addr().unwrap();
    let mut am = AddrMan::new();
    am.add(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 18444)));
    let (busy_tx, busy_rx) = tokio::sync::oneshot::channel();
    let (gate_tx, gate_rx) = tokio::sync::oneshot::channel();
    let (got_tx, mut got_rx) = mpsc::unbounded_channel();
    let recipient = tokio::spawn(gated_recipient(socks, busy_tx, gate_rx, got_tx));
    let sender = spawn_isolated_broadcast_loop(
        mp.clone(),
        Dialer::socks(proxy, true),
        Arc::new(Mutex::new(am)),
        Magic::REGTEST,
        "/rbitcoin:test/".into(),
    );
    submit(&locals[0]);
    tokio::time::timeout(Duration::from_secs(30), busy_rx)
        .await
        .expect("the first send reaches the recipient")
        .unwrap();
    for tx in &locals[1..=BURST as usize] {
        submit(tx);
    }
    let mined = locals[5].compute_txid();
    hub.generate_to_script(
        1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![locals[5].clone()],
    )
    .expect("mine a queued local tx");
    assert!(!mp.contains(&mined), "the block took it from the mempool");
    let last = &locals[BURST as usize + 1];
    submit(last);
    gate_tx.send(()).unwrap();

    let want: Vec<Txid> = locals[..=BURST as usize + 1]
        .iter()
        .map(Transaction::compute_txid)
        .filter(|t| *t != mined)
        .collect();
    let mut sent = Vec::new();
    while sent.last() != Some(&last.compute_txid()) {
        sent.push(next_sent(&mut got_rx).await);
    }
    assert_eq!(
        sent, want,
        "every queued local tx still in the mempool goes out once, in submit order"
    );
    let late = locals[BURST as usize + 2].compute_txid();
    submit(&locals[BURST as usize + 2]);
    assert_eq!(
        next_sent(&mut got_rx).await,
        late,
        "an idle loop wakes for the next local tx and resends nothing"
    );
    sender.abort();
    recipient.abort();

    let h = spawn_loop(AddrMan::new());
    tokio::time::sleep(Duration::from_millis(20)).await;
    mp.mark_local_origin(dummy_tx().compute_txid());
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        !h.is_finished(),
        "an unknown txid is skipped without panicking on a tokio worker"
    );
    for i in 0..40u8 {
        mp.mark_local_origin(Txid::from_byte_array([i; 32]));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!h.is_finished(), "Lagged kicks must not stop isolated send");

    let cb = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap()
        .txdata[0]
        .compute_txid();
    let local = Transaction {
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
    mp.accept_tx(&local).expect("local");
    mp.mark_local_origin(local.compute_txid());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!h.is_finished(), "a local tx with no targets is a no-op");
    h.abort();

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest = closed.local_addr().unwrap();
    drop(closed);
    let err = send_tx_isolated_timed(
        &Dialer::Direct,
        NetAddr::Ip(dest),
        Magic::REGTEST,
        local.clone(),
        "/rbitcoin:test/",
        Duration::from_millis(200),
    )
    .await;
    assert!(err.is_err(), "closed listener must fail the one-shot");
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
    let (tx, mut rx) = mpsc::unbounded_channel();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let sess = peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    sess.attach_out(tx);
    rbitcoin_net::force_announce_txid(&hub, &peers, local.compute_txid());
    assert!(
        rx.try_recv().is_err(),
        "failed isolated send must not fall back to standing INV"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ephemeral_broadcast_known_tx_one_shot() {
    let bitcoin_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = bitcoin_l.local_addr().unwrap();
    let inbound = tokio::spawn(async move {
        let (stream, from) = bitcoin_l.accept().await.unwrap();
        let (_ver, mut reader, _writer, _wire, _tcp) = connect_and_handshake_timed(
            Duration::from_secs(5),
            stream,
            Magic::REGTEST,
            peer_addr,
            from,
            0,
            true,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        )
        .await
        .unwrap();
        let frame = tokio::time::timeout(
            Duration::from_secs(5),
            read_v2_frame(&mut reader, Magic::REGTEST),
        )
        .await
        .expect("tx frame")
        .expect("tx decrypt");
        let msg = decode_framed_offload(frame).await.unwrap();
        assert!(
            matches!(msg.payload(), NetworkMessage::Tx(_)),
            "expected tx, got {:?}",
            msg.payload()
        );
        true
    });
    let socks_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = socks_l.local_addr().unwrap();
    let (accepted_tx, mut accepted_rx) = tokio::sync::oneshot::channel();
    let splice = tokio::spawn(async move {
        let (s, _) = socks_l.accept().await.unwrap();
        let _ = accepted_tx.send(());
        splice_after_userpass(s, peer_addr).await;
    });
    let mut am = AddrMan::new();
    am.add(peer_addr);
    let tx = dummy_tx();
    isolated_broadcast_known_tx(
        &Dialer::socks(proxy, true),
        &Mutex::new(am),
        Magic::REGTEST,
        "/rbitcoin:test/",
        tx.compute_txid(),
        tx,
    )
    .await;
    assert!(inbound.await.unwrap(), "one-shot reached the peer");
    accepted_rx
        .try_recv()
        .expect("the one-shot went through the SOCKS proxy");
    splice.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onion_only_isolated_broadcast_never_reaches_clearnet() {
    let clearnet = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let onion_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut am = AddrMan::new();
    am.add(clearnet.local_addr().unwrap());
    let tx = dummy_tx();
    isolated_broadcast_known_tx(
        &Dialer::with_proxies(None, Some(onion_proxy.local_addr().unwrap()), true),
        &Mutex::new(am),
        Magic::REGTEST,
        "/rbitcoin:test/",
        tx.compute_txid(),
        tx,
    )
    .await;
    for listener in [clearnet, onion_proxy] {
        assert!(
            tokio::time::timeout(Duration::ZERO, listener.accept())
                .await
                .is_err(),
            "the onion-only broadcast reached {:?}",
            listener.local_addr()
        );
    }
}
