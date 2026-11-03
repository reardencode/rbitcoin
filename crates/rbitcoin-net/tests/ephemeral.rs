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

async fn wait_isolated_lap(
    mp: &MempoolHub,
    before: u64,
    read: impl Fn(&MempoolHub) -> u64,
    what: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if read(mp) > before {
            return;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!left.is_zero(), "{what}");
        let _ = tokio::time::timeout(left, mp.isolated_lap_notified()).await;
    }
}

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

/// splitmix64, so a target pick is the same on every run.
fn seeded_draw(seed: u64) -> impl FnMut(usize) -> usize {
    let mut s = seed;
    move |n| {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) % n as u64) as usize
    }
}

fn every_network_addrman(per_net: u8) -> AddrMan {
    let mut am = AddrMan::new();
    am.set_onion_reachable(true);
    am.set_i2p_reachable(true);
    am.set_cjdns_reachable(true);
    for i in 1..=per_net {
        am.add_addr(NetAddr::Onion {
            pk: [i; 32],
            port: 8333,
        });
        am.add(SocketAddr::from((Ipv4Addr::new(1, 2, 3, i), 8333)));
        am.add(SocketAddr::from((
            std::net::Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, u16::from(i)),
            8333,
        )));
        am.add_addr(NetAddr::I2p {
            dest: [i; 32],
            port: 0,
        });
        am.add_addr(NetAddr::Cjdns {
            ip: std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, u16::from(i)),
            port: 8333,
        });
    }
    am
}

/// Each tx gets its own targets, drawn like Core's `PickNetwork`: a network
/// the dialer reaches privately, then a row in it. Never I2P or CJDNS, and
/// an IPv4/IPv6 row only through `--proxy`.
#[test]
fn isolated_broadcast_targets_are_fresh_per_tx_and_private() {
    use rbitcoin_net::OnlyNet;
    use std::collections::HashSet;

    let am = every_network_addrman(12);
    let socks = SocketAddr::from(([127, 0, 0, 1], 9050));
    let proxy = Dialer::with_proxies(Some(socks), None, true);
    let onion_only = Dialer::with_proxies(None, Some(socks), true);

    let mut draw = seeded_draw(1275);
    let mut pairs = HashSet::new();
    let mut nets = Vec::new();
    for _ in 0..20 {
        let got = isolated_broadcast_targets(&am, &proxy, ISOLATED_BROADCAST_PEERS, &mut draw);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_ne!(got[0], got[1], "one tx never goes to the same peer twice");
        for a in &got {
            assert!(
                !matches!(a, NetAddr::I2p { .. } | NetAddr::Cjdns { .. }),
                "{a} is not reachable through SOCKS"
            );
            if !nets.contains(&OnlyNet::of(*a)) {
                nets.push(OnlyNet::of(*a));
            }
        }
        pairs.insert((got[0], got[1]));
    }
    assert!(pairs.len() >= 18, "txs share targets: {pairs:?}");
    for net in [OnlyNet::Onion, OnlyNet::Ipv4, OnlyNet::Ipv6] {
        assert!(nets.contains(&net), "{net:?} never drawn: {nets:?}");
    }

    let mut onions = HashSet::new();
    for _ in 0..20 {
        for a in isolated_broadcast_targets(&am, &onion_only, ISOLATED_BROADCAST_PEERS, &mut draw) {
            assert!(
                matches!(a, NetAddr::Onion { .. }),
                "--onion alone picked {a}"
            );
            onions.insert(a);
        }
    }
    assert!(onions.len() >= 8, "onion picks repeat: {onions:?}");

    assert!(
        isolated_broadcast_targets(&am, &Dialer::Direct, ISOLATED_BROADCAST_PEERS, &mut draw)
            .is_empty(),
        "a direct dialer reaches nothing privately"
    );

    let mut one_onion = every_network_addrman(0);
    let lone = NetAddr::Onion {
        pk: [7; 32],
        port: 8333,
    };
    one_onion.add_addr(lone);
    one_onion.add(SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 8333)));
    assert_eq!(
        isolated_broadcast_targets(&one_onion, &onion_only, ISOLATED_BROADCAST_PEERS, &mut draw),
        vec![lone],
        "one eligible row is the whole pick"
    );
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

/// One hub with a mempool and local txs. The isolated-broadcast loop is
/// idle until isolation is on. A burst of local txs behind one stuck send
/// all go out once, in order, except one mined first. The loop then
/// survives an unknown txid read off the reactor and a local tx with no
/// address to send to. A one-shot send that fails does not fall back to
/// INV on a standing peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ephemeral_broadcast() {
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
    let mut fan = spend(OutPoint { txid: cb2, vout: 0 }, 90_000_000);
    fan.output = vec![fan.output[0].clone(); BURST as usize + 9];
    let fan_id = fan.compute_txid();
    hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![fan])
        .expect("fan-out block");
    let locals: Vec<Transaction> = (0..BURST + 9)
        .map(|vout| spend(OutPoint { txid: fan_id, vout }, 89_990_000))
        .collect();
    let submit = |tx: &Transaction| {
        mp.accept_tx_from(tx, rbitcoin_net::TxOrigin::Local)
            .expect("local");
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

    // Two peers per tx. A tx that leaves the mempool while its first send
    // is in flight is not dialed to the second peer.
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = socks.local_addr().unwrap();
    let mut am = AddrMan::new();
    am.add(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 18444)));
    am.add(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 18444)));
    let (busy_tx, busy_rx) = tokio::sync::oneshot::channel();
    let (gate_tx, gate_rx) = tokio::sync::oneshot::channel();
    let (got_tx, mut got_rx) = mpsc::unbounded_channel();
    let recipient = tokio::spawn(gated_recipient(socks, busy_tx, gate_rx, got_tx));
    let sender = spawn_isolated_broadcast_loop(
        mp.clone(),
        Dialer::socks(proxy, true),
        Arc::new(Mutex::new(am)),
        Magic::REGTEST,
    );
    let gone = &locals[BURST as usize + 3];
    let kept = &locals[BURST as usize + 4];
    submit(gone);
    tokio::time::timeout(Duration::from_secs(30), busy_rx)
        .await
        .expect("the first send reaches the recipient")
        .unwrap();
    hub.generate_to_script(1, ScriptBuf::from_bytes(vec![0x51]), vec![gone.clone()])
        .expect("mine the tx in flight");
    gate_tx.send(()).unwrap();
    assert_eq!(
        next_sent(&mut got_rx).await,
        gone.compute_txid(),
        "the send already dialed completes"
    );
    submit(kept);
    assert_eq!(
        [next_sent(&mut got_rx).await, next_sent(&mut got_rx).await],
        [kept.compute_txid(); 2],
        "a mined tx is not dialed to its second peer; a live one reaches both"
    );
    sender.abort();
    recipient.abort();

    // A mempool write held across the loop's fetch (a block connect holds
    // it through persist) delays a local tx; it does not drop it. A marked
    // txid that was never admitted is read as gone and skipped once.
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
    );
    let [first, held, after, idle] = [5, 6, 7, 8].map(|i| &locals[BURST as usize + i]);
    let never_admitted = spend(
        OutPoint {
            txid: fan_id,
            vout: 999,
        },
        1,
    )
    .compute_txid();
    submit(first);
    tokio::time::timeout(Duration::from_secs(30), busy_rx)
        .await
        .expect("the first send reaches the recipient")
        .unwrap();
    mp.queue_isolated(never_admitted);
    submit(held);
    submit(after);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn({
        let mp = mp.clone();
        move || {
            let _write = mp.lock_write();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }
    });
    held_rx.recv().unwrap();
    // Sample before the gate opens. The next read notes the lap as soon as
    // the in-flight send returns, which can be before this task resumes.
    let lagged = mp.isolated_laps().lagged;
    gate_tx.send(()).unwrap();
    assert_eq!(next_sent(&mut got_rx).await, first.compute_txid());
    wait_isolated_lap(
        &mp,
        lagged,
        |m| m.isolated_laps().lagged,
        "isolated broadcast did not report a lagged read",
    )
    .await;
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(
        [next_sent(&mut got_rx).await, next_sent(&mut got_rx).await],
        [held.compute_txid(), after.compute_txid()],
        "a busy mempool write delays the next local txs; it does not drop them"
    );
    submit(idle);
    assert_eq!(
        next_sent(&mut got_rx).await,
        idle.compute_txid(),
        "the never-admitted txid was skipped once and the loop went idle"
    );
    assert!(
        mp.is_local_origin(&never_admitted),
        "a skipped txid stays marked, so it is not queued again"
    );
    sender.abort();
    recipient.abort();

    let h = spawn_loop(AddrMan::new());
    let skipped = mp.isolated_laps().skipped_unknown;
    mp.queue_isolated(dummy_tx().compute_txid());
    wait_isolated_lap(
        &mp,
        skipped,
        |m| m.isolated_laps().skipped_unknown,
        "an unknown txid was not reported skipped",
    )
    .await;
    assert!(
        !h.is_finished(),
        "an unknown txid is skipped without panicking on a tokio worker"
    );

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
    let no_targets = mp.isolated_laps().no_targets;
    mp.accept_tx_from(&local, rbitcoin_net::TxOrigin::Local)
        .expect("local");
    wait_isolated_lap(
        &mp,
        no_targets,
        |m| m.isolated_laps().no_targets,
        "a local tx with no targets was not reported",
    )
    .await;
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
        tx.compute_txid(),
        tx,
        || true,
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
        tx.compute_txid(),
        tx,
        || true,
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

/// A BIP324 recipient that answers our VERSION with its own (`relay` as
/// given) and VERACK, then records every message until we hang up.
async fn recording_recipient(l: TcpListener, relay: bool) -> Vec<NetworkMessage> {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::v2::{open_v2, write_v2_msg};

    let (stream, from) = l.accept().await.unwrap();
    let (mut reader, mut writer, _wire, _tcp) =
        open_v2(stream, Magic::REGTEST, true).await.unwrap();
    let mut seen = Vec::new();
    while let Ok(Ok(frame)) = tokio::time::timeout(
        Duration::from_secs(5),
        read_v2_frame(&mut reader, Magic::REGTEST),
    )
    .await
    {
        let msg = decode_framed_offload(frame)
            .await
            .unwrap()
            .payload()
            .clone();
        if matches!(msg, NetworkMessage::Version(_)) {
            let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2;
            let ours = VersionMessage {
                version: 70016,
                services,
                timestamp: 1_700_000_000,
                receiver: Address::new(&from, ServiceFlags::NONE),
                sender: Address::new(&from, services),
                nonce: 7,
                user_agent: "/Satoshi:31.0.0/".into(),
                start_height: 0,
                relay,
            };
            write_v2_msg(&mut writer, NetworkMessage::Version(ours))
                .await
                .unwrap();
            write_v2_msg(&mut writer, NetworkMessage::Verack)
                .await
                .unwrap();
        }
        seen.push(msg);
    }
    seen
}

/// One SOCKS hop from the isolated dialer to `dest`.
async fn socks_to(dest: SocketAddr) -> (Dialer, tokio::task::JoinHandle<Vec<u8>>) {
    let socks_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = socks_l.local_addr().unwrap();
    let splice = tokio::spawn(async move {
        let (s, _) = socks_l.accept().await.unwrap();
        splice_after_userpass(s, dest).await
    });
    (Dialer::socks(proxy, true), splice)
}

fn commands(seen: &[NetworkMessage]) -> Vec<&'static str> {
    seen.iter()
        .map(|m| match m {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::WtxidRelay => "wtxidrelay",
            NetworkMessage::SendAddrV2 => "sendaddrv2",
            NetworkMessage::Tx(_) => "tx",
            _ => "other",
        })
        .collect()
}

/// Core #29415 `PushNodeVersion` for a private broadcast connection: no
/// services, time 0, both addresses unset, `/pynode:0.0.1/`, height 0,
/// relay off. Then VERACK and the tx, with no WTXIDRELAY or SENDADDRV2. An
/// ordinary outbound handshake still sends this node's own VERSION.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn isolated_broadcast_sends_core_private_broadcast_version() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::ServiceFlags;

    let peer_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer_l.local_addr().unwrap();
    let recipient = tokio::spawn(recording_recipient(peer_l, true));
    let (dialer, splice) = socks_to(peer_addr).await;
    send_tx_isolated_timed(
        &dialer,
        NetAddr::Ip(peer_addr),
        Magic::REGTEST,
        dummy_tx(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let seen = recipient.await.unwrap();
    splice.abort();
    assert_eq!(commands(&seen), ["version", "verack", "tx"]);
    let NetworkMessage::Version(v) = &seen[0] else {
        unreachable!()
    };
    let unset = Address {
        services: ServiceFlags::NONE,
        address: [0; 8],
        port: 0,
    };
    assert_eq!(v.version, 70016);
    assert_eq!(v.services, ServiceFlags::NONE);
    assert_eq!(v.timestamp, 0);
    assert_eq!(v.receiver, unset);
    assert_eq!(v.sender, unset);
    assert_eq!(v.user_agent, "/pynode:0.0.1/");
    assert_eq!(v.start_height, 0);
    assert!(!v.relay);

    let normal_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let normal_addr = normal_l.local_addr().unwrap();
    let recipient = tokio::spawn(recording_recipient(normal_l, true));
    let stream = TcpStream::connect(normal_addr).await.unwrap();
    let our = stream.local_addr().unwrap();
    let (_ver, reader, writer, _wire, tcp) = connect_and_handshake_timed(
        Duration::from_secs(5),
        stream,
        Magic::REGTEST,
        our,
        normal_addr,
        7,
        false,
        "/rbitcoin:test/",
        HandshakePolicy::plain(),
    )
    .await
    .unwrap();
    let _ = tcp.shutdown(std::net::Shutdown::Both);
    drop((reader, writer));
    let seen = recipient.await.unwrap();
    assert_eq!(
        commands(&seen),
        ["version", "wtxidrelay", "sendaddrv2", "verack"]
    );
    let NetworkMessage::Version(v) = &seen[0] else {
        unreachable!()
    };
    assert!(v.services.has(ServiceFlags::WITNESS | ServiceFlags::P2P_V2));
    assert!(v.timestamp > 0);
    assert_eq!(v.user_agent, "/rbitcoin:test/");
    assert_eq!(v.start_height, 7);
    assert!(v.relay);
}

/// Core drops a private broadcast peer whose own VERSION has relay off
/// ("connected in vain"): no VERACK, no tx.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn isolated_broadcast_skips_a_peer_that_does_not_relay() {
    let peer_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer_l.local_addr().unwrap();
    let recipient = tokio::spawn(recording_recipient(peer_l, false));
    let (dialer, splice) = socks_to(peer_addr).await;
    let sent = send_tx_isolated_timed(
        &dialer,
        NetAddr::Ip(peer_addr),
        Magic::REGTEST,
        dummy_tx(),
        Duration::from_secs(5),
    )
    .await;
    assert!(sent.is_err(), "a peer with relay off must not get the tx");
    let seen = recipient.await.unwrap();
    splice.abort();
    assert_eq!(commands(&seen), ["version"]);
}
