//! One-shot isolated SOCKS broadcast of locally submitted transactions.

use crate::error::NetError;
use crate::peer::{connect_and_handshake_timed, HandshakePolicy, HANDSHAKE_TIMEOUT};
use crate::seeds::AddrMan;
use crate::socks::Dialer;
use crate::tx_relay::MempoolHub;
use crate::v2::write_v2_msg;
use crate::NetAddr;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::Transaction;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;

pub(crate) const ISOLATED_BROADCAST_PEERS: usize = 2;

pub(crate) fn isolated_broadcast_targets(am: &AddrMan, max: usize) -> Vec<NetAddr> {
    let mut onions = Vec::new();
    let mut ips = Vec::new();
    for e in am.entries() {
        match e.addr {
            NetAddr::Onion { .. } => onions.push(e.addr),
            NetAddr::Ip(_) => ips.push(e.addr),
            NetAddr::I2p { .. } => {}
            NetAddr::Cjdns { .. } => {}
        }
    }
    let mut out = Vec::new();
    for a in onions.into_iter().chain(ips) {
        if out.len() >= max {
            break;
        }
        out.push(a);
    }
    out
}

pub(crate) async fn send_tx_isolated(
    dialer: &Dialer,
    target: NetAddr,
    magic: Magic,
    tx: Transaction,
    user_agent: &str,
) -> Result<(), NetError> {
    send_tx_isolated_timed(dialer, target, magic, tx, user_agent, HANDSHAKE_TIMEOUT).await
}

pub(crate) async fn send_tx_isolated_timed(
    dialer: &Dialer,
    target: NetAddr,
    magic: Magic,
    tx: Transaction,
    user_agent: &str,
    limit: Duration,
) -> Result<(), NetError> {
    let stream = dialer.connect_isolated_net(target).await?;
    let our = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));
    let their = target
        .socket_addr()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], target.port())));
    let (_ver, _reader, mut writer, _wire, tcp_shutdown) = connect_and_handshake_timed(
        limit,
        stream,
        magic,
        our,
        their,
        0,
        false,
        user_agent,
        HandshakePolicy::plain(),
    )
    .await?;
    write_v2_msg(&mut writer, NetworkMessage::Tx(tx)).await?;
    let _ = tcp_shutdown.shutdown(std::net::Shutdown::Both);
    Ok(())
}

async fn isolated_broadcast_known_tx(
    dialer: &Dialer,
    addrman: &Mutex<AddrMan>,
    magic: Magic,
    user_agent: &str,
    txid: bitcoin::Txid,
    tx: Transaction,
) {
    let targets = {
        let am = addrman.lock().unwrap_or_else(|e| e.into_inner());
        isolated_broadcast_targets(&am, ISOLATED_BROADCAST_PEERS)
    };
    if targets.is_empty() {
        rbitcoin_log::warn!("isolated broadcast {txid}: no AddrMan targets");
        return;
    }
    for t in targets {
        if let Err(e) = send_tx_isolated(dialer, t, magic, tx.clone(), user_agent).await {
            rbitcoin_log::warn!("isolated broadcast {txid} to {t}: {e}");
        }
    }
}

pub fn spawn_isolated_broadcast_loop(
    mp: Arc<MempoolHub>,
    dialer: Dialer,
    addrman: Arc<Mutex<AddrMan>>,
    magic: Magic,
    user_agent: String,
) -> JoinHandle<()> {
    if !mp.isolated_broadcast() {
        return tokio::spawn(async {});
    }
    let mut rx = mp.subscribe_isolated();
    tokio::spawn(async move {
        loop {
            let txid = match rx.recv().await {
                Ok(txid) => txid,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            // `get_tx` refuses the reactor thread. This task is a tokio worker.
            let tx = match mp.try_get_tx(&txid) {
                Some(tx) => Some(tx),
                None => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    mp.try_get_tx(&txid)
                }
            };
            let Some(tx) = tx else {
                continue;
            };
            isolated_broadcast_known_tx(&dialer, &addrman, magic, &user_agent, txid, tx).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg_decode::decode_framed_offload;
    use crate::peer::connect_and_handshake_timed;
    use crate::v2::read_v2_frame;
    use bitcoin::absolute::LockTime;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::Magic;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Transaction, TxOut};
    use bitcoin::{ScriptBuf, Sequence, TxIn, Witness};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
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

    #[test]
    fn isolated_broadcast_targets_prefers_onion() {
        let mut am = AddrMan::new();
        am.add(SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 8333)));
        let onion: NetAddr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
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

        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("ephemeral-broadcast");
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
        let peers = crate::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
        let sess = peers.register(
            addr,
            addr,
            &ver,
            false,
            crate::peers::PeerConnType::OutboundFullRelay,
        );
        sess.attach_out(tx);
        crate::force_announce_txid(&hub, &peers, local.compute_txid());
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
        let mut am = AddrMan::new();
        am.add(peer_addr);
        let tx = dummy_tx();
        isolated_broadcast_known_tx(
            &Dialer::Direct,
            &Mutex::new(am),
            Magic::REGTEST,
            "/rbitcoin:test/",
            tx.compute_txid(),
            tx,
        )
        .await;
        assert!(inbound.await.unwrap(), "one-shot reached the peer");
    }
}
