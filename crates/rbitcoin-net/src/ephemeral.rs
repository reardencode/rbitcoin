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

pub const ISOLATED_BROADCAST_PEERS: usize = 2;

pub fn isolated_broadcast_targets(am: &AddrMan, max: usize) -> Vec<NetAddr> {
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

pub async fn send_tx_isolated(
    dialer: &Dialer,
    target: NetAddr,
    magic: Magic,
    tx: Transaction,
    user_agent: &str,
) -> Result<(), NetError> {
    send_tx_isolated_timed(dialer, target, magic, tx, user_agent, HANDSHAKE_TIMEOUT).await
}

pub async fn send_tx_isolated_timed(
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

pub async fn isolated_broadcast_known_tx(
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
        match send_tx_isolated(dialer, t, magic, tx.clone(), user_agent).await {
            Ok(()) => rbitcoin_log::info!("isolated broadcast {txid} to {t}: sent"),
            Err(e) => rbitcoin_log::warn!("isolated broadcast {txid} to {t}: {e}"),
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
    // Each send can spend `HANDSHAKE_TIMEOUT` per peer, so a queue this deep
    // waits minutes.
    const BACKLOG_WARN: usize = 32;
    tokio::spawn(async move {
        let mut warned = false;
        loop {
            let (txid, behind) = mp.next_isolated().await;
            if behind < BACKLOG_WARN {
                warned = false;
            } else if !warned {
                warned = true;
                rbitcoin_log::warn!(
                    "isolated broadcast is behind: {behind} local txs wait after {txid}"
                );
            }
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
