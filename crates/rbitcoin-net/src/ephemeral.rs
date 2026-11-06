//! One-shot isolated SOCKS broadcast of locally submitted transactions.

use crate::error::NetError;
use crate::msg_decode::decode_framed_offload;
use crate::peer::{
    connect_and_handshake_timed, rand_nonce, HandshakePolicy, HANDSHAKE_TIMEOUT,
    PRIVATE_BROADCAST_USER_AGENT,
};
use crate::seeds::AddrMan;
use crate::socks::Dialer;
use crate::tx_relay::{IsolatedLap, IsolatedTake, MempoolHub};
use crate::v2::{read_v2_frame, write_v2_msg, V2Reader, V2Writer};
use crate::{NetAddr, OnlyNet};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::Magic;
use bitcoin::Transaction;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;

pub const ISOLATED_BROADCAST_PEERS: usize = 2;

/// Core `PrivateBroadcast::PickNetwork` then `AddrMan::Select`, once per target:
/// draw a network uniformly among those with a row left that `dialer` reaches
/// privately (onion; IPv4/IPv6 only through `--proxy`), then a row uniformly
/// within it. So one tx's targets say nothing about another's. `draw(n)` is
/// an index below `n`.
pub fn isolated_broadcast_targets(
    am: &AddrMan,
    dialer: &Dialer,
    max: usize,
    mut draw: impl FnMut(usize) -> usize,
) -> Vec<NetAddr> {
    let mut out: Vec<NetAddr> = Vec::with_capacity(max);
    for _ in 0..max {
        let left = || {
            am.order
                .iter()
                .copied()
                .filter(|a| dialer.proxy_for(OnlyNet::of(*a)).is_some() && !out.contains(a))
        };
        let mut nets: Vec<(OnlyNet, usize)> = Vec::new();
        for a in left() {
            let net = OnlyNet::of(a);
            match nets.iter_mut().find(|(n, _)| *n == net) {
                Some((_, rows)) => *rows += 1,
                None => nets.push((net, 1)),
            }
        }
        if nets.is_empty() {
            break;
        }
        let (net, rows) = nets[draw(nets.len())];
        let pick = left().filter(|a| OnlyNet::of(*a) == net).nth(draw(rows));
        out.extend(pick);
    }
    out
}

pub async fn send_tx_isolated(
    dialer: &Dialer,
    target: NetAddr,
    magic: Magic,
    tx: Transaction,
) -> Result<(), NetError> {
    send_tx_isolated_timed(dialer, target, magic, tx, HANDSHAKE_TIMEOUT).await
}

pub async fn send_tx_isolated_timed(
    dialer: &Dialer,
    target: NetAddr,
    magic: Magic,
    tx: Transaction,
    limit: Duration,
) -> Result<(), NetError> {
    let stream = dialer.connect_isolated_net(target).await?;
    let our = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));
    let their = target
        .socket_addr()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], target.port())));
    let deadline = tokio::time::Instant::now() + limit;
    let (_ver, mut reader, mut writer, _wire, tcp_shutdown) = connect_and_handshake_timed(
        limit,
        stream,
        magic,
        our,
        their,
        0,
        false,
        PRIVATE_BROADCAST_USER_AGENT,
        HandshakePolicy::private_broadcast(),
    )
    .await?;
    let handed_over =
        tokio::time::timeout_at(deadline, hand_over_tx(&mut reader, &mut writer, magic, tx)).await;
    let _ = tcp_shutdown.shutdown(std::net::Shutdown::Both);
    handed_over.map_err(|_| NetError::Timeout)?
}

async fn hand_over_tx(
    reader: &mut V2Reader,
    writer: &mut V2Writer,
    magic: Magic,
    tx: Transaction,
) -> Result<(), NetError> {
    let txid = tx.compute_txid();
    write_v2_msg(
        writer,
        NetworkMessage::Inv(vec![Inventory::Transaction(txid)]),
    )
    .await?;
    loop {
        if let NetworkMessage::GetData(asked) = next_message(reader, magic).await? {
            if asked.iter().any(|inv| asks_for(inv, txid)) {
                break;
            }
        }
    }
    write_v2_msg(writer, NetworkMessage::Tx(tx)).await?;
    let nonce = rand_nonce();
    write_v2_msg(writer, NetworkMessage::Ping(nonce)).await?;
    while next_message(reader, magic).await? != NetworkMessage::Pong(nonce) {}
    Ok(())
}

/// What one pass of [`isolated_broadcast_known_tx`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolatedBroadcast {
    /// AddrMan had no onion or IP to dial.
    NoTargets,
    /// Each target was attempted, or the tx left the mempool between dials.
    Finished,
}

fn asks_for(inv: &Inventory, txid: bitcoin::Txid) -> bool {
    matches!(inv, Inventory::Transaction(t) | Inventory::WitnessTransaction(t) if *t == txid)
}

async fn next_message(reader: &mut V2Reader, magic: Magic) -> Result<NetworkMessage, NetError> {
    let frame = read_v2_frame(reader, magic).await?;
    Ok(decode_framed_offload(frame).await?.into_payload())
}

/// Send `tx` one-shot to each target while `in_pool()` holds. It is asked
/// before every dial: one send can take [`HANDSHAKE_TIMEOUT`], and a tx that
/// left the mempool meanwhile must not reach the next peer.
pub async fn isolated_broadcast_known_tx(
    dialer: &Dialer,
    addrman: &Mutex<AddrMan>,
    magic: Magic,
    txid: bitcoin::Txid,
    tx: Transaction,
    in_pool: impl Fn() -> bool,
) -> IsolatedBroadcast {
    let targets = {
        let am = addrman.lock().unwrap_or_else(|e| e.into_inner());
        isolated_broadcast_targets(&am, dialer, ISOLATED_BROADCAST_PEERS, |n| {
            (crate::peer::rand_nonce() % n as u64) as usize
        })
    };
    if targets.is_empty() {
        rbitcoin_log::warn!(
            "isolated broadcast {txid}: no AddrMan peer reachable through the proxy"
        );
        return IsolatedBroadcast::NoTargets;
    }
    for t in targets {
        if !in_pool() {
            rbitcoin_log::info!("isolated broadcast {txid}: left the mempool, not sent to {t}");
            return IsolatedBroadcast::Finished;
        }
        match send_tx_isolated(dialer, t, magic, tx.clone()).await {
            Ok(()) => rbitcoin_log::info!("isolated broadcast {txid} to {t}: sent"),
            // A failed dial is this target's attempt. The next target, or the
            // next queued tx, runs immediately. There is no poll interval.
            Err(e) => rbitcoin_log::warn!("isolated broadcast {txid} to {t}: {e}"),
        }
    }
    IsolatedBroadcast::Finished
}

pub const ISOLATED_RESEND_SWEEP: Duration = Duration::from_secs(30);

pub fn spawn_isolated_broadcast_loop(
    mp: Arc<MempoolHub>,
    dialer: Dialer,
    addrman: Arc<Mutex<AddrMan>>,
    magic: Magic,
    resend_sweep: Duration,
) -> JoinHandle<()> {
    if !mp.isolated_broadcast() {
        return tokio::spawn(async {});
    }
    // Each send can spend `HANDSHAKE_TIMEOUT` per peer, so a queue this deep
    // waits minutes.
    const BACKLOG_WARN: usize = 32;
    tokio::spawn(async move {
        let mut warned = false;
        let mut sweep = tokio::time::interval(resend_sweep);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let (txid, behind) = tokio::select! {
                next = mp.next_isolated() => next,
                _ = sweep.tick() => {
                    mp.requeue_unreturned();
                    continue;
                }
            };
            if behind < BACKLOG_WARN {
                warned = false;
            } else {
                mp.note_isolated_lap(IsolatedLap::Lagged);
                if !warned {
                    warned = true;
                    rbitcoin_log::warn!(
                        "isolated broadcast is behind: {behind} local txs wait after {txid}"
                    );
                }
            }
            // A real read: `try_read` cannot tell a held write from a tx that
            // left, and `take` already marked this txid taken. A failed try
            // is the lagged lap; the read then waits on the same guard.
            let hub = Arc::clone(&mp);
            let take = tokio::task::spawn_blocking(move || {
                let _g = crate::reactor::BlockingRegion::enter();
                hub.isolated_tx_to_send(&txid)
            })
            .await
            .expect("isolated broadcast get_tx join");
            let tx = match take {
                IsolatedTake::Send(tx) => tx,
                IsolatedTake::Gone => {
                    rbitcoin_log::debug!(
                        "isolated broadcast {txid}: left the mempool before its turn"
                    );
                    mp.note_isolated_lap(IsolatedLap::SkippedUnknown);
                    continue;
                }
                IsolatedTake::InBlock => {
                    rbitcoin_log::debug!("isolated broadcast {txid}: already in a block, not sent");
                    continue;
                }
            };
            // `unindex_txid` drops the local-origin entry on every removal,
            // and this check never waits on the mempool lock.
            let in_pool = || mp.is_local_origin(&txid);
            let outcome =
                isolated_broadcast_known_tx(&dialer, &addrman, magic, txid, tx, in_pool).await;
            mp.isolated_sent(&txid);
            if outcome == IsolatedBroadcast::NoTargets {
                mp.note_isolated_lap(IsolatedLap::NoTargets);
            }
        }
    })
}
