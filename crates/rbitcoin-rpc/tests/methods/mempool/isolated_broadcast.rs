use super::super::{child_of, ctx_from_mature_pad, dispatch, mature_coinbase_spend_hex};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{Transaction, Txid};
use rbitcoin_net::peers::{CappedSet, LivePeer, PeerConnType, PeerHub, PeerOut};
use rbitcoin_net::tx_relay::MempoolAnnounce;
use rbitcoin_net::MempoolHub;
use rbitcoin_rpc::methods::RpcContext;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

fn standing_outbound(peers: &Arc<PeerHub>, last_octet: u8) -> Arc<LivePeer> {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)), 18444);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: u64::from(last_octet),
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    peers.register(addr, addr, &ver, false, PeerConnType::OutboundFullRelay)
}

fn recv_announce(rx: &mut broadcast::Receiver<MempoolAnnounce>) -> MempoolAnnounce {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match rx.try_recv() {
            Ok(ann) => return ann,
            Err(broadcast::error::TryRecvError::Empty) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("no accept announce: {e:?}"),
        }
    }
}

fn tx_invs(rx: &mut mpsc::UnboundedReceiver<PeerOut>) -> Vec<Inventory> {
    let mut out = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        if let PeerOut::Msg(NetworkMessage::Inv(v)) = msg {
            out.extend(v);
        }
    }
    out
}

/// Every txid the isolated loop could take now, oldest first. One poll
/// each: `next_isolated` is ready at once while a tx waits, so nothing here
/// depends on a timeout.
fn drain_isolated(mp: &MempoolHub) -> Vec<Txid> {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let mut out = Vec::new();
    loop {
        let next = std::pin::pin!(mp.next_isolated());
        match next.poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready((txid, _)) => out.push(txid),
            Poll::Pending => return out,
        }
    }
}

/// Submit `txs` through `method` with isolated broadcast on, and act as two
/// standing outbound sessions on each accept announce: one runs the
/// announce arm, the other a forced heartbeat walk.
///
/// The test holds `unbroadcast` across the submit. The RPC notes the tx
/// unbroadcast right after accept returns, so the submitter parks there:
/// the last point a mark taken after accept could still be pending. Each
/// announce is therefore read while the submitter is provably stopped, and
/// the result does not depend on scheduling.
fn isolated_submit_reaches_no_standing_peer(
    mut ctx: RpcContext,
    method: &str,
    params: Vec<Value>,
    txs: &[Transaction],
) {
    let mp: Arc<MempoolHub> = Arc::clone(ctx.mempool.as_ref().unwrap());
    let chain = Arc::clone(ctx.chain.as_ref().unwrap());
    mp.set_isolated_broadcast(true);
    let peers = PeerHub::new();
    let announced_to = standing_outbound(&peers, 1);
    let (announce_out, mut announce_rx) = mpsc::unbounded_channel();
    announced_to.attach_out(announce_out.clone());
    let walked = standing_outbound(&peers, 2);
    let (walk_out, mut walk_rx) = mpsc::unbounded_channel();
    walked.attach_out(walk_out.clone());
    ctx.peers = Some(Arc::clone(&peers));
    let mut ann_rx = mp.subscribe_announces();
    let follow = rbitcoin_net::peer::PeerFollowState::new();

    let ours: Vec<Txid> = txs.iter().map(Transaction::compute_txid).collect();
    let reply = std::thread::scope(|s| {
        let held = mp.unbroadcast.lock().unwrap();
        let submit = s.spawn(|| dispatch(&ctx, method, params));
        for _ in txs {
            let ann = recv_announce(&mut ann_rx);
            assert!(ours.contains(&ann.txid), "announce of {}", ann.txid);
            assert!(
                mp.skip_standing_inv(&ann.txid),
                "{method}: {} announced before it was marked local origin",
                ann.txid
            );
            rbitcoin_net::peer::on_tx_announce_ok(
                &chain,
                &announce_out,
                &follow,
                Some(announced_to.as_ref()),
                ann,
            )
            .unwrap();
            walked.request_tx_inv();
            rbitcoin_net::peer::queue_due_tx_invs(
                &chain,
                walked.as_ref(),
                &CappedSet::new(),
                &walk_out,
            );
        }
        drop(held);
        submit.join().unwrap()
    });
    reply.unwrap_or_else(|e| panic!("{method}: {e}"));
    walked.request_tx_inv();
    rbitcoin_net::peer::queue_due_tx_invs(&chain, walked.as_ref(), &CappedSet::new(), &walk_out);
    for txid in &ours {
        assert!(mp.contains(txid), "{method}: {txid} admitted");
    }
    assert_eq!(
        tx_invs(&mut announce_rx),
        Vec::<Inventory>::new(),
        "{method}: the announce arm INVed a local tx to a standing peer"
    );
    assert_eq!(
        tx_invs(&mut walk_rx),
        Vec::<Inventory>::new(),
        "{method}: the heartbeat walk INVed a local tx to a standing peer"
    );
    let mut kicks = drain_isolated(&mp);
    kicks.sort();
    let mut want = ours.clone();
    want.sort();
    assert_eq!(
        kicks, want,
        "{method}: the isolated loop gets each local tx exactly once"
    );
}

#[test]
fn sendrawtransaction_is_local_before_its_announce() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let (hex, tx) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 10_000);
    isolated_submit_reaches_no_standing_peer(ctx, "sendrawtransaction", vec![json!(hex)], &[tx]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn submitpackage_is_local_before_its_announces() {
    let (ctx, dir, _hub) = ctx_from_mature_pad(300_000_000);
    let (parent_hex, parent) = mature_coinbase_spend_hex(&ctx, 50_0000_0000 - 10_000);
    let child = child_of(&parent, 10_000);
    let params = vec![json!([parent_hex, serialize_hex(&child)])];
    isolated_submit_reaches_no_standing_peer(ctx, "submitpackage", params, &[parent, child]);
    let _ = std::fs::remove_dir_all(&dir);
}
