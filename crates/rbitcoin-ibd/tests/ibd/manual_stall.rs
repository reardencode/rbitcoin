//! A `--connect` peer that stalls block download is kept and sits out block
//! requests for two minutes (Core `MANUAL_PEER_BLOCK_DOWNLOAD_COOLDOWN`,
//! bitcoin/bitcoin#34743). Any other stalling peer is still disconnected.

use super::assign::{h, plant_work_path, tmp_hub, wired_slots};
use bitcoin::BlockHash;
use rbitcoin_ibd::ibd::assign::{assign_work_ordered, inflight_add_peer, AssignDepth};
use rbitcoin_ibd::ibd::dial::{dial_batch, disconnect_stalled_block_peers_at};
use rbitcoin_ibd::ibd::peer_io::{PeerCmd, PeerEventSinks};
use rbitcoin_ibd::ibd::state::IbdWorkState;
use rbitcoin_ibd::ibd::status::LoopStats;
use rbitcoin_ibd::ibd::IbdConfig;
use rbitcoin_net::chain::ChainHub;
use rbitcoin_net::peers::PeerConnType;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const T0: i64 = 1_700_000_000;
const COOLDOWN_SECS: i64 = 120;

/// Peer `pid` owes `hash`, and that getdata went out at mono `written_ms`.
fn owe_on_wire(st: &mut IbdWorkState, pid: usize, hash: BlockHash, written_ms: u64) {
    let slot = st.slots.iter_mut().find(|s| s.id == pid).unwrap();
    slot.track_insert(hash);
    slot.getdata_wire.queue(1);
    slot.getdata_wire.wrote(1, written_ms);
    inflight_add_peer(&mut st.inflight, hash, pid);
}

/// What each peer was sent since the last drain: block getdata hashes, and
/// whether it was told to shut down.
fn drain_wire(wire: &mut [mpsc::UnboundedReceiver<PeerCmd>]) -> Vec<(Vec<BlockHash>, bool)> {
    wire.iter_mut()
        .map(|rx| {
            let mut asked = Vec::new();
            let mut shutdown = false;
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    PeerCmd::GetData { hashes } => asked.extend(hashes),
                    PeerCmd::Shutdown => shutdown = true,
                    PeerCmd::GetHeaders { .. } => {}
                }
            }
            (asked, shutdown)
        })
        .collect()
}

/// The main loop's stall pass at mono `now_ms`, on the hub's node clock.
fn stall_pass(st: &mut IbdWorkState, hub: &ChainHub, now_ms: u64) -> Vec<BlockHash> {
    let freed = disconnect_stalled_block_peers_at(
        &mut st.slots,
        &mut st.inflight,
        &mut st.body,
        &mut st.addr_cooldown,
        &mut st.addr_strikes,
        Instant::now(),
        Duration::from_secs(30),
        now_ms,
        hub.clock.now_secs(),
    );
    st.reopen_for_densify(&freed);
    freed
}

fn assign(st: &mut IbdWorkState, hub: &ChainHub) {
    let cfg = IbdConfig::for_test();
    assign_work_ordered(
        st,
        hub,
        &cfg,
        &LoopStats::default(),
        AssignDepth::Full,
        None,
    );
}

/// `n` wired peers of type `conn_type` on a 40-block path above genesis.
fn connect_peers(
    hub: &ChainHub,
    n: usize,
    conn_type: PeerConnType,
) -> (IbdWorkState, Vec<mpsc::UnboundedReceiver<PeerCmd>>) {
    hub.ensure_genesis().unwrap();
    hub.clock.set_mock(T0);
    let (mut slots, wire) = wired_slots(n);
    for s in &mut slots {
        s.conn_type = conn_type;
    }
    let mut st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
    plant_work_path(&mut st, 1, 40);
    (st, wire)
}

/// Two `--connect` peers. Peer 0 owes heights 1 and 2 and has sent nothing
/// for the 30s stall; peer 1 is the header peer.
///
/// Peer 0 stays connected, its address is not cooled, and both blocks go to
/// peer 1. Peer 0 is sent no block getdata for two minutes on the node
/// clock, then it is asked again.
#[test]
fn stalling_connect_peer_stays_and_its_blocks_go_to_the_other_peer() {
    let (dir, hub) = tmp_hub();
    let (mut st, mut wire) = connect_peers(&hub, 2, PeerConnType::Manual);
    st.header_walk.reserved = Some(1);
    owe_on_wire(&mut st, 0, h(1), 0);
    owe_on_wire(&mut st, 0, h(2), 0);
    rbitcoin_log::capture_logs(true);

    let freed = stall_pass(&mut st, &hub, 30_001);
    let logs: Vec<String> = rbitcoin_log::take_logs()
        .into_iter()
        .map(|(_, l)| l)
        .collect();
    rbitcoin_log::capture_logs(false);

    let sent = drain_wire(&mut wire);
    assert!(
        st.slots[0].alive && !sent[0].1,
        "a stalling --connect peer is kept"
    );
    assert!(
        st.addr_cooldown.is_empty() && st.addr_strikes.is_empty(),
        "a kept peer's address is not cooled"
    );
    assert!(
        logs.iter()
            .any(|l| l
                .contains("Pausing block downloads from stalling manual peer=0 for 120 seconds")),
        "the pause is logged as Core does; logs={logs:?}"
    );
    let mut freed_sorted = freed.clone();
    freed_sorted.sort();
    let mut owed = vec![h(1), h(2)];
    owed.sort();
    assert_eq!(freed_sorted, owed, "its requests are released");
    assert!(st.slots[0].in_flight.is_empty());
    assert!(!st.inflight.contains_key(&h(1)) && !st.inflight.contains_key(&h(2)));

    assign(&mut st, &hub);
    let sent = drain_wire(&mut wire);
    assert!(
        sent[0].0.is_empty(),
        "a paused peer is sent no block getdata; got {:?}",
        sent[0].0
    );
    assert!(
        sent[1].0.contains(&h(1)) && sent[1].0.contains(&h(2)),
        "the released blocks go to the other --connect peer; got {:?}",
        sent[1].0
    );

    hub.clock.set_mock(T0 + COOLDOWN_SECS - 1);
    assign(&mut st, &hub);
    assert!(
        drain_wire(&mut wire)[0].0.is_empty(),
        "one second before the cooldown ends the peer is still paused"
    );

    hub.clock.set_mock(T0 + COOLDOWN_SECS);
    assign(&mut st, &hub);
    assert!(
        !drain_wire(&mut wire)[0].0.is_empty(),
        "after the cooldown the peer is asked for blocks again"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A getdata still in the writer when the peer was paused goes out after
/// its requests are released. That late write must not open the stall
/// window for the blocks asked after the cooldown.
#[test]
fn resumed_connect_peer_gets_a_fresh_stall_window() {
    let (dir, hub) = tmp_hub();
    let (mut st, mut wire) = connect_peers(&hub, 1, PeerConnType::Manual);
    owe_on_wire(&mut st, 0, h(1), 0);
    owe_on_wire(&mut st, 0, h(2), 0);
    st.slots[0].track_insert(h(3));
    st.slots[0].getdata_wire.queue(1);
    inflight_add_peer(&mut st.inflight, h(3), 0);

    stall_pass(&mut st, &hub, 30_001);
    assert!(st.slots[0].alive && st.slots[0].in_flight.is_empty());
    st.slots[0].getdata_wire.wrote(1, 31_000);

    hub.clock.set_mock(T0 + COOLDOWN_SECS);
    assign(&mut st, &hub);
    let asked = drain_wire(&mut wire)[0].0.len();
    assert!(asked > 0, "the resumed peer is asked again");
    st.slots[0].getdata_wire.wrote(asked, 151_000);

    stall_pass(&mut st, &hub, 151_500);
    assert!(
        !st.slots[0].in_flight.is_empty(),
        "half a second after the new write is not a stall"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The only peer is a `--connect` peer and it stalls. Catch-up has no other
/// peer to ask, waits out the cooldown, and asks that peer again.
#[test]
fn sole_connect_peer_is_retried_after_the_cooldown() {
    let (dir, hub) = tmp_hub();
    let (mut st, mut wire) = connect_peers(&hub, 1, PeerConnType::Manual);
    owe_on_wire(&mut st, 0, h(1), 0);

    stall_pass(&mut st, &hub, 30_001);
    assert!(st.slots[0].alive && !drain_wire(&mut wire)[0].1);

    hub.clock.set_mock(T0 + 60);
    assign(&mut st, &hub);
    assert!(
        drain_wire(&mut wire)[0].0.is_empty() && st.inflight.is_empty(),
        "inside the cooldown nothing is asked"
    );

    hub.clock.set_mock(T0 + COOLDOWN_SECS);
    assign(&mut st, &hub);
    assert!(
        drain_wire(&mut wire)[0].0.contains(&h(1)),
        "the sole peer is asked for the released block again"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A stalling peer that is not a `--connect` target is still disconnected,
/// its address cooled, and its blocks reassigned.
#[test]
fn stalling_outbound_peer_is_still_disconnected() {
    let (dir, hub) = tmp_hub();
    let (mut st, mut wire) = connect_peers(&hub, 2, PeerConnType::OutboundFullRelay);
    owe_on_wire(&mut st, 0, h(1), 0);
    let net = st.slots[0].net;

    stall_pass(&mut st, &hub, 30_001);
    assert!(!st.slots[0].alive, "an outbound staller is dropped");
    assert!(drain_wire(&mut wire)[0].1, "and told to shut down");
    assert!(st.addr_cooldown.contains_key(&net));

    st.slots.retain(|s| s.alive);
    assign(&mut st, &hub);
    assert!(drain_wire(&mut wire)[1].0.contains(&h(1)));
    let _ = std::fs::remove_dir_all(dir);
}

/// Core dials `-connect` as a manual connection. An IBD dial to a
/// `--connect` target is manual; a dial to the same address without
/// `--connect` is outbound full relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ibd_dial_of_a_connect_target_is_manual() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("ibd-dial-manual").unwrap();
    let q = rbitcoin_query::Query::open_or_create_tiny(dir.join("store")).unwrap();
    let seed = rbitcoin_net::service::P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        q,
        rbitcoin_consensus::ChainParams::regtest(),
        rbitcoin_consensus::Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .expect("listen");
    let target = rbitcoin_net::NetAddr::Ip(seed.local_addr);
    let mut book = rbitcoin_net::seeds::AddrMan::new();
    book.add_addr(target);
    let (body_tx, _body_rx) = mpsc::unbounded_channel();
    let (ctrl_tx, _ctrl_rx) = mpsc::unbounded_channel();
    let sinks = PeerEventSinks {
        body: body_tx,
        ctrl: ctrl_tx,
        header_fks: rbitcoin_ibd::ibd::peer_io::empty_header_fk_bus(),
    };
    let clock = rbitcoin_consensus::NodeClock::new();
    for (connect, want, label) in [
        (vec![target], PeerConnType::Manual, "manual"),
        (
            Vec::new(),
            PeerConnType::OutboundFullRelay,
            "outbound-full-relay",
        ),
    ] {
        rbitcoin_log::capture_logs(true);
        let r = dial_batch(
            &book,
            1,
            HashSet::new(),
            &[],
            seed.magic,
            "127.0.0.1:0".parse().unwrap(),
            Some(0),
            sinks.clone(),
            Duration::from_secs(5),
            None,
            rbitcoin_net::socks::Dialer::Direct,
            &clock,
            None,
            &connect,
        )
        .await;
        let logs: Vec<String> = rbitcoin_log::take_logs()
            .into_iter()
            .map(|(_, l)| l)
            .collect();
        rbitcoin_log::capture_logs(false);
        assert_eq!(r.slots.len(), 1, "dial reached the seed: {:?}", r.failed);
        assert_eq!(r.slots[0].conn_type, want);
        let line = format!("p2p: trying connection ({label}) to {target}");
        assert!(
            logs.iter().any(|l| l == &line),
            "dial log names the type; want {line:?} in {logs:?}"
        );
        for s in &r.slots {
            let _ = s.cmd_tx.send(PeerCmd::Shutdown);
        }
    }
    seed.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
