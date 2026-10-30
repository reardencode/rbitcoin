use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::CompactTarget;
use bitcoin::Work;
use rbitcoin_ibd::ibd::events::apply_peer_event;
use rbitcoin_ibd::ibd::header_walk::*;
use rbitcoin_ibd::ibd::peer_io::{solicit_track, PeerCmd, PeerEvent, PeerSlot};
use rbitcoin_ibd::ibd::state::IbdWorkState;
use rbitcoin_ibd::ibd::ORDERED_HEADERS_SOFT_CAP;
use rbitcoin_net::chain::ChainHub;
use std::time::{Duration, Instant};

use rbitcoin_net::seeds::AddrMan;

use bitcoin::TxMerkleNode;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

fn mine(prev: BlockHash, n: u32) -> Header {
    let mut h = Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([n as u8; 32]),
        time: 1_600_000_000 + n,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: n,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut h);
    h
}

#[test]
fn pow_linked_accepts_a_chain_and_rejects_a_bad_link_or_pow() {
    let a = mine(BlockHash::from_byte_array([0; 32]), 1);
    let b = mine(a.block_hash(), 2);
    let c = mine(b.block_hash(), 3);
    assert!(pow_linked(&[a, b, c]));
    assert!(pow_linked(&[a]));
    let mislink = mine(a.block_hash(), 9);
    assert!(!pow_linked(&[a, b, mislink]));
    // Regtest 0x207fffff accepts every hash, so a nonce bump is not a pow miss.
    let mut bad_pow = c;
    bad_pow.bits = CompactTarget::from_consensus(0x1d00ffff);
    assert!(!pow_linked(&[a, b, bad_pow]));
}

fn slot(id: usize) -> (PeerSlot, mpsc::UnboundedReceiver<PeerCmd>) {
    let (cmd_tx, rx) = mpsc::unbounded_channel();
    let task = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .spawn(async {});
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, id as u8)), 8333);
    (
        PeerSlot {
            id,
            addr,
            net: rbitcoin_net::NetAddr::from_socket(addr),
            cmd_tx,
            in_flight: Default::default(),
            requested: solicit_track().0,
            solicited_bytes: solicit_track().1,
            solicited_ms: solicit_track().2,
            any_rx_ms: Arc::new(AtomicU64::new(0)),
            getdata_wire: rbitcoin_ibd::ibd::peer_io::GetdataWire::new(),
            peer_height: 50_000,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            chain: Default::default(),
            conn_type: rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
            block_download_pause: None,
            alive: true,
            task,
        },
        rx,
    )
}

/// Expire an actually-aged walk ask without waiting five wall-clock seconds.
fn expire_walk_ask_for(st: &mut IbdWorkState, peer: usize) -> Option<usize> {
    st.header_walk.reserved = Some(peer);
    note_lane(st, peer);
    st.header_walk.walk.at = Instant::now().checked_sub(LOOKAHEAD_ASK + Duration::from_secs(1));
    assert!(!lane_fresh(&st.header_walk.walk));
    expire_header_ask(st)
}

#[test]
fn header_timeouts_preserve_recent_solicited_block_download() {
    use rbitcoin_ibd::ibd::peer_io::{
        ibd_mono_ms, note_block_rx, note_read_progress, note_solicited_block,
    };
    use rbitcoin_ibd::ibd::state::InflightReq;
    use std::sync::atomic::Ordering;

    // Keep the peer task genuinely unfinished, unlike slot()'s disposable task.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut downloading, mut rx) = slot(0);
    downloading.task = runtime.spawn(std::future::pending::<()>());
    let (requested, bytes, ms) = solicit_track();
    downloading.requested = requested;
    downloading.solicited_bytes = bytes;
    downloading.solicited_ms = ms;
    let mut st = IbdWorkState::new(vec![downloading], None, None);
    let owed = BlockHash::from_byte_array([0xa5; 32]);
    st.slots[0].track_insert(owed);
    st.slots[0].getdata_wire.queue(1);
    st.slots[0].getdata_wire.wrote(1, ibd_mono_ms());
    st.inflight.insert(owed, InflightReq::new(0));
    st.body.mark_missing(owed);

    // Zero is the "no data yet" sentinel; start the production monotonic clock.
    let _ = ibd_mono_ms();
    std::thread::sleep(Duration::from_millis(2));
    for miss in 0..HEADER_MISS_DISCONNECT {
        // A different solicited block arrives immediately before each expiry.
        // Keep another block outstanding, matching the production capture.
        let delivered = BlockHash::from_byte_array([0x20 + miss; 32]);
        st.inflight.insert(delivered, InflightReq::new(0));
        let slot = &mut st.slots[0];
        slot.track_insert(delivered);
        slot.getdata_wire.queue(1);
        slot.getdata_wire.wrote(1, ibd_mono_ms());
        let mut progress_mark = 0;
        note_read_progress(
            &slot.bytes_rx_total,
            &slot.any_rx_ms,
            &mut progress_mark,
            1_000_000,
        );
        assert!(note_solicited_block(
            &slot.requested,
            &slot.solicited_bytes,
            &slot.solicited_ms,
            &delivered,
            1_000_000,
        ));
        slot.track_remove(&delivered);
        st.inflight.remove(&delivered);
        note_block_rx(&mut st.slots, 0, 1_000_000);
        assert!(!st.slots[0].task.is_finished());
        assert!(st.slots[0].solicited_ms.load(Ordering::Relaxed) > 0);
        assert_eq!(st.slots[0].getdata_wire.unwritten(), 0);

        let _ = expire_walk_ask_for(&mut st, 0);
        if miss == 0 {
            assert!(
                st.slots[0].alive,
                "the first header miss must not drop the peer"
            );
            assert_eq!(st.header_walk.header_misses.get(&0), Some(&1));
        }
    }

    let alive = st.slots[0].alive;
    let owns_block = st.slots[0].in_flight.contains(&owed)
        && st
            .inflight
            .get(&owed)
            .is_some_and(|request| request.holds(0));
    let still_requested = st.slots[0].requested_set().contains(&owed);
    let shutdown = std::iter::from_fn(|| rx.try_recv().ok())
        .any(|command| matches!(command, PeerCmd::Shutdown));
    assert!(
        alive && owns_block && still_requested && !shutdown,
        "header-only timeouts destroyed an active solicited-block download: \
         alive={alive}, owns_block={owns_block}, still_requested={still_requested}, shutdown={shutdown}"
    );
}

#[test]
fn header_timeouts_still_disconnect_an_idle_peer() {
    let (idle, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![idle], None, None);
    assert_eq!(expire_walk_ask_for(&mut st, 0), Some(0));
    assert!(st.slots[0].alive);
    assert_eq!(expire_walk_ask_for(&mut st, 0), None);
    assert!(!st.slots[0].alive);
    assert!(matches!(rx.try_recv(), Ok(PeerCmd::Shutdown)));
}

fn productive_block_peer(
    id: usize,
    now_ms: u64,
) -> (
    tokio::runtime::Runtime,
    PeerSlot,
    mpsc::UnboundedReceiver<PeerCmd>,
    BlockHash,
) {
    use std::sync::atomic::Ordering;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut peer, rx) = slot(id);
    peer.task = runtime.spawn(std::future::pending::<()>());
    let (requested, bytes, ms) = solicit_track();
    peer.requested = requested;
    peer.solicited_bytes = bytes;
    peer.solicited_ms = ms;
    let owed = BlockHash::from_byte_array([0xa5; 32]);
    peer.track_insert(owed);
    peer.getdata_wire.queue(1);
    peer.getdata_wire.wrote(1, now_ms.saturating_sub(1));
    peer.solicited_bytes.store(1_000_000, Ordering::Relaxed);
    peer.solicited_ms
        .store(now_ms.saturating_sub(1), Ordering::Relaxed);
    peer.bytes_rx_total.store(1_000_000, Ordering::Relaxed);
    peer.any_rx_ms.store(now_ms, Ordering::Relaxed);
    (runtime, peer, rx, owed)
}

#[test]
fn header_timeout_grace_requires_recent_solicited_on_wire_work() {
    use std::sync::atomic::Ordering;
    let now_ms = 60_000;
    let (_runtime, mut peer, _rx, owed) = productive_block_peer(0, now_ms);
    assert!(header_timeout_has_block_progress(&peer, now_ms));

    peer.solicited_bytes.store(0, Ordering::Relaxed);
    assert!(
        !header_timeout_has_block_progress(&peer, now_ms),
        "ping/stream activity is not a solicited body"
    );
    peer.solicited_bytes.store(1_000_000, Ordering::Relaxed);
    peer.solicited_ms
        .store(now_ms - HEADER_BLOCK_PROGRESS_GRACE_MS, Ordering::Relaxed);
    assert!(
        !header_timeout_has_block_progress(&peer, now_ms),
        "the grace expires at the block-stall boundary"
    );
    peer.solicited_ms.store(
        now_ms - HEADER_BLOCK_PROGRESS_GRACE_MS + 1,
        Ordering::Relaxed,
    );
    assert!(header_timeout_has_block_progress(&peer, now_ms));

    peer.getdata_wire.queue(1);
    assert!(
        !header_timeout_has_block_progress(&peer, now_ms),
        "queued-only work cannot keep the peer"
    );
    peer.getdata_wire.wrote(1, now_ms);
    assert!(header_timeout_has_block_progress(&peer, now_ms));
    peer.getdata_wire.disarm_window();
    assert!(!header_timeout_has_block_progress(&peer, now_ms));
    peer.getdata_wire.arm_window_if_closed(now_ms);
    peer.track_remove(&owed);
    assert!(
        !header_timeout_has_block_progress(&peer, now_ms),
        "nothing remains to download"
    );
    peer.track_insert(owed);
    peer.getdata_wire.wrote(1, now_ms);
    peer.alive = false;
    assert!(!header_timeout_has_block_progress(&peer, now_ms));
}

#[test]
fn header_timeouts_move_header_role_without_releasing_block_work() {
    use rbitcoin_ibd::ibd::state::InflightReq;
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-timeout-keep-blocks");
    hub.ensure_genesis().unwrap();
    let (_runtime, mut peer, mut rx, owed) =
        productive_block_peer(0, rbitcoin_ibd::ibd::peer_io::ibd_mono_ms());
    let (replacement, mut replacement_rx) = slot(1);
    peer.peer_height = 100_000;
    let mut st = IbdWorkState::new(vec![peer, replacement], hub.tip_hash(), Some(0));
    st.inflight.insert(owed, InflightReq::new(0));
    fill_queue(&mut st);
    assert_eq!(expire_walk_ask_for(&mut st, 0), Some(0));
    assert_eq!(expire_walk_ask_for(&mut st, 0), None);
    assert!(st.slots[0].alive);
    assert!(st.slots[0].in_flight.contains(&owed));
    assert!(st.inflight.get(&owed).is_some_and(|r| r.holds(0)));
    assert!(st.header_walk.header_timeout_peers.contains(&0));
    assert!(!st.header_walk.walk_quiet.contains(&0));
    assert_eq!(
        peer_horizon(&st),
        100_000,
        "a timeout is not evidence that the peer lacks the chain"
    );
    assert_ne!(st.header_walk.reserved, Some(0));
    assert!(
        may_serve(&st, 0, &owed),
        "header retirement must not make blocks ineligible"
    );
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(st.header_walk.walk.peer, Some(1));
    assert_eq!(drain_getheaders(&mut replacement_rx), 1);
    assert!(!std::iter::from_fn(|| rx.try_recv().ok()).any(|c| matches!(c, PeerCmd::Shutdown)));
    assert_eq!(take_header_ask(&mut st, 0), HeaderAsk::Late);
    assert!(!st.header_walk.header_misses.contains_key(&0));
    assert!(
        !st.header_walk.header_timeout_peers.contains(&0),
        "a late reply clears the soft preference"
    );
    assert_eq!(pick_header_peer(&st, 0, None), Some(0));
    st.header_walk.header_timeout_peers.insert(0);
    st.header_walk.header_misses.insert(0, 1);
    forget_walk_peer(&mut st, 0);
    assert!(!st.header_walk.header_timeout_peers.contains(&0));
    assert!(!st.header_walk.header_misses.contains_key(&0));
}

#[test]
fn header_timeouts_do_not_preserve_ping_only_block_peers() {
    use std::sync::atomic::Ordering;
    let (_runtime, peer, mut rx, _owed) =
        productive_block_peer(0, rbitcoin_ibd::ibd::peer_io::ibd_mono_ms());
    peer.solicited_bytes.store(0, Ordering::Relaxed);
    let mut st = IbdWorkState::new(vec![peer], None, None);
    let _ = expire_walk_ask_for(&mut st, 0);
    let _ = expire_walk_ask_for(&mut st, 0);
    assert!(!st.slots[0].alive);
    assert!(matches!(rx.try_recv(), Ok(PeerCmd::Shutdown)));
}

#[test]
fn header_validation_punishment_still_disconnects_productive_block_peer() {
    let (_runtime, peer, mut rx, _owed) =
        productive_block_peer(0, rbitcoin_ibd::ibd::peer_io::ibd_mono_ms());
    assert!(header_timeout_has_block_progress(
        &peer,
        rbitcoin_ibd::ibd::peer_io::ibd_mono_ms()
    ));
    let mut st = IbdWorkState::new(vec![peer], None, None);
    punish_header_peer(&mut st, 0);
    assert!(!st.slots[0].alive);
    assert!(matches!(rx.try_recv(), Ok(PeerCmd::Shutdown)));
}

#[test]
fn probe_and_challenge_timeouts_preserve_productive_block_work() {
    for probe in [true, false] {
        let (_runtime, peer, mut rx, owed) =
            productive_block_peer(0, rbitcoin_ibd::ibd::peer_io::ibd_mono_ms());
        let mut st = IbdWorkState::new(vec![peer], None, None);
        let _ = expire_walk_ask_for(&mut st, 0);
        if probe {
            st.header_walk.probe_open = Some(0);
        } else {
            st.header_walk.challenge_open = Some(0);
            st.header_walk.challenge_external = true;
        }
        let _ = expire_walk_ask_for(&mut st, 0);
        assert!(st.slots[0].alive);
        assert!(st.slots[0].in_flight.contains(&owed));
        assert!(st.header_walk.probe_open.is_none());
        assert!(st.header_walk.challenge_open.is_none());
        assert!(!st.header_walk.challenge_external);
        assert_ne!(st.header_walk.reserved, Some(0));
        assert!(!std::iter::from_fn(|| rx.try_recv().ok()).any(|c| matches!(c, PeerCmd::Shutdown)));
    }
}

#[test]
fn header_timeout_deprioritized_sole_block_peer_can_still_answer_headers() {
    let (_dir, hub) =
        rbitcoin_net::chain::tiny_regtest_hub_labeled("header-timeout-sole-block-peer");
    hub.ensure_genesis().unwrap();
    let (_runtime, peer, mut rx, owed) =
        productive_block_peer(0, rbitcoin_ibd::ibd::peer_io::ibd_mono_ms());
    let mut st = IbdWorkState::new(vec![peer], hub.tip_hash(), Some(0));
    fill_queue(&mut st);
    let _ = expire_walk_ask_for(&mut st, 0);
    let _ = expire_walk_ask_for(&mut st, 0);
    assert!(st.slots[0].alive);
    assert!(st.header_walk.header_timeout_peers.contains(&0));
    assert!(!st.header_walk.walk_quiet.contains(&0));
    assert!(wants_lookahead(&st));
    assert!(
        send_getheaders(&mut st, &hub).unwrap(),
        "soft preference must not deadlock a sole peer's header progress"
    );
    assert_eq!(st.header_walk.walk.peer, Some(0));
    assert!(st.slots[0].in_flight.contains(&owed));
    assert!(matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })));
    assert!(rx.try_recv().is_err());
}

#[test]
fn header_timeout_grace_does_not_keep_a_finished_peer_task() {
    let (runtime, mut peer, _rx, _owed) = productive_block_peer(0, 60_000);
    assert!(header_timeout_has_block_progress(&peer, 60_000));
    peer.task.abort();
    assert!(runtime.block_on(&mut peer.task).unwrap_err().is_cancelled());
    assert!(!header_timeout_has_block_progress(&peer, 60_000));
}

#[test]
fn first_challenge_timeout_keeps_productive_frontier_ownership() {
    use rbitcoin_ibd::ibd::state::InflightReq;
    let (_runtime, peer, _rx, owed) =
        productive_block_peer(0, rbitcoin_ibd::ibd::peer_io::ibd_mono_ms());
    let mut st = IbdWorkState::new(vec![peer], None, None);
    st.inflight.insert(owed, InflightReq::new(0));
    st.header_walk.challenge_open = Some(0);
    let _ = expire_walk_ask_for(&mut st, 0);
    assert!(st.slots[0].alive);
    assert!(!st.header_walk.header_timeout_peers.contains(&0));
    assert_eq!(st.header_walk.header_misses.get(&0), Some(&1));
    assert!(st.inflight[&owed].peers.contains(&0));
    assert!(st.slots[0].in_flight.contains(&owed));
    assert!(!st.header_walk.walk_quiet.contains(&0));
    assert!(wants_lookahead(&st));
}

#[test]
fn continued_header_silence_disconnects_even_with_fresh_block_progress() {
    use rbitcoin_ibd::ibd::peer_io::ibd_mono_ms;
    use rbitcoin_ibd::ibd::state::InflightReq;
    use std::sync::atomic::Ordering;

    for lane in ["walk", "probe", "challenge"] {
        for replacement in [false, true] {
            let (_runtime, peer, mut rx, owed) = productive_block_peer(0, ibd_mono_ms());
            let mut slots = vec![peer];
            if replacement {
                let (mut other, _rx) = slot(1);
                other.peer_height = 0;
                slots.push(other);
            }
            let mut st = IbdWorkState::new(slots, None, None);
            st.inflight.insert(owed, InflightReq::new(0));
            for miss in 1..=4 {
                st.slots[0]
                    .solicited_ms
                    .store(ibd_mono_ms(), Ordering::Relaxed);
                assert!(header_timeout_has_block_progress(
                    &st.slots[0],
                    ibd_mono_ms()
                ));
                if lane == "probe" {
                    st.header_walk.probe_open = Some(0);
                } else if lane == "challenge" {
                    st.header_walk.challenge_open = Some(0);
                    st.header_walk.challenge_external = true;
                }
                let _ = expire_walk_ask_for(&mut st, 0);
                if miss < 4 {
                    assert!(
                        st.slots[0].alive,
                        "{lane}, replacement={replacement}, miss={miss}"
                    );
                    assert_eq!(st.header_walk.header_misses.get(&0), Some(&miss));
                    assert!(st.inflight[&owed].holds(0));
                }
            }
            assert!(!st.slots[0].alive, "{lane}, replacement={replacement}");
            assert!(!st.inflight.contains_key(&owed));
            assert!(!wants_lookahead(&st));
            assert!(std::iter::from_fn(|| rx.try_recv().ok())
                .any(|command| matches!(command, PeerCmd::Shutdown)));
        }
    }
}

fn fill_queue(st: &mut IbdWorkState) {
    for i in 0..ORDERED_HEADERS_SOFT_CAP {
        let mut b = [0u8; 32];
        b[28..32].copy_from_slice(&(i as u32).to_le_bytes());
        let h = BlockHash::from_byte_array(b);
        st.ordered.push_back(h);
        st.ordered_set.insert(h);
    }
}

#[test]
fn follow_session_inv_pokes_a_live_header_peer() {
    let (s0, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], None, None);
    assert!(note_external_block_inv(&mut st));
    assert_eq!(st.header_walk.challenge, Some(0));
    st.slots[0].alive = false;
    st.header_walk.challenge = None;
    assert!(!note_external_block_inv(&mut st));
}

fn apply(st: &mut IbdWorkState, hub: &ChainHub, peer: usize, headers: Vec<Header>) {
    apply_peer_event(
        st,
        hub,
        PeerEvent::Headers { peer, headers },
        &AtomicU32::new(0),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        None,
    );
}

fn blocks_inv(st: &mut IbdWorkState, hub: &ChainHub, peer: usize, hashes: Vec<BlockHash>) {
    apply_peer_event(
        st,
        hub,
        PeerEvent::BlocksInv { peer, hashes },
        &AtomicU32::new(0),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        None,
    );
}

fn plant_on_queue(st: &mut IbdWorkState, hash: BlockHash, height: u32) {
    let old = st.ordered.pop_back().unwrap();
    st.ordered_set.remove(&old);
    st.ordered.push_back(hash);
    st.ordered_set.insert(hash);
    st.hash_height.insert(hash, height);
}

#[test]
fn full_queue_checkpoints_lookahead_and_refill_stores_the_successor() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-1");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let (s0, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(
        !st.header_walk.has_checkpoints(),
        "a walk with no replies has no checkpoints"
    );
    let before = hub.query.store().header_count();
    log_status(&mut st, &hub, 50_000);
    assert!(
        !st.header_walk.announced_done,
        "the status line stays quiet until the walk has a candidate"
    );

    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![good]);
    assert_eq!(
        hub.query.store().header_count(),
        before + 1,
        "an accepted batch is written even when the queue is full"
    );
    assert_eq!(st.ordered.len(), ORDERED_HEADERS_SOFT_CAP);
    assert_eq!(st.header_walk.checkpoints().len(), 1);
    assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
    assert!(wants_lookahead(&st));
    log_status(&mut st, &hub, 50_000);
    assert!(
        !st.header_walk.announced_done,
        "peers still advertise headers past the candidate"
    );
    let tip = st.header_walk.tip_height();
    st.max_peer_height = tip;
    log_status(&mut st, &hub, tip);
    assert!(
        !st.header_walk.announced_done,
        "advertised height alone does not end the walk"
    );
    st.slots[0].peer_height = tip;
    log_status(&mut st, &hub, tip);
    assert!(
        st.header_walk.announced_done,
        "the done line fires once no connected peer is ahead of the walk"
    );
    log_status(&mut st, &hub, tip);
    assert!(st.header_walk.announced_done);
}

#[test]
fn a_taller_peer_that_cannot_extend_the_candidate_leaves_the_walk() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-quiet");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let (mut tall, mut rx) = slot(0);
    tall.peer_height = 100_000;
    let mut st = IbdWorkState::new(vec![tall], Some(gen), Some(0));
    // A full queue still asks while a peer is ahead and the next header
    // is not indexed.
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![good]);
    assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
    assert!(
        wants_lookahead(&st),
        "an advertisement past the walk keeps the lane on"
    );

    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![]);
    assert!(
        !wants_lookahead(&st),
        "one empty reply from a taller peer ends the walk"
    );
    assert!(
        rx.try_recv().is_err(),
        "the walk does not ask that peer again"
    );
    log_status(&mut st, &hub, 100_000);
    assert!(st.header_walk.announced_done);

    blocks_inv(&mut st, &hub, 0, vec![good.block_hash()]);
    assert!(
        !wants_lookahead(&st),
        "announcing a header the walk holds does not put the peer back"
    );
    assert!(rx.try_recv().is_err());

    blocks_inv(
        &mut st,
        &hub,
        0,
        vec![mine(good.block_hash(), 2).block_hash()],
    );
    assert!(
        wants_lookahead(&st),
        "a later block announcement puts the peer back on the walk"
    );
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })));

    apply(&mut st, &hub, 0, vec![]);
    assert!(!wants_lookahead(&st));
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::Dead {
            peer: 0,
            reason: "drop".into(),
        },
        &AtomicU32::new(0),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        None,
    );
    st.slots[0].alive = true;
    assert!(
        wants_lookahead(&st),
        "a redialed peer is a candidate until they fail once"
    );
}

#[test]
fn a_short_lighter_fork_does_not_keep_the_walk_asking() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-light");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let fork = mine(gen, 2);
    let (mut tall, mut rx) = slot(0);
    tall.peer_height = 100_000;
    let mut st = IbdWorkState::new(vec![tall], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![good]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![fork]);
    assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
    assert!(
        !wants_lookahead(&st),
        "a short fork that does not beat the candidate ends the walk"
    );
    assert!(rx.try_recv().is_err());
}

/// One peer advertised a height no chain has. Once the walk is at the
/// confirmed tip and that peer cannot extend it, IBD is caught up.
#[test]
fn a_false_peer_height_does_not_hold_ibd_at_the_tip() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-exit");
    hub.ensure_genesis().unwrap();
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(2, op_true.clone(), vec![]).unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let third = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        time,
        3,
        op_true.clone(),
        vec![],
    );
    let third_hash = third.block_hash();
    let fourth = rbitcoin_consensus::mine_regtest_paying(third_hash, time + 1, 4, op_true, vec![]);
    let (mut liar, mut liar_rx) = slot(0);
    liar.peer_height = 100_000;
    let (mut honest, mut honest_rx) = slot(1);
    honest.peer_height = 2;
    let mut st = IbdWorkState::new(vec![liar, honest], hub.tip_hash(), Some(2));
    assert_eq!(st.max_peer_height, 100_000);

    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut liar_rx), 1);
    assert_eq!(
        peer_horizon(&st),
        100_000,
        "a peer still on the walk sets the progress horizon"
    );
    apply(&mut st, &hub, 0, vec![third.header]);
    assert_eq!(st.header_walk.tip_height(), 3);
    hub.accept_block(third).unwrap();
    assert_eq!(hub.tip_height(), Some(3));
    assert!(
        !rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, 3),
        "the advertised height is still a candidate"
    );

    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut liar_rx), 1);
    apply(&mut st, &hub, 0, vec![]);
    assert!(!wants_lookahead(&st));
    st.ordered.clear();
    st.ordered_set.clear();
    assert!(
        rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, 3),
        "no peer can extend the walk past the confirmed tip"
    );
    assert_eq!(st.max_peer_height, 100_000);
    assert_eq!(
        peer_horizon(&st),
        3,
        "a retired peer's advertised height leaves the progress horizon"
    );

    // The honest peer's start height is below the walk. A block inv is
    // still a header it has and we do not.
    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlocksInv {
            peer: 1,
            hashes: vec![fourth.block_hash()],
        },
        &AtomicU32::new(0),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        None,
    );
    assert!(send_getheaders(&mut st, &hub).unwrap());
    match honest_rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => {
            assert_eq!(locator[0], third_hash, "the ask starts at the walk tip");
        }
        Ok(_) => panic!("expected getheaders"),
        Err(_) => panic!("the announcing peer was not asked for headers"),
    }
    assert_eq!(drain_getheaders(&mut liar_rx), 0);
    apply(&mut st, &hub, 1, vec![fourth.header]);
    assert_eq!(st.header_walk.tip_height(), 4);
    assert_eq!(peer_horizon(&st), 4);
    assert!(st.ordered_set.contains(&fourth.block_hash()));
    assert!(
        !rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, 3),
        "the announced block is still owed"
    );
}

/// Restart on a validated tip. No new checkpoint has been built, and one
/// peer advertises a height no chain has. IBD is caught up once that
/// peer fails to extend the stored tip.
#[test]
fn a_restarted_tip_exits_once_the_false_height_fails() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-restart-tip");
    hub.ensure_genesis().unwrap();
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(2, op_true, vec![]).unwrap();
    let tip = hub.tip_height().unwrap();
    let (mut liar, mut liar_rx) = slot(0);
    liar.peer_height = 100_000;
    let (mut honest, _honest_rx) = slot(1);
    honest.peer_height = tip;
    let mut st = IbdWorkState::new(vec![liar, honest], hub.tip_hash(), Some(tip));
    assert_eq!(st.max_peer_height, 100_000);

    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut liar_rx), 1);
    assert!(
        !rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, tip),
        "the advertised height is still a candidate"
    );
    apply(&mut st, &hub, 0, vec![]);
    assert!(!wants_lookahead(&st));
    assert!(st.ordered.is_empty());
    assert!(
        rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, tip),
        "the stored tip is caught up once no peer can extend it"
    );
    assert_eq!(st.max_peer_height, 100_000);
}

/// Several peers advertised a height no chain has (#1157). Each fails
/// to extend the stored tip once. Their later announcements of blocks this
/// node already has do not put them back on the walk, so IBD stays caught
/// up instead of waiting for each one to be asked again.
#[test]
fn known_block_invs_from_false_height_peers_keep_ibd_caught_up() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-known-inv");
    hub.ensure_genesis().unwrap();
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(2, op_true.clone(), vec![]).unwrap();
    let tip = hub.tip_height().unwrap();
    let tip_hash = hub.tip_hash().unwrap();
    let below_tip = hub.header_of(&tip_hash).unwrap().prev_blockhash;
    let mut slots = Vec::new();
    let mut rxs = Vec::new();
    for id in 0..3 {
        let (mut liar, rx) = slot(id);
        liar.peer_height = 100_000;
        slots.push(liar);
        rxs.push(rx);
    }
    let mut st = IbdWorkState::new(slots, Some(tip_hash), Some(tip));

    for _ in 0..3 {
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let asked = rxs
            .iter_mut()
            .position(|rx| drain_getheaders(rx) == 1)
            .expect("one peer is asked");
        apply(&mut st, &hub, asked, vec![]);
    }
    assert!(!wants_lookahead(&st));
    assert!(rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, tip));

    for id in 0..3 {
        blocks_inv(&mut st, &hub, id, vec![tip_hash]);
        blocks_inv(&mut st, &hub, id, vec![below_tip, tip_hash]);
    }
    assert!(
        !wants_lookahead(&st),
        "an announced block this node holds is no evidence of a taller chain"
    );
    assert_eq!(st.header_walk.challenge, None);
    assert!(
        rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, tip),
        "catch-up still exits at the tip"
    );
    assert!(!send_getheaders(&mut st, &hub).unwrap());

    // A new block reaches every peer at once. Each announces it before its
    // header lands, so all three are back on the walk. Each is asked once
    // more, fails to extend it, and catch-up exits again.
    let time = hub.tip_header().unwrap().time + 1;
    let next = rbitcoin_consensus::mine_regtest_paying(tip_hash, time, 3, op_true, vec![]);
    for id in 0..3 {
        blocks_inv(&mut st, &hub, id, vec![tip_hash, next.block_hash()]);
    }
    assert!(
        wants_lookahead(&st),
        "a block this node lacks still puts the announcer back on the walk"
    );
    let mut asks = 0;
    let mut have_next = false;
    while wants_lookahead(&st) && asks < 6 {
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let asked = rxs
            .iter_mut()
            .position(|rx| drain_getheaders(rx) == 1)
            .expect("one peer is asked");
        let reply = if have_next { vec![] } else { vec![next.header] };
        have_next = true;
        apply(&mut st, &hub, asked, reply);
        asks += 1;
    }
    assert_eq!(
        asks, 4,
        "the header, then one empty reply per re-armed peer"
    );
    assert_eq!(st.header_walk.tip_height(), tip + 1);
    hub.accept_block(next).unwrap();
    st.ordered.clear();
    st.ordered_set.clear();
    assert!(
        rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, tip + 1),
        "catch-up exits at the new tip"
    );
}

/// A block found after connect is written from the announcing peer.
/// That peer's `version.start_height` is still the old tip, so nobody
/// looks taller than the stored path. The one ask still goes to them.
#[test]
fn block_inv_writes_the_next_header_from_the_stored_tip() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-refill-at-tip");
    hub.ensure_genesis().unwrap();
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(2, op_true.clone(), vec![]).unwrap();
    let tip = hub.tip_height().unwrap();
    let tip_hash = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let next = rbitcoin_consensus::mine_regtest_paying(tip_hash, time, 3, op_true, vec![]);
    let (mut liar, mut liar_rx) = slot(0);
    liar.peer_height = 100_000;
    let (mut honest, mut honest_rx) = slot(1);
    honest.peer_height = tip;
    let mut st = IbdWorkState::new(vec![liar, honest], Some(tip_hash), Some(tip));

    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut liar_rx), 1);
    apply(&mut st, &hub, 0, vec![]);
    assert!(!wants_lookahead(&st));

    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlocksInv {
            peer: 1,
            hashes: vec![next.block_hash()],
        },
        &AtomicU32::new(0),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        None,
    );
    assert!(send_getheaders(&mut st, &hub).unwrap());
    match honest_rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => {
            assert_eq!(locator[0], tip_hash, "the ask starts at the stored tip");
        }
        Ok(_) => panic!("expected getheaders"),
        Err(_) => panic!("the peer at the stored tip was not asked"),
    }
    let before = hub.query.store().header_count();
    apply(&mut st, &hub, 1, vec![next.header]);
    assert_eq!(st.header_walk.tip_height(), tip + 1);
    assert!(st.ordered_set.contains(&next.block_hash()));
    assert!(hub.query.store().header_count() > before);
    assert_eq!(drain_getheaders(&mut liar_rx), 0);
    assert!(
        !send_getheaders(&mut st, &hub).unwrap(),
        "the written header is not asked for again"
    );
    assert!(!rbitcoin_ibd::ibd::exit::ibd_caught_up(&st, tip));
}

/// The header peer's connect-time height is the walk tip and the queue
/// is full. Their block inv is still a getheaders, on this poll.
#[test]
fn a_reserved_peer_block_inv_is_asked_with_a_full_queue() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-reserved-inv");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (mut peer, mut rx) = slot(0);
    peer.peer_height = 100;
    let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut rx), 1);
    let _ = take_header_ask(&mut st, 0);
    assert_eq!(st.header_walk.reserved, Some(0));
    st.header_walk.tip.height = 100;
    assert!(
        !wants_lookahead(&st),
        "connect-time height is not past the walk"
    );
    assert_eq!(st.ordered.len(), ORDERED_HEADERS_SOFT_CAP);

    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlocksInv {
            peer: 0,
            hashes: vec![BlockHash::from_byte_array([7u8; 32])],
        },
        &AtomicU32::new(0),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        None,
    );
    assert_eq!(
        st.header_walk.challenge,
        Some(0),
        "the reserved header peer's inv is still a challenge"
    );
    assert!(
        matches!(
            header_poll(
                &st,
                HeaderPollIn {
                    live: st.ordered_set.len(),
                    need_ready_headroom: false,
                    lag: 0,
                    min_cache: 8192,
                    fan: 0,
                },
            ),
            HeaderPoll::Ask
        ),
        "a full queue does not hold the announced header"
    );
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })),
        "the announcing peer was asked for headers"
    );
}

/// One ask from the stored tip. An accepted batch is written and
/// checkpointed. A header already indexed is appended and not asked for.
/// On that same hub, a second ask at one confirmed tip reuses the
/// confirmed-chain tail. A same-height tip hash, then a taller tip, each
/// rebuild it.
#[test]
fn a_seeded_header_walk_stores_drains_and_refills() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-seeded");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let first = mine(gen, 1);
    let second = mine(first.block_hash(), 2);

    let (s0, mut rx0) = slot(0);
    let (s1, mut rx1) = slot(1);
    let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        st.header_walk.origin,
        "the first ask starts the walk at the stored tip"
    );
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    rbitcoin_log::capture_logs(true);
    log_status(&mut st, &hub, 50_000);
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        logs.iter()
            .any(|(_, line)| line.contains("ibd: headers height=")),
        "the status line starts with the stored tip"
    );
    let asked = st.header_walk.walk.peer.expect("walk lane");
    let front = if asked == 0 {
        locator_front(&mut rx0)
    } else {
        locator_front(&mut rx1)
    };
    assert_eq!(front, Some(gen), "the first locator is the stored tip");
    let before = hub.query.store().header_count();
    apply(&mut st, &hub, asked, vec![first, second]);
    assert!(
        hub.query.store().header_count() > before,
        "an accepted batch is written"
    );
    assert!(st.ordered_set.contains(&second.block_hash()));
    assert_eq!(st.header_walk.tip_hash(), Some(second.block_hash()));

    st.ordered.clear();
    st.ordered_set.clear();
    st.ordered.push_back(gen);
    st.ordered_set.insert(gen);
    st.hash_height.insert(gen, 0);
    st.height_to_hash.remove(&1);
    st.height_to_hash.remove(&2);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let ask = st.header_walk.walk.peer.expect("one ask");
    let front = if ask == 0 {
        locator_front(&mut rx0)
    } else {
        locator_front(&mut rx1)
    };
    assert_eq!(
        front,
        Some(gen),
        "a missing next header is asked from the stored tip, not the walk"
    );
    let other = if ask == 0 {
        rx1.try_recv()
    } else {
        rx0.try_recv()
    };
    assert!(other.is_err(), "a second peer is not asked in parallel");

    let _ = take_header_ask(&mut st, ask);
    let stored = BlockHash::from_byte_array([0x44; 32]);
    st.height_to_hash.insert(1, stored);
    st.hash_height.insert(stored, 1);
    st.height_to_hash.insert(2, second.block_hash());
    st.hash_height.insert(second.block_hash(), 2);
    st.slots[0].peer_height = st.header_walk.tip_height();
    st.slots[1].peer_height = st.header_walk.tip_height();
    assert!(!send_getheaders(&mut st, &hub).unwrap());
    assert!(st.ordered_set.contains(&stored));
    assert!(st.ordered_set.contains(&second.block_hash()));
    assert!(rx0.try_recv().is_err());
    assert!(rx1.try_recv().is_err());
    confirmed_tail_follows_the_published_tip(&hub);
}

/// Same hub as the seeded walk. Two asks share one confirmed tail. A
/// same-height hash, then a taller tip, each rebuild it.
fn confirmed_tail_follows_the_published_tip(hub: &ChainHub) {
    let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(2, script.clone(), vec![]).unwrap();
    let tip = hub.tip_hash().unwrap();
    let tip_h = hub.tip_height().unwrap();
    let genesis = hub.params.genesis_hash;
    let ancestor = hub
        .query
        .locator_hashes()
        .unwrap()
        .into_iter()
        .find(|hash| *hash != tip && *hash != genesis)
        .expect("the confirmed chain locator has an ancestor between tip and genesis");
    let (peer, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(tip), Some(tip_h));
    let ahead = BlockHash::from_byte_array([0xab; 32]);
    st.ordered.push_back(ahead);
    st.ordered_set.insert(ahead);
    st.hash_height.insert(ahead, tip_h.saturating_add(100));
    assert!(st.ordered.len() < ORDERED_HEADERS_SOFT_CAP);
    assert!(send_getheaders(&mut st, hub).unwrap());
    let first = take_locator(&mut rx);
    assert_eq!(
        first.first().copied(),
        Some(ahead),
        "a queue with room asks from the stored path tip"
    );
    assert!(
        first.contains(&ancestor),
        "the confirmed ancestor stays in the locator"
    );
    assert!(first.contains(&tip));
    same_tip_reuses_the_tail(&mut st, hub, &mut rx, &first);
    let same_h_tip = same_height_rebuilds_the_tail(&mut st, hub, &mut rx, tip, tip_h, ahead);
    taller_tip_rebuilds_the_tail(&mut st, hub, &mut rx, &script, same_h_tip, ahead);
}

fn same_tip_reuses_the_tail(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    rx: &mut mpsc::UnboundedReceiver<PeerCmd>,
    first: &[BlockHash],
) {
    assert_ne!(take_header_ask(st, 0), HeaderAsk::Unsolicited);
    let before = rbitcoin_query::header_lookup_count();
    assert!(send_getheaders(st, hub).unwrap());
    let second_ask = take_locator(rx);
    assert_eq!(
        rbitcoin_query::header_lookup_count().saturating_sub(before),
        0,
        "a second ask at the same confirmed tip does not walk the header store"
    );
    assert_eq!(second_ask, first);
}

fn same_height_rebuilds_the_tail(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    rx: &mut mpsc::UnboundedReceiver<PeerCmd>,
    tip: BlockHash,
    tip_h: u32,
    ahead: BlockHash,
) -> BlockHash {
    hub.invalidate_block(tip).unwrap();
    assert_eq!(hub.tip_height(), Some(tip_h - 1));
    let alt_script = bitcoin::ScriptBuf::from_bytes(vec![0x52]);
    hub.generate_to_script(1, alt_script, vec![]).unwrap();
    let same_h_tip = hub.tip_hash().unwrap();
    let published = hub.query.published_tip().expect("published tip");
    assert_eq!(hub.tip_height(), Some(tip_h));
    assert_eq!(published.height, tip_h);
    assert_eq!(published.hash, same_h_tip.to_byte_array());
    assert_ne!(same_h_tip, tip);
    assert_ne!(take_header_ask(st, 0), HeaderAsk::Unsolicited);
    let before = rbitcoin_query::header_lookup_count();
    assert!(send_getheaders(st, hub).unwrap());
    let reorged = take_locator(rx);
    assert!(
        rbitcoin_query::header_lookup_count() > before,
        "a same-height tip hash rebuilds the tail"
    );
    assert_eq!(reorged.first().copied(), Some(ahead));
    assert!(
        reorged.contains(&same_h_tip),
        "the rebuilt tail names the replacement tip"
    );
    let tail = st
        .confirmed_locator_tail
        .as_ref()
        .expect("the same-height ask stored a tail");
    assert_eq!(tail.height, Some(tip_h));
    assert_eq!(tail.hash, Some(*same_h_tip.as_byte_array()));
    assert!(tail.hashes.contains(&same_h_tip));
    assert!(
        !tail.hashes.contains(&tip),
        "the replaced tip hash leaves the confirmed tail"
    );
    same_h_tip
}

fn taller_tip_rebuilds_the_tail(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    rx: &mut mpsc::UnboundedReceiver<PeerCmd>,
    script: &bitcoin::ScriptBuf,
    same_h_tip: BlockHash,
    ahead: BlockHash,
) {
    hub.generate_to_script(1, script.clone(), vec![]).unwrap();
    let new_tip = hub.tip_hash().unwrap();
    assert_ne!(new_tip, same_h_tip);
    assert_ne!(take_header_ask(st, 0), HeaderAsk::Unsolicited);
    let before = rbitcoin_query::header_lookup_count();
    assert!(send_getheaders(st, hub).unwrap());
    let taller = take_locator(rx);
    assert!(
        rbitcoin_query::header_lookup_count() > before,
        "a changed confirmed tip rebuilds the tail"
    );
    assert_eq!(taller.first().copied(), Some(ahead));
    assert!(
        taller.contains(&new_tip),
        "the rebuilt tail names the new confirmed tip"
    );
}

fn locator_front(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> Option<BlockHash> {
    match rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => locator.first().copied(),
        _ => None,
    }
}

fn shrink_queue(st: &mut IbdWorkState, keep: usize) {
    while st.ordered.len() > keep {
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
    }
}

fn take_locator(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> Vec<BlockHash> {
    match rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => locator,
        _ => panic!("expected one getheaders"),
    }
}

/// Walk tip is `first` (height 1). Queue tail height is 0, so the walk is ahead.
fn walk_ahead_of_a_short_queue(
    label: &str,
    keep: usize,
    peers: usize,
) -> (
    rbitcoin_query::testutil::TempDir,
    ChainHub,
    IbdWorkState,
    Vec<mpsc::UnboundedReceiver<PeerCmd>>,
    Header,
    BlockHash,
) {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let first = mine(gen, 1);
    let mut rxs = Vec::new();
    let mut slots = Vec::new();
    for id in 0..peers {
        let (slot_i, rx) = slot(id);
        slots.push(slot_i);
        rxs.push(rx);
    }
    let mut st = IbdWorkState::new(slots, Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    for rx in &mut rxs {
        let _ = rx.try_recv();
    }
    apply(&mut st, &hub, 0, vec![first]);
    shrink_queue(&mut st, keep);
    let tail = st.ordered.back().copied().unwrap();
    st.hash_height.insert(tail, 0);
    (dir, hub, st, rxs, first, tail)
}

#[test]
fn empty_queue_reseeds_stored_path_before_the_tip() {
    let (_dir, hub, mut st, mut rxs, first, _tail) =
        walk_ahead_of_a_short_queue("header-walk-reseed", 1, 2);
    let second = mine(first.block_hash(), 2);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    for rx in &mut rxs {
        let _ = rx.try_recv();
    }
    apply(&mut st, &hub, 0, vec![second]);
    assert_eq!(st.header_walk.tip_height(), 2);
    st.ordered.clear();
    st.ordered_set.clear();
    let stored = BlockHash::from_byte_array([0x44; 32]);
    st.height_to_hash.insert(1, stored);
    st.hash_height.insert(stored, 1);
    st.height_to_hash.remove(&2);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        st.ordered_set.contains(&stored),
        "headers still on the work path go back on the queue"
    );
    let mut fronts = Vec::new();
    for rx in &mut rxs {
        if let Some(h) = locator_front(rx) {
            fronts.push(h);
        }
    }
    assert!(
        fronts.contains(&stored),
        "the ask starts at the stored tip so the missing header can be queued: {fronts:?}"
    );
}

#[test]
fn missing_next_header_asks_from_the_stored_tip() {
    let (_dir, hub, mut st, mut rxs, first, tail) =
        walk_ahead_of_a_short_queue("header-walk-missing", 20_000, 1);
    st.height_to_hash.remove(&1);
    assert_ne!(tail, first.block_hash());
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(
        locator_front(&mut rxs[0]),
        Some(tail),
        "a missing next header is asked from the stored tip, not the walk"
    );
}

#[test]
fn indexed_next_header_is_appended_without_an_ask() {
    let (_dir, hub, mut st, mut rxs, first, _tail) =
        walk_ahead_of_a_short_queue("header-walk-indexed", 100, 1);
    st.slots[0].peer_height = st.header_walk.tip_height();
    assert!(!send_getheaders(&mut st, &hub).unwrap());
    assert!(st.ordered_set.contains(&first.block_hash()));
    assert!(rxs[0].try_recv().is_err());
}

#[test]
fn caught_up_walk_reply_is_stored() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-caught");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let first = mine(gen, 1);
    let second = mine(first.block_hash(), 2);
    let (slot0, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![slot0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![first]);
    assert_eq!(st.header_walk.tip_hash(), Some(first.block_hash()));

    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    let before = hub.query.store().header_count();
    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let queued = st.ordered.len();
    apply(&mut st, &hub, 0, vec![second]);
    assert!(
        hub.query.store().header_count() > before,
        "a reply that continues the stored walk tip is written"
    );
    assert!(st.ordered.len() > queued);
    assert_eq!(st.header_walk.tip_hash(), Some(second.block_hash()));
}

#[test]
fn status_line_names_the_stored_height_and_the_queue() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-status");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let first = mine(gen, 1);
    let (slot0, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![slot0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![first]);
    let tail = st.ordered.back().copied().unwrap();
    st.hash_height.insert(tail, 76_000);
    rbitcoin_log::capture_logs(true);
    log_status(&mut st, &hub, 200_000);
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let line = logs
        .iter()
        .find_map(|(_, line)| line.contains("ibd: headers height=").then_some(line))
        .expect("status line");
    assert!(
        line.contains("stored=76000"),
        "the stored path is on the status line: {line}"
    );
    assert!(
        line.contains(&format!("queue={}", ORDERED_HEADERS_SOFT_CAP)),
        "the queue length is on the status line: {line}"
    );
    assert!(line.contains("phase=walk"), "{line}");
}

#[test]
fn short_chain_rewinds_and_the_next_peer_is_followed() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-2");
    hub.ensure_genesis().unwrap();
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 840_000,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: BlockHash::from_byte_array([0xab; 32]),
            min_work_be: [0xff; 32],
        }),
    };
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let b1 = mine(gen, 11);
    let b2 = mine(b1.block_hash(), 12);
    let b3 = mine(b2.block_hash(), 13);
    let (s0, _rx0) = slot(0);
    let (s1, _rx1) = slot(1);
    let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
    fill_queue(&mut st);
    let before = hub.query.store().header_count();

    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1, a2]);
    assert_eq!(hub.query.store().header_count(), before + 2);
    log_status(&mut st, &hub, 50_000);
    assert!(!st.header_walk.proven, "work is still below the floor");
    assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
    plant_on_queue(&mut st, a1.block_hash(), 1);
    plant_on_queue(&mut st, a2.block_hash(), 2);

    apply(&mut st, &hub, 0, vec![]);
    assert_eq!(
        st.header_walk.tip_hash(),
        Some(a2.block_hash()),
        "one peer's empty does not abandon the candidate"
    );
    apply(&mut st, &hub, 1, vec![]);
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    log_status(&mut st, &hub, 50_000);
    assert!(!st.header_walk.announced_done);
    assert!(!st.ordered_set.contains(&a1.block_hash()));
    assert!(!st.ordered_set.contains(&a2.block_hash()));
    assert!(hub
        .query
        .get_header_by_hash(a1.block_hash().as_byte_array())
        .unwrap()
        .is_some());
    assert!(hub
        .query
        .get_header_by_hash(a2.block_hash().as_byte_array())
        .unwrap()
        .is_some());

    while st.ordered.len() > 10 {
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
    }
    apply(&mut st, &hub, 1, vec![b1, b2, b3]);
    assert_eq!(st.header_walk.tip_hash(), Some(b3.block_hash()));
    assert!(st.ordered_set.contains(&b3.block_hash()));
    assert!(hub
        .query
        .get_header_by_hash(a2.block_hash().as_byte_array())
        .unwrap()
        .is_some());
    assert_eq!(hub.query.store().header_count(), before + 5);
}

fn skips(hub: &ChainHub, height: u32, hash: &[u8; 32]) -> bool {
    hub.milestone
        .skips_scripts(height, hash, |h| hub.query.milestone_header_at(h))
}

fn fill_to_cap(st: &mut IbdWorkState) {
    let mut i = st.ordered.len();
    while st.ordered.len() < ORDERED_HEADERS_SOFT_CAP {
        let mut b = [0xee; 32];
        b[28..32].copy_from_slice(&(i as u32).to_le_bytes());
        let h = BlockHash::from_byte_array(b);
        st.ordered.push_back(h);
        st.ordered_set.insert(h);
        i += 1;
    }
}

#[test]
fn milestone_checkpoint_opens_script_skip_without_the_lookahead_headers() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-3");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    let h3 = mine(h2.block_hash(), 3);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 2,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: h2.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    apply(&mut st, &hub, 0, vec![h1]);
    let after_queue = hub.query.store().header_count();
    fill_to_cap(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![h2, h3]);

    assert_eq!(
        hub.query.store().header_count(),
        after_queue + 2,
        "an accepted batch is written"
    );
    assert!(hub
        .query
        .get_header_by_hash(h2.block_hash().as_byte_array())
        .unwrap()
        .is_some());
    assert!(st.ordered_set.contains(&h1.block_hash()));
    assert!(
        skips(&hub, 1, h1.block_hash().as_byte_array()),
        "the queued block skips when the checkpoint hash is the anchor"
    );
    assert!(!skips(&hub, 1, &[0x44; 32]));
    assert!(
        !skips(&hub, 2, &[0x55; 32]),
        "a different hash at the milestone height does not skip"
    );
}

#[test]
fn heavier_chain_replaces_checkpoints_and_a_cheap_fork_is_not_stored() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-4");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let c2 = mine(a1.block_hash(), 21);
    let c3 = mine(c2.block_hash(), 22);
    let c4 = mine(c3.block_hash(), 23);
    let c5 = mine(c4.block_hash(), 24);
    let light = mine(gen, 31);
    let less = mine(a1.block_hash(), 41);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 2,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: a2.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    apply(&mut st, &hub, 0, vec![a1]);
    fill_to_cap(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2]);
    plant_on_queue(&mut st, a2.block_hash(), 2);
    let before = hub.query.store().header_count();
    hub.set_minimum_chain_work(Some([0xff; 32]));

    apply(&mut st, &hub, 0, vec![c2, c3, c4, c5]);
    assert_eq!(st.header_walk.tip_hash(), Some(c5.block_hash()));
    assert!(!st.ordered_set.contains(&a2.block_hash()));
    assert_eq!(hub.query.store().header_count(), before + 4);
    assert!(st.ordered_set.contains(&c5.block_hash()));

    let after_heavy = hub.query.store().header_count();
    apply(&mut st, &hub, 0, vec![light]);
    apply(&mut st, &hub, 0, vec![less]);
    assert_eq!(hub.query.store().header_count(), after_heavy);
    assert_eq!(st.header_walk.tip_hash(), Some(c5.block_hash()));
    assert!(hub
        .query
        .get_header_by_hash(light.block_hash().as_byte_array())
        .unwrap()
        .is_none());
    assert!(hub
        .query
        .get_header_by_hash(less.block_hash().as_byte_array())
        .unwrap()
        .is_none());
    assert!(hub
        .query
        .get_header_by_hash(a2.block_hash().as_byte_array())
        .unwrap()
        .is_some());
}

#[test]
fn queue_stores_a_reply_that_ends_on_the_checkpoint() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-5");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let later = mine(good.block_hash(), 2);
    let miss = mine(gen, 9);
    let (s0, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    let before = hub.query.store().header_count();
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![good, later]);
    assert_eq!(hub.query.store().header_count(), before + 2);
    assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));

    st.ordered.clear();
    st.ordered_set.clear();
    st.height_to_hash.remove(&1);
    st.height_to_hash.remove(&2);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    match rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => {
            assert_eq!(
                locator[0], gen,
                "an empty queue asks for the headers after the stored tip"
            );
        }
        Ok(_) => panic!("expected getheaders"),
        Err(_) => panic!("peer was not asked for headers"),
    }
    apply(&mut st, &hub, 0, vec![good]);
    assert!(
        st.ordered_set.contains(&good.block_hash()),
        "a header short of the next checkpoint still fills the queue"
    );
    assert_eq!(hub.query.store().header_count(), before + 2);

    let after = hub.query.store().header_count();
    apply(&mut st, &hub, 0, vec![miss]);
    assert_eq!(hub.query.store().header_count(), after);
    assert!(
        !st.header_walk.dead_ends.contains(&miss.block_hash()),
        "a lighter valid chain stays available for a later heavier extension"
    );
    assert!(st.slots[0].alive);
    assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));
    assert!(hub
        .query
        .get_header_by_hash(miss.block_hash().as_byte_array())
        .unwrap()
        .is_none());
}

/// A connected peer's start height is not a hole once the walk is proved
/// at the confirmed tip. A proved walk that is still above that tip is.
#[test]
fn proved_walk_at_the_tip_ignores_a_tall_peer() {
    let (s0, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], None, Some(100));
    st.max_peer_height = 50_000;
    st.headers_done = true;
    st.header_walk.prove_through(100);
    assert!(
        !rbitcoin_ibd::ibd::exit::should_unlatch_headers_done(&st, 100),
        "a proved walk at the confirmed tip does not chase a connected peer"
    );
    st.header_walk.prove_through(150);
    assert!(
        rbitcoin_ibd::ibd::exit::should_unlatch_headers_done(&st, 100),
        "a proved walk above the confirmed tip still opens an empty queue"
    );
}

/// A batch that misses the checkpoint must not occupy the gap, and a
/// later batch that meets it must replace a short unproved queue.
#[test]
fn an_unproved_queue_does_not_hide_the_checkpoint() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-unproved");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let later = mine(good.block_hash(), 2);
    let miss = mine(gen, 9);
    let miss2 = mine(miss.block_hash(), 8);
    let (s0, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![good, later]);
    assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));

    st.ordered.clear();
    st.ordered_set.clear();
    st.height_to_hash.remove(&1);
    st.height_to_hash.remove(&2);

    apply(&mut st, &hub, 0, vec![miss, miss2]);
    assert!(
        !st.ordered_set.contains(&miss.block_hash()),
        "a window that misses the checkpoint must not occupy the gap"
    );
    assert!(!st.ordered_set.contains(&miss2.block_hash()));
    assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));

    apply(&mut st, &hub, 0, vec![miss]);
    assert!(
        st.ordered_set.contains(&miss.block_hash()),
        "a short refill still fills the queue before the next checkpoint"
    );
    assert!(send_getheaders(&mut st, &hub).unwrap());
    match rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => {
            assert!(
                locator.contains(&gen),
                "a peer that lacks the unproved tail must still be asked from the stored tip"
            );
        }
        Ok(_) => panic!("expected getheaders"),
        Err(_) => panic!("peer was not asked for headers"),
    }
    apply(&mut st, &hub, 0, vec![good, later]);
    assert!(
        st.ordered_set.contains(&good.block_hash()),
        "a batch that meets the checkpoint replaces the unproved queue"
    );
    assert!(!st.ordered_set.contains(&miss.block_hash()));
    assert_eq!(st.header_walk.tip_hash(), Some(later.block_hash()));
}

#[test]
fn restart_restores_the_checkpoint_skip_and_garbage_does_not() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-6");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    let h3 = mine(h2.block_hash(), 3);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 2,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: h2.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    apply(&mut st, &hub, 0, vec![h1]);
    fill_to_cap(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![h2, h3]);
    assert!(skips(&hub, 1, h1.block_hash().as_byte_array()));
    assert!(hub
        .query
        .get_header_by_hash(h2.block_hash().as_byte_array())
        .unwrap()
        .is_some());

    st.header_walk = HeaderWalk::default();
    hub.query.clear_milestone_path_above(0);
    assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));
    assert!(restore_adopt(&mut st, &hub));
    assert!(
        skips(&hub, 1, h1.block_hash().as_byte_array()),
        "the skip is on again from header.adopt without the look-ahead rows"
    );
    assert_eq!(
        st.header_walk.tip_header().map(|h| h.block_hash()),
        Some(h3.block_hash()),
        "restart keeps the tip header for the next look-ahead"
    );

    let base_h = st.header_walk.base_height;
    st.header_walk = HeaderWalk::default();
    hub.query.clear_milestone_path_above(0);
    st.height_to_hash
        .insert(base_h, BlockHash::from_byte_array([0x11; 32]));
    assert!(
        !restore_adopt(&mut st, &hub),
        "a base hash that is not on this chain is not restored"
    );
    assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));

    st.height_to_hash.remove(&base_h);
    assert!(restore_adopt(&mut st, &hub));
    assert!(st.header_walk.base_height > 0);
    let path = hub.query.store().path().join("header.adopt");
    assert_eq!(hub.best_header_height(), 3);
    on_confirmed_rewind(&mut st, &hub, 0);
    assert!(
        !path.exists(),
        "a reorg under the base deletes header.adopt"
    );
    hub.query.clear_milestone_path_above(0);
    assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));
    assert!(!restore_adopt(&mut st, &hub));

    st.header_walk = HeaderWalk::default();
    hub.query.clear_milestone_path_above(0);
    let path = hub.query.store().path().join("header.adopt");
    std::fs::write(&path, b"not-a-checkpoint-file").unwrap();
    assert!(!restore_adopt(&mut st, &hub));
    assert!(
        !skips(&hub, 1, h1.block_hash().as_byte_array()),
        "a file that does not parse does not skip scripts by height"
    );

    // A candidate retired on a failed block restarts at its parent.
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-retire");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let p1 = mine(gen, 61);
    let p2 = mine(p1.block_hash(), 62);
    let p3 = mine(p2.block_hash(), 63);
    let (s1, _rx1) = slot(1);
    let mut st = IbdWorkState::new(vec![s1], Some(gen), Some(0));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 1, vec![p1, p2, p3]);
    assert!(st.is_on_path(&p3.block_hash(), 3));
    retire_invalid(&mut st, &hub, p3.block_hash(), 3);
    st.header_walk = HeaderWalk::default();
    assert!(restore_adopt(&mut st, &hub));
    assert_eq!(st.header_walk.tip_hash(), Some(p2.block_hash()));
    assert_eq!(st.header_walk.tip_height(), 2);
    // Once a failed block is stored, a saved candidate above the confirmed
    // tip may build on it and is not restored.
    hub.note_failed_connect(p3.block_hash());
    st.header_walk = HeaderWalk::default();
    assert!(!restore_adopt(&mut st, &hub));
}

/// A failure stored at or below the saved walk's base is on no chain that
/// walk can take, so the walk is restored. One whose height is not found may
/// be on it.
#[test]
fn a_failure_below_the_saved_base_keeps_the_resume() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-resume-below");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine_block(gen, 1);
    hub.accept_block(b1.clone()).unwrap();
    let b2 = mine_block(b1.block_hash(), 2);
    hub.accept_block(b2.clone()).unwrap();
    let stale = mine(gen, 64);
    hub.ensure_header(&stale).unwrap();
    assert!(hub.note_failed_connect(stale.block_hash()));
    let (s2, _rx2) = slot(2);
    let mut st = IbdWorkState::new(vec![s2], hub.tip_hash(), hub.tip_height());
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let q3 = mine(b2.block_hash(), 65);
    let q4 = mine(q3.block_hash(), 66);
    apply(&mut st, &hub, 2, vec![q3, q4]);
    save_adopt(&st, &hub);
    st.header_walk = HeaderWalk::default();
    assert!(
        restore_adopt(&mut st, &hub),
        "a failure below the walk's base does not stop the resume"
    );
    assert_eq!(st.header_walk.tip_hash(), Some(q4.block_hash()));
    // A failure whose height is not found may be on it.
    assert!(hub.note_failed_connect(BlockHash::from_byte_array([0x5a; 32])));
    st.header_walk = HeaderWalk::default();
    assert!(!restore_adopt(&mut st, &hub));
}

#[test]
fn a_failed_adopt_still_notes_the_queued_path() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-renote");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 2,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: h2.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    apply(&mut st, &hub, 0, vec![h1, h2]);
    assert!(skips(&hub, 1, h1.block_hash().as_byte_array()));

    hub.query.clear_milestone_path_above(0);
    st.header_walk = HeaderWalk::default();
    assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));
    let path = hub.query.store().path().join("header.adopt");
    std::fs::write(&path, b"not-a-checkpoint-file").unwrap();
    assert!(!restore_adopt(&mut st, &hub));
    assert_eq!(
        hub.query.milestone_header_at(1),
        Some(h1.block_hash().to_byte_array()),
        "a queued header stays on the milestone path when header.adopt does not parse"
    );
    assert_eq!(
        hub.query.milestone_header_at(2),
        Some(h2.block_hash().to_byte_array())
    );
    assert!(skips(&hub, 1, h1.block_hash().as_byte_array()));

    hub.query.clear_milestone_path_above(0);
    std::fs::remove_file(&path).unwrap();
    assert!(!restore_adopt(&mut st, &hub));
    assert_eq!(
        hub.query.milestone_header_at(1),
        Some(h1.block_hash().to_byte_array()),
        "a missing header.adopt still notes the queued path"
    );

    hub.query.clear_milestone_path_above(0);
    st.height_to_hash
        .insert(2, BlockHash::from_byte_array([0x22; 32]));
    assert!(!restore_adopt(&mut st, &hub));
    assert_eq!(
        hub.query.milestone_header_at(1),
        Some(h1.block_hash().to_byte_array())
    );
    assert_eq!(
        hub.query.milestone_header_at(2),
        None,
        "a height that does not link to the previous header is not the milestone chain"
    );
    assert!(!skips(&hub, 1, h1.block_hash().as_byte_array()));
}

/// Two peers, one walk. The fast peer keeps headers until a short miss,
/// a heavier inv takes the reservation back, a lighter inv restores it,
/// and a low queue refills from that same peer. A miss that disconnects
/// needs both peers still eligible, which a retired challenger is not,
/// so that arc is a second chapter on this hub. One peer alone is a
/// third: nobody else can take the reservation.
#[test]
#[allow(clippy::cognitive_complexity)] // one hub, many reservation arms
fn two_peers_reserve_the_header_walk() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-reserve");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (mut slow, mut slow_rx) = slot(0);
    let (mut fast, mut fast_rx) = slot(1);
    slow.first_data_ms = 5_000;
    fast.first_data_ms = 50;
    let mut st = IbdWorkState::new(vec![slow, fast], Some(gen), Some(0));

    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(slow_rx.try_recv().is_err(), "the slower peer is not asked");
    assert!(
        matches!(fast_rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })),
        "the lowest time-to-first-byte peer takes the walk"
    );
    assert_eq!(st.header_walk.reserved, Some(1));

    let hash = {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&1u32.to_le_bytes());
        BlockHash::from_byte_array(b)
    };
    st.record_height(hash, 1);
    st.height_to_hash.insert(1, hash);
    st.ordered_set.insert(hash);
    st.ordered.push_back(hash);
    st.max_ordered_height = 1;
    st.body.mark_missing(hash);
    let cfg = rbitcoin_ibd::ibd::IbdConfig::for_test();
    let stats = rbitcoin_ibd::ibd::status::LoopStats::default();
    rbitcoin_ibd::ibd::assign::assign_work_ordered(
        &mut st,
        &hub,
        &cfg,
        &stats,
        rbitcoin_ibd::ibd::assign::AssignDepth::Full,
        None,
    );
    assert!(
        st.slots[0].in_flight.contains(&hash),
        "block getdata goes to the peer who is not walking headers"
    );
    assert!(
        !st.slots[1].in_flight.contains(&hash),
        "the reserved header peer is not given a block"
    );
    assert!(matches!(slow_rx.try_recv(), Ok(PeerCmd::GetData { .. })));
    assert!(fast_rx.try_recv().is_err());

    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::NotFound {
            peer: 0,
            hashes: vec![hash],
        },
        &AtomicU32::new(0),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        None,
    );
    rbitcoin_ibd::ibd::assign::assign_work_ordered(
        &mut st,
        &hub,
        &cfg,
        &stats,
        rbitcoin_ibd::ibd::assign::AssignDepth::Full,
        None,
    );
    assert!(
        st.slots[1].in_flight.contains(&hash),
        "the header peer takes a block the other peer does not have"
    );
    assert!(slow_rx.try_recv().is_err(), "notfound is not asked again");
    assert!(matches!(fast_rx.try_recv(), Ok(PeerCmd::GetData { .. })));
    let _ = st.slots[1].track_remove(&hash);
    st.inflight.remove(&hash);

    st.ordered.clear();
    st.ordered_set.clear();
    st.height_to_hash.remove(&1);
    st.hash_height.remove(&hash);
    fill_queue(&mut st);
    let _ = take_header_ask(&mut st, 1);

    let good = mine(gen, 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut fast_rx), 1);
    assert_eq!(drain_getheaders(&mut slow_rx), 0);
    apply(&mut st, &hub, 1, vec![good]);
    assert_eq!(st.header_walk.reserved, Some(1));

    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut fast_rx), 1);
    apply(&mut st, &hub, 1, vec![]);
    assert!(st.slots[1].alive, "less work does not disconnect");
    assert_eq!(drain_getheaders(&mut fast_rx), 0);
    assert_eq!(drain_getheaders(&mut slow_rx), 1);
    assert_eq!(st.header_walk.reserved, Some(0));

    let _ = take_header_ask(&mut st, 0);
    let fork_a = mine(gen, 2);
    let fork_b = mine(fork_a.block_hash(), 3);
    blocks_inv(&mut st, &hub, 1, vec![fork_b.block_hash()]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut slow_rx), 0);
    assert_eq!(drain_getheaders(&mut fast_rx), 1);
    apply(&mut st, &hub, 1, vec![fork_a, fork_b]);
    assert_eq!(st.header_walk.tip_hash(), Some(fork_b.block_hash()));
    assert_eq!(st.header_walk.reserved, Some(1));
    assert!(st.slots[0].alive);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut slow_rx), 0);
    assert_eq!(drain_getheaders(&mut fast_rx), 1);

    let _ = take_header_ask(&mut st, 1);
    let fork = mine(gen, 4);
    blocks_inv(&mut st, &hub, 0, vec![fork.block_hash()]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut slow_rx), 1);
    apply(&mut st, &hub, 0, vec![fork]);
    assert_eq!(st.header_walk.tip_hash(), Some(fork_b.block_hash()));
    assert_eq!(st.header_walk.reserved, Some(1));
    assert!(st.header_walk.walk_quiet.contains(&0));
    assert!(st.slots[0].alive);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut fast_rx), 1);
    assert_eq!(drain_getheaders(&mut slow_rx), 0);
    let _ = take_header_ask(&mut st, 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut fast_rx), 1);
    assert_eq!(drain_getheaders(&mut slow_rx), 0);

    let _ = take_header_ask(&mut st, 1);
    shrink_queue(&mut st, 100);
    let tail = st.ordered.back().copied().unwrap();
    st.hash_height.insert(tail, st.header_walk.tip_height());
    assert!(walk_ahead_of_queue(&st, &hub) || wants_lookahead(&st));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut fast_rx), 1);
    assert_eq!(drain_getheaders(&mut slow_rx), 0);
    assert_eq!(st.header_walk.reserved, Some(1));
    assert_eq!(st.header_walk.walk.peer, Some(1));

    // Both peers have to be eligible. The lighter challenger is retired.
    let (quiet, mut quiet_rx) = slot(2);
    let (mut busy, mut busy_rx) = slot(3);
    busy.in_flight.insert(BlockHash::from_byte_array([9u8; 32]));
    let quiet_addr = quiet.addr;
    let mut st = IbdWorkState::new(vec![quiet, busy], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut quiet_rx), 1);
    assert_eq!(drain_getheaders(&mut busy_rx), 0);
    age_header_ask(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(
        drain_getheaders(&mut quiet_rx),
        0,
        "one missed header ask skips that peer while another tall peer is up"
    );
    assert_eq!(drain_getheaders(&mut busy_rx), 1);
    assert!(st.slots.iter().any(|s| s.id == 2 && s.alive));
    age_header_ask(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(
        drain_getheaders(&mut quiet_rx),
        1,
        "the next miss moves the reservation back"
    );
    assert_eq!(drain_getheaders(&mut busy_rx), 0);
    age_header_ask(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        st.slots.iter().any(|s| s.id == 2 && !s.alive),
        "a second missed header ask disconnects that peer"
    );
    assert!(st
        .addr_cooldown
        .contains_key(&rbitcoin_net::NetAddr::from_socket(quiet_addr)));
    assert!(matches!(quiet_rx.try_recv(), Ok(PeerCmd::Shutdown)));
    assert_eq!(drain_getheaders(&mut busy_rx), 1);

    // The survivor already has a miss, so a fresh sole peer is required.
    let (only, mut rx) = slot(4);
    let addr = only.addr;
    let mut st = IbdWorkState::new(vec![only], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut rx), 1);
    age_header_ask(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(
        drain_getheaders(&mut rx),
        1,
        "the only tall peer is asked again after one miss"
    );
    assert!(st.slots[0].alive);
    age_header_ask(&mut st);
    assert!(!send_getheaders(&mut st, &hub).unwrap());
    assert!(!st.slots[0].alive);
    assert!(st
        .addr_cooldown
        .contains_key(&rbitcoin_net::NetAddr::from_socket(addr)));
    assert!(matches!(rx.try_recv(), Ok(PeerCmd::Shutdown)));

    // A fourth, because the header peer must hold the path: a block peer
    // that never announced a chain is asked for headers once. Its reply
    // forks below the path, so it is not asked for path blocks.
    let (mut head, mut head_rx) = slot(5);
    let (mut other, mut other_rx) = slot(6);
    let (mut short, _short_rx) = slot(7);
    // Asked once, and answered nothing yet.
    let (mut unknown, _unknown_rx) = slot(12);
    head.first_data_ms = 50;
    other.first_data_ms = 5_000;
    short.first_data_ms = 6_000;
    unknown.first_data_ms = 7_000;
    unknown.chain.note_probe_sent(Instant::now(), true);
    let mut st = IbdWorkState::new(vec![head, other, short, unknown], Some(gen), Some(0));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut head_rx), 1);
    let path = [mine(gen, 41), mine(mine(gen, 41).block_hash(), 42)];
    apply(&mut st, &hub, 5, path.to_vec());
    assert_eq!(st.header_walk.reserved, Some(5));
    let _ = take_header_ask(&mut st, 5);
    probe_unprobed_peer(&mut st, &hub);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(
        drain_getheaders(&mut other_rx),
        1,
        "the silent peer is asked once"
    );
    assert_eq!(drain_getheaders(&mut head_rx), 0);
    let fork = mine(gen, 43);
    apply(&mut st, &hub, 6, vec![fork, mine(fork.block_hash(), 46)]);
    // A short reply is everything that peer has: its chain ends at height 1.
    apply(&mut st, &hub, 7, vec![path[0]]);
    probe_unprobed_peer(&mut st, &hub);
    assert!(st.header_walk.probe.is_none(), "a peer is probed once");
    for h in &path {
        st.body.mark_missing(h.block_hash());
    }
    rbitcoin_ibd::ibd::assign::assign_work_ordered(
        &mut st,
        &hub,
        &cfg,
        &stats,
        rbitcoin_ibd::ibd::assign::AssignDepth::Full,
        None,
    );
    assert!(
        st.slots[1].in_flight.is_empty(),
        "a peer whose chain left the path below a block is not asked for it"
    );
    assert!(
        !st.slots[2].in_flight.contains(&path[1].block_hash()),
        "a peer whose whole chain ends below a block is not asked for it"
    );
    rbitcoin_ibd::ibd::assign::assign_work_ordered(
        &mut st,
        &hub,
        &cfg,
        &stats,
        rbitcoin_ibd::ibd::assign::AssignDepth::Full,
        None,
    );
    assert!(!st.slots[2].in_flight.contains(&path[1].block_hash()));
    assert!(
        may_serve(&st, 5, &path[1].block_hash()),
        "a peer that announced nothing does not keep the header peer from a block it showed"
    );
    assert!(
        [0, 3]
            .iter()
            .any(|&i| st.slots[i].in_flight.contains(&path[1].block_hash())),
        "the header peer, or a peer with no record, takes what no other peer holds"
    );

    // With no peer that holds the block by what it announced, a peer that
    // did not answer `notfound` is still asked.
    st.slots[0].chain.note_notfound(
        path[1].block_hash(),
        rbitcoin_ibd::ibd::peer_io::ibd_mono_ms(),
    );
    st.slots[2].chain.note_notfound(
        path[1].block_hash(),
        rbitcoin_ibd::ibd::peer_io::ibd_mono_ms(),
    );
    st.slots[3].chain.note_notfound(
        path[1].block_hash(),
        rbitcoin_ibd::ibd::peer_io::ibd_mono_ms(),
    );
    assert!(may_serve(&st, 6, &path[1].block_hash()));

    // A batch stored after one of its blocks failed is not planted, and does
    // not grow the candidate again.
    let late0 = mine(path[1].block_hash(), 44);
    let late = [late0, mine(late0.block_hash(), 45)];
    st.reorg.invalid.mark(late[0].block_hash().to_byte_array());
    let tip = st.header_walk.tip_hash();
    let (fks, work) = rbitcoin_ibd::ibd::events::prepare_header_store(&hub, &late);
    let added =
        rbitcoin_ibd::ibd::events::on_headers_batch(&mut st, &hub, 5, late.to_vec(), &fks, work);
    assert_eq!(added, 0);
    assert!(!st.ordered_set.contains(&late[1].block_hash()));
    assert_eq!(st.header_walk.tip_hash(), tip);

    // A fifth, on its own hub, because this node takes the forked peer's
    // chain: once the fork height is confirmed and leaves the path, that peer
    // holds the next path block again, also while a peer that announced
    // nothing is up.
    let (_dir5, hub5) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-taken");
    hub5.ensure_genesis().unwrap();
    let gen5 = hub5.tip_hash().unwrap();
    let (mut head, _head_rx) = slot(8);
    let (forked, _forked_rx) = slot(9);
    let (silent, _silent_rx) = slot(10);
    let (other_fork, _other_rx) = slot(11);
    head.first_data_ms = 50;
    let mut st = IbdWorkState::new(vec![head, forked, silent, other_fork], Some(gen5), Some(0));
    assert!(send_getheaders(&mut st, &hub5).unwrap());
    let lost0 = mine(gen5, 81);
    apply(&mut st, &hub5, 8, vec![lost0, mine(lost0.block_hash(), 82)]);
    let taken1 = mine_block(gen5, 1);
    let taken2 = mine_block(taken1.block_hash(), 2);
    apply(&mut st, &hub5, 9, vec![taken1.header, taken2.header]);
    let elsewhere = mine(gen5, 83);
    apply(
        &mut st,
        &hub5,
        11,
        vec![elsewhere, mine(elsewhere.block_hash(), 84)],
    );
    hub5.accept_block(taken1.clone()).unwrap();
    st.height_to_hash.remove(&1);
    st.height_to_hash.insert(2, taken2.block_hash());
    st.record_height(taken2.block_hash(), 2);
    st.body.mark_missing(taken2.block_hash());
    rbitcoin_ibd::ibd::assign::assign_work_ordered(
        &mut st,
        &hub5,
        &cfg,
        &stats,
        rbitcoin_ibd::ibd::assign::AssignDepth::Full,
        None,
    );
    assert!(
        may_serve(&st, 9, &taken2.block_hash()),
        "the peer whose chain this node took is asked again"
    );
    assert!(
        !may_serve(&st, 11, &taken2.block_hash()),
        "a peer that left where this node confirmed a different block has still left"
    );
    // With no peer that holds a block by what it announced, the header peer
    // is asked too.
    st.slots[1].chain.note_notfound(
        taken2.block_hash(),
        rbitcoin_ibd::ibd::peer_io::ibd_mono_ms(),
    );
    st.slots[2].chain.note_notfound(
        taken2.block_hash(),
        rbitcoin_ibd::ibd::peer_io::ibd_mono_ms(),
    );
    assert!(may_serve(&st, 8, &taken2.block_hash()));

    // A sixth, on its own hub, because a probe must say what a peer has. It
    // asks after the path top alone, and a reply on that top shows the whole
    // path. A peer that does not show it is asked from the confirmed tip,
    // where an empty reply is a chain that ends there. The probe is not a
    // walk answer, and a reply with a header the walk has not seen gets the
    // walk's own ask. An empty reply to a walk ask is a caught-up peer as well
    // as one behind, so that peer is probed again.
    let (_dir6, hub6) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-probe");
    hub6.ensure_genesis().unwrap();
    let gen6 = hub6.tip_hash().unwrap();
    let (mut head, mut head_rx) = slot(13);
    let (mut caught, mut caught_rx) = slot(14);
    let (mut behind, mut behind_rx) = slot(15);
    let (mut fallback, mut fallback_rx) = slot(26);
    let (mut side, mut side_rx) = slot(16);
    head.first_data_ms = 50;
    caught.first_data_ms = 5_000;
    behind.first_data_ms = 6_000;
    fallback.first_data_ms = 6_500;
    side.first_data_ms = 7_000;
    let mut st = IbdWorkState::new(
        vec![head, caught, behind, fallback, side],
        Some(gen6),
        Some(0),
    );
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    assert_eq!(drain_getheaders(&mut head_rx), 1);
    let path = [mine(gen6, 51), mine(mine(gen6, 51).block_hash(), 52)];
    apply(&mut st, &hub6, 13, path.to_vec());
    assert_eq!(st.header_walk.reserved, Some(13));
    let _ = take_header_ask(&mut st, 13);

    probe_unprobed_peer(&mut st, &hub6);
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    let locator = getheaders_locator(&mut caught_rx).expect("the caught-up peer is probed");
    assert_eq!(
        locator,
        vec![path[1].block_hash()],
        "the probe asks after the path top alone"
    );
    // An announcement that crosses the probe is not its reply.
    let stray = mine(BlockHash::from_byte_array([0x77; 32]), 53);
    apply(&mut st, &hub6, 14, vec![stray]);
    assert_eq!(
        st.header_walk.walk.peer,
        Some(14),
        "the probe ask stays open, so it can still expire"
    );
    // That stray batch went to the walk, which retired the peer from it.
    st.header_walk.walk_quiet.remove(&14);
    // At the top the peer has nothing after it, so it is asked again from
    // the tip.
    apply(&mut st, &hub6, 14, Vec::new());
    assert_eq!(st.header_walk.probe_open, None);
    assert!(
        !st.header_walk.walk_quiet.contains(&14),
        "a probe reply is not a walk answer"
    );
    assert_eq!(st.header_walk.reserved, Some(13));
    probe_unprobed_peer(&mut st, &hub6);
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    let locator = getheaders_locator(&mut caught_rx).expect("the peer is asked again");
    assert_eq!(locator.first(), Some(&gen6), "then from the confirmed tip");
    assert!(
        !st.slots[1].chain.probe_from_tip(),
        "and the probe after that asks after the top again"
    );
    apply(&mut st, &hub6, 14, path.to_vec());
    assert!(may_serve(&st, 14, &path[1].block_hash()));

    // A peer without the top answers from genesis: this node sends genesis
    // itself, Core the header after it. One that stops at or below the tip
    // is asked again from the tip, where an empty reply is a chain that ends
    // there.
    probe_unprobed_peer(&mut st, &hub6);
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    assert_eq!(getheaders_locator(&mut behind_rx).map(|l| l.len()), Some(1));
    apply(&mut st, &hub6, 15, vec![hub6.header_of(&gen6).unwrap()]);
    assert_eq!(st.header_walk.probe_open, None);
    assert!(st.slots[2].chain.probe_from_tip());
    probe_unprobed_peer(&mut st, &hub6);
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    assert!(getheaders_locator(&mut behind_rx).is_some());
    apply(&mut st, &hub6, 15, Vec::new());
    assert!(
        st.slots[2].chain.left_path_by(&st.height_to_hash, 1),
        "a peer with nothing above the tip does not hold a path block"
    );
    probe_unprobed_peer(&mut st, &hub6);
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    assert!(getheaders_locator(&mut fallback_rx).is_some());
    // A reply from genesis that already goes past the tip says what a probe
    // from the tip would.
    apply(&mut st, &hub6, 26, vec![mine(gen6, 55)]);
    assert_eq!(st.header_walk.probe_open, None);
    assert!(!st.slots[3].chain.probe_from_tip());
    assert!(st.slots[3].chain.left_path_by(&st.height_to_hash, 1));
    st.header_walk.challenge = None;

    // A reply on the path top shows the path below it. Its new header is one
    // the walk has not seen, so that peer gets the walk's own ask.
    probe_unprobed_peer(&mut st, &hub6);
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    assert!(getheaders_locator(&mut side_rx).is_some());
    apply(&mut st, &hub6, 16, vec![mine(path[1].block_hash(), 54)]);
    assert!(st.slots[4].chain.shows(&st.height_to_hash, 1));
    assert_eq!(st.header_walk.challenge, Some(16));
    st.header_walk.challenge = None;

    // A block inv's ask carries the path top, so an empty reply is a peer at
    // that top as well as one behind it.
    note_block_inv(&mut st, 14);
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    assert!(getheaders_locator(&mut caught_rx).is_some());
    apply(&mut st, &hub6, 14, Vec::new());
    assert!(
        may_serve(&st, 14, &path[1].block_hash()),
        "an empty walk reply does not take a caught-up peer off the path"
    );
    assert!(
        !st.slots[1].chain.probed(),
        "an empty walk reply is followed by a probe"
    );

    // A late reply to a walk ask could be read as the probe's, so a peer
    // with one out is neither picked nor asked.
    st.header_walk.walk.peer = None;
    st.header_walk.walk.at = None;
    st.header_walk.walk.prev_peer = Some(14);
    probe_unprobed_peer(&mut st, &hub6);
    assert_ne!(st.header_walk.probe, Some(14));
    st.header_walk.probe = Some(14);
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    assert_eq!(st.header_walk.probe, None);
    assert_ne!(st.header_walk.probe_open, Some(14));
    assert!(!st.slots[1].chain.probed(), "it is picked again later");
    // Neither is a peer with an expired walk ask that it has not answered,
    // after another peer's expiry took the lane's last slot for it.
    st.header_walk.walk.prev_peer = None;
    st.header_walk.header_misses.insert(14, 1);
    probe_unprobed_peer(&mut st, &hub6);
    assert_ne!(st.header_walk.probe, Some(14));
    st.header_walk.header_misses.clear();

    // An open probe keeps the lane until it is answered or expires, also
    // when the walk has nothing left to ask.
    for s in &mut st.slots {
        s.peer_height = 0;
    }
    st.header_walk.walk.peer = None;
    st.header_walk.walk.at = None;
    probe_unprobed_peer(&mut st, &hub6);
    assert_eq!(st.header_walk.probe, Some(14));
    assert!(send_getheaders(&mut st, &hub6).unwrap());
    assert_eq!(st.header_walk.probe_open, Some(14));
    let _ = send_getheaders(&mut st, &hub6);
    assert_eq!(
        st.header_walk.walk.peer,
        Some(14),
        "the probe keeps its lane"
    );
    // With header sync otherwise done, the poll still asks once the probe is
    // past its window, so the ask that expires it is sent.
    st.headers_done = true;
    let quiet = || HeaderPollIn {
        live: 0,
        need_ready_headroom: false,
        lag: 0,
        min_cache: 0,
        fan: 0,
    };
    assert!(matches!(header_poll(&st, quiet()), HeaderPoll::Wait));
    age_header_ask(&mut st);
    assert!(
        matches!(header_poll(&st, quiet()), HeaderPoll::Ask),
        "a probe past its window is polled"
    );
    let _ = send_getheaders(&mut st, &hub6);
    assert_eq!(
        st.header_walk.probe_open, None,
        "an unanswered probe expires"
    );

    // A seventh, on its own hub, because a rewind replaces the confirmed
    // blocks a peer's record took as its chain: that peer is not asked for
    // the new chain's blocks, and one that had shown the new chain, all of
    // it or only its top, is.
    let (_dir7, hub7) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-rewound");
    hub7.ensure_genesis().unwrap();
    let gen7 = hub7.tip_hash().unwrap();
    let l1 = mine_block(gen7, 1);
    hub7.accept_block(l1.clone()).unwrap();
    let l2 = mine_block(l1.block_hash(), 2);
    hub7.accept_block(l2.clone()).unwrap();
    let w1 = mine(gen7, 71);
    let w2 = mine(w1.block_hash(), 72);
    let w3 = mine(w2.block_hash(), 73);
    for w in [&w1, &w2, &w3] {
        hub7.ensure_header(w).unwrap();
    }
    let (old, _old_rx) = slot(17);
    let (fresh, _fresh_rx) = slot(18);
    let (taken, _taken_rx) = slot(19);
    let (suffix, _suffix_rx) = slot(20);
    let mut st = IbdWorkState::new(
        vec![old, fresh, taken, suffix],
        hub7.tip_hash(),
        hub7.tip_height(),
    );
    let confirmed = |h| rbitcoin_ibd::ibd::peer_chain::confirmed_at(&hub7, h);
    let l3 = mine(l2.block_hash(), 74);
    st.slots[0].chain.note_headers(
        &st.height_to_hash,
        confirmed,
        2,
        1,
        &[l1.header, l2.header, l3],
    );
    st.slots[2]
        .chain
        .note_headers(&st.height_to_hash, confirmed, 2, 1, &[w1, w2]);
    // Announced only the new chain's top, above the old tip.
    st.slots[3]
        .chain
        .note_headers(&st.height_to_hash, confirmed, 2, 3, &[w3]);
    st.header_walk.tip.hash = Some(w3.block_hash());
    st.header_walk.tip.height = 3;
    let shared = Mutex::new(st);
    assert!(rbitcoin_ibd::ibd::reorg::consider_disconnected_heavier(&shared, &hub7).unwrap());
    let st = shared.into_inner().unwrap_or_else(|err| err.into_inner());
    assert_eq!(st.height_to_hash.get(&1), Some(&w1.block_hash()));
    assert!(
        !may_serve(&st, 17, &w1.block_hash()),
        "a peer on the rewound chain is not asked for the new one"
    );
    assert!(!st.slots[0].chain.probed(), "and is probed again");
    assert!(
        !st.slots[1].chain.left_path_by(&st.height_to_hash, 1),
        "a peer with no record is not left stale by the rewind"
    );
    assert!(!may_serve(&st, 18, &w1.block_hash()));
    assert!(
        may_serve(&st, 19, &w1.block_hash()),
        "a peer whose split is the new chain's block shows it"
    );
    assert!(
        may_serve(&st, 20, &w3.block_hash()),
        "a peer that announced the new chain is asked for it"
    );

    // An eighth, because a block is asked only of a peer whose chain showed
    // it: a peer whose full reply ended below the block, or one with no
    // record, is not asked for it while another peer shows it. With no peer
    // that shows a block, a peer that has not left the path is asked first.
    let (_dir8, hub8) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-shown");
    hub8.ensure_genesis().unwrap();
    let gen8 = hub8.tip_hash().unwrap();
    let (head, _head_rx) = slot(22);
    let (full, _full_rx) = slot(23);
    let (blank, _blank_rx) = slot(24);
    let (left, _left_rx) = slot(25);
    let mut st = IbdWorkState::new(vec![head, full, blank, left], Some(gen8), Some(0));
    let mut prev = gen8;
    let mut chain8 = Vec::new();
    for n in 0..2_004u32 {
        let h = mine(prev, 90_000 + n);
        prev = h.block_hash();
        chain8.push(h);
    }
    for (i, h) in chain8.iter().enumerate() {
        st.record_height(h.block_hash(), i as u32 + 1);
        st.height_to_hash.insert(i as u32 + 1, h.block_hash());
    }
    st.header_walk.reserved = Some(22);
    let none = |_| None;
    let path8 = st.height_to_hash.clone();
    st.slots[0]
        .chain
        .note_headers(&path8, none, 0, 1, &chain8[..2_003]);
    st.slots[1]
        .chain
        .note_headers(&path8, none, 0, 1, &chain8[..2_000]);
    let fork = mine(chain8[0].block_hash(), 99_999);
    st.slots[3].chain.note_headers(&path8, none, 0, 2, &[fork]);
    let at = |h: u32| chain8[h as usize - 1].block_hash();
    assert!(may_serve(&st, 23, &at(100)));
    assert!(
        !may_serve(&st, 22, &at(100)),
        "the header peer stays on headers while another peer shows the block"
    );
    assert!(
        !may_serve(&st, 23, &at(2_003)),
        "a full reply that ended below a block does not show it"
    );
    assert!(
        !may_serve(&st, 24, &at(2_003)),
        "a peer with no record is not asked for a block another peer shows"
    );
    assert!(
        may_serve(&st, 22, &at(2_003)),
        "the header peer shows it alone"
    );
    assert!(may_serve(&st, 24, &at(2_004)));
    assert!(
        !may_serve(&st, 25, &at(2_004)),
        "with nobody showing a block, a peer that left the path is not asked"
    );
    // A peer whose record stops short of the next blocks is probed again; one
    // probed just now is not.
    st.max_ordered_height = 2_004;
    probe_unprobed_peer(&mut st, &hub8);
    assert_eq!(st.header_walk.probe, Some(23));
    st.header_walk.probe = None;
    st.slots[1].chain.note_probe_sent(Instant::now(), true);
    probe_unprobed_peer(&mut st, &hub8);
    assert_eq!(
        st.header_walk.probe,
        Some(24),
        "the next is the peer with no record"
    );
}

/// A long chain on an invalid block stays refused past the cap on
/// remembered tips: the newest link is kept.
#[test]
fn a_long_chain_on_an_invalid_block_stays_refused() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-refuse-cap");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    let bad = mine(gen, 1);
    st.reorg.invalid.mark(bad.block_hash().to_byte_array());
    let mut prev = bad.block_hash();
    let mut branch = None;
    for n in 0..1_100u32 {
        let next = mine(prev, 2 + n);
        assert!(
            refuse_invalid_batch(&mut st, 0, &[next]),
            "batch {n} builds on the refused chain"
        );
        prev = next.block_hash();
        if n == 100 {
            // A second branch off the invalid block, refused once.
            let side = mine(bad.block_hash(), 5_000);
            assert!(refuse_invalid_batch(&mut st, 0, &[side]));
            branch = Some(side.block_hash());
        }
    }
    let side_next = mine(branch.unwrap(), 5_001);
    assert!(
        refuse_invalid_batch(&mut st, 0, &[side_next]),
        "a branch refused after the oldest tips is still refused past the cap"
    );

    // A batch that is not one linked chain does not build on the invalid
    // block, so its last header is not remembered: an honest header cannot
    // be refused by sending it after one that is.
    let honest1 = mine(gen, 7_001);
    let honest2 = mine(honest1.block_hash(), 7_002);
    let junk = Header {
        prev_blockhash: bad.block_hash(),
        ..honest1
    };
    assert!(!refuse_invalid_batch(&mut st, 0, &[junk, honest2]));
    assert!(!refuse_invalid_batch(&mut st, 0, &[bad, honest1]));
    assert!(
        !refuse_invalid_batch(&mut st, 0, &[honest1, honest2]),
        "the honest chain is not refused"
    );
}

/// A peer that announced the path and then forks below the confirmed tip no
/// longer shows path blocks, so it does not keep the header peer that
/// announced them from them.
#[test]
fn a_peer_that_forks_below_the_tip_does_not_keep_the_header_peer_off() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-fork-below");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let b1 = mine_block(gen, 1);
    hub.accept_block(b1.clone()).unwrap();
    let b2 = mine_block(b1.block_hash(), 2);
    hub.accept_block(b2.clone()).unwrap();
    let (mut head, _head_rx) = slot(0);
    let (mut other, _other_rx) = slot(1);
    head.first_data_ms = 50;
    other.first_data_ms = 5_000;
    let mut st = IbdWorkState::new(vec![head, other], Some(b2.block_hash()), Some(2));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let h3 = mine(b2.block_hash(), 3);
    let path = [h3, mine(h3.block_hash(), 4)];
    apply(&mut st, &hub, 0, path.to_vec());
    apply(&mut st, &hub, 1, path.to_vec());
    assert_eq!(st.header_walk.reserved, Some(0));
    assert!(st.slots[1].chain.shows(&st.height_to_hash, 3));
    apply(&mut st, &hub, 1, vec![mine(b1.block_hash(), 92)]);
    assert!(
        !st.slots[1].chain.shows(&st.height_to_hash, 3),
        "a peer that left the path does not show a block on it"
    );
    assert!(
        may_serve(&st, 0, &path[0].block_hash()),
        "the header peer that announced the block is still asked"
    );
}

/// When the failure cannot be written, this process still retires the
/// candidate, but the retired walk is not left on disk as the resume point.
#[test]
fn a_retire_whose_failure_is_not_written_leaves_no_resume_point() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-retire-unsaved");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let store = hub.query.store().path().to_path_buf();
    std::fs::create_dir(store.join("block.invalid")).unwrap();
    let (s1, _rx1) = slot(1);
    let mut st = IbdWorkState::new(vec![s1], Some(gen), Some(0));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let p1 = mine(gen, 61);
    apply(&mut st, &hub, 1, vec![p1, mine(p1.block_hash(), 62)]);
    assert_eq!(hub.best_header_height(), 2);
    assert!(st.is_on_path(&p1.block_hash(), 1));
    rbitcoin_ibd::ibd::events::apply_consensus_invalid_reject(
        &mut st,
        1,
        p1.block_hash(),
        "bad block: coinbase excess value",
        Some(hub.query.as_ref()),
        Some(&hub),
    );
    assert_eq!(st.header_walk.tip_height(), 0, "the candidate is retired");
    assert_eq!(
        hub.best_header_height(),
        0,
        "the retired tip is not reported"
    );
    assert!(
        !store.join("header.adopt").exists(),
        "a retired walk is not the resume point while its failure is not on disk"
    );
    assert!(
        !hub.note_failed_connect(p1.block_hash()),
        "a mark whose write failed is still not on disk"
    );
    save_adopt(&st, &hub);
    assert!(
        !store.join("header.adopt").exists(),
        "no walk is saved while a failure is not on disk"
    );
    std::fs::remove_dir(store.join("block.invalid")).unwrap();
    assert!(
        hub.note_failed_connect(p1.block_hash()),
        "once the file can be written the pending mark goes to disk"
    );
    assert!(std::fs::read(store.join("block.invalid"))
        .unwrap()
        .windows(32)
        .any(|w| w == p1.block_hash().as_byte_array()));
    save_adopt(&st, &hub);
    assert!(store.join("header.adopt").exists());
}

#[test]
fn idle_header_requests_rotate_and_skip_a_short_peer() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-rotate");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (a, mut rx_a) = slot(0);
    let (b, mut rx_b) = slot(1);
    let (mut short, mut rx_short) = slot(2);
    short.peer_height = 10;
    let mut st = IbdWorkState::new(vec![a, b, short], Some(gen), Some(0));
    st.header_walk.origin = true;
    st.header_walk.tip.height = 100;
    st.ordered.clear();
    for _ in 0..ORDERED_HEADERS_SOFT_CAP {
        push_dummy(&mut st, 0);
    }
    let mut got = [0u32; 3];
    for _ in 0..6 {
        assert!(send_getheaders(&mut st, &hub).unwrap());
        if rx_a.try_recv().is_ok() {
            got[0] += 1;
        }
        if rx_b.try_recv().is_ok() {
            got[1] += 1;
        }
        if rx_short.try_recv().is_ok() {
            got[2] += 1;
        }
        if let Some(peer) = st.header_walk.walk.peer {
            let _ = take_header_ask(&mut st, peer);
        }
    }
    assert_eq!(got[2], 0, "a peer at or below the walk tip is not asked");
    assert_eq!(got[0], 6, "one peer keeps the walk until they miss");
    assert_eq!(got[1], 0, "a second tall peer is not asked in parallel");
}

#[test]
fn a_challenger_can_extend_past_the_current_tip() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-challenger-extend");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let common = mine(gen, 1);
    let current = mine(common.block_hash(), 2);
    let current_tip = mine(current.block_hash(), 3);
    let side = mine(common.block_hash(), 12);
    let side_tip = mine(side.block_hash(), 13);
    let heavier = mine(side_tip.block_hash(), 14);
    hub.milestone.height = 4;
    let (first, mut first_rx) = slot(0);
    let (second, mut second_rx) = slot(1);
    let mut st = IbdWorkState::new(vec![first, second], Some(gen), Some(0));
    fill_queue(&mut st);

    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = drain_getheaders(&mut first_rx);
    apply(&mut st, &hub, 0, vec![common]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = drain_getheaders(&mut first_rx);
    apply(&mut st, &hub, 0, vec![current, current_tip]);
    assert_eq!(st.header_walk.tip_hash(), Some(current_tip.block_hash()));

    apply_peer_event(
        &mut st,
        &hub,
        PeerEvent::BlocksInv {
            peer: 1,
            hashes: vec![side_tip.block_hash()],
        },
        &AtomicU32::new(0),
        &mut AddrMan::new(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        None,
    );
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut second_rx), 1);
    apply(&mut st, &hub, 1, vec![side, side_tip]);
    assert_eq!(st.header_walk.tip_hash(), Some(current_tip.block_hash()));
    assert!(st.header_walk.challenger.is_some());

    apply(&mut st, &hub, 1, vec![heavier]);
    assert_eq!(st.header_walk.tip_hash(), Some(heavier.block_hash()));
    assert_eq!(st.header_walk.tip_height(), 4);
    assert!(st.header_walk.challenger.is_none());
    assert_eq!(
        hub.query.milestone_header_at(4),
        Some(heavier.block_hash().to_byte_array())
    );
}

/// Median time while the tip is still genesis, then that same hub confirms
/// a stale ancestor and rewinds onto it. Retarget is a second hub: its
/// period length is not regtest difficulty, and each checkpoint layout
/// replaces the candidate the previous layout measured.
#[test]
#[allow(clippy::cognitive_complexity)] // one chain story, many context arms
fn a_heavier_header_chain_keeps_its_context() {
    {
        let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-heavier-chain");
        hub.ensure_genesis().unwrap();

        // Eleven ancestors on a genesis tip. A confirmed block would hide this median.
        let gen = hub.tip_hash().unwrap();
        let chain = (1..=12).fold((Vec::new(), gen), |(mut headers, prev), n| {
            let header = mine(prev, n);
            headers.push(header);
            (headers, header.block_hash())
        });
        let main = chain.0;
        let side12 = mine(main[10].block_hash(), 32);
        let (first, mut first_rx) = slot(0);
        let (second, mut second_rx) = slot(1);
        let mut st = IbdWorkState::new(vec![first, second], Some(gen), Some(0));
        fill_queue(&mut st);

        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = drain_getheaders(&mut first_rx);
        apply(&mut st, &hub, 0, main[..11].to_vec());
        assert!(send_getheaders(&mut st, &hub).unwrap());
        let _ = drain_getheaders(&mut first_rx);
        apply(&mut st, &hub, 0, main[11..].to_vec());
        let current_tip = main[11].block_hash();

        apply_peer_event(
            &mut st,
            &hub,
            PeerEvent::BlocksInv {
                peer: 1,
                hashes: vec![side12.block_hash()],
            },
            &AtomicU32::new(0),
            &mut AddrMan::new(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            None,
        );
        assert!(send_getheaders(&mut st, &hub).unwrap());
        assert_eq!(drain_getheaders(&mut second_rx), 1);
        apply(&mut st, &hub, 1, vec![side12]);
        assert!(st.header_walk.challenger.is_some());

        let side_times = st
            .header_walk
            .challenger
            .as_ref()
            .unwrap()
            .tip
            .times
            .clone();
        let mtp = rbitcoin_primitives::median_time_past_times(
            rbitcoin_primitives::MedianWindow::new(&side_times).unwrap(),
        );
        let invalid = mine_at(side12.block_hash(), 40, mtp);
        apply(&mut st, &hub, 1, vec![invalid]);
        assert_eq!(st.header_walk.tip_hash(), Some(current_tip));
        assert_eq!(
            st.header_walk.challenger.as_ref().unwrap().tip.hash,
            Some(side12.block_hash())
        );

        let valid = mine_at(side12.block_hash(), 41, mtp + 1);
        apply(&mut st, &hub, 1, vec![valid]);
        assert_eq!(st.header_walk.tip_hash(), Some(valid.block_hash()));
        {
            // A stale height-1 anchor on this hub. The median-time walk left the confirmed tip at genesis.
            let gen = hub.tip_hash().unwrap();
            let stale = mine_block(gen, 1);
            hub.accept_block(stale.clone()).unwrap();
            assert_eq!(hub.tip_height(), Some(1));
            let stale_hash = stale.block_hash();
            let stale_next = mine(stale_hash, 2);
            let mut floor = [0u8; 32];
            floor[31] = 1;
            hub.milestone = rbitcoin_consensus::Milestone {
                height: 2,
                anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                    hash: stale_next.block_hash(),
                    min_work_be: floor,
                }),
            };
            // Mainnet sets this above the confirmed tip for most of IBD. One
            // header on that tip is below the threshold; the chain is not.
            hub.set_minimum_chain_work(Some([0xff; 32]));
            let (s0, _rx0) = slot(0);
            let mut st = IbdWorkState::new(vec![s0], hub.tip_hash(), hub.tip_height());
            fill_queue(&mut st);
            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, vec![stale_next]);
            assert!(st.header_walk.proven);
            assert!(
                skips(&hub, 2, stale_next.block_hash().as_byte_array()),
                "the first chain through the anchor may skip until a heavier one wins"
            );

            let mut prev = gen;
            let mut honest = Vec::new();
            for n in 10..16 {
                let hdr = mine(prev, n);
                prev = hdr.block_hash();
                honest.push(hdr);
            }
            let heavy = prev;
            apply(&mut st, &hub, 0, honest);
            assert!(
                st.slots[0].alive,
                "a heavier chain forking below the confirmed tip does not disconnect"
            );
            assert_eq!(st.header_walk.tip_hash(), Some(heavy));
            assert_eq!(st.header_walk.tip_height(), 6);
            assert!(
                !skips(&hub, 2, stale_next.block_hash().as_byte_array()),
                "script skip does not stay on the chain that lost"
            );
        }
        {
            // Rewind onto the confirmed chain this hub just grew past the stale block.
            let have = hub.tip_height().unwrap();
            hub.generate_to_script(5 - have, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
                .unwrap();
            let base_height = hub.tip_height().unwrap();
            let base_hash = hub.tip_hash().unwrap();
            let base_header = hub.tip_header().unwrap();
            floor_unreachable(&mut hub);
            let (s0, _rx0) = slot(0);
            let mut st = IbdWorkState::new(vec![s0], Some(base_hash), Some(base_height));
            fill_queue(&mut st);
            let first = mine_at(base_hash, 50, base_header.time + 1);
            let second = mine_at(first.block_hash(), 51, base_header.time + 2);

            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, vec![first, second]);
            apply(&mut st, &hub, 0, vec![]);
            assert_eq!(st.header_walk.tip_hash(), Some(base_hash));
            assert_eq!(st.header_walk.tip_height(), base_height);
            assert_eq!(
                st.header_walk.tip.work,
                Work::from_be_bytes(st.header_walk.base_work)
            );
            assert!(
                st.header_walk.tip.work > Work::from_be_bytes([0; 32]),
                "an empty rewind keeps the confirmed chain's work"
            );

            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, vec![first, second]);
            assert_eq!(st.header_walk.tip_hash(), Some(second.block_hash()));
            assert_eq!(st.header_walk.tip_height(), base_height + 2);

            let parent = hub
                .query
                .wire_header_at_height(rbitcoin_primitives::Height(base_height - 1))
                .unwrap();
            let side = mine_at(parent.block_hash(), 52, parent.time + 1);
            apply(&mut st, &hub, 0, vec![side]);
            assert_eq!(
                st.header_walk.tip_hash(),
                Some(second.block_hash()),
                "one less-work header from the confirmed parent does not replace the walk"
            );
        }
    }
    {
        // Retarget every 20 blocks. The walks above leave regtest difficulty in place.
        let (_dir, mut hub) =
            rbitcoin_net::chain::tiny_regtest_hub_labeled("header-heavier-retarget");
        hub.ensure_genesis().unwrap();
        arm_retarget(&mut hub);
        {
            let gen_hash = hub.tip_hash().unwrap();
            let genesis = hub.header_of(&gen_hash).unwrap();
            floor_unreachable(&mut hub);
            let (s0, _rx0) = slot(0);
            let mut st = IbdWorkState::new(vec![s0], Some(gen_hash), Some(0));
            fill_queue(&mut st);
            assert_eq!(hub.params.difficulty_adjustment_interval(), 20);
            let chain = extend_chain(&hub, &genesis, &[], 45, 1);
            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, chain[..20].to_vec());
            assert!(st.slots[0].alive, "the first period is valid");
            assert_eq!(st.header_walk.tip_height(), 20);
            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, chain[20..40].to_vec());
            assert!(
                st.slots[0].alive,
                "the retarget at the period start is valid"
            );
            assert_eq!(st.header_walk.tip_height(), 40);
            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, chain[40..].to_vec());
            assert!(st.slots[0].alive, "the walk continues past that retarget");
            assert_eq!(st.header_walk.tip_height(), 45);

            let fork = extend_chain(&hub, &genesis, &chain[..20], 30, 2);
            let fork_tip = fork.last().unwrap().block_hash();
            apply(&mut st, &hub, 0, fork);
            assert!(
                st.slots[0].alive,
                "a heavier fork whose period start is only on the fork checkpoint is valid"
            );
            assert_eq!(st.header_walk.tip_height(), 50);
            assert_eq!(st.header_walk.tip_hash(), Some(fork_tip));
        }
        {
            // The gap fork replaces the candidate, so this rewind keeps its own checkpoints.
            let gen_hash = hub.tip_hash().unwrap();
            let genesis = hub.header_of(&gen_hash).unwrap();
            floor_unreachable(&mut hub);
            let (s0, _rx0) = slot(0);
            let mut st = IbdWorkState::new(vec![s0], Some(gen_hash), Some(0));
            fill_queue(&mut st);
            assert_eq!(hub.params.difficulty_adjustment_interval(), 20);
            let chain = extend_chain(&hub, &genesis, &[], 46, 1);
            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, chain[..16].to_vec());
            assert!(st.slots[0].alive);
            assert_eq!(st.header_walk.tip_height(), 16);
            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, chain[16..36].to_vec());
            assert!(
                st.slots[0].alive,
                "the retarget inside the second reply is valid"
            );
            assert_eq!(st.header_walk.tip_height(), 36);
            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, chain[36..].to_vec());
            assert!(st.slots[0].alive);
            assert_eq!(st.header_walk.tip_height(), 46);

            apply(&mut st, &hub, 0, vec![]);
            assert_eq!(
                st.header_walk.tip_height(),
                36,
                "an empty reply below the floor steps back one checkpoint"
            );
            let checkpoint = st.header_walk.checkpoints.last().unwrap();
            assert_eq!(
                st.header_walk.tip_hash(),
                Some(checkpoint.hash),
                "an empty rewind lands on that checkpoint"
            );
            let checkpoint_work = Work::from_be_bytes(checkpoint.work);
            assert_eq!(st.header_walk.tip.work, checkpoint_work);
            assert!(
                checkpoint_work > Work::from_be_bytes([0; 32]),
                "an empty rewind keeps that checkpoint's work"
            );
            let next = extend_chain(&hub, &genesis, &chain[..36], 20, 3);
            let tip = next.last().unwrap().block_hash();
            assert!(send_getheaders(&mut st, &hub).unwrap());
            apply(&mut st, &hub, 0, next);
            assert!(
                st.slots[0].alive,
                "the period start on the checkpoint we rewound to still checks nBits"
            );
            assert_eq!(st.header_walk.tip_height(), 56);
            assert_eq!(st.header_walk.tip_hash(), Some(tip));

            let lighter = extend_chain(&hub, &genesis, &[], 55, 4);
            apply(&mut st, &hub, 0, lighter);
            assert_eq!(
                st.header_walk.tip_hash(),
                Some(tip),
                "work before the restored checkpoint still counts when comparing a lighter fork"
            );
        }
        {
            // A second peer's snapshot. The rewind chain has no challenger and a different tip.
            let gen = hub.tip_hash().unwrap();
            let genesis = hub.header_of(&gen).unwrap();
            let main = extend_chain(&hub, &genesis, &[], 22, 1);
            let side = extend_chain(&hub, &genesis, &main[..20], 21, 2);
            floor_unreachable(&mut hub);
            hub.milestone.height = 41;
            let (first, mut first_rx) = slot(0);
            let (second, mut second_rx) = slot(1);
            let mut st = IbdWorkState::new(vec![first, second], Some(gen), Some(0));
            fill_queue(&mut st);

            assert!(send_getheaders(&mut st, &hub).unwrap());
            let _ = drain_getheaders(&mut first_rx);
            apply(&mut st, &hub, 0, main[..20].to_vec());
            assert!(send_getheaders(&mut st, &hub).unwrap());
            let _ = drain_getheaders(&mut first_rx);
            apply(&mut st, &hub, 0, main[20..].to_vec());
            assert_eq!(st.header_walk.tip_height(), 22);

            apply_peer_event(
                &mut st,
                &hub,
                PeerEvent::BlocksInv {
                    peer: 1,
                    hashes: vec![side[0].block_hash()],
                },
                &AtomicU32::new(0),
                &mut AddrMan::new(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
                None,
            );
            assert!(send_getheaders(&mut st, &hub).unwrap());
            assert_eq!(drain_getheaders(&mut second_rx), 1);
            apply(&mut st, &hub, 1, vec![side[0]]);
            assert_eq!(st.header_walk.tip_hash(), Some(main[21].block_hash()));
            assert!(st.header_walk.challenger.is_some());

            apply(&mut st, &hub, 1, side[1..].to_vec());
            assert_eq!(st.header_walk.tip_height(), 41);
            assert_eq!(st.header_walk.tip_hash(), Some(side[20].block_hash()));
            assert!(st.header_walk.challenger.is_none());
            assert_eq!(
                hub.query.milestone_header_at(41),
                Some(side[20].block_hash().to_byte_array())
            );
        }
    }
}

fn getheaders_locator(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> Option<Vec<BlockHash>> {
    loop {
        match rx.try_recv() {
            Ok(PeerCmd::GetHeaders { locator }) => return Some(locator),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

fn drain_getheaders(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> usize {
    let mut n = 0usize;
    loop {
        match rx.try_recv() {
            Ok(PeerCmd::GetHeaders { .. }) => n += 1,
            Ok(_) => {}
            Err(_) => return n,
        }
    }
}

fn age_header_ask(st: &mut IbdWorkState) {
    let old = Instant::now().checked_sub(Duration::from_secs(6));
    if st.header_walk.walk.peer.is_some() {
        st.header_walk.walk.at = old;
    }
}

#[test]
fn a_refill_ask_waits_then_skips_the_peer_that_missed() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-refill-miss");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (quiet, mut quiet_rx) = slot(0);
    let (mut busy, mut busy_rx) = slot(1);
    busy.in_flight.insert(BlockHash::from_byte_array([8u8; 32]));
    let mut st = IbdWorkState::new(vec![quiet, busy], Some(gen), Some(0));

    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut quiet_rx), 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(
        drain_getheaders(&mut quiet_rx),
        0,
        "a refill still inside the window is not sent again"
    );
    age_header_ask(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut quiet_rx), 0);
    assert_eq!(drain_getheaders(&mut busy_rx), 1);
}

#[test]
fn a_late_lookahead_from_the_asked_peer_still_extends_the_tip() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-late");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let (quiet, mut quiet_rx) = slot(0);
    let (mut busy, mut busy_rx) = slot(1);
    busy.in_flight.insert(BlockHash::from_byte_array([7u8; 32]));
    let mut st = IbdWorkState::new(vec![quiet, busy], Some(gen), Some(0));
    fill_queue(&mut st);

    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut quiet_rx), 1);
    age_header_ask(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert_eq!(drain_getheaders(&mut quiet_rx), 0);
    assert_eq!(drain_getheaders(&mut busy_rx), 1);

    rbitcoin_log::capture_logs(true);
    apply(&mut st, &hub, 0, vec![good]);
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert_eq!(
        st.header_walk.tip_hash(),
        Some(good.block_hash()),
        "a late look-ahead from the peer that was asked still extends the tip"
    );
    assert!(
        logs.iter()
            .any(|(level, line)| *level == rbitcoin_log::Level::Info
                && line.contains("ibd: headers late")),
        "a late look-ahead is logged"
    );
    assert!(st.slots.iter().any(|s| s.id == 0 && s.alive));

    let next = mine(good.block_hash(), 2);
    let tip = st.header_walk.tip_hash();
    apply(&mut st, &hub, 2, vec![next]);
    assert_eq!(
        st.header_walk.tip_hash(),
        tip,
        "a look-ahead from a peer that was not asked is ignored"
    );
}

#[test]
fn off_path_headers_disconnect_the_peer_and_path_headers_do_not() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-8");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    floor_unreachable(&mut hub);
    let owed = BlockHash::from_byte_array([0x5a; 32]);
    let (path_peer, _rx0) = slot(0);
    let (mut side_peer, _rx1) = slot(1);
    let path_addr = path_peer.addr;
    let side_addr = side_peer.addr;
    side_peer.track_insert(owed);
    let mut st = IbdWorkState::new(vec![path_peer, side_peer], Some(gen), Some(0));
    rbitcoin_ibd::ibd::assign::inflight_add_peer(&mut st.inflight, owed, 1);
    apply(&mut st, &hub, 0, vec![h1, h2]);
    assert!(st.slots.iter().any(|s| s.id == 0 && s.alive));
    assert!(!st
        .addr_cooldown
        .contains_key(&rbitcoin_net::NetAddr::from_socket(path_addr)));
    assert!(
        st.inflight.contains_key(&owed),
        "the side peer still owes the block while it is connected"
    );

    let mut prev = gen;
    let mut side = Vec::with_capacity(4_001);
    for n in 0..4_001 {
        let hdr = mine(prev, 10_000 + n);
        prev = hdr.block_hash();
        side.push(hdr);
    }
    apply(&mut st, &hub, 1, side);
    assert!(
        st.slots.iter().any(|s| s.id == 1 && !s.alive),
        "a peer over the off-path budget is disconnected"
    );
    assert!(st
        .addr_cooldown
        .contains_key(&rbitcoin_net::NetAddr::from_socket(side_addr)));
    assert!(st.slots.iter().any(|s| s.id == 0 && s.alive));
    assert!(
        !st.inflight.contains_key(&owed),
        "the disconnected peer's block getdata is free to ask another peer"
    );
}

fn push_dummy(st: &mut IbdWorkState, n: u32) {
    let mut b = [0x11; 32];
    b[28..32].copy_from_slice(&n.to_le_bytes());
    let h = BlockHash::from_byte_array(b);
    st.ordered.push_back(h);
    st.ordered_set.insert(h);
}

/// The work floor is above anything a regtest header can reach.
fn floor_unreachable(hub: &mut ChainHub) {
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 840_000,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: BlockHash::from_byte_array([0xab; 32]),
            min_work_be: [0xff; 32],
        }),
    };
}

fn queue_at_cap_ending_on(st: &mut IbdWorkState, hub: &ChainHub, tail: Header) {
    let mut n = 0u32;
    while st.ordered.len() + 1 < ORDERED_HEADERS_SOFT_CAP {
        push_dummy(st, n);
        n += 1;
    }
    apply(st, hub, 0, vec![tail]);
}

#[test]
fn queue_refill_below_the_floor_stores_the_successor() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-refill");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let a3 = mine(a2.block_hash(), 3);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, a1);
    assert_eq!(st.ordered.back().copied(), Some(a1.block_hash()));
    let before = hub.query.store().header_count();
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2]);
    assert_eq!(hub.query.store().header_count(), before + 1);
    assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));

    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    apply(&mut st, &hub, 0, vec![a2, a3]);
    assert_eq!(
        hub.query.store().header_count(),
        before + 2,
        "the queue stores the successor of its tail below the work floor"
    );
    assert!(st.ordered_set.contains(&a2.block_hash()));
    assert!(st.ordered_set.contains(&a3.block_hash()));
}

#[test]
fn easy_bits_lookahead_does_not_capture_the_walk() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-easy");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let honest = mine(gen, 1);
    let mut easy = honest;
    easy.bits = CompactTarget::from_consensus(0x2100ffff);
    let (s0, _rx0) = slot(0);
    let (s1, _rx1) = slot(1);
    let bad_addr = s0.addr;
    let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
    fill_queue(&mut st);
    let before = hub.query.store().header_count();
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![easy]);
    assert_eq!(hub.query.store().header_count(), before);
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    assert!(st.header_walk.checkpoints().is_empty());
    assert!(
        !st.slots[0].alive,
        "the peer that sent the easy header is down"
    );
    assert!(st
        .addr_cooldown
        .contains_key(&rbitcoin_net::NetAddr::from_socket(bad_addr)));
    assert!(st.slots[1].alive);

    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 1, vec![honest]);
    assert_eq!(st.header_walk.tip_hash(), Some(honest.block_hash()));
    assert_eq!(hub.query.store().header_count(), before + 1);
    assert!(st.slots[1].alive);
}

#[test]
fn unsolicited_lookahead_from_another_peer_is_ignored() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-unasked");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let (s0, _rx0) = slot(0);
    let (s1, _rx1) = slot(1);
    let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 1, vec![good]);
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    assert!(st.header_walk.checkpoints().is_empty());
    assert!(st.slots[1].alive, "an unasked peer is not disconnected");
    apply(&mut st, &hub, 0, vec![good]);
    assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
    assert!(st.slots[1].alive);
}

#[test]
fn rewind_clears_a_milestone_hash_from_the_abandoned_chain() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-milestone");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let b1 = mine(gen, 11);
    let b2 = mine(b1.block_hash(), 12);
    floor_unreachable(&mut hub);
    hub.milestone.height = 2;
    hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
        hash: b2.block_hash(),
        min_work_be: [0xff; 32],
    });
    let (s0, _rx0) = slot(0);
    let (s1, _rx1) = slot(1);
    let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1, a2]);
    assert_eq!(st.header_walk.milestone_hash(), Some(a2.block_hash()));
    let side = BlockHash::from_byte_array([0x42; 32]);
    assert!(!note_off_path(&mut st, &hub, 0, side));
    assert!(!note_off_path(&mut st, &hub, 0, side));
    assert_eq!(st.header_walk.off_path.get(&0).map(|s| s.len()), Some(1));
    plant_on_queue(&mut st, a1.block_hash(), 1);
    plant_on_queue(&mut st, a2.block_hash(), 2);

    apply(&mut st, &hub, 0, vec![]);
    apply(&mut st, &hub, 1, vec![]);
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    assert!(
        st.header_walk.off_path.is_empty(),
        "a rewind forgets side headers from the abandoned chain"
    );
    assert!(
        st.header_walk.milestone_hash().is_none(),
        "rewinding under the milestone drops the abandoned hash"
    );

    apply(&mut st, &hub, 1, vec![b1, b2]);
    assert_eq!(st.header_walk.milestone_hash(), Some(b2.block_hash()));
}

#[test]
fn confirmed_reorg_drops_a_milestone_hash_below_the_fork() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-reorg-ms");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    floor_unreachable(&mut hub);
    hub.milestone.height = 2;
    hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
        hash: a2.block_hash(),
        min_work_be: [0xff; 32],
    });
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1, a2]);
    assert_eq!(st.header_walk.base_height, 0);
    assert_eq!(st.header_walk.milestone_hash(), Some(a2.block_hash()));

    rbitcoin_log::capture_logs(true);
    hub.query.clear_milestone_path_above(2);
    on_confirmed_rewind(&mut st, &hub, 2);
    let above = rbitcoin_log::take_logs();
    assert_eq!(st.header_walk.milestone_hash(), Some(a2.block_hash()));
    assert_eq!(
        hub.query.milestone_header_at(2),
        Some(a2.block_hash().to_byte_array())
    );
    assert!(
        above
            .iter()
            .all(|(_, line)| !line.contains("milestone dropped")),
        "a reorg that stays above the milestone keeps the latched hash"
    );

    hub.query.clear_milestone_path_above(0);
    on_confirmed_rewind(&mut st, &hub, 0);
    let below = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        st.header_walk.milestone_hash().is_none(),
        "a fork under the milestone drops the latched hash and does not put it back"
    );
    assert!(
        below.iter().any(|(level, line)| {
            *level == rbitcoin_log::Level::Warn && line.contains("ibd: headers milestone dropped")
        }),
        "dropping the latch is logged so script checks staying on is visible"
    );
    st.header_walk = HeaderWalk::default();
    assert!(restore_adopt(&mut st, &hub));
    assert!(
        st.header_walk.milestone_hash().is_none(),
        "header.adopt does not restore a hash from below the fork"
    );
}

#[test]
fn origin_stops_at_the_queue_tail() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-origin");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    let h3 = mine(h2.block_hash(), 3);
    let next = mine(h2.block_hash(), 4);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    apply(&mut st, &hub, 0, vec![h1, h2, h3]);
    fill_to_cap(&mut st);
    plant_on_queue(&mut st, h2.block_hash(), 2);
    st.height_to_hash.remove(&3);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![next]);
    assert_eq!(st.header_walk.tip_hash(), Some(next.block_hash()));
    assert_eq!(st.header_walk.base_height, 2);
}

fn mine_at(prev: BlockHash, n: u32, time: u32) -> Header {
    let mut h = Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([n as u8; 32]),
        time,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: n,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut h);
    h
}

#[test]
fn refill_matching_the_first_of_two_checkpoints_is_stored() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-two-ckpt");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let a3 = mine(a2.block_hash(), 3);
    let a4 = mine(a3.block_hash(), 4);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, a1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2, a3]);
    while st.ordered.len() + 4 > ORDERED_HEADERS_SOFT_CAP {
        let Some(dropped) = st.ordered.pop_front() else {
            break;
        };
        st.ordered_set.remove(&dropped);
    }
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a4]);
    assert!(
        st.slots[0].alive,
        "the peer that extended the walk stays up"
    );
    assert_eq!(st.header_walk.checkpoints().len(), 2);
    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let before = hub.query.store().header_count();
    apply(&mut st, &hub, 0, vec![a2, a3]);
    assert_eq!(
        hub.query.store().header_count(),
        before,
        "a refill that matches a checkpoint already written is not stored again"
    );
    assert!(hub
        .query
        .get_header_by_hash(a3.block_hash().as_byte_array())
        .unwrap()
        .is_some());
    assert_eq!(st.header_walk.checkpoints().len(), 2);
}

#[test]
fn refill_that_contradicts_a_checkpoint_rewinds_and_stores() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-rewind-miss");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let honest = mine(a1.block_hash(), 9);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, a1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2]);
    assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let before = hub.query.store().header_count();
    apply(&mut st, &hub, 0, vec![honest]);
    assert_eq!(hub.query.store().header_count(), before + 1);
    assert_eq!(st.header_walk.tip_hash(), Some(honest.block_hash()));
    assert!(st
        .header_walk
        .checkpoints()
        .iter()
        .all(|c| c.hash != a2.block_hash()));
    assert!(!st.header_walk.dead_ends.contains(&honest.block_hash()));
    assert!(hub
        .query
        .get_header_by_hash(honest.block_hash().as_byte_array())
        .unwrap()
        .is_some());
    assert!(st.slots[0].alive);
}

#[test]
fn a_second_lookahead_ask_waits_for_the_reply() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-latch");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let (s0, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. })));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        rx.try_recv().is_err(),
        "a look-ahead ask still inside the window is not sent again"
    );
    apply(&mut st, &hub, 0, vec![good]);
    assert_eq!(st.header_walk.tip_hash(), Some(good.block_hash()));
    assert!(st.slots[0].alive);
}

#[test]
fn heavier_chain_below_the_floor_is_adopted_without_an_empty_reply() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-heavy-floor");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let stale = mine(gen, 1);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![stale]);
    assert_eq!(st.header_walk.tip_hash(), Some(stale.block_hash()));
    let mut prev = gen;
    let mut honest = Vec::new();
    for n in 10..14 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        honest.push(hdr);
    }
    let tip = honest.last().unwrap().block_hash();
    apply(&mut st, &hub, 0, honest);
    assert_eq!(st.header_walk.tip_hash(), Some(tip));
    assert!(st.slots[0].alive);
    assert!(st
        .header_walk
        .checkpoints()
        .iter()
        .all(|c| c.hash != stale.block_hash()));
}

#[test]
fn a_short_peer_does_not_block_an_empty_rewind() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-short-empty");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    floor_unreachable(&mut hub);
    let (tall, _rx0) = slot(0);
    let (mut short, _rx1) = slot(1);
    short.peer_height = 1;
    let mut st = IbdWorkState::new(vec![tall, short], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1, a2]);
    assert_eq!(st.header_walk.tip_height(), 2);
    plant_on_queue(&mut st, a1.block_hash(), 1);
    plant_on_queue(&mut st, a2.block_hash(), 2);
    apply(&mut st, &hub, 0, vec![]);
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    assert!(st.slots.iter().any(|s| s.id == 1 && s.alive));
}

#[test]
fn a_queued_hash_between_checkpoints_is_not_stored_while_the_queue_is_full() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-between");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1]);
    let tip = st.header_walk.tip_hash();
    let before = hub.query.store().header_count();
    let mid = st.ordered[st.ordered.len() / 2];
    let side = mine(mid, 40);
    apply(&mut st, &hub, 0, vec![side]);
    assert_eq!(hub.query.store().header_count(), before);
    assert_eq!(st.header_walk.tip_hash(), tip);
    assert!(!st.ordered_set.contains(&side.block_hash()));
}

#[test]
fn restored_checkpoint_times_accept_a_header_under_the_tip_time() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-mtp");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    floor_unreachable(&mut hub);
    let mut prev = gen;
    let mut chain = Vec::new();
    for n in 1..=12 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        chain.push(hdr);
    }
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, chain.clone());
    assert_eq!(st.header_walk.tip.times.len(), 11);
    let tip = chain[11];
    st.header_walk = HeaderWalk::default();
    assert!(restore_adopt(&mut st, &hub));
    assert_eq!(st.header_walk.tip.times.len(), 11);
    assert_eq!(
        st.header_walk.tip_header().map(|h| h.block_hash()),
        Some(tip.block_hash())
    );
    let soft = mine_at(tip.block_hash(), 13, tip.time - 2);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![soft]);
    assert_eq!(st.header_walk.tip_hash(), Some(soft.block_hash()));
    assert!(st.slots[0].alive);

    apply(&mut st, &hub, 0, vec![]);
    assert_eq!(st.header_walk.tip_hash(), Some(tip.block_hash()));
    let mtp = rbitcoin_primitives::median_time_past_times(
        rbitcoin_primitives::MedianWindow::new(&st.header_walk.tip.times).unwrap(),
    );
    let invalid = mine_at(tip.block_hash(), 14, mtp);
    apply(&mut st, &hub, 0, vec![invalid]);
    assert_eq!(st.header_walk.tip_hash(), Some(tip.block_hash()));
}

#[test]
fn a_missing_parent_header_is_consumed_without_a_disconnect() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-no-parent");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let stale = mine(gen, 1);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![stale]);
    st.header_walk.tip.header = None;
    st.header_walk.tip.times.clear();
    if let Some(c) = st.header_walk.checkpoints.last_mut() {
        c.header = None;
        c.times.clear();
    }
    let mut prev = stale.block_hash();
    let mut heavier = Vec::new();
    for n in 20..24 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        heavier.push(hdr);
    }
    let before = st.header_walk.tip_hash();
    apply(&mut st, &hub, 0, heavier);
    assert_eq!(st.header_walk.tip_hash(), before);
    assert!(st.slots[0].alive);
}

#[test]
fn min_difficulty_walk_back_rejects_a_limit_header() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-mindiff");
    hub.ensure_genesis().unwrap();
    hub.params.btc.allow_min_difficulty_blocks = true;
    let gen = hub.tip_hash().unwrap();
    let tip = mine(gen, 1);
    let (s0, _rx0) = slot(0);
    let addr = s0.addr;
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![tip]);
    assert!(st.slots[0].alive);
    st.header_walk.tip.diff.full_diff_bits = Some(CompactTarget::from_consensus(0x1d00ffff));
    st.header_walk.tip.diff.full_diff_height = st.header_walk.tip_height().saturating_sub(1);
    let next = mine_at(tip.block_hash(), 2, tip.time + 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![next]);
    assert_eq!(st.header_walk.tip_hash(), Some(tip.block_hash()));
    assert!(!st.slots[0].alive);
    assert!(st
        .addr_cooldown
        .contains_key(&rbitcoin_net::NetAddr::from_socket(addr)));
}

/// Core `GetNextWorkRequired`: a header within 20 minutes of a
/// min-difficulty parent takes the last non-limit `nBits`, even when that
/// header is earlier in the same reply.
#[test]
fn min_difficulty_walk_back_finds_a_retarget_in_the_same_batch() {
    let (_dir, mut hub) =
        rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-mindiff-batch");
    hub.ensure_genesis().unwrap();
    arm_retarget(&mut hub);
    let gen = hub.tip_hash().unwrap();
    let genesis = hub.header_of(&gen).unwrap();
    let mut chain = extend_chain(&hub, &genesis, &[], 20, 1);
    hub.params.btc.allow_min_difficulty_blocks = true;
    let limit = hub.params.pow_limit.to_compact_lossy();
    let retarget = chain[19];
    assert_ne!(retarget.bits, limit, "height 20 retargets above the limit");
    let spacing = hub.params.btc.pow_target_spacing as u32;
    let min_diff = mine_bits(
        retarget.block_hash(),
        21,
        retarget.time + 2 * spacing + 1,
        limit,
        1,
    );
    let next = mine_bits(
        min_diff.block_hash(),
        22,
        min_diff.time + 1,
        retarget.bits,
        1,
    );
    chain.extend([min_diff, next]);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, chain);
    assert!(st.slots[0].alive);
    assert_eq!(st.header_walk.tip_hash(), Some(next.block_hash()));
}

#[test]
fn a_restored_checkpoint_header_adopts_a_heavier_fork() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-restore-fork");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let fork = mine(gen, 1);
    let tip = mine(fork.block_hash(), 2);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![fork]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![tip]);
    assert_eq!(st.header_walk.checkpoints().len(), 2);
    st.header_walk = HeaderWalk::default();
    assert!(restore_adopt(&mut st, &hub));
    let mut prev = fork.block_hash();
    let mut heavier = Vec::new();
    for n in 30..34 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        heavier.push(hdr);
    }
    let heavy_tip = heavier.last().unwrap().block_hash();
    apply(&mut st, &hub, 0, heavier);
    assert_eq!(st.header_walk.tip_hash(), Some(heavy_tip));
    assert!(st.slots[0].alive);
}

fn arm_retarget(hub: &mut rbitcoin_net::chain::ChainHub) {
    hub.params.btc.no_pow_retargeting = false;
    hub.params.btc.allow_min_difficulty_blocks = false;
    let spacing = hub.params.btc.pow_target_spacing;
    hub.params.btc.pow_target_timespan = spacing.saturating_mul(20);
}

fn chain_time(genesis_time: u32, spacing: u32, height: u32) -> u32 {
    genesis_time.saturating_add(spacing.saturating_mul(height))
}

fn bits_for(
    hub: &rbitcoin_net::chain::ChainHub,
    genesis: &Header,
    prior: &[Header],
    height: u32,
    time: u32,
    parent: &Header,
) -> CompactTarget {
    let interval = hub.params.difficulty_adjustment_interval();
    let period_first = if interval > 0 && height.is_multiple_of(interval) {
        let start = height - interval;
        if start == 0 {
            Some(genesis.time)
        } else {
            prior.get((start as usize) - 1).map(|h| h.time)
        }
    } else {
        None
    };
    rbitcoin_consensus::next_work_bits(
        &hub.params,
        height,
        parent.bits,
        parent.time,
        time,
        period_first,
        |_| None,
    )
    .expect("difficulty bits")
}

fn mine_bits(prev: BlockHash, n: u32, time: u32, bits: CompactTarget, salt: u8) -> Header {
    let mut merkle = [salt; 32];
    merkle[28..32].copy_from_slice(&n.to_le_bytes());
    let mut h = Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array(merkle),
        time,
        bits,
        nonce: 0,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut h);
    h
}

/// Headers at heights `prior.len()+1` onward. `prior` is the shared prefix
/// (height 1 first). Difficulty matches `hub.params`.
fn extend_chain(
    hub: &rbitcoin_net::chain::ChainHub,
    genesis: &Header,
    prior: &[Header],
    extra: u32,
    salt: u8,
) -> Vec<Header> {
    let spacing = hub.params.btc.pow_target_spacing as u32;
    let mut all = prior.to_vec();
    let mut parent = prior.last().copied().unwrap_or(*genesis);
    let start = prior.len() as u32;
    let mut out = Vec::with_capacity(extra as usize);
    for n in 1..=extra {
        let height = start + n;
        let time = chain_time(genesis.time, spacing, height);
        let bits = bits_for(hub, genesis, &all, height, time, &parent);
        let hdr = mine_bits(parent.block_hash(), height, time, bits, salt);
        all.push(hdr);
        out.push(hdr);
        parent = hdr;
    }
    out
}

#[test]
fn a_full_queue_next_ask_starts_at_the_walk_tip() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-ask-past-cap");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    floor_unreachable(&mut hub);
    let (mut peer, mut rx) = slot(0);
    peer.peer_height = 100_000;
    let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, a1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![a2]);
    assert!(
        !st.ordered_set.contains(&a2.block_hash()),
        "the soft cap keeps the new header off the queue"
    );
    assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
    st.hygiene();
    assert!(
        st.height_to_hash
            .values()
            .any(|hash| *hash == a2.block_hash()),
        "a header written past the queue stays indexed until the queue takes it"
    );
    assert!(
        send_getheaders(&mut st, &hub).unwrap(),
        "the walk still needs the header after the one it just stored"
    );
    match rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => {
            assert_eq!(
                locator[0],
                a2.block_hash(),
                "the ask starts at the stored walk tip, not the queue tail"
            );
        }
        Ok(_) => panic!("expected getheaders"),
        Err(_) => panic!("peer was not asked for the next header"),
    }
}

#[test]
fn new_lookahead_batch_does_not_skip_stored_queue_successors() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-no-queue-gap");
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    floor_unreachable(&mut hub);
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(genesis), Some(0));
    let tail = mine(genesis, 1);
    queue_at_cap_ending_on(&mut st, &hub, tail);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let next = mine(tail.block_hash(), 2);
    let third = mine(next.block_hash(), 3);
    apply(&mut st, &hub, 0, vec![next, third]);
    for _ in 0..2 {
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
    }
    let fourth = mine(third.block_hash(), 4);
    apply(&mut st, &hub, 0, vec![fourth]);
    rbitcoin_ibd::ibd::path::append_stored_headers(&mut st, &hub);
    let queued: Vec<_> = st.ordered.iter().rev().take(2).copied().collect();
    assert_eq!(
        queued,
        vec![third.block_hash(), next.block_hash()],
        "new lookahead must leave the free queue slots for already stored successors"
    );
    assert_eq!(st.header_walk.tip_hash(), Some(fourth.block_hash()));
}

#[test]
fn drained_queue_refills_stored_headers_after_known_header_pruning() {
    let (_dir, mut hub) =
        rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-pruned-refill");
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    floor_unreachable(&mut hub);
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(genesis), Some(0));
    let tail = mine(genesis, 1);
    queue_at_cap_ending_on(&mut st, &hub, tail);
    st.known_headers.extend(st.ordered.iter().copied());
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let next = mine(tail.block_hash(), 2);
    let last = mine(next.block_hash(), 3);
    apply(&mut st, &hub, 0, vec![next, last]);
    assert_eq!(st.header_walk.tip_hash(), Some(last.block_hash()));
    while st.ordered.len() > 1 {
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
    }
    assert_eq!(st.ordered.back(), Some(&tail.block_hash()));
    st.hygiene();
    assert_eq!(
        rbitcoin_ibd::ibd::path::append_stored_headers(&mut st, &hub),
        2,
        "both stored successors must remain available to the download queue after pruning"
    );
    assert_eq!(path_top(&st, &hub), Some((last.block_hash(), 3)));
}

#[test]
fn a_heavier_fork_below_the_floor_is_written_when_the_queue_has_room() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-stray-write");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    floor_unreachable(&mut hub);
    let (s0, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    let mut prev = gen;
    let mut candidate = Vec::new();
    for n in 1..=2 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        candidate.push(hdr);
    }
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, candidate);
    let before = hub.query.store().header_count();
    let mut prev = gen;
    let mut fork = Vec::new();
    for n in 20..26 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        fork.push(hdr);
    }
    let heavy = prev;
    apply(&mut st, &hub, 0, fork);
    assert_eq!(st.header_walk.tip_hash(), Some(heavy));
    assert!(
        hub.query.store().header_count() > before,
        "a heavier fork is written when the queue can hold it"
    );
}

#[test]
fn an_external_block_inv_does_not_retire_the_header_peer() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-external-inv");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
        hash: gen,
        min_work_be: [0; 32],
    });
    let (mut peer, mut rx) = slot(0);
    peer.peer_height = 1;
    let (mut tall, _tall_rx) = slot(1);
    tall.peer_height = 50;
    let mut st = IbdWorkState::new(vec![peer, tall], Some(gen), Some(0));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![mine(gen, 1)]);
    assert_eq!(st.header_walk.reserved, Some(0));
    assert_eq!(st.header_walk.tip_height(), 1);
    assert!(note_external_block_inv(&mut st));
    assert_eq!(st.header_walk.challenge, Some(0));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, vec![]);
    assert_eq!(
        st.header_walk.reserved,
        Some(0),
        "an inv from a peer with no header slot does not drop the reservation"
    );
    assert!(
        !st.header_walk.walk_quiet.contains(&0),
        "that empty reply does not retire the header peer"
    );
}

#[test]
fn an_inflight_external_inv_does_not_retire_on_empty() {
    let (_dir, mut hub) =
        rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-external-inflight");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
        hash: gen,
        min_work_be: [0; 32],
    });
    let (mut peer, mut rx) = slot(0);
    peer.peer_height = 1;
    let (mut tall, _tall_rx) = slot(1);
    tall.peer_height = 50;
    let mut st = IbdWorkState::new(vec![peer, tall], Some(gen), Some(0));
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    assert_eq!(st.header_walk.reserved, Some(0));
    assert_eq!(st.header_walk.walk.peer, Some(0));
    // The walk caught this peer's advertised height while their ask is
    // still out, so the inv is a challenge rather than the next walk ask.
    st.header_walk.tip.height = st.slots[0].peer_height;
    assert!(note_external_block_inv(&mut st));
    assert_eq!(
        st.header_walk.challenge_open,
        Some(0),
        "the ask already in flight is the challenge answer"
    );
    apply(&mut st, &hub, 0, vec![]);
    assert_eq!(
        st.header_walk.reserved,
        Some(0),
        "an inv from a peer with no header slot does not drop the reservation"
    );
    assert!(
        !st.header_walk.walk_quiet.contains(&0),
        "the in-flight empty reply does not retire the header peer"
    );
}

#[test]
fn a_heavier_chain_arriving_in_two_batches_replaces_the_candidate() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-two-batch");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    floor_unreachable(&mut hub);
    let (s0, mut rx) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    let mut prev = gen;
    let mut candidate = Vec::new();
    for n in 1..=4 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        candidate.push(hdr);
    }
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    apply(&mut st, &hub, 0, candidate);
    let candidate_tip = st.header_walk.tip_hash();
    assert_eq!(st.header_walk.tip_height(), 4);
    let before = hub.query.store().header_count();

    let mut prev = gen;
    let mut first = Vec::new();
    for n in 20..22 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        first.push(hdr);
    }
    apply(&mut st, &hub, 0, first);
    assert_eq!(
        st.header_walk.tip_hash(),
        candidate_tip,
        "a short valid batch does not replace a heavier candidate"
    );
    assert_eq!(hub.query.store().header_count(), before);
    assert!(st.slots[0].alive);
    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    match rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => {
            assert!(
                locator.contains(&prev),
                "the ask names the lighter fork so that peer can send the next window"
            );
        }
        Ok(_) => panic!("expected getheaders"),
        Err(_) => panic!("peer was not asked for headers"),
    }

    let mut second = Vec::new();
    for n in 22..26 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        second.push(hdr);
    }
    let heavy = prev;
    apply(&mut st, &hub, 0, second);
    assert!(
        st.slots[0].alive,
        "feeding the heavier chain does not disconnect"
    );
    assert_eq!(st.header_walk.tip_height(), 6);
    assert_eq!(st.header_walk.tip_hash(), Some(heavy));
    assert_eq!(
        hub.query.store().header_count(),
        before,
        "headers past the full queue stay off header.body"
    );
}

#[test]
fn a_fork_from_the_confirmed_tip_keeps_that_height() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-fork-height");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    let h3 = mine(h2.block_hash(), 3);
    floor_unreachable(&mut hub);
    hub.milestone.height = 2;
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    apply(&mut st, &hub, 0, vec![h1, h2]);
    fill_to_cap(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![h3]);
    assert_eq!(st.header_walk.base_height, 2);
    assert_eq!(st.header_walk.tip_height(), 3);
    assert_eq!(st.header_walk.milestone_hash(), Some(h2.block_hash()));

    let mut prev = gen;
    let mut fork = Vec::new();
    for n in 30..35 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        fork.push(hdr);
    }
    let on_milestone = fork[1].block_hash();
    hub.milestone.anchor = Some(rbitcoin_consensus::MilestoneAnchor {
        hash: on_milestone,
        min_work_be: [0xff; 32],
    });
    apply(&mut st, &hub, 0, fork);
    assert!(st.slots[0].alive);
    assert_eq!(
        st.header_walk.tip_height(),
        5,
        "the fork height is the confirmed tip, not the queue tail"
    );
    assert_eq!(
        st.header_walk.milestone_hash(),
        Some(on_milestone),
        "a fork under the milestone drops the abandoned hash"
    );
    assert!(!st.ordered_set.contains(&h2.block_hash()));
}

#[test]
fn a_short_refill_keeps_the_lookahead() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-short-refill");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let a3 = mine(a2.block_hash(), 3);
    let a4 = mine(a3.block_hash(), 4);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, a1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2, a3]);
    while st.ordered.len() + 4 > ORDERED_HEADERS_SOFT_CAP {
        let Some(dropped) = st.ordered.pop_front() else {
            break;
        };
        st.ordered_set.remove(&dropped);
    }
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a4]);
    assert_eq!(st.header_walk.checkpoints().len(), 2);
    let tip = st.header_walk.tip_hash();
    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let before = hub.query.store().header_count();
    apply(&mut st, &hub, 0, vec![a2]);
    assert_eq!(hub.query.store().header_count(), before);
    assert!(st.ordered_set.contains(&a2.block_hash()));
    assert_eq!(st.header_walk.checkpoints().len(), 2);
    assert_eq!(
        st.header_walk.tip_hash(),
        tip,
        "a prefix that has not reached the next checkpoint is not a contradiction"
    );
}

#[test]
fn a_divergent_refill_does_not_drop_a_proven_lookahead() {
    let (_dir, mut hub) =
        rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-proven-refill");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let sibling = mine(a1.block_hash(), 9);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 2,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: a2.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, a1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2]);
    assert!(st.header_walk.proven);
    assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let before = hub.query.store().header_count();
    apply(&mut st, &hub, 0, vec![sibling]);
    assert_eq!(hub.query.store().header_count(), before);
    assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
    assert!(st
        .header_walk
        .checkpoints()
        .iter()
        .any(|c| c.hash == a2.block_hash()));
    assert!(hub
        .query
        .get_header_by_hash(sibling.block_hash().as_byte_array())
        .unwrap()
        .is_none());
    assert!(st.slots[0].alive);
}

#[test]
fn a_header_between_checkpoints_does_not_skip_scripts() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-between-skip");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    let h3 = mine(h2.block_hash(), 3);
    let h4 = mine(h3.block_hash(), 4);
    let side = mine(h1.block_hash(), 9);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 4,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: h4.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, h1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![h2, h3, h4]);
    assert!(st.header_walk.proven);
    assert!(
        skips(&hub, 1, h1.block_hash().as_byte_array()),
        "the queued ancestor of the milestone skips"
    );
    let before = hub.query.store().header_count();

    apply(&mut st, &hub, 0, vec![side]);
    assert_eq!(hub.query.store().header_count(), before);
    assert_eq!(
        hub.query.milestone_header_at(2),
        Some(h2.block_hash().to_byte_array())
    );
    assert!(!skips(&hub, 2, side.block_hash().as_byte_array()));
    assert_eq!(
        st.header_walk.tip_hash(),
        Some(h4.block_hash()),
        "a one-block fork does not replace the candidate"
    );
    assert_eq!(st.header_walk.tip_hash(), Some(h4.block_hash()));
    assert!(st.slots[0].alive);

    for _ in 0..3 {
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
    }
    apply(&mut st, &hub, 0, vec![side]);
    assert_eq!(
        hub.query.store().header_count(),
        before,
        "a refill that has not reached the next checkpoint is not stored"
    );
    assert!(!st.ordered_set.contains(&side.block_hash()));
    assert!(!st.is_on_path(&side.block_hash(), 2));
    assert!(!skips(&hub, 2, side.block_hash().as_byte_array()));
    assert!(skips(&hub, 1, h1.block_hash().as_byte_array()));
    assert_eq!(st.header_walk.tip_hash(), Some(h4.block_hash()));
    assert!(st.slots[0].alive);

    apply(&mut st, &hub, 0, vec![h2, h3, h4]);
    assert!(st.ordered_set.contains(&h2.block_hash()));
    assert!(
        skips(&hub, 2, h2.block_hash().as_byte_array()),
        "a refill that meets the milestone checkpoint skips"
    );
    assert!(skips(&hub, 4, h4.block_hash().as_byte_array()));
}

#[test]
fn a_refill_stops_at_the_agreed_checkpoint() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-stop-at-ckpt");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    let h3 = mine(h2.block_hash(), 3);
    let h4 = mine(h3.block_hash(), 4);
    let h5 = mine(h4.block_hash(), 5);
    let h6 = mine(h5.block_hash(), 6);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 6,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: h6.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, h1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![h2, h3]);
    while st.ordered.len() + 4 > ORDERED_HEADERS_SOFT_CAP {
        let Some(dropped) = st.ordered.pop_front() else {
            break;
        };
        st.ordered_set.remove(&dropped);
    }
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![h4, h5, h6]);
    assert!(st.header_walk.proven);
    assert_eq!(st.header_walk.tip_hash(), Some(h6.block_hash()));

    for _ in 0..3 {
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
    }
    apply(&mut st, &hub, 0, vec![h2, h3, h4]);
    assert_eq!(
        st.header_walk.tip_hash(),
        Some(h6.block_hash()),
        "a prefix of the written chain is not a contradiction"
    );
    assert!(hub
        .query
        .get_header_by_hash(h3.block_hash().as_byte_array())
        .unwrap()
        .is_some());
    assert!(
        hub.query
            .get_header_by_hash(h4.block_hash().as_byte_array())
            .unwrap()
            .is_some(),
        "headers the walk already accepted stay written"
    );
    assert!(skips(&hub, 4, h4.block_hash().as_byte_array()));
    assert!(skips(&hub, 3, h3.block_hash().as_byte_array()));

    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let mut prev = h3.block_hash();
    let mut fork = Vec::new();
    for n in 40..44 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        fork.push(hdr);
    }
    let heavy = prev;
    apply(&mut st, &hub, 0, fork);
    assert!(
        st.slots[0].alive,
        "a heavier fork from the agreed checkpoint does not disconnect"
    );
    assert_eq!(st.header_walk.tip_height(), 7);
    assert_eq!(st.header_walk.tip_hash(), Some(heavy));
    assert!(st
        .header_walk
        .checkpoints()
        .iter()
        .all(|c| c.hash != h6.block_hash()));
}

#[test]
fn a_heavier_fork_from_a_stored_gap_header_is_adopted() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-gap-fork");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let h1 = mine(gen, 1);
    let h2 = mine(h1.block_hash(), 2);
    let h3 = mine(h2.block_hash(), 3);
    let h4 = mine(h3.block_hash(), 4);
    let h5 = mine(h4.block_hash(), 5);
    let h6 = mine(h5.block_hash(), 6);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 6,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: h6.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, h1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![h2, h3]);
    while st.ordered.len() + 4 > ORDERED_HEADERS_SOFT_CAP {
        let Some(dropped) = st.ordered.pop_front() else {
            break;
        };
        st.ordered_set.remove(&dropped);
    }
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![h4, h5, h6]);
    assert!(st.header_walk.proven);
    assert_eq!(st.header_walk.tip_hash(), Some(h6.block_hash()));

    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    apply(&mut st, &hub, 0, vec![h2, h3, h4]);
    assert_eq!(
        st.header_walk.tip_hash(),
        Some(h6.block_hash()),
        "a stored prefix between checkpoints does not replace the candidate"
    );
    assert!(st
        .header_walk
        .checkpoints()
        .iter()
        .all(|c| c.hash != h2.block_hash()));
    assert!(hub
        .query
        .get_header_by_hash(h2.block_hash().as_byte_array())
        .unwrap()
        .is_some());

    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let mut prev = h2.block_hash();
    let mut fork = Vec::new();
    for n in 40..45 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        fork.push(hdr);
    }
    let heavy = prev;
    let fork_child = fork[0].block_hash();
    apply(&mut st, &hub, 0, fork);
    assert!(
        st.slots[0].alive,
        "a heavier fork from a stored header between checkpoints does not disconnect"
    );
    assert_eq!(st.header_walk.tip_height(), 7);
    assert_eq!(st.header_walk.tip_hash(), Some(heavy));
    assert!(
        st.is_on_path(&fork_child, 3),
        "the adopted fork becomes the download path"
    );
    assert!(!skips(&hub, 6, h6.block_hash().as_byte_array()));
}

/// Block that extends `prev` at `height`, with a real coinbase.
fn mine_block(prev: BlockHash, height: u32) -> bitcoin::Block {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let mut ss = rbitcoin_consensus::bip34_height_script(height);
    while ss.len() < 2 {
        ss.push(0x00);
    }
    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = bitcoin::Block {
        header: mine(prev, height),
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    block
}

/// A block inv asks only once the header lane is idle. A fresh ask keeps
/// the challenge until that reply lands.
#[test]
fn a_stale_announcement_asks_while_headers_are_done() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-inv-stale");
    hub.ensure_genesis().unwrap();
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], hub.tip_hash(), hub.tip_height());
    st.headers_done = true;
    st.header_walk.challenge = Some(0);
    let poll = || HeaderPollIn {
        live: ORDERED_HEADERS_SOFT_CAP,
        need_ready_headroom: false,
        lag: 0,
        min_cache: 1,
        fan: 0,
    };
    assert!(
        matches!(header_poll(&st, poll()), HeaderPoll::Ask),
        "a block announcement with no header ask in flight still asks"
    );
    st.header_walk.walk.peer = Some(0);
    st.header_walk.walk.at = Some(std::time::Instant::now());
    assert!(
        matches!(header_poll(&st, poll()), HeaderPoll::Wait),
        "an announcement does not ask again while that header ask is in flight"
    );
}

/// Checkpoint timestamps are the median-time window when the tip has not
/// copied them yet. The tip's own window wins once it has one.
#[test]
fn checkpoint_times_stand_in_for_an_empty_tip() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-times");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    floor_unreachable(&mut hub);
    let mut prev = gen;
    let mut chain = Vec::new();
    for n in 1..=12 {
        let hdr = mine(prev, n);
        prev = hdr.block_hash();
        chain.push(hdr);
    }
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, chain.clone());
    let tip = chain[11];
    let real = st.header_walk.tip.times.clone();
    assert_eq!(real.len(), 11);
    let raised: Vec<u32> = real.iter().map(|t| t.saturating_add(10_000)).collect();
    st.header_walk.checkpoints.last_mut().unwrap().times = raised.clone();
    st.header_walk.tip.times.clear();
    let from_checkpoint = times_ending_at(&st, &hub, tip.block_hash());
    assert_eq!(
        from_checkpoint, raised,
        "an empty tip takes the checkpoint median-time window"
    );
    st.header_walk.tip.times = real.clone();
    let from_tip = times_ending_at(&st, &hub, tip.block_hash());
    assert_eq!(
        from_tip, real,
        "the tip's own window is kept when a checkpoint disagrees"
    );
}

/// Two empty replies abandon the candidate. The previous dead tip stays
/// dead, and a queued hash with no height is not the abandoned one.
#[test]
fn two_abandoned_candidates_both_stay_dead() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-two-dead");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let b1 = mine(gen, 11);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let (s1, _rx1) = slot(1);
    let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1]);
    let kept = BlockHash::from_byte_array([0x44; 32]);
    st.ordered.push_back(kept);
    st.ordered_set.insert(kept);
    apply(&mut st, &hub, 0, vec![]);
    apply(&mut st, &hub, 1, vec![]);
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    assert!(
        st.header_walk.dead_ends.contains(&a1.block_hash()),
        "the first abandoned tip stays dead"
    );
    assert!(
        st.ordered_set.contains(&kept),
        "a queued hash with no height is not the dead tip"
    );

    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![b1]);
    apply(&mut st, &hub, 0, vec![]);
    apply(&mut st, &hub, 1, vec![]);
    assert!(st.header_walk.dead_ends.contains(&a1.block_hash()));
    assert!(
        st.header_walk.dead_ends.contains(&b1.block_hash()),
        "a second abandoned tip does not forget the first"
    );
}

/// Equal work is a challenger, not a new tip. One more header promotes
/// it and drops checkpoints above the fork.
#[test]
fn a_tied_challenger_stays_off_the_tip_until_it_is_heavier() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-tie");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let a3 = mine(a2.block_hash(), 3);
    let s2 = mine(a1.block_hash(), 12);
    let s3 = mine(s2.block_hash(), 13);
    let s4 = mine(s3.block_hash(), 14);
    let weak = mine(a1.block_hash(), 21);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let (s1, _rx1) = slot(1);
    let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a3]);
    assert_eq!(st.header_walk.tip_hash(), Some(a3.block_hash()));
    assert!(
        st.header_walk
            .checkpoints()
            .iter()
            .any(|c| c.hash == a1.block_hash()),
        "the first lookahead is a checkpoint below the tip"
    );

    let replay = hub.query.store().header_count();
    apply(&mut st, &hub, 0, vec![a1]);
    assert_eq!(
        hub.query.store().header_count(),
        replay,
        "a batch that ends on an earlier checkpoint is not a new chain"
    );
    assert_eq!(st.header_walk.tip_hash(), Some(a3.block_hash()));
    assert!(
        st.header_walk.challenger.is_none(),
        "replaying a checkpoint does not open a challenger"
    );
    assert!(st.slots[0].alive);

    apply(&mut st, &hub, 0, vec![s2]);
    assert_eq!(
        st.header_walk.challenger.as_ref().and_then(|c| c.tip.hash),
        Some(s2.block_hash()),
        "a lighter fork is remembered"
    );
    assert_eq!(st.header_walk.tip_hash(), Some(a3.block_hash()));
    apply(&mut st, &hub, 0, vec![weak]);
    assert_eq!(
        st.header_walk.challenger.as_ref().and_then(|c| c.tip.hash),
        Some(s2.block_hash()),
        "a lighter fork does not replace the challenger"
    );
    apply(&mut st, &hub, 0, vec![s3]);
    assert_eq!(
        st.header_walk.tip_hash(),
        Some(a3.block_hash()),
        "matching work does not promote the challenger"
    );
    assert_eq!(
        st.header_walk.challenger.as_ref().and_then(|c| c.tip.hash),
        Some(s3.block_hash()),
        "the tied extension is still the challenger"
    );

    apply(&mut st, &hub, 0, vec![s4]);
    assert_eq!(
        st.header_walk.tip_hash(),
        Some(s4.block_hash()),
        "one header past the tie replaces the candidate"
    );
    assert!(
        st.header_walk
            .checkpoints()
            .iter()
            .any(|c| c.hash == a1.block_hash()),
        "checkpoints at or below the fork stay"
    );
    assert!(
        st.header_walk
            .checkpoints()
            .iter()
            .all(|c| c.hash != a3.block_hash()),
        "checkpoints above the fork are dropped"
    );
}

/// A rewind to the fork height keeps that checkpoint and the challenger.
/// Dropping every checkpoint above the base drops the challenger too.
#[test]
fn rewind_keeps_a_challenger_forked_at_a_live_checkpoint() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-retain");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let side = mine(a1.block_hash(), 12);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2]);
    apply(&mut st, &hub, 0, vec![side]);
    assert_eq!(
        st.header_walk.challenger.as_ref().map(|c| c.fork_hash),
        Some(a1.block_hash()),
        "the side header forks at the first checkpoint"
    );
    rewind_above(&mut st, &hub, 1);
    assert!(
        st.header_walk
            .checkpoints()
            .iter()
            .any(|c| c.hash == a1.block_hash()),
        "the checkpoint at the rewind height stays"
    );
    assert!(
        st.header_walk
            .checkpoints()
            .iter()
            .all(|c| c.hash != a2.block_hash()),
        "a checkpoint above the rewind is popped"
    );
    assert!(
        st.header_walk
            .challenger
            .as_ref()
            .is_some_and(|c| c.fork_hash == a1.block_hash()),
        "the challenger stays while its fork checkpoint is on the walk"
    );
    rewind_above(&mut st, &hub, 0);
    assert!(
        st.header_walk.challenger.is_none(),
        "rewinding under the fork drops the challenger"
    );
}

/// The fork is the walk base, and the tip is a later checkpoint. Rewinding
/// onto that checkpoint must keep the challenger: the base is still on the
/// candidate even though the tip hash is not the fork.
#[test]
fn rewind_keeps_a_challenger_forked_at_the_base() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-retain-base");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let side = mine(gen, 12);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1]);
    apply(&mut st, &hub, 0, vec![side]);
    assert_eq!(
        st.header_walk.challenger.as_ref().map(|c| c.fork_hash),
        Some(gen),
        "the side header forks at the confirmed base"
    );
    rewind_above(&mut st, &hub, 1);
    assert_eq!(st.header_walk.tip_hash(), Some(a1.block_hash()));
    assert!(
        st.header_walk
            .challenger
            .as_ref()
            .is_some_and(|c| c.fork_hash == gen),
        "the challenger stays while the walk base is its fork"
    );
}

/// Popping the fork's checkpoint, while an earlier checkpoint remains,
/// drops the challenger. The fork is neither the base nor the new tip.
#[test]
fn rewind_drops_a_challenger_when_its_fork_checkpoint_is_gone() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-retain-drop");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let a3 = mine(a2.block_hash(), 3);
    let side = mine(a2.block_hash(), 12);
    floor_unreachable(&mut hub);
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    fill_queue(&mut st);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a1]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2]);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a3]);
    apply(&mut st, &hub, 0, vec![side]);
    assert_eq!(
        st.header_walk.challenger.as_ref().map(|c| c.fork_hash),
        Some(a2.block_hash()),
        "the side header forks at the middle checkpoint"
    );
    rewind_above(&mut st, &hub, 1);
    assert!(
        st.header_walk
            .checkpoints()
            .iter()
            .any(|c| c.hash == a1.block_hash()),
        "the checkpoint under the cut stays"
    );
    assert!(
        st.header_walk
            .checkpoints()
            .iter()
            .all(|c| c.hash != a2.block_hash()),
        "the fork checkpoint above the cut is popped"
    );
    assert!(
        st.header_walk.challenger.is_none(),
        "a fork that is no longer a base, tip, or checkpoint is dropped"
    );
}

/// A diverging refill whose headers do not link is not a chain. Comparing
/// its first header would remember a challenger for a reply that breaks.
#[test]
fn an_unlinked_divergent_refill_is_not_a_challenger() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-unlinked");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let a1 = mine(gen, 1);
    let a2 = mine(a1.block_hash(), 2);
    let sibling = mine(a1.block_hash(), 9);
    let broken = mine(gen, 11);
    let mut floor = [0u8; 32];
    floor[31] = 1;
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 2,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: a2.block_hash(),
            min_work_be: floor,
        }),
    };
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    queue_at_cap_ending_on(&mut st, &hub, a1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    apply(&mut st, &hub, 0, vec![a2]);
    assert!(st.header_walk.proven);
    let dropped = st.ordered.pop_front().unwrap();
    st.ordered_set.remove(&dropped);
    let before = hub.query.store().header_count();
    apply(&mut st, &hub, 0, vec![sibling, broken]);
    assert_eq!(hub.query.store().header_count(), before);
    assert_eq!(st.header_walk.tip_hash(), Some(a2.block_hash()));
    assert!(
        st.header_walk.challenger.is_none(),
        "a batch that does not link is not a competing chain"
    );
    assert!(st.slots[0].alive);
}

/// The walk base is genesis and the download path has a hole under the
/// confirmed tip, so only the confirmed tip can price the next header.
#[test]
fn stored_work_uses_the_confirmed_tip_when_the_base_does_not_link() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("header-walk-stored-tip");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let gen_work = hub.chain_work().unwrap();
    hub.generate_to_script(2, bitcoin::ScriptBuf::from_bytes(vec![0x51]), Vec::new())
        .unwrap();
    let tip = hub.tip_hash().unwrap();
    let tip_h = hub.tip_height().unwrap();
    let mut next = mine(tip, 40);
    next.time = hub.tip_header().unwrap().time.saturating_add(60);
    rbitcoin_consensus::grind_regtest_pow(&mut next);
    hub.ensure_header(&next).unwrap();
    let (s0, _rx0) = slot(0);
    let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
    st.header_walk.base_hash = Some(gen);
    st.header_walk.base_height = 0;
    st.header_walk.base_work = gen_work.to_be_bytes();
    st.header_walk.checkpoints.push(Checkpoint {
        hash: BlockHash::from_byte_array([0xab; 32]),
        height: tip_h + 10,
        work: [0u8; 32],
        header: None,
        times: Vec::new(),
        diff: DiffSnap::default(),
    });
    st.record_height(next.block_hash(), tip_h + 1);
    let (work, _) = stored_path_state(&st, &hub, next.block_hash())
        .expect("the confirmed tip prices a header the base cannot reach");
    assert_eq!(work, hub.chain_work().unwrap() + next.work());
}

fn byte_hash(n: u8) -> BlockHash {
    let mut raw = [0u8; 32];
    raw[31] = n;
    BlockHash::from_byte_array(raw)
}

fn mark_checkpoint(hash: BlockHash, height: u32) -> Checkpoint {
    Checkpoint {
        hash,
        height,
        work: [0; 32],
        header: None,
        times: Vec::new(),
        diff: DiffSnap::default(),
    }
}

fn fresh_walk() -> IbdWorkState {
    let (peer, _rx) = slot(0);
    IbdWorkState::new(vec![peer], None, None)
}

fn plant_challenger(st: &mut IbdWorkState, fork: BlockHash) {
    st.header_walk.challenger = Some(Challenger {
        fork_hash: fork,
        fork_height: 1,
        tip: WalkTip::default(),
        checkpoints: Vec::new(),
    });
}

#[test]
fn retain_challenger_keeps_a_fork_that_is_still_on_the_candidate() {
    let fork = byte_hash(1);
    let other = byte_hash(2);
    let mut st = fresh_walk();
    st.header_walk.base_hash = Some(fork);
    plant_challenger(&mut st, fork);
    retain_challenger(&mut st);
    assert!(
        st.header_walk.challenger.is_some(),
        "the walk base still holds the fork"
    );

    st.header_walk.base_hash = Some(other);
    st.header_walk.checkpoints.push(mark_checkpoint(fork, 4));
    retain_challenger(&mut st);
    assert!(
        st.header_walk.challenger.is_some(),
        "a checkpoint still holds the fork"
    );

    st.header_walk.checkpoints.clear();
    retain_challenger(&mut st);
    assert!(
        st.header_walk.challenger.is_none(),
        "a fork off the candidate is dropped"
    );
}

#[test]
fn adopt_heavier_keeps_the_milestone_at_the_fork_height() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-adopt-pin");
    hub.ensure_genesis().unwrap();
    let prev = byte_hash(3);
    let header = Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([4; 32]),
        time: 1_600_000_100,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: 1,
    };
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], hub.tip_hash(), hub.tip_height());
    st.hash_height.insert(prev, 5);
    hub.milestone.height = 5;
    let marker = byte_hash(9);
    st.header_walk.tip.milestone_hash = Some(marker);
    let mut raw = [0u8; 32];
    raw[31] = 9;
    let passed = Work::from_be_bytes(raw);
    adopt_heavier(&mut st, &hub, prev, &[header], passed);
    assert_eq!(st.header_walk.tip.milestone_hash, Some(marker));
    assert_eq!(st.header_walk.tip.work, passed);
}

#[test]
fn walk_ahead_of_stored_is_strictly_above_the_recorded_height() {
    let mut st = fresh_walk();
    st.header_walk.origin = true;
    st.header_walk.tip.height = 4;
    st.max_ordered_height = 4;
    assert!(!walk_ahead_of_stored(&st));
    st.header_walk.tip.height = 5;
    assert!(walk_ahead_of_stored(&st));
}

#[test]
fn classify_pins_an_unlinked_batch_a_refill_and_the_first_checkpoint() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-classify-pin");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let mut broken = mine(good.block_hash(), 2);
    broken.prev_blockhash = byte_hash(8);
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    assert_eq!(
        classify(&st, &hub, HeaderAsk::InWindow, &[good, broken]),
        HeaderClass::Fork,
        "an unlinked batch is not a refill of the stored tip"
    );
    assert_eq!(
        classify(&st, &hub, HeaderAsk::InWindow, &[good]),
        HeaderClass::Refill
    );

    st.header_walk.origin = true;
    st.header_walk.tip.hash = Some(gen);
    st.header_walk.tip.height = 0;
    assert_eq!(
        classify(&st, &hub, HeaderAsk::InWindow, &[good]),
        HeaderClass::WalkAbsorb,
        "the first solicited continuation is a checkpoint"
    );
}

#[test]
fn headers_late_is_logged_only_for_a_late_extension() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-late-pin");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 7);
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    st.header_walk.origin = true;
    st.header_walk.tip.hash = Some(gen);
    st.header_walk.tip.height = 0;
    st.header_walk.tip.header = hub.tip_header();
    rbitcoin_log::capture_logs(true);
    assert!(absorb_lookahead(
        &mut st,
        &hub,
        0,
        HeaderAsk::InWindow,
        &[good]
    ));
    let on_time = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        on_time
            .iter()
            .all(|(_, line)| !line.contains("ibd: headers late")),
        "an in-window extension is not late: {on_time:?}"
    );

    let next = mine(good.block_hash(), 8);
    rbitcoin_log::capture_logs(true);
    assert!(absorb_lookahead(&mut st, &hub, 0, HeaderAsk::Late, &[next]));
    let late = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        late.iter()
            .any(|(_, line)| line.contains("ibd: headers late")),
        "a late extension names itself: {late:?}"
    );
}

fn floor_above(hub: &mut ChainHub) {
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 100,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: byte_hash(1),
            min_work_be: [0xff; 32],
        }),
    };
}

#[test]
fn ignore_below_floor_pins_the_floor_gate_and_the_queue_cap() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-floor-pin");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 1);
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    st.header_walk.origin = true;
    st.header_walk.tip.hash = Some(byte_hash(3));
    st.header_walk.tip.work = Work::from_be_bytes([0; 32]);
    st.header_walk.dead_ends.insert(gen);
    assert!(
        !ignore_below_floor(&st, &hub, &[good]),
        "above the floor a dead-end parent is not ignored"
    );

    floor_above(&mut hub);
    st.header_walk.origin = false;
    assert!(
        !ignore_below_floor(&st, &hub, &[good]),
        "below the floor a walk that has not started is not ignored"
    );
    st.header_walk.origin = true;
    st.header_walk.dead_ends.clear();
    assert!(
        !ignore_below_floor(&st, &hub, &[good]),
        "under the cap the stored tip's child is still the download path"
    );
    fill_queue(&mut st);
    plant_on_queue(&mut st, gen, 0);
    assert!(
        ignore_below_floor(&st, &hub, &[good]),
        "a full queue does not keep writing that child"
    );
}

fn heavy_proved(st: &mut IbdWorkState, hub: &ChainHub) {
    st.header_walk.origin = true;
    st.header_walk.proven = true;
    st.header_walk.tip.hash = hub.tip_hash();
    st.header_walk.tip.height = hub.tip_height().unwrap_or(0);
    st.header_walk.tip.work = Work::from_be_bytes([0xff; 32]);
}

#[test]
fn reject_refill_miss_pins_each_reason_it_returns() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-refill-pin");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let good = mine(gen, 3);
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    heavy_proved(&mut st, &hub);
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(9), 1));
    st.header_walk.origin = false;
    assert!(
        !reject_refill_miss(&mut st, &hub, &[good]),
        "a walk with no origin does not judge the refill"
    );

    heavy_proved(&mut st, &hub);
    st.header_walk.checkpoints.clear();
    let queued = byte_hash(8);
    st.ordered.push_back(queued);
    st.ordered_set.insert(queued);
    st.hash_height.insert(queued, 1);
    assert!(
        !reject_refill_miss(&mut st, &hub, &[good]),
        "no checkpoint means there is nothing to miss"
    );
    st.ordered.clear();
    st.ordered_set.clear();
    st.hash_height.remove(&queued);

    heavy_proved(&mut st, &hub);
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(9), 1));
    fill_queue(&mut st);
    plant_on_queue(&mut st, gen, 0);
    assert!(
        !reject_refill_miss(&mut st, &hub, &[good]),
        "a full queue is not a refill"
    );

    let stray = mine(byte_hash(7), 4);
    let (peer, _rx) = slot(1);
    let mut open = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    heavy_proved(&mut open, &hub);
    open.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(9), 1));
    open.header_walk.tip.hash = Some(byte_hash(6));
    assert!(
        !reject_refill_miss(&mut open, &hub, &[stray]),
        "a batch that does not build on the confirmed tip is not a refill miss"
    );
}

#[test]
fn proved_above_floor_requires_both() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-proved-pin");
    hub.ensure_genesis().unwrap();
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], hub.tip_hash(), Some(0));
    st.header_walk.proven = false;
    st.header_walk.tip.work = Work::from_be_bytes([0xff; 32]);
    assert!(!proved_above_floor(&st, &hub));
    st.header_walk.proven = true;
    assert!(proved_above_floor(&st, &hub));
}

#[test]
fn unproved_anchor_stops_at_a_met_checkpoint_and_keeps_the_one_below() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-anchor-pin");
    hub.ensure_genesis().unwrap();
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], hub.tip_hash(), Some(0));
    let front = byte_hash(5);
    st.ordered.push_back(front);
    st.ordered_set.insert(front);
    st.hash_height.insert(front, 5);
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(3), 3));
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(4), 5));
    assert!(unproved_anchor(&st, &hub).is_none());

    st.header_walk.checkpoints.pop();
    assert_eq!(unproved_anchor(&st, &hub), Some((byte_hash(3), 3)));

    st.header_walk.checkpoints.clear();
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(3), 3));
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(6), 3));
    assert_eq!(
        unproved_anchor(&st, &hub),
        Some((byte_hash(3), 3)),
        "two checkpoints at one height keep the earlier hash"
    );
}

#[test]
fn candidate_prev_accepts_base_tip_and_checkpoint() {
    let prev = byte_hash(1);
    let mut st = fresh_walk();
    st.header_walk.base_hash = Some(prev);
    assert!(candidate_prev(&st, prev));
    st.header_walk.base_hash = None;
    st.header_walk.tip.hash = Some(prev);
    assert!(candidate_prev(&st, prev));
    st.header_walk.tip.hash = None;
    st.header_walk.checkpoints.push(mark_checkpoint(prev, 2));
    assert!(candidate_prev(&st, prev));
    st.header_walk.checkpoints.clear();
    assert!(!candidate_prev(&st, prev));
}

fn prefix_body(st: &mut IbdWorkState, _hub: &ChainHub, prev: BlockHash) -> Vec<Header> {
    st.header_walk.proven = true;
    st.header_walk.origin = true;
    st.header_walk.tip.work = Work::from_be_bytes([0xff; 32]);
    st.header_walk.base_hash = Some(prev);
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(9), 50));
    vec![mine(prev, 11)]
}

#[test]
fn proven_header_prefix_writes_the_whole_reply_until_the_candidate_is_proved() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-prefix-pin");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    let prev = byte_hash(4);
    let headers = prefix_body(&mut st, &hub, prev);
    st.header_walk.proven = false;
    assert_eq!(proven_header_prefix(&st, &hub, &headers), headers.len());
    st.header_walk.proven = true;
    st.header_walk.origin = false;
    assert_eq!(proven_header_prefix(&st, &hub, &headers), headers.len());
    st.header_walk.origin = true;
    floor_above(&mut hub);
    st.header_walk.tip.work = Work::from_be_bytes([0; 32]);
    assert_eq!(proven_header_prefix(&st, &hub, &headers), headers.len());
    hub.milestone.anchor = None;
    st.header_walk.tip.work = Work::from_be_bytes([0xff; 32]);
    assert_eq!(
        proven_header_prefix(&st, &hub, &headers),
        0,
        "a proved candidate writes no header that misses the checkpoint"
    );
}

#[test]
fn refill_misses_checkpoint_only_above_the_queue_tail() {
    let tail = byte_hash(1);
    let first = mine(tail, 21);
    let second = mine(first.block_hash(), 22);
    let mut st = fresh_walk();
    st.header_walk.checkpoints.push(mark_checkpoint(tail, 5));
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(first.block_hash(), 6));
    st.header_walk
        .checkpoints
        .push(mark_checkpoint(byte_hash(8), 7));
    assert!(refill_misses_checkpoint(&st, 5, &[first, second]));
    st.header_walk.checkpoints.clear();
    st.header_walk.checkpoints.push(mark_checkpoint(tail, 5));
    assert!(!refill_misses_checkpoint(&st, 5, &[first]));
}

#[test]
fn note_empty_rewinds_only_when_every_taller_peer_is_empty() {
    let (_dir, mut hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-empty-pin");
    hub.ensure_genesis().unwrap();
    floor_above(&mut hub);
    let gen = hub.tip_hash().unwrap();
    let (mut tall, _rx0) = slot(0);
    tall.peer_height = 10;
    let (mut level, _rx1) = slot(1);
    level.peer_height = 3;
    let mut st = IbdWorkState::new(vec![tall, level], Some(gen), Some(0));
    st.header_walk.origin = true;
    st.header_walk.base_hash = Some(gen);
    st.header_walk.base_height = 0;
    st.header_walk.tip.hash = Some(byte_hash(4));
    st.header_walk.tip.height = 3;
    st.header_walk.tip.work = Work::from_be_bytes([0; 32]);
    assert!(note_empty(&mut st, &hub, 0));
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
}

#[test]
fn note_stored_candidate_ignores_a_dead_end_tip() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-stored-pin");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (peer, _rx) = slot(0);
    let mut st = IbdWorkState::new(vec![peer], Some(gen), Some(0));
    st.header_walk.origin = true;
    st.header_walk.tip.hash = Some(gen);
    st.header_walk.tip.height = 0;
    st.header_walk.dead_ends.insert(gen);
    note_stored_candidate(&mut st, &hub, &[mine(gen, 30)]);
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    assert!(st.header_walk.checkpoints.is_empty());

    st.header_walk.dead_ends.clear();
    let mut broken = mine(gen, 31);
    broken.bits = CompactTarget::from_consensus(0x1d00ffff);
    note_stored_candidate(&mut st, &hub, &[broken]);
    assert_eq!(st.header_walk.tip_hash(), Some(gen));
    assert!(st.header_walk.checkpoints.is_empty());
}
