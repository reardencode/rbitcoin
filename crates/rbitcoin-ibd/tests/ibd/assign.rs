use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_ibd::ibd::peer_io::solicit_track;
use rbitcoin_ibd::ibd::peer_io::{PeerCmd, PeerSlot};
use rbitcoin_ibd::ibd::state::{self, IbdWorkState};
use rbitcoin_ibd::ibd::status::LoopStats;
use rbitcoin_ibd::ibd::{IbdConfig, PRE_HOLE_MAX_PEERS, TIP_HOLE_MAX, TIP_HOLE_MAX_PEERS};
use rbitcoin_net::chain::ChainHub;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rbitcoin_ibd::ibd::assign::*;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::mpsc;

#[test]
fn need_any_valid_body_download_empty_and_missing_tip_child() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    assert!(
        !need_any_valid_body_download(&st, &hub),
        "genesis-only path has no body download"
    );
    let want = h(0x21);
    let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
    st.record_height(want, ht);
    st.height_to_hash.insert(ht, want);
    st.body.mark_missing(want);
    assert!(
        need_any_valid_body_download(&st, &hub),
        "missing tip+1 must keep download open"
    );
    let _ = std::fs::remove_dir_all(dir);
}

pub(crate) fn h(n: u32) -> BlockHash {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&n.to_le_bytes());
    BlockHash::from_byte_array(b)
}

pub(crate) fn dummy_slot(id: usize) -> PeerSlot {
    let (cmd_tx, _rx) = mpsc::unbounded_channel();
    let task = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .spawn(async {});
    PeerSlot {
        id,
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444 + id as u16),
        net: rbitcoin_net::NetAddr::from_socket(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            18444 + id as u16,
        )),
        cmd_tx,
        in_flight: HashSet::new(),
        requested: solicit_track().0,
        solicited_bytes: solicit_track().1,
        solicited_ms: solicit_track().2,
        any_rx_ms: Arc::new(AtomicU64::new(0)),
        getdata_wire: rbitcoin_ibd::ibd::peer_io::GetdataWire::new(),
        peer_height: 100,
        connected_ms: 1,
        first_data_ms: 0,
        bytes_rx_total: Arc::new(AtomicU64::new(0)),
        rate: Default::default(),
        chain: Default::default(),
        conn_type: rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
        block_download_paused_until: None,
        alive: true,
        task,
    }
}

pub(crate) fn plant_work_path(st: &mut IbdWorkState, lo: u32, hi: u32) {
    for ht in lo..=hi {
        let hash = h(ht);
        st.record_height(hash, ht);
        st.height_to_hash.insert(ht, hash);
        st.ordered_set.insert(hash);
        st.ordered.push_back(hash);
        st.max_ordered_height = ht;
        st.body.mark_missing(hash);
    }
}

/// A known rate is not recent rx. The synthetic 5 s sample would read as
/// recent only while the test process is under 35 s old, so rx is
/// `note_rx` alone.
fn seed_ewma(slot: &mut PeerSlot, bytes_per_sec: u64) {
    let progress_ms = slot.rate.progress_ms;
    slot.rate.sample(0, 0, true);
    slot.rate
        .sample(5_000, bytes_per_sec.saturating_mul(5), true);
    slot.rate.progress_ms = progress_ms;
}

pub(crate) fn wired_slots(n: usize) -> (Vec<PeerSlot>, Vec<mpsc::UnboundedReceiver<PeerCmd>>) {
    (0..n)
        .map(|id| {
            let mut slot = dummy_slot(id);
            let (tx, rx) = mpsc::unbounded_channel();
            slot.cmd_tx = tx;
            (slot, rx)
        })
        .unzip()
}

/// Getdata for `hash` each peer received since the last drain.
fn getdata_asks(wire: &mut [mpsc::UnboundedReceiver<PeerCmd>], hash: BlockHash) -> Vec<usize> {
    wire.iter_mut()
        .map(|rx| {
            let mut n = 0;
            while let Ok(cmd) = rx.try_recv() {
                if let PeerCmd::GetData { hashes } = cmd {
                    n += hashes.iter().filter(|&&x| x == hash).count();
                }
            }
            n
        })
        .collect()
}

/// IBD restarts on the same hub: empty body queue, fresh work state, and
/// the same peers with drained queues and unknown rates. Only `alive` are
/// connected.
fn restart_on(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    wire: &mut [mpsc::UnboundedReceiver<PeerCmd>],
    alive: &[usize],
) {
    for ht in hub.query.block_queue_queued_heights() {
        hub.query.block_queue_dequeue_height(ht).unwrap();
    }
    let _ = getdata_asks(wire, BlockHash::all_zeros());
    let mut slots = std::mem::take(&mut st.slots);
    for s in &mut slots {
        s.track_clear();
        s.rate = Default::default();
        s.alive = alive.contains(&s.id);
    }
    *st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
}

fn plant_tip_hole(st: &mut IbdWorkState, hash: BlockHash, ht: u32) {
    st.record_height(hash, ht);
    st.height_to_hash.insert(ht, hash);
    st.body.mark_missing(hash);
}

fn mark_tip_batch_ready(st: &mut IbdWorkState, hub: &ChainHub, path_lo: u32) {
    use bitcoin::hashes::Hash as _;
    for ht in path_lo..=32 {
        hub.query
            .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 81])
            .unwrap();
        st.body.mark_pending(h(ht));
    }
}

fn mark_heights_ready(st: &mut IbdWorkState, hub: &ChainHub, lo: u32, hi: u32) {
    use bitcoin::hashes::Hash as _;
    for ht in lo..=hi {
        hub.query
            .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 81])
            .unwrap();
        st.body.mark_pending(h(ht));
    }
}

/// 75 header-only bodies past the tip window. At 5 blk/s the confirm window is
/// 300 blocks, so this is a quarter of that window.
fn plant_quarter_window(hub: &ChainHub, path_lo: u32) {
    use bitcoin::hashes::Hash as _;
    let start = path_lo.saturating_add(64);
    for i in 0..75u32 {
        let ht = start.saturating_add(i);
        hub.query
            .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 81])
            .unwrap();
    }
}

pub(crate) fn tmp_hub() -> (rbitcoin_query::testutil::TempDir, ChainHub) {
    rbitcoin_net::chain::tiny_regtest_hub_labeled("assign")
}

/// A split that has left the path reads the confirmed header. That read
/// must not run while the coordinator flag is set, or the header thread
/// blocks on `shared` for a store pread.
#[test]
fn off_path_split_settles_outside_the_coord_lock() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    let mut other = hub.tip_header().unwrap();
    other.nonce = other.nonce.wrapping_add(1);
    let mut slot = dummy_slot(0);
    slot.chain.note_headers(
        &HashMap::new(),
        |_| Some(genesis),
        0,
        0,
        std::slice::from_ref(&other),
    );
    let mut st = IbdWorkState::new(vec![slot], hub.tip_hash(), hub.tip_height());
    // `new` plants the tip. Settlement runs only once that height has left the path.
    st.height_to_hash.remove(&0);
    let heights = rbitcoin_ibd::ibd::header_walk::split_heights_off_path(&st);
    assert_eq!(
        heights,
        vec![0],
        "the foreign genesis split has left the path"
    );
    let shared = std::sync::Mutex::new(st);
    let before = rbitcoin_query::header_lookup_count();
    let _probe = rbitcoin_store::HeaderThreadProbe::arm();
    rbitcoin_query::reset_header_lookups_under_coord_lock();
    rbitcoin_ibd::ibd::settle_off_path_for_test(&shared, &hub);
    assert!(
        rbitcoin_query::header_lookup_count() > before,
        "settling the split read the confirmed header"
    );
    assert_eq!(
        rbitcoin_query::header_lookups_under_coord_lock(),
        0,
        "that read ran while the coordinator lock was down"
    );
    assert_eq!(rbitcoin_store::coord_lock_store_reads(), 0);
    let st = shared.lock().unwrap_or_else(|err| err.into_inner());
    assert!(
        st.slots[0].chain.left_path_by(&HashMap::new(), 0),
        "a different confirmed block leaves the peer off the path"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Headers are stored and the walk tip is ahead, but tip+1 is not planted.
/// Assign used to walk those headers while `shared` was held. A linear
/// extension is not a rewind; the read still has to happen with the lock down.
#[test]
fn unplanted_walk_reads_headers_outside_the_coord_lock() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    let first = rbitcoin_consensus::mine_empty_regtest(genesis, 1_500_070_100, 1);
    hub.ensure_header(&first.header).unwrap();
    let second = rbitcoin_consensus::mine_empty_regtest(first.block_hash(), 1_500_070_200, 2);
    hub.ensure_header(&second.header).unwrap();
    let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
    st.header_walk.origin = true;
    st.header_walk.tip.hash = Some(second.block_hash());
    st.header_walk.tip.height = 2;
    let shared = std::sync::Mutex::new(st);
    let before = rbitcoin_query::header_lookup_count();
    let _probe = rbitcoin_store::HeaderThreadProbe::arm();
    rbitcoin_query::reset_header_lookups_under_coord_lock();
    rbitcoin_ibd::ibd::settle_disconnected_heavier_for_test(&shared, &hub);
    assert!(
        rbitcoin_query::header_lookup_count() > before,
        "the unplanted walk read stored headers"
    );
    assert_eq!(
        rbitcoin_query::header_lookups_under_coord_lock(),
        0,
        "that read ran while the coordinator lock was down"
    );
    assert_eq!(rbitcoin_store::coord_lock_store_reads(), 0);
    assert_eq!(
        hub.tip_height(),
        Some(0),
        "a linear extension above genesis is not a rewind"
    );
    let st = shared.lock().unwrap_or_else(|err| err.into_inner());
    assert!(
        st.ordered.is_empty(),
        "the linear candidate stays unplanted"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn download_gate_stops_getdata_when_tip_plus_one_unconfirmable() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
    plant_work_path(&mut st, 1, 20);
    st.body.mark_rejected(h(1));
    st.confirm_stuck_since = Instant::now().checked_sub(Duration::from_secs(60));
    let stats = LoopStats::default();
    let cfg = IbdConfig::for_test();
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        st.inflight.is_empty(),
        "gate must issue no getdata while tip+1 is unconfirmable; inflight={:?}",
        st.inflight.keys().collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn clear_inflight_add_peer_pop_need_and_tip_holes() {
    let (dir, hub) = tmp_hub();
    let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
    let hash = h(10);
    st.slots[0].in_flight.insert(hash);
    st.slots[1].in_flight.insert(hash);
    inflight_add_peer(&mut st.inflight, hash, 0);
    inflight_add_peer(&mut st.inflight, hash, 1);
    assert_eq!(st.inflight[&hash].len(), 2);
    clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
    assert!(st.inflight.is_empty());
    assert!(st.slots[0].in_flight.is_empty());
    assert!(st.slots[1].in_flight.is_empty());

    let mut q = VecDeque::from([h(1), h(2)]);
    st.body.mark_pending(h(1));
    st.body.mark_missing(h(2));
    assert_eq!(pop_need(&mut q, &mut st, &hub), Some(h(2)));
    assert!(pop_need(&mut q, &mut st, &hub).is_none());

    st.height_to_hash.clear();
    let hole = h(21);
    let zombie = h(22);
    st.height_to_hash.insert(0, hole);
    st.height_to_hash.insert(1, zombie);
    st.body.mark_missing(hole);
    // Pending without body queue is a fetch hole (not claim-ready).
    st.body.mark_pending(zombie);
    let holes = contiguous_tip_holes(&mut st, &hub, 8);
    assert_eq!(holes, vec![hole, zombie]);

    let mut room = 10usize;
    let mut issued = 0u64;
    assert!(!issue_one(&mut st, 99, h(30), &mut room, &mut issued));
    assert!(!issue_batch(&mut st, 0, vec![], &mut room, &mut issued));
    st.body.mark_missing(h(30));
    assert!(issue_one(&mut st, 0, h(30), &mut room, &mut issued));
    assert!(issued >= 1);
    assert!(st.inflight.contains_key(&h(30)));
    assert!(st.slots[0].in_flight.contains(&h(30)));

    st.slots.iter_mut().for_each(|s| s.alive = false);
    let stats = LoopStats::default();
    let cfg = IbdConfig::for_test();
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn issue_batch_does_not_count_as_rx() {
    let (dir, _hub) = tmp_hub();
    let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
    st.slots[0].rate.progress_ms = 42;
    st.slots[0].rate.work_started_ms = 7;
    let mut room = 10usize;
    let mut issued = 0u64;
    assert!(issue_one(&mut st, 0, h(30), &mut room, &mut issued));
    assert_eq!(st.slots[0].rate.progress_ms, 42);
    assert_eq!(
        st.slots[0].rate.work_started_ms, 7,
        "queueing getdata is not the stall clock"
    );
    assert_eq!(st.slots[0].getdata_wire.unwritten(), 1);
    let mut one = 1usize;
    let mut issued_one = 0u64;
    assert!(issue_one(&mut st, 0, h(31), &mut one, &mut issued_one));
    assert_eq!(one, 0, "a new hash spends the one free room");
    st.slots.push(dummy_slot(1));
    let mut again = 1usize;
    assert!(issue_one(&mut st, 1, h(31), &mut again, &mut issued_one));
    assert_eq!(
        again, 1,
        "a second peer on an in-flight hash does not spend unique room"
    );
    st.slots[0].getdata_wire.wrote(1, 9_000);
    assert!(
        !rbitcoin_ibd::ibd::peer_io::getdata_on_wire_stalled(&st.slots[0], 9_000 + 29_999, 30_000),
        "the opening write starts 30s; last rx at 42ms does not"
    );
    assert!(
        rbitcoin_ibd::ibd::peer_io::getdata_on_wire_stalled(&st.slots[0], 9_000 + 30_001, 30_000),
        "silence after the opening write still stalls"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Silence on an old on-wire request stays a stall after a later hash is
/// written. A hash already in flight does not move the written timestamp.
#[test]
fn new_hash_on_a_busy_peer_does_not_refresh_stall() {
    use rbitcoin_ibd::ibd::peer_io::getdata_on_wire_stalled;
    let (dir, _hub) = tmp_hub();
    let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
    st.slots[0].in_flight.insert(h(1));
    st.slots[0].rate.progress_ms = 0;
    st.slots[0].rate.work_started_ms = 0;
    assert!(
        getdata_on_wire_stalled(&st.slots[0], 30_001, 30_000),
        "an old request already on the wire can stall"
    );
    let mut room = 10usize;
    let mut issued = 0u64;
    assert!(issue_one(&mut st, 0, h(2), &mut room, &mut issued));
    assert_eq!(st.slots[0].getdata_wire.unwritten(), 1);
    assert!(
        getdata_on_wire_stalled(&st.slots[0], 30_001, 30_000),
        "the old request is still unanswered"
    );
    let now = 100_000;
    st.slots[0].getdata_wire.wrote(1, now);
    assert!(
        getdata_on_wire_stalled(&st.slots[0], now + 1, 30_000),
        "a new getdata write does not open a fresh stall window"
    );
    let again = st.slots[0].getdata_wire.written_ms();
    assert!(!issue_one(&mut st, 0, h(2), &mut room, &mut issued));
    assert_eq!(st.slots[0].getdata_wire.unwritten(), 0);
    assert_eq!(st.slots[0].getdata_wire.written_ms(), again);
    let _ = std::fs::remove_dir_all(dir);
}

/// Idle with nothing outstanding, then a queued ask, does not stall until
/// that ask is on the socket.
#[test]
fn queued_getdata_does_not_count_idle_time_before_the_write() {
    use rbitcoin_ibd::ibd::peer_io::getdata_on_wire_stalled;
    let (dir, _hub) = tmp_hub();
    let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
    st.slots[0].rate.progress_ms = 0;
    st.slots[0].rate.work_started_ms = 0;
    let mut room = 10usize;
    let mut issued = 0u64;
    assert!(issue_one(&mut st, 0, h(2), &mut room, &mut issued));
    assert!(!getdata_on_wire_stalled(&st.slots[0], 1_000_000, 30_000));
    let now = 50_000;
    st.slots[0].getdata_wire.wrote(1, now);
    assert!(
        !getdata_on_wire_stalled(&st.slots[0], now + 1, 30_000),
        "the opening write starts a fresh 30s, ignoring idle time before it"
    );
    assert!(
        getdata_on_wire_stalled(&st.slots[0], now + 30_001, 30_000),
        "silence after the opening write still stalls"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Off-path getdata (mainnet 08:16:23: ordered empty, h2h=0, inflight=7)
/// must not occupy slots; tip+1 and live awaiting-reorg need stay.
/// Speculative explore-need at an empty remainder is leftover — drop it.
#[test]
fn prune_off_path_inflight_drops_orphans_keeps_path_and_reorg() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
    assert!(st.ordered.is_empty());
    assert!(st.height_to_hash.is_empty() || st.height_to_hash.len() <= 1);

    for i in 0..7u32 {
        let hash = h(1000 + i);
        st.slots[0].in_flight.insert(hash);
        inflight_add_peer(&mut st.inflight, hash, 0);
    }
    let want = h(0x11);
    let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
    st.record_height(want, ht);
    st.slots[0].in_flight.insert(want);
    inflight_add_peer(&mut st.inflight, want, 0);
    let explore_h = h(0x22);
    st.reorg.register_explore(std::iter::once(explore_h), None);
    st.slots[0].in_flight.insert(explore_h);
    inflight_add_peer(&mut st.inflight, explore_h, 0);
    assert_eq!(st.inflight.len(), 9);

    prune_off_path_inflight(&mut st);

    assert!(st.inflight.contains_key(&want), "tip+1 occupant stays");
    assert!(
        !st.inflight.contains_key(&explore_h),
        "explore-need at empty remainder is leftover"
    );
    for i in 0..7u32 {
        let hash = h(1000 + i);
        assert!(!st.inflight.contains_key(&hash), "orphan {i} dropped");
        assert!(!st.slots[0].in_flight.contains(&hash));
    }
    assert_eq!(st.inflight.len(), 1, "orphans+explore dropped; path kept");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn scale_and_saturated_helpers() {
    assert!(!bq_pipeline_saturated(20, false));
    assert!(!bq_pipeline_saturated(0, false));
    assert!(!bq_pipeline_saturated(0, false));
    assert!(bq_pipeline_saturated(0, true));
    assert!(bq_pipeline_saturated(15, true));
    assert!(!bq_pipeline_saturated(32, true));
}

#[test]
fn peer_block_room_is_count_until_bodies_have_a_size() {
    let mut st = IbdWorkState::new(vec![], None, None);
    let stand_in = block_len_estimate(&st);
    assert_eq!(stand_in, 1024);
    assert!(
        peer_has_block_room(16, 64, stand_in),
        "sixteen small hashes are under both caps"
    );
    assert!(
        !peer_has_block_room(64, 64, stand_in),
        "the count cap is 64 before any size samples"
    );

    for _ in 0..8 {
        note_block_len(&mut st, 1024 * 1024);
    }
    let mib = block_len_estimate(&st);
    assert_eq!(mib, 1024 * 1024);
    assert!(
        !peer_has_block_room(16, 64, mib),
        "sixteen 1 MiB bodies are the 16 MiB cap"
    );

    st.block_lens.clear();
    for len in [100u32, 200, 300, 400, 500, 600, 700, 8_000] {
        note_block_len(&mut st, len as usize);
    }
    assert_eq!(
        block_len_estimate(&st),
        500,
        "once samples differ the estimate is the median"
    );
    st.block_lens.clear();
    for _ in 0..8 {
        note_block_len(&mut st, 1024);
    }
    let kib = block_len_estimate(&st);
    assert!(peer_has_block_room(63, 64, kib));
    assert!(!peer_has_block_room(64, 64, kib));
}

fn drain_block_queue(hub: &ChainHub) {
    for ht in hub.query.block_queue_queued_heights() {
        hub.query.block_queue_dequeue_height(ht).unwrap();
    }
}

/// Fresh six-peer work on `hub` after the body queue is drained.
fn gap_work(hub: &ChainHub) -> (IbdWorkState, IbdConfig, LoopStats) {
    drain_block_queue(hub);
    let mut st = IbdWorkState::new(
        (0..6).map(dummy_slot).collect(),
        hub.tip_hash(),
        hub.tip_height(),
    );
    for s in &mut st.slots {
        seed_ewma(s, 2_000_000);
    }
    let mut cfg = IbdConfig::for_test();
    cfg.window = 64;
    cfg.per_peer = 16;
    (st, cfg, LoopStats::default())
}

/// Tip-gap frontier versus tip-hole on the cover journey's hub.
fn tip_gap_frontier_and_holes(hub: &ChainHub) {
    use bitcoin::hashes::Hash as _;
    let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
    let owners = |st: &IbdWorkState, ht: u32| st.inflight.get(&h(ht)).map_or(0, |e| e.len());

    let (mut st, cfg, stats) = gap_work(hub);
    plant_work_path(&mut st, path_lo, path_lo.saturating_add(80));
    assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(
        owners(&st, path_lo),
        1,
        "empty queue is the frontier; tip+1 gets one owner"
    );
    let past = path_lo.saturating_add(TIP_HOLE_MAX as u32);
    assert!(
        st.inflight.contains_key(&h(past)),
        "densify continues past the tip window on the frontier"
    );

    // 74 ready bodies on the odd heights. 5 blk/s → 300-block window;
    // 74 * 4 = 296 stays under a quarter, so the tip gap is the frontier.
    let (mut st, cfg, stats) = gap_work(hub);
    plant_work_path(&mut st, path_lo, path_lo.saturating_add(400));
    for i in 0..74u32 {
        let ht = path_lo
            .saturating_add(1)
            .saturating_add(i.saturating_mul(2));
        mark_heights_ready(&mut st, hub, ht, ht);
    }
    assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
    assert_eq!(owners(&st, path_lo), 1, "under a quarter of the window");
    assert!(
        st.inflight.contains_key(&h(path_lo.saturating_add(2))),
        "densify fills the gap behind the first ready body"
    );

    let (mut st, cfg, stats) = gap_work(hub);
    plant_work_path(&mut st, path_lo, path_lo.saturating_add(400));
    for i in 0..75u32 {
        let ht = path_lo
            .saturating_add(1)
            .saturating_add(i.saturating_mul(2));
        mark_heights_ready(&mut st, hub, ht, ht);
    }
    assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
    assert_eq!(
        owners(&st, path_lo),
        4,
        "a quarter of the confirm window, with gaps, is a tip hole"
    );
    assert!(
        stats.assign_issued.load(Ordering::Relaxed) > 0,
        "tip-hole assign increments the issued counter"
    );
    assert!(
        !st.inflight.contains_key(&h(path_lo.saturating_add(2))),
        "densify stays off while the quarter-full tip hole is open"
    );

    // Quarter of the configured assign-stop. One new hash reserves 4 MiB,
    // so the stop must still fit that reserve on top of the queued quarter.
    let stop: u64 = 8 * 1024 * 1024;
    let (mut st, mut cfg, stats) = gap_work(hub);
    cfg.assign_stop_bytes = stop;
    plant_work_path(&mut st, path_lo, path_lo.saturating_add(80));
    let n = (stop / 4) as usize;
    let payload = vec![0u8; n];
    hub.query
        .block_queue_offer(
            path_lo.saturating_add(64),
            h(path_lo.saturating_add(64)).to_byte_array(),
            1,
            &payload,
        )
        .unwrap();
    assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(
        owners(&st, path_lo),
        4,
        "a quarter of the configured assign-stop is a tip hole"
    );
    assert!(
        !st.inflight
            .contains_key(&h(path_lo.saturating_add(TIP_HOLE_MAX as u32))),
        "densify stays off at the byte quarter"
    );
    drain_block_queue(hub);

    let (mut st, cfg, stats) = gap_work(hub);
    plant_work_path(&mut st, path_lo, path_lo.saturating_add(40));
    let start = path_lo.saturating_add(64);
    for i in 0..rbitcoin_query::TIP_HOLE_MIN_AHEAD_BLOCKS {
        let ht = start.saturating_add(i);
        hub.query
            .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 81])
            .unwrap();
    }
    assign_work_ordered(&mut st, hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(
        owners(&st, path_lo),
        4,
        "1000 queued bodies with a cold rate is a tip hole"
    );
    assert!(
        !st.inflight
            .contains_key(&h(path_lo.saturating_add(TIP_HOLE_MAX as u32))),
        "densify stays off once the ahead-block floor is met"
    );
}

/// Tip+1 on one hub at genesis, raced by the same six peers across IBD
/// restarts: when it is a fetch hole, who races it, which owner leaves the
/// race, and that a peer is never asked for a hash twice. The same hub
/// then decides the empty, gapped, byte-quarter, and ahead-count tip gaps.
#[allow(clippy::cognitive_complexity)] // one hub, many tip-hole race arms
#[test]
fn ibd_cover_tip_holes() {
    use rbitcoin_ibd::ibd::peer_io::ibd_mono_ms;
    use rbitcoin_ibd::ibd::progress::claim_ready;
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let (slots, mut wire) = wired_slots(6);
    let mut st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
    let stats = LoopStats::default();
    let mut cfg = IbdConfig::for_test();
    cfg.window = 64;
    cfg.per_peer = 16;
    let tip1 = hub.tip_height().unwrap_or(0).saturating_add(1);
    let ago = |s| Instant::now() - Duration::from_secs(s);
    let rx_now =
        |st: &mut IbdWorkState, pid: usize| st.slots[pid].rate.note_rx(ibd_mono_ms().max(1));
    let race = |st: &mut IbdWorkState, alive: &[usize], hole: BlockHash, max: usize| {
        cover_tip_holes(st, &hub, &cfg, alive, &[hole], max)
    };

    // Lookup already took tip+1, so it is not a fetch hole.
    restart_on(&mut st, &hub, &mut wire, &[0, 1, 2]);
    let three = [0, 1, 2];
    let hole = h(0x11);
    plant_tip_hole(&mut st, hole, tip1);
    hub.query.set_lookup_taken_hi(Some(tip1));
    assert!(contiguous_tip_holes(&mut st, &hub, 8).is_empty());
    assert_eq!(
        race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS),
        0,
        "must not race getdata for a taken height"
    );
    assert!(st.inflight.is_empty());

    // Lookup rewinds. Every live peer races tip+1, fastest first.
    hub.query.set_lookup_taken_hi(None);
    for (pid, bps) in [(0, 100_000), (1, 10_000_000), (2, 1_000_000)] {
        seed_ewma(&mut st.slots[pid], bps);
    }
    assert_eq!(
        rank_peers_by_speed(&st.slots, &three, &HashSet::new()),
        vec![1, 2, 0]
    );
    assert_eq!(contiguous_tip_holes(&mut st, &hub, 8), vec![hole]);
    assert_eq!(race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS), 3);
    assert_eq!(getdata_asks(&mut wire, hole), vec![1, 1, 1, 0, 0, 0]);

    // Nobody has streamed yet: too early to drop anyone.
    race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS);
    assert_eq!(st.inflight[&hole].len(), 3, "no rx yet is too early");

    // Slow peer 0 streams. Silent racers leave one per pass, fastest
    // first, keep the request they were sent, and are never asked for
    // it again.
    rx_now(&mut st, 0);
    race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS);
    let r = &st.inflight[&hole];
    assert!(
        r.holds(1) && !r.peers.contains(&1) && r.peers.contains(&0),
        "silent owner leaves when a sibling streams; peers={:?}",
        r.peers
    );
    for _ in 0..4 {
        race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS);
    }
    let r = &st.inflight[&hole];
    assert_eq!(r.peers, HashSet::from([0]), "the streaming racer stays");
    assert!(r.holds(1) && r.holds(2));
    assert!(
        st.slots[1].in_flight.contains(&hole),
        "dropped owner still counts the request it holds"
    );
    assert_eq!(
        getdata_asks(&mut wire, hole),
        vec![0; 6],
        "one getdata per peer per hash"
    );

    // A wrong first-wins body at tip+1 is dequeued and the path hash re-got.
    restart_on(&mut st, &hub, &mut wire, &three);
    let want = h(0xabc);
    plant_tip_hole(&mut st, want, tip1);
    hub.query
        .block_queue_offer(tip1, h(0xdef).to_byte_array(), 0, &[0u8; 81])
        .unwrap();
    assert!(hub.query.block_queue_has_height(tip1));
    assert!(!claim_ready(&hub, &mut st.body, tip1, &want));
    assert_eq!(contiguous_tip_holes(&mut st, &hub, 8), vec![want]);
    assert!(race(&mut st, &three, want, TIP_HOLE_MAX_PEERS) >= 1);
    assert!(
        !hub.query.block_queue_has_height(tip1)
            || hub
                .query
                .block_queue_hash_at_height(tip1)
                .is_some_and(|x| x == want.to_byte_array()),
        "wrong BQ body must be dequeued"
    );
    assert!(st.inflight.contains_key(&want));

    // After a restart the resume seed knows tip+1 from Class A, but confirm
    // reads only the body queue. Still a hole.
    restart_on(&mut st, &hub, &mut wire, &three);
    plant_tip_hole(&mut st, want, tip1);
    st.body.mark_archived(want);
    assert!(st.body.is_known_archived(&want) && !st.body.is_pending(&want));
    assert!(!claim_ready(&hub, &mut st.body, tip1, &want));
    assert_eq!(contiguous_tip_holes(&mut st, &hub, 8), vec![want]);
    assert!(race(&mut st, &three, want, TIP_HOLE_MAX_PEERS) >= 1);
    assert!(st.inflight.contains_key(&want));

    // Pending with no body-queue wire is a zombie: re-get it and demote it.
    restart_on(&mut st, &hub, &mut wire, &three);
    plant_tip_hole(&mut st, want, tip1);
    st.body.mark_pending(want);
    assert!(!claim_ready(&hub, &mut st.body, tip1, &want));
    assert_eq!(contiguous_tip_holes(&mut st, &hub, 8), vec![want]);
    assert!(race(&mut st, &three, want, TIP_HOLE_MAX_PEERS) >= 1);
    assert!(st.inflight.contains_key(&want));
    assert!(!st.body.is_pending(&want), "cover demotes zombie pending");

    // Load claimed tip+1 and write has not finished: its body is in the
    // pipeline with no queue row. It is not a zombie and is not raced.
    restart_on(&mut st, &hub, &mut wire, &three);
    plant_tip_hole(&mut st, want, tip1);
    st.body.mark_pending(want);
    let feed = std::sync::Arc::new(rbitcoin_ibd::ibd::confirm::ConfirmFeed::new());
    feed.inner.lock().unwrap().inflight.insert(tip1);
    st.confirm_feed = Some(std::sync::Arc::clone(&feed));
    assert_eq!(race(&mut st, &three, want, TIP_HOLE_MAX_PEERS), 0);
    assert!(
        st.body.is_pending(&want),
        "a held body keeps its pending flag"
    );
    feed.finish([tip1]);
    assert!(race(&mut st, &three, want, TIP_HOLE_MAX_PEERS) >= 1);
    assert!(!st.body.is_pending(&want), "a released zombie is demoted");
    st.confirm_feed = None;

    // A tight pack of streaming racers keeps its owners however old the
    // request is.
    restart_on(&mut st, &hub, &mut wire, &three);
    let hole = h(0x51);
    plant_tip_hole(&mut st, hole, tip1);
    for (pid, bps) in [(0, 1_000_000), (1, 1_100_000), (2, 1_050_000)] {
        seed_ewma(&mut st.slots[pid], bps);
    }
    race(&mut st, &three, hole, 2);
    assert_eq!(st.inflight[&hole].peers, HashSet::from([1, 2]));
    st.inflight.get_mut(&hole).unwrap().started_at = ago(7);
    rx_now(&mut st, 1);
    rx_now(&mut st, 2);
    race(&mut st, &three, hole, 2);
    assert_eq!(
        st.inflight[&hole].peers,
        HashSet::from([1, 2]),
        "tight pack with live rx keeps owners"
    );

    // A quarter-median racer among streaming racers leaves.
    restart_on(&mut st, &hub, &mut wire, &three);
    let hole = h(0x53);
    plant_tip_hole(&mut st, hole, tip1);
    for (pid, bps) in [(0, 400_000), (1, 2_000_000), (2, 1_900_000)] {
        seed_ewma(&mut st.slots[pid], bps);
    }
    race(&mut st, &three, hole, 3);
    assert_eq!(st.inflight[&hole].len(), 3);
    for pid in three {
        rx_now(&mut st, pid);
    }
    race(&mut st, &three, hole, 3);
    let r = &st.inflight[&hole];
    assert!(
        !r.peers.contains(&0),
        "slow outlier leaves; peers={:?}",
        r.peers
    );

    // Peer 0 is the only live peer. It keeps an aged hole while it
    // streams, and loses it once rx stops for 30 s.
    restart_on(&mut st, &hub, &mut wire, &[0]);
    let hole = h(0x54);
    plant_tip_hole(&mut st, hole, tip1);
    assert_eq!(race(&mut st, &[0], hole, TIP_HOLE_MAX_PEERS), 1);
    rx_now(&mut st, 0);
    let req = st.inflight.get_mut(&hole).unwrap();
    req.started_at = ago(31);
    req.asked_at.insert(0, ago(31));
    race(&mut st, &[0], hole, TIP_HOLE_MAX_PEERS);
    assert!(
        st.inflight[&hole].peers.contains(&0),
        "a sole streaming peer keeps the hole"
    );
    st.slots[0].rate.progress_ms = 0;
    race(&mut st, &[0], hole, TIP_HOLE_MAX_PEERS);
    let r = &st.inflight[&hole];
    assert!(
        r.peers.contains(&0) && r.holds(0),
        "a silent retired owner is re-asked when no other peer exists"
    );

    st.slots[1].alive = true;
    seed_ewma(&mut st.slots[1], 2_000_000);
    race(&mut st, &[0, 1], hole, TIP_HOLE_MAX_PEERS);
    assert!(st.inflight[&hole].peers.contains(&1));

    // Peer 1 streams but holds it 31 s while peer 2 is connected.
    rx_now(&mut st, 1);
    st.inflight
        .get_mut(&hole)
        .unwrap()
        .asked_at
        .insert(1, ago(31));
    st.slots[2].alive = true;
    seed_ewma(&mut st.slots[2], 1_000_000);
    race(&mut st, &three, hole, TIP_HOLE_MAX_PEERS);
    let r = &st.inflight[&hole];
    assert!(
        !r.peers.contains(&0) && r.peers.contains(&1) && r.peers.contains(&2),
        "the silent owner leaves before the aged one; peers={:?}",
        r.peers
    );

    // The hash is old but peer 2 was asked just now: age counts from the
    // owner's ask.
    st.inflight.get_mut(&hole).unwrap().started_at = ago(31);
    rx_now(&mut st, 2);
    st.slots[3].alive = true;
    seed_ewma(&mut st.slots[3], 1_000_000);
    race(&mut st, &[0, 1, 2, 3], hole, 1);
    let r = &st.inflight[&hole];
    assert!(
        r.peers.contains(&2) && !r.peers.contains(&3),
        "an owner asked just now is not aged; peers={:?}",
        r.peers
    );

    // A fast peer with densify queued drains sooner than an idle slow
    // one. Held 6 s, it keeps the hole: the idle peer would not start it
    // clearly sooner.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    let hole = h(0x56);
    plant_tip_hole(&mut st, hole, tip1);
    seed_ewma(&mut st.slots[0], 10_000_000);
    seed_ewma(&mut st.slots[1], 100_000);
    for i in 0..4u32 {
        st.slots[0].in_flight.insert(h(1000 + i));
    }
    assert_eq!(
        rank_peers_for_tip_hole(&st.slots, &[0, 1], &HashSet::new())[0],
        0
    );
    race(&mut st, &[0, 1], hole, 1);
    assert_eq!(st.inflight[&hole].peers, HashSet::from([0]));
    rx_now(&mut st, 0);
    st.inflight
        .get_mut(&hole)
        .unwrap()
        .asked_at
        .insert(0, ago(6));
    race(&mut st, &[0, 1], hole, 1);
    assert_eq!(st.inflight[&hole].peers, HashSet::from([0]));

    // Peer 0 has densify ahead of the hole. Alone it keeps it. Once a
    // faster empty peer connects, it keeps it for 5 s, then leaves it.
    restart_on(&mut st, &hub, &mut wire, &[0]);
    let hole = h(0x57);
    plant_tip_hole(&mut st, hole, tip1);
    seed_ewma(&mut st.slots[0], 2_000_000);
    st.slots[0].in_flight.insert(h(0x99));
    race(&mut st, &[0], hole, 1);
    rx_now(&mut st, 0);
    st.inflight
        .get_mut(&hole)
        .unwrap()
        .asked_at
        .insert(0, ago(6));
    race(&mut st, &[0], hole, 1);
    assert_eq!(
        st.inflight[&hole].peers,
        HashSet::from([0]),
        "no one else to race"
    );
    st.slots[1].alive = true;
    seed_ewma(&mut st.slots[1], 10_000_000);
    st.inflight
        .get_mut(&hole)
        .unwrap()
        .asked_at
        .insert(0, Instant::now());
    race(&mut st, &[0, 1], hole, 1);
    assert_eq!(
        st.inflight[&hole].peers,
        HashSet::from([0]),
        "young owner has not had time to reach the hash"
    );
    st.inflight
        .get_mut(&hole)
        .unwrap()
        .asked_at
        .insert(0, ago(6));
    race(&mut st, &[0, 1], hole, 2);
    let r = &st.inflight[&hole];
    assert!(
        r.holds(0) && r.peers == HashSet::from([1]),
        "densify-FIFO owner leaves for the empty fast peer; peers={:?}",
        r.peers
    );
    assert_eq!(getdata_asks(&mut wire, hole), vec![1, 1, 0, 0, 0, 0]);

    // Peer 1 holds only the hole, so the FIFO rule never drops it, not
    // even for a much faster empty peer.
    st.slots[2].alive = true;
    seed_ewma(&mut st.slots[2], 50_000_000);
    rx_now(&mut st, 1);
    st.inflight
        .get_mut(&hole)
        .unwrap()
        .asked_at
        .insert(1, ago(6));
    race(&mut st, &three, hole, 2);
    let r = &st.inflight[&hole];
    assert!(r.peers.contains(&1) && !r.holds(2));

    // Peers who still owe the block count toward the race cap.
    let four = [0, 1, 2, 3];
    restart_on(&mut st, &hub, &mut wire, &four);
    let hole = h(0x5c);
    plant_tip_hole(&mut st, hole, tip1);
    for pid in four {
        seed_ewma(&mut st.slots[pid], 1_000_000);
    }
    race(&mut st, &four, hole, 2);
    assert_eq!(getdata_asks(&mut wire, hole), vec![1, 1, 0, 0, 0, 0]);
    st.slots[0].in_flight.insert(h(0x99));
    st.inflight
        .get_mut(&hole)
        .unwrap()
        .asked_at
        .insert(0, ago(6));
    for pid in four {
        rx_now(&mut st, pid);
    }
    for _ in 0..5 {
        race(&mut st, &four, hole, 2);
    }
    let r = &st.inflight[&hole];
    assert!(!r.peers.contains(&0) && r.holds(0) && r.holds(1));
    assert!(!r.holds(2) && !r.holds(3));
    assert_eq!(
        getdata_asks(&mut wire, hole),
        vec![0; 6],
        "two peers already owe the block; cap is 2"
    );

    // A quarter-full body queue races tip+1 on four peers and each later
    // contiguous hole on one.
    let six = [0, 1, 2, 3, 4, 5];
    restart_on(&mut st, &hub, &mut wire, &six);
    plant_work_path(&mut st, tip1, tip1.saturating_add(31));
    for pid in six {
        seed_ewma(&mut st.slots[pid], 2_000_000);
    }
    plant_quarter_window(&hub, tip1);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
    let racers = |st: &IbdWorkState, ht: u32| st.inflight.get(&h(ht)).map_or(0, |r| r.len());
    assert_eq!(racers(&st, tip1), TIP_HOLE_MAX_PEERS);
    assert_eq!(racers(&st, tip1.saturating_add(1)), 1);
    assert_eq!(racers(&st, tip1.saturating_add(2)), 1);

    // With tip+2..=tip+4 in hand, tip+1 still races and the later gap waits.
    restart_on(&mut st, &hub, &mut wire, &[0, 1, 2, 3, 4]);
    plant_work_path(&mut st, tip1, tip1.saturating_add(31));
    mark_heights_ready(
        &mut st,
        &hub,
        tip1.saturating_add(1),
        tip1.saturating_add(3),
    );
    for s in &mut st.slots {
        seed_ewma(s, 2_000_000);
    }
    plant_quarter_window(&hub, tip1);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
    assert_eq!(racers(&st, tip1), TIP_HOLE_MAX_PEERS);
    assert!(
        !st.inflight.contains_key(&h(tip1.saturating_add(4))),
        "pre-hole waits while the prefix hole is open"
    );

    // Tip+1..=tip+4 in hand: the first gap is a pre-hole. A fast young
    // owner stays solo, including on an old request, until its own ask
    // ages. Then one fresh racer replaces it.
    restart_on(&mut st, &hub, &mut wire, &four);
    plant_work_path(&mut st, tip1, tip1.saturating_add(31));
    mark_heights_ready(&mut st, &hub, tip1, tip1.saturating_add(3));
    let gap_ht = tip1.saturating_add(4);
    let gap = h(gap_ht);
    assert_eq!(first_pre_hole(&mut st, &hub, TIP_HOLE_MAX), Some(gap));
    for (pid, bps) in [
        (0, 2_000_000),
        (1, 2_000_000),
        (2, 1_800_000),
        (3, 1_900_000),
    ] {
        seed_ewma(&mut st.slots[pid], bps);
    }
    race(&mut st, &[0], gap, 1);
    rx_now(&mut st, 0);
    let past_gap_raced_once = |st: &IbdWorkState| {
        (gap_ht.saturating_add(1)..=gap_ht.saturating_add(27)).all(|ht| racers(st, ht) <= 1)
    };
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(racers(&st, gap_ht), 1, "fast young owner stays solo");
    assert!(past_gap_raced_once(&st));
    st.inflight.get_mut(&gap).unwrap().started_at = ago(31);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(racers(&st, gap_ht), 1, "an old request with a fresh ask");
    st.inflight
        .get_mut(&gap)
        .unwrap()
        .asked_at
        .insert(0, ago(31));
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    let r = &st.inflight[&gap];
    assert!(r.holds(0) && !r.peers.contains(&0), "aged owner is retired");
    assert_eq!(r.len(), 1, "one fresh racer replaces it");
    assert_eq!(r.holders(), PRE_HOLE_MAX_PEERS);

    // A quarter-median pre-hole owner gets one extra racer, not a window.
    restart_on(&mut st, &hub, &mut wire, &four);
    plant_work_path(&mut st, tip1, tip1.saturating_add(31));
    mark_heights_ready(&mut st, &hub, tip1, tip1.saturating_add(3));
    for (pid, bps) in [(0, 250_000), (1, 1_000_000), (2, 1_000_000), (3, 1_000_000)] {
        seed_ewma(&mut st.slots[pid], bps);
    }
    race(&mut st, &[0], gap, 1);
    rx_now(&mut st, 0);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(racers(&st, gap_ht), PRE_HOLE_MAX_PEERS);
    assert!(past_gap_raced_once(&st));

    tip_gap_frontier_and_holes(&hub);

    let hash = h(0x71);
    let mut req = state::InflightReq::new(0);
    req.asked_at
        .insert(0, Instant::now() - Duration::from_secs(6));
    req.add_peer(1);
    req.retire_peer(1);
    let mut owner = dummy_slot(0);
    let mut holds = dummy_slot(1);
    seed_ewma(&mut owner, 1_000_000);
    seed_ewma(&mut holds, 10_000_000);
    owner.in_flight.insert(h(0x70));
    owner.in_flight.insert(hash);
    assert!(
        fifo_blocked_owner_to_drop(&req, &hash, &[owner, holds], 64, 1024).is_none(),
        "a peer that already holds the hash is not a free replacement"
    );
    let mut owner = dummy_slot(0);
    let mut capped = dummy_slot(2);
    seed_ewma(&mut owner, 1_000_000);
    seed_ewma(&mut capped, 10_000_000);
    owner.in_flight.insert(h(0x70));
    owner.in_flight.insert(hash);
    for n in 0..16u32 {
        capped.in_flight.insert(h(0x200 + n));
    }
    assert!(
        fifo_blocked_owner_to_drop(&req, &hash, &[owner, capped], 64, 1024 * 1024).is_none(),
        "a peer at the byte cap is not a free replacement"
    );
    // No samples yet, so this owner's rate is zero, the same figure a dead
    // slot reports. The other live peer already holds the hash.
    let mut unsampled = dummy_slot(0);
    let holds_alive = dummy_slot(1);
    let mut dead = dummy_slot(2);
    dead.alive = false;
    unsampled.in_flight.insert(h(0x70));
    unsampled.in_flight.insert(hash);
    assert!(
        fifo_blocked_owner_to_drop(&req, &hash, &[unsampled, holds_alive, dead], 64, 1024)
            .is_none(),
        "a dead slot is not a free replacement for an unsampled owner"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// A tip-hole hash whose only holders are retired has no live getdata: the
/// retired peers keep their stale requests but cannot count as coverage, or
/// the hash — and the in-order tip behind it — freezes while densify sits
/// at its hole-open zero cap. (Mainnet wedge: tip frozen with idle peers.)
#[test]
#[allow(clippy::cognitive_complexity)] // one hub, many retire/re-ask arms
fn ibd_cover_tip_holes_recovers_all_retired() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let (slots, mut wire) = wired_slots(4);
    let mut st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
    let cfg = IbdConfig::for_test();
    let tip1 = hub.tip_height().unwrap_or(0).saturating_add(1);
    let alive = [0, 1, 2, 3];
    restart_on(&mut st, &hub, &mut wire, &alive);
    let hole = h(0x61);
    plant_tip_hole(&mut st, hole, tip1);
    for pid in alive {
        seed_ewma(&mut st.slots[pid], 2_000_000);
    }

    // Rest-of-hole cover keeps one owner. It stalls to retirement over the
    // churn and keeps the request it was sent: nobody is pulling now.
    assert_eq!(cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], 1), 1);
    retire_hash_owner(&mut st, hole, 0);
    let r = &st.inflight[&hole];
    assert!(
        r.peers.is_empty() && r.holds(0),
        "the stall-retired owner keeps its request; peers={:?}",
        r.peers
    );

    // Retired holders are not coverage: a fresh peer is asked, the retired
    // owner is not.
    let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], 1);
    assert!(issued >= 1, "an all-retired hole must be re-covered");
    let r = &st.inflight[&hole];
    assert_eq!(r.len(), 1, "exactly one fresh racer; peers={:?}", r.peers);
    assert!(!r.peers.contains(&0), "the retired owner is not re-asked");
    let asks = getdata_asks(&mut wire, hole);
    assert_eq!(asks[0], 1, "the retired owner is never re-asked");
    assert_eq!(
        asks[1..].iter().sum::<usize>(),
        1,
        "one fresh peer is asked"
    );

    // Same frozen state at the pre-hole cap: two retired holders.
    restart_on(&mut st, &hub, &mut wire, &alive);
    let hole = h(0x62);
    plant_tip_hole(&mut st, hole, tip1);
    for pid in alive {
        seed_ewma(&mut st.slots[pid], 2_000_000);
    }
    let mut room = 1;
    let mut issued = 0;
    assert!(issue_one(&mut st, 0, hole, &mut room, &mut issued));
    let mut room = 1;
    assert!(issue_one(&mut st, 1, hole, &mut room, &mut issued));
    retire_hash_owner(&mut st, hole, 0);
    retire_hash_owner(&mut st, hole, 1);
    let r = &st.inflight[&hole];
    assert!(r.peers.is_empty() && r.holders() == PRE_HOLE_MAX_PEERS);
    let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], PRE_HOLE_MAX_PEERS);
    assert!(issued >= 1, "an all-retired pre-hole must be re-covered");
    let r = &st.inflight[&hole];
    assert_eq!(r.len(), 1, "exactly one fresh racer; peers={:?}", r.peers);

    // A live racer keeps the sleeping-holder cap: two retired holders plus
    // one racer already close the pre-hole cap.
    let r = &st.inflight[&hole];
    assert_eq!(r.holders(), PRE_HOLE_MAX_PEERS + 1);
    assert_eq!(
        cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], PRE_HOLE_MAX_PEERS + 1),
        0,
        "a live racer is coverage; the retired holders still count the cap"
    );

    // Every peer that can be asked is retired again: the hash must not
    // freeze. The longest-held aged-out retired owner is re-asked.
    for pid in alive {
        retire_hash_owner(&mut st, hole, pid);
    }
    let now = Instant::now();
    {
        let req = st.inflight.get_mut(&hole).unwrap();
        for (pid, age) in [(0usize, 40u64), (1, 35), (2, 32), (3, 31)] {
            req.asked_at.insert(pid, now - Duration::from_secs(age));
        }
        assert!(req.peers.is_empty());
        assert!(req.holders() >= PRE_HOLE_MAX_PEERS);
    }
    assert_eq!(
        cover_tip_holes(&mut st, &hub, &cfg, &alive[..3], &[hole], 1),
        1
    );
    let r = &st.inflight[&hole];
    assert_eq!(
        r.peers,
        HashSet::from([0]),
        "the longest-held retired owner is re-asked"
    );
    assert!(r.retired.contains(&1));

    // Below the cap a racerless hash keeps the full fill: one retired holder
    // plus three fresh peers for the tip+1 cap, not one racer per pass.
    restart_on(&mut st, &hub, &mut wire, &alive);
    let hole = h(0x63);
    plant_tip_hole(&mut st, hole, tip1);
    for pid in alive {
        seed_ewma(&mut st.slots[pid], 2_000_000);
    }
    let mut room = 1;
    let mut issued = 0;
    assert!(issue_one(&mut st, 0, hole, &mut room, &mut issued));
    retire_hash_owner(&mut st, hole, 0);
    assert_eq!(
        cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS),
        (TIP_HOLE_MAX_PEERS - 1) as u64,
        "the racerless hash fills up to the cap in one pass"
    );
    assert_eq!(st.inflight[&hole].holders(), TIP_HOLE_MAX_PEERS);

    let _ = std::fs::remove_dir_all(dir);
}

/// Four retired holders already meet the tip+1 cap. One fresh peer is asked.
/// The next pass does not add another racer on top of that retired set.
#[test]
fn ibd_cover_tip_holes_retired_cap_stays_one_racer() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let n = TIP_HOLE_MAX_PEERS + 1;
    let (slots, mut wire) = wired_slots(n);
    let mut st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
    let cfg = IbdConfig::for_test();
    let tip1 = hub.tip_height().unwrap_or(0).saturating_add(1);
    let alive: Vec<usize> = (0..n).collect();
    restart_on(&mut st, &hub, &mut wire, &alive);
    let hole = h(0x64);
    plant_tip_hole(&mut st, hole, tip1);
    for &pid in &alive {
        seed_ewma(&mut st.slots[pid], 2_000_000);
    }
    for &pid in &alive[..TIP_HOLE_MAX_PEERS] {
        let mut room = 1;
        let mut issued = 0;
        assert!(issue_one(&mut st, pid, hole, &mut room, &mut issued));
        retire_hash_owner(&mut st, hole, pid);
    }
    let r = &st.inflight[&hole];
    assert!(r.peers.is_empty());
    assert_eq!(r.holders(), TIP_HOLE_MAX_PEERS);

    assert_eq!(
        cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS),
        1
    );
    let r = &st.inflight[&hole];
    assert_eq!(
        r.peers,
        HashSet::from([TIP_HOLE_MAX_PEERS]),
        "the peer who does not already hold the hash is the one racer"
    );
    assert_eq!(r.holders(), TIP_HOLE_MAX_PEERS + 1);

    assert_eq!(
        cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS),
        0,
        "a live racer closes the cap; retired holders still count"
    );
    assert_eq!(st.inflight[&hole].len(), 1);

    let _ = std::fs::remove_dir_all(dir);
}

/// Densify on one hub at genesis across IBD restarts: assign depth, the
/// tip batch, band limits from the body queue, per-peer caps, hung
/// owners, and reorg need.
#[allow(clippy::cognitive_complexity)] // one hub, many densify arms
#[test]
fn assign_depth_densify_cache_and_early_exits() {
    use rbitcoin_ibd::ibd::dial::release_peer_block_work;
    use rbitcoin_ibd::ibd::peer_io::ibd_mono_ms;
    use rbitcoin_query::{soft_confirm_window_n, BQ_SOFT_FREE_BYTES};
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let (slots, mut wire) = wired_slots(3);
    let mut st = IbdWorkState::new(slots, None, Some(0));
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    let stats = LoopStats::default();
    let mut cfg = IbdConfig::for_test();
    cfg.window = 64;
    cfg.per_peer = 8;
    let ago = |s| Instant::now() - Duration::from_secs(s);
    let issued_heights = |st: &IbdWorkState| -> Vec<u32> {
        st.inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .collect()
    };
    let enqueue = |st: &mut IbdWorkState, ht: u32, payload: &[u8]| {
        hub.query
            .block_queue_enqueue(ht, h(ht).to_byte_array(), ht as u64, payload)
            .unwrap();
        st.body.mark_pending(h(ht));
    };

    for ht in 1u32..=12 {
        let hash = h(ht);
        st.record_height(hash, ht);
        st.height_to_hash.insert(ht, hash);
        st.ordered_set.insert(hash);
        st.ordered.push_back(hash);
        st.max_ordered_height = ht;
        st.body.mark_missing(hash);
    }
    plant_quarter_window(&hub, 1);

    assign_work_ordered(
        &mut st,
        &hub,
        &cfg,
        &stats,
        AssignDepth::Critical,
        Some(5.0),
    );
    let after_crit = st.inflight.len();
    assert!(after_crit > 0, "critical should still issue tip/race");

    let n_before = st.inflight.len();
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
    assert!(st.inflight.len() <= n_before + 8);

    let hashes: Vec<_> = st.inflight.keys().copied().collect();
    for hash in hashes {
        clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
        st.body.mark_missing(hash);
    }
    st.body.mark_pending(h(5));
    let _ = st
        .body
        .expire_stale_pending_if(std::time::Duration::ZERO, |_| true);
    st.body.mark_pending(h(5));
    st.body.mark_pending(h(1));
    let expired = st
        .body
        .expire_stale_pending_if(std::time::Duration::ZERO, |_| true);
    for hash in expired {
        clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
        st.body.mark_missing(hash);
    }

    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(!st.inflight.is_empty());
    assert!(stats.assign_issued.load(Ordering::Relaxed) > 0);

    for ht in 20u32..20 + cfg.window as u32 {
        let hash = h(ht + 100);
        inflight_add_peer(&mut st.inflight, hash, 0);
        st.slots[0].in_flight.insert(hash);
    }
    let n_full = st.inflight.len();
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(st.inflight.len() <= n_full + 2);

    st.inflight.clear();
    st.slots[0].in_flight.clear();
    st.slots[1].in_flight.clear();
    for ht in 1u32..=4 {
        let hash = h(ht);
        st.body.mark_missing(hash);
    }
    for i in 0..cfg.per_peer {
        let hash = h(200 + i as u32);
        st.slots[0].in_flight.insert(hash);
        inflight_add_peer(&mut st.inflight, hash, 0);
    }
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(!st.slots[1].in_flight.is_empty() || st.inflight.len() > cfg.per_peer);

    // Claim-ready: pending **with** body-queue wire (not Class A alone).
    // Zombie pending without BQ is a tip fetch hole (cover_tip_holes re-gets).
    let tiny = [0u8; 8];
    for ht in 1u32..=12 {
        let hash = h(ht);
        hub.query
            .block_queue_enqueue(ht, hash.to_byte_array(), ht as u64, &tiny)
            .unwrap();
        st.body.mark_pending(hash);
    }
    st.inflight.clear();
    st.slots.iter_mut().for_each(|s| s.in_flight.clear());
    st.max_ready_height = 12;
    st.max_ordered_height = 12;
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        st.inflight.is_empty(),
        "claim-ready tip band must not re-get; inflight={:?}",
        st.inflight.keys().collect::<Vec<_>>()
    );

    // Tip+1 is a hole behind a quarter-full queue: nothing is densified
    // past it.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    cfg.window = 64;
    cfg.per_peer = 16;
    plant_work_path(&mut st, 1, 40);
    mark_heights_ready(&mut st, &hub, 2, 32);
    seed_ewma(&mut st.slots[0], 2_000_000);
    seed_ewma(&mut st.slots[1], 2_000_000);
    plant_quarter_window(&hub, 1);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
    assert_eq!(
        issued_heights(&st),
        vec![1],
        "far densify must not issue while tip+1 is a fetch hole"
    );

    // Under the free-byte floor densify fills far ahead even at a slow
    // tip rate, and skips heights lookup has already taken.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    plant_work_path(&mut st, 1, 100);
    for ht in 1u32..=10 {
        enqueue(&mut st, ht, b"x");
    }
    assert!(hub.query.block_queue_stats().0 < BQ_SOFT_FREE_BYTES);
    hub.query.set_lookup_taken_hi(Some(20));
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(0.1));
    hub.query.set_lookup_taken_hi(None);
    let issued = issued_heights(&st);
    assert!(
        issued.contains(&21) && issued.iter().all(|&ht| ht > 20),
        "the first gap is above the taken height; issued={issued:?}"
    );
    assert!(
        issued.iter().any(|&ht| ht > 21),
        "under free bytes densify runs past the 1-min window; issued={issued:?}"
    );

    // A queued prefix moves the densify cursor past it.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    cfg.window = 128;
    cfg.per_peer = 64;
    plant_work_path(&mut st, 1, 80);
    for ht in 1u32..=40 {
        enqueue(&mut st, ht, b"x");
    }
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        st.densify_scan_lo >= 41,
        "queued 1..=40 must bump scan_lo; scan_lo={}",
        st.densify_scan_lo
    );
    assert!(
        issued_heights(&st).iter().all(|&ht| ht > 40),
        "must not getdata heights already queued"
    );

    // Past the legacy 2048-height ceiling when the queue allows it.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    cfg.window = 128;
    cfg.per_peer = 16;
    plant_work_path(&mut st, 1, 2200);
    for ht in 1u32..=2040 {
        enqueue(&mut st, ht, &[0u8; 8]);
    }
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    let far = issued_heights(&st);
    assert!(
        far.iter().any(|&ht| ht > 2048),
        "legacy CONTIG_DENSIFY_AHEAD=2048 must not be the ceiling; issued={far:?}"
    );

    // Over the free-byte floor densify stays inside the confirm window:
    // 0.1 blk/s × 60 s is heights 1..=6.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    cfg.window = 64;
    plant_work_path(&mut st, 1, 200);
    let chunk = vec![0u8; 55 * 1024 * 1024];
    enqueue(&mut st, 1, &chunk);
    enqueue(&mut st, 2, &chunk);
    drop(chunk);
    assert!(hub.query.block_queue_stats().0 > BQ_SOFT_FREE_BYTES);
    assert_eq!(soft_confirm_window_n(Some(0.1)), 6);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(0.1));
    let issued = issued_heights(&st);
    assert!(
        !issued.is_empty() && issued.iter().all(|&ht| ht <= 6),
        "densify only inside the confirm window; issued={issued:?}"
    );

    // At the assign-stop nothing new is requested.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    cfg.window = 128;
    cfg.per_peer = 64;
    cfg.assign_stop_bytes = 2048;
    plant_work_path(&mut st, 1, 500);
    for ht in 1u32..=TIP_HOLE_MAX as u32 {
        enqueue(&mut st, ht, b"x");
    }
    enqueue(&mut st, 500, &[0u8; 4096]);
    assert!(hub.query.block_queue_stats().0 >= 2048);
    assert_eq!(hub.query.block_queue_max_height(), Some(500));
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
    cfg.assign_stop_bytes = rbitcoin_query::BQ_ASSIGN_STOP_BYTES;
    assert!(
        st.inflight.is_empty(),
        "queue already at the assign-stop: no new getdata; issued={:?}",
        issued_heights(&st)
    );

    // Tip+1 in hand and tip+2 the pre-hole. Past it, densify re-gets a
    // zombie pending (no wire) and a wrong first-wins body by path hash.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    cfg.window = 32;
    cfg.per_peer = 8;
    plant_work_path(&mut st, 1, 4);
    enqueue(&mut st, 1, b"ok1");
    st.body.mark_pending(h(3));
    hub.query
        .block_queue_offer(4, h(0x99).to_byte_array(), 0, &[0u8; 81])
        .unwrap();
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!((2..=4).all(|ht| st.inflight.contains_key(&h(ht))));
    assert!(
        !st.body.is_pending(&h(3)),
        "zombie pending demoted before issue"
    );
    assert!(
        !hub.query.block_queue_has_height(4)
            || hub
                .query
                .block_queue_hash_at_height(4)
                .is_some_and(|x| x == h(4).to_byte_array()),
        "wrong body at a densify height is dequeued"
    );

    // A most-work reorg needs two bodies. Both are fetched by hash, one
    // although its height holds another body.
    restart_on(&mut st, &hub, &mut wire, &[0]);
    cfg.window = 16;
    cfg.per_peer = 4;
    let (need, mid) = (h(0xab), h(0xac));
    st.record_height(need, 1);
    hub.query
        .block_queue_offer(1, h(0xde).to_byte_array(), 0, &[0u8; 81])
        .unwrap();
    assert!(!hub.query.block_queue_has_hash(&need.to_byte_array()));
    st.reorg.register_explore([need, mid], None);
    st.body.mark_pending(need);
    st.body.mark_missing(mid);
    assert_eq!(
        st.reorg.need_getdata().into_iter().collect::<HashSet<_>>(),
        HashSet::from([need, mid])
    );
    // Direct reorg issue. A full assign also covers this height as a tip
    // hole, which would fetch it even if the pending conjunct were wrong.
    let issued = assign_reorg_need(&mut st, &hub, &cfg, &[0]);
    assert!(issued >= 2, "both reorg hashes are issued, issued={issued}");
    assert!(st.inflight.contains_key(&need) && st.inflight.contains_key(&mid));
    assert!(
        !st.body.is_pending(&need),
        "pending reorg need with no body-queue row is fetched"
    );

    // The first densify hash goes to the fastest peer. A 2×-median peer
    // gets the full cap, the others half.
    restart_on(&mut st, &hub, &mut wire, &[0, 1, 2]);
    cfg.window = 128;
    cfg.per_peer = 16;
    plant_work_path(&mut st, 1, 52);
    mark_tip_batch_ready(&mut st, &hub, 1);
    for (pid, bps) in [(0, 5_000_000), (1, 15_000_000), (2, 5_000_000)] {
        seed_ewma(&mut st.slots[pid], bps);
    }
    st.densify_scan_lo = 33;
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(st.inflight[&h(33)].peers.contains(&1));
    assert_eq!(st.slots[1].in_flight.len(), 16);
    assert!(st.slots[0].in_flight.len() <= 8 && st.slots[2].in_flight.len() <= 8);

    // Every peer at its cap: no new getdata. The cursor still rewinds to
    // the first height that is not claim-ready.
    restart_on(&mut st, &hub, &mut wire, &[0, 1]);
    plant_work_path(&mut st, 1, 70);
    mark_tip_batch_ready(&mut st, &hub, 1);
    for i in 0..16u32 {
        let pid = (i % 2) as usize;
        let mut room = 1;
        let mut issued = 0;
        assert!(issue_one(&mut st, pid, h(40 + i), &mut room, &mut issued));
    }
    st.densify_scan_lo = 40;
    let before: HashSet<_> = st.inflight.keys().copied().collect();
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    let after: HashSet<_> = st.inflight.keys().copied().collect();
    assert_eq!(after, before, "no new densify when peers at cap");
    assert_eq!(st.densify_scan_lo, 33);

    // Peer 0 disconnects holding work below the cursor. The next assign
    // rewinds and re-asks it.
    restart_on(&mut st, &hub, &mut wire, &[0, 1, 2]);
    plant_work_path(&mut st, 1, 49);
    mark_tip_batch_ready(&mut st, &hub, 1);
    seed_ewma(&mut st.slots[1], 1_000_000);
    seed_ewma(&mut st.slots[2], 1_000_000);
    let lost = h(45);
    let mut room = 1;
    let mut issued = 0;
    assert!(issue_one(&mut st, 0, lost, &mut room, &mut issued));
    st.densify_scan_lo = 50;
    let freed = release_peer_block_work(&mut st.slots, &mut st.inflight, &mut st.body, 0);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        st.inflight.contains_key(&lost),
        "a gone holder below the cursor is re-asked"
    );
    st.reopen_for_densify(&freed);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(st.inflight.contains_key(&lost), "reopened work is re-asked");

    // Only tip+40 is missing, asked of peer 0. Silent but asked just now,
    // it keeps the hash from faster peer 1. Hung 31 s with peer 1 gone,
    // nothing faster can take it. While peer 0 streams it keeps it. Once
    // silent, peer 1 takes it. When peer 1 hangs too, the steal skips
    // peer 0, which still holds the request, for peer 2.
    restart_on(&mut st, &hub, &mut wire, &[0]);
    cfg.window = 64;
    plant_work_path(&mut st, 1, 40);
    mark_heights_ready(&mut st, &hub, 1, 39);
    let hung = h(40);
    let mut room = 1;
    let mut issued = 0;
    assert!(issue_one(&mut st, 0, hung, &mut room, &mut issued));
    let age_owner = |st: &mut IbdWorkState, pid: usize| {
        let req = st.inflight.get_mut(&hung).unwrap();
        req.started_at = ago(31);
        req.asked_at.insert(pid, ago(31));
    };
    st.slots[1].alive = true;
    seed_ewma(&mut st.slots[1], 1_000_000);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(
        st.inflight[&hung].peers,
        HashSet::from([0]),
        "a young request is not hung"
    );
    st.slots[1].alive = false;
    age_owner(&mut st, 0);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(
        st.inflight[&hung].peers,
        HashSet::from([0]),
        "no faster peer"
    );
    st.slots[1].alive = true;
    // `seed_ewma` blends into the previous sample. Both start cold so the
    // stored rates are equal; a second seed on peer 1 alone would be faster.
    st.slots[0].rate = Default::default();
    st.slots[1].rate = Default::default();
    seed_ewma(&mut st.slots[0], 1_000_000);
    seed_ewma(&mut st.slots[1], 1_000_000);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(
        st.inflight[&hung].peers,
        HashSet::from([0]),
        "an equal-bps peer does not steal"
    );
    st.slots[1].rate = Default::default();
    seed_ewma(&mut st.slots[1], 2_000_000);
    st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert_eq!(st.inflight[&hung].peers, HashSet::from([0]), "live rx");
    st.slots[0].rate.progress_ms = 0;
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    let r = &st.inflight[&hung];
    assert!(
        r.peers == HashSet::from([1]) && r.holds(0),
        "hung densify moves to the faster peer; peers={:?}",
        r.peers
    );
    st.slots[0].rate = Default::default();
    seed_ewma(&mut st.slots[0], 9_000_000);
    st.slots[2].alive = true;
    seed_ewma(&mut st.slots[2], 5_000_000);
    age_owner(&mut st, 1);
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    let r = &st.inflight[&hung];
    assert!(
        r.peers == HashSet::from([2]) && r.holds(0) && r.holds(1),
        "steal skips a peer that already holds the hash; peers={:?}",
        r.peers
    );

    // No faster peer has a free slot: the hung owner is retired, keeps
    // its request, and the cursor rewinds to it. Once a slot frees the
    // freed peer is asked, even with the getdata window full, and the
    // hung peer is not asked again.
    restart_on(&mut st, &hub, &mut wire, &[0, 1, 2]);
    cfg.window = 64;
    cfg.per_peer = 2;
    plant_work_path(&mut st, 1, 40);
    enqueue(&mut st, 1, &[0u8; 80]);
    let mut room = 1;
    let mut issued = 0;
    assert!(issue_one(&mut st, 0, hung, &mut room, &mut issued));
    age_owner(&mut st, 0);
    for n in 0..2 {
        st.slots[1].in_flight.insert(h(300 + n));
        st.slots[2].in_flight.insert(h(400 + n));
    }
    seed_ewma(&mut st.slots[1], 5_000_000);
    seed_ewma(&mut st.slots[2], 4_000_000);
    st.densify_scan_lo = 50;
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    let r = &st.inflight[&hung];
    assert!(
        r.holds(0) && r.peers.is_empty(),
        "no free faster slot retires the hung owner; peers={:?}",
        r.peers
    );
    assert!(st.slots[0].in_flight.contains(&hung));
    assert!(st.densify_scan_lo <= 40, "scan_lo={}", st.densify_scan_lo);
    seed_ewma(&mut st.slots[0], 9_000_000);
    st.slots[1].in_flight.clear();
    cfg.window = 1;
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    let r = &st.inflight[&hung];
    assert!(
        r.peers.contains(&1) && r.holds(0) && !r.peers.contains(&0),
        "the freed peer is asked; the hung peer stays retired; peers={:?}",
        r.peers
    );
    assert_eq!(getdata_asks(&mut wire, hung), vec![1, 1, 0]);

    let mut live_and_retired = state::InflightReq::new(0);
    live_and_retired.add_peer(2);
    live_and_retired.retire_peer(2);
    assert!(
        !inflight_needs_racer(&live_and_retired),
        "a live holder plus a retired holder is not a racer"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// Assign-stop charge is the max of the last 32 recorded bodies, capped
/// at 4 MiB. Under 8 samples it stays 4 MiB. A hash already in flight
/// does not need another charge.
#[test]
fn intake_reserve_charges_max_of_recent_bodies() {
    let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, None);
    let mut room = 64usize;
    let mut issued = 0u64;

    for _ in 0..7 {
        note_block_len(&mut st, 50_000);
    }
    st.intake_queued = 0;
    st.intake_stop = GETDATA_RESERVE_BYTES - 1;
    assert!(
        !issue_one(&mut st, 0, h(1), &mut room, &mut issued),
        "seven samples still need a full 4 MiB"
    );
    st.intake_stop = GETDATA_RESERVE_BYTES;
    assert!(
        issue_one(&mut st, 0, h(1), &mut room, &mut issued),
        "exactly 4 MiB fits one new hash before eight samples"
    );
    assert!(
        !issue_one(&mut st, 0, h(2), &mut room, &mut issued),
        "a second new hash still needs another 4 MiB"
    );

    st.inflight.clear();
    for slot in &mut st.slots {
        slot.in_flight.clear();
    }
    st.block_lens.clear();
    let samples = [
        100_000u32, 50_000, 200_000, 80_000, 10_000, 90_000, 120_000, 40_000,
    ];
    for n in samples {
        note_block_len(&mut st, n as usize);
    }
    let max_len = u64::from(*samples.iter().max().unwrap());
    let queued = 1_000_000u64;
    let headroom = max_len * 5 + max_len / 2;
    st.intake_queued = queued;
    st.intake_stop = queued + headroom;
    room = 64;
    let mut fit = 0u32;
    for i in 0..8u32 {
        let before = st.inflight.len();
        let _ = issue_one(&mut st, 0, h(100 + i), &mut room, &mut issued);
        if st.inflight.len() > before {
            fit += 1;
        }
    }
    let by_max = (headroom / max_len) as u32;
    let by_flat = (headroom / GETDATA_RESERVE_BYTES) as u32;
    assert_eq!(
        fit, by_max,
        "headroom {headroom} at max {max_len} fits {by_max}, flat 4 MiB would fit {by_flat}"
    );

    st.inflight.clear();
    for slot in &mut st.slots {
        slot.in_flight.clear();
    }
    st.block_lens.clear();
    note_block_len(&mut st, 4_000_000);
    for _ in 0..32 {
        note_block_len(&mut st, 100_000);
    }
    let window_max = 100_000u64;
    st.intake_queued = 0;
    st.intake_stop = window_max * 3 + window_max / 2;
    room = 16;
    fit = 0;
    for i in 0..6u32 {
        let before = st.inflight.len();
        let _ = issue_one(&mut st, 0, h(400 + i), &mut room, &mut issued);
        if st.inflight.len() > before {
            fit += 1;
        }
    }
    assert_eq!(
        fit,
        (st.intake_stop / window_max) as u32,
        "a max that aged out of the 32-ring must not keep the charge"
    );

    st.inflight.clear();
    for slot in &mut st.slots {
        slot.in_flight.clear();
    }
    st.block_lens.clear();
    for _ in 0..8 {
        note_block_len(&mut st, 5 * 1024 * 1024);
    }
    st.intake_queued = 0;
    st.intake_stop = GETDATA_RESERVE_BYTES;
    room = 8;
    assert!(
        issue_one(&mut st, 0, h(200), &mut room, &mut issued),
        "a recorded length above 4 MiB still charges 4 MiB"
    );
    assert!(
        !issue_one(&mut st, 0, h(201), &mut room, &mut issued),
        "the ceiling is one 4 MiB charge, not the recorded length"
    );

    st.inflight.clear();
    for slot in &mut st.slots {
        slot.in_flight.clear();
    }
    st.block_lens.clear();
    for _ in 0..8 {
        note_block_len(&mut st, max_len as usize);
    }
    st.intake_queued = 0;
    st.intake_stop = max_len;
    room = 8;
    assert!(issue_one(&mut st, 0, h(300), &mut room, &mut issued));
    st.intake_stop = max_len - 1;
    assert!(
        issue_one(&mut st, 1, h(300), &mut room, &mut issued),
        "a hash already in flight is issued with no new charge"
    );
    assert!(
        !issue_one(&mut st, 1, h(301), &mut room, &mut issued),
        "a different hash still needs a full charge"
    );
}

#[test]
fn hostile_peer_session() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let four_mib = GETDATA_RESERVE_BYTES;
    let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
    st.intake_queued = 0;
    st.intake_stop = four_mib - 1;
    let mut room = 10usize;
    let mut issued = 0u64;
    assert!(
        !issue_one(&mut st, 0, h(32), &mut room, &mut issued),
        "one byte under 4 MiB cannot reserve a new hash"
    );
    assert!(st.inflight.is_empty());

    st.intake_stop = four_mib;
    assert!(
        issue_one(&mut st, 0, h(31), &mut room, &mut issued),
        "one new hash fits in exactly 4 MiB"
    );
    assert!(st.inflight.contains_key(&h(31)));
    let before = st.inflight.len();
    assert!(
        !issue_one(&mut st, 0, h(33), &mut room, &mut issued),
        "a second hash would pass the 4 MiB stop"
    );
    assert_eq!(st.inflight.len(), before);
    assert!(!st.inflight.contains_key(&h(33)));

    plant_work_path(&mut st, 1, 2);
    let queued = vec![0u8; 1000];
    hub.query
        .block_queue_enqueue(50, h(50).to_byte_array(), 50, &queued)
        .unwrap();
    assert!(hub.query.block_queue_stats().0 >= 1000);
    let stats = LoopStats::default();
    let mut cfg = IbdConfig::for_test();
    cfg.assign_stop_bytes = 1000;
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        !st.inflight.contains_key(&h(1)) && !st.inflight.contains_key(&h(2)),
        "queue already at the stop: no new getdata; inflight={:?}",
        st.inflight.keys().collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn retained_header_timeout_frontier_recovers_below_and_above_racing_threshold() {
    for (ahead, depth) in [
        (7, AssignDepth::Critical),
        (rbitcoin_query::TIP_HOLE_MIN_AHEAD_BLOCKS, AssignDepth::Full),
    ] {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let (slots, mut wire) = wired_slots(2);
        let mut st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
        plant_work_path(&mut st, 1, ahead + 1);
        mark_heights_ready(&mut st, &hub, 2, ahead + 1);
        st.slots[0].in_flight.insert(h(1));
        st.inflight.insert(h(1), state::InflightReq::new(0));
        st.header_walk.header_timeout_peers.insert(0);
        let mut cfg = IbdConfig::for_test();
        cfg.window = 16;
        cfg.per_peer = 8;

        assign_work_ordered(&mut st, &hub, &cfg, &LoopStats::default(), depth, None);

        assert_eq!(
            getdata_asks(&mut wire, h(1)),
            vec![0, 1],
            "assignment must ask the alternative peer below and above the racing threshold"
        );
        if matches!(depth, AssignDepth::Critical) {
            assert!(st.inflight[&h(1)].retired.contains(&0));
        }
        assert!(st.inflight[&h(1)].peers.contains(&1));
        assert!(
            st.slots[0].in_flight.contains(&h(1)),
            "the retained peer keeps its outstanding request"
        );
        assert_eq!(st.inflight.len(), 1);
        assign_work_ordered(&mut st, &hub, &cfg, &LoopStats::default(), depth, None);
        assert_eq!(
            getdata_asks(&mut wire, h(1)),
            vec![0, 0],
            "existing coverage must not amplify duplicate requests"
        );
        drop(st);
        drop(hub);
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A hole in front of queued bodies is requested even when the densify
/// cursor has moved past it. A holder whose peer is gone does not cover it.
#[test]
fn tip_hole_in_front_of_queued_bodies_is_requested() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let (slots, mut wire) = wired_slots(2);
    let mut st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
    restart_on(&mut st, &hub, &mut wire, &[0]);
    let stats = LoopStats::default();
    let mut cfg = IbdConfig::for_test();
    cfg.window = 16;
    cfg.per_peer = 8;

    plant_work_path(&mut st, 1, 8);
    mark_heights_ready(&mut st, &hub, 3, 8);
    st.densify_scan_lo = 5;
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        st.inflight.contains_key(&h(1)) && st.inflight.contains_key(&h(2)),
        "hole in front of queued bodies is requested; inflight={:?}",
        st.inflight.keys().collect::<Vec<_>>()
    );
    assert!(st.inflight[&h(1)].peers.contains(&0));

    restart_on(&mut st, &hub, &mut wire, &[0]);
    plant_work_path(&mut st, 1, 8);
    mark_heights_ready(&mut st, &hub, 3, 8);
    st.densify_scan_lo = 5;
    st.slots[1].alive = false;
    st.slots[1].in_flight.insert(h(1));
    st.inflight
        .insert(h(1), rbitcoin_ibd::ibd::state::InflightReq::new(1));
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        st.inflight
            .get(&h(1))
            .is_some_and(|req| req.peers.contains(&0)),
        "a gone holder does not cover the hole; inflight={:?}",
        st.inflight.get(&h(1)).map(|req| req.peers.clone())
    );

    let _ = std::fs::remove_dir_all(dir);
}
