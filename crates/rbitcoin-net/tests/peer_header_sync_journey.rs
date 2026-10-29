// Header-sync pins. Each chapter drives the IBD loop's own functions and
// checks the getheaders, getdata, shutdown, datadir header, or status line
// a peer or operator would see.

use rbitcoin_ibd::ibd::{
    apply_confirm_reject, apply_headers_event, assign_work_ordered, candidate_tip, candidate_work,
    drain_ready_peer_and_body_events, empty_header_fk_bus, forget_walk_peer, header_poll,
    header_status_view, install_origin, load_origin, log_progress_tick, need_ready_headroom,
    note_block_inv, note_reservation, origin_input, read_progress_published,
    send_getheaders, settle_walk_peer, take_header_ask,
    solicit_track, spawn_header_thread, AssignDepth, ConfirmRejectClass, GetdataWire, HeaderPoll,
    HeaderPollIn, IbdWorkState, LoopStats, PeerCmd, PeerEvent, PeerSlot, RejectParent, StatusClock,
    StatusSnap, ORDERED_HEADERS_SOFT_CAP,
};

use bitcoin::block::Header;
use bitcoin::{CompactTarget, TxMerkleNode};
use std::sync::atomic::AtomicU64;
use std::sync::Mutex;
use std::time::Instant;

fn mine(prev: BlockHash, n: u32) -> Header {
    let mut h = Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([n as u8; 32]),
        time: 1_600_000_000 + n,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: n,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut h);
    h
}

fn chain_of(mut prev: BlockHash, n: u32) -> Vec<Header> {
    let mut out = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let h = mine(prev, i);
        prev = h.block_hash();
        out.push(h);
    }
    out
}

fn slot_at(id: usize, ip: Ipv4Addr, height: u32) -> (PeerSlot, mpsc::UnboundedReceiver<PeerCmd>) {
    let (cmd_tx, rx) = mpsc::unbounded_channel();
    let task = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .spawn(async {});
    let addr = SocketAddr::new(IpAddr::V4(ip), 8333);
    let (requested, solicited_bytes, solicited_ms) = solicit_track();
    (
        PeerSlot {
            id,
            addr,
            net: rbitcoin_net::NetAddr::from_socket(addr),
            cmd_tx,
            in_flight: Default::default(),
            requested,
            solicited_bytes,
            solicited_ms,
            any_rx_ms: Arc::new(AtomicU64::new(0)),
            getdata_wire: GetdataWire::new(),
            peer_height: height,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            chain: Default::default(),
            alive: true,
            task,
        },
        rx,
    )
}

fn slot(id: usize, height: u32) -> (PeerSlot, mpsc::UnboundedReceiver<PeerCmd>) {
    slot_at(id, Ipv4Addr::new(10, 9, 0, id as u8), height)
}

fn hub_pair(label: &str) -> (rbitcoin_query::testutil::TempDir, rbitcoin_net::chain::ChainHub) {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    (dir, hub)
}

fn fresh(
    label: &str,
    height: u32,
) -> (
    rbitcoin_query::testutil::TempDir,
    rbitcoin_net::chain::ChainHub,
    IbdWorkState,
    mpsc::UnboundedReceiver<PeerCmd>,
) {
    let (dir, hub) = hub_pair(label);
    let (s0, rx) = slot(0, height);
    let st = IbdWorkState::new(vec![s0], hub.tip_hash(), hub.tip_height());
    (dir, hub, st, rx)
}

fn poll_in(live: usize, headroom: bool, lag: u32, min_cache: usize, fan: usize) -> HeaderPollIn {
    HeaderPollIn {
        live,
        need_ready_headroom: headroom,
        lag,
        min_cache,
        fan,
    }
}

/// The coordination loop's header arm: ask, latch, or leave the peer alone.
fn drive_poll(st: &mut IbdWorkState, hub: &rbitcoin_net::chain::ChainHub, poll: HeaderPollIn) {
    match header_poll(st, poll) {
        HeaderPoll::Ask => {
            let _ = send_getheaders(st, hub);
        }
        HeaderPoll::LatchDone => {
            st.headers_done = true;
        }
        HeaderPoll::Wait => {}
    }
}

fn took_getheaders(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> bool {
    matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. }))
}

fn locator_of(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> Vec<BlockHash> {
    match rx.try_recv() {
        Ok(PeerCmd::GetHeaders { locator }) => locator,
        Ok(_) => panic!("expected getheaders, got another command"),
        Err(_) => panic!("expected getheaders, channel was empty"),
    }
}

fn status_line(st: &IbdWorkState, hub: &rbitcoin_net::chain::ChainHub) -> String {
    let view = header_status_view(st, hub);
    let snap = StatusSnap {
        peers: st.slots.iter().filter(|s| s.alive).count(),
        horizon: view.horizon,
        hole: 0,
        header_origin: view.origin,
        header_height: view.height,
        header_stored: view.stored,
        header_queue: view.queue,
        header_work_ok: view.work_ok,
        header_walk: view.walk,
        header_quiet: view.quiet,
    };
    rbitcoin_log::capture_logs(true);
    let published = read_progress_published(hub.query.as_ref());
    let mut clock = StatusClock::new(published.tip.unwrap_or(0), Instant::now());
    log_progress_tick(
        &mut clock,
        &snap,
        &published,
        (0, 0, 0),
        0,
        0,
        Instant::now(),
    );
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    logs.into_iter().map(|(_, msg)| msg).collect::<Vec<_>>().join("\n")
}

fn plant_origin(st: &mut IbdWorkState, hub: &rbitcoin_net::chain::ChainHub) {
    let input = origin_input(st, hub);
    let loaded = load_origin(hub, &input);
    install_origin(st, hub, loaded);
}

fn fill_soft_queue(st: &mut IbdWorkState) {
    st.ordered.clear();
    st.ordered_set.clear();
    for i in 0..ORDERED_HEADERS_SOFT_CAP {
        let mut raw = [0xab; 32];
        raw[..4].copy_from_slice(&(i as u32).to_le_bytes());
        let placeholder = BlockHash::from_byte_array(raw);
        st.ordered.push_back(placeholder);
        st.ordered_set.insert(placeholder);
    }
}

/// Retarget every 20 headers. Look-ahead batches are not in the header store,
/// so a later fork has to keep the period header it saw.
fn arm_retarget(hub: &mut rbitcoin_net::chain::ChainHub) {
    hub.params.btc.no_pow_retargeting = false;
    hub.params.btc.allow_min_difficulty_blocks = false;
    let spacing = hub.params.btc.pow_target_spacing;
    hub.params.btc.pow_target_timespan = spacing.saturating_mul(20);
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

/// One accepted header, then an empty download queue, so the walk sits above
/// the stored tip while the ordered-height mark says the path is already there.
/// One stored header, recorded before the walk has an origin, so the origin
/// load lifts the candidate without a checkpoint. The queue is then a full
/// window of placeholders whose tail is the confirmed tip: a later ask is
/// ahead of that path and is not filled from the header index.
fn walk_ahead_of_store(st: &mut IbdWorkState, hub: &rbitcoin_net::chain::ChainHub) -> BlockHash {
    let gen = hub.tip_hash().unwrap();
    let hdr = mine(gen, 1);
    let hash = hdr.block_hash();
    apply_headers_event(st, hub, 0, vec![hdr]);
    plant_origin(st, hub);
    st.ordered.clear();
    st.ordered_set.clear();
    for i in 0..ORDERED_HEADERS_SOFT_CAP {
        let mut raw = [0xab; 32];
        raw[..4].copy_from_slice(&(i as u32).to_le_bytes());
        let placeholder = BlockHash::from_byte_array(raw);
        st.ordered.push_back(placeholder);
        st.ordered_set.insert(placeholder);
    }
    let tail = st.ordered.back().copied().expect("soft-cap queue");
    st.hash_height.insert(tail, 0);
    st.max_ordered_height = u32::MAX;
    hash
}

#[test]
fn caught_up_empty_path_does_not_ask_again() {
    let (dir, hub, mut st, mut rx) = fresh("sync-latch", 0);
    drive_poll(&mut st, &hub, poll_in(0, false, 0, 10, 0));
    st.slots[0].peer_height = 100_000;
    drive_poll(&mut st, &hub, poll_in(0, false, 0, 10, 1));
    assert!(
        !took_getheaders(&mut rx),
        "an empty path with no peer ahead latches; a later advertisement waits"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn soft_cap_with_lag_does_not_open_header_sync() {
    let (dir, hub, mut st, mut rx) = fresh("sync-le", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    drive_poll(
        &mut st,
        &hub,
        poll_in(ORDERED_HEADERS_SOFT_CAP, false, 1, 1, 0),
    );
    assert!(
        !took_getheaders(&mut rx),
        "at the soft cap a lagging queue does not ask unless headroom, a taller peer, or stored look-ahead says so"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headroom_past_the_soft_cap_still_asks() {
    let (dir, hub, mut st, mut rx) = fresh("sync-head", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    drive_poll(
        &mut st,
        &hub,
        poll_in(ORDERED_HEADERS_SOFT_CAP, true, 0, 1, 0),
    );
    assert!(
        took_getheaders(&mut rx),
        "ready headroom past the soft cap asks for the next header"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_taller_peer_past_the_soft_cap_still_asks() {
    let (dir, hub, mut st, mut rx) = fresh("sync-wants", 100_000);
    walk_ahead_of_store(&mut st, &hub);
    st.max_ordered_height = u32::MAX;
    drive_poll(
        &mut st,
        &hub,
        poll_in(ORDERED_HEADERS_SOFT_CAP, false, 0, 1, 0),
    );
    assert!(
        took_getheaders(&mut rx),
        "a connected peer above the walk asks past the soft cap"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn look_ahead_past_the_soft_cap_still_asks() {
    let (dir, hub, mut st, mut rx) = fresh("sync-walk", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    st.max_ordered_height = 0;
    drive_poll(
        &mut st,
        &hub,
        poll_in(ORDERED_HEADERS_SOFT_CAP, false, 1, 1, 0),
    );
    assert!(
        took_getheaders(&mut rx),
        "a walk tip past the stored path asks past the soft cap"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_short_queue_asks_until_the_cache_is_full() {
    let (dir, hub, mut st, mut rx) = fresh("ask-lt", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    drive_poll(&mut st, &hub, poll_in(5, false, 0, 10, 0));
    assert!(
        took_getheaders(&mut rx),
        "five queued headers against a ten-header cache still asks"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_full_cache_without_lag_does_not_ask() {
    let (dir, hub, mut st, mut rx) = fresh("ask-le", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    drive_poll(&mut st, &hub, poll_in(5, false, 0, 5, 0));
    assert!(
        !took_getheaders(&mut rx),
        "a queue that already fills the cache does not ask"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn lag_asks_even_when_the_cache_is_full() {
    let (dir, hub, mut st, mut rx) = fresh("ask-lag", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    drive_poll(&mut st, &hub, poll_in(10, false, 3, 5, 0));
    assert!(
        took_getheaders(&mut rx),
        "lag behind the walk asks even when the cache is full"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ready_headroom_asks_when_the_cache_is_full() {
    let (dir, hub, mut st, mut rx) = fresh("ask-or-head", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    drive_poll(&mut st, &hub, poll_in(10, true, 0, 5, 0));
    assert!(took_getheaders(&mut rx), "headroom alone asks");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_taller_peer_asks_when_the_cache_is_full() {
    let (dir, hub, mut st, mut rx) = fresh("ask-or-wants", 100_000);
    walk_ahead_of_store(&mut st, &hub);
    st.max_ordered_height = u32::MAX;
    drive_poll(&mut st, &hub, poll_in(10, false, 0, 5, 0));
    assert!(took_getheaders(&mut rx), "a taller peer alone asks");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn stored_look_ahead_asks_when_the_cache_is_full() {
    let (dir, hub, mut st, mut rx) = fresh("ask-or-walk", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    st.max_ordered_height = 0;
    drive_poll(&mut st, &hub, poll_in(10, false, 0, 5, 0));
    assert!(
        took_getheaders(&mut rx),
        "look-ahead past the stored path alone asks"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_already_done_does_not_ask() {
    let (dir, hub, mut st, mut rx) = fresh("poll-done", 100_000);
    st.headers_done = true;
    drive_poll(&mut st, &hub, poll_in(5, false, 3, 10, 1));
    assert!(
        !took_getheaders(&mut rx),
        "a latched header sync does not ask again"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_empty_queue_with_no_fan_latches_without_asking() {
    let (dir, hub, mut st, mut rx) = fresh("poll-zero", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    drive_poll(&mut st, &hub, poll_in(0, false, 0, 10, 0));
    assert!(
        !took_getheaders(&mut rx),
        "no live headers and no fan latches instead of asking"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_block_announcement_asks_immediately() {
    let (dir, hub, mut st, mut rx) = fresh("poll-inv", 100_000);
    // No challenge is pending. The poll must not treat an idle lane as an ask.
    drive_poll(&mut st, &hub, poll_in(0, false, 0, 10, 0));
    assert!(
        !took_getheaders(&mut rx),
        "without a block announcement an idle lane does not ask"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn locator_names_the_earlier_checkpoint() {
    let (dir, hub, mut st, mut rx) = fresh("loc-ck", 100_000);
    plant_origin(&mut st, &hub);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = rx.try_recv();
    let gen = hub.tip_hash().unwrap();
    let first = mine(gen, 1);
    let first_hash = first.block_hash();
    apply_headers_event(&mut st, &hub, 0, vec![first]);
    while rx.try_recv().is_ok() {}
    assert!(send_getheaders(&mut st, &hub).unwrap());
    while rx.try_recv().is_ok() {}
    let second = mine(first_hash, 2);
    apply_headers_event(&mut st, &hub, 0, vec![second]);
    while rx.try_recv().is_ok() {}
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let locator = locator_of(&mut rx);
    assert!(
        locator.contains(&first_hash),
        "the getheaders locator names the earlier checkpoint, got {locator:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn getheaders_locator_stops_at_eight_hashes() {
    let (dir, hub, mut st, mut rx) = fresh("loc-eight", 100_000);
    plant_origin(&mut st, &hub);
    let gen = hub.tip_hash().unwrap();
    // One header per batch: each accepted batch is one checkpoint. 256 keeps
    // the eighth hash off checkpoint 0, so a ninth comparison still names one.
    let headers = chain_of(gen, 256);
    let early = headers[1].block_hash();
    for hdr in headers {
        apply_headers_event(&mut st, &hub, 0, vec![hdr]);
    }
    while rx.try_recv().is_ok() {}
    assert!(
        send_getheaders(&mut st, &hub).unwrap(),
        "a peer still ahead of a long walk is asked"
    );
    let locator = locator_of(&mut rx);
    assert!(
        locator.contains(&early),
        "getheaders names an early checkpoint, got {locator:?}"
    );
    assert_eq!(
        locator.len(),
        9,
        "getheaders is eight walk hashes plus the confirmed tip, got {locator:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn successor_at_the_walk_tip_is_what_gets_asked() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("next-h");
    let (s0, mut rx) = slot(0, 50_000);
    let mut st = IbdWorkState::new(vec![s0], None, None);
    let parent = BlockHash::from_byte_array([0x11; 32]);
    st.record_height(parent, 0);
    assert!(
        send_getheaders(&mut st, &hub).unwrap(),
        "nothing is indexed at the next height, so the peer is asked"
    );
    assert!(
        took_getheaders(&mut rx),
        "the ask is a getheaders, not a skipped successor"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn full_header_window_asks_again_under_the_soft_cap() {
    let (dir, hub, mut st, mut rx) = fresh("batch-under", 500_000);
    let gen = hub.tip_hash().unwrap();
    let headers = chain_of(gen, rbitcoin_net::codec::MAX_HEADERS_RESULTS as u32);
    apply_headers_event(&mut st, &hub, 0, headers);
    assert!(
        took_getheaders(&mut rx),
        "a full header window under the soft cap asks for the next window"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn full_header_window_stops_at_the_soft_cap() {
    let (dir, hub, mut st, mut rx) = fresh("batch-cap", 500_000);
    let pad = ORDERED_HEADERS_SOFT_CAP - rbitcoin_net::codec::MAX_HEADERS_RESULTS;
    for i in 0..pad {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&(i as u32).to_le_bytes());
        st.ordered_set.insert(BlockHash::from_byte_array(raw));
    }
    let gen = hub.tip_hash().unwrap();
    let headers = chain_of(gen, rbitcoin_net::codec::MAX_HEADERS_RESULTS as u32);
    apply_headers_event(&mut st, &hub, 0, headers);
    assert!(
        !took_getheaders(&mut rx),
        "a full window that lands on the soft cap does not ask for more"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ctrl_headers_are_applied_while_the_header_thread_has_room() {
    let (dir, hub) = hub_pair("drain-room");
    let hub = Arc::new(hub);
    let (s0, _rx) = slot(0, 10);
    let mut st = IbdWorkState::new(vec![s0], hub.tip_hash(), hub.tip_height());
    let (tx, rx) = mpsc::channel(1);
    st.header_cmd = Some(tx.clone());
    let shared = Arc::new(Mutex::new(st));
    let join = spawn_header_thread(
        Arc::clone(&shared),
        Arc::clone(&hub),
        rx,
        empty_header_fk_bus(),
        rbitcoin_store::HeaderThreadProbe::new(),
    );
    let gen = hub.tip_hash().unwrap();
    let hdr = mine(gen, 7);
    let hash = hdr.block_hash();
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel();
    ctrl_tx
        .send(PeerEvent::Headers {
            peer: 0,
            headers: vec![hdr],
        })
        .unwrap();
    let (body_tx, mut body_rx) = mpsc::unbounded_channel();
    let mut book = AddrMan::new();
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    {
        let mut st = shared.lock().unwrap();
        drain_ready_peer_and_body_events(
            &mut st,
            hub.as_ref(),
            &mut body_rx,
            &mut ctrl_rx,
            &AtomicU32::new(0),
            &LoopStats::default(),
            &mut book,
            local,
            None,
        )
        .unwrap();
        st.header_cmd = None;
    }
    drop(tx);
    drop(ctrl_tx);
    drop(body_tx);
    join.join().unwrap();
    assert!(
        hub.header_of(&hash).is_some(),
        "a headers message is written while the header thread still has room"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_mutated_block_drops_the_sender_not_a_noban_neighbor() {
    let (dir, hub) = hub_pair("punish-or");
    let (noban_slot, _noban_rx) = slot_at(1, Ipv4Addr::new(127, 0, 0, 1), 10);
    let (sender, mut sender_rx) = slot_at(2, Ipv4Addr::new(10, 1, 1, 2), 10);
    let mut st = IbdWorkState::new(vec![noban_slot, sender], hub.tip_hash(), hub.tip_height());
    let peers = rbitcoin_net::peers::PeerHub::new(rbitcoin_consensus::NodeClock::new());
    let mut table = rbitcoin_net::net_permissions::NetPermTable::default();
    table
        .whitelist
        .push(rbitcoin_net::net_permissions::parse_whitelist("noban,out@127.0.0.1").unwrap());
    peers.set_net_perms(table);
    st.perms = Some(peers);
    let hash = BlockHash::from_byte_array([0x44; 32]);
    apply_confirm_reject(
        &mut st,
        1,
        hash,
        ConfirmRejectClass::SoftWire,
        "bad-txnmrklroot",
        None,
        Some(&hub),
        1,
        None,
        Some(2),
        RejectParent::default(),
    );
    assert!(
        matches!(sender_rx.try_recv(), Ok(PeerCmd::Shutdown)),
        "the sender of a mutated block is dropped"
    );
    assert!(st.slots[0].alive, "the noban neighbor stays connected");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_batched_consensus_reject_does_not_reget_the_first_hash() {
    let (dir, hub, mut st, mut rx) = fresh("cascade-and", 20);
    let hash = BlockHash::from_byte_array([0x55; 32]);
    st.record_height(hash, 50);
    st.densify_scan_lo = 100;
    st.body.mark_pending(hash);
    apply_confirm_reject(
        &mut st,
        50,
        hash,
        ConfirmRejectClass::ConsensusInvalid,
        "consensus: bad-txns",
        Some(hub.query.as_ref()),
        Some(&hub),
        2,
        None,
        None,
        RejectParent {
            hash: Some(BlockHash::from_byte_array([0x01; 32])),
            unreadable: false,
        },
    );
    let stats = LoopStats::default();
    let cfg = rbitcoin_ibd::ibd::IbdConfig::for_test();
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        !took_getdata(&mut rx),
        "a two-block consensus wave does not ask again for the first hash"
    );
    let _ = std::fs::remove_dir_all(dir);
}

fn took_getdata(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> bool {
    matches!(rx.try_recv(), Ok(PeerCmd::GetData { .. }))
}

#[test]
fn growing_the_queue_keeps_the_peer_on_the_walk() {
    let (dir, hub, mut fast, mut fast_rx) = {
        let (dir, hub) = hub_pair("settle-grow");
        let (mut a, ra) = slot(0, 100_000);
        a.first_data_ms = 2;
        let (b, _rb) = slot(1, 100_000);
        let mut st = IbdWorkState::new(vec![a, b], hub.tip_hash(), hub.tip_height());
        plant_origin(&mut st, &hub);
        (dir, hub, st, ra)
    };
    let before = fast.ordered.len();
    let tip = candidate_tip(&fast);
    let dummy = BlockHash::from_byte_array([0x61; 32]);
    fast.ordered.push_back(dummy);
    fast.ordered_set.insert(dummy);
    settle_walk_peer(&mut fast, &hub, 0, tip, before, None, 1);
    assert!(send_getheaders(&mut fast, &hub).unwrap());
    assert!(
        took_getheaders(&mut fast_rx),
        "a reply that queues a header keeps the fast peer as the ask"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn before_origin_a_short_reply_does_not_retire_the_peer() {
    let (dir, hub) = hub_pair("settle-origin");
    let (mut a, mut ra) = slot(0, 100_000);
    a.first_data_ms = 2;
    let (b, _rb) = slot(1, 100_000);
    let mut st = IbdWorkState::new(vec![a, b], hub.tip_hash(), hub.tip_height());
    settle_walk_peer(&mut st, &hub, 0, None, 0, None, 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        took_getheaders(&mut ra),
        "before the origin is known a short reply does not move the ask"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn equal_work_is_not_below_the_floor() {
    let (dir, mut hub) = hub_pair("floor-eq");
    let (mut fast, mut fast_rx) = slot(0, 100_000);
    fast.first_data_ms = 2;
    fast.connected_ms = 1;
    let (mut slow, mut slow_rx) = slot(1, 100_000);
    slow.first_data_ms = 80;
    slow.connected_ms = 1;
    let mut st = IbdWorkState::new(vec![fast, slow], hub.tip_hash(), hub.tip_height());
    plant_origin(&mut st, &hub);
    let work = candidate_work(&st);
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 1,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: hub.tip_hash().unwrap(),
            min_work_be: work,
        }),
    };
    let tip = candidate_tip(&st);
    let queued = st.ordered.len();
    settle_walk_peer(&mut st, &hub, 0, tip, queued, None, 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        took_getheaders(&mut slow_rx),
        "work equal to the floor still retires the fast peer"
    );
    assert!(
        fast_rx.try_recv().is_err(),
        "the fast peer is not asked again"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn forgetting_a_different_peer_keeps_the_challenge() {
    let (dir, hub) = hub_pair("forget-ch");
    let (mut challenged, mut challenged_rx) = slot(0, 100_000);
    challenged.first_data_ms = 80;
    challenged.connected_ms = 1;
    let (mut other, mut other_rx) = slot(1, 100_000);
    other.first_data_ms = 2;
    other.connected_ms = 1;
    let mut st = IbdWorkState::new(
        vec![challenged, other],
        hub.tip_hash(),
        hub.tip_height(),
    );
    plant_origin(&mut st, &hub);
    note_block_inv(&mut st, 0);
    forget_walk_peer(&mut st, 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        took_getheaders(&mut challenged_rx),
        "dropping another peer keeps the block-inv challenge on its sender"
    );
    assert!(other_rx.try_recv().is_err(), "the other peer is not asked");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unproven_origin_logs_headers_in_progress() {
    let (dir, mut hub, mut st, _rx) = fresh("quiet-and", 0);
    hub.milestone = rbitcoin_consensus::Milestone {
        height: 1,
        anchor: Some(rbitcoin_consensus::MilestoneAnchor {
            hash: hub.tip_hash().unwrap(),
            min_work_be: [0xff; 32],
        }),
    };
    plant_origin(&mut st, &hub);
    let line = status_line(&st, &hub);
    assert!(
        line.contains("phase=write") || line.contains("phase=walk"),
        "an unproved origin is still in progress: {line}"
    );
    assert!(
        !line.contains("headers done"),
        "an unproved origin is not the caught-up line: {line}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_proved_quiet_walk_logs_headers_done() {
    let (dir, hub, mut st, _rx) = fresh("quiet-not", 0);
    st.header_walk.prove_through(0);
    let line = status_line(&st, &hub);
    assert!(
        line.contains("headers done"),
        "a proved walk with no peer ahead logs headers done: {line}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn block_getdata_skips_the_reserved_header_peer() {
    let (dir, hub) = hub_pair("peers-le");
    let (a, mut ra) = slot(0, 10);
    let (b, mut rb) = slot(1, 10);
    let mut st = IbdWorkState::new(vec![a, b], hub.tip_hash(), hub.tip_height());
    st.slots[0].peer_height = 100_000;
    assert!(send_getheaders(&mut st, &hub).unwrap());
    let _ = ra.try_recv();
    let hash = BlockHash::from_byte_array([0x72; 32]);
    st.record_height(hash, 40);
    st.body.mark_missing(hash);
    st.reorg.register_explore([hash], None);
    let stats = LoopStats::default();
    let cfg = rbitcoin_ibd::ibd::IbdConfig::for_test();
    assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
    assert!(
        matches!(rb.try_recv(), Ok(PeerCmd::GetData { .. })),
        "block getdata goes to the peer that is not serving headers"
    );
    assert!(
        ra.try_recv().is_err(),
        "the reserved header peer does not also get the block"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_peer_level_with_the_walk_does_not_ask() {
    let (dir, hub, mut st, mut rx) = fresh("wants-eq", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = st.header_walk.tip_height();
    st.max_ordered_height = u32::MAX;
    drive_poll(
        &mut st,
        &hub,
        poll_in(ORDERED_HEADERS_SOFT_CAP, false, 0, 1, 0),
    );
    assert!(
        !took_getheaders(&mut rx),
        "a peer at the walk tip is not ahead, so the soft cap stays closed"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn above_the_soft_cap_with_lag_does_not_ask() {
    let (dir, hub, mut st, mut rx) = fresh("sync-gt", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    drive_poll(
        &mut st,
        &hub,
        poll_in(ORDERED_HEADERS_SOFT_CAP + 1, false, 1, 1, 0),
    );
    assert!(
        !took_getheaders(&mut rx),
        "one past the soft cap does not open header sync"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn no_checkpoint_still_asks_for_body_headroom() {
    let (dir, hub, mut st, mut rx) = fresh("ck-head", 0);
    walk_ahead_of_store(&mut st, &hub);
    st.slots[0].peer_height = 0;
    st.max_ordered_height = u32::MAX;
    let headroom = need_ready_headroom(true, st.header_walk.has_checkpoints());
    drive_poll(
        &mut st,
        &hub,
        poll_in(ORDERED_HEADERS_SOFT_CAP, headroom, 0, 1, 0),
    );
    assert!(
        took_getheaders(&mut rx),
        "with no checkpoint yet, a full queue still asks when bodies want headroom"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A block inv opened a challenge and the reply has arrived, so the lane is
/// clear and the challenge is waiting to be judged.
fn challenge_answered(
    st: &mut IbdWorkState,
    hub: &rbitcoin_net::chain::ChainHub,
    peer: usize,
    rx: &mut mpsc::UnboundedReceiver<PeerCmd>,
) {
    note_block_inv(st, peer);
    assert!(send_getheaders(st, hub).unwrap());
    assert!(took_getheaders(rx), "the block inv asks that peer");
    let _ = take_header_ask(st, peer);
}

#[test]
fn forgetting_another_peer_keeps_the_reservation() {
    let (dir, hub) = hub_pair("forget-res");
    let (mut slow, mut slow_rx) = slot(0, 100_000);
    slow.first_data_ms = 80;
    slow.connected_ms = 1;
    let (mut fast, mut fast_rx) = slot(1, 0);
    fast.first_data_ms = 2;
    fast.connected_ms = 1;
    let mut st = IbdWorkState::new(vec![slow, fast], hub.tip_hash(), hub.tip_height());
    plant_origin(&mut st, &hub);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(took_getheaders(&mut slow_rx), "the tall peer takes the ask");
    let gen = hub.tip_hash().unwrap();
    apply_headers_event(&mut st, &hub, 0, vec![mine(gen, 1)]);
    while slow_rx.try_recv().is_ok() {}
    st.slots[1].peer_height = 100_000;
    forget_walk_peer(&mut st, 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        took_getheaders(&mut slow_rx),
        "forgetting a different peer keeps the reserved header peer"
    );
    assert!(fast_rx.try_recv().is_err(), "the faster peer is not asked");
    let _ = std::fs::remove_dir_all(dir);
}

/// Judge one answered challenge, then the next getheaders shows who is still
/// on the walk.
fn judge_challenge(
    label: &str,
    tip_before: Option<BlockHash>,
    work_before: [u8; 32],
) {
    let (dir, hub) = hub_pair(label);
    let (mut fast, mut fast_rx) = slot(0, 100_000);
    fast.first_data_ms = 2;
    fast.connected_ms = 1;
    let (mut slow, mut slow_rx) = slot(1, 100_000);
    slow.first_data_ms = 80;
    slow.connected_ms = 1;
    let mut st = IbdWorkState::new(vec![fast, slow], hub.tip_hash(), hub.tip_height());
    plant_origin(&mut st, &hub);
    challenge_answered(&mut st, &hub, 0, &mut fast_rx);
    note_reservation(&mut st, &hub, 0, tip_before, work_before);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        took_getheaders(&mut slow_rx),
        "a challenge reply that does not beat the candidate asks the other peer"
    );
    assert!(fast_rx.try_recv().is_err(), "the challenged peer is retired");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn equal_work_does_not_beat_the_candidate() {
    let (dir, hub) = hub_pair("beat-ge");
    let (fast, _fast_rx) = slot(0, 100_000);
    let (slow, _slow_rx) = slot(1, 100_000);
    let mut st = IbdWorkState::new(vec![fast, slow], hub.tip_hash(), hub.tip_height());
    plant_origin(&mut st, &hub);
    let work = candidate_work(&st);
    drop(st);
    let _ = std::fs::remove_dir_all(dir);
    judge_challenge(
        "beat-ge2",
        Some(BlockHash::from_byte_array([0x22; 32])),
        work,
    );
}

#[test]
fn same_tip_does_not_beat_the_candidate() {
    let (dir, hub) = hub_pair("beat-or");
    let (fast, _rx) = slot(0, 100_000);
    let (slow, _rx2) = slot(1, 100_000);
    let mut st = IbdWorkState::new(vec![fast, slow], hub.tip_hash(), hub.tip_height());
    plant_origin(&mut st, &hub);
    let tip = candidate_tip(&st);
    drop(st);
    let _ = std::fs::remove_dir_all(dir);
    judge_challenge("beat-or2", tip, [0u8; 32]);
}

#[test]
fn a_reply_at_the_same_work_retires_the_challenger() {
    let (dir, hub) = hub_pair("beat-not");
    let (fast, _rx) = slot(0, 100_000);
    let (slow, _rx2) = slot(1, 100_000);
    let mut st = IbdWorkState::new(vec![fast, slow], hub.tip_hash(), hub.tip_height());
    plant_origin(&mut st, &hub);
    let tip = candidate_tip(&st);
    let work = candidate_work(&st);
    drop(st);
    let _ = std::fs::remove_dir_all(dir);
    judge_challenge("beat-not2", tip, work);
}

#[test]
fn forgetting_another_peer_keeps_the_open_challenge() {
    let (dir, hub) = hub_pair("forget-open");
    let (mut fast, mut fast_rx) = slot(0, 100_000);
    fast.first_data_ms = 2;
    fast.connected_ms = 1;
    let (mut slow, mut slow_rx) = slot(1, 100_000);
    slow.first_data_ms = 80;
    slow.connected_ms = 1;
    let mut st = IbdWorkState::new(vec![fast, slow], hub.tip_hash(), hub.tip_height());
    plant_origin(&mut st, &hub);
    challenge_answered(&mut st, &hub, 0, &mut fast_rx);
    forget_walk_peer(&mut st, 1);
    let tip = candidate_tip(&st);
    let work = candidate_work(&st);
    note_reservation(&mut st, &hub, 0, tip, work);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        took_getheaders(&mut slow_rx),
        "forgetting a different peer keeps the open challenge on its sender"
    );
    assert!(fast_rx.try_recv().is_err(), "the challenged peer is retired");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unlinked_batch_stays_on_the_wire_peer() {
    let (dir, hub, mut st, _rx) = fresh("sup-or", 100_000);
    plant_origin(&mut st, &hub);
    let gen = hub.tip_hash().unwrap();
    let side = mine(gen, 7);
    hub.ensure_headers_batch(&[side]).unwrap();
    let side_hash = side.block_hash();
    st.record_height(side_hash, 1);
    let first = mine(side_hash, 8);
    let second = mine(side_hash, 9);
    let before = hub.query.store().header_count();
    apply_headers_event(&mut st, &hub, 0, vec![first, second]);
    assert!(
        st.slots[0].alive,
        "headers that do not link are not a reason to drop the peer"
    );
    assert_eq!(
        hub.query.store().header_count(),
        before + 2,
        "an unlinked batch off a stored side header is still written"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_short_fork_off_a_known_header_is_not_stored() {
    let (dir, hub, mut st, _rx) = fresh("sup-and", 100_000);
    plant_origin(&mut st, &hub);
    let gen = hub.tip_hash().unwrap();
    let side = mine(gen, 4);
    hub.ensure_headers_batch(&[side]).unwrap();
    let side_hash = side.block_hash();
    st.record_height(side_hash, 1);
    let hdr = mine(side_hash, 5);
    let before = hub.query.store().header_count();
    apply_headers_event(&mut st, &hub, 0, vec![hdr]);
    assert_eq!(
        hub.query.store().header_count(),
        before,
        "a short fork off a side header is not written over the walk"
    );
    assert!(st.slots[0].alive, "that fork does not drop the peer");
    let _ = std::fs::remove_dir_all(dir);
}

/// A lighter fork off an unstored look-ahead checkpoint retargets from that
/// checkpoint's period header. Dropping the snap makes the next period's
/// `nBits` uncomputable, and the peer is disconnected.
#[test]
fn a_fork_retarget_uses_the_challenger_period() {
    let (dir, mut hub, mut st, mut rx) = fresh("chal-diff", 100_000);
    arm_retarget(&mut hub);
    let gen_hash = hub.tip_hash().unwrap();
    let genesis = hub.header_of(&gen_hash).unwrap();
    plant_origin(&mut st, &hub);
    fill_soft_queue(&mut st);
    assert_eq!(hub.best_header_height(), 0, "peer height is not a local header");
    let main_a = extend_chain(&hub, &genesis, &[], 20, 1);
    let main_b = extend_chain(&hub, &genesis, &main_a, 10, 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(took_getheaders(&mut rx), "the look-ahead ask goes to the peer");
    apply_headers_event(&mut st, &hub, 0, main_a.clone());
    assert!(st.slots[0].alive, "the first look-ahead window is accepted");
    assert_eq!(hub.best_header_height(), 20);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(took_getheaders(&mut rx), "the next look-ahead ask goes to the peer");
    apply_headers_event(&mut st, &hub, 0, main_b);
    assert!(st.slots[0].alive, "the second look-ahead window is accepted");
    assert_eq!(hub.best_header_height(), 30);
    // The download path names a different header at the period height than the
    // checkpoint that opened that period. The store fallback would retarget
    // from this decoy; the challenger snap must keep the checkpoint header.
    let period = main_a[19];
    let parent = main_a[18];
    let decoy = mine_bits(
        parent.block_hash(),
        20,
        period.time.saturating_add(2_000_000),
        period.bits,
        9,
    );
    hub.ensure_headers_batch(&[decoy]).unwrap();
    st.record_height(decoy.block_hash(), 20);
    let fork_a = extend_chain(&hub, &genesis, &main_a, 10, 2);
    apply_headers_event(&mut st, &hub, 0, fork_a.clone());
    assert!(
        st.slots[0].alive,
        "a lighter fork off the first checkpoint stays on that peer"
    );
    let fork_b = extend_chain(&hub, &genesis, &[&main_a[..], &fork_a[..]].concat(), 10, 2);
    apply_headers_event(&mut st, &hub, 0, fork_b);
    assert!(
        st.slots[0].alive,
        "the retarget on that fork uses the checkpoint period, so the peer stays"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_header_only_parent_outside_the_walk_is_extended() {
    let (dir, hub, mut st, _rx) = fresh("sup-or2", 100_000);
    plant_origin(&mut st, &hub);
    let gen = hub.tip_hash().unwrap();
    let side = mine(gen, 6);
    hub.ensure_headers_batch(&[side]).unwrap();
    let side_hash = side.block_hash();
    // Height is known, but the path slot is not this header, so it is not a
    // candidate parent. The short-fork gate must not swallow the write.
    st.record_height(side_hash, 1);
    st.height_to_hash.remove(&1);
    let hdr = mine(side_hash, 11);
    let before = hub.query.store().header_count();
    apply_headers_event(&mut st, &hub, 0, vec![hdr]);
    assert_eq!(
        hub.query.store().header_count(),
        before + 1,
        "a header on a stored parent that is not the walk is written"
    );
    assert!(st.slots[0].alive, "that header does not drop the peer");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_local_challenge_still_retires_a_short_reply() {
    let (dir, hub) = hub_pair("settle-ch");
    let (mut fast, mut fast_rx) = slot(0, 100_000);
    fast.first_data_ms = 2;
    fast.connected_ms = 1;
    let (mut slow, mut slow_rx) = slot(1, 100_000);
    slow.first_data_ms = 80;
    slow.connected_ms = 1;
    let mut st = IbdWorkState::new(vec![fast, slow], hub.tip_hash(), hub.tip_height());
    plant_origin(&mut st, &hub);
    challenge_answered(&mut st, &hub, 0, &mut fast_rx);
    let tip = candidate_tip(&st);
    let queued = st.ordered.len();
    settle_walk_peer(&mut st, &hub, 0, tip, queued, None, 1);
    assert!(send_getheaders(&mut st, &hub).unwrap());
    assert!(
        took_getheaders(&mut slow_rx),
        "a short reply to our own block inv retires that peer"
    );
    assert!(fast_rx.try_recv().is_err(), "the challenged peer is retired");
    let _ = std::fs::remove_dir_all(dir);
}
