use rbitcoin_ibd::ibd::rate::*;

#[test]
fn relslow_active_is_longer_than_rank() {
    let mut r = PeerRate::default();
    r.sample(0, 0, true);
    r.sample(RANK_MATURE_MS, RANK_MATURE_MS * 1_000, true);
    assert!(r.bps().is_some());
    assert!(r.active_ms < RELSLOW_ACTIVE_MS);
}

#[test]
fn idle_rebaseline_freezes_ewma() {
    let mut r = PeerRate::default();
    r.sample(0, 0, true);
    r.sample(5_000, 5_000_000, true);
    let frozen = r.bps().expect("mature after 5s");
    r.sample(15_000, 5_000_000 + 50_000_000, false);
    assert_eq!(r.bps(), Some(frozen));
}

#[test]
fn silence_keeps_saved_bps_and_eviction_scales_with_age() {
    let mut r = PeerRate::default();
    r.sample(0, 0, true);
    r.sample(5_000, 5_000_000, true);
    let saved = r.bps().expect("mature");
    // In-flight gaps must not rewrite the saved transfer rate.
    r.sample(10_000, 5_000_000, true);
    r.sample(15_000, 5_000_000, true);
    assert_eq!(r.bps(), Some(saved));
    // Last qualifying rx is the byte sample at 5s. Eviction folds silence
    // in as zero throughput: age == TAU → half, age == 3*TAU → quarter.
    assert_eq!(r.eviction_bps(5_000), Some(saved));
    assert_eq!(r.eviction_bps(5_000 + TAU_MS), Some(saved / 2));
    assert_eq!(r.eviction_bps(5_000 + 3 * TAU_MS), Some(saved / 4));
}

#[test]
fn bps_none_until_rank_mature() {
    let mut r = PeerRate::default();
    r.sample(0, 0, true);
    r.sample(4_000, 4_000_000, true);
    assert!(r.bps().is_none());
    r.sample(5_000, 5_000_000, true);
    assert!(r.bps().is_some());
}

#[test]
fn progress_marks_on_64k_not_on_small_delta() {
    let mut r = PeerRate::default();
    r.sample(0, 0, true);
    r.sample(1_000, 1_000, true);
    assert_eq!(r.progress_ms, 0);
    r.sample(2_000, 1_000 + PROGRESS_STEP, true);
    assert_eq!(r.progress_ms, 2_000);
}

#[test]
fn stalled_ignores_getdata_write_time() {
    let mut r = PeerRate::default();
    // Last real receive is t=0. A getdata write at t=20s is us, not the peer.
    r.note_rx(0);
    r.note_work_started(20_000);
    assert!(r.stalled(30_001, 30_000));
    assert!(r.stalled(40_000, 30_000));
}

#[test]
fn stalled_false_when_rx_within_grace() {
    let mut r = PeerRate::default();
    r.note_work_started(0);
    r.note_rx(20_000);
    assert!(!r.stalled(45_000, 30_000));
    assert!(r.stalled(50_001, 30_000));
    assert!(r.has_recent_rx(45_000, 30_000));
    assert!(!r.has_recent_rx(50_001, 30_000));
    assert!(!r.quiet(45_000, 30_000));
}

#[test]
fn any_rx_does_not_move_block_progress() {
    let mut r = PeerRate::default();
    r.note_connected(1_000);
    r.note_any_rx(40_000);
    assert_eq!(r.progress_ms, 1_000);
    assert_eq!(r.any_rx_ms, 40_000);
    assert!(r.stalled(40_000, 30_000));
    assert!(!r.quiet(40_000, 30_000));
}
