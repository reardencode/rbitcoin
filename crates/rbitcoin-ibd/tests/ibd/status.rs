use rbitcoin_ibd::ibd::status::*;
use std::sync::atomic::Ordering;

#[test]
fn loop_stats_sample_dominant_and_live() {
    let s = LoopStats::default();
    assert!(s.confirm_live_snap().is_none());
    s.confirm_begin(10, 4, 100);
    let live = s.confirm_live_snap().unwrap();
    assert_eq!(live.0, 10);
    assert_eq!(live.1, 4);
    assert_eq!(live.2, 100);
    rbitcoin_ibd::ibd::peer_io::wait_past_mono_sentinel();
    let sample = s.sample_and_reset();
    assert!(sample.confirm_live.is_some());
    assert_eq!(sample.dominant(), "confirm"); // live with 0 ns → confirm
    s.confirm_end();
    assert!(s.confirm_live_snap().is_none());

    s.confirm_ns.store(5_000_000, Ordering::Relaxed);
    s.confirm_blocks.store(2, Ordering::Relaxed);
    s.assign_ns.store(1_000_000, Ordering::Relaxed);
    s.assign_issued.store(3, Ordering::Relaxed);
    s.drain_ns.store(500_000, Ordering::Relaxed);
    s.drain_events.store(9, Ordering::Relaxed);
    s.status_scan_ns.store(100_000, Ordering::Relaxed);
    s.confirm_reject_stops.store(1, Ordering::Relaxed);
    let sample = s.sample_and_reset();
    assert_eq!(sample.confirm_blocks, 2);
    assert_eq!(sample.confirm_ms(), 5);
    assert_eq!(sample.assign_ms(), 1);
    assert!(sample.drain_ms() <= 1);
    assert_eq!(sample.status_scan_ms(), 0);
    assert_eq!(sample.confirm_us_per_block(), 2500);
    assert_eq!(sample.dominant(), "confirm");
    assert_eq!(sample.confirm_reject_stops, 1);
    let z = s.sample_and_reset();
    assert_eq!(z.confirm_ns, 0);
    assert_eq!(z.dominant(), "idle");

    s.assign_ns.store(9_000_000, Ordering::Relaxed);
    assert_eq!(s.sample_and_reset().dominant(), "assign");
    s.drain_ns.store(9_000_000, Ordering::Relaxed);
    assert_eq!(s.sample_and_reset().dominant(), "drain");
    s.status_scan_ns.store(9_000_000, Ordering::Relaxed);
    assert_eq!(s.sample_and_reset().dominant(), "status_scan");
}
