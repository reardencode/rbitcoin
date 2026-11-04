use rbitcoin_ibd::ibd::cadence::*;
use std::time::{Duration, Instant};

#[test]
fn assign_due_first_then_period_unless_inflight_empty() {
    let mut c = IbdLoopCadence::new();
    let t0 = Instant::now();
    assert!(c.assign_due(t0, false), "first turn is due");
    c.mark_assign(t0);
    assert!(
        !c.assign_due(t0 + Duration::from_millis(49), false),
        "event-rate assign is the waste"
    );
    assert!(c.assign_due(t0 + ASSIGN_PERIOD, false));
    assert!(
        c.assign_due(t0 + Duration::from_millis(1), true),
        "empty inflight must not wait the period"
    );
}

#[test]
fn peer_slow_is_one_second_not_every_turn() {
    let mut c = IbdLoopCadence::new();
    let t0 = Instant::now();
    assert!(c.peer_slow_due(t0));
    c.mark_peer_slow(t0);
    assert!(!c.peer_slow_due(t0 + Duration::from_millis(50)));
    assert!(!c.peer_slow_due(t0 + Duration::from_millis(999)));
    assert!(c.peer_slow_due(t0 + PEER_SLOW_PERIOD));
}

#[test]
fn hygiene_period_or_bloated() {
    let mut c = IbdLoopCadence::new();
    let t0 = Instant::now();
    assert!(c.hygiene_due(t0, false));
    c.mark_hygiene(t0);
    assert!(!c.hygiene_due(t0 + Duration::from_millis(50), false));
    assert!(
        c.hygiene_due(t0 + Duration::from_millis(1), true),
        "ghost-bloated deque skips the wait"
    );
    assert!(c.hygiene_due(t0 + HYGIENE_PERIOD, false));
}

#[test]
fn deep_hygiene_is_minutes_not_seconds() {
    let mut c = IbdLoopCadence::new();
    let t0 = Instant::now();
    assert!(c.deep_hygiene_due(t0), "first turn is due");
    c.mark_deep_hygiene(t0);
    assert!(
        !c.deep_hygiene_due(t0 + HYGIENE_PERIOD),
        "the chain-sized sweep must not ride the 1 s hygiene period"
    );
    assert!(!c.deep_hygiene_due(t0 + DEEP_HYGIENE_PERIOD - Duration::from_millis(1)));
    assert!(c.deep_hygiene_due(t0 + DEEP_HYGIENE_PERIOD));
}

#[test]
fn headers_period_or_empty_path() {
    let mut c = IbdLoopCadence::new();
    let t0 = Instant::now();
    assert!(c.headers_due(t0, false, false));
    c.mark_headers(t0);
    assert!(
        !c.headers_due(t0 + Duration::from_millis(50), false, false),
        "locator_hashes must not run on every frame"
    );
    assert!(
        c.headers_due(t0 + Duration::from_millis(1), true, false),
        "empty path header fan is immediate"
    );
    assert!(
        c.headers_due(t0 + Duration::from_millis(1), false, true),
        "a block inv asks for headers on this turn"
    );
    assert!(!c.headers_due(t0 + Duration::from_millis(1), false, false));
    assert!(c.headers_due(t0 + HEADERS_PERIOD, false, false));
}
