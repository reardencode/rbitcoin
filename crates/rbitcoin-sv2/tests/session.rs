use rbitcoin_sv2::session::{constraints_rebuild_at, Templates, MAX_RETIRED_TIPS};
use rbitcoin_sv2::template::Job;
use rbitcoin_sv2::CONSTRAINTS_COOLDOWN;
use std::time::Duration;
use tokio::time::Instant;

#[test]
fn constraints_rebuild_at_uses_the_cooldown() {
    let built_at = Instant::now();
    let soon = built_at + CONSTRAINTS_COOLDOWN - Duration::from_millis(1);
    assert_eq!(
        constraints_rebuild_at(built_at, soon, CONSTRAINTS_COOLDOWN),
        Some(built_at + CONSTRAINTS_COOLDOWN)
    );
    let due = built_at + CONSTRAINTS_COOLDOWN;
    assert_eq!(
        constraints_rebuild_at(built_at, due, CONSTRAINTS_COOLDOWN),
        None
    );
}

#[test]
fn tip_event_rebuilds_a_template_built_before_it() {
    let (old, new) = ([1; 32], [2; 32]);
    let mut t = Templates::default();
    assert!(t.on_tip(old), "first tip");
    t.current_prev = Some(old);
    assert!(!t.on_tip(old), "repeat event with no build since");
    // A build between the store tip move and its event (constraints, or
    // the previous event's rebuild) already sits on the new prev hash.
    t.current_prev = Some(new);
    t.built_since_tip = true;
    assert!(t.on_tip(new), "template may hold the block's confirmed txs");
    assert!(!t.on_tip(new), "no build since the event");
    // A failed reorg disconnects `new` without an event, then its rollback
    // reconnects `new`; a build in that window precedes the second event.
    t.built_since_tip = true;
    assert!(t.on_tip(new), "reconnect of the same hash after a build");
}

const A: [u8; 32] = [0xa; 32];
const B: [u8; 32] = [0xb; 32];
const GRACE: Duration = Duration::from_secs(10);

fn job(prev: [u8; 32]) -> Job {
    Job {
        merkle_path: Vec::new(),
        prev_hash: prev,
        header_timestamp: 0,
        n_bits: 0,
        target: [0; 32],
        txs: Vec::new(),
    }
}

/// Retention by the job's own parent. The orderings below sit between
/// `ChainHub` publishing the store tip and this session handling its tip
/// event (see `Templates::on_tip`), where a validation can finish on either
/// tip. No socket reaches them deterministically, so as in
/// `tip_event_rebuilds_a_template_built_before_it` the shipped `Templates`
/// methods are driven directly (TESTING.md "True journeys").
fn on_tip_a() -> (Templates, Instant) {
    let now = Instant::now();
    let mut t = Templates::default();
    t.start_grace(A, now + GRACE);
    t.retain(1, job(A), (0, now));
    (t, now)
}

fn retains(t: &Templates, id: u64) -> bool {
    t.get(id).is_some()
}

#[test]
fn a_job_on_the_new_tip_validated_before_its_event_is_not_retired_by_that_event() {
    let (mut t, now) = on_tip_a();
    t.retain(2, job(B), (0, now));
    assert_eq!(t.get(2).unwrap().retire_at, None, "no deadline yet");
    let deadline = now + GRACE;
    t.start_grace(B, deadline);
    assert_eq!(t.get(1).unwrap().retire_at, Some(deadline), "the old tip's");
    assert_eq!(t.get(2).unwrap().retire_at, None, "B is the tip now");
    t.retire(deadline + GRACE);
    assert!(!retains(&t, 1) && retains(&t, 2));
    let later = deadline + GRACE;
    t.start_grace(A, later + GRACE);
    assert_eq!(
        t.get(2).unwrap().retire_at,
        Some(later + GRACE),
        "the next tip event retires it with its own grace"
    );
}

#[test]
fn a_job_on_the_old_tip_finishing_after_the_new_tip_retires_at_the_original_deadline() {
    let (mut t, now) = on_tip_a();
    let deadline = now + GRACE;
    t.start_grace(B, deadline);
    t.retain(2, job(A), (0, now));
    assert_eq!(t.get(2).unwrap().retire_at, Some(deadline));
    assert_eq!(t.next_retire(), Some(deadline));
    t.retire(deadline - Duration::from_millis(1));
    assert!(retains(&t, 1) && retains(&t, 2), "inside the grace");
    t.retire(deadline);
    assert!(
        !retains(&t, 1) && !retains(&t, 2),
        "both at the one deadline"
    );
}

#[test]
fn a_job_on_the_old_tip_finishing_past_its_deadline_is_retired_at_once() {
    let (mut t, now) = on_tip_a();
    let deadline = now + GRACE;
    t.start_grace(B, deadline);
    let late = deadline + GRACE;
    t.retain(2, job(A), (0, late));
    assert_eq!(
        t.get(2).unwrap().retire_at,
        Some(deadline),
        "not a new grace"
    );
    t.retire(late);
    assert!(!retains(&t, 2));
}

#[test]
fn going_back_to_a_tip_keeps_its_jobs_and_retires_the_other() {
    let (mut t, now) = on_tip_a();
    t.start_grace(B, now + GRACE);
    t.retain(2, job(B), (0, now));
    assert!(t.get(1).unwrap().retire_at.is_some());
    let back = now + GRACE / 2;
    t.start_grace(A, back + GRACE);
    assert_eq!(t.get(1).unwrap().retire_at, None, "A is the tip again");
    assert_eq!(t.get(2).unwrap().retire_at, Some(back + GRACE));
    t.retain(3, job(A), (0, back));
    t.retain(4, job(B), (0, back));
    assert_eq!(t.get(3).unwrap().retire_at, None);
    assert_eq!(
        t.get(4).unwrap().retire_at,
        Some(back + GRACE),
        "B left again at the later deadline"
    );
}

#[test]
fn a_tip_older_than_the_record_is_left_for_the_next_event_to_classify() {
    let now = Instant::now();
    let mut t = Templates::default();
    let tip = |n: usize| [n as u8; 32];
    for n in 0..=MAX_RETIRED_TIPS + 1 {
        t.start_grace(tip(n), now + GRACE);
    }
    t.retain(1, job(tip(0)), (0, now));
    assert_eq!(t.get(1).unwrap().retire_at, None, "forgotten tip");
    t.retain(2, job(tip(2)), (0, now));
    assert_eq!(t.get(2).unwrap().retire_at, Some(now + GRACE));
    let next = now + GRACE;
    t.start_grace(tip(MAX_RETIRED_TIPS + 2), next + GRACE);
    assert_eq!(t.get(1).unwrap().retire_at, Some(next + GRACE));
}
