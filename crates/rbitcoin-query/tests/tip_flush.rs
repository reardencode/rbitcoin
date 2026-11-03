//! IBD Class C barrier thread.
//!
//! The OS name is read from `/proc`, so this file is Linux-only. The count is
//! this query's thread: other tests in the process also name `rbtc-tip-flush`.

#![cfg(target_os = "linux")]

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// Two barriers share one `rbtc-tip-flush` thread. Tip mode does not start it.
#[test]
fn two_ibd_flushes_share_one_named_thread() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("tip-flush-one");
    assert!(q.index_mode().unwrap().is_tip());
    q.flush_tip(None).unwrap();
    assert_eq!(q.tip_flush_alive(), 0, "tip mode flushes inline");

    q.enter_direct_index_mode_sh(false).unwrap();
    let hold = q.hold_tip_flushes();
    let _release = ReleaseHold(&hold);
    q.spawn_tip_flush().unwrap();
    q.spawn_tip_flush().unwrap();
    let published = q.wait_tip_flush_published(Duration::from_millis(200));
    assert_eq!(
        q.tip_flush_alive(),
        1,
        "two IBD barriers use one rbtc-tip-flush thread"
    );
    let tid = published.expect("rbtc-tip-flush published its tid");
    assert_eq!(
        q.tip_flush_os_tid(),
        tid,
        "the second barrier starts another thread"
    );
    assert_eq!(
        task_comm(tid).as_deref(),
        Some("rbtc-tip-flush"),
        "IBD barrier thread name"
    );
    hold.store(false, Ordering::SeqCst);
    q.join_tip_flush().unwrap();
    assert_eq!(
        q.tip_flush_alive(),
        1,
        "the barrier thread outlives one flush"
    );
    assert_eq!(q.tip_flush_os_tid(), tid);
    drop(q);
    drop(dir);
    // Linux can retain a /proc task entry briefly after a successful join.
    let deadline = Instant::now() + Duration::from_secs(2);
    while task_comm(tid).is_some() {
        assert!(Instant::now() < deadline, "drop joins rbtc-tip-flush");
        std::thread::sleep(Duration::from_millis(1));
    }
}

struct ReleaseHold<'a>(&'a rbitcoin_store::TipFlushHold);

impl Drop for ReleaseHold<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn task_comm(tid: u64) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")).ok()?;
    Some(raw.trim_end_matches('\n').to_string())
}
