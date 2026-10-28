//! IBD Class C barrier thread.
//!
//! The worker publishes its own tid. A process-wide comm scan also counts
//! other queries running in this suite.

#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Clears the flush hold on drop so a failed assert cannot leave the worker
/// parked while `Query`'s drop joins it.
struct ReleaseHold(Arc<AtomicBool>);

impl Drop for ReleaseHold {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Two barriers share one `rbtc-tip-flush` thread. Tip mode does not start it.
#[test]
fn two_ibd_flushes_share_one_named_thread() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("tip-flush-one");
    assert!(q.index_mode().unwrap().is_tip());
    let alive = q.tip_flush_alive();
    q.flush_tip(None).unwrap();
    assert_eq!(alive.load(Ordering::Acquire), 0, "tip mode flushes inline");

    q.enter_direct_index_mode_sh(false).unwrap();
    let hold = q.hold_tip_flushes();
    let _release = ReleaseHold(Arc::clone(&hold));
    q.spawn_tip_flush().unwrap();
    let tid = wait_tid(&q, Duration::from_millis(200));
    assert_eq!(
        task_comm(tid).as_deref(),
        Some("rbtc-tip-flush"),
        "IBD barrier thread name"
    );
    q.spawn_tip_flush().unwrap();
    let n = alive_max(&alive, Duration::from_millis(200));
    assert_eq!(n, 1, "two IBD barriers use one rbtc-tip-flush thread");
    assert_eq!(
        q.tip_flush_os_tid(),
        tid,
        "second barrier keeps the same thread"
    );
    hold.store(false, Ordering::SeqCst);
    q.join_tip_flush().unwrap();
    drop(_release);
    drop(q);
    drop(dir);
    assert_eq!(
        alive.load(Ordering::Acquire),
        0,
        "drop joins rbtc-tip-flush"
    );
    assert!(
        task_gone(tid, Duration::from_secs(2)),
        "rbtc-tip-flush tid {tid} still in /proc"
    );
}

fn wait_tid(q: &rbitcoin_query::Query, window: Duration) -> u64 {
    let deadline = Instant::now() + window;
    loop {
        let tid = q.tip_flush_os_tid();
        if tid != 0 {
            return tid;
        }
        assert!(
            Instant::now() < deadline,
            "rbtc-tip-flush did not publish a tid"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn alive_max(alive: &Arc<AtomicUsize>, window: Duration) -> usize {
    let deadline = Instant::now() + window;
    let mut n = 0;
    loop {
        n = n.max(alive.load(Ordering::Acquire));
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    n
}

fn task_comm(tid: u64) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")).ok()?;
    Some(raw.trim_end_matches('\n').to_string())
}

fn task_gone(tid: u64, window: Duration) -> bool {
    let deadline = Instant::now() + window;
    loop {
        if std::fs::metadata(format!("/proc/self/task/{tid}")).is_err() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
