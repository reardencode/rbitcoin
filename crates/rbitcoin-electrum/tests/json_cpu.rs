//! JSON under 4 KiB encodes on the caller. At 4 KiB it waits for `rbtc-scripts-*`.

use rbitcoin_electrum::{encode_json_body, json_is_cpu_heavy, JSON_CPU_MIN};
use serde_json::{json, Value};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

struct ScriptHold {
    gate: Arc<(Mutex<bool>, Condvar)>,
}

impl ScriptHold {
    fn all() -> Self {
        let n = rbitcoin_consensus::script_pool::worker_spawn_count();
        assert!(n >= 1, "script pool did not start");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let entered = Arc::new(AtomicUsize::new(0));
        let parked = Arc::new((Mutex::new(()), Condvar::new()));
        for _ in 0..n {
            let entered = Arc::clone(&entered);
            let gate = Arc::clone(&gate);
            let parked = Arc::clone(&parked);
            rbitcoin_consensus::script_pool::spawn_detached(move || {
                {
                    let _g = parked.0.lock().unwrap_or_else(|p| p.into_inner());
                    entered.fetch_add(1, Ordering::SeqCst);
                    parked.1.notify_all();
                }
                let (lock, cv) = &*gate;
                let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
                while !*g {
                    g = cv.wait(g).unwrap_or_else(|p| p.into_inner());
                }
            });
        }
        let start = Instant::now();
        let (lock, cv) = &*parked;
        let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
        while entered.load(Ordering::SeqCst) < n {
            let left = Duration::from_secs(2).saturating_sub(start.elapsed());
            assert!(!left.is_zero(), "script workers did not park");
            let (next, _timeout) = cv.wait_timeout(g, left).unwrap_or_else(|p| p.into_inner());
            g = next;
        }
        Self { gate }
    }
}

impl Drop for ScriptHold {
    fn drop(&mut self) {
        let (lock, cv) = &*self.gate;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
    }
}

fn poll_until(v: &Value, limit: Duration) -> Vec<u8> {
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;
    struct Unpark(thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(encode_json_body(Arc::new(v.clone())));
    let start = Instant::now();
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(bytes) => return bytes.expect("json encode"),
            Poll::Pending => {
                assert!(
                    start.elapsed() < limit,
                    "json encode waited on rbtc-scripts under 4 KiB"
                );
                thread::park_timeout(Duration::from_millis(10));
            }
        }
    }
}

fn string_body(chars: usize) -> Value {
    Value::String("a".repeat(chars))
}

/// A body just under 4 KiB encodes on the caller. At 4 KiB the encode stays
/// pending until a script worker is free, and the bytes match `serde_json`.
#[test]
fn encode_json_body_hops_only_at_4kib() {
    let light = string_body(JSON_CPU_MIN - 3);
    let heavy = string_body(JSON_CPU_MIN - 2);
    assert!(!json_is_cpu_heavy(&light));
    assert!(json_is_cpu_heavy(&heavy));
    assert!(!json_is_cpu_heavy(&json!({})));

    let hold = ScriptHold::all();
    let got = poll_until(&light, Duration::from_millis(200));
    assert_eq!(got, serde_json::to_vec(&light).unwrap());
    assert!(got.len() < JSON_CPU_MIN);

    let waker = {
        use std::task::{Wake, Waker};
        struct Unpark(std::thread::Thread);
        impl Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        Waker::from(Arc::new(Unpark(std::thread::current())))
    };
    let mut cx = std::task::Context::from_waker(&waker);
    let mut pending = Box::pin(encode_json_body(Arc::new(heavy.clone())));
    assert!(
        matches!(pending.as_mut().poll(&mut cx), std::task::Poll::Pending),
        "4 KiB json encode ran while rbtc-scripts workers were held"
    );
    drop(hold);
    let start = Instant::now();
    let got = loop {
        match pending.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(bytes) => break bytes.expect("json encode"),
            std::task::Poll::Pending => {
                assert!(start.elapsed() < Duration::from_secs(2));
                std::thread::park_timeout(Duration::from_millis(10));
            }
        }
    };
    assert_eq!(got, serde_json::to_vec(&heavy).unwrap());
    assert!(got.len() >= JSON_CPU_MIN);
}
