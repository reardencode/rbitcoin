//! One in-flight template build per (prev, coinbase budget, update counter).
//! The second caller waits on the session task. The build closure is the
//! production `TemplateFlight` path.

use rbitcoin_sv2::template::{Template, TemplateFlight, TemplateKey};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn key(size: u32, updates: u64) -> TemplateKey {
    TemplateKey {
        prev_hash: [7u8; 32],
        max_additional_size: size,
        max_additional_sigops: 1,
        template_updates: updates,
    }
}

fn dummy() -> Template {
    Template {
        version: 2,
        coinbase_prefix: Vec::new(),
        value_remaining: 50,
        coinbase_outputs: Vec::new(),
        merkle_path: Vec::new(),
        prev_hash: [7u8; 32],
        header_timestamp: 1,
        n_bits: 1,
        target: [1u8; 32],
        txs: Vec::new(),
    }
}

fn runtime(blocking: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(blocking)
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn one_build_serves_the_same_key_and_a_different_budget_builds_again() {
    runtime(4).block_on(async {
        let flight = Arc::new(TemplateFlight::new());
        let builds = Arc::new(AtomicUsize::new(0));
        let same = key(10, 1);

        let n = Arc::clone(&builds);
        let first = flight
            .get_or_build(same, move || {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(Some(dummy()))
            })
            .await
            .expect("first");
        let n = Arc::clone(&builds);
        let second = flight
            .get_or_build(same, move || {
                n.fetch_add(1, Ordering::SeqCst);
                panic!("same key must not build twice");
            })
            .await
            .expect("second");
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(
            first.expect("cached").value_remaining,
            second.expect("reuse").value_remaining
        );

        let n = Arc::clone(&builds);
        flight
            .get_or_build(key(11, 1), move || {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(Some(dummy()))
            })
            .await
            .expect("other size");
        let n = Arc::clone(&builds);
        flight
            .get_or_build(key(10, 2), move || {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(Some(dummy()))
            })
            .await
            .expect("bumped updates");
        assert_eq!(builds.load(Ordering::SeqCst), 3);

        let n = Arc::clone(&builds);
        let missed = flight
            .get_or_build(key(10, 3), move || {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            })
            .await
            .expect("ibd");
        assert!(missed.is_none());
        let n = Arc::clone(&builds);
        flight
            .get_or_build(key(10, 3), move || {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            })
            .await
            .expect("ibd retry");
        assert_eq!(builds.load(Ordering::SeqCst), 5);

        let n = Arc::clone(&builds);
        let odd = TemplateKey {
            prev_hash: [9u8; 32],
            ..key(3, 9)
        };
        flight
            .get_or_build(odd, move || {
                n.fetch_add(1, Ordering::SeqCst);
                let mut built = dummy();
                built.prev_hash = [1u8; 32];
                Ok(Some(built))
            })
            .await
            .expect("mismatched tip");
        let n = Arc::clone(&builds);
        flight
            .get_or_build(odd, move || {
                n.fetch_add(1, Ordering::SeqCst);
                Ok(Some(dummy()))
            })
            .await
            .expect("mismatch is not reused");
        assert_eq!(builds.load(Ordering::SeqCst), 7);
    });
}

#[test]
fn dropped_caller_keeps_the_flight_until_the_build_finishes() {
    runtime(1).block_on(async {
        let flight = Arc::new(TemplateFlight::new());
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let builds = Arc::new(AtomicUsize::new(0));
        let started = Arc::clone(&builds);
        let building = Arc::clone(&flight);
        let first = tokio::spawn(async move {
            building
                .get_or_build(key(4, 8), move || {
                    started.fetch_add(1, Ordering::SeqCst);
                    let _ = gate.blocking_recv();
                    Ok(Some(dummy()))
                })
                .await
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while builds.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "build never started");
            tokio::task::yield_now().await;
        }
        first.abort();
        let _ = first.await;

        let waiting = Arc::clone(&flight);
        let second = tokio::spawn(async move {
            waiting
                .get_or_build(key(4, 8), || panic!("waiter must not build"))
                .await
                .expect("waiter")
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !second.is_finished(),
            "waiter finished while the dropped caller's build still held the flight"
        );
        release.send(()).expect("release");
        let reused = tokio::time::timeout(Duration::from_secs(2), second)
            .await
            .expect("waiter finishes after the build")
            .expect("join");
        assert!(reused.is_some());
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn same_key_waiter_does_not_take_a_pool_thread() {
    runtime(1).block_on(async {
        let flight = Arc::new(TemplateFlight::new());
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let builds = Arc::new(AtomicUsize::new(0));
        let started = Arc::clone(&builds);
        let building = Arc::clone(&flight);
        let first = tokio::spawn(async move {
            building
                .get_or_build(key(4, 0), move || {
                    started.fetch_add(1, Ordering::SeqCst);
                    let _ = gate.blocking_recv();
                    Ok(Some(dummy()))
                })
                .await
                .expect("builder")
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while builds.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "build never entered the pool"
            );
            tokio::task::yield_now().await;
        }

        let waiting = Arc::clone(&flight);
        let second = tokio::spawn(async move {
            waiting
                .get_or_build(key(4, 0), || panic!("waiter must not build"))
                .await
                .expect("waiter")
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !second.is_finished(),
            "waiter finished while the only pool thread was parked"
        );

        release.send(()).expect("release");
        let done = tokio::time::timeout(Duration::from_secs(2), async {
            let built = first.await.expect("join builder");
            let reused = second.await.expect("join waiter");
            (built, reused)
        })
        .await
        .expect("both finish after the pool thread is released");
        assert!(done.0.is_some() && done.1.is_some());
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    });
}

/// The build runs while every blocking-pool thread is parked. Connect holds
/// `template_prev` for the whole tip update, so the build cannot sit on that
/// pool waiting for the mutex.
#[test]
fn template_build_runs_while_the_blocking_pool_is_parked() {
    runtime(1).block_on(async {
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let parked = tokio::task::spawn_blocking(move || {
            let _ = gate.blocking_recv();
        });
        tokio::time::sleep(Duration::from_millis(80)).await;

        let flight = Arc::new(TemplateFlight::new());
        let built = tokio::time::timeout(
            Duration::from_secs(2),
            flight.get_or_build(key(1, 0), || {
                assert_eq!(
                    std::thread::current().name(),
                    Some("rbtc-off-pool"),
                    "template build must not use the blocking pool"
                );
                Ok(Some(dummy()))
            }),
        )
        .await
        .expect("build finished while the blocking pool was parked");
        assert!(built.expect("build").is_some());
        release.send(()).expect("release");
        parked.await.expect("parked");
    });
}
