use rbitcoin_net::tip_accept::*;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// The tip-accept lane and the park-gate atomics are process-wide. Cargo
/// runs this binary's tests in parallel, so one permit keeps them apart.
fn lane_gate() -> &'static (Mutex<bool>, Condvar) {
    static LANE: std::sync::OnceLock<(Mutex<bool>, Condvar)> = std::sync::OnceLock::new();
    LANE.get_or_init(|| (Mutex::new(false), Condvar::new()))
}

struct LanePermit;

impl LanePermit {
    fn take() -> Self {
        let (mu, cv) = lane_gate();
        let mut busy = mu.lock().unwrap_or_else(|p| p.into_inner());
        while *busy {
            busy = cv.wait(busy).unwrap_or_else(|p| p.into_inner());
        }
        *busy = true;
        Self
    }
}

impl Drop for LanePermit {
    fn drop(&mut self) {
        let (mu, cv) = lane_gate();
        *mu.lock().unwrap_or_else(|p| p.into_inner()) = false;
        cv.notify_one();
    }
}

/// A panic while the debug park gate is armed must not leave later senders
/// asleep in `wait_park_gate`.
struct ParkGate;

impl ParkGate {
    fn arm() -> Self {
        TIP_PARK_ENTERED.store(0, Ordering::SeqCst);
        TIP_PARK_GO.store(false, Ordering::SeqCst);
        TIP_PARK_DELAY.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for ParkGate {
    fn drop(&mut self) {
        TIP_PARK_GO.store(true, Ordering::SeqCst);
        TIP_PARK_DELAY.store(false, Ordering::SeqCst);
        tip_park_gate_notify();
    }
}

#[test]
fn lane_runs_on_named_thread() {
    let _lane = LanePermit::take();
    let name = run_on_tip_accept(|| thread::current().name().map(str::to_string));
    assert_eq!(name.as_deref(), Some(TIP_ACCEPT_THREAD_NAME));
}

#[test]
fn wait_idle_blocks_until_job_finishes() {
    use std::sync::mpsc;
    use std::time::Duration;

    let _lane = LanePermit::take();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        run_on_tip_accept(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
    });
    started_rx.recv().unwrap();
    let seen = subscribe_wait_seen();
    let waiter = thread::spawn(wait_idle);
    seen.recv_timeout(Duration::from_secs(2))
        .expect("wait_idle did not observe the running job");
    assert!(
        !waiter.is_finished(),
        "wait_idle must not return while a tip-accept job is running"
    );
    release_tx.send(()).unwrap();
    waiter.join().expect("wait_idle");
    worker.join().expect("job");
    wait_idle();
}

#[test]
fn wait_current_job_returns_while_second_job_queued() {
    use std::sync::mpsc;
    use std::time::Duration;

    let _lane = LanePermit::take();
    let (started1_tx, started1_rx) = mpsc::sync_channel(1);
    let (release1_tx, release1_rx) = mpsc::sync_channel(1);
    let (started2_tx, started2_rx) = mpsc::sync_channel(1);
    let (release2_tx, release2_rx) = mpsc::sync_channel(1);
    let first = thread::spawn(move || {
        run_on_tip_accept(move || {
            started1_tx.send(()).unwrap();
            release1_rx.recv().unwrap();
        });
    });
    started1_rx.recv().unwrap();
    let second = thread::spawn(move || {
        run_on_tip_accept(move || {
            started2_tx.send(()).unwrap();
            release2_rx.recv().unwrap();
        });
    });
    let seen = subscribe_wait_seen();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let waiter = thread::spawn(move || {
        wait_current_job();
        done_tx.send(()).ok();
    });
    seen.recv_timeout(Duration::from_secs(2))
        .expect("wait_current_job did not observe the running job");
    assert_eq!(
        done_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "wait_current_job must not return while the snapshotted job is running"
    );
    release1_tx.send(()).unwrap();
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("wait_current_job must return when job 1 ends");
    waiter.join().expect("wait_current_job thread");
    assert!(
        started2_rx.try_recv().is_err() || !second.is_finished(),
        "second job must still be queued or running after wait_current_job returns"
    );
    release2_tx.send(()).unwrap();
    first.join().expect("job1");
    second.join().expect("job2");
}

/// `ChainHub::set_rpc_wait_tip_idle` is off until the node turns it on. On an
/// idle lane the RPC tip wait returns in either mode.
#[test]
fn rpc_wait_tip_idle_is_off_until_set() {
    let _lane = LanePermit::take();
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("wait-tip-idle");
    assert!(!hub.rpc_wait_tip_idle());
    hub.wait_tip_stable_for_rpc();
    hub.set_rpc_wait_tip_idle(true);
    assert!(hub.rpc_wait_tip_idle());
    hub.wait_tip_stable_for_rpc();
}

#[tokio::test]
async fn lane_sync_from_current_thread_runtime() {
    let _lane = LanePermit::take();
    assert_eq!(run_on_tip_accept(|| 7), 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lane_async_is_not_tokio_worker() {
    let _lane = LanePermit::take();
    let task = tokio::spawn(async {
        let caller = thread::current().name().map(str::to_string);
        let name = run_on_tip_accept_async(|| thread::current().name().map(str::to_string)).await;
        (caller, name)
    });
    let (caller, name) = task.await.expect("join worker task");
    assert!(
        caller
            .as_deref()
            .is_some_and(|n| n.starts_with("tokio-rt-worker")),
        "spawned task must run on a tokio worker, got {caller:?}"
    );
    assert_eq!(name.as_deref(), Some(TIP_ACCEPT_THREAD_NAME));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn drop_join_does_not_park_worker() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    let _lane = LanePermit::take();
    let started = Arc::new(AtomicBool::new(false));
    let release = Arc::new((std::sync::Mutex::new(false), Condvar::new()));
    // A failed assert must still wake the job. The tip-accept thread is
    // process-wide, and leaving it parked hangs every later test.
    let _wake = ReleaseOnDrop(Arc::clone(&release));
    let s2 = Arc::clone(&started);
    let r2 = Arc::clone(&release);
    let waiter = tokio::spawn(async move {
        run_on_tip_accept_async(move || {
            s2.store(true, Ordering::Release);
            let (lock, cv) = &*r2;
            let mut g = lock.lock().unwrap();
            while !*g {
                g = cv.wait(g).unwrap();
            }
            1u8
        })
        .await
    });
    // The lane is shared by every test in this binary. A journey that
    // mines 100+ blocks is one job and can hold it for seconds under load.
    let t0 = Instant::now();
    while !started.load(Ordering::Acquire) {
        assert!(t0.elapsed() < Duration::from_secs(60), "job never started");
        tokio::task::yield_now().await;
    }
    waiter.abort();
    let progressed = tokio::time::timeout(Duration::from_millis(200), async {
        tokio::task::yield_now().await;
        1u8
    })
    .await;
    assert_eq!(
        progressed,
        Ok(1),
        "JoinOnDrop must not park the tokio worker"
    );
    drop(_wake);
}

struct ReleaseFillers(Vec<std::sync::mpsc::SyncSender<()>>);

impl Drop for ReleaseFillers {
    fn drop(&mut self) {
        for tx in self.0.drain(..) {
            tx.send(()).ok();
        }
    }
}

/// `Full` stops the filler. A blocking `send` waits for a slot while the
/// holder is the tip-accept thread, so that slot never frees.
fn enqueue_or_full(job: Job) -> bool {
    match sender().try_send(job) {
        Ok(()) => true,
        Err(std::sync::mpsc::TrySendError::Full(_)) => false,
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => panic!("tip-accept thread"),
    }
}

struct ReleaseOnDrop(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        let (lock, cv) = &*self.0;
        *lock.lock().unwrap() = true;
        cv.notify_one();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_lane_parks_instead_of_spinning() {
    use std::sync::mpsc;
    use std::time::Duration;

    let _lane = LanePermit::take();
    let (holder_tx, holder_rx) = mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let _wake = ReleaseOnDrop(Arc::clone(&release));
    let rel = Arc::clone(&release);
    let holder = thread::spawn(move || {
        run_on_tip_accept(move || {
            holder_tx.send(()).ok();
            let (lock, cv) = &*rel;
            let mut g = lock.lock().unwrap();
            while !*g {
                g = cv.wait(g).unwrap();
            }
        });
    });
    holder_rx.recv().expect("holder running");

    let filler = thread::spawn(move || {
        let mut queued = Vec::with_capacity(QUEUE_CAP);
        for _ in 0..QUEUE_CAP {
            let (tx, rx) = mpsc::sync_channel::<()>(1);
            if !enqueue_or_full(Box::new(move || {
                let _ = rx.recv();
            })) {
                break;
            }
            queued.push(tx);
        }
        queued
    });
    let releases = filler.join().expect("filler queued");

    FULL_QUEUE_SPINS.store(0, Ordering::Relaxed);
    let parked_note = send_parked_notify().notified();
    tokio::pin!(parked_note);
    let ninth = tokio::spawn(async { run_on_tip_accept_async(|| 9u8).await });
    tokio::time::timeout(Duration::from_secs(2), parked_note)
        .await
        .expect("ninth sender did not park on a full queue");
    let parked = FULL_QUEUE_SPINS.load(Ordering::Relaxed);
    assert!(
        (1..=8).contains(&parked),
        "a full queue parks after a handful of failed sends, saw {parked}"
    );
    let spins = FULL_QUEUE_SPINS.load(Ordering::Relaxed);
    assert_eq!(
        spins, parked,
        "a parked sender must not keep retrying ({parked} -> {spins})"
    );
    assert!(!ninth.is_finished(), "the ninth job must still be waiting");

    {
        let (lock, cv) = &*release;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    for tx in releases {
        tx.send(()).ok();
    }
    let got = tokio::time::timeout(Duration::from_secs(2), ninth)
        .await
        .expect("ninth job parked forever")
        .expect("ninth");
    assert_eq!(got, 9);
    holder.join().expect("holder");
    wait_idle();
}

/// Two senders that both saw a full queue must both enqueue once two slots
/// are free, even while the lane is still inside a job. `notify_one` before
/// either waiter registers keeps only one permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_full_senders_both_enqueue() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let _lane = LanePermit::take();
    wait_idle();
    let (holder_tx, holder_rx) = mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let _wake = ReleaseOnDrop(Arc::clone(&release));
    let rel = Arc::clone(&release);
    let holder = thread::spawn(move || {
        run_on_tip_accept(move || {
            holder_tx.send(()).ok();
            let (lock, cv) = &*rel;
            let mut g = lock.lock().unwrap();
            while !*g {
                g = cv.wait(g).unwrap();
            }
        });
    });
    holder_rx.recv().expect("holder running");

    let filler = thread::spawn(move || {
        let mut started = Vec::with_capacity(QUEUE_CAP);
        let mut releases = Vec::with_capacity(QUEUE_CAP);
        for _ in 0..QUEUE_CAP {
            let (go_tx, go_rx) = mpsc::sync_channel::<()>(1);
            let (ran_tx, ran_rx) = mpsc::sync_channel::<()>(1);
            if !enqueue_or_full(Box::new(move || {
                ran_tx.send(()).ok();
                let _ = go_rx.recv();
            })) {
                break;
            }
            started.push(ran_rx);
            releases.push(go_tx);
        }
        (started, releases)
    });
    let (started, release_txs) = filler.join().expect("filler queued");
    let mut releases = ReleaseFillers(release_txs);
    assert!(
        started.len() >= 2,
        "need two of this test's jobs queued to free two slots, queued {}",
        started.len()
    );

    let _park = ParkGate::arm();
    let first = tokio::spawn(async { run_on_tip_accept_async(|| 1u8).await });
    let second = tokio::spawn(async { run_on_tip_accept_async(|| 2u8).await });
    let t0 = Instant::now();
    while TIP_PARK_ENTERED.load(Ordering::SeqCst) < 2 {
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "both senders must see a full queue"
        );
        tokio::task::yield_now().await;
    }

    {
        let (lock, cv) = &*release;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    releases.0[0].send(()).ok();
    started[0].recv().expect("first queued job started");
    started[1].recv().expect("second queued job started");

    TIP_ASYNC_ENQUEUED.store(0, Ordering::SeqCst);
    TIP_PARK_GO.store(true, Ordering::SeqCst);
    TIP_PARK_DELAY.store(false, Ordering::SeqCst);
    tip_park_gate_notify();
    let t1 = Instant::now();
    while TIP_ASYNC_ENQUEUED.load(Ordering::SeqCst) < 2 {
        assert!(
            t1.elapsed() < Duration::from_millis(500),
            "one coalesced wake left a free tip-accept slot with a sender still parked"
        );
        tokio::task::yield_now().await;
    }

    for tx in releases.0.drain(..).skip(1) {
        tx.send(()).ok();
    }
    let (a, b) = tokio::time::timeout(Duration::from_secs(2), async {
        let a = first.await.expect("first");
        let b = second.await.expect("second");
        (a, b)
    })
    .await
    .expect("jobs finish");
    holder.join().expect("holder");
    wait_idle();
    assert_eq!((a, b), (1, 2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owned_job_finishes_after_waiter_abort() {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let _lane = LanePermit::take();
    let saw = Arc::new(AtomicU8::new(0));
    let saw_job = Arc::clone(&saw);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let waiter = tokio::spawn(async move {
        run_on_tip_accept_async(move || {
            saw_job.fetch_add(1, Ordering::SeqCst);
            started_tx.send(()).unwrap();
            let _ = release_rx.recv();
            saw_job.fetch_add(1, Ordering::SeqCst);
        })
        .await;
    });
    started_rx.recv().expect("job started");
    waiter.abort();
    release_tx.send(()).unwrap();
    let t0 = Instant::now();
    while saw.load(Ordering::SeqCst) < 2 {
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "aborted waiter left the tip-accept job unfinished"
        );
        tokio::task::yield_now().await;
    }
    wait_idle();
}
