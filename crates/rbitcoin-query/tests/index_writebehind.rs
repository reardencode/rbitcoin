use rbitcoin_log::progress;
use rbitcoin_primitives::Fk;
use rbitcoin_primitives::Height;
use rbitcoin_query::index_writebehind::*;
use rbitcoin_query::Query;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Info lines from one `io_loop`. A loop that waits out `budget` is the
/// height equal to the target being skipped.
fn io_loop_lines(
    query: &Query,
    stop: &AtomicBool,
    resync: &AtomicBool,
    stages: &IndexStageMs,
    tx: &std::sync::mpsc::SyncSender<ReadyWindow>,
    budget: Duration,
    on_caught: impl FnOnce() + Send,
) -> Vec<String> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let logs = std::thread::scope(|scope| {
        scope.spawn(move || {
            rbitcoin_log::capture_logs(false);
            rbitcoin_log::capture_logs(true);
            let result = io_loop(
                query,
                stop,
                resync,
                stages,
                tx,
                PROGRESS_EVERY,
                || {},
                on_caught,
            );
            let logs = rbitcoin_log::take_logs();
            rbitcoin_log::capture_logs(false);
            let _ = done_tx.send((result, logs));
        });
        match done_rx.recv_timeout(budget) {
            Ok((result, logs)) => {
                result.expect("io_loop");
                stop.store(true, Ordering::Relaxed);
                logs
            }
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                panic!("io_loop waited instead of sealing the height that equals the target");
            }
        }
    });
    logs.into_iter().map(|(_, line)| line).collect()
}

/// Seal from the current watermarks through the released tip.
/// `hold_first` parks the first offer. This function opens that gate
/// after `progress_every` has elapsed, so a later window in the pass logs.
fn drive_index_pass(query: &Query, hold_first: bool, progress_every: Duration) -> Vec<String> {
    let stop = AtomicBool::new(false);
    let resync = AtomicBool::new(false);
    let stages = IndexStageMs::default();
    let (tx, rx) = sync_channel(0);
    let (worker_tx, worker_rx) = sync_channel(2);
    let parked = Arc::new((Mutex::new(false), Condvar::new()));
    let open = Arc::new((Mutex::new(!hold_first), Condvar::new()));
    let first = AtomicBool::new(false);
    let budget = Duration::from_secs(120);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let stop = &stop;
    let resync = &resync;
    let stages = &stages;
    let logs = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            rbitcoin_log::capture_logs(false);
            rbitcoin_log::capture_logs(true);
            cpu_worker(query, worker_rx, resync, stages).unwrap();
            let logs = rbitcoin_log::take_logs();
            rbitcoin_log::capture_logs(false);
            logs
        });
        scope.spawn(move || {
            while let Ok(window) = rx.recv() {
                if worker_tx.send(window).is_err() {
                    break;
                }
            }
        });
        let parked_io = Arc::clone(&parked);
        let open_io = Arc::clone(&open);
        scope.spawn(move || {
            rbitcoin_log::capture_logs(false);
            rbitcoin_log::capture_logs(true);
            let result = io_loop(
                query,
                stop,
                resync,
                stages,
                &tx,
                progress_every,
                || {
                    if !hold_first || first.swap(true, Ordering::SeqCst) {
                        return;
                    }
                    {
                        let (lock, cv) = &*parked_io;
                        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
                        cv.notify_all();
                    }
                    let (lock, cv) = &*open_io;
                    let mut gate = lock.lock().unwrap_or_else(|e| e.into_inner());
                    while !*gate {
                        gate = cv.wait(gate).unwrap_or_else(|e| e.into_inner());
                    }
                },
                || stop.store(true, Ordering::Relaxed),
            );
            drop(tx);
            let logs = rbitcoin_log::take_logs();
            rbitcoin_log::capture_logs(false);
            let _ = done_tx.send((result, logs));
        });
        if hold_first {
            let (lock, cv) = &*parked;
            let mut seen = lock.lock().unwrap_or_else(|e| e.into_inner());
            let deadline = Instant::now() + Duration::from_secs(2);
            while !*seen {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    stop.store(true, Ordering::Relaxed);
                    panic!("first window was not queued");
                }
                let (guard, status) = cv
                    .wait_timeout(seen, left)
                    .unwrap_or_else(|e| e.into_inner());
                seen = guard;
                if status.timed_out() && !*seen {
                    stop.store(true, Ordering::Relaxed);
                    panic!("first window was not queued");
                }
            }
            drop(seen);
            let started = Instant::now();
            let (lock, cv) = &*open;
            let mut gate = lock.lock().unwrap_or_else(|e| e.into_inner());
            while started.elapsed() < progress_every {
                let left = progress_every - started.elapsed();
                let (guard, _) = cv
                    .wait_timeout(gate, left)
                    .unwrap_or_else(|e| e.into_inner());
                gate = guard;
            }
            *gate = true;
            cv.notify_all();
        }
        let (result, mut logs) = match done_rx.recv_timeout(budget) {
            Ok(done) => done,
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                panic!("io_loop waited instead of sealing the height that equals the target");
            }
        };
        result.expect("io_loop");
        stop.store(true, Ordering::Relaxed);
        logs.extend(worker.join().unwrap());
        logs
    });
    logs.into_iter().map(|(_, line)| line).collect()
}

fn connect_coinbases(
    q: &Query,
    from: u32,
    to: u32,
    prev_fk: &mut Fk,
    prev_hash: &mut Option<[u8; 32]>,
) {
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_store::{InputRecord, OutputRecord};

    for height in from..=to {
        let header = header_rec(height, *prev_fk, *prev_hash);
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&height.to_le_bytes());
        txid[31] = 0xcb;
        *prev_fk = q
            .connect_block(
                Height(height),
                &header,
                &[tx_apply(
                    txid,
                    vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
                    vec![OutputRecord::unspent(1, vec![0x51])],
                )],
            )
            .unwrap();
        *prev_hash = Some(header.hash);
    }
}

#[test]
fn index_build_progress_names_stage_ms() {
    let line = format_index_build_progress(&IndexBuildProgress {
        next: 800_000,
        tip: 900_000,
        from: 700_000,
        elapsed: Duration::from_secs(100),
        stages: IndexStageSample {
            read_ms: 4_000,
            build_ms: 5_500,
            commit_ms: 12,
        },
    });
    assert!(line.contains("next=800000"), "{line}");
    assert!(line.contains("tip=900000"), "{line}");
    assert!(line.contains("rate=1000/s"), "{line}");
    assert!(line.contains("remain=100001"), "{line}");
    assert!(line.contains("elapsed=100s"), "{line}");
    assert!(line.contains("read=4000ms"), "{line}");
    assert!(line.contains("build=5500ms"), "{line}");
    assert!(line.contains("commit=12ms"), "{line}");
}

#[test]
fn index_apply_names_stage_ms() {
    let line = format_index_apply(
        5,
        5,
        IndexStageSample {
            read_ms: 20,
            build_ms: 30,
            commit_ms: 4,
        },
    );
    assert_eq!(line, "index: apply h=5..=5 read=20ms build=30ms commit=4ms");
}

#[test]
fn stage_sample_take_resets() {
    let s = IndexStageMs::default();
    s.add_read(2_500_000);
    s.add_build(1_500_000);
    s.add_commit(500_000);
    let a = s.take_ms();
    assert_eq!((a.read_ms, a.build_ms, a.commit_ms), (2, 1, 0));
    let b = s.take_ms();
    assert_eq!((b.read_ms, b.build_ms, b.commit_ms), (0, 0, 0));
}

/// Three heights: coinbase (ineligible), a same-window spend into P2TR,
/// and a later coinbase that is also ineligible. Pooled assemble matches
/// the serial window walk.
#[test]
fn per_height_jobs_match_serial_window() {
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_store::{InputRecord, OutputRecord};

    let _gate = rbitcoin_consensus::script_pool::steal_test_gate();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("idx-jobs");
    q.set_block_filter_index(true).unwrap();
    q.set_sptweaks_enabled(true, Height(0)).unwrap();

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let ser = pk.serialize();
    let h160 = hash160::Hash::hash(&ser);
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(h160.as_ref());
    let (xonly, _) = pk.x_only_public_key();
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&xonly.serialize());

    let mut genesis_txid = [0u8; 32];
    genesis_txid[31] = 0xcb;
    let h0 = header_rec(0, Fk::NULL, None);
    let fk0 = q
        .connect_block(
            Height(0),
            &h0,
            &[tx_apply(
                genesis_txid,
                vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                vec![OutputRecord::unspent(50_0000_0000, p2wpkh.clone())],
            )],
        )
        .unwrap();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];

    let mut spend_txid = [0u8; 32];
    spend_txid[0] = 0x11;
    spend_txid[31] = 0xcd;
    let h1 = header_rec(1, fk0, Some(h0.hash));
    let fk1 = q
        .connect_block(
            Height(1),
            &h1,
            &[tx_apply(
                spend_txid,
                vec![InputRecord {
                    prev_txid: genesis_txid,
                    parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![vec![0u8; 64], ser.to_vec()],
                }],
                vec![OutputRecord::unspent(49_0000_0000, p2tr)],
            )],
        )
        .unwrap();

    let mut later_txid = [0u8; 32];
    later_txid[31] = 0xee;
    let h2 = header_rec(2, fk1, Some(h1.hash));
    q.connect_block(
        Height(2),
        &h2,
        &[tx_apply(
            later_txid,
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            vec![OutputRecord::unspent(50_0000_0000, p2wpkh)],
        )],
    )
    .unwrap();

    let window = Arc::new(read_window(&q, 0, 2).unwrap());
    assert_eq!(window.blocks.len(), 3);
    let got = assemble_window(&q, &window).unwrap();
    assert_eq!(got.filters.len(), 3);
    assert_eq!(got.tweaks.len(), 3);
    for (i, block) in window.blocks.iter().enumerate() {
        let serial_f = q.basic_filter_from_window(&window, i).unwrap();
        assert_eq!(got.filters[i].1.content, serial_f.content, "filter {i}");
        assert_eq!(got.filters[i].2, block.header_fk);
        let serial_t = rbitcoin_query::sp_read::tweak_records_from_window(&window, i).unwrap();
        assert_eq!(got.tweaks[i].2, serial_t, "tweaks {i}");
    }
    assert!(got.tweaks[0].2.iter().all(|t| t.is_none()), "coinbase");
    assert!(
        got.tweaks[1].2.iter().any(|t| t.is_some()),
        "same-window P2TR spend"
    );
    assert!(
        got.tweaks[2].2.iter().all(|t| t.is_none()),
        "no P2TR output"
    );

    let resync = AtomicBool::new(true);
    let stages = IndexStageMs::default();
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(ReadyWindow {
        window: read_window(&q, 0, 2).unwrap(),
        start: 0,
        end: 2,
        read_ns: 0,
        log_apply: false,
    })
    .unwrap();
    drop(tx);
    cpu_worker(&q, rx, &resync, &stages).unwrap();
    assert_eq!(
        q.filter_index_next(),
        Some(0),
        "resync drops queued filters"
    );
    assert_eq!(q.tweak_index_next(), Some(0), "resync drops queued tweaks");

    let stale = Arc::new(read_window(&q, 0, 2).unwrap());
    q.disconnect_tip().unwrap();
    assert!(
        !commit_window(&q, &stale, &stages).unwrap().ok,
        "a window whose confirmed tip moved must request resync"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

#[test]
fn released_builder_crosses_a_full_window_and_success_does_not_resync() {
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_store::{InputRecord, OutputRecord};

    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("idx-full-window");
    q.set_block_filter_index(true).unwrap();
    q.set_sptweaks_enabled(true, Height(0)).unwrap();

    let mut prev_fk = Fk::NULL;
    let mut prev_hash = None;
    for height in 0..=WINDOW_HEIGHTS {
        let header = header_rec(height, prev_fk, prev_hash);
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&height.to_le_bytes());
        txid[31] = 0xcb;
        prev_fk = q
            .connect_block(
                Height(height),
                &header,
                &[tx_apply(
                    txid,
                    vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
                    vec![OutputRecord::unspent(1, vec![0x51])],
                )],
            )
            .unwrap();
        prev_hash = Some(header.hash);
    }
    q.release_index_writebehind(Height(WINDOW_HEIGHTS));

    build_indexes_released(&q).unwrap();
    assert_eq!(q.filter_index_next(), Some(WINDOW_HEIGHTS + 1));
    assert_eq!(q.tweak_index_next(), Some(WINDOW_HEIGHTS + 1));

    let resync = AtomicBool::new(false);
    let stages = IndexStageMs::default();
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(ReadyWindow {
        window: read_window(&q, WINDOW_HEIGHTS, WINDOW_HEIGHTS).unwrap(),
        start: WINDOW_HEIGHTS,
        end: WINDOW_HEIGHTS,
        read_ns: 0,
        log_apply: false,
    })
    .unwrap();
    drop(tx);
    cpu_worker(&q, rx, &resync, &stages).unwrap();
    assert!(
        !resync.load(Ordering::Acquire),
        "a successful commit stays synced"
    );

    let resume = q.filter_index_next().unwrap();
    let pass_tip = resume + WINDOW_HEIGHTS;
    connect_coinbases(&q, resume, pass_tip, &mut prev_fk, &mut prev_hash);
    q.release_index_writebehind(Height(pass_tip));
    assert_eq!(PROGRESS_EVERY.as_secs(), 10);
    let progress_every = Duration::from_secs(1);
    let lines = drive_index_pass(&q, true, progress_every);
    let heights = pass_tip + 1 - resume;
    assert!(
        lines
            .iter()
            .any(|line| line.contains(&format!("heights={heights} elapsed"))),
        "{lines:?}"
    );
    let progress: Vec<_> = lines
        .iter()
        .filter(|line| line.contains("index: build next="))
        .collect();
    assert_eq!(progress.len(), 1, "{lines:?}");
    assert!(
        progress[0].contains(&format!("next={pass_tip} tip=")),
        "{lines:?}"
    );
    assert_eq!(q.filter_index_next(), Some(pass_tip + 1));
    assert_eq!(q.tweak_index_next(), Some(pass_tip + 1));

    let short_from = q.filter_index_next().unwrap();
    let short_tip = short_from + 10;
    connect_coinbases(&q, short_from, short_tip, &mut prev_fk, &mut prev_hash);
    q.release_index_writebehind(Height(short_tip));
    let lines = drive_index_pass(&q, false, PROGRESS_EVERY);
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("index: build from=")),
        "{lines:?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("index: apply h="))
            .count(),
        1,
        "{lines:?}"
    );
    assert_eq!(q.filter_index_next(), Some(short_tip + 1));
    assert_eq!(q.tweak_index_next(), Some(short_tip + 1));

    let _ = std::fs::remove_dir_all(dir.path());
}

#[test]
fn filter_catchup_callback_fires_only_after_the_released_tip() {
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_store::{InputRecord, OutputRecord};

    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("idx-filter-catchup");
    q.set_block_filter_index(true).unwrap();
    let mut prev_fk = Fk::NULL;
    let mut prev_hash = None;
    for height in 0..=1 {
        let header = header_rec(height, prev_fk, prev_hash);
        let mut txid = [0u8; 32];
        txid[0] = height as u8 + 1;
        txid[31] = 0xcb;
        prev_fk = q
            .connect_block(
                Height(height),
                &header,
                &[tx_apply(
                    txid,
                    vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
                    vec![OutputRecord::unspent(1, vec![0x51])],
                )],
            )
            .unwrap();
        prev_hash = Some(header.hash);
    }

    let first = Arc::new(read_window(&q, 0, 0).unwrap());
    let filter = q.basic_filter_from_window(&first, 0).unwrap();
    q.commit_window_filters(0, &[(filter, first.blocks[0].header_fk)])
        .unwrap();
    assert_eq!(q.filter_index_next(), Some(1));

    let called = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let resync = AtomicBool::new(false);
    let stages = IndexStageMs::default();
    let (tx, rx) = sync_channel(1);
    drop(rx);
    let lines = io_loop_lines(
        &q,
        &stop,
        &resync,
        &stages,
        &tx,
        Duration::from_secs(8),
        || {
            called.fetch_add(1, Ordering::Relaxed);
        },
    );
    assert_eq!(called.load(Ordering::Relaxed), 0, "next equals the tip");
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("index: build from=")),
        "{lines:?}"
    );

    let last = Arc::new(read_window(&q, 1, 1).unwrap());
    let filter = q.basic_filter_from_window(&last, 0).unwrap();
    q.commit_window_filters(1, &[(filter, last.blocks[0].header_fk)])
        .unwrap();
    let stop = AtomicBool::new(false);
    let lines = io_loop_lines(
        &q,
        &stop,
        &resync,
        &stages,
        &tx,
        Duration::from_secs(8),
        || {
            called.fetch_add(1, Ordering::Relaxed);
            stop.store(true, Ordering::Relaxed);
        },
    );
    assert_eq!(called.load(Ordering::Relaxed), 1, "next is past the tip");
    assert!(
        lines
            .iter()
            .any(|line| line.contains("blockfilter: caught up through=1;")),
        "{lines:?}"
    );

    let _ = std::fs::remove_dir_all(dir.path());
}

/// Heights `0..=through`, one coinbase each.
fn coinbase_chain(q: &Query, through: u32) {
    let (mut prev_fk, mut prev_hash) = (Fk::NULL, None);
    connect_coinbases(q, 0, through, &mut prev_fk, &mut prev_hash);
}

/// `(stage, base, done, total)` of the index stages that ended on this
/// thread since [`progress::capture_finished`].
fn finished_index_stages() -> Vec<(&'static str, u64, u64, u64)> {
    progress::take_finished()
        .into_iter()
        .filter(|s| s.stage == "blockfilter build" || s.stage == "sp_tweaks build")
        .map(|s| (s.stage, s.base, s.done, s.total))
        .collect()
}

#[test]
fn index_stage_begins_a_window_behind_and_ends_past_the_target() {
    progress::capture_finished(true);
    let mut slot = None;
    track_index(
        &mut slot,
        "blockfilter build",
        Some(0),
        0,
        Some(WINDOW_HEIGHTS - 1),
    );
    assert!(slot.is_none(), "less than a window behind");
    track_index(
        &mut slot,
        "blockfilter build",
        Some(0),
        0,
        Some(WINDOW_HEIGHTS),
    );
    assert!(slot.is_some(), "a full window behind");
    track_index(&mut slot, "blockfilter build", Some(40), 0, Some(100));
    track_index(&mut slot, "blockfilter build", Some(90), 0, Some(100));
    assert!(slot.is_some(), "short of the target");
    track_index(&mut slot, "blockfilter build", Some(102), 0, Some(101));
    assert!(slot.is_none(), "past a target that moved");
    assert_eq!(
        finished_index_stages(),
        [("blockfilter build", 0, 102, 102)]
    );

    track_index(&mut slot, "sp_tweaks build", Some(1_000), 900, Some(1_100));
    track_index(&mut slot, "sp_tweaks build", Some(1_050), 900, Some(1_100));
    track_index(&mut slot, "sp_tweaks build", None, 900, Some(1_100));
    assert!(slot.is_none(), "index turned off");
    assert_eq!(
        finished_index_stages(),
        [("sp_tweaks build", 100, 150, 201)],
        "counted from the origin, stopped where it was"
    );
    track_index(&mut slot, "sp_tweaks build", Some(5), 0, None);
    assert!(slot.is_none(), "no target, nothing to build");
    progress::capture_finished(false);
}

/// Filters already sealed at height 0, tweaks from origin 1: each stage
/// counts from its own start and ends at its own total.
#[test]
fn released_builder_reports_each_index_from_its_start() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("idx-progress-released");
    q.set_block_filter_index(true).unwrap();
    let tip = WINDOW_HEIGHTS + 1;
    coinbase_chain(&q, tip);
    let first = Arc::new(read_window(&q, 0, 0).unwrap());
    let filter = q.basic_filter_from_window(&first, 0).unwrap();
    q.commit_window_filters(0, &[(filter, first.blocks[0].header_fk)])
        .unwrap();
    q.set_sptweaks_enabled(true, Height(1)).unwrap();
    q.release_index_writebehind(Height(tip));

    progress::capture_finished(true);
    build_indexes_released(&q).unwrap();
    let fin = finished_index_stages();
    progress::capture_finished(false);
    assert_eq!(q.filter_index_next(), Some(tip + 1));
    assert_eq!(q.tweak_index_next(), Some(tip + 1));
    let total = u64::from(tip) + 1;
    assert_eq!(
        fin,
        [
            ("blockfilter build", 1, total, total),
            ("sp_tweaks build", 0, total - 1, total - 1),
        ]
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

#[test]
fn startup_repair_reports_only_the_indexes_it_seals() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("idx-progress-repair");
    q.set_block_filter_index(true).unwrap();
    q.set_sptweaks_enabled(true, Height(0)).unwrap();
    let tip = WINDOW_HEIGHTS + 1;
    coinbase_chain(&q, tip);
    let first = Arc::new(read_window(&q, 0, 0).unwrap());
    let filter = q.basic_filter_from_window(&first, 0).unwrap();
    q.commit_window_filters(0, &[(filter, first.blocks[0].header_fk)])
        .unwrap();

    // Tweaks are one height further behind than the cap: only filters
    // are repaired here.
    progress::capture_finished(true);
    prepare_live_indexes_limited(&q, tip).unwrap();
    let fin = finished_index_stages();
    progress::capture_finished(false);
    assert_eq!(q.filter_index_next(), Some(tip + 1));
    assert_eq!(q.tweak_index_next(), Some(0));
    let total = u64::from(tip) + 1;
    assert_eq!(fin, [("blockfilter build", 1, total, total)]);
    let _ = std::fs::remove_dir_all(dir.path());
}

/// The write-behind IO thread registers the stage from the watermark
/// before it reads; with no CPU worker nothing commits, so it ends where
/// it began.
#[test]
fn writebehind_registers_a_stage_for_a_wide_gap() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("idx-progress-wb");
    q.set_block_filter_index(true).unwrap();
    let tip = WINDOW_HEIGHTS + 1;
    coinbase_chain(&q, tip);
    q.release_index_writebehind(Height(tip));

    progress::capture_finished(true);
    let stop = AtomicBool::new(false);
    let resync = AtomicBool::new(false);
    let stages = IndexStageMs::default();
    let (tx, rx) = sync_channel(1);
    drop(rx);
    io_loop(
        &q,
        &stop,
        &resync,
        &stages,
        &tx,
        PROGRESS_EVERY,
        || {},
        || {},
    )
    .unwrap();
    let fin = finished_index_stages();
    progress::capture_finished(false);
    assert_eq!(fin, [("blockfilter build", 0, 0, u64::from(tip) + 1)]);
    let _ = std::fs::remove_dir_all(dir.path());
}

fn header_rec(h: u32, prev_fk: Fk, prev_hash: Option<[u8; 32]>) -> rbitcoin_store::HeaderRecord {
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&h.to_le_bytes());
    merkle[5] = 0xec;
    let hash = match prev_hash {
        None => merkle,
        Some(ph) => rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207f_ffff, h),
    };
    rbitcoin_store::HeaderRecord {
        prev_fk,
        version: 1,
        timestamp: h + 1,
        bits: 0x207f_ffff,
        nonce: h,
        merkle_root: merkle,
        hash,
        size: 0,
        weight: 0,
    }
}

fn tx_apply(
    txid: [u8; 32],
    inputs: Vec<rbitcoin_store::InputRecord>,
    outputs: Vec<rbitcoin_store::OutputRecord>,
) -> rbitcoin_query::TxApply {
    rbitcoin_query::TxApply {
        tx: rbitcoin_store::TxRecord {
            txid,
            version: 2,
            locktime: 0,
            input_count: inputs.len() as u32,
            output_count: outputs.len() as u32,
        },
        inputs,
        outputs,
    }
}
