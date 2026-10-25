//! `ArrayTable` under one writer, concurrent flushers, and readers, over an
//! in-memory file that can fail. The writer's RAM states are one history:
//! `base`, then the state after each op. Everything the race shows must come
//! from it:
//!
//! - each reader's `get`/`len` results read that history in order;
//! - every successful flush leaves the file, published and reopened, at one
//!   state of it (disk lags RAM, never diverges);
//! - a restart right after the race reopens one state, or the in-prefix
//!   rewrite residual the scenario names;
//! - one quiescent `flush` brings table, file, and reopen to the last state.

use crate::engine;
use crate::mem_file::{FailAt, MemFile};
use rbitcoin_store::array_table::{ArrayFile, ArrayTable, FlushStep};
use rbitcoin_store::file::FILE_HEADER_LEN;
use rbitcoin_store::sync::atomic::Ordering;
use rbitcoin_store::sync::{thread, Arc};

const HEADER: u64 = FILE_HEADER_LEN as u64;

#[derive(Clone, Debug)]
enum Op {
    Set(u64, u64),
    SetMany(Vec<(u64, u64)>),
    Truncate(u64),
}

impl Op {
    fn apply(&self, t: &ArrayTable<MemFile>) {
        match self {
            Op::Set(i, v) => t.set(*i, *v).unwrap(),
            Op::SetMany(pairs) => t.set_many(pairs).unwrap(),
            Op::Truncate(n) => t.truncate(*n).unwrap(),
        }
    }

    /// Lowest index this op sets, or the length it truncates to.
    fn lowest_touched(&self) -> u64 {
        match self {
            Op::Set(i, _) => *i,
            Op::SetMany(pairs) => pairs.iter().map(|&(i, _)| i).min().unwrap_or(u64::MAX),
            Op::Truncate(n) => *n,
        }
    }

    /// The states a reader can see while this op runs on `v`, last one
    /// final. In RAM every op is one step. On the fd-only path `set_many`
    /// writes through slot by slot: a zero-filled grow publishes the new
    /// length, then each pair lands.
    fn steps(&self, v: &[u64], fd_only: bool) -> Vec<Vec<u64>> {
        let set = |v: &mut Vec<u64>, i: u64, x: u64| {
            if v.len() <= i as usize {
                v.resize(i as usize + 1, 0);
            }
            v[i as usize] = x;
        };
        let mut v = v.to_vec();
        match self {
            Op::Set(i, x) => set(&mut v, *i, *x),
            Op::Truncate(n) => v.truncate(*n as usize),
            Op::SetMany(pairs) if fd_only => {
                let mut steps = Vec::new();
                let max = pairs.iter().map(|&(i, _)| i).max().unwrap_or(0);
                if max as usize >= v.len() {
                    v.resize(max as usize + 1, 0);
                    steps.push(v.clone());
                }
                for &(i, x) in pairs {
                    set(&mut v, i, x);
                    steps.push(v.clone());
                }
                return steps;
            }
            Op::SetMany(pairs) => pairs.iter().for_each(|&(i, x)| set(&mut v, i, x)),
        }
        vec![v]
    }
}

#[derive(Default)]
struct Scenario {
    /// Image on disk and in RAM before the race.
    base: Vec<u64>,
    /// Load with a zero RAM cap (L0) instead of into RAM (L2).
    fd_only: bool,
    /// One writer thread applies these in order (the store's single writer).
    writer: Vec<Op>,
    /// Threads that each call `flush_dirty` once.
    flushers: usize,
    /// One thread per entry; for each index in order it calls `get` then
    /// `len`.
    readers: Vec<Vec<u64>>,
    /// Armed for the race: the next `.1` file calls of kind `.0` fail.
    fault: Option<(FailAt, usize)>,
    /// What a restart after the race may reopen besides a state.
    residual: Residual,
}

/// Crash images an in-prefix rewrite can leave that are no state of the
/// writer: the module doc's residual risk, mitigated by the tip-last connect
/// and tip-first disconnect barriers (`docs/crash-recovery.md`).
#[derive(Default)]
enum Residual {
    #[default]
    None,
    /// A short write tore the rewritten range.
    Torn(Vec<Vec<u64>>),
}

/// What a reader saw.
#[derive(Clone, Copy, Debug)]
enum Seen {
    Get(u64, u64),
    Len(u64),
}

impl Seen {
    fn agrees(self, state: &[u64]) -> bool {
        match self {
            Seen::Get(i, v) => state.get(i as usize).copied().unwrap_or(0) == v,
            Seen::Len(n) => state.len() as u64 == n,
        }
    }
}

/// The writer's states in order.
struct History(Vec<Vec<u64>>);

impl History {
    fn new(s: &Scenario) -> Self {
        let mut states = vec![s.base.clone()];
        for op in &s.writer {
            let steps = op.steps(states.last().unwrap(), s.fd_only);
            states.extend(steps);
        }
        Self(states)
    }

    fn last(&self) -> &[u64] {
        self.0.last().unwrap()
    }

    fn contains(&self, image: &[u64]) -> bool {
        self.0.iter().any(|state| state == image)
    }

    fn allows_crash(&self, image: &[u64], residual: &Residual) -> bool {
        self.contains(image)
            || match residual {
                Residual::None => false,
                Residual::Torn(images) => images.iter().any(|t| t == image),
            }
    }

    /// Readers are linearizable: one thread's results fit states in order.
    fn assert_in_order(&self, seen: &[Seen]) {
        let mut k = 0;
        for &s in seen {
            k = (k..self.0.len())
                .find(|&k| s.agrees(&self.0[k]))
                .unwrap_or_else(|| panic!("reads {seen:?} leave the history at {s:?}"));
        }
    }
}

/// What a successful flush left on disk, read while it still held the
/// flush lock.
struct Landed {
    image: Vec<u64>,
    reopened: Vec<u64>,
    disk_len: u64,
}

fn run(s: Scenario) {
    #[cfg(loom)]
    assert!(
        1 + s.flushers + s.readers.len() <= 4,
        "loom models at most 4 spawned threads"
    );
    assert!(
        !s.fd_only || !s.base.is_empty(),
        "an empty body always loads into RAM"
    );
    assert!(
        !s.fd_only || s.fault.is_none(),
        "fd-only writer ops would take the fault"
    );
    let history = History::new(&s);
    if let Residual::Torn(images) = &s.residual {
        assert!(
            images.iter().all(|img| !history.contains(img)),
            "a listed tear is a state"
        );
    }
    engine::check(move || race(&s, &history));
}

fn race(s: &Scenario, h: &History) {
    let file = MemFile::with_body(&s.base);
    if let Some((at, times)) = s.fault {
        file.arm(at, times);
    }
    let ram_cap = if s.fd_only { 0 } else { u64::MAX };
    let t = Arc::new(ArrayTable::load(file, ram_cap).unwrap());

    let writer = {
        let (t, ops) = (Arc::clone(&t), s.writer.clone());
        thread::spawn(move || ops.iter().for_each(|op| op.apply(&t)))
    };
    let flushers: Vec<_> = (0..s.flushers)
        .map(|_| {
            let t = Arc::clone(&t);
            thread::spawn(move || {
                let mut landed = None;
                let flushed = t.flush_dirty_between(|t, step| {
                    if step == FlushStep::Clean {
                        landed = Some(Landed {
                            image: t.file.image(),
                            reopened: t.file.reopen().image(),
                            disk_len: t.disk_len.load(Ordering::Acquire),
                        });
                    }
                });
                (flushed.map_err(|e| e.to_string()), landed)
            })
        })
        .collect();
    let readers: Vec<_> = s
        .readers
        .iter()
        .map(|indices| {
            let (t, indices) = (Arc::clone(&t), indices.clone());
            thread::spawn(move || {
                let mut seen = Vec::new();
                for i in indices {
                    let got = t.get(i).unwrap_or_else(|e| panic!("get({i}): {e}"));
                    seen.extend([Seen::Get(i, got), Seen::Len(t.len())]);
                }
                seen
            })
        })
        .collect();
    writer.join().unwrap();
    for f in flushers {
        let (flushed, landed) = f.join().unwrap();
        assert!(s.fault.is_some() || flushed.is_ok(), "flush: {flushed:?}");
        let Some(l) = landed.filter(|_| flushed.is_ok()) else {
            continue;
        };
        assert!(h.contains(&l.image), "a flush published {:?}", l.image);
        assert_eq!(l.reopened, l.image, "a flush left the HWM behind");
        assert_eq!(l.image.len() as u64, l.disk_len, "disk_len after a flush");
    }
    for r in readers {
        h.assert_in_order(&r.join().unwrap());
    }

    let crashed = t.file.reopen().image();
    assert!(
        h.allows_crash(&crashed, &s.residual),
        "a restart after the race reopens {crashed:?}"
    );
    let reopened = ArrayTable::load(t.file.reopen(), ram_cap).unwrap();
    assert_eq!(reopened.len(), crashed.len() as u64, "reopened len");

    t.file.disarm();
    t.flush().unwrap();
    let want = h.last();
    let n = want.len() as u64;
    assert_eq!(t.len(), n);
    for (i, &v) in want.iter().enumerate() {
        assert_eq!(t.get(i as u64).unwrap(), v, "get({i})");
    }
    assert_eq!(t.get(n).unwrap(), 0);
    assert_eq!(t.file.image(), want, "file image");
    assert_eq!(t.file.logical_len(), HEADER + 8 * n);
    assert_eq!(t.file.reopen().image(), want, "reopened image");
    if !s.fd_only {
        assert_eq!(t.disk_len.load(Ordering::Acquire), n, "disk_len");
        assert_eq!(t.dirty_epoch.load(Ordering::Acquire), 0, "dirty_epoch");
        assert_eq!(t.dirty_lo.load(Ordering::Acquire), u64::MAX, "dirty_lo");
    }
    if s.fault.is_none() {
        // A set past the on-disk length writes the zero gap from `base.len()`.
        let lowest = s.writer.iter().map(Op::lowest_touched).min();
        let floor = lowest.unwrap_or(u64::MAX).min(s.base.len() as u64);
        assert!(
            t.file.min_write_offset() >= HEADER + 8 * floor,
            "a flush wrote below the lowest touched index"
        );
    }
}

#[test]
fn in_prefix_set_races_flush() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::Set(0, 20)],
        flushers: 1,
        ..Scenario::default()
    });
}

#[test]
fn append_then_in_prefix_set_races_flush() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::Set(2, 22), Op::Set(0, 20)],
        flushers: 1,
        ..Scenario::default()
    });
}

#[test]
fn empty_table_grows_races_flush() {
    run(Scenario {
        writer: vec![Op::Set(1, 5), Op::Set(0, 4)],
        flushers: 1,
        readers: vec![vec![0]],
        ..Scenario::default()
    });
}

#[test]
fn append_set_races_flush() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::Set(2, 22)],
        flushers: 1,
        ..Scenario::default()
    });
}

#[test]
fn two_appends_race_two_flushes() {
    run(Scenario {
        base: vec![10],
        writer: vec![Op::Set(1, 11), Op::Set(2, 12)],
        flushers: 2,
        ..Scenario::default()
    });
}

#[test]
fn set_many_mixed_races_flush() {
    run(Scenario {
        base: vec![10, 11, 12],
        writer: vec![Op::SetMany(vec![(1, 21), (4, 24)])],
        flushers: 1,
        ..Scenario::default()
    });
}

/// Unsorted pairs straddle the on-disk length, leave a zero gap, and name
/// one index twice: the last pair wins.
#[test]
fn set_many_unsorted_duplicates_straddle_disk_len() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::SetMany(vec![(3, 23), (1, 21), (3, 33)])],
        flushers: 1,
        readers: vec![vec![3, 1]],
        ..Scenario::default()
    });
}

#[test]
fn truncate_races_flush() {
    run(Scenario {
        base: vec![1, 2, 3, 4],
        writer: vec![Op::Truncate(2)],
        flushers: 1,
        ..Scenario::default()
    });
}

#[test]
fn two_flushers_race_truncate() {
    run(Scenario {
        base: vec![1, 2, 3, 4],
        writer: vec![Op::Truncate(2)],
        flushers: 2,
        ..Scenario::default()
    });
}

/// The flusher's rewrite from index 2 races a truncate below it.
#[test]
fn rewrite_races_truncate_below_from() {
    run(Scenario {
        base: vec![1, 2, 3, 4],
        writer: vec![Op::Set(2, 30), Op::Truncate(1)],
        flushers: 2,
        ..Scenario::default()
    });
}

/// The stale bytes under the regrown range must be zeroed on disk.
#[test]
fn truncate_to_zero_then_regrow_past_disk_len() {
    run(Scenario {
        base: vec![1, 2],
        writer: vec![Op::Truncate(0), Op::Set(3, 9)],
        flushers: 1,
        ..Scenario::default()
    });
}

#[test]
fn two_flushers_one_writer_mixed() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::Set(0, 20), Op::Set(2, 22)],
        flushers: 2,
        ..Scenario::default()
    });
}

/// `get` loads `len` before the read lock; a truncate lands in between.
#[test]
fn get_races_truncate_and_set() {
    run(Scenario {
        base: vec![0, 0, 0, 7],
        writer: vec![Op::Truncate(0), Op::Set(3, 7)],
        readers: vec![vec![3]],
        ..Scenario::default()
    });
}

#[test]
fn get_races_append_gap() {
    run(Scenario {
        base: vec![1],
        writer: vec![Op::Set(3, 9)],
        readers: vec![vec![3], vec![2]],
        ..Scenario::default()
    });
}

#[test]
fn flush_write_error_keeps_dirty() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::Set(0, 5)],
        flushers: 1,
        fault: Some((FailAt::Write, 1)),
        ..Scenario::default()
    });
}

#[test]
fn two_failed_flushes_then_quiescent() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::Set(0, 20), Op::Set(2, 22)],
        flushers: 2,
        fault: Some((FailAt::Write, 2)),
        ..Scenario::default()
    });
}

#[test]
fn shrink_len_publish_fails_before_store() {
    run(Scenario {
        base: vec![1, 2, 3, 4],
        writer: vec![Op::Truncate(2)],
        flushers: 1,
        fault: Some((FailAt::SetLenBeforeStore, 1)),
        ..Scenario::default()
    });
}

/// The published end moved and the HWM did not: a restart reopens the old
/// length, and the next flush still shrinks.
#[test]
fn shrink_len_publish_fails_after_store() {
    run(Scenario {
        base: vec![1, 2, 3, 4],
        writer: vec![Op::Truncate(2)],
        flushers: 1,
        fault: Some((FailAt::SetLenAfterStore, 1)),
        ..Scenario::default()
    });
}

/// A short in-prefix rewrite tears the published range: the module doc's
/// residual risk.
#[test]
fn torn_in_prefix_rewrite() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::SetMany(vec![(0, 20), (1, 21)])],
        flushers: 1,
        fault: Some((FailAt::TornWrite, 1)),
        residual: Residual::Torn(vec![vec![20, 11]]),
        ..Scenario::default()
    });
}

/// A torn append lands past the published end: a restart reopens the old
/// image.
#[test]
fn torn_append() {
    run(Scenario {
        base: vec![10],
        writer: vec![Op::SetMany(vec![(1, 11), (2, 12)])],
        flushers: 1,
        fault: Some((FailAt::TornWrite, 1)),
        ..Scenario::default()
    });
}

/// A rewrite that also grows tears before the old end: a restart reopens
/// the new prefix at the old length.
#[test]
fn torn_growing_rewrite() {
    run(Scenario {
        base: vec![10, 11],
        writer: vec![Op::Set(2, 22), Op::Set(0, 20)],
        flushers: 1,
        fault: Some((FailAt::TornWrite, 1)),
        residual: Residual::Torn(vec![vec![20, 11]]),
        ..Scenario::default()
    });
}

/// A reader that has seen the new length must not read the slot as past
/// the file's end on its next `get`.
#[test]
fn fd_only_get_races_set_extend() {
    run(Scenario {
        base: vec![1],
        fd_only: true,
        writer: vec![Op::Set(3, 9)],
        readers: vec![vec![3, 3], vec![2]],
        ..Scenario::default()
    });
}

/// The fd-only `set_many` publishes its grown length before its pairs land.
#[test]
fn fd_only_set_many_races_reader() {
    run(Scenario {
        base: vec![1, 2, 3],
        fd_only: true,
        writer: vec![Op::SetMany(vec![(4, 24), (1, 21)])],
        readers: vec![vec![0, 4, 1]],
        ..Scenario::default()
    });
}
