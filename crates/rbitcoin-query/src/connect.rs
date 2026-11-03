//! Tip confirm / connect / disconnect.

use super::*;
use std::sync::atomic::Ordering;

/// One height of SH creates waiting for the Class B appender.
#[derive(Clone)]
pub struct ShPendingJob {
    pub height: Height,
    pub header_fk: Fk,
    pub records: Vec<ScriptHashRecord>,
}

#[doc(hidden)]
pub fn index_sh_ram_head(head: &mut HashMap<[u8; 32], Vec<Fk>>, job: &ShPendingJob) {
    for r in &job.records {
        head.entry(r.scripthash).or_default().push(r.create_tx_fk);
    }
}

#[doc(hidden)]
pub fn unindex_sh_ram_head(head: &mut HashMap<[u8; 32], Vec<Fk>>, job: &ShPendingJob) {
    for r in &job.records {
        let Some(v) = head.get_mut(&r.scripthash) else {
            continue;
        };
        if let Some(i) = v.iter().position(|fk| *fk == r.create_tx_fk) {
            v.swap_remove(i);
        }
        if v.is_empty() {
            head.remove(&r.scripthash);
        }
    }
}

/// One height ready for Class C (header + body already archived).
///
/// Callers that already resolved `header_fk` / `tx_fks` (e.g. multi-block confirm)
/// pass them here to avoid redoing hash lookups.
#[derive(Debug, Clone)]
pub struct ConfirmPrepared {
    pub height: Height,
    pub header_fk: Fk,
    pub tx_fks: Vec<Fk>,
    /// Block hash. Published as the tip when this run extends `confirmed[]`.
    pub hash: [u8; 32],
}

/// Last tip a Class A seal made durable (`u32::MAX` = none).
///
/// [`Self::landed`] is the only upward move, and it takes the height the
/// seal returned. [`Self::shrunk_to`] stores a disconnect tip only when
/// that tip is below the current seal, so an unsealed block cannot become
/// the seqsigwit prune anchor.
pub struct SealedTip(std::sync::atomic::AtomicU32);

impl SealedTip {
    pub fn at_open(tip: Option<Height>) -> Self {
        Self(std::sync::atomic::AtomicU32::new(
            tip.map(|h| h.0).unwrap_or(u32::MAX),
        ))
    }

    pub fn get(&self) -> Option<Height> {
        match self.0.load(Ordering::Acquire) {
            u32::MAX => None,
            h => Some(Height(h)),
        }
    }

    fn store(&self, height: Option<Height>) {
        let v = height.map(|h| h.0).unwrap_or(u32::MAX);
        self.0.store(v, Ordering::Release);
    }

    pub fn landed(&self, height: Height) {
        self.store(Some(height));
    }

    pub fn shrunk_to(&self, now: Option<Height>) {
        match self.get() {
            None => self.store(now),
            Some(sealed) if now.is_none_or(|tip| tip.0 < sealed.0) => self.store(now),
            Some(_) => {}
        }
    }

    /// Height prune may advance to. `landed` is the height this flush sealed.
    /// `before` fills in only when this process has not sealed a tip yet.
    pub fn for_prune(&self, before: Option<Height>, landed: Option<Height>) -> Option<Height> {
        if let Some(height) = landed {
            self.landed(height);
            return Some(height);
        }
        if let Some(height) = self.get() {
            return Some(height);
        }
        self.store(before);
        before
    }
}

/// IBD tip barrier. One `rbtc-tip-flush` thread runs each barrier; the next
/// `tip_commit` taker waits for the in-flight one.
#[derive(Default)]
pub enum TipFlush {
    #[default]
    Idle,
    Running(InflightFlush),
    Failed,
}

pub struct InflightFlush {
    rx: std::sync::mpsc::Receiver<Result<Option<Height>, StoreError>>,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl InflightFlush {
    fn still_running(&self) -> bool {
        !self.done.load(Ordering::Acquire)
    }
}

pub struct TipFlushJob {
    reply: std::sync::mpsc::Sender<Result<Option<Height>, StoreError>>,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// The confirm engine's Class C barrier thread. Tests start it on the first
/// IBD flush. Tip mode does not use it.
pub struct TipFlushWorker {
    tx: std::sync::Mutex<Option<std::sync::mpsc::Sender<TipFlushJob>>>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Live threads of this worker. A second spawn would leave this above one.
    #[cfg(debug_assertions)]
    alive: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Linux tid of this worker. Zero until the thread publishes it.
    #[cfg(all(debug_assertions, target_os = "linux"))]
    os_tid: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Set after `os_tid` is stored. The name is already the builder name.
    #[cfg(all(debug_assertions, target_os = "linux"))]
    published: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    /// Set when `join_tip_flush` is blocked on the in-flight barrier.
    #[cfg(debug_assertions)]
    blocked: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl Default for TipFlushWorker {
    fn default() -> Self {
        Self {
            tx: std::sync::Mutex::new(None),
            thread: std::sync::Mutex::new(None),
            #[cfg(debug_assertions)]
            alive: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(all(debug_assertions, target_os = "linux"))]
            os_tid: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            #[cfg(all(debug_assertions, target_os = "linux"))]
            published: std::sync::Arc::new((
                std::sync::Mutex::new(false),
                std::sync::Condvar::new(),
            )),
            #[cfg(debug_assertions)]
            blocked: std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
        }
    }
}

/// Decrements the worker's live count when the barrier thread exits.
#[cfg(debug_assertions)]
struct TipFlushAlive(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(debug_assertions)]
impl TipFlushAlive {
    fn arm(alive: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        alive.fetch_add(1, Ordering::Release);
        Self(alive)
    }
}

#[cfg(debug_assertions)]
impl Drop for TipFlushAlive {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

#[cfg(target_os = "linux")]
fn linux_task_id() -> Option<u64> {
    let path = std::fs::read_link("/proc/thread-self").ok()?;
    path.file_name()?.to_str()?.parse().ok()
}

impl Query {
    /// Tip hash from the last confirm or disconnect, if it still matches `height`.
    pub fn published_tip(&self) -> Option<PublishedTip> {
        self.published_tip.load_full().as_deref().copied()
    }

    /// Publish `hash` as the confirmed tip at `height`. Called in the same
    /// confirm that advanced `confirmed[]`, before the Class C flush.
    pub fn publish_confirmed_tip(&self, height: u32, hash: [u8; 32]) {
        self.publish_confirmed_rows(&[(hash, height)]);
    }

    /// Publish `rows` (height order) as the new tip and index every height
    /// from the previous index tip through the last row, when that span is
    /// contiguous. A gap still waits for the catch-up walk.
    pub fn publish_confirmed_rows(&self, rows: &[([u8; 32], u32)]) {
        let Some(&(hash, height)) = rows.last() else {
            return;
        };
        self.published_tip
            .store(Some(std::sync::Arc::new(PublishedTip { height, hash })));
        let expected = self.with_height_index(|index| index.tip);
        let start = match expected {
            None => {
                if rows.len() == 1 && height == 0 {
                    let _ = self.extend_height_index(rows, 0, None, false);
                }
                return;
            }
            Some(prev) => prev.saturating_add(1),
        };
        if height < start {
            return;
        }
        let mut seq = Vec::with_capacity((height - start) as usize + 1);
        for h in start..=height {
            let Some(row) = rows.iter().find(|(_, rh)| *rh == h) else {
                return;
            };
            seq.push(*row);
        }
        if self.extend_height_index(&seq, height, expected, false) {
            // Same counter the catch-up walk records, so a span publish is
            // still an incremental extend and not a silent index update.
            crate::note_confirm(&self.confirm_stats().height_index_delta_n, seq.len() as u64);
        }
    }

    pub fn clear_published_tip(&self) {
        self.published_tip.store(None);
    }

    /// Block until the in-flight tip flush or disconnect releases the commit,
    /// then join an IBD tip flush that is still running.
    pub fn lock_tip_commit(&self) -> Result<std::sync::MutexGuard<'_, ()>, QueryError> {
        let commit = self.tip_commit.lock().unwrap_or_else(|e| e.into_inner());
        self.join_tip_flush()?;
        Ok(commit)
    }

    /// `None` while a confirm flush or disconnect holds the commit, while an
    /// IBD tip flush is still running, or after one failed.
    /// Rewind uses this so the orchestration task does not wait on that disk.
    pub fn try_lock_tip_commit(&self) -> Option<std::sync::MutexGuard<'_, ()>> {
        let commit = match self.tip_commit.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        let running = matches!(
            &*self.tip_flush.lock().unwrap_or_else(|e| e.into_inner()),
            TipFlush::Running(job) if job.still_running()
        );
        if running || self.join_tip_flush().is_err() {
            return None;
        }
        Some(commit)
    }

    /// Wait for the IBD tip barrier. Its failure sticks: a failed `fsync` is
    /// not retried, so every later commit fails until restart.
    pub fn join_tip_flush(&self) -> Result<(), QueryError> {
        let mut state = self.tip_flush.lock().unwrap_or_else(|e| e.into_inner());
        let joined = match std::mem::take(&mut *state) {
            TipFlush::Idle => return Ok(()),
            TipFlush::Failed => Err(StoreError::io(
                self.store.path(),
                std::io::Error::other("an earlier IBD tip flush failed; restart the node"),
            )),
            TipFlush::Running(flush) => {
                #[cfg(debug_assertions)]
                self.note_tip_commit_blocked();
                let t = std::time::Instant::now();
                let r = flush
                    .rx
                    .recv()
                    .unwrap_or(Err(StoreError::Corrupt("IBD tip flush thread panicked")));
                crate::note_confirm(
                    &self.confirm_stats().write_tip_flush_wait_ns,
                    t.elapsed().as_nanos() as u64,
                );
                match r {
                    Ok(Some(h)) => {
                        self.sealed_tip.landed(h);
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(e) => Err(e),
                }
            }
        };
        if joined.is_err() {
            *state = TipFlush::Failed;
        }
        joined
    }

    /// L2 write-behind barrier: the complete-or-fail Class C image to disk.
    /// Tip mode returns after it. IBD returns before it and may dequeue the
    /// RAM body queue: a kill then loses at most one more batch to download
    /// again. Returns the last sealed tip. IBD returns that height while
    /// this batch's flush is still running. A withheld locator header does
    /// not move it. Seqsigwit prune keeps its window below that tip.
    #[doc(hidden)]
    pub fn flush_tip(&self, before: Option<Height>) -> Result<Option<Height>, QueryError> {
        if self.index_mode()?.is_tip() {
            let landed = self.store.flush_class_c_tip()?;
            return Ok(self.sealed_tip.for_prune(before, landed));
        }
        self.spawn_tip_flush()?;
        Ok(self.sealed_tip.for_prune(before, None))
    }

    /// IBD: the next batch's archive and checks run while this batch's
    /// barrier syncs. That batch's commit joins it first, so the disk order
    /// stays the same. One thread serves every barrier.
    #[doc(hidden)]
    pub fn spawn_tip_flush(&self) -> Result<(), QueryError> {
        if self.tip_flush_spawn_fails() {
            return self.flush_tip_inline("test hook: no tip flush thread");
        }
        self.ensure_tip_flush_worker();
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let job = TipFlushJob {
            reply: reply_tx,
            done: Arc::clone(&done),
        };
        let sent = {
            let tx = self
                .tip_flush_worker
                .tx
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match tx.as_ref() {
                Some(tx) => tx.send(job).is_ok(),
                None => false,
            }
        };
        if sent {
            let mut state = self.tip_flush.lock().unwrap_or_else(|e| e.into_inner());
            *state = TipFlush::Running(InflightFlush { rx: reply_rx, done });
            return Ok(());
        }
        self.flush_tip_inline("rbtc-tip-flush is not running")
    }

    fn flush_tip_inline(&self, why: &str) -> Result<(), QueryError> {
        rbitcoin_log::warn!("store: no IBD tip flush thread ({why}); flushing inline");
        let mut state = self.tip_flush.lock().unwrap_or_else(|e| e.into_inner());
        match self.store.flush_class_c_tip() {
            Ok(Some(h)) => {
                self.sealed_tip.landed(h);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => {
                *state = TipFlush::Failed;
                Err(e)
            }
        }
    }

    /// Start the IBD barrier thread if this query does not already have one.
    #[doc(hidden)]
    pub fn ensure_tip_flush_worker(&self) {
        let mut slot = self
            .tip_flush_worker
            .thread
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        *self
            .tip_flush_worker
            .tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let store = Arc::clone(&self.store);
        #[cfg(debug_assertions)]
        let hold = Arc::clone(&self.tip_flush_hold);
        #[cfg(debug_assertions)]
        let alive = Arc::clone(&self.tip_flush_worker.alive);
        #[cfg(all(debug_assertions, target_os = "linux"))]
        let os_tid = Arc::clone(&self.tip_flush_worker.os_tid);
        #[cfg(all(debug_assertions, target_os = "linux"))]
        let published = Arc::clone(&self.tip_flush_worker.published);
        let handle = std::thread::Builder::new()
            .name("rbtc-tip-flush".into())
            .spawn(move || {
                #[cfg(debug_assertions)]
                let _alive = TipFlushAlive::arm(alive);
                #[cfg(all(debug_assertions, target_os = "linux"))]
                if let Some(tid) = linux_task_id() {
                    os_tid.store(tid, Ordering::Release);
                    let (lock, cv) = &*published;
                    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
                    cv.notify_all();
                }
                while let Ok(job) = rx.recv() {
                    // Pause after the flush excludes stores, not before it starts.
                    #[cfg(debug_assertions)]
                    rbitcoin_store::bind_tip_flush_hold(Some(Arc::clone(&hold)));
                    let result = store.flush_class_c_tip();
                    #[cfg(debug_assertions)]
                    rbitcoin_store::bind_tip_flush_hold(None);
                    let _ = job.reply.send(result);
                    job.done.store(true, Ordering::Release);
                }
            })
            .expect("rbtc-tip-flush thread");
        *slot = Some(handle);
    }

    /// Drop the job sender and join the barrier thread.
    #[doc(hidden)]
    pub fn stop_tip_flush_worker(&self) {
        let mut slot = self
            .tip_flush_worker
            .thread
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *self
            .tip_flush_worker
            .tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(handle) = slot.take() {
            let _ = handle.join();
        }
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn tip_flush_spawn_fails(&self) -> bool {
        self.tip_flush_spawn_fail.swap(false, Ordering::SeqCst)
    }

    #[cfg(not(debug_assertions))]
    #[doc(hidden)]
    pub fn tip_flush_spawn_fails(&self) -> bool {
        false
    }

    /// Live `rbtc-tip-flush` threads of this query. Other queries do not count.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn tip_flush_alive(&self) -> usize {
        self.tip_flush_worker
            .alive
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Linux tid once the barrier thread has published it and its name.
    #[cfg(all(debug_assertions, target_os = "linux"))]
    #[doc(hidden)]
    pub fn wait_tip_flush_published(&self, timeout: std::time::Duration) -> Option<u64> {
        let (lock, cv) = &*self.tip_flush_worker.published;
        let mut ready = lock.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if *ready {
                let tid = self.tip_flush_os_tid();
                return (tid != 0).then_some(tid);
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            let (guard, status) = cv
                .wait_timeout(ready, left)
                .unwrap_or_else(|e| e.into_inner());
            ready = guard;
            if status.timed_out() && !*ready {
                return None;
            }
        }
    }

    /// Linux tid of this query's barrier thread, or zero before it publishes.
    #[cfg(all(debug_assertions, target_os = "linux"))]
    #[doc(hidden)]
    pub fn tip_flush_os_tid(&self) -> u64 {
        self.tip_flush_worker
            .os_tid
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(debug_assertions)]
    fn note_tip_commit_blocked(&self) {
        let (lock, cv) = &*self.tip_flush_worker.blocked;
        let mut blocked = lock.lock().unwrap_or_else(|e| e.into_inner());
        *blocked = true;
        cv.notify_all();
    }

    /// `true` once a commit is inside [`Self::join_tip_flush`] for a running barrier.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn wait_tip_commit_blocked(&self, timeout: std::time::Duration) -> bool {
        let (lock, cv) = &*self.tip_flush_worker.blocked;
        let mut blocked = lock.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if *blocked {
                return true;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            let (guard, status) = cv
                .wait_timeout(blocked, left)
                .unwrap_or_else(|e| e.into_inner());
            blocked = guard;
            if status.timed_out() && !*blocked {
                return false;
            }
        }
    }

    /// IBD tip flush threads pause after they exclude stores, until this flag clears.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn hold_tip_flushes(&self) -> Arc<rbitcoin_store::TipFlushHold> {
        self.tip_flush_hold.store(true, Ordering::SeqCst);
        Arc::clone(&self.tip_flush_hold)
    }

    /// The next IBD tip flush thread fails to start.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn fail_next_tip_flush_spawn(&self) {
        self.tip_flush_spawn_fail.store(true, Ordering::SeqCst);
    }

    /// One header read at open, so the first orchestration pass does not
    /// re-read the tip. Later tips come from [`Self::publish_confirmed_tip`].
    /// A tip height with no header row is corrupt: leaving the snapshot empty
    /// would make every later `tip_hash` miss.
    pub fn seed_published_tip(&self) -> Result<(), QueryError> {
        let Some(tip) = self.tip_height() else {
            self.clear_published_tip();
            return Ok(());
        };
        let Some((_, rec)) = self.header_at_height(tip)? else {
            return Err(StoreError::Corrupt("confirmed tip has no header"));
        };
        self.publish_confirmed_tip(tip.0, rec.hash);
        Ok(())
    }

    pub fn confirm_block(&self, height: Height, header_hash: &[u8; 32]) -> Result<Fk, QueryError> {
        if let Some(h) = self.height_of_hash(header_hash)? {
            if h == height {
                if let Some((fk, _)) = self.get_header_by_hash(header_hash)? {
                    return Ok(fk);
                }
            }
        }

        let (header_fk, _rec) = self
            .get_header_by_hash(header_hash)?
            .ok_or(StoreError::NotFound)?;
        let tx_fks = self
            .store
            .header_txs
            .get_list(header_fk)?
            .ok_or(StoreError::Corrupt("confirm without archived body"))?;

        let prepared = ConfirmPrepared {
            height,
            header_fk,
            tx_fks,
            hash: *header_hash,
        };
        let out = self.confirm_blocks_run(std::slice::from_ref(&prepared))?;
        self.annotate_spends_for_confirmed(std::slice::from_ref(&prepared))?;
        Ok(out[0])
    }

    /// Class C-only abs-meta annotate. Wire confirm uses `post_commit` instead;
    /// do not call from [`Self::confirm_blocks_run_with_create_pins`].
    #[doc(hidden)]
    pub fn annotate_spends_for_confirmed(
        &self,
        items: &[ConfirmPrepared],
    ) -> Result<(), QueryError> {
        if !self.spend_index_enabled() {
            return Ok(());
        }
        let mut abs_edges: Vec<(u64, Fk, u32, Fk, u32)> = Vec::new();
        for item in items {
            for &spend_fk in &item.tx_fks {
                let tx = self.get_tx(spend_fk)?;
                let ins = self.tx_input_run_class_a(spend_fk, &tx)?;
                for (vin, inp) in ins.into_iter().enumerate() {
                    if inp.is_coinbase() {
                        continue;
                    }
                    let create_fk = if inp.create_fk().is_null() {
                        self.store
                            .get_fk_by_txid_tip(&inp.prev_txid)?
                            .unwrap_or(Fk::NULL)
                    } else {
                        inp.create_fk()
                    };
                    if create_fk.is_null() {
                        continue;
                    }
                    let (off, len) = self.store.tx_spent_range(create_fk)?;
                    let abs = rbitcoin_store::spent_abs(off, inp.prev_index());
                    if abs.saturating_add(rbitcoin_store::OutputRecord::SPENT_SLOT_LEN as u64)
                        > off.saturating_add(len)
                    {
                        return Err(StoreError::Corrupt(
                            "invariant: confirm_block spend slot OOB",
                        ));
                    }
                    abs_edges.push((abs, create_fk, inp.prev_index(), spend_fk, vin as u32));
                }
            }
        }
        if abs_edges.is_empty() {
            return Ok(());
        }
        let cold = {
            let _utxo_view = self.store.hold_utxo_view();
            self.store.put_spend_batch_by_abs_meta(&abs_edges)?
        };
        if !cold.is_empty() {
            return Err(StoreError::Corrupt(
                "invariant: confirm_block spend annotate abs cold",
            ));
        }
        Ok(())
    }

    /// Confirm a contiguous tip-extension run of already-archived bodies.
    ///
    /// Skips per-block `height_of_hash` / `get_header_by_hash` (caller supplies fks).
    ///
    /// # Class C write order (crash atomicity)
    ///
    /// Per block we write `strong_tx`, then **last** advance `confirmed[]` for
    /// the whole run. Scripthash creates are enqueued after that commit and
    /// applied by [`Self::apply_sh_pending`]. The confirmed tip is the commit
    /// point: [`rbitcoin_store::Store::spenders`] /
    /// [`rbitcoin_store::Store::is_confirmed_strong`] only treat a spend as
    /// best-chain once the height fence (confirmed + header_txs) contains the
    /// spender. A hard kill after strong bits but before tip advance leaves
    /// recoverable state — open repairs strong not on the fence, and re-confirm
    /// of tip+1 does not see false PrevoutSpent.
    ///
    /// # Spend annotations
    ///
    /// When `spend_index` is on, durable spend annotations land on create outputs
    /// (schema v5+). Wire confirm (`post_commit`) writes them after Class C.
    /// [`Self::confirm_block`] does the same abs-meta annotate for the Query
    /// Class C-only path. [`Self::confirm_blocks_run`] itself does not annotate
    /// (the wire write stage would double-walk).
    pub fn confirm_blocks_run(&self, items: &[ConfirmPrepared]) -> Result<Vec<Fk>, QueryError> {
        self.confirm_blocks_run_with_create_pins(items, None, &[])
    }

    /// The run must be contiguous, start at tip+1 (genesis on an empty
    /// chain), and name real headers. `Some(fk)` is a one-block retry of the
    /// block already confirmed at that height.
    #[doc(hidden)]
    pub fn check_run_extends_tip(
        &self,
        items: &[ConfirmPrepared],
    ) -> Result<Option<Fk>, QueryError> {
        for w in items.windows(2) {
            if w[1].height.0 != w[0].height.0.saturating_add(1) {
                return Err(StoreError::Corrupt("confirm run not contiguous heights"));
            }
        }

        match self.tip_height() {
            None => {
                if items[0].height != Height::GENESIS {
                    return Err(StoreError::Corrupt("first block must be genesis height"));
                }
            }
            Some(tip) => {
                let expect = tip.next().ok_or(StoreError::Corrupt("height overflow"))?;
                if items[0].height != expect {
                    if items.len() == 1 {
                        if let Some(fk) = self.store.confirmed.get(items[0].height)? {
                            if fk == items[0].header_fk {
                                return Ok(Some(fk));
                            }
                        }
                    }
                    return Err(StoreError::Corrupt("connect height not tip+1"));
                }
            }
        }

        for item in items {
            if item.header_fk.is_null() {
                return Err(StoreError::InvalidFk);
            }
        }
        Ok(None)
    }

    /// Like [`Self::confirm_blocks_run`], with optional write-batch create pins.
    ///
    /// `create_pins` is `create_fk → CreatePin` for creates committed on this write
    /// path. Collect runs after tip (cheap); records sit on the job so queries
    /// join them before durable seed. Enqueue is after the tip commit: a collect
    /// failure can surface after `confirmed[]` advanced; retry is the heal
    /// (re-confirm at the same height is idempotent).
    pub fn confirm_blocks_run_with_create_pins(
        &self,
        items: &[ConfirmPrepared],
        create_pins: Option<&crate::FkMap<CreatePin>>,
        header_ranges: &[(Fk, Fk, u32)],
    ) -> Result<Vec<Fk>, QueryError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let commit = self.lock_tip_commit()?;
        let durable_before = self.tip_height();
        if let Some(fk) = self.check_run_extends_tip(items)? {
            return Ok(vec![fk]);
        }

        let write = rbitcoin_store::ClassCWrite::new();
        if !header_ranges.is_empty() {
            self.store
                .header_txs
                .put_ranges_batch(&write, header_ranges)?;
        }

        let t_strong = std::time::Instant::now();
        let mut confirmed_pairs = Vec::with_capacity(items.len());
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let contiguous = item
                .tx_fks
                .windows(2)
                .all(|w| w[1].0 == w[0].0.saturating_add(1));
            if contiguous {
                if let Some(&first) = item.tx_fks.first() {
                    self.store.strong_tx.set_strong_range(
                        &write,
                        first,
                        item.tx_fks.len() as u32,
                        item.header_fk,
                    )?;
                }
            } else {
                for &tx_fk in &item.tx_fks {
                    self.store
                        .strong_tx
                        .set_strong(&write, tx_fk, item.header_fk)?;
                }
            }
            confirmed_pairs.push((item.height, item.header_fk));
            out.push(item.header_fk);
        }
        crate::note_confirm(
            &self.confirm_stats().strong_ns,
            t_strong.elapsed().as_nanos() as u64,
        );

        // Fence first: missing header_txs is Corrupt. Publishing confirmed[]
        // before extend would leave tip ahead of height_of (leftover TipOnly hole).
        let t_tip = std::time::Instant::now();
        for item in items {
            self.store
                .height_fence_extend(item.height, item.header_fk)?;
        }
        self.store.confirmed.set_many(&write, &confirmed_pairs)?;
        // Same commit as `confirmed[]`, before the flush. `tip_height` is
        // already the new tip; the orchestration loop reads this snapshot.
        if !items.is_empty() {
            let rows: Vec<([u8; 32], u32)> = items
                .iter()
                .map(|item| (item.hash, item.height.0))
                .collect();
            self.publish_confirmed_rows(&rows);
            self.forget_reconnected(items.iter().map(|item| &item.hash));
        }
        // Do not forget pending here: drain may still be inserting tx.head
        // (67438). Write forgets after drain.join() *and* this extend.
        let durable = self.flush_tip(durable_before)?;
        drop(commit);
        crate::note_confirm(
            &self.confirm_stats().tip_ns,
            t_tip.elapsed().as_nanos() as u64,
        );

        self.enqueue_sh_pending(items, create_pins)?;

        if let Some(tip) = self.tip_height() {
            let _ = self.ensure_height_by_hash_index(tip);
        }
        self.record_confirmed_seqsigwit_window(items, durable)?;

        Ok(out)
    }

    #[doc(hidden)]
    pub fn record_confirmed_seqsigwit_window(
        &self,
        items: &[ConfirmPrepared],
        durable: Option<Height>,
    ) -> Result<(), QueryError> {
        self.prune_seqsigwit_below(durable)?;
        if !self.prune_seqsigwit() {
            return Ok(());
        }
        for item in items {
            self.note_seqsigwit_ram_for_confirmed(item.height, &item.tx_fks)?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn enqueue_sh_pending(
        &self,
        items: &[ConfirmPrepared],
        create_pins: Option<&crate::FkMap<CreatePin>>,
    ) -> Result<(), QueryError> {
        if !self.enqueues_sh_writebehind() {
            return Ok(());
        }
        let through = self.sh_indexed_through_height();
        let mut jobs = Vec::new();
        for item in items {
            if through.map(|t| item.height.0 <= t).unwrap_or(false) {
                continue;
            }
            let t_collect = std::time::Instant::now();
            let mut records: Vec<ScriptHashRecord> =
                Vec::with_capacity(item.tx_fks.len().saturating_mul(2));
            for &fk in &item.tx_fks {
                let pin = create_pins.and_then(|m| m.get(&fk));
                self.collect_scripthash_creates(fk, &mut records, pin)?;
            }
            self.confirm_stats().add_sh_part(
                &self.confirm_stats().sh_collect_ns,
                t_collect.elapsed().as_nanos() as u64,
            );
            jobs.push(ShPendingJob {
                height: item.height,
                header_fk: item.header_fk,
                records,
            });
        }
        if jobs.is_empty() {
            return Ok(());
        }
        let mut pending = self.sh.pending.lock().unwrap();
        let mut head = self.sh.ram_head.lock().unwrap();
        for job in &jobs {
            index_sh_ram_head(&mut head, job);
        }
        pending.extend(jobs);
        Ok(())
    }

    /// Allow index write-behind appenders to durable-apply through `through`.
    ///
    /// Enqueue publishes RAM records; seed waits for this so tip connect and
    /// block announce do not share disk with `locate_head`.
    pub fn release_index_writebehind(&self, through: Height) {
        let v = through.0.saturating_add(1);
        self.index_released_through.fetch_max(v, Ordering::Release);
        self.sh.pending_cv.notify_one();
        self.bf_wb.notify();
    }

    /// Last height durable apply is allowed to run (`None` until first release).
    pub fn index_released_through_height(&self) -> Option<u32> {
        let v = self.index_released_through.load(Ordering::Acquire);
        v.checked_sub(1)
    }

    #[doc(hidden)]
    pub fn release_queued_sh_writebehind(&self) {
        if let Some(h) = self.sh_pending_max_height() {
            self.release_index_writebehind(Height(h));
        }
    }

    #[doc(hidden)]
    pub fn clamp_index_released_before(&self, height: Height) {
        let cap = height.0;
        loop {
            let cur = self.index_released_through.load(Ordering::Acquire);
            if cur <= cap {
                return;
            }
            if self
                .index_released_through
                .compare_exchange(cur, cap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    #[doc(hidden)]
    pub fn sh_job_released(&self, job: &ShPendingJob) -> bool {
        let rel = self.index_released_through.load(Ordering::Acquire);
        rel > 0 && job.height.0.saturating_add(1) <= rel
    }

    pub fn pending_sh_create_fks(&self, scripthash: &[u8; 32]) -> Vec<Fk> {
        self.sh
            .ram_head
            .lock()
            .unwrap()
            .get(scripthash)
            .cloned()
            .unwrap_or_default()
    }

    pub fn sh_pending_max_height(&self) -> Option<u32> {
        let queued = self
            .sh
            .pending
            .lock()
            .unwrap()
            .iter()
            .map(|j| j.height.0)
            .max();
        let applying = self
            .sh
            .applying
            .lock()
            .unwrap()
            .as_ref()
            .map(|j| j.height.0);
        match (queued, applying) {
            (None, None) => None,
            (Some(a), None) | (None, Some(a)) => Some(a),
            (Some(a), Some(b)) => Some(a.max(b)),
        }
    }

    /// Durable watermark plus pending jobs (RAM records already collected),
    /// never above the live tip (reorg may leave pending jobs until mempool reaccept).
    pub fn sh_visible_through_height(&self) -> Option<u32> {
        let vis = self
            .sh_indexed_through_height()
            .max(self.sh_pending_max_height())?;
        self.tip_height().map(|tip| vis.min(tip.0))
    }

    /// Apply queued SH write-behind jobs in height order (one Class B appender).
    ///
    /// Production: the tip-follow worker. Tests / `Self::connect_block`: drain
    /// so SH history is visible immediately after the fixture connect.
    pub fn apply_sh_pending(&self) -> Result<(), QueryError> {
        self.release_queued_sh_writebehind();
        loop {
            if let Some(job) = self.take_sh_job_for_apply() {
                let height = job.height;
                let result = self.apply_sh_job(job.clone());
                if result.is_err() {
                    self.requeue_sh_job_front(job);
                }
                self.finish_sh_job(height);
                result?;
                continue;
            }
            let pending = self.sh.pending.lock().unwrap();
            let applying = self.sh.applying.lock().unwrap();
            if pending.is_empty() && applying.is_none() {
                return Ok(());
            }
            drop(applying);
            let _ = self
                .sh
                .pending_cv
                .wait_timeout(pending, std::time::Duration::from_millis(200))
                .unwrap();
        }
    }

    /// Pop queue → `sh.applying` so readers still join pending at live tip.
    pub fn take_sh_job_for_apply(&self) -> Option<ShPendingJob> {
        let mut pending = self.sh.pending.lock().unwrap();
        let mut applying = self.sh.applying.lock().unwrap();
        if applying.is_some() {
            return None;
        }
        let job = pending.front()?;
        if !self.sh_job_released(job) {
            return None;
        }
        let job = pending.pop_front()?;
        *applying = Some(job.clone());
        Some(job)
    }

    #[doc(hidden)]
    pub fn requeue_sh_job_front(&self, job: ShPendingJob) {
        self.sh.pending.lock().unwrap().push_front(job);
        self.sh.pending_cv.notify_one();
    }

    pub fn finish_sh_job(&self, height: Height) {
        let mut applying = self.sh.applying.lock().unwrap();
        if applying.as_ref().is_some_and(|j| j.height == height) {
            *applying = None;
        }
        self.sh.pending_cv.notify_all();
    }

    pub fn apply_sh_job(&self, job: ShPendingJob) -> Result<(), QueryError> {
        let applied = self.apply_sh_job_inner(&job)?;
        if applied {
            unindex_sh_ram_head(&mut self.sh.ram_head.lock().unwrap(), &job);
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn apply_sh_job_inner(&self, job: &ShPendingJob) -> Result<bool, QueryError> {
        let _appender = self.sh.appender.lock().unwrap();
        if !self.enqueues_sh_writebehind() {
            return Ok(false);
        }
        if self
            .sh_indexed_through_height()
            .is_some_and(|t| job.height.0 <= t)
        {
            return Ok(false);
        }
        if self.store.confirmed.get(job.height)? != Some(job.header_fk) {
            return Ok(false);
        }

        let sh_creates = &job.records;

        if !sh_creates.is_empty() {
            crate::note_confirm(&self.confirm_stats().sh_create_n, sh_creates.len() as u64);
            let mut uniq = std::collections::HashSet::with_capacity(sh_creates.len());
            for r in sh_creates {
                uniq.insert(r.scripthash);
            }
            crate::note_confirm(&self.confirm_stats().sh_unique_n, uniq.len() as u64);
        }

        let mut tip_sh_max_fk = 0u64;
        if !sh_creates.is_empty() {
            for r in sh_creates {
                tip_sh_max_fk = tip_sh_max_fk.max(r.create_tx_fk.0);
            }
            let (n, timing) = self.store.scripthash.put_create_batch_append(sh_creates)?;
            crate::note_confirm(&self.confirm_stats().sh_written_n, n as u64);
            let st = self.confirm_stats();
            st.add_sh_part(&st.sh_sort_ns, timing.sort_ns);
            st.add_sh_part(&st.sh_seed_ns, timing.seed_ns);
            st.add_sh_part(&st.sh_body_ns, timing.body_ns);
            st.add_sh_part(&st.sh_head_ns, timing.head_ns);
        }

        self.set_sh_indexed_through_height(Some(job.height.0));
        self.sh
            .applied_max_fk
            .fetch_max(tip_sh_max_fk, Ordering::AcqRel);
        self.advance_sh_include_hwm()?;
        Ok(true)
    }

    /// Sync the SH tables, then advance `include_hwm` (and SEAL) to the
    /// applied max create fk.
    ///
    /// `include_hwm` tells recovery which creates are already durable, so it
    /// must never lead the body/head bytes: a power cut after an unsynced
    /// append would otherwise lose those creates for good. Runs when no job
    /// waits behind this one (a tip block, or the end of a catch-up burst) or
    /// a second after the last advance; recovery replays the idempotent
    /// appends above a lagging HWM.
    #[doc(hidden)]
    pub fn advance_sh_include_hwm(&self) -> Result<(), QueryError> {
        const EVERY: std::time::Duration = std::time::Duration::from_secs(1);
        let want = self.sh.applied_max_fk.load(Ordering::Acquire);
        if want == 0 {
            return Ok(());
        }
        let queued = !self.sh.pending.lock().unwrap().is_empty();
        let mut last = self.sh.last_durable.lock().unwrap();
        if queued && last.elapsed() < EVERY {
            return Ok(());
        }
        if want <= self.store.scripthash.include_hwm() {
            return Ok(());
        }
        let t0 = std::time::Instant::now();
        self.store.scripthash.flush()?;
        let st = self.confirm_stats();
        crate::note_confirm(&st.sh_sync_ns, t0.elapsed().as_nanos() as u64);
        crate::note_confirm(&st.sh_sync_n, 1);
        self.store.scripthash.note_include_hwm(want)?;
        self.sh_run.publish_seal_watermark(want)?;
        *last = std::time::Instant::now();
        Ok(())
    }

    pub fn drop_sh_pending_from(&self, height: Height) {
        let mut pending = self.sh.pending.lock().unwrap();
        let dropped: Vec<ShPendingJob> = pending
            .iter()
            .filter(|job| job.height.0 >= height.0)
            .cloned()
            .collect();
        pending.retain(|job| job.height.0 < height.0);
        drop(pending);
        let mut applying = self.sh.applying.lock().unwrap();
        let applying_job = if applying.as_ref().is_some_and(|j| j.height.0 >= height.0) {
            applying.take()
        } else {
            None
        };
        drop(applying);
        {
            let mut head = self.sh.ram_head.lock().unwrap();
            for job in &dropped {
                unindex_sh_ram_head(&mut head, job);
            }
            if let Some(job) = applying_job.as_ref() {
                unindex_sh_ram_head(&mut head, job);
            }
        }
        self.clamp_index_released_before(height);
    }

    /// Restore SH watermark from durable `include_hwm` and re-queue heights the
    /// RAM write-behind lost on restart.
    pub fn recover_sh_writebehind(&self) -> Result<(), QueryError> {
        let recovered = self.recover_sh_indexed_through()?;
        self.set_sh_indexed_through_height(recovered);
        if !self.store.scripthash.has_durable_index() {
            return Ok(());
        }
        let Some(tip) = self.tip_height() else {
            return Ok(());
        };
        let from = recovered.map(|h| h.saturating_add(1)).unwrap_or(0);
        if from > tip.0 {
            return Ok(());
        }
        let mut items = Vec::new();
        for h in from..=tip.0 {
            let header_fk = self
                .store
                .confirmed
                .get(Height(h))?
                .ok_or(StoreError::Corrupt(
                    "invariant: confirmed height missing header",
                ))?;
            let tx_fks = match self.store.header_txs.get_list(header_fk)? {
                Some(tx_fks) => tx_fks,
                None if h == tip.0 => break,
                None => {
                    return Err(StoreError::Corrupt(
                        "invariant: confirmed height missing header_txs",
                    ));
                }
            };
            let hash = self.store.get_header(header_fk)?.hash;
            items.push(ConfirmPrepared {
                height: Height(h),
                header_fk,
                tx_fks,
                hash,
            });
        }
        if !items.is_empty() {
            self.enqueue_sh_pending(&items, None)?;
            if let Some(last) = items.last() {
                self.release_index_writebehind(last.height);
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn recover_sh_indexed_through(&self) -> Result<Option<u32>, QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(None);
        };
        let hwm = self.store.scripthash.include_hwm();
        if hwm == 0 {
            if self.store.scripthash.has_durable_index() {
                return Ok(Some(tip.0));
            }
            return Ok(None);
        }
        let mut h = tip.0;
        loop {
            let header_fk = self
                .store
                .confirmed
                .get(Height(h))?
                .ok_or(StoreError::Corrupt(
                    "invariant: confirmed height missing header",
                ))?;
            let fks = match self.store.header_txs.get_list(header_fk)? {
                Some(fks) => fks,
                None if h == tip.0 => {
                    if h == 0 {
                        return Ok(None);
                    }
                    h -= 1;
                    continue;
                }
                None => {
                    return Err(StoreError::Corrupt(
                        "invariant: confirmed height missing header_txs",
                    ));
                }
            };
            let max_fk = fks.iter().map(|f| f.0).max().unwrap_or(0);
            if max_fk <= hwm {
                return Ok(Some(h));
            }
            if h == 0 {
                return Ok(None);
            }
            h -= 1;
        }
    }

    /// Collect thin scripthash create pointers for one tx's outputs (no spend marks).
    ///
    /// Source order (first hit wins):
    /// 1. **Write-batch CreatePin** — outs already on the confirm write path
    /// 2. **Cold store** — Class A body pread/decode
    ///
    /// Same-batch creates must hit (1) or SH collect re-reads every body.
    /// `write_pin` is the pin Arc for this `tx_fk` when the write path has it.
    pub fn collect_scripthash_creates(
        &self,
        tx_fk: Fk,
        out: &mut Vec<ScriptHashRecord>,
        write_pin: Option<&CreatePin>,
    ) -> Result<(), QueryError> {
        if let Some(pin) = write_pin {
            pin.for_each_script(|script| {
                out.push(ScriptHashRecord::from_fk(script_hash(script), tx_fk));
            });
            crate::note_confirm(&self.confirm_stats().sh_collect_pin, 1);
            return Ok(());
        }
        let outputs = self.tx_output_run_class_a(tx_fk)?;
        if outputs.is_empty() {
            crate::note_confirm(&self.confirm_stats().sh_collect_cold, 1);
            return Ok(());
        }
        for o in outputs.iter() {
            out.push(ScriptHashRecord::from_fk(script_hash(&o.script), tx_fk));
        }
        crate::note_confirm(&self.confirm_stats().sh_collect_cold, 1);
        Ok(())
    }

    /// Input run keyed by known create fk (packed body works without `tx.head`).
    pub fn tx_input_run_class_a(
        &self,
        create_fk: Fk,
        tx: &TxRecord,
    ) -> Result<Vec<InputRecord>, QueryError> {
        if tx.input_count == 0 {
            return Ok(Vec::new());
        }
        let inputs = if let Some(v) = self.seqsigwit_cached_inputs(create_fk, tx.input_count)? {
            v
        } else {
            let (_, inputs, _) = self.store.get_tx_full(create_fk)?;
            inputs
        };
        if inputs.len() as u32 != tx.input_count {
            return Err(StoreError::Corrupt("packed input count mismatch"));
        }
        Ok(inputs)
    }

    /// Output run from store (keyed by known create fk — no txid lookup).
    ///
    /// Outs-only Class A (`get_tx_meta_and_outputs`); does not zip `seqsigwit`.
    pub fn tx_output_run_class_a(&self, create_fk: Fk) -> Result<Vec<OutputRecord>, QueryError> {
        let (_meta, outs) = self.store.get_tx_meta_and_outputs(create_fk)?;
        Ok(outs)
    }

    /// Disconnect the current tip (Class C + scripthash create unlink; archive remains).
    ///
    /// Durable point edges remain for archive history; strong bits cleared below.
    ///
    /// # Crash order (**tip first** — opposite of connect)
    ///
    /// 1. SH unlink (index only; filtered by strong+tip at query time).
    /// 2. `confirmed` truncate in RAM → **`flush_confirmed_only`** (durable tip shrink).
    /// 3. Then `set_unstrong` for disconnected txs → flush strong.
    ///
    /// Unstrong-before-tip would make tip txs fail `is_confirmed_strong` while
    /// tip is still high (permanent if kill). Mid-kill after tip shrink leaves
    /// strong **not on the new fence** → `repair_class_c_above_tip` heals.
    ///
    /// Logs [`format_disconnect_tip_line`] at **warn** before the scripthash
    /// unlink and again after the tip shrink commits.
    pub fn disconnect_tip(&self) -> Result<(), QueryError> {
        let _commit = self.lock_tip_commit()?;
        self.disconnect_tip_body(true)
    }

    /// [`Self::disconnect_tip`] for a caller that already holds
    /// [`Self::lock_tip_commit`].
    pub fn disconnect_tip_in_commit(&self) -> Result<(), QueryError> {
        self.disconnect_tip_body(true)
    }

    /// Class C disconnect without dropping RAM SH pending (reorg reaccept first).
    pub fn disconnect_tip_keep_pending(&self) -> Result<(), QueryError> {
        let _commit = self.lock_tip_commit()?;
        self.disconnect_tip_body(false)
    }

    /// [`Self::disconnect_tip_keep_pending`] for a caller that already holds
    /// [`Self::lock_tip_commit`].
    pub fn disconnect_tip_keep_pending_in_commit(&self) -> Result<(), QueryError> {
        self.disconnect_tip_body(false)
    }

    #[doc(hidden)]
    pub fn disconnect_tip_body(&self, drop_pending: bool) -> Result<(), QueryError> {
        let _utxo_view = self.store.hold_utxo_view();
        let height = self
            .tip_height()
            .ok_or(StoreError::Corrupt("no tip to disconnect"))?;
        self.forget_bip34_ancestor_if_reorged(height.0);
        self.require_seqsigwit_at(height)?;
        self.drop_seqsigwit_ram_height(height.0);
        let _appender = self.sh.appender.lock().unwrap();
        let _bf_appender = self.bf_wb.lock_appender();
        if drop_pending {
            self.drop_sh_pending_from(height);
        } else {
            self.clamp_index_released_before(height);
        }
        let disconnected = self.header_at_height(height)?.map(|(_, rec)| rec);
        let hash = disconnected
            .as_ref()
            .map(|rec| rec.hash)
            .unwrap_or([0u8; 32]);
        let tx_fks = self.block_tx_fks(height)?;

        log_disconnect_tip(height.0, &hash, tx_fks.len());
        let mut by_sh: HashMap<[u8; 32], Vec<Fk>> = HashMap::new();
        for &tx_fk in &tx_fks {
            let outputs = self.tx_output_run_class_a(tx_fk)?;
            for o in &outputs {
                by_sh.entry(script_hash(&o.script)).or_default().push(tx_fk);
            }
        }
        let mut groups: Vec<([u8; 32], Vec<Fk>)> = Vec::with_capacity(by_sh.len());
        for (sh, mut fks) in by_sh {
            fks.sort_by_key(|fk| fk.0);
            fks.dedup();
            groups.push((sh, fks));
        }
        self.store.scripthash.unlink_creates_batch(&groups)?;

        let write = rbitcoin_store::ClassCWrite::new();
        self.store.confirmed.disconnect_tip(&write, height)?;
        self.store.height_fence_pop_tip(height);
        self.note_disconnect_height(height.0);
        let _ = self.on_load_pack();
        if let Some(new_tip) = self.tip_height() {
            let (_, rec) = self
                .header_at_height(new_tip)?
                .ok_or(StoreError::Corrupt("disconnect left a tip with no header"))?;
            self.publish_confirmed_tip(new_tip.0, rec.hash);
            let _ = self.ensure_height_by_hash_index(new_tip);
        } else {
            self.clear_published_tip();
            self.invalidate_height_by_hash_index();
        }
        self.store.flush_confirmed_only()?;
        self.sealed_tip.shrunk_to(self.tip_height());
        self.store.scripthash.commit_deferred_empty_heads()?;
        self.store.clamp_spend_durable()?;
        log_disconnect_tip(height.0, &hash, tx_fks.len());

        for &tx_fk in &tx_fks {
            self.store.strong_tx.set_unstrong(&write, tx_fk)?;
        }
        self.store.flush_class_c_after_disconnect_tip()?;

        if self.sh_indexed_through_height() == Some(height.0) {
            self.set_sh_indexed_through_height(self.tip_height().map(|h| h.0));
        }
        self.truncate_sp_tweaks_through_tip(self.tip_height())?;
        self.truncate_basic_filters_to_tip()?;
        if disconnected.is_some() {
            self.disconnected
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(hash);
        }
        Ok(())
    }

    fn forget_reconnected<'a>(&self, hashes: impl Iterator<Item = &'a [u8; 32]>) {
        let mut disconnected = self.disconnected.lock().unwrap_or_else(|e| e.into_inner());
        if disconnected.is_empty() {
            return;
        }
        for hash in hashes {
            disconnected.remove(hash);
        }
    }

    /// This process connected `hash` and later disconnected it.
    pub fn was_disconnected(&self, hash: &[u8; 32]) -> bool {
        self.disconnected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(hash)
    }
}

/// Operator line for one confirmed-block disconnect (reorg / restore).
///
/// Hash is Core display-order hex (`BlockHash` `Display`).
pub fn format_disconnect_tip_line(height: u32, hash: &[u8; 32], tx_count: usize) -> String {
    let hash = BlockHash::from_byte_array(*hash);
    format!("DisconnectTip: hash={hash} height={height} tx={tx_count}")
}

#[doc(hidden)]
pub fn log_disconnect_tip(height: u32, hash: &[u8; 32], tx_count: usize) {
    rbitcoin_log::warn!("{}", format_disconnect_tip_line(height, hash, tx_count));
}

pub fn request_sh_writebehind_halt(
    stop: &std::sync::atomic::AtomicBool,
    h: u32,
    e: &impl std::fmt::Display,
) {
    rbitcoin_log::error!("scripthash write-behind h={h}: {e}");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Class B scripthash appender. The builder name is `rbtc-sh-wb`.
pub struct ShWritebehind {
    join: std::thread::JoinHandle<()>,
    #[cfg(target_os = "linux")]
    os_tid: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(target_os = "linux")]
    published: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl ShWritebehind {
    pub fn join(self) -> std::thread::Result<()> {
        self.join.join()
    }

    pub fn thread(&self) -> &std::thread::Thread {
        self.join.thread()
    }

    /// Linux tid after the appender has published it. The name is already set.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn wait_published(&self, timeout: std::time::Duration) -> Option<u64> {
        let (lock, cv) = &*self.published;
        let mut ready = lock.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if *ready {
                let tid = self.os_tid.load(std::sync::atomic::Ordering::Acquire);
                return (tid != 0).then_some(tid);
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            let (guard, status) = cv
                .wait_timeout(ready, left)
                .unwrap_or_else(|e| e.into_inner());
            ready = guard;
            if status.timed_out() && !*ready {
                return None;
            }
        }
    }
}

/// One Class B appender for SH write-behind. Tests drain via [`Query::apply_sh_pending`].
///
/// Apply errors request `stop` and `on_fatal` so the process exits instead of
/// leaving a dead worker with a growing pending queue.
pub fn spawn_sh_writebehind(
    query: std::sync::Arc<Query>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    on_fatal: impl FnOnce() + Send + 'static,
) -> ShWritebehind {
    #[cfg(target_os = "linux")]
    let os_tid = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    #[cfg(target_os = "linux")]
    let published = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    #[cfg(target_os = "linux")]
    let thread_tid = std::sync::Arc::clone(&os_tid);
    #[cfg(target_os = "linux")]
    let thread_published = std::sync::Arc::clone(&published);
    let join = std::thread::Builder::new()
        .name("rbtc-sh-wb".into())
        .spawn(move || {
            #[cfg(target_os = "linux")]
            if let Some(tid) = linux_task_id() {
                thread_tid.store(tid, std::sync::atomic::Ordering::Release);
                let (lock, cv) = &*thread_published;
                *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
                cv.notify_all();
            }
            let mut on_fatal = Some(on_fatal);
            loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let job = loop {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    if let Some(job) = query.take_sh_job_for_apply() {
                        break job;
                    }
                    let g = query.sh.pending.lock().unwrap();
                    let (g2, wait) = query
                        .sh
                        .pending_cv
                        .wait_timeout(g, std::time::Duration::from_millis(200))
                        .unwrap();
                    drop(g2);
                    if wait.timed_out() {
                        continue;
                    }
                };
                let t0 = std::time::Instant::now();
                let h = job.height.0;
                let height = job.height;
                let apply_err = query.apply_sh_job(job.clone()).err();
                if let Some(e) = apply_err {
                    query.requeue_sh_job_front(job);
                    query.finish_sh_job(height);
                    request_sh_writebehind_halt(&stop, h, &e);
                    if let Some(f) = on_fatal.take() {
                        f();
                    }
                    return;
                }
                query.finish_sh_job(height);
                let wall_ms = t0.elapsed().as_millis();
                let lag = query.sh_lag_heights();
                rbitcoin_log::info!("sh: apply h={h} wall={wall_ms}ms lag={lag}");
            }
        })
        .expect("spawn sh write-behind");
    ShWritebehind {
        join,
        #[cfg(target_os = "linux")]
        os_tid,
        #[cfg(target_os = "linux")]
        published,
    }
}
