//! Growable dense array of little-endian `u64` values, 0-based.
//!
//! `confirmed` and `header_txs_*` load into RAM up to [`class_c_inram_max_bytes`];
//! `strong_tx` is one anonymous reservation of that cap and commits the used
//! prefix. Stores update live slots. `flush` writes those
//! slots in [`FLUSH_SCRATCH`] chunks and clears the unstored mark only after the
//! persist succeeds. A clean table returns before new stores are excluded. Over
//! the cap, tables stay fd write-through: an append pwrites the new slots
//! (a zero gap fills that span first), then the file length, then `len`.
//! In-RAM gets take no reader-writer lock.
//! Counter order is the Class C paragraph of `docs/concurrency.md`.

use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::sync::atomic::{self, AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use rbitcoin_primitives::TableKind;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Mutex;

/// Debug builds pause the IBD tip-flush thread here when a test armed the hold.
/// The pause is after `seq_arm`, so a store on another thread sees `flushing`.
#[cfg(debug_assertions)]
mod flush_hold {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    thread_local! {
        static HOLD: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
    }

    pub(super) fn bind(hold: Option<Arc<AtomicBool>>) {
        HOLD.with(|slot| *slot.borrow_mut() = hold);
    }

    pub(super) fn wait() {
        let Some(hold) = HOLD.with(|slot| slot.borrow().clone()) else {
            return;
        };
        while hold.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

/// Install the IBD tip-flush hold on this thread. [`ArrayTable::flush`] waits
/// after it excludes stores. Release builds have no hold.
#[doc(hidden)]
#[cfg(debug_assertions)]
pub fn bind_tip_flush_hold(hold: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>) {
    flush_hold::bind(hold);
}

/// Minted on the storing thread (`!Send` + `!Sync`). A shared store cannot
/// carry this value onto another thread. It does not stop that thread from
/// minting its own. The sequence counter's even-to-odd exchange is what keeps
/// two stores out of one image. Confirm-write, tip-accept, and startup each
/// mint one. The flush thread reads live slots and does not take it.
#[derive(Default)]
pub struct ClassCWrite(PhantomData<*const ()>);

impl ClassCWrite {
    /// Mint a writer capability on the calling thread.
    pub fn new() -> Self {
        Self(PhantomData)
    }

    /// Same as [`Self::new`]. Tests are not the confirm-write thread.
    #[doc(hidden)]
    pub fn for_test() -> Self {
        Self::new()
    }
}

#[doc(hidden)]
pub const ELEM: u64 = 8;

/// Bytes of the fixed pwrite buffer. A flush does not allocate a second image.
#[doc(hidden)]
pub const FLUSH_SCRATCH: usize = 4096;

const CLEAN: u64 = u64::MAX;

/// Where a flush calls its test hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum FlushStep {
    /// Dirty, before new stores are excluded. A store here belongs in this flush.
    Admit,
    /// After the range is recorded, before the write.
    Write,
    /// After the persist, before the unstored mark clears.
    Clean,
}

/// Default max body size for L2 InRam (256 MiB). Over → pure FdOnly L0.
pub const DEFAULT_CLASS_C_INRAM_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Cap for loading Class C arrays into process RAM.
///
/// Env: `RBITCOIN_CLASS_C_INRAM_MAX_MB` (integer MiB). Unset → 256 MiB.
pub fn class_c_inram_max_bytes() -> u64 {
    match std::env::var("RBITCOIN_CLASS_C_INRAM_MAX_MB") {
        Ok(s) => {
            let mb: u64 = s.trim().parse().unwrap_or(256);
            mb.saturating_mul(1024 * 1024)
        }
        Err(_) => DEFAULT_CLASS_C_INRAM_MAX_BYTES,
    }
}

/// Copy `dst.len()` bytes from packed words at byte `start`.
pub(crate) fn copy_bit_bytes(words: &[AtomicU64], start: usize, dst: &mut [u8]) {
    let mut i = 0;
    while i < dst.len() {
        let abs = start + i;
        let packed = words[abs / 8].load(Ordering::Relaxed).to_le_bytes();
        let off = abs % 8;
        let n = (8 - off).min(dst.len() - i);
        dst[i..i + n].copy_from_slice(&packed[off..off + n]);
        i += n;
    }
}

struct Buf {
    slots: Box<[AtomicU64]>,
    /// Previous buffer. Growth publishes `slots` first; this box keeps the old
    /// pointer until the table drops.
    prev: Option<Box<Buf>>,
}

/// In-RAM `u64` slots. A slot table keeps the previous buffer on the new box.
/// `strong_tx` uses [`BitReserve`] instead: one mapping, no retired copy.
pub(crate) struct RamSlots {
    ptr: AtomicPtr<Buf>,
    reserve: Option<BitReserve>,
}

/// Anonymous reservation for the strong-bit image. The base does not move.
struct BitReserve {
    base: AtomicPtr<u8>,
    cap: usize,
    committed: AtomicUsize,
}

impl Drop for RamSlots {
    fn drop(&mut self) {
        if let Some(reserve) = self.reserve.take() {
            release_reserve(reserve.base.load(Ordering::Relaxed), reserve.cap);
            return;
        }
        let p = self.ptr.load(Ordering::Relaxed);
        if p.is_null() {
            return;
        }
        // SAFETY: `p` came from `Box::into_raw`. Dropping `prev` frees every
        // buffer this table published.
        drop(unsafe { Box::from_raw(p) }.prev);
    }
}

impl RamSlots {
    pub(crate) fn empty() -> Self {
        Self {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
            reserve: None,
        }
    }

    pub(crate) fn from_values(values: Vec<u64>) -> Self {
        let buf = Box::new(Buf {
            slots: values.into_iter().map(AtomicU64::new).collect(),
            prev: None,
        });
        Self {
            ptr: AtomicPtr::new(Box::into_raw(buf)),
            reserve: None,
        }
    }

    /// Reserve `cap` bytes. Nothing is committed until [`Self::grow`].
    pub(crate) fn reserve(cap: usize) -> Result<Self, StoreError> {
        let cap = cap.max(page_size());
        let base = map_reserve(cap)?;
        Ok(Self {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
            reserve: Some(BitReserve {
                base: AtomicPtr::new(base),
                cap,
                committed: AtomicUsize::new(0),
            }),
        })
    }

    pub(crate) fn grow(&self, need: usize) -> Result<(), StoreError> {
        if let Some(reserve) = &self.reserve {
            return reserve.commit_words(need);
        }
        let cur = self.ptr.load(Ordering::Relaxed);
        // SAFETY: `cur` is null or a box this writer published. The copy finishes
        // before `from_raw` moves that box onto the new buffer.
        let old = unsafe { cur.as_ref().map(|buf| &buf.slots[..]) };
        let cap = old.map_or(0, |slots| slots.len());
        if old.is_some() && need <= cap {
            return Ok(());
        }
        let new_cap = if cap == 0 {
            need.max(1).next_power_of_two()
        } else {
            cap.saturating_mul(2).max(need)
        };
        let slots: Box<[AtomicU64]> = (0..new_cap)
            .map(|i| {
                let v = old
                    .and_then(|s| s.get(i))
                    .map_or(0, |a| a.load(Ordering::Relaxed));
                AtomicU64::new(v)
            })
            .collect();
        let prev = (!cur.is_null()).then(|| {
            // SAFETY: `cur` came from `Box::into_raw` on this writer.
            unsafe { Box::from_raw(cur) }
        });
        let buf = Box::into_raw(Box::new(Buf { slots, prev }));
        self.ptr.store(buf, Ordering::Release);
        Ok(())
    }

    /// Writer (Relaxed) or flush (Acquire), after the buffer covers the index.
    pub(crate) fn slots(&self, order: Ordering) -> &[AtomicU64] {
        if let Some(reserve) = &self.reserve {
            return reserve.words(order);
        }
        let ptr = self.ptr.load(order);
        // SAFETY: caller indexes a buffer this table still owns.
        unsafe { &(*ptr).slots }
    }

    /// Committed bytes of a strong-bit reservation, or the published box.
    pub(crate) fn committed_bytes(&self) -> u64 {
        if let Some(reserve) = &self.reserve {
            return reserve.committed.load(Ordering::Relaxed) as u64;
        }
        let ptr = self.ptr.load(Ordering::Relaxed);
        if ptr.is_null() {
            return 0;
        }
        // SAFETY: `ptr` is a box this table published.
        let slots = unsafe { &(*ptr).slots };
        slots.len() as u64 * 8
    }

    /// `None` when the published buffer is missing or shorter than `need`.
    /// A torn length can name a slot this buffer does not have.
    pub(crate) fn try_slots(&self, need: usize) -> Option<&[AtomicU64]> {
        if let Some(reserve) = &self.reserve {
            let words = reserve.words(Ordering::Acquire);
            return (words.len() >= need).then_some(words);
        }
        let ptr = self.ptr.load(Ordering::Acquire);
        // SAFETY: growth keeps every published buffer until this table drops.
        let buf = unsafe { ptr.as_ref() }?;
        (buf.slots.len() >= need).then_some(&buf.slots)
    }
}

impl BitReserve {
    fn commit_words(&self, need_words: usize) -> Result<(), StoreError> {
        let page = page_size();
        let bytes = need_words.saturating_mul(8);
        let bytes = bytes.div_ceil(page).saturating_mul(page);
        let cur = self.committed.load(Ordering::Relaxed);
        if bytes <= cur {
            return Ok(());
        }
        if bytes > self.cap {
            return Err(StoreError::Corrupt(
                "strong bit image exceeds the reservation",
            ));
        }
        commit_prefix(self.base.load(Ordering::Relaxed), bytes)?;
        self.committed.store(bytes, Ordering::Release);
        Ok(())
    }

    fn words(&self, order: Ordering) -> &[AtomicU64] {
        let n = self.committed.load(order) / 8;
        if n == 0 {
            return &[];
        }
        let base = self.base.load(Ordering::Relaxed) as *const AtomicU64;
        // SAFETY: `commit_words` published `n` aligned words at `base`. The
        // mapping lives until this table drops, and the base does not move.
        unsafe { std::slice::from_raw_parts(base, n) }
    }
}

/// Page size the strong-bit reservation commits in.
#[doc(hidden)]
pub fn class_c_commit_quantum() -> u64 {
    page_size() as u64
}

fn page_size() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        #[cfg(unix)]
        {
            // SAFETY: `sysconf` takes a constant and returns the page size.
            let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if n <= 0 {
                4096
            } else {
                n as usize
            }
        }
        #[cfg(not(unix))]
        {
            4096
        }
    })
}

#[cfg(unix)]
fn map_reserve(cap: usize) -> Result<*mut u8, StoreError> {
    // SAFETY: anonymous private mapping. Pages stay inaccessible until commit.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            cap,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(StoreError::Corrupt("strong bit reservation failed"));
    }
    Ok(ptr.cast())
}

#[cfg(unix)]
fn commit_prefix(base: *mut u8, bytes: usize) -> Result<(), StoreError> {
    if bytes == 0 {
        return Ok(());
    }
    // SAFETY: `base`/`bytes` is a page-aligned prefix of this reservation.
    let rc = unsafe { libc::mprotect(base.cast(), bytes, libc::PROT_READ | libc::PROT_WRITE) };
    if rc != 0 {
        return Err(StoreError::Corrupt("strong bit commit failed"));
    }
    Ok(())
}

#[cfg(unix)]
fn release_reserve(base: *mut u8, cap: usize) {
    if base.is_null() || cap == 0 {
        return;
    }
    // SAFETY: `base`/`cap` came from `map_reserve` for this table.
    unsafe {
        libc::munmap(base.cast(), cap);
    }
}

#[cfg(windows)]
fn map_reserve(cap: usize) -> Result<*mut u8, StoreError> {
    // SAFETY: reserve the address range. Commit happens in `commit_prefix`.
    let ptr = unsafe { VirtualAlloc(std::ptr::null_mut(), cap, MEM_RESERVE, PAGE_NOACCESS) };
    if ptr.is_null() {
        return Err(StoreError::Corrupt("strong bit reservation failed"));
    }
    Ok(ptr.cast())
}

#[cfg(windows)]
fn commit_prefix(base: *mut u8, bytes: usize) -> Result<(), StoreError> {
    if bytes == 0 {
        return Ok(());
    }
    // SAFETY: `base` is inside the reservation. `bytes` is page-aligned.
    let ptr = unsafe { VirtualAlloc(base.cast(), bytes, MEM_COMMIT, PAGE_READWRITE) };
    if ptr.is_null() {
        return Err(StoreError::Corrupt("strong bit commit failed"));
    }
    Ok(())
}

#[cfg(windows)]
fn release_reserve(base: *mut u8, _cap: usize) {
    if base.is_null() {
        return;
    }
    // SAFETY: `base` came from `VirtualAlloc` with `MEM_RESERVE`.
    unsafe {
        VirtualFree(base.cast(), 0, MEM_RELEASE);
    }
}

#[cfg(windows)]
const MEM_COMMIT: u32 = 0x1000;
#[cfg(windows)]
const MEM_RESERVE: u32 = 0x2000;
#[cfg(windows)]
const MEM_RELEASE: u32 = 0x8000;
#[cfg(windows)]
const PAGE_NOACCESS: u32 = 0x01;
#[cfg(windows)]
const PAGE_READWRITE: u32 = 0x04;

#[cfg(windows)]
extern "system" {
    fn VirtualAlloc(
        addr: *mut std::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut std::ffi::c_void;
    fn VirtualFree(addr: *mut std::ffi::c_void, size: usize, free_type: u32) -> i32;
}

#[cfg(not(any(unix, windows)))]
fn map_reserve(_cap: usize) -> Result<*mut u8, StoreError> {
    Err(StoreError::Corrupt("strong bit reservation failed"))
}

#[cfg(not(any(unix, windows)))]
fn commit_prefix(_base: *mut u8, _bytes: usize) -> Result<(), StoreError> {
    Err(StoreError::Corrupt("strong bit commit failed"))
}

#[cfg(not(any(unix, windows)))]
fn release_reserve(_base: *mut u8, _cap: usize) {}

/// Evens the counter on drop. The raw pointer keeps the guard from holding
/// a field borrow across the slot stores. An fd-only store holds `None`.
pub(crate) struct SeqOdd(*const AtomicU64);

impl Drop for SeqOdd {
    fn drop(&mut self) {
        // SAFETY: the pointer is the counter just borrowed. The guard does not outlive that table.
        unsafe { &*self.0 }.fetch_add(1, Ordering::Release);
    }
}

/// Order is the Class C paragraph of `docs/concurrency.md`. Loom 0.7 does
/// not order `SeqCst` accesses; the two `SeqCst` fences do.
pub(crate) fn seq_begin(seq: &AtomicU64, flushing: &AtomicBool) -> Result<SeqOdd, StoreError> {
    if flushing.load(Ordering::SeqCst) {
        return Err(StoreError::Rejected("class C store during flush"));
    }
    claim_odd(seq);
    atomic::fence(Ordering::SeqCst);
    if flushing.load(Ordering::SeqCst) {
        seq.fetch_add(1, Ordering::SeqCst);
        return Err(StoreError::Rejected("class C store during flush"));
    }
    atomic::fence(Ordering::Release);
    Ok(SeqOdd(seq as *const AtomicU64))
}

/// Header pairs have no flush flag. Same odd-then-fence order as [`seq_begin`].
pub(crate) fn seq_odd(seq: &AtomicU64) -> SeqOdd {
    claim_odd(seq);
    atomic::fence(Ordering::Release);
    SeqOdd(seq as *const AtomicU64)
}

/// Even to odd. A loser waits. The release fence after this is what publishes
/// the slot stores; this exchange does not.
fn claim_odd(seq: &AtomicU64) {
    loop {
        let cur = seq.load(Ordering::SeqCst);
        if cur & 1 == 1 {
            crate::sync::spin();
            continue;
        }
        if seq
            .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return;
        }
    }
}

pub(crate) fn seq_arm(seq: &AtomicU64, flushing: &AtomicBool) {
    loop {
        let g1 = seq.load(Ordering::SeqCst);
        if g1 & 1 != 0 {
            crate::sync::spin();
            continue;
        }
        flushing.store(true, Ordering::SeqCst);
        atomic::fence(Ordering::SeqCst);
        if seq.load(Ordering::SeqCst) == g1 {
            return;
        }
        while seq.load(Ordering::SeqCst) & 1 != 0 {
            crate::sync::spin();
        }
    }
}

/// On success, disk length and the clean mark publish before `flushing` clears.
/// Fields are the flag, the disk length, the unstored mark, and the persisted length.
#[must_use]
struct FlushGuard<'a>(&'a AtomicBool, &'a AtomicU64, &'a AtomicU64, Option<u64>);

impl Drop for FlushGuard<'_> {
    fn drop(&mut self) {
        if let Some(n) = self.3 {
            self.1.store(n, Ordering::Release);
            self.2.store(u64::MAX, Ordering::Release);
        }
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Acquire fence, then the counter. See `docs/concurrency.md`.
pub(crate) fn seq_holds(seq: &AtomicU64, g1: u64) -> bool {
    atomic::fence(Ordering::Acquire);
    seq.load(Ordering::Relaxed) == g1
}

/// `sample` returns `None` to retry this even generation. `Some` is accepted
/// only when the counter is still `g1` after the acquire fence.
pub(crate) fn seq_read<T>(seq: &AtomicU64, mut sample: impl FnMut() -> Option<T>) -> T {
    loop {
        let g1 = seq.load(Ordering::Acquire);
        if g1 & 1 != 0 {
            crate::sync::spin();
            continue;
        }
        if let Some(v) = sample() {
            if seq_holds(seq, g1) {
                return v;
            }
        } else if seq_holds(seq, g1) {
            crate::sync::spin();
        }
    }
}

pub struct ArrayTable {
    pub file: TableFile,
    pub len: AtomicU64,
    /// False = L0 fd-only. Never changes after `new`.
    in_ram: bool,
    /// `len` and `disk_len` count body bytes, and `unstored_from` is a bit.
    /// Slot tables count elements. `strong_tx` is the byte table.
    byte_body: bool,
    pub(crate) slots: RamSlots,
    /// Even means the slots and `len` published together are complete.
    pub(crate) seq: AtomicU64,
    /// Lowest index not yet persisted. `u64::MAX` means none.
    pub unstored_from: AtomicU64,
    /// True from the moment a flush records its range until it returns.
    pub flushing: AtomicBool,
    /// Length last flushed. Elements, or body bytes when `byte_body` is set.
    pub disk_len: AtomicU64,
    /// One flusher at a time.
    pub flush_lock: Mutex<()>,
    /// Largest chunk the last flush passed to `write_at`.
    #[doc(hidden)]
    pub flush_chunk_max: AtomicUsize,
}

impl ArrayTable {
    pub fn create(path: impl AsRef<Path>, kind: TableKind) -> Result<Self, StoreError> {
        let file = TableFile::create(path.as_ref(), kind)?;
        Ok(Self::new(file, Some(Vec::new()), 0, false))
    }

    pub fn open(path: impl AsRef<Path>, kind: TableKind) -> Result<Self, StoreError> {
        let file = TableFile::open(path.as_ref(), kind)?;
        let body = file.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body % ELEM != 0 {
            return Err(StoreError::Corrupt("array table size"));
        }
        let n = body / ELEM;
        let data = if body <= class_c_inram_max_bytes() {
            let mut v = vec![0u64; n as usize];
            if n > 0 {
                let mut bytes = vec![0u8; body as usize];
                file.read_at(FILE_HEADER_LEN as u64, &mut bytes)?;
                for (i, chunk) in bytes.chunks_exact(8).enumerate() {
                    v[i] = u64::from_le_bytes(chunk.try_into().unwrap());
                }
            }
            Some(v)
        } else {
            None
        };
        Ok(Self::new(file, data, n, false))
    }

    /// In-RAM bit image. `bytes` is the body length and is not rounded to a word.
    /// The mapping is the 256 MiB cap. A grow commits the used prefix only.
    pub(crate) fn bit_image(file: TableFile, bytes: u64) -> Result<Self, StoreError> {
        let mut table = Self::new(file, None, bytes, true);
        table.slots = RamSlots::reserve(DEFAULT_CLASS_C_INRAM_MAX_BYTES as usize)?;
        Ok(table)
    }

    fn new(file: TableFile, data: Option<Vec<u64>>, n: u64, byte_body: bool) -> Self {
        let in_ram = byte_body || data.is_some();
        Self {
            file,
            len: AtomicU64::new(n),
            in_ram,
            byte_body,
            slots: data.map_or_else(RamSlots::empty, RamSlots::from_values),
            seq: AtomicU64::new(0),
            unstored_from: AtomicU64::new(CLEAN),
            flushing: AtomicBool::new(false),
            disk_len: AtomicU64::new(n),
            flush_lock: Mutex::new(()),
            flush_chunk_max: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> u64 {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[doc(hidden)]
    pub fn offset(index: u64) -> u64 {
        FILE_HEADER_LEN as u64 + index * ELEM
    }

    pub(crate) fn begin_store(&self) -> Result<SeqOdd, StoreError> {
        if self.in_ram {
            return seq_begin(&self.seq, &self.flushing);
        }
        Ok(seq_odd(&self.seq))
    }

    fn mark_unstored(&self, index: u64) {
        let _ = self.unstored_from.fetch_min(index, Ordering::AcqRel);
    }

    pub fn get(&self, index: u64) -> Result<u64, StoreError> {
        Ok(self.get_sample(index)?.0)
    }

    /// One slot, with no sequence counter. A header pair checks its own counter
    /// after both columns; an inner check would accept one column early.
    pub(crate) fn peek_slot(&self, index: u64) -> Result<Option<u64>, StoreError> {
        if !self.in_ram {
            return Ok(Some(self.get(index)?));
        }
        Ok(self.sample_ram(index, Ordering::Acquire).map(|(v, _)| v))
    }

    /// `(value, len)` from one even generation. `get` is the value.
    #[doc(hidden)]
    pub fn get_sample(&self, index: u64) -> Result<(u64, u64), StoreError> {
        if !self.in_ram {
            return self.get_sample_fd(index);
        }
        Ok(seq_read(&self.seq, || {
            self.sample_ram(index, Ordering::Relaxed)
        }))
    }

    /// Slots `index` and `index + 1`, and `len`, from one even generation.
    #[doc(hidden)]
    pub fn get_pair_sample(&self, index: u64) -> Result<([u64; 2], u64), StoreError> {
        if !self.in_ram {
            return self.fd_generation(|| {
                let (a, len) = self.pread_sample(index)?;
                let (b, _) = self.pread_sample(index + 1)?;
                Ok(([a, b], len))
            });
        }
        Ok(seq_read(&self.seq, || {
            let (a, len) = self.sample_ram(index, Ordering::Relaxed)?;
            let (b, _) = self.sample_ram(index + 1, Ordering::Relaxed)?;
            Some(([a, b], len))
        }))
    }

    fn get_sample_fd(&self, index: u64) -> Result<(u64, u64), StoreError> {
        self.fd_generation(|| self.pread_sample(index))
    }

    /// One even generation of fd reads. A result read while a store ran,
    /// error or not, is read again.
    fn fd_generation<T>(
        &self,
        mut sample: impl FnMut() -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        loop {
            let g1 = self.seq.load(Ordering::Acquire);
            if g1 & 1 != 0 {
                crate::sync::spin();
                continue;
            }
            let read = sample();
            if seq_holds(&self.seq, g1) {
                return read;
            }
        }
    }

    /// A truncate may shorten `len` and the file after the first load. The
    /// slot is empty when the reloaded length no longer covers it. A past-end
    /// pread whose length still covers the index stays an error.
    fn pread_sample(&self, index: u64) -> Result<(u64, u64), StoreError> {
        let len = self.len.load(Ordering::Acquire);
        if index >= len {
            return Ok((0, len));
        }
        // Loom branches before the load. `pread` is not a loom access, so the
        // model yields after `len` has covered `index` and before the read.
        #[cfg(loom)]
        loom::thread::yield_now();
        let mut buf = [0u8; 8];
        let value = match self.file.read_at(Self::offset(index), &mut buf) {
            Ok(()) => Some(u64::from_le_bytes(buf)),
            Err(StoreError::Corrupt("pread past logical end")) => None,
            Err(e) => return Err(e),
        };
        let len = self.len.load(Ordering::Acquire);
        if index >= len {
            return Ok((0, len));
        }
        match value {
            Some(value) => Ok((value, len)),
            None => Err(StoreError::Corrupt("pread past logical end")),
        }
    }

    /// `None` when the published buffer is shorter than `index`. Past `len` is
    /// `(0, len)`, not a missing slot.
    fn sample_ram(&self, index: u64, order: Ordering) -> Option<(u64, u64)> {
        let len = self.len.load(Ordering::Relaxed);
        if index >= len {
            return Some((0, len));
        }
        let slots = self.slots.try_slots(index as usize + 1)?;
        Some((slots[index as usize].load(order), len))
    }

    /// Overwrite `index < len`, or append `index == len`. A higher index is
    /// corrupt: the buffer can still hold bytes above `len` after a truncate.
    pub fn set(&self, write: &ClassCWrite, index: u64, value: u64) -> Result<(), StoreError> {
        self.write_slots(write, index, index, &[(index, value)], false)
    }

    /// Like [`Self::set`], and indexes from `len` up to `index` that this call
    /// does not name become zero. Header ranges use this. A failed header can
    /// sit between two bodies; that slot is empty, not the bytes truncate left.
    pub fn set_zero_gap(
        &self,
        write: &ClassCWrite,
        index: u64,
        value: u64,
    ) -> Result<(), StoreError> {
        self.write_slots(write, index, index, &[(index, value)], true)
    }

    pub fn set_many(&self, write: &ClassCWrite, pairs: &[(u64, u64)]) -> Result<(), StoreError> {
        self.write_many(write, pairs, false)
    }

    /// Like [`Self::set_many`]. Slots from `len` through `max` that `pairs`
    /// does not name become zero.
    pub fn set_many_zero_gap(
        &self,
        write: &ClassCWrite,
        pairs: &[(u64, u64)],
    ) -> Result<(), StoreError> {
        self.write_many(write, pairs, true)
    }

    fn write_many(
        &self,
        write: &ClassCWrite,
        pairs: &[(u64, u64)],
        zero_gap: bool,
    ) -> Result<(), StoreError> {
        if pairs.is_empty() {
            return Ok(());
        }
        let max_idx = pairs.iter().map(|(i, _)| *i).max().unwrap();
        let min_idx = pairs.iter().map(|(i, _)| *i).min().unwrap();
        self.write_slots(write, min_idx, max_idx, pairs, zero_gap)
    }

    fn write_slots(
        &self,
        _write: &ClassCWrite,
        min_idx: u64,
        max_idx: u64,
        pairs: &[(u64, u64)],
        zero_gap: bool,
    ) -> Result<(), StoreError> {
        if !zero_gap && !self.extension_is_dense(max_idx, pairs) {
            return Err(StoreError::Corrupt("array set skips slots"));
        }
        let _odd = self.begin_store()?;
        if !self.in_ram {
            self.write_fd(pairs, max_idx, zero_gap)?;
            return Ok(());
        }
        self.store_ram(min_idx, max_idx, pairs, zero_gap)
    }

    /// An index already inside `len` is a direct write. An extension publishes
    /// its length only after the new bytes.
    fn write_fd(
        &self,
        pairs: &[(u64, u64)],
        max_idx: u64,
        zero_gap: bool,
    ) -> Result<(), StoreError> {
        let len = self.len.load(Ordering::Acquire);
        for &(index, value) in pairs {
            if index < len {
                self.file
                    .write_at(Self::offset(index), &value.to_le_bytes())?;
            }
        }
        if max_idx < len {
            return Ok(());
        }
        self.append_fd(len, max_idx, pairs, zero_gap)
    }

    /// Bytes, then the file length, then `len`. `write_at` would publish the
    /// file end during a zero fill. A zero gap fills the new span first; the
    /// named slots then overwrite their places in that span.
    fn append_fd(
        &self,
        len: u64,
        max_idx: u64,
        pairs: &[(u64, u64)],
        zero_gap: bool,
    ) -> Result<(), StoreError> {
        let new_len = max_idx + 1;
        let end = Self::offset(new_len);
        self.file.ensure_capacity(end)?;
        if zero_gap {
            self.pwrite_zeros(Self::offset(len), (new_len - len) * ELEM)?;
        }
        for &(index, value) in pairs {
            if index >= len {
                self.file
                    .pwrite_all(Self::offset(index), &value.to_le_bytes())?;
            }
        }
        self.file.set_logical_len(end)?;
        self.len.store(new_len, Ordering::Release);
        // Loom branches before the store. The pwrite is not a loom access,
        // so the model yields once `len` covers the new slots.
        #[cfg(loom)]
        loom::thread::yield_now();
        Ok(())
    }

    fn pwrite_zeros(&self, mut offset: u64, mut remaining: u64) -> Result<(), StoreError> {
        const CHUNK: usize = 1024 * 1024;
        let zeros = vec![0u8; CHUNK.min(remaining as usize)];
        while remaining > 0 {
            let n = remaining.min(zeros.len() as u64) as usize;
            self.file.pwrite_all(offset, &zeros[..n])?;
            offset += n as u64;
            remaining -= n as u64;
        }
        Ok(())
    }

    /// An append must name every index from `len` through `max`. Overwrites
    /// below `len` may skip. A single next-slot append is dense by itself.
    /// A skip would publish buffer bytes the length no longer names.
    fn extension_is_dense(&self, max_idx: u64, pairs: &[(u64, u64)]) -> bool {
        let len = self.len.load(Ordering::Acquire);
        if max_idx <= len {
            return true;
        }
        let width = max_idx - len + 1;
        if width > pairs.len() as u64 {
            return false;
        }
        let mut seen = vec![false; width as usize];
        for &(index, _) in pairs {
            if index >= len {
                seen[(index - len) as usize] = true;
            }
        }
        seen.iter().all(|slot| *slot)
    }

    /// Release-store each slot, then the length. A relaxed slot store can move
    /// one header column while that pair's counter still looks even.
    fn store_ram(
        &self,
        min_idx: u64,
        max_idx: u64,
        pairs: &[(u64, u64)],
        zero_gap: bool,
    ) -> Result<(), StoreError> {
        self.slots.grow(max_idx as usize + 1)?;
        let slots = self.slots.slots(Ordering::Relaxed);
        let len_now = self.len.load(Ordering::Relaxed);
        let mark = if zero_gap {
            if max_idx >= len_now {
                for i in len_now..=max_idx {
                    slots[i as usize].store(0, Ordering::Release);
                }
            }
            min_idx.min(len_now)
        } else {
            min_idx
        };
        for &(index, value) in pairs {
            slots[index as usize].store(value, Ordering::Release);
        }
        let len = len_now.max(max_idx + 1);
        self.len.store(len, Ordering::Relaxed);
        self.mark_unstored(mark);
        Ok(())
    }

    pub fn truncate(&self, _write: &ClassCWrite, new_len: u64) -> Result<(), StoreError> {
        let len = self.len.load(Ordering::Acquire);
        if new_len > len {
            return Err(StoreError::Corrupt("array truncate grows"));
        }
        let _odd = self.begin_store()?;
        if !self.in_ram {
            self.len.store(new_len, Ordering::Release);
            let logical = FILE_HEADER_LEN as u64 + new_len * ELEM;
            self.file.set_logical_len(logical)?;
            return Ok(());
        }
        self.len.store(new_len, Ordering::Relaxed);
        // The mark is a bit index on a byte body and an element index
        // otherwise. `fetch_min` keeps a dirtier prefix. A clean image marks
        // the cut, so the flush shortens without rewriting that prefix.
        let mark = if self.byte_body {
            new_len.saturating_mul(8)
        } else {
            new_len
        };
        self.mark_unstored(mark);
        Ok(())
    }

    /// In-RAM L2 image bytes (0 when FdOnly).
    pub fn l2_resident_bytes(&self) -> u64 {
        if !self.in_ram {
            return 0;
        }
        let n = self.len.load(Ordering::Relaxed);
        n.saturating_mul(if self.byte_body { 1 } else { ELEM })
    }

    /// Slot a flush would copy. Not a sequence-counter read: the flush model
    /// records this at [`FlushStep::Write`] without waiting out an odd section.
    #[doc(hidden)]
    pub fn live_slot(&self, index: u64) -> u64 {
        self.slots.slots(Ordering::Acquire)[index as usize].load(Ordering::Relaxed)
    }

    /// Write one live slot without the sequence counter. Flush tests use this
    /// to show the persist reads the slot the writer would read.
    #[doc(hidden)]
    pub fn poke_live_slot(&self, index: u64, value: u64) {
        self.slots.slots(Ordering::Acquire)[index as usize].store(value, Ordering::Relaxed);
    }

    pub fn flush_dirty(&self) -> Result<(), StoreError> {
        self.flush_dirty_between(|_, _| {})
    }

    #[doc(hidden)]
    pub fn flush_dirty_between(
        &self,
        mut between: impl FnMut(&Self, FlushStep),
    ) -> Result<(), StoreError> {
        // One flusher, including the strong-bit image.
        let _one = self.flush_lock.lock().unwrap_or_else(|e| e.into_inner());
        if !self.in_ram {
            return Ok(());
        }
        let from = self.unstored_from.load(Ordering::Acquire);
        if from == CLEAN {
            return Ok(());
        }
        between(self, FlushStep::Admit);
        seq_arm(&self.seq, &self.flushing);
        // After stores are excluded. A test hold pauses the tip flush here.
        #[cfg(debug_assertions)]
        flush_hold::wait();
        let from = self.unstored_from.load(Ordering::Acquire);
        let n = self.len.load(Ordering::Acquire);
        let disk = self.disk_len.load(Ordering::Acquire);
        let mut end = FlushGuard(&self.flushing, &self.disk_len, &self.unstored_from, None);
        between(self, FlushStep::Write);
        // A byte body counts `len` in bytes and the mark in bits. Slot tables
        // count elements. Write the dirty prefix the new length still names,
        // including when that length is below the last flush. The file length
        // then drops bytes at and above `n`. The file is not padded to a word.
        let stride = if self.byte_body { 1 } else { ELEM };
        let start = if self.byte_body { from / 8 } else { from }.min(disk);
        if start < n {
            let mut scratch = [0u8; FLUSH_SCRATCH];
            let mut off = 0u64;
            let mut max_chunk = 0usize;
            let base = FILE_HEADER_LEN as u64 + start * stride;
            let span = (n - start) * stride;
            // One acquire: stores stay excluded until this flush returns.
            let words = self.slots.slots(Ordering::Acquire);
            while off < span {
                let nbyte = ((span - off) as usize).min(FLUSH_SCRATCH);
                let src = (start * stride + off) as usize;
                copy_bit_bytes(words, src, &mut scratch[..nbyte]);
                max_chunk = max_chunk.max(nbyte);
                self.file.write_at(base + off, &scratch[..nbyte])?;
                off += nbyte as u64;
            }
            self.flush_chunk_max.store(max_chunk, Ordering::Relaxed);
        }
        let logical = FILE_HEADER_LEN as u64 + n * stride;
        self.file.set_logical_len(logical)?;
        between(self, FlushStep::Clean);
        end.3 = Some(n);
        Ok(())
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.flush_dirty()?;
        self.file.flush()
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.flush_dirty()?;
        self.file.flush_async()
    }
}
