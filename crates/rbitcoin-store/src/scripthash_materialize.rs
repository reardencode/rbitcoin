//! Two-scan SH tip extract: unique key16 per shard, then fuse-hit postings.
//!
//! Pass 1: each worker owns a contiguous create-fk span and `n_shards` unsized
//! identity maps (`key16 → pack8 word`; `0` = multi). Cap is
//! [`SH_EXTRACT_WORKER_RAM_BYTES`] (1.5 GiB estimate, 64 B/key). After each
//! 64 k-fk loc/body batch, spill the largest shard map while over budget
//! (`SHKSP01` under `keys/NN/`, one writer, 1-slot queue). Status is
//! `scanned=` finished fks. Merge folds those spill files into one map,
//! one walk to `scripthash.head/NN` and `multi/NN.fuse8`, then unlinks
//! `keys/NN/`. A `keys/NN` file with no valid `DONE.keys` is wiped with the
//! previous layout. A spill whose magic is not `SHKSP01` refuses.
//! Pass 2 keeps fuse8 only (no BDZ): same static spans and per-worker maps
//! (`key16 → Vec<fk>`, estimate `80n+8f`), spill-largest as `SHPST01` under
//! `post/NN/`. Pack folds those spills, then `slot_for_key16` + 2+ bodies;
//! 1-fk after fold is `fp_singles`. A `post/NN` file refuses.

use crate::error::StoreError;
use crate::fuse8_filter::SealedFuse8;
use crate::scripthash::{sorted_main_shard_path, ColdProgress, ScriptHashTable, ShShardPack};
use crate::scripthash_head::prefix_shard_of;
use crate::scripthash_layout::{head_key_from_full, ShHeadKey, SH_HEAD_KEY_LEN};
use crate::scripthash_mphf::{mix_key16, mphf_path, val_path, MphfHead};
use crate::store::Store;
use crate::tx_table::TxTable;
use rbitcoin_primitives::{read_uleb128, write_uleb128, Fk};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::hash::{BuildHasherDefault, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MATERIALIZE_STATUS_INTERVAL: Duration = Duration::from_secs(10);

pub const UNSORTED_SHARD_DIR: &str = "scripthash.unsorted";
const KEYS_SUBDIR: &str = "keys";
const POST_SUBDIR: &str = "post";
const MULTI_SUBDIR: &str = "multi";
#[cfg(test)]
const MPHF_SUBDIR: &str = "mphf";
const KEYS_DONE_NAME: &str = "DONE.keys";
const POST_DONE_NAME: &str = "DONE.post";
const KEYS_DONE_MAGIC: &[u8; 8] = b"SHKEYS02";
const POST_DONE_MAGIC: &[u8; 8] = b"SHPOST02";
const LEGACY_DONE_NAME: &str = "DONE";

const KEY16_LEN: usize = SH_HEAD_KEY_LEN;
/// One keys-body codec. Anything else is leftover (refuse, do not open).
const KEYS_SPILL_MAGIC: &[u8; 8] = b"SHKSP01\0";
const KEYS_SPILL_HDR: usize = 16;
/// Collect-map estimate: `64 × n_keys` (HashMap overhead, not a prefault).
const KEYS_COLLECT_BYTES_PER_KEY: u64 = 64;
const INDEX_REFUSE_KEYS_LEFTOVER: &str = "scripthash unsorted keys leftover from an older extract; wipe store/scripthash.unsorted and rematerialize";
const INDEX_REFUSE_POST_LEFTOVER: &str = "scripthash unsorted post leftover from an older extract; wipe store/scripthash.unsorted and rematerialize";
/// Inner loc/body batch inside a static worker fk span.
pub(crate) const CLASS_A_CHUNK_FKS: u64 = 1 << 16;
/// One posts-body codec. Anything else is leftover (refuse, do not open).
const POSTS_SPILL_MAGIC: &[u8; 8] = b"SHPST01\0";
const POSTS_SPILL_HDR: usize = 12;
/// Collect-map estimate: `80 × n_keys + 8 × n_fks`.
const POST_MAP_KEY_BYTES: usize = 80;
const POST_MAP_FK_BYTES: usize = 8;

/// One extract worker: BDZ `g` + fuse + maps (~1.5 GiB).
pub const SH_EXTRACT_WORKER_RAM_BYTES: u64 = 3 << 29;

struct MaterializeProgress {
    recs_packed: AtomicU64,
    keys_packed: AtomicU64,
    shards_published: AtomicU32,
    creates_published: AtomicU64,
    merge_ns: AtomicU64,
    pack_ns: AtomicU64,
    mphf_ns: AtomicU64,
    body_flush_ns: AtomicU64,
}

impl MaterializeProgress {
    fn new() -> Self {
        Self {
            recs_packed: AtomicU64::new(0),
            keys_packed: AtomicU64::new(0),
            shards_published: AtomicU32::new(0),
            creates_published: AtomicU64::new(0),
            merge_ns: AtomicU64::new(0),
            pack_ns: AtomicU64::new(0),
            mphf_ns: AtomicU64::new(0),
            body_flush_ns: AtomicU64::new(0),
        }
    }

    fn stages(&self) -> MaterializeStageNs {
        MaterializeStageNs {
            merge_ns: self.merge_ns.load(Ordering::Relaxed),
            pack_ns: self.pack_ns.load(Ordering::Relaxed),
            mphf_ns: self.mphf_ns.load(Ordering::Relaxed),
            body_flush_ns: self.body_flush_ns.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MaterializeStageNs {
    pub merge_ns: u64,
    pub pack_ns: u64,
    pub mphf_ns: u64,
    pub body_flush_ns: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ShShardMaterialize {
    pub creates: u64,
    pub keys: u64,
    pub max_fk: u64,
    pub merge_ns: u64,
    pub pack_ns: u64,
    pub mphf_ns: u64,
    pub body_flush_ns: u64,
    pub head_fill_ns: u64,
}

impl ShShardMaterialize {
    fn with_stages(mut self, stages: MaterializeStageNs) -> Self {
        self.merge_ns = stages.merge_ns;
        self.pack_ns = stages.pack_ns;
        self.mphf_ns = stages.mphf_ns;
        self.body_flush_ns = stages.body_flush_ns;
        self.head_fill_ns = 0;
        self
    }
}

fn check_cancel(cancel: Option<&AtomicBool>, what: &'static str) -> Result<(), StoreError> {
    if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
        Err(StoreError::Cancelled(what))
    } else {
        Ok(())
    }
}

pub fn unsorted_shard_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(UNSORTED_SHARD_DIR)
}

pub fn unsorted_shard_path(dir: &Path, shard: usize) -> PathBuf {
    dir.join(format!("{shard:02x}"))
}

pub(crate) fn unsorted_keys_path(dir: &Path, shard: usize) -> PathBuf {
    dir.join(KEYS_SUBDIR).join(format!("{shard:02x}"))
}

pub(crate) fn unsorted_keys_spill_path(dir: &Path, shard: usize, seq: u32) -> PathBuf {
    unsorted_keys_path(dir, shard).join(format!("{seq:06}"))
}

pub(crate) fn unsorted_post_path(dir: &Path, shard: usize) -> PathBuf {
    dir.join(POST_SUBDIR).join(format!("{shard:02x}"))
}

pub(crate) fn unsorted_post_spill_path(dir: &Path, shard: usize, seq: u32) -> PathBuf {
    unsorted_post_path(dir, shard).join(format!("{seq:06}"))
}

pub(crate) fn unsorted_multi_fuse_path(dir: &Path, shard: usize) -> PathBuf {
    dir.join(MULTI_SUBDIR).join(format!("{shard:02x}.fuse8"))
}

#[cfg(test)]
pub(crate) fn unsorted_mphf_base(dir: &Path, shard: usize) -> PathBuf {
    dir.join(MPHF_SUBDIR).join(format!("{shard:02x}"))
}

pub fn unsorted_collect_workers() -> usize {
    sh_extract_workers()
}

/// `min(nCPU, max(1, free_RAM / 1.5 GiB))`. `RBITCOIN_SH_MERGE_WORKERS` overrides.
pub fn sh_extract_workers() -> usize {
    if let Ok(s) = std::env::var("RBITCOIN_SH_MERGE_WORKERS") {
        if let Ok(n) = s.parse::<usize>() {
            return n.clamp(1, 256);
        }
    }
    crate::sorted_run::workers_for_free_ram(
        crate::sorted_run::logical_cpus(),
        crate::sorted_run::host_mem_available_bytes().unwrap_or(0),
        SH_EXTRACT_WORKER_RAM_BYTES,
    )
}

pub fn unsorted_pack_workers() -> usize {
    sh_extract_workers()
}

pub fn clear_unsorted_shard_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

#[derive(Debug, Clone)]
pub struct UnsortedCollect {
    pub recs: u64,
    pub last_fk: u64,
    pub per_shard: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnsortedCollectAction {
    Full,
    Append { first: u64, last: u64 },
    Skip,
}

fn plan_unsorted_collect(
    done_last: Option<u64>,
    class_a_last: u64,
    any_sealed_shards: bool,
    keys_present: bool,
) -> UnsortedCollectAction {
    match done_last {
        None => UnsortedCollectAction::Full,
        Some(d) if d >= class_a_last => UnsortedCollectAction::Skip,
        Some(_) if any_sealed_shards => UnsortedCollectAction::Skip,
        Some(_) if !keys_present => UnsortedCollectAction::Full,
        Some(d) => UnsortedCollectAction::Append {
            first: d.saturating_add(1).max(1),
            last: class_a_last,
        },
    }
}

fn any_unsorted_keys(dir: &Path, n_shards: usize) -> bool {
    (0..n_shards).any(|si| {
        let p = unsorted_keys_path(dir, si);
        p.is_file() || p.is_dir()
    })
}

struct PhaseDone {
    last_fk: u64,
    counts: Vec<u64>,
}

fn write_phase_done(
    dir: &Path,
    name: &str,
    magic: &[u8; 8],
    last_fk: u64,
    per_shard: &[u64],
) -> Result<(), StoreError> {
    let n = per_shard.len() as u32;
    let mut buf = Vec::with_capacity(20 + per_shard.len() * 8);
    buf.extend_from_slice(magic);
    buf.extend_from_slice(&n.to_le_bytes());
    buf.extend_from_slice(&last_fk.to_le_bytes());
    for c in per_shard {
        buf.extend_from_slice(&c.to_le_bytes());
    }
    let tmp = dir.join(format!("{name}.tmp"));
    let dst = dir.join(name);
    fs::write(&tmp, &buf).map_err(|e| StoreError::io(&tmp, e))?;
    {
        let f = OpenOptions::new()
            .write(true)
            .open(&tmp)
            .map_err(|e| StoreError::io(&tmp, e))?;
        f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
    }
    fs::rename(&tmp, &dst).map_err(|e| StoreError::io(&dst, e))?;
    Ok(())
}

fn read_phase_done(dir: &Path, name: &str, magic: &[u8; 8], n_shards: usize) -> Option<PhaseDone> {
    let buf = fs::read(dir.join(name)).ok()?;
    if buf.len() < 20 || &buf[0..8] != magic {
        return None;
    }
    let n = u32::from_le_bytes(buf[8..12].try_into().ok()?) as usize;
    if n != n_shards {
        return None;
    }
    let last_fk = u64::from_le_bytes(buf[12..20].try_into().ok()?);
    if buf.len() != 20 + n * 8 {
        return None;
    }
    let mut counts = Vec::with_capacity(n);
    for i in 0..n {
        let o = 20 + i * 8;
        counts.push(u64::from_le_bytes(buf[o..o + 8].try_into().ok()?));
    }
    Some(PhaseDone { last_fk, counts })
}

pub fn unsorted_done_last_fk(dir: &Path, n_shards: usize) -> Option<u64> {
    read_phase_done(dir, KEYS_DONE_NAME, KEYS_DONE_MAGIC, n_shards).map(|d| d.last_fk)
}

fn leftover_legacy_unsorted(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    if dir.join(LEGACY_DONE_NAME).is_file() {
        return true;
    }
    for i in 0..256 {
        if unsorted_shard_path(dir, i).is_file() {
            return true;
        }
        if unsorted_keys_path(dir, i).is_file() {
            return true;
        }
        if unsorted_post_path(dir, i).is_file() {
            return true;
        }
    }
    false
}

fn chunk_ranges(first: u64, last: u64, chunk: u64) -> Vec<(u64, u64)> {
    if last < first {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = first;
    while cur <= last {
        let hi = cur.saturating_add(chunk.saturating_sub(1)).min(last);
        out.push((cur, hi));
        if hi == last {
            break;
        }
        cur = hi.saturating_add(1);
    }
    out
}

/// Contiguous, covering, disjoint create-fk spans. Remainder on the last span.
/// `n_workers` clamps to `[1, span]`.
fn worker_fk_spans(first: u64, last: u64, n_workers: usize) -> Vec<(u64, u64)> {
    if last < first {
        return Vec::new();
    }
    let span = last.saturating_sub(first).saturating_add(1);
    let n = (n_workers.max(1) as u64).min(span);
    let base = span / n;
    let rem = span % n;
    let mut out = Vec::with_capacity(n as usize);
    let mut cur = first;
    for i in 0..n {
        let len = if i + 1 == n {
            base.saturating_add(rem)
        } else {
            base
        };
        let hi = cur.saturating_add(len.saturating_sub(1));
        out.push((cur, hi));
        cur = hi.saturating_add(1);
    }
    out
}

/// Finished create-fks, not the max fk. A late span must not look like the scan is done.
fn note_scanned_fks(scanned: &AtomicU64, lo: u64, hi: u64) -> u64 {
    let n = hi.saturating_sub(lo).saturating_add(1);
    scanned.fetch_add(n, Ordering::Relaxed).saturating_add(n)
}

fn key16_halves_bytes(bytes: &[u8]) -> (u64, u64) {
    let a = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let b = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    (a, b)
}

/// Identity hasher for uniform key16: `finish()` is the xor of the two LE u64 halves.
/// Does not FNV-mix bytes ([`crate::int_map::U64IdentityHasher::write`]).
#[derive(Default, Clone, Copy)]
struct Key16IdentityHasher(u64);

impl Hasher for Key16IdentityHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() == KEY16_LEN {
            let (a, b) = key16_halves_bytes(bytes);
            self.0 = a ^ b;
        }
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        if i > KEY16_LEN as u64 {
            self.0 = i;
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

type Key16PackMap = HashMap<ShHeadKey, u64, BuildHasherDefault<Key16IdentityHasher>>;
type KeysSpillJob = (usize, Key16PackMap);
type KeysSpillTx = SyncSender<KeysSpillJob>;
type KeysSpillRx = Receiver<KeysSpillJob>;

fn keys_map_estimated_bytes(map: &Key16PackMap) -> u64 {
    (map.len() as u64).saturating_mul(KEYS_COLLECT_BYTES_PER_KEY)
}

fn keys_maps_estimated_bytes(maps: &[Key16PackMap]) -> u64 {
    maps.iter().map(keys_map_estimated_bytes).sum()
}

fn largest_keys_shard(maps: &[Key16PackMap]) -> Option<usize> {
    maps.iter()
        .enumerate()
        .filter(|(_, m)| !m.is_empty())
        .max_by_key(|(_, m)| m.len())
        .map(|(i, _)| i)
}

fn refuse_keys_leftover() -> StoreError {
    StoreError::Corrupt(INDEX_REFUSE_KEYS_LEFTOVER)
}

/// Vacant stores `word`; occupied nonzero becomes `0` (multi) unless `word` matches.
fn insert_key_word(map: &mut Key16PackMap, key: ShHeadKey, word: u64) {
    match map.entry(key) {
        Entry::Vacant(v) => {
            v.insert(word);
        }
        Entry::Occupied(mut o) => {
            if *o.get() != 0 && (*o.get() != word || word == 0) {
                o.insert(0);
            }
        }
    }
}

struct CollectTally {
    recs: u64,
    hits: u64,
    per: Vec<u64>,
}

impl CollectTally {
    fn new(n_shards: usize) -> Self {
        Self {
            recs: 0,
            hits: 0,
            per: vec![0; n_shards],
        }
    }
}

/// Add a worker's batch counts once. A zero tally does not touch the atomics.
fn flush_collect_tally(
    tally: &mut CollectTally,
    recs: &AtomicU64,
    hits: Option<&AtomicU64>,
    per: Option<&[AtomicU64]>,
) {
    if tally.recs != 0 {
        recs.fetch_add(tally.recs, Ordering::Relaxed);
        tally.recs = 0;
    }
    if tally.hits != 0 {
        if let Some(hits) = hits {
            hits.fetch_add(tally.hits, Ordering::Relaxed);
        }
        tally.hits = 0;
    }
    if let Some(per) = per {
        for (slot, n) in per.iter().zip(tally.per.iter_mut()) {
            if *n != 0 {
                slot.fetch_add(*n, Ordering::Relaxed);
                *n = 0;
            }
        }
    }
}

fn insert_key_pack(map: &mut Key16PackMap, key: ShHeadKey, fk: Fk) {
    if fk.is_null() {
        return;
    }
    insert_key_word(map, key, fk.0);
}

fn encode_keys_spill(map: &Key16PackMap) -> Vec<u8> {
    let mut multis = Vec::new();
    let mut singles = Vec::new();
    for (k, w) in map {
        if *w == 0 {
            multis.push(*k);
        } else {
            singles.push((*w, *k));
        }
    }
    singles.sort_unstable_by_key(|a| a.0);
    let mut bytes = Vec::with_capacity(
        KEYS_SPILL_HDR + (multis.len() + singles.len()).saturating_mul(KEY16_LEN + 8),
    );
    bytes.extend_from_slice(KEYS_SPILL_MAGIC);
    bytes.extend_from_slice(&(multis.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(singles.len() as u32).to_le_bytes());
    for k in &multis {
        bytes.extend_from_slice(k);
    }
    let mut prev = 0u64;
    for &(fk, k) in &singles {
        write_uleb128(&mut bytes, fk.saturating_sub(prev));
        bytes.extend_from_slice(&k);
        prev = fk;
    }
    bytes
}

fn fold_keys_spill_bytes(map: &mut Key16PackMap, bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.len() < KEYS_SPILL_HDR || bytes[0..8] != KEYS_SPILL_MAGIC[..] {
        return Err(refuse_keys_leftover());
    }
    let n_multi = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let n_single = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let mut i = KEYS_SPILL_HDR;
    for _ in 0..n_multi {
        if bytes.len().saturating_sub(i) < KEY16_LEN {
            return Err(StoreError::Corrupt("scripthash keys spill truncated"));
        }
        let mut k = [0u8; KEY16_LEN];
        k.copy_from_slice(&bytes[i..i + KEY16_LEN]);
        i += KEY16_LEN;
        insert_key_word(map, k, 0);
    }
    let mut prev = 0u64;
    for _ in 0..n_single {
        let (delta, n) = read_uleb128(&bytes[i..])
            .map_err(|_| StoreError::Corrupt("scripthash keys spill uleb"))?;
        i = i.saturating_add(n);
        if bytes.len().saturating_sub(i) < KEY16_LEN {
            return Err(StoreError::Corrupt("scripthash keys spill truncated"));
        }
        let mut k = [0u8; KEY16_LEN];
        k.copy_from_slice(&bytes[i..i + KEY16_LEN]);
        i += KEY16_LEN;
        let fk = prev.saturating_add(delta);
        insert_key_word(map, k, fk);
        prev = fk;
    }
    if i != bytes.len() {
        return Err(StoreError::Corrupt("scripthash keys spill trailing bytes"));
    }
    Ok(())
}

fn parse_spill_seq(name: &str) -> Option<u32> {
    if name.len() == 6 && name.bytes().all(|b| b.is_ascii_digit()) {
        name.parse().ok()
    } else {
        None
    }
}

fn list_keys_spill_paths(dir: &Path, shard: usize) -> Result<Vec<PathBuf>, StoreError> {
    let p = unsorted_keys_path(dir, shard);
    if p.is_file() {
        return Err(refuse_keys_leftover());
    }
    if !p.is_dir() {
        return Ok(Vec::new());
    }
    let rd = fs::read_dir(&p).map_err(|e| StoreError::io(&p, e))?;
    let mut seqs = Vec::new();
    for ent in rd {
        let ent = ent.map_err(|e| StoreError::io(&p, e))?;
        let name = ent.file_name();
        let s = name.to_string_lossy();
        if s.ends_with(".tmp") {
            continue;
        }
        let Some(seq) = parse_spill_seq(&s) else {
            return Err(refuse_keys_leftover());
        };
        seqs.push((seq, ent.path()));
    }
    seqs.sort_unstable_by_key(|a| a.0);
    Ok(seqs.into_iter().map(|(_, path)| path).collect())
}

fn load_keys_shard_map(dir: &Path, shard: usize) -> Result<Key16PackMap, StoreError> {
    let mut map = Key16PackMap::default();
    for path in list_keys_spill_paths(dir, shard)? {
        let bytes = fs::read(&path).map_err(|e| StoreError::io(&path, e))?;
        fold_keys_spill_bytes(&mut map, &bytes)?;
    }
    Ok(map)
}

fn write_keys_spill(
    dir: &Path,
    shard: usize,
    seq: u32,
    map: &Key16PackMap,
) -> Result<(), StoreError> {
    let path = unsorted_keys_spill_path(dir, shard, seq);
    crate::file::write_tmp_rename(&path, &encode_keys_spill(map))
}

fn next_keys_spill_seq(dir: &Path, shard: usize) -> Result<u32, StoreError> {
    let paths = list_keys_spill_paths(dir, shard)?;
    let mut max_seq = None;
    for p in &paths {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(seq) = parse_spill_seq(name) {
            max_seq = Some(max_seq.map_or(seq, |m: u32| m.max(seq)));
        }
    }
    Ok(max_seq.map(|s| s.saturating_add(1)).unwrap_or(0))
}

#[cfg(test)]
pub(crate) fn write_keys_spill_entries(
    dir: &Path,
    shard: usize,
    seq: u32,
    items: &[(ShHeadKey, Option<Fk>)],
) -> Result<(), StoreError> {
    let mut map = Key16PackMap::default();
    for &(k, first) in items {
        match first {
            Some(fk) => insert_key_pack(&mut map, k, fk),
            None => insert_key_word(&mut map, k, 0),
        }
    }
    write_keys_spill(dir, shard, seq, &map)
}

fn unlink_keys_shard(dir: &Path, shard: usize) {
    let p = unsorted_keys_path(dir, shard);
    if p.is_dir() {
        let _ = fs::remove_dir_all(&p);
    } else if p.is_file() {
        let _ = fs::remove_file(&p);
    }
}

type Key16FkMap = HashMap<ShHeadKey, Vec<u64>, BuildHasherDefault<Key16IdentityHasher>>;

#[derive(Default, Debug)]
struct PostPackMap {
    map: Key16FkMap,
    n_fks: usize,
}

impl PostPackMap {
    fn estimated_bytes(&self) -> usize {
        self.map
            .len()
            .saturating_mul(POST_MAP_KEY_BYTES)
            .saturating_add(self.n_fks.saturating_mul(POST_MAP_FK_BYTES))
    }

    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

fn refuse_posts_leftover() -> StoreError {
    StoreError::Corrupt(INDEX_REFUSE_POST_LEFTOVER)
}

fn posts_maps_estimated_bytes(maps: &[PostPackMap]) -> u64 {
    maps.iter().map(|m| m.estimated_bytes() as u64).sum()
}

fn largest_posts_shard(maps: &[PostPackMap]) -> Option<usize> {
    maps.iter()
        .enumerate()
        .filter(|(_, m)| !m.is_empty())
        .max_by_key(|(_, m)| m.estimated_bytes())
        .map(|(i, _)| i)
}

fn fks_strictly_increasing(fks: &[u64]) -> bool {
    fks.windows(2).all(|w| w[0] < w[1])
}

/// Keep `Vec<fk>` strictly increasing. Scan order appends; an older fk inserts.
fn insert_post_fk(map: &mut PostPackMap, key: ShHeadKey, fk: u64) {
    if fk == 0 {
        return;
    }
    match map.map.entry(key) {
        Entry::Vacant(v) => {
            v.insert(vec![fk]);
            map.n_fks = map.n_fks.saturating_add(1);
        }
        Entry::Occupied(mut o) => {
            let v = o.get_mut();
            if let Some(last) = v.last().copied() {
                if fk > last {
                    v.push(fk);
                    map.n_fks = map.n_fks.saturating_add(1);
                    return;
                }
                if fk == last {
                    return;
                }
            }
            match v.binary_search(&fk) {
                Ok(_) => {}
                Err(i) => {
                    v.insert(i, fk);
                    map.n_fks = map.n_fks.saturating_add(1);
                }
            }
        }
    }
}

/// Linear merge of two strictly increasing fk runs. Equals collapse.
fn merge_sorted_unique_fks(dst: &mut Vec<u64>, src: Vec<u64>) {
    if src.is_empty() {
        return;
    }
    if dst.is_empty() {
        *dst = src;
        dst.dedup();
        return;
    }
    debug_assert!(fks_strictly_increasing(dst));
    debug_assert!(fks_strictly_increasing(&src));
    let mut out = Vec::with_capacity(dst.len().saturating_add(src.len()));
    let mut i = 0usize;
    let mut j = 0usize;
    while i < dst.len() || j < src.len() {
        let take = match (dst.get(i), src.get(j)) {
            (Some(&a), Some(&b)) if a < b => {
                i += 1;
                a
            }
            (Some(&a), Some(&b)) if a > b => {
                j += 1;
                b
            }
            (Some(&a), Some(_)) => {
                i += 1;
                j += 1;
                a
            }
            (Some(&a), None) => {
                i += 1;
                a
            }
            (None, Some(&b)) => {
                j += 1;
                b
            }
            (None, None) => break,
        };
        if out.last().copied() != Some(take) {
            out.push(take);
        }
    }
    *dst = out;
}

fn fold_post_map(dst: &mut PostPackMap, src: PostPackMap) {
    for (k, fks) in src.map {
        match dst.map.entry(k) {
            Entry::Vacant(v) => {
                let mut f = fks;
                f.dedup();
                debug_assert!(fks_strictly_increasing(&f));
                dst.n_fks = dst.n_fks.saturating_add(f.len());
                v.insert(f);
            }
            Entry::Occupied(mut o) => {
                let before = o.get().len();
                merge_sorted_unique_fks(o.get_mut(), fks);
                dst.n_fks = dst
                    .n_fks
                    .saturating_sub(before)
                    .saturating_add(o.get().len());
            }
        }
    }
}

fn encode_posts_spill(map: &PostPackMap) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        POSTS_SPILL_HDR
            + map
                .map
                .len()
                .saturating_mul(KEY16_LEN + 8)
                .saturating_add(map.n_fks.saturating_mul(8)),
    );
    bytes.extend_from_slice(POSTS_SPILL_MAGIC);
    bytes.extend_from_slice(&(map.map.len() as u32).to_le_bytes());
    for (k, fks) in &map.map {
        debug_assert!(fks_strictly_increasing(fks));
        bytes.extend_from_slice(k);
        write_uleb128(&mut bytes, fks.len() as u64);
        let mut prev = 0u64;
        for &fk in fks {
            write_uleb128(&mut bytes, fk.saturating_sub(prev));
            prev = fk;
        }
    }
    bytes
}

fn fold_posts_spill_bytes(map: &mut PostPackMap, bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.len() < POSTS_SPILL_HDR || bytes[0..8] != POSTS_SPILL_MAGIC[..] {
        return Err(refuse_posts_leftover());
    }
    let n_keys = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let mut i = POSTS_SPILL_HDR;
    let mut src = PostPackMap::default();
    for _ in 0..n_keys {
        if bytes.len().saturating_sub(i) < KEY16_LEN {
            return Err(StoreError::Corrupt("scripthash posts spill truncated"));
        }
        let mut k = [0u8; KEY16_LEN];
        k.copy_from_slice(&bytes[i..i + KEY16_LEN]);
        i += KEY16_LEN;
        let (n, nread) = read_uleb128(&bytes[i..])
            .map_err(|_| StoreError::Corrupt("scripthash posts spill uleb"))?;
        i = i.saturating_add(nread);
        let mut fks = Vec::with_capacity(n as usize);
        let mut prev = 0u64;
        for _ in 0..n {
            let (delta, nread) = read_uleb128(&bytes[i..])
                .map_err(|_| StoreError::Corrupt("scripthash posts spill uleb"))?;
            i = i.saturating_add(nread);
            let fk = prev.saturating_add(delta);
            fks.push(fk);
            prev = fk;
        }
        src.map.insert(k, fks);
        src.n_fks = src.n_fks.saturating_add(n as usize);
    }
    if i != bytes.len() {
        return Err(StoreError::Corrupt("scripthash posts spill trailing bytes"));
    }
    fold_post_map(map, src);
    Ok(())
}

fn list_posts_spill_paths(dir: &Path, shard: usize) -> Result<Vec<PathBuf>, StoreError> {
    let p = unsorted_post_path(dir, shard);
    if p.is_file() {
        return Err(refuse_posts_leftover());
    }
    if !p.is_dir() {
        return Ok(Vec::new());
    }
    let rd = fs::read_dir(&p).map_err(|e| StoreError::io(&p, e))?;
    let mut seqs = Vec::new();
    for ent in rd {
        let ent = ent.map_err(|e| StoreError::io(&p, e))?;
        let name = ent.file_name();
        let s = name.to_string_lossy();
        if s.ends_with(".tmp") {
            continue;
        }
        let Some(seq) = parse_spill_seq(&s) else {
            return Err(refuse_posts_leftover());
        };
        seqs.push((seq, ent.path()));
    }
    seqs.sort_unstable_by_key(|a| a.0);
    Ok(seqs.into_iter().map(|(_, path)| path).collect())
}

fn load_post_shard_map(dir: &Path, shard: usize) -> Result<PostPackMap, StoreError> {
    let mut map = PostPackMap::default();
    for path in list_posts_spill_paths(dir, shard)? {
        let bytes = fs::read(&path).map_err(|e| StoreError::io(&path, e))?;
        fold_posts_spill_bytes(&mut map, &bytes)?;
    }
    Ok(map)
}

fn write_posts_spill(
    dir: &Path,
    shard: usize,
    seq: u32,
    map: &PostPackMap,
) -> Result<(), StoreError> {
    let path = unsorted_post_spill_path(dir, shard, seq);
    crate::file::write_tmp_rename(&path, &encode_posts_spill(map))
}

fn next_post_spill_seq(dir: &Path, shard: usize) -> Result<u32, StoreError> {
    let paths = list_posts_spill_paths(dir, shard)?;
    let mut max_seq = None;
    for p in &paths {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(seq) = parse_spill_seq(name) {
            max_seq = Some(max_seq.map_or(seq, |m: u32| m.max(seq)));
        }
    }
    Ok(max_seq.map(|s| s.saturating_add(1)).unwrap_or(0))
}

fn spill_post_shard_map(
    dir: &Path,
    shard: usize,
    seqs: &[AtomicU32],
    map: PostPackMap,
) -> Result<(), StoreError> {
    if map.is_empty() {
        return Ok(());
    }
    let seq = seqs[shard].fetch_add(1, Ordering::Relaxed);
    write_posts_spill(dir, shard, seq, &map)
}

fn spill_largest_posts_while_over(
    maps: &mut [PostPackMap],
    budget: u64,
    mut spill: impl FnMut(usize, PostPackMap) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    while posts_maps_estimated_bytes(maps) >= budget {
        let Some(si) = largest_posts_shard(maps) else {
            break;
        };
        let taken = std::mem::take(&mut maps[si]);
        spill(si, taken)?;
    }
    Ok(())
}

fn spill_all_post_maps(
    maps: &mut [PostPackMap],
    mut spill: impl FnMut(usize, PostPackMap) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    for (si, local) in maps.iter_mut().enumerate() {
        let taken = std::mem::take(local);
        spill(si, taken)?;
    }
    Ok(())
}

type PostSpillJob = (usize, PostPackMap);
type PostSpillTx = SyncSender<PostSpillJob>;
type PostSpillRx = Receiver<PostSpillJob>;

fn posts_spill_channel() -> (PostSpillTx, PostSpillRx) {
    mpsc::sync_channel(1)
}

fn send_posts_spill(tx: &PostSpillTx, shard: usize, map: PostPackMap) -> Result<(), StoreError> {
    if map.is_empty() {
        return Ok(());
    }
    tx.send((shard, map))
        .map_err(|_| StoreError::Corrupt("scripthash post spill writer stopped"))
}

fn posts_spill_writer(
    rx: PostSpillRx,
    dir: &Path,
    seqs: &[AtomicU32],
    err: &Mutex<Option<StoreError>>,
) {
    while let Ok((si, map)) = rx.recv() {
        if err.lock().unwrap().is_some() {
            continue;
        }
        if let Err(e) = spill_post_shard_map(dir, si, seqs, map) {
            let mut g = err.lock().unwrap();
            if g.is_none() {
                *g = Some(e);
            }
        }
    }
}

fn unlink_post_shard(dir: &Path, shard: usize) {
    let p = unsorted_post_path(dir, shard);
    if p.is_dir() {
        let _ = fs::remove_dir_all(&p);
    } else if p.is_file() {
        let _ = fs::remove_file(&p);
    }
}

#[cfg(test)]
pub(crate) fn write_post_spill_entries(
    dir: &Path,
    shard: usize,
    seq: u32,
    items: &[(ShHeadKey, &[u64])],
) -> Result<(), StoreError> {
    let mut map = PostPackMap::default();
    for &(k, fks) in items {
        for &fk in fks {
            insert_post_fk(&mut map, k, fk);
        }
    }
    write_posts_spill(dir, shard, seq, &map)
}

#[cfg(test)]
pub(crate) fn load_post_shard_entries(
    dir: &Path,
    shard: usize,
) -> Result<Vec<(ShHeadKey, Vec<u64>)>, StoreError> {
    let map = load_post_shard_map(dir, shard)?;
    Ok(map.map.into_iter().collect())
}

fn finish_key_shard(
    table: &ScriptHashTable,
    dir: &Path,
    shard: usize,
    n_shards: usize,
) -> Result<(u64, u64, u64), StoreError> {
    let map = load_keys_shard_map(dir, shard)?;
    let times = seal_pack_map_to_head_and_fuse(table, dir, shard, n_shards, map)?;
    unlink_keys_shard(dir, shard);
    Ok(times)
}

fn spill_shard_map(
    dir: &Path,
    shard: usize,
    seqs: &[AtomicU32],
    map: Key16PackMap,
) -> Result<(), StoreError> {
    if map.is_empty() {
        return Ok(());
    }
    let seq = seqs[shard].fetch_add(1, Ordering::Relaxed);
    write_keys_spill(dir, shard, seq, &map)
}

fn spill_largest_keys_while_over(
    maps: &mut [Key16PackMap],
    budget: u64,
    mut spill: impl FnMut(usize, Key16PackMap) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    while keys_maps_estimated_bytes(maps) >= budget {
        let Some(si) = largest_keys_shard(maps) else {
            break;
        };
        let taken = std::mem::take(&mut maps[si]);
        spill(si, taken)?;
    }
    Ok(())
}

fn spill_all_keys_maps(
    maps: &mut [Key16PackMap],
    mut spill: impl FnMut(usize, Key16PackMap) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    for (si, local) in maps.iter_mut().enumerate() {
        let taken = std::mem::take(local);
        spill(si, taken)?;
    }
    Ok(())
}

/// One in-flight map. The next spill blocks until the writer takes this one.
fn keys_spill_channel() -> (KeysSpillTx, KeysSpillRx) {
    mpsc::sync_channel(1)
}

fn send_keys_spill(tx: &KeysSpillTx, shard: usize, map: Key16PackMap) -> Result<(), StoreError> {
    if map.is_empty() {
        return Ok(());
    }
    tx.send((shard, map))
        .map_err(|_| StoreError::Corrupt("scripthash keys spill writer stopped"))
}

fn keys_spill_writer(
    rx: KeysSpillRx,
    dir: &Path,
    seqs: &[AtomicU32],
    err: &Mutex<Option<StoreError>>,
) {
    while let Ok((si, map)) = rx.recv() {
        if err.lock().unwrap().is_some() {
            continue;
        }
        if let Err(e) = spill_shard_map(dir, si, seqs, map) {
            let mut g = err.lock().unwrap();
            if g.is_none() {
                *g = Some(e);
            }
        }
    }
}

fn collect_keys_from_txs(
    txs: &TxTable,
    table: &ScriptHashTable,
    dir: &Path,
    first: u64,
    last: u64,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<UnsortedCollect, StoreError> {
    let n_shards = table.head_shard_count().max(1);
    if last < first {
        return Ok(UnsortedCollect {
            recs: 0,
            last_fk: last,
            per_shard: vec![0; n_shards],
        });
    }
    fs::create_dir_all(dir.join(KEYS_SUBDIR)).map_err(|e| StoreError::io(dir, e))?;
    let budget = SH_EXTRACT_WORKER_RAM_BYTES;
    let seqs: Vec<AtomicU32> = {
        let mut v = Vec::with_capacity(n_shards);
        for si in 0..n_shards {
            v.push(AtomicU32::new(next_keys_spill_seq(dir, si)?));
        }
        v
    };
    let recs = AtomicU64::new(0);
    let scanned = AtomicU64::new(0);
    let span_fks = last.saturating_sub(first).saturating_add(1);
    let err = Mutex::new(None::<StoreError>);
    let t0 = Instant::now();
    let last_status = Mutex::new(t0);
    let spans = worker_fk_spans(first, last, workers);
    let live = rbitcoin_log::progress::begin("scripthash keys collect", span_fks);
    std::thread::scope(|scope| {
        let n_workers = spans.len().max(1);
        rbitcoin_log::info!(
            "store: scripthash keys collect start workers={n_workers} budget_MiB={} fk={first}..{last}",
            budget / (1 << 20)
        );
        let (tx, rx) = keys_spill_channel();
        scope.spawn(|| keys_spill_writer(rx, dir, &seqs, &err));
        for &(span_lo, span_hi) in &spans {
            let tx = tx.clone();
            let recs = &recs;
            let scanned = &scanned;
            let live = &live;
            let err = &err;
            let last_status = &last_status;
            scope.spawn(move || {
                let mut locals: Vec<Key16PackMap> =
                    (0..n_shards).map(|_| Key16PackMap::default()).collect();
                let mut tally = CollectTally::new(0);
                for (lo, hi) in chunk_ranges(span_lo, span_hi, CLASS_A_CHUNK_FKS) {
                    if check_cancel(cancel, "scripthash keys collect").is_err() {
                        let mut g = err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(StoreError::Cancelled("scripthash keys collect"));
                        }
                        break;
                    }
                    if err.lock().unwrap().is_some() {
                        break;
                    }
                    let r = txs.for_each_script_hashes_in_fk_span(lo, hi, |fk, sh| {
                        let si = prefix_shard_of(&sh, n_shards);
                        tally.recs = tally.recs.saturating_add(1);
                        insert_key_pack(&mut locals[si], head_key_from_full(&sh), fk);
                        Ok(())
                    });
                    flush_collect_tally(&mut tally, recs, None, None);
                    if let Err(e) = r {
                        *err.lock().unwrap() = Some(e);
                        break;
                    }
                    if let Err(e) = spill_largest_keys_while_over(&mut locals, budget, |si, map| {
                        send_keys_spill(&tx, si, map)
                    }) {
                        let mut g = err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(e);
                        }
                        break;
                    }
                    let done = note_scanned_fks(scanned, lo, hi);
                    live.set_done(done);
                    let now = Instant::now();
                    let mut st = last_status.lock().unwrap();
                    if now.duration_since(*st) >= MATERIALIZE_STATUS_INTERVAL {
                        *st = now;
                        rbitcoin_log::info!(
                            "store: scripthash keys collect scanned={done}/{span_fks} recs={} elapsed={:?}",
                            recs.load(Ordering::Relaxed),
                            t0.elapsed()
                        );
                    }
                }
                if err.lock().unwrap().is_none() {
                    rbitcoin_log::info!(
                        "store: scripthash keys collect flush span={span_lo}..{span_hi}"
                    );
                    if let Err(e) = spill_all_keys_maps(&mut locals, |si, map| {
                        send_keys_spill(&tx, si, map)
                    }) {
                        let mut g = err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(e);
                        }
                    }
                }
            });
        }
        drop(tx);
    });
    if let Some(e) = err.lock().unwrap().take() {
        return Err(e);
    }
    drop(live);
    let merge_workers = workers.max(1).min(n_shards.max(1));
    fs::create_dir_all(dir.join(MULTI_SUBDIR)).map_err(|e| StoreError::io(dir, e))?;
    let live_merge = rbitcoin_log::progress::begin("scripthash keys merge", n_shards as u64);
    rbitcoin_log::info!(
        "store: scripthash keys merge start n_shards={n_shards} workers={merge_workers}"
    );
    let t_merge = Instant::now();
    let per_shard: Vec<AtomicU64> = (0..n_shards).map(|_| AtomicU64::new(0)).collect();
    if merge_workers <= 1 {
        for (si, slot) in per_shard.iter().enumerate() {
            check_cancel(cancel, "scripthash keys merge")?;
            let (n, fold_ns, bdz_ns) = finish_key_shard(table, dir, si, n_shards)?;
            slot.store(n, Ordering::Relaxed);
            live_merge.add_done(1);
            rbitcoin_log::info!(
                "store: scripthash keys merge shard={si:02x} keys={n} fold={:?} bdz={:?}",
                Duration::from_nanos(fold_ns),
                Duration::from_nanos(bdz_ns)
            );
        }
    } else {
        let merge_err = Mutex::new(None::<StoreError>);
        let merge_jobs = Mutex::new(VecDeque::from_iter(0..n_shards));
        std::thread::scope(|scope| {
            for _ in 0..merge_workers {
                let merge_jobs = &merge_jobs;
                let merge_err = &merge_err;
                let per_shard = &per_shard;
                let live_merge = &live_merge;
                scope.spawn(move || loop {
                    if check_cancel(cancel, "scripthash keys merge").is_err() {
                        let mut g = merge_err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(StoreError::Cancelled("scripthash keys merge"));
                        }
                        break;
                    }
                    if merge_err.lock().unwrap().is_some() {
                        break;
                    }
                    let si = merge_jobs.lock().unwrap().pop_front();
                    let Some(si) = si else {
                        break;
                    };
                    match finish_key_shard(table, dir, si, n_shards) {
                        Ok((n, fold_ns, bdz_ns)) => {
                            per_shard[si].store(n, Ordering::Relaxed);
                            live_merge.add_done(1);
                            rbitcoin_log::info!(
                                "store: scripthash keys merge shard={si:02x} keys={n} fold={:?} bdz={:?}",
                                Duration::from_nanos(fold_ns),
                                Duration::from_nanos(bdz_ns)
                            );
                        }
                        Err(e) => {
                            *merge_err.lock().unwrap() = Some(e);
                            break;
                        }
                    }
                });
            }
        });
        if let Some(e) = merge_err.lock().unwrap().take() {
            return Err(e);
        };
    }
    let per_shard: Vec<u64> = per_shard
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    rbitcoin_log::info!(
        "store: scripthash keys merge done elapsed={:?}",
        t_merge.elapsed()
    );
    write_phase_done(dir, KEYS_DONE_NAME, KEYS_DONE_MAGIC, last, &per_shard)?;
    Ok(UnsortedCollect {
        recs: recs.load(Ordering::Relaxed),
        last_fk: last,
        per_shard,
    })
}

pub fn collect_unsorted_shard_files(
    store: &Store,
    dir: &Path,
    n_shards: usize,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<UnsortedCollect, StoreError> {
    collect_unsorted_covering_class_a(store, dir, n_shards, workers, false, cancel)
}

pub(crate) fn collect_unsorted_covering_class_a(
    store: &Store,
    dir: &Path,
    n_shards: usize,
    workers: usize,
    any_sealed_shards: bool,
    cancel: Option<&AtomicBool>,
) -> Result<UnsortedCollect, StoreError> {
    collect_unsorted_covering_txs(
        &store.txs,
        &store.scripthash,
        dir,
        n_shards,
        workers,
        any_sealed_shards,
        cancel,
    )
}

pub(crate) fn collect_unsorted_covering_txs(
    txs: &TxTable,
    table: &ScriptHashTable,
    dir: &Path,
    n_shards: usize,
    workers: usize,
    any_sealed_shards: bool,
    cancel: Option<&AtomicBool>,
) -> Result<UnsortedCollect, StoreError> {
    let last = txs.count();
    if leftover_legacy_unsorted(dir)
        && read_phase_done(dir, KEYS_DONE_NAME, KEYS_DONE_MAGIC, n_shards).is_none()
    {
        clear_unsorted_shard_dir(dir);
    }
    let done = read_phase_done(dir, KEYS_DONE_NAME, KEYS_DONE_MAGIC, n_shards);
    let keys_present = any_unsorted_keys(dir, n_shards);
    let action = plan_unsorted_collect(
        done.as_ref().map(|d| d.last_fk),
        last,
        any_sealed_shards,
        keys_present,
    );
    check_cancel(cancel, "scripthash keys collect")?;
    match action {
        UnsortedCollectAction::Skip => {
            let d = done.expect("skip requires DONE.keys");
            Ok(UnsortedCollect {
                recs: d.counts.iter().sum(),
                last_fk: d.last_fk,
                per_shard: d.counts,
            })
        }
        UnsortedCollectAction::Full => {
            clear_unsorted_shard_dir(dir);
            collect_keys_from_txs(txs, table, dir, 1, last, workers, cancel)
        }
        UnsortedCollectAction::Append { first, last } => {
            collect_keys_from_txs(txs, table, dir, first, last, workers, cancel)
        }
    }
}

fn write_multi_fuse_keys(dir: &Path, si: usize, dupes: &[u64]) -> Result<u64, StoreError> {
    let path = unsorted_multi_fuse_path(dir, si);
    if dupes.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(0);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| StoreError::io(parent, e))?;
    }
    let fuse = SealedFuse8::build(dupes)?;
    fuse.write_to(&path)?;
    Ok(dupes.len() as u64)
}

fn seal_pack_map_to_head_and_fuse(
    table: &ScriptHashTable,
    dir: &Path,
    si: usize,
    n_shards: usize,
    map: Key16PackMap,
) -> Result<(u64, u64, u64), StoreError> {
    let nkeys = map.len() as u64;
    let t_fold = Instant::now();
    let n = map.len();
    let mut recs = Vec::with_capacity(n);
    let mut mixed = Vec::with_capacity(n);
    let mut dupes = Vec::new();
    let mut n_singles = 0u64;
    // Consuming the map drops its buckets before fuse8 and BDZ.
    for (k, w) in map {
        let m = mix_key16(&k);
        mixed.push(m);
        if w == 0 {
            dupes.push(m);
        } else {
            n_singles += 1;
        }
        recs.push((k, w));
    }
    let _n_fuse = write_multi_fuse_keys(dir, si, &dupes)?;
    let fold_ns = t_fold.elapsed().as_nanos() as u64;
    let t_bdz = Instant::now();
    let head = sorted_main_shard_path(table.store_dir(), si, n_shards);
    let _ = fs::remove_file(mphf_path(&head));
    let _ = fs::remove_file(val_path(&head));
    MphfHead::write_pack8_mixed(&head, &recs, &mixed)?;
    if si < table.head_shard_count() {
        table.set_extract_inline_creates(si, n_singles)?;
    }
    let bdz_ns = t_bdz.elapsed().as_nanos() as u64;
    Ok((nkeys, fold_ns, bdz_ns))
}

pub(crate) fn seal_mphf_from_keys(
    table: &ScriptHashTable,
    dir: &Path,
    n_shards: usize,
    cancel: Option<&AtomicBool>,
) -> Result<(), StoreError> {
    fs::create_dir_all(dir.join(MULTI_SUBDIR)).map_err(|e| StoreError::io(dir, e))?;
    let unsealed: HashSet<usize> = table.unsealed_main_shards().into_iter().collect();
    let jobs: Vec<usize> = (0..n_shards)
        .filter(|&si| {
            if !unsealed.contains(&si) {
                unlink_keys_shard(dir, si);
                return false;
            }
            let p = unsorted_keys_path(dir, si);
            p.is_dir() || p.is_file()
        })
        .collect();
    let remaining = jobs.len();
    let t_all = Instant::now();
    let workers = sh_extract_workers().max(1).min(remaining.max(1));
    let live = (remaining > 0).then(|| {
        rbitcoin_log::progress::begin_at(
            "scripthash keys merge",
            n_shards as u64,
            (n_shards - remaining) as u64,
        )
    });
    if remaining > 0 {
        rbitcoin_log::info!(
            "store: scripthash keys merge start remaining={remaining} n_shards={n_shards} workers={workers}"
        );
    }
    let err = Mutex::new(None::<StoreError>);
    let jobq = Mutex::new(VecDeque::from(jobs));
    std::thread::scope(|scope| {
        for _ in 0..workers.min(remaining.max(1)) {
            if remaining == 0 {
                break;
            }
            let jobq = &jobq;
            let err = &err;
            let live = live.as_ref();
            scope.spawn(move || loop {
                if check_cancel(cancel, "scripthash mphf from keys").is_err() {
                    let mut g = err.lock().unwrap();
                    if g.is_none() {
                        *g = Some(StoreError::Cancelled("scripthash mphf from keys"));
                    }
                    break;
                }
                if err.lock().unwrap().is_some() {
                    break;
                }
                let Some(si) = jobq.lock().unwrap().pop_front() else {
                    break;
                };
                match seal_one_mphf_shard(table, dir, si, n_shards) {
                    Ok((nkeys, fold_ns, bdz_ns)) => {
                        if let Some(live) = live {
                            live.add_done(1);
                        }
                        rbitcoin_log::info!(
                            "store: scripthash keys merge shard={si:02x} keys={nkeys} fold={:?} bdz={:?}",
                            Duration::from_nanos(fold_ns),
                            Duration::from_nanos(bdz_ns)
                        );
                    }
                    Err(e) => {
                        *err.lock().unwrap() = Some(e);
                        break;
                    }
                }
            });
        }
    });
    if let Some(e) = err.lock().unwrap().take() {
        return Err(e);
    }
    if remaining > 0 {
        rbitcoin_log::info!(
            "store: scripthash keys merge done remaining={remaining} elapsed={:?}",
            t_all.elapsed()
        );
    }
    Ok(())
}

fn seal_one_mphf_shard(
    table: &ScriptHashTable,
    dir: &Path,
    si: usize,
    n_shards: usize,
) -> Result<(usize, u64, u64), StoreError> {
    let map = load_keys_shard_map(dir, si)?;
    let (nkeys, fold_ns, bdz_ns) = seal_pack_map_to_head_and_fuse(table, dir, si, n_shards, map)?;
    unlink_keys_shard(dir, si);
    Ok((nkeys as usize, fold_ns, bdz_ns))
}

fn open_multi_fuses(dir: &Path, n_shards: usize) -> Result<Vec<Option<SealedFuse8>>, StoreError> {
    let mut out = Vec::with_capacity(n_shards);
    for si in 0..n_shards {
        let p = unsorted_multi_fuse_path(dir, si);
        if p.is_file() {
            out.push(Some(SealedFuse8::read_from(&p)?));
        } else {
            out.push(None);
        }
    }
    Ok(out)
}

fn leftover_post_file(dir: &Path) -> bool {
    (0..256).any(|i| unsorted_post_path(dir, i).is_file())
}

fn collect_posts_from_txs(
    txs: &TxTable,
    table: &ScriptHashTable,
    dir: &Path,
    first: u64,
    last: u64,
    workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<UnsortedCollect, StoreError> {
    let n_shards = table.head_shard_count().max(1);
    if last < first {
        return Ok(UnsortedCollect {
            recs: 0,
            last_fk: last,
            per_shard: vec![0; n_shards],
        });
    }
    if leftover_post_file(dir) {
        return Err(refuse_posts_leftover());
    }
    fs::create_dir_all(dir.join(POST_SUBDIR)).map_err(|e| StoreError::io(dir, e))?;
    let fuses = Arc::new(open_multi_fuses(dir, n_shards)?);
    let budget = SH_EXTRACT_WORKER_RAM_BYTES;
    let seqs: Vec<AtomicU32> = {
        let mut v = Vec::with_capacity(n_shards);
        for si in 0..n_shards {
            v.push(AtomicU32::new(next_post_spill_seq(dir, si)?));
        }
        v
    };
    let recs = AtomicU64::new(0);
    let hits = AtomicU64::new(0);
    let scanned = AtomicU64::new(0);
    let span_fks = last.saturating_sub(first).saturating_add(1);
    let per = (0..n_shards).map(|_| AtomicU64::new(0)).collect::<Vec<_>>();
    let err = Mutex::new(None::<StoreError>);
    let t0 = Instant::now();
    let last_status = Mutex::new(t0);
    let spans = worker_fk_spans(first, last, workers);
    let live = rbitcoin_log::progress::begin("scripthash postings collect", span_fks);
    std::thread::scope(|scope| {
        let n_workers = spans.len().max(1);
        rbitcoin_log::info!(
            "store: scripthash postings collect start workers={n_workers} budget_MiB={} fk={first}..{last}",
            budget / (1 << 20)
        );
        let (tx, rx) = posts_spill_channel();
        scope.spawn(|| posts_spill_writer(rx, dir, &seqs, &err));
        for &(span_lo, span_hi) in &spans {
            let tx = tx.clone();
            let fuses = Arc::clone(&fuses);
            let recs = &recs;
            let hits = &hits;
            let scanned = &scanned;
            let live = &live;
            let per = &per;
            let err = &err;
            let last_status = &last_status;
            scope.spawn(move || {
                let mut locals: Vec<PostPackMap> =
                    (0..n_shards).map(|_| PostPackMap::default()).collect();
                let mut tally = CollectTally::new(n_shards);
                for (lo, hi) in chunk_ranges(span_lo, span_hi, CLASS_A_CHUNK_FKS) {
                    if check_cancel(cancel, "scripthash postings collect").is_err() {
                        let mut g = err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(StoreError::Cancelled("scripthash postings collect"));
                        }
                        break;
                    }
                    if err.lock().unwrap().is_some() {
                        break;
                    }
                    let r = txs.for_each_script_hashes_in_fk_span(lo, hi, |fk, sh| {
                        tally.recs = tally.recs.saturating_add(1);
                        let si = prefix_shard_of(&sh, n_shards);
                        let Some(fuse) = fuses[si].as_ref() else {
                            return Ok(());
                        };
                        let key = head_key_from_full(&sh);
                        if !fuse.contains(mix_key16(&key)) {
                            return Ok(());
                        }
                        insert_post_fk(&mut locals[si], key, fk.0);
                        tally.hits = tally.hits.saturating_add(1);
                        tally.per[si] = tally.per[si].saturating_add(1);
                        Ok(())
                    });
                    flush_collect_tally(&mut tally, recs, Some(hits), Some(per));
                    if let Err(e) = r {
                        *err.lock().unwrap() = Some(e);
                        break;
                    }
                    if let Err(e) =
                        spill_largest_posts_while_over(&mut locals, budget, |si, map| {
                            send_posts_spill(&tx, si, map)
                        })
                    {
                        let mut g = err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(e);
                        }
                        break;
                    }
                    let done = note_scanned_fks(scanned, lo, hi);
                    live.set_done(done);
                    let now = Instant::now();
                    let mut st = last_status.lock().unwrap();
                    if now.duration_since(*st) >= MATERIALIZE_STATUS_INTERVAL {
                        *st = now;
                        rbitcoin_log::info!(
                            "store: scripthash postings collect scanned={done}/{span_fks} recs={} hits={} elapsed={:?}",
                            recs.load(Ordering::Relaxed),
                            hits.load(Ordering::Relaxed),
                            t0.elapsed()
                        );
                    }
                }
                if err.lock().unwrap().is_none() {
                    rbitcoin_log::info!(
                        "store: scripthash postings collect flush span={span_lo}..{span_hi}"
                    );
                    if let Err(e) = spill_all_post_maps(&mut locals, |si, map| {
                        send_posts_spill(&tx, si, map)
                    }) {
                        let mut g = err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(e);
                        }
                    }
                }
            });
        }
        drop(tx);
    });
    if let Some(e) = err.lock().unwrap().take() {
        return Err(e);
    }
    let per_shard: Vec<u64> = per.iter().map(|a| a.load(Ordering::Relaxed)).collect();
    write_phase_done(dir, POST_DONE_NAME, POST_DONE_MAGIC, last, &per_shard)?;
    Ok(UnsortedCollect {
        recs: recs.load(Ordering::Relaxed),
        last_fk: last,
        per_shard,
    })
}

pub(crate) fn collect_posts_covering(
    txs: &TxTable,
    table: &ScriptHashTable,
    dir: &Path,
    workers: usize,
    any_sealed_shards: bool,
    cancel: Option<&AtomicBool>,
) -> Result<UnsortedCollect, StoreError> {
    if leftover_post_file(dir) {
        return Err(refuse_posts_leftover());
    }
    let n_shards = table.head_shard_count().max(1);
    let last = txs.count();
    let done = read_phase_done(dir, POST_DONE_NAME, POST_DONE_MAGIC, n_shards);
    let action = plan_unsorted_collect(
        done.as_ref().map(|d| d.last_fk),
        last,
        any_sealed_shards,
        true,
    );
    check_cancel(cancel, "scripthash postings collect")?;
    match action {
        UnsortedCollectAction::Skip => {
            let d = done.expect("skip requires DONE.post");
            Ok(UnsortedCollect {
                recs: d.counts.iter().sum(),
                last_fk: d.last_fk,
                per_shard: d.counts,
            })
        }
        UnsortedCollectAction::Full => {
            let post_dir = dir.join(POST_SUBDIR);
            let _ = fs::remove_dir_all(&post_dir);
            collect_posts_from_txs(txs, table, dir, 1, last, workers, cancel)
        }
        UnsortedCollectAction::Append { first, last } => {
            collect_posts_from_txs(txs, table, dir, first, last, workers, cancel)
        }
    }
}

fn pack_post_shard(
    table: &ScriptHashTable,
    unsorted_dir: &Path,
    shard: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardPack, StoreError> {
    check_cancel(cancel, "scripthash unsorted shard pack")?;
    let mut session = table.pack_shard_session(shard)?;
    let map = load_post_shard_map(unsorted_dir, shard)?;
    if map.is_empty() {
        return session.finish_pack();
    }
    let n_shards = table.head_shard_count().max(1);
    let mphf = MphfHead::open(sorted_main_shard_path(table.store_dir(), shard, n_shards))?;
    session.reserve_pack_recs(map.n_fks);
    let mut fp_singles = 0u64;
    for (k, fks) in map.map {
        check_cancel(cancel, "scripthash unsorted shard pack")?;
        debug_assert!(fks_strictly_increasing(&fks));
        if fks.len() <= 1 {
            if fks.len() == 1 {
                fp_singles = fp_singles.saturating_add(1);
            }
            continue;
        }
        let slot = mphf.slot_for_key16(&k)?;
        for fk in fks {
            session.push_sorted_slot_fk(slot, Fk(fk))?;
        }
    }
    let mut pack = session.finish_pack()?;
    pack.fp_singles = fp_singles;
    Ok(pack)
}

fn seal_shard(
    table: &ScriptHashTable,
    shard: usize,
    pack: ShShardPack,
    max_fk: &AtomicU64,
    progress: &MaterializeProgress,
) -> Result<(), StoreError> {
    max_fk.fetch_max(pack.max_fk, Ordering::Relaxed);
    let creates = pack.creates;
    let t_mphf = Instant::now();
    table.publish_packed_shard(shard, pack)?;
    progress
        .mphf_ns
        .fetch_add(t_mphf.elapsed().as_nanos() as u64, Ordering::Relaxed);
    progress.shards_published.fetch_add(1, Ordering::Relaxed);
    progress
        .creates_published
        .fetch_add(creates, Ordering::Relaxed);
    table.store_sharded_cold_progress(
        progress.keys_packed.load(Ordering::Relaxed),
        progress.creates_published.load(Ordering::Relaxed),
    )?;
    Ok(())
}

struct ShardPool {
    jobs: Mutex<VecDeque<usize>>,
    err: Mutex<Option<StoreError>>,
}

struct PackShardDone {
    shard: usize,
    keys: u64,
    creates: u64,
    fp_singles: u64,
    elapsed: Duration,
}

fn log_unsorted_pack_shard(n_shards: usize, published: u32, d: &PackShardDone) {
    rbitcoin_log::info!(
        "store: scripthash unsorted pack shard={:02x} keys={} creates={} fp_singles={} \
         shards={published}/{n_shards} elapsed={:?}",
        d.shard,
        d.keys,
        d.creates,
        d.fp_singles,
        d.elapsed
    );
}

fn pack_and_seal_unsorted_shard(
    table: &ScriptHashTable,
    unsorted_dir: &Path,
    shard: usize,
    cancel: Option<&AtomicBool>,
    progress: &MaterializeProgress,
    max_fk: &AtomicU64,
) -> Result<PackShardDone, StoreError> {
    check_cancel(cancel, "scripthash unsorted shard pack")?;
    let t0 = Instant::now();
    let t_merge = Instant::now();
    let pack = pack_post_shard(table, unsorted_dir, shard, cancel)?;
    progress
        .merge_ns
        .fetch_add(t_merge.elapsed().as_nanos() as u64, Ordering::Relaxed);
    progress.pack_ns.fetch_add(pack.pack_ns, Ordering::Relaxed);
    progress
        .body_flush_ns
        .fetch_add(pack.body_flush_ns, Ordering::Relaxed);
    progress.keys_packed.fetch_add(pack.keys, Ordering::Relaxed);
    progress
        .recs_packed
        .fetch_add(pack.creates, Ordering::Relaxed);
    let done = PackShardDone {
        shard,
        keys: pack.keys,
        creates: pack.creates,
        fp_singles: pack.fp_singles,
        elapsed: t0.elapsed(),
    };
    seal_shard(table, shard, pack, max_fk, progress)?;
    unlink_post_shard(unsorted_dir, shard);
    Ok(done)
}

#[cfg(test)]
pub(crate) fn pack_one_extract_shard(
    table: &ScriptHashTable,
    unsorted_dir: &Path,
    shard: usize,
) -> Result<(), StoreError> {
    let n = table.head_shard_count().max(1);
    let progress = MaterializeProgress::new();
    let max_fk = AtomicU64::new(0);
    let done = pack_and_seal_unsorted_shard(table, unsorted_dir, shard, None, &progress, &max_fk)?;
    log_unsorted_pack_shard(n, progress.shards_published.load(Ordering::Relaxed), &done);
    Ok(())
}

pub fn materialize_sh_from_unsorted(
    table: &ScriptHashTable,
    unsorted_dir: &Path,
    pack_workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    let n_shards = table.head_shard_count().max(1);
    seal_mphf_from_keys(table, unsorted_dir, n_shards, cancel)?;
    let jobs: Vec<usize> = table
        .unsealed_main_shards()
        .into_iter()
        .filter(|s| *s < n_shards)
        .collect();
    if jobs.is_empty() {
        return Ok(ShShardMaterialize {
            creates: table.entry_count(),
            keys: 0,
            max_fk: 0,
            merge_ns: 0,
            pack_ns: 0,
            mphf_ns: 0,
            body_flush_ns: 0,
            head_fill_ns: 0,
        });
    }
    let workers = pack_workers.max(1).min(jobs.len());
    let t0 = Instant::now();
    let progress = MaterializeProgress::new();
    let already = (n_shards - jobs.len()) as u32;
    progress.shards_published.store(already, Ordering::Relaxed);
    progress
        .recs_packed
        .store(table.entry_count(), Ordering::Relaxed);
    progress
        .creates_published
        .store(table.entry_count(), Ordering::Relaxed);
    let max_fk = AtomicU64::new(0);
    let live =
        rbitcoin_log::progress::begin_at("scripthash pack", n_shards as u64, u64::from(already));
    rbitcoin_log::info!(
        "store: scripthash unsorted pack start unsealed={} n_shards={n_shards} workers={workers}",
        jobs.len()
    );

    let out = std::thread::scope(|scope| {
        let progress = &progress;
        let max_fk = &max_fk;
        let live = &live;
        if workers <= 1 {
            for shard in jobs {
                let d = pack_and_seal_unsorted_shard(
                    table,
                    unsorted_dir,
                    shard,
                    cancel,
                    progress,
                    max_fk,
                )?;
                let published = progress.shards_published.load(Ordering::Relaxed);
                live.set_done(u64::from(published));
                log_unsorted_pack_shard(n_shards, published, &d);
            }
        } else {
            let shared = Arc::new(ShardPool {
                jobs: Mutex::new(VecDeque::from(jobs)),
                err: Mutex::new(None),
            });
            let mut joins = Vec::with_capacity(workers);
            for _ in 0..workers {
                let shared = Arc::clone(&shared);
                joins.push(scope.spawn(move || loop {
                    if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                        let mut g = shared.err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(StoreError::Cancelled("scripthash unsorted shard pack"));
                        }
                        break;
                    }
                    if shared.err.lock().unwrap().is_some() {
                        break;
                    }
                    let shard = shared.jobs.lock().unwrap().pop_front();
                    let Some(shard) = shard else {
                        break;
                    };
                    match pack_and_seal_unsorted_shard(
                        table,
                        unsorted_dir,
                        shard,
                        cancel,
                        progress,
                        max_fk,
                    ) {
                        Ok(d) => {
                            let published = progress.shards_published.load(Ordering::Relaxed);
                            live.set_done(u64::from(published));
                            log_unsorted_pack_shard(n_shards, published, &d);
                        }
                        Err(e) => {
                            *shared.err.lock().unwrap() = Some(e);
                            break;
                        }
                    }
                }));
            }
            for j in joins {
                if j.join().is_err() {
                    return Err(StoreError::Corrupt(
                        "scripthash unsorted pack worker panicked",
                    ));
                }
            }
            let err = shared.err.lock().unwrap().take();
            if let Some(e) = err {
                return Err(e);
            }
        }
        Ok(ShShardMaterialize {
            creates: progress.creates_published.load(Ordering::Relaxed),
            keys: progress.keys_packed.load(Ordering::Relaxed),
            max_fk: max_fk.load(Ordering::Relaxed),
            merge_ns: 0,
            pack_ns: 0,
            mphf_ns: 0,
            body_flush_ns: 0,
            head_fill_ns: 0,
        }
        .with_stages(progress.stages()))
    })?;
    rbitcoin_log::info!(
        "store: scripthash unsorted pack done creates≈{} keys≈{} elapsed={:?}",
        out.creates,
        out.keys,
        t0.elapsed()
    );
    Ok(out)
}

pub fn materialize_sh_unsorted_from_class_a(
    store: &Store,
    collect_workers: usize,
    pack_workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    let table = &store.scripthash;
    let n_shards = table.head_shard_count().max(1);
    let dir = unsorted_shard_dir(store.path());
    let collect_workers = if collect_workers == 0 {
        unsorted_collect_workers()
    } else {
        collect_workers
    };
    let pack_workers = if pack_workers == 0 {
        unsorted_pack_workers()
    } else {
        pack_workers
    };

    let unsealed = table.unsealed_main_shards();
    if unsealed.is_empty() && (!table.head_is_empty() || table.entry_count() > 0) {
        clear_unsorted_shard_dir(&dir);
        ColdProgress::clear(store.path());
        return Ok(ShShardMaterialize {
            creates: table.entry_count(),
            keys: 0,
            max_fk: 0,
            merge_ns: 0,
            pack_ns: 0,
            mphf_ns: 0,
            body_flush_ns: 0,
            head_fill_ns: 0,
        });
    }

    // Pass-1 sets `live_count` and leaves MPHF on disk without loading it, so
    // `head_is_empty` is true. Reinit would drop write-behind body rows.
    if table.head_is_empty() && table.entry_count() == 0 {
        table.reinit_empty_for_cold_materialize()?;
    }

    let any_sealed = unsealed.len() < n_shards;
    let collected = collect_unsorted_covering_class_a(
        store,
        &dir,
        n_shards,
        collect_workers,
        any_sealed,
        cancel,
    )?;
    let mut mat = materialize_sh_from_unsorted_from_txs(
        table,
        &store.txs,
        &dir,
        collect_workers,
        pack_workers,
        cancel,
    )?;
    mat.max_fk = mat.max_fk.max(collected.last_fk);
    if table.unsealed_main_shards().is_empty() {
        clear_unsorted_shard_dir(&dir);
        ColdProgress::clear(store.path());
    }
    Ok(mat)
}

/// Seal extract MPHF, scan Class A into postings, pack unsealed shards.
pub(crate) fn materialize_sh_from_unsorted_from_txs(
    table: &ScriptHashTable,
    txs: &TxTable,
    unsorted_dir: &Path,
    collect_workers: usize,
    pack_workers: usize,
    cancel: Option<&AtomicBool>,
) -> Result<ShShardMaterialize, StoreError> {
    let n_shards = table.head_shard_count().max(1);
    seal_mphf_from_keys(table, unsorted_dir, n_shards, cancel)?;
    let any_sealed = table.unsealed_main_shards().len() < n_shards;
    collect_posts_covering(
        txs,
        table,
        unsorted_dir,
        collect_workers,
        any_sealed,
        cancel,
    )?;
    materialize_sh_from_unsorted(table, unsorted_dir, pack_workers, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripthash_layout::ShHeadKey;
    use std::hash::{Hash, Hasher};

    fn prefix_key(b0: u8) -> ShHeadKey {
        let mut k = [0u8; KEY16_LEN];
        k[0] = b0;
        k
    }

    #[test]
    fn key16_identity_hasher_is_xor_of_u64_halves() {
        let mut k = [0u8; KEY16_LEN];
        k[0..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        k[8..16].copy_from_slice(&0x1112_1314_1516_1718u64.to_le_bytes());
        let mut h = Key16IdentityHasher::default();
        k.hash(&mut h);
        assert_eq!(h.finish(), 0x0102_0304_0506_0708u64 ^ 0x1112_1314_1516_1718);
        let mut h2 = Key16IdentityHasher::default();
        k.hash(&mut h2);
        assert_eq!(h.finish(), h2.finish());
    }

    #[test]
    fn key16_identity_try_insert_first_second_third_is_pack8_word() {
        let mut map = Key16PackMap::default();
        let k = prefix_key(1);
        insert_key_pack(&mut map, k, Fk(10));
        assert_eq!(map.get(&k).copied(), Some(10));
        insert_key_pack(&mut map, k, Fk(11));
        assert_eq!(map.get(&k).copied(), Some(0));
        insert_key_pack(&mut map, k, Fk(12));
        assert_eq!(map.get(&k).copied(), Some(0), "third hit must not write");
        assert_eq!(KEYS_SPILL_MAGIC, b"SHKSP01\0");
        assert_eq!(KEYS_COLLECT_BYTES_PER_KEY, 64);
        assert_eq!(SH_EXTRACT_WORKER_RAM_BYTES, 3 << 29);
    }

    #[test]
    fn worker_fk_spans_are_contiguous_covering_and_disjoint() {
        assert_eq!(
            worker_fk_spans(1, 100, 4),
            vec![(1, 25), (26, 50), (51, 75), (76, 100)]
        );
        assert_eq!(
            worker_fk_spans(1, 10, 3),
            vec![(1, 3), (4, 6), (7, 10)],
            "remainder on the last span"
        );
        assert_eq!(worker_fk_spans(1, 5, 1), vec![(1, 5)]);
        assert_eq!(
            worker_fk_spans(1, 3, 10),
            vec![(1, 1), (2, 2), (3, 3)],
            "n_workers > span clamps to one fk per worker"
        );
        assert!(worker_fk_spans(5, 4, 4).is_empty());
        assert_eq!(worker_fk_spans(1, 8, 0), vec![(1, 8)]);
    }

    #[test]
    fn flush_collect_tally_matches_per_item_and_skips_zeros() {
        let recs = AtomicU64::new(0);
        let hits = AtomicU64::new(0);
        let per = [AtomicU64::new(0), AtomicU64::new(0)];
        let mut one = CollectTally::new(2);
        for _ in 0..3 {
            one.recs = one.recs.saturating_add(1);
            one.hits = one.hits.saturating_add(1);
            one.per[0] = one.per[0].saturating_add(1);
            flush_collect_tally(&mut one, &recs, Some(&hits), Some(&per));
        }
        let batch_recs = AtomicU64::new(0);
        let batch_hits = AtomicU64::new(0);
        let batch_per = [AtomicU64::new(0), AtomicU64::new(0)];
        let mut batch = CollectTally {
            recs: 3,
            hits: 3,
            per: vec![3, 0],
        };
        flush_collect_tally(&mut batch, &batch_recs, Some(&batch_hits), Some(&batch_per));
        assert_eq!(
            recs.load(Ordering::Relaxed),
            batch_recs.load(Ordering::Relaxed)
        );
        assert_eq!(
            hits.load(Ordering::Relaxed),
            batch_hits.load(Ordering::Relaxed)
        );
        assert_eq!(
            per[0].load(Ordering::Relaxed),
            batch_per[0].load(Ordering::Relaxed)
        );
        assert_eq!(per[1].load(Ordering::Relaxed), 0);
        let snap = (
            batch_recs.load(Ordering::Relaxed),
            batch_hits.load(Ordering::Relaxed),
            batch_per[0].load(Ordering::Relaxed),
        );
        flush_collect_tally(&mut batch, &batch_recs, Some(&batch_hits), Some(&batch_per));
        assert_eq!(
            snap,
            (
                batch_recs.load(Ordering::Relaxed),
                batch_hits.load(Ordering::Relaxed),
                batch_per[0].load(Ordering::Relaxed),
            )
        );
    }

    #[test]
    fn scanned_fks_count_finished_spans_not_max_fk() {
        let spans = worker_fk_spans(1, 100, 4);
        assert_eq!(spans[3], (76, 100));
        let scanned = AtomicU64::new(0);
        let one = note_scanned_fks(&scanned, spans[3].0, spans[3].0);
        assert_eq!(one, 1, "finishing one fk of the late span is not fk 76");
        note_scanned_fks(&scanned, spans[0].0, spans[0].1);
        assert_eq!(scanned.load(Ordering::Relaxed), 1 + 25);
    }

    #[test]
    fn keys_spill_channel_is_one_slot() {
        let (tx, rx) = keys_spill_channel();
        let mut first = Key16PackMap::default();
        insert_key_pack(&mut first, prefix_key(1), Fk(1));
        tx.send((0, first)).unwrap();
        let mut second = Key16PackMap::default();
        insert_key_pack(&mut second, prefix_key(2), Fk(2));
        match tx.try_send((0, second)) {
            Err(mpsc::TrySendError::Full(_)) => {}
            other => panic!("second spill must block on the one-slot queue, got {other:?}"),
        }
        assert_eq!(rx.recv().unwrap().0, 0);
    }

    #[test]
    fn keys_spill_writer_folds_two_senders() {
        let dir = crate::testutil::TempDir::labeled("sh-spill-writer").expect("temp");
        let seqs = [AtomicU32::new(0)];
        let err = Mutex::new(None);
        let (tx, rx) = keys_spill_channel();
        std::thread::scope(|scope| {
            scope.spawn(|| keys_spill_writer(rx, dir.path(), &seqs, &err));
            let tx_b = tx.clone();
            scope.spawn(move || {
                let mut map = Key16PackMap::default();
                insert_key_pack(&mut map, prefix_key(1), Fk(1));
                send_keys_spill(&tx_b, 0, map).unwrap();
            });
            let mut map = Key16PackMap::default();
            insert_key_pack(&mut map, prefix_key(2), Fk(9));
            send_keys_spill(&tx, 0, map).unwrap();
            drop(tx);
        });
        assert!(err.lock().unwrap().is_none());
        let got = load_keys_shard_map(dir.path(), 0).unwrap();
        assert_eq!(got.get(&prefix_key(1)).copied(), Some(1));
        assert_eq!(got.get(&prefix_key(2)).copied(), Some(9));
    }

    #[test]
    fn leftover_keys_file_refuses_to_open() {
        let dir = crate::testutil::TempDir::labeled("sh-leftover-file").expect("temp");
        std::fs::create_dir_all(dir.join(KEYS_SUBDIR)).unwrap();
        let path = unsorted_keys_path(dir.path(), 0);
        crate::file::write_synced_tmp_rename(&path, b"not-a-spill-dir").unwrap();
        match load_keys_shard_map(dir.path(), 0) {
            Err(StoreError::Corrupt(m)) => {
                assert!(m.contains("wipe store/scripthash.unsorted"), "{m}");
            }
            other => panic!("must refuse leftover keys file, got {other:?}"),
        }
        assert!(leftover_legacy_unsorted(dir.path()));
    }

    #[test]
    fn two_spills_fold_repeat_key_to_zero_without_sort() {
        let dir = crate::testutil::TempDir::labeled("sh-two-spill").expect("temp");
        let a = prefix_key(1);
        let b = prefix_key(2);
        write_keys_spill_entries(dir.path(), 0, 0, &[(b, Some(Fk(5))), (a, Some(Fk(1)))]).unwrap();
        write_keys_spill_entries(dir.path(), 0, 1, &[(a, Some(Fk(9)))]).unwrap();
        assert!(unsorted_keys_spill_path(dir.path(), 0, 0).is_file());
        assert!(unsorted_keys_spill_path(dir.path(), 0, 1).is_file());
        assert!(unsorted_keys_path(dir.path(), 0).is_dir());
        let map = load_keys_shard_map(dir.path(), 0).unwrap();
        assert_eq!(map.get(&a).copied(), Some(0), "cross-spill repeat is multi");
        assert_eq!(map.get(&b).copied(), Some(5));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn keys_spill_magic_wrong_refuses() {
        let dir = crate::testutil::TempDir::labeled("sh-bad-magic").expect("temp");
        std::fs::create_dir_all(unsorted_keys_path(dir.path(), 0)).unwrap();
        let path = unsorted_keys_spill_path(dir.path(), 0, 0);
        crate::file::write_synced_tmp_rename(&path, b"SHKEYS02........").unwrap();
        match load_keys_shard_map(dir.path(), 0) {
            Err(StoreError::Corrupt(m)) => {
                assert!(m.contains("wipe store/scripthash.unsorted"), "{m}");
            }
            other => panic!("wrong magic must refuse, got {other:?}"),
        }
    }

    #[test]
    fn spill_largest_keys_writes_fattest_and_spills_while_over() {
        let dir = crate::testutil::TempDir::labeled("sh-spill-largest").expect("temp");
        let mut maps: Vec<Key16PackMap> = (0..3).map(|_| Key16PackMap::default()).collect();
        insert_key_pack(&mut maps[0], prefix_key(1), Fk(1));
        insert_key_pack(&mut maps[0], prefix_key(2), Fk(2));
        insert_key_pack(&mut maps[0], prefix_key(3), Fk(3));
        insert_key_pack(&mut maps[1], prefix_key(4), Fk(4));
        insert_key_pack(&mut maps[2], prefix_key(5), Fk(5));
        let seqs: Vec<AtomicU32> = (0..3).map(|_| AtomicU32::new(0)).collect();
        let budget = 2 * KEYS_COLLECT_BYTES_PER_KEY;
        spill_largest_keys_while_over(&mut maps, budget, |si, map| {
            spill_shard_map(dir.path(), si, &seqs, map)
        })
        .unwrap();
        assert!(maps[0].is_empty(), "fattest shard spilled first");
        assert!(
            maps[1].is_empty() ^ maps[2].is_empty(),
            "second while-over spill empties exactly one remaining shard"
        );
        let leftover = if maps[1].is_empty() { 2 } else { 1 };
        assert_eq!(maps[leftover].len(), 1, "one shard stays under budget");
        assert!(unsorted_keys_spill_path(dir.path(), 0, 0).is_file());
        let n_files = [0, 1, 2]
            .iter()
            .filter(|si| unsorted_keys_spill_path(dir.path(), **si, 0).is_file())
            .count();
        assert_eq!(n_files, 2);
        let got0 = load_keys_shard_map(dir.path(), 0).unwrap();
        assert_eq!(got0.len(), 3);
    }

    #[test]
    fn multi_fuse8_contains_inserted_mix64() {
        let k = prefix_key(9);
        let mixed = mix_key16(&k);
        let fuse = SealedFuse8::build(&[mixed]).unwrap();
        assert!(fuse.contains(mixed));
    }

    #[test]
    fn sh_extract_workers_cap_at_1_5gib() {
        assert_eq!(SH_EXTRACT_WORKER_RAM_BYTES, 3 << 29);
        assert_eq!(
            crate::sorted_run::workers_for_free_ram(8, 3 << 30, SH_EXTRACT_WORKER_RAM_BYTES),
            2
        );
        assert_eq!(
            crate::sorted_run::workers_for_free_ram(16, 24 << 30, SH_EXTRACT_WORKER_RAM_BYTES),
            16
        );
    }

    #[test]
    fn class_a_scan_chunk_is_loc_fold_grain() {
        assert_eq!(
            CLASS_A_CHUNK_FKS,
            1 << 16,
            "inner loc/body batch inside a static worker span, not a steal grain"
        );
        assert_eq!(
            chunk_ranges(1, CLASS_A_CHUNK_FKS + 1, CLASS_A_CHUNK_FKS),
            vec![
                (1, CLASS_A_CHUNK_FKS),
                (CLASS_A_CHUNK_FKS + 1, CLASS_A_CHUNK_FKS + 1)
            ]
        );
        assert_eq!(
            chunk_ranges(1, 70_000, CLASS_A_CHUNK_FKS),
            vec![(1, CLASS_A_CHUNK_FKS), (CLASS_A_CHUNK_FKS + 1, 70_000)]
        );
    }

    #[test]
    fn keys_done_magic_is_shkeys02() {
        assert_eq!(KEYS_DONE_MAGIC, b"SHKEYS02");
        assert_eq!(POST_DONE_MAGIC, b"SHPOST02");
        assert_eq!(POSTS_SPILL_MAGIC, b"SHPST01\0");
        assert_eq!(POST_MAP_KEY_BYTES, 80);
        assert_eq!(POST_MAP_FK_BYTES, 8);
    }

    #[test]
    fn spill_largest_posts_writes_fattest_shard() {
        let dir = crate::testutil::TempDir::labeled("sh-post-largest").expect("temp");
        let mut maps: Vec<PostPackMap> = (0..2).map(|_| PostPackMap::default()).collect();
        insert_post_fk(&mut maps[0], prefix_key(1), 1);
        insert_post_fk(&mut maps[0], prefix_key(1), 2);
        insert_post_fk(&mut maps[1], prefix_key(2), 3);
        let seqs: Vec<AtomicU32> = (0..2).map(|_| AtomicU32::new(0)).collect();
        let fat = maps[0].estimated_bytes() as u64;
        spill_largest_posts_while_over(&mut maps, fat.saturating_sub(1), |si, map| {
            spill_post_shard_map(dir.path(), si, &seqs, map)
        })
        .unwrap();
        assert!(maps[0].is_empty());
        assert_eq!(maps[1].map.len(), 1);
        let folded = load_post_shard_map(dir.path(), 0).unwrap();
        assert_eq!(
            folded.map.get(&prefix_key(1)).map(|v| v.as_slice()),
            Some(&[1u64, 2][..])
        );
    }

    #[test]
    fn leftover_shunsrt3_done_is_not_ok() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-sh-done-v3-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let n_shards = 2usize;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SHUNSRT3");
        buf.extend_from_slice(&(n_shards as u32).to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        fs::write(dir.join("DONE"), &buf).unwrap();
        fs::write(unsorted_shard_path(&dir, 0), [0u8; 24]).unwrap();
        fs::write(unsorted_shard_path(&dir, 1), []).unwrap();
        assert!(
            unsorted_done_last_fk(&dir, n_shards).is_none(),
            "SHUNSRT3 must not count as DONE.keys"
        );
        assert!(leftover_legacy_unsorted(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn leftover_shunsrt2_done_is_not_ok() {
        let dir = std::env::temp_dir().join(format!(
            "rbitcoin-sh-done-v2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let n_shards = 2usize;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SHUNSRT2");
        buf.extend_from_slice(&(n_shards as u32).to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        fs::write(dir.join("DONE"), &buf).unwrap();
        fs::write(unsorted_shard_path(&dir, 0), []).unwrap();
        fs::write(unsorted_shard_path(&dir, 1), []).unwrap();
        assert!(
            unsorted_done_last_fk(&dir, n_shards).is_none(),
            "SHUNSRT2 without last_fk must restart collect"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_unsorted_collect_appends_only_when_no_shards() {
        assert!(matches!(
            plan_unsorted_collect(None, 10, false, true),
            UnsortedCollectAction::Full
        ));
        assert!(matches!(
            plan_unsorted_collect(Some(10), 10, false, true),
            UnsortedCollectAction::Skip
        ));
        assert!(matches!(
            plan_unsorted_collect(Some(4), 10, false, true),
            UnsortedCollectAction::Append { first: 5, last: 10 }
        ));
        assert!(matches!(
            plan_unsorted_collect(Some(4), 10, true, true),
            UnsortedCollectAction::Skip
        ));
        assert!(matches!(
            plan_unsorted_collect(Some(4), 10, false, false),
            UnsortedCollectAction::Full
        ));
    }

    #[test]
    fn keys_spill_delta_roundtrip_first_fk_order() {
        let mut map = Key16PackMap::default();
        insert_key_pack(&mut map, prefix_key(3), Fk(100));
        insert_key_word(&mut map, prefix_key(1), 0);
        insert_key_pack(&mut map, prefix_key(2), Fk(20));
        let bytes = encode_keys_spill(&map);
        assert_eq!(&bytes[0..8], KEYS_SPILL_MAGIC);
        let mut got = Key16PackMap::default();
        fold_keys_spill_bytes(&mut got, &bytes).unwrap();
        assert_eq!(got.get(&prefix_key(1)).copied(), Some(0));
        assert_eq!(got.get(&prefix_key(2)).copied(), Some(20));
        assert_eq!(got.get(&prefix_key(3)).copied(), Some(100));
    }

    #[test]
    fn reused_script_two_spans_one_spill_rec_under_cap() {
        let mut map = Key16PackMap::default();
        let k = prefix_key(7);
        insert_key_pack(&mut map, k, Fk(1));
        insert_key_pack(&mut map, k, Fk(65_536));
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&k).copied(), Some(0));
        let bytes = encode_keys_spill(&map);
        let n_multi = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let n_single = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        assert_eq!(n_multi, 1, "one rec while the map has not filled");
        assert_eq!(n_single, 0);
    }

    #[test]
    fn hashmap_iteration_order_seals_valid_mphf() {
        let mut map = Key16PackMap::default();
        insert_key_pack(&mut map, prefix_key(1), Fk(10));
        insert_key_pack(&mut map, prefix_key(2), Fk(20));
        insert_key_word(&mut map, prefix_key(3), 0);
        let mut recs = Vec::with_capacity(map.len());
        let mut mixed = Vec::with_capacity(map.len());
        for (k, w) in &map {
            mixed.push(mix_key16(k));
            recs.push((*k, *w));
        }
        let dir = crate::testutil::TempDir::labeled("sh-map-mphf").expect("temp");
        let base = dir.join("00");
        MphfHead::write_pack8_mixed(&base, &recs, &mixed).unwrap();
        let h = MphfHead::open(&base).unwrap();
        assert_eq!(
            h.get(&prefix_key(1)).unwrap().unwrap(),
            crate::scripthash_layout::ShHeadValue::inline_one(Fk(10))
        );
        assert_eq!(
            h.get(&prefix_key(2)).unwrap().unwrap(),
            crate::scripthash_layout::ShHeadValue::inline_one(Fk(20))
        );
        assert_eq!(
            h.get(&prefix_key(3)).unwrap().unwrap(),
            crate::scripthash_layout::ShHeadValue::Empty
        );
    }

    #[test]
    fn insert_post_fk_out_of_order_stays_strict_and_roundtrips() {
        let mut map = PostPackMap::default();
        let k = prefix_key(4);
        insert_post_fk(&mut map, k, 3);
        insert_post_fk(&mut map, k, 1);
        insert_post_fk(&mut map, k, 3);
        assert_eq!(map.map.get(&k).map(|v| v.as_slice()), Some(&[1u64, 3][..]));
        assert_eq!(map.n_fks, 2);
        let bytes = encode_posts_spill(&map);
        let mut round = PostPackMap::default();
        fold_posts_spill_bytes(&mut round, &bytes).unwrap();
        assert_eq!(
            round.map.get(&k).map(|v| v.as_slice()),
            Some(&[1u64, 3][..])
        );
    }

    #[test]
    fn fold_post_spills_merges_sorted_runs() {
        let dir = crate::testutil::TempDir::labeled("sh-post-merge-order").expect("temp");
        let k = prefix_key(8);
        write_post_spill_entries(dir.path(), 0, 0, &[(k, &[1u64, 5][..])]).unwrap();
        write_post_spill_entries(dir.path(), 0, 1, &[(k, &[3u64, 5, 9][..])]).unwrap();
        let map = load_post_shard_map(dir.path(), 0).unwrap();
        assert_eq!(
            map.map.get(&k).map(|v| v.as_slice()),
            Some(&[1u64, 3, 5, 9][..])
        );
        assert_eq!(map.n_fks, 4);
    }

    #[test]
    fn posts_two_fks_one_spill_rec_under_cap() {
        let mut map = PostPackMap::default();
        let k = prefix_key(7);
        insert_post_fk(&mut map, k, 2);
        insert_post_fk(&mut map, k, 2);
        insert_post_fk(&mut map, k, 11);
        assert_eq!(map.map.get(&k).map(|v| v.as_slice()), Some(&[2u64, 11][..]));
        assert_eq!(map.n_fks, 2);
        assert_eq!(
            map.estimated_bytes(),
            POST_MAP_KEY_BYTES + 2 * POST_MAP_FK_BYTES
        );
        let bytes = encode_posts_spill(&map);
        assert_eq!(&bytes[0..8], POSTS_SPILL_MAGIC);
        let n_keys = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(n_keys, 1);
        let mut round = PostPackMap::default();
        fold_posts_spill_bytes(&mut round, &bytes).unwrap();
        assert_eq!(
            round.map.get(&k).map(|v| v.as_slice()),
            Some(&[2u64, 11][..])
        );
    }

    #[test]
    fn tiny_post_budget_spills_then_flush() {
        let dir = crate::testutil::TempDir::labeled("sh-tiny-post").expect("temp");
        let mut maps = vec![PostPackMap::default()];
        let seqs = [AtomicU32::new(0)];
        insert_post_fk(&mut maps[0], prefix_key(1), 1);
        insert_post_fk(&mut maps[0], prefix_key(1), 2);
        insert_post_fk(&mut maps[0], prefix_key(2), 3);
        spill_largest_posts_while_over(&mut maps, 100, |si, map| {
            spill_post_shard_map(dir.path(), si, &seqs, map)
        })
        .unwrap();
        assert!(maps[0].is_empty());
        insert_post_fk(&mut maps[0], prefix_key(2), 4);
        spill_all_post_maps(&mut maps, |si, map| {
            spill_post_shard_map(dir.path(), si, &seqs, map)
        })
        .unwrap();
        assert!(unsorted_post_spill_path(dir.path(), 0, 0).is_file());
        assert!(unsorted_post_spill_path(dir.path(), 0, 1).is_file());
        assert!(unsorted_post_path(dir.path(), 0).is_dir());
        let folded = load_post_shard_map(dir.path(), 0).unwrap();
        assert_eq!(
            folded.map.get(&prefix_key(1)).map(|v| v.as_slice()),
            Some(&[1u64, 2][..])
        );
        assert_eq!(
            folded.map.get(&prefix_key(2)).map(|v| v.as_slice()),
            Some(&[3u64, 4][..])
        );
    }

    #[test]
    fn two_post_spills_fold_same_key() {
        let dir = crate::testutil::TempDir::labeled("sh-post-fold").expect("temp");
        let k = prefix_key(9);
        write_post_spill_entries(dir.path(), 0, 0, &[(k, &[1u64, 3][..])]).unwrap();
        write_post_spill_entries(dir.path(), 0, 1, &[(k, &[3u64, 5][..])]).unwrap();
        let map = load_post_shard_map(dir.path(), 0).unwrap();
        assert_eq!(
            map.map.get(&k).map(|v| v.as_slice()),
            Some(&[1u64, 3, 5][..])
        );
    }

    #[test]
    fn leftover_post_file_refuses_to_open() {
        let dir = crate::testutil::TempDir::labeled("sh-leftover-post").expect("temp");
        std::fs::create_dir_all(dir.join(POST_SUBDIR)).unwrap();
        let path = unsorted_post_path(dir.path(), 0);
        crate::file::write_synced_tmp_rename(&path, b"not-a-spill-dir").unwrap();
        match load_post_shard_map(dir.path(), 0) {
            Err(StoreError::Corrupt(m)) => {
                assert!(m.contains("wipe store/scripthash.unsorted"), "{m}");
            }
            other => panic!("must refuse leftover post file, got {other:?}"),
        }
        assert!(leftover_legacy_unsorted(dir.path()));
        assert!(leftover_post_file(dir.path()));
    }

    #[test]
    fn leftover_post_spill_wrong_magic_refuses() {
        let dir = crate::testutil::TempDir::labeled("sh-post-bad-magic").expect("temp");
        std::fs::create_dir_all(unsorted_post_path(dir.path(), 0)).unwrap();
        let path = unsorted_post_spill_path(dir.path(), 0, 0);
        crate::file::write_synced_tmp_rename(&path, b"SHPOST02........").unwrap();
        match load_post_shard_map(dir.path(), 0) {
            Err(StoreError::Corrupt(m)) => {
                assert!(m.contains("wipe store/scripthash.unsorted"), "{m}");
            }
            other => panic!("wrong magic must refuse, got {other:?}"),
        }
    }

    #[test]
    fn posts_spill_fallocate_padding_refuses() {
        let mut map = PostPackMap::default();
        insert_post_fk(&mut map, prefix_key(1), 7);
        let mut bytes = encode_posts_spill(&map);
        bytes.extend_from_slice(&[0u8; 64]);
        match fold_posts_spill_bytes(&mut PostPackMap::default(), &bytes) {
            Err(StoreError::Corrupt(m)) => {
                assert!(
                    m.contains("trailing bytes"),
                    "padding after SHPST01 must not scan as recs, got {m}"
                );
            }
            other => panic!("fallocate padding must refuse, got {other:?}"),
        }
    }
}
