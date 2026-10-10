use crate::chain::{ConfirmedTable, HeaderTxsTable, StrongTxTable};
use crate::error::StoreError;
use crate::hashhead::{HeadOpenOpts, HeadScale};
use crate::header_table::{HeaderRecord, HeaderTable};
use crate::height_fence::{HeightFence, MtpRing};
use crate::point_table::{self, PointRecord};
use crate::scripthash::ScriptHashTable;
use crate::spender_table::SpenderTable;
use crate::tx_table::{InputRecord, OutputRecord, TxRecord, TxTable};
use rbitcoin_primitives::{schema_file_openable, Fk, Height, SCHEMA_VERSION, STORE_MAGIC};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Sidecar in the hot `{datadir}/store`. Present when the append-only files live
/// under `{datadir-cold}/store`. Presence-only (the path comes from the operator).
pub const SEQSIGWIT_RELOC_NAME: &str = "seqsigwit.reloc";

/// Index directories that live next to seqsigwit when the store is split.
const COLD_INDEX_DIRS: &[&str] = &[
    "blockfilter.idx",
    "blockfilter.body",
    "sp_tweaks.idx",
    "sp_tweaks.body",
];

/// Where a store’s files live, plus open-time head geometry.
///
/// `dir` is `{datadir}/store`. When `cold_dir` is set and distinct, the
/// append-only IBD files live there: `seqsigwit.*`, `txstat.*`, `input.*`,
/// and (once enabled) `blockfilter.*` and `sp_tweaks.*`. The pin set stays
/// in `dir`.
///
/// [`Self::single`] / [`Self::with_cold`] are **Mainnet** scale (production).
/// Tests use [`Self::tiny`]. Scale is not read from `RBITCOIN_HEAD_SCALE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreLayout {
    pub dir: PathBuf,
    pub cold_dir: Option<PathBuf>,
    pub head_scale: HeadScale,
    pub tx_head_rebuild_seal_bits: Option<u32>,
    pub tx_head_rebuild_workers: Option<usize>,
}

impl StoreLayout {
    pub fn single(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            cold_dir: None,
            head_scale: HeadScale::Mainnet,
            tx_head_rebuild_seal_bits: None,
            tx_head_rebuild_workers: None,
        }
    }

    pub fn tiny(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            cold_dir: None,
            head_scale: HeadScale::Tiny,
            tx_head_rebuild_seal_bits: None,
            tx_head_rebuild_workers: None,
        }
    }

    pub fn with_cold(dir: impl Into<PathBuf>, cold_dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            cold_dir: Some(cold_dir.into()),
            head_scale: HeadScale::Mainnet,
            tx_head_rebuild_seal_bits: None,
            tx_head_rebuild_workers: None,
        }
    }

    pub fn with_cold_dir(mut self, cold_dir: impl Into<PathBuf>) -> Self {
        self.cold_dir = Some(cold_dir.into());
        self
    }

    pub fn with_head_scale(mut self, scale: HeadScale) -> Self {
        self.head_scale = scale;
        self
    }

    pub fn with_rebuild_seal_bits(mut self, bits: u32) -> Self {
        self.tx_head_rebuild_seal_bits = Some(bits);
        self
    }

    pub fn with_rebuild_workers(mut self, n: usize) -> Self {
        self.tx_head_rebuild_workers = Some(n);
        self
    }

    /// Header hash-head slot target (honors `RBITCOIN_HEAD_SLOTS_HEADER`).
    pub fn header_slots(&self) -> u64 {
        crate::hashhead::initial_slots_for(self.head_scale)
    }

    /// SH main shard count for this scale (1 Tiny, 64 Mainnet).
    pub fn sh_shard_count(&self) -> usize {
        self.head_scale.sh_main_shards()
    }

    /// `tx.head` bits (honors `RBITCOIN_TX_HEAD_BITS`).
    pub fn tx_head_bits(&self) -> u32 {
        crate::address_head::bits_for_scale(self.head_scale)
    }

    pub fn open_opts(&self) -> HeadOpenOpts {
        HeadOpenOpts {
            scale: self.head_scale,
            rebuild_seal_bits: self.tx_head_rebuild_seal_bits,
            rebuild_workers: self.tx_head_rebuild_workers,
        }
    }

    /// True when seqsigwit is configured on a different directory than the hot store.
    pub fn is_split(&self) -> bool {
        self.cold_dir.as_ref().is_some_and(|c| c != &self.dir)
    }

    pub fn seqsigwit_dir(&self) -> &Path {
        self.cold_dir
            .as_deref()
            .filter(|c| *c != self.dir)
            .unwrap_or(&self.dir)
    }
}

pub(crate) fn rename_legacy_input_files(dir: &Path) -> Result<(), StoreError> {
    if !dir.exists() {
        return Ok(());
    }
    for (old, new) in [
        ("inputs.loc", "input.loc"),
        ("inputs.off", "input.off"),
        ("inputs.body", "input.body"),
    ] {
        let from = dir.join(old);
        let to = dir.join(new);
        if !from.exists() {
            continue;
        }
        if to.exists() {
            return Err(StoreError::Layout(format!(
                "{} and {} both exist; keep only {}",
                from.display(),
                to.display(),
                new
            )));
        }
        std::fs::rename(&from, &to).map_err(|e| StoreError::io(&from, e))?;
    }
    Ok(())
}

pub(crate) fn rename_legacy_inwit_files(dir: &Path) -> Result<(), StoreError> {
    if !dir.exists() {
        return Ok(());
    }
    for (old, new) in [
        ("inwit.body", "seqsigwit.body"),
        ("inwit.loc", "seqsigwit.loc"),
        ("inwit.off", "seqsigwit.off"),
        ("inwit.loc.ovf", "seqsigwit.loc.ovf"),
        ("inwit.idx", "seqsigwit.idx"),
        ("inwit.reloc", "seqsigwit.reloc"),
        ("inwit.prune", "seqsigwit.prune"),
        ("inwit.window", "seqsigwit.window"),
    ] {
        let from = dir.join(old);
        let to = dir.join(new);
        if !from.exists() {
            continue;
        }
        if to.exists() {
            return Err(StoreError::Layout(format!(
                "{} and {} both exist; keep only {}",
                from.display(),
                to.display(),
                new
            )));
        }
        std::fs::rename(&from, &to).map_err(|e| StoreError::io(&from, e))?;
    }
    Ok(())
}

fn refuse_cold_index_dirs(hot: &Path, cold: &Path) -> Result<(), StoreError> {
    for name in COLD_INDEX_DIRS {
        let on_hot = hot.join(name);
        let on_cold = cold.join(name);
        if !on_hot.is_dir() {
            continue;
        }
        if on_cold.exists() {
            return Err(StoreError::Layout(format!(
                "{name} exists in both {} and {}; keep it only under the cold store",
                hot.display(),
                cold.display()
            )));
        }
        return Err(StoreError::Layout(format!(
            "{name} is still in {}; move it next to seqsigwit under {}",
            hot.display(),
            cold.display()
        )));
    }
    Ok(())
}

fn seqsigwit_files_present(dir: &Path) -> bool {
    dir.join("seqsigwit.body").exists()
        || dir.join("seqsigwit.loc").exists()
        || dir.join("seqsigwit.idx").exists()
}

fn seqsigwit_reloc_path(hot: &Path) -> PathBuf {
    hot.join(SEQSIGWIT_RELOC_NAME)
}

/// Decide the seqsigwit VarTable directory. Split stores refuse leftovers in hot
/// and dual copies; a reloc marker without `--datadir-cold` is a layout error
/// (not `Corrupt`).
fn resolve_seqsigwit_dir(layout: &StoreLayout) -> Result<PathBuf, StoreError> {
    rename_legacy_inwit_files(&layout.dir)?;
    rename_legacy_input_files(&layout.dir)?;
    if !layout.is_split() {
        if seqsigwit_reloc_path(&layout.dir).exists() {
            return Err(StoreError::Layout(format!(
                "seqsigwit is on a cold datadir ({SEQSIGWIT_RELOC_NAME} present); pass --datadir-cold"
            )));
        }
        return Ok(layout.dir.clone());
    }
    let cold = layout.seqsigwit_dir();
    rename_legacy_inwit_files(cold)?;
    rename_legacy_input_files(cold)?;
    if !cold.exists() {
        std::fs::create_dir_all(cold).map_err(|e| StoreError::io(cold, e))?;
    } else if !cold.is_dir() {
        return Err(StoreError::NotDirectory(cold.to_path_buf()));
    }
    let hot_has = seqsigwit_files_present(&layout.dir);
    let cold_has = seqsigwit_files_present(cold);
    match (hot_has, cold_has) {
        (true, true) => Err(StoreError::Layout(format!(
            "seqsigwit.body exists in both {} and {}; keep it only under the cold store",
            layout.dir.display(),
            cold.display()
        ))),
        (true, false) => Err(StoreError::Layout(format!(
            "seqsigwit is still in {}; move seqsigwit.body and seqsigwit.loc to {} \
             (copy+remove if cross-device)",
            layout.dir.display(),
            cold.display()
        ))),
        (false, _) => Ok(cold.to_path_buf()),
    }
}

fn dir_file_bytes(root: &Path) -> u64 {
    fn walk(p: &Path, acc: &mut u64) {
        let Ok(rd) = std::fs::read_dir(p) else {
            return;
        };
        for ent in rd.flatten() {
            let path = ent.path();
            let Ok(meta) = ent.metadata() else {
                continue;
            };
            if meta.is_dir() {
                walk(&path, acc);
            } else if meta.is_file() {
                *acc = acc.saturating_add(meta.len());
            }
        }
    }
    let mut n = 0;
    walk(root, &mut n);
    n
}

fn write_seqsigwit_reloc(hot: &Path) -> Result<(), StoreError> {
    let p = seqsigwit_reloc_path(hot);
    if p.exists() {
        return Ok(());
    }
    std::fs::write(&p, b"seqsigwit\n").map_err(|e| StoreError::io(&p, e))
}

/// Top-level store handle for a datadir `store/` directory.
pub struct Store {
    path: PathBuf,
    /// `{datadir-cold}/store` when append-only files are split; `None` = they live in [`Self::path`].
    cold_path: Option<PathBuf>,
    head_scale: HeadScale,
    pub headers: HeaderTable,
    pub txs: TxTable,
    /// Multi-spender overflow (`spent.ovf`). Sole spends live on create outputs.
    pub spenders: SpenderTable,
    pub scripthash: ScriptHashTable,
    pub confirmed: ConfirmedTable,
    pub strong_tx: StrongTxTable,
    /// Class A: header_fk → tx list (archive before tip confirm).
    /// Confirmed heights resolve txs via `confirmed[h]` → this list.
    pub header_txs: HeaderTxsTable,
    /// Resident create-height fence (confirmed[] + header_txs). No `tx_height.body`.
    height_fence: std::sync::RwLock<HeightFence>,
    /// BIP113 window at the fence tip (extend O(1); pop rebuilds).
    mtp_ring: std::sync::RwLock<MtpRing>,
    /// Latest confirm height plus one. Zero means no snapshot yet.
    spend_snapshot: std::sync::atomic::AtomicU64,
    /// Serializes spend-marker publishes so a checkpoint cannot overwrite a clamp.
    spend_marker: std::sync::Mutex<()>,
    /// First height of a confirm write whose spend annotate has not finished,
    /// plus one. Zero means none.
    spend_annotate_from: std::sync::atomic::AtomicU64,
    /// Disconnects since process start. A checkpoint publishes only when this
    /// word is unchanged across its `sync_data` window.
    spend_reorg_gen: std::sync::atomic::AtomicU64,
    /// Even while confirmed spentness is stable. Odd while a confirm annotate
    /// or a disconnect is publishing a change.
    utxo_view: std::sync::atomic::AtomicU64,
}

/// Holds [`Store::utxo_view`] odd until drop.
pub struct UtxoViewGuard<'a> {
    view: &'a std::sync::atomic::AtomicU64,
}

impl Drop for UtxoViewGuard<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.view.fetch_add(1, Ordering::Release);
    }
}

/// How txid → Class A fk picks among rows with the same txid.
///
/// Head probe is newest-first. A later **unconnected** row (rejected block)
/// must not hide an older **connected** instance (height fence hit).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxidResolveMode {
    /// Connected instance only (fence height Some). Else `None`.
    /// Confirm stamp, structural spends, mempool "confirmed?", annotate.
    TipOnly,
    /// Connected if any, else newest unconnected Class A row (RPC / reconstruct).
    TipThenAny,
}

/// Compact `items` to the in-order live vouts from [`Store::unspent_create_vouts`].
pub fn keep_unspent_vout_subsequence<T>(
    items: &mut Vec<T>,
    live: &[u32],
    vout: impl Fn(&T) -> u32,
) {
    if live.len() == items.len() {
        return;
    }
    let mut i = 0;
    items.retain(|item| {
        if i < live.len() && live[i] == vout(item) {
            i += 1;
            true
        } else {
            false
        }
    });
}

impl Store {
    pub fn create(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::create_layout(StoreLayout::single(path.into()))
    }

    pub fn create_tiny(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::create_layout(StoreLayout::tiny(path.into()))
    }

    pub fn create_layout(layout: StoreLayout) -> Result<Self, StoreError> {
        let head = crate::address_head::default_layout(layout.head_scale);
        Self::create_layout_with_head(layout, head)
    }

    pub(crate) fn create_layout_with_head(
        layout: StoreLayout,
        head: crate::address_head::HeadLayout,
    ) -> Result<Self, StoreError> {
        // SH open-address shards open many FDs; raise soft nofile before create.
        crate::file::ensure_nofile_budget();
        let path = layout.dir.clone();
        if path.exists() {
            if !path.is_dir() {
                return Err(StoreError::NotDirectory(path));
            }
        } else {
            std::fs::create_dir_all(&path).map_err(|e| StoreError::io(&path, e))?;
        }
        write_meta(&path)?;
        let seqsigwit_dir = resolve_seqsigwit_dir(&layout)?;
        let opts = layout.open_opts();
        let txs = TxTable::create_with_head_layout_seqsigwit(&path, &seqsigwit_dir, head, opts)?;
        if layout.is_split() {
            write_seqsigwit_reloc(&path)?;
        }
        let cold_path = layout.is_split().then_some(seqsigwit_dir);
        Ok(Self {
            headers: HeaderTable::create_with_scale(&path, layout.head_scale)?,
            txs,
            spenders: SpenderTable::create(&path)?,
            scripthash: ScriptHashTable::create_with_scale(&path, layout.head_scale)?,
            confirmed: ConfirmedTable::create(&path)?,
            strong_tx: StrongTxTable::create(&path)?,
            header_txs: HeaderTxsTable::create(&path)?,
            height_fence: std::sync::RwLock::new(HeightFence::empty()),
            mtp_ring: std::sync::RwLock::new(MtpRing::empty()),
            spend_snapshot: std::sync::atomic::AtomicU64::new(0),
            spend_annotate_from: std::sync::atomic::AtomicU64::new(0),
            spend_reorg_gen: std::sync::atomic::AtomicU64::new(0),
            utxo_view: std::sync::atomic::AtomicU64::new(0),
            spend_marker: std::sync::Mutex::new(()),
            path,
            cold_path,
            head_scale: layout.head_scale,
        })
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::open_layout(StoreLayout::single(path.into()))
    }

    pub fn open_tiny(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::open_layout(StoreLayout::tiny(path.into()))
    }

    pub fn open_layout(layout: StoreLayout) -> Result<Self, StoreError> {
        crate::file::ensure_nofile_budget();
        let path = layout.dir.clone();
        if !path.is_dir() {
            return Err(StoreError::NotDirectory(path));
        }
        let meta_ver = check_meta(&path)?;
        open_layout_refuse_old(&path, meta_ver)?;
        drop_unread_store_leftovers(&path);
        let scripthash = if path.join("scripthash.body").exists() {
            ScriptHashTable::open_with_scale(&path, layout.head_scale)?
        } else {
            ScriptHashTable::create_with_scale(&path, layout.head_scale)?
        };
        let header_txs = if path.join("header_txs_first.body").exists() {
            HeaderTxsTable::open(&path)?
        } else {
            HeaderTxsTable::create(&path)?
        };
        let confirmed = ConfirmedTable::open(&path)?;
        let height_fence = HeightFence::from_confirmed(&confirmed, &header_txs)?;
        drop_leftover_tx_height(&path);
        crate::scripthash::unlink_scripthash_run_leftovers(&path)?;
        open_layout_rewrite_current(&path, meta_ver)?;
        let seqsigwit_dir = resolve_seqsigwit_dir(&layout)?;
        if layout.is_split() {
            refuse_cold_index_dirs(&path, &seqsigwit_dir)?;
        }
        let txs = TxTable::open_seqsigwit(&path, &seqsigwit_dir, layout.open_opts())?;
        if layout.is_split() {
            write_seqsigwit_reloc(&path)?;
        }
        let cold_path = layout.is_split().then_some(seqsigwit_dir);
        let store = Self {
            headers: HeaderTable::open_with_scale(&path, layout.head_scale)?,
            txs,
            spenders: SpenderTable::open(&path)?,
            scripthash,
            confirmed,
            strong_tx: StrongTxTable::open(&path)?,
            header_txs,
            height_fence: std::sync::RwLock::new(height_fence),
            mtp_ring: std::sync::RwLock::new(MtpRing::empty()),
            spend_snapshot: std::sync::atomic::AtomicU64::new(0),
            spend_annotate_from: std::sync::atomic::AtomicU64::new(0),
            spend_reorg_gen: std::sync::atomic::AtomicU64::new(0),
            utxo_view: std::sync::atomic::AtomicU64::new(0),
            spend_marker: std::sync::Mutex::new(()),
            path,
            cold_path,
            head_scale: layout.head_scale,
        };
        store.rebuild_mtp_ring()?;
        Ok(store)
    }

    pub fn open_or_create(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::open_or_create_layout(StoreLayout::single(path.into()))
    }

    pub fn open_or_create_tiny(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::open_or_create_layout(StoreLayout::tiny(path.into()))
    }

    pub fn head_scale(&self) -> HeadScale {
        self.head_scale
    }

    pub fn open_or_create_layout(layout: StoreLayout) -> Result<Self, StoreError> {
        if layout.dir.join("meta").exists() {
            Self::open_layout(layout)
        } else {
            Self::create_layout(layout)
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Cold store directory when the append-only files are split
    /// (`{datadir-cold}/store`).
    pub fn cold_path(&self) -> Option<&Path> {
        self.cold_path.as_deref()
    }

    /// Where IBD append-only files live. The cold store when split, otherwise
    /// [`Self::path`].
    pub fn cold_files_dir(&self) -> &Path {
        self.cold_path.as_deref().unwrap_or(&self.path)
    }

    /// Sum of regular file lengths under the hot store and, when split, the
    /// cold store. Used by `getblockchaininfo.size_on_disk`.
    pub fn datadir_bytes(&self) -> u64 {
        let mut n = dir_file_bytes(&self.path);
        if let Some(cold) = &self.cold_path {
            n = n.saturating_add(dir_file_bytes(cold));
        }
        n
    }

    pub fn tip_height(&self) -> Option<Height> {
        self.confirmed.tip_height()
    }

    fn fence(&self) -> std::sync::RwLockReadGuard<'_, HeightFence> {
        self.height_fence.read().unwrap_or_else(|e| e.into_inner())
    }

    fn fence_write(&self) -> std::sync::RwLockWriteGuard<'_, HeightFence> {
        self.height_fence.write().unwrap_or_else(|e| e.into_inner())
    }

    fn mtp_write(&self) -> std::sync::RwLockWriteGuard<'_, MtpRing> {
        self.mtp_ring.write().unwrap_or_else(|e| e.into_inner())
    }

    /// BIP113 times for `height` when it is the fence tip and the ring is warm.
    pub fn mtp_times_at(&self, height: Height) -> Option<(u8, [u32; 11])> {
        self.mtp_ring
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .window_at(height.0)
    }

    fn mtp_push(&self, height: u32, time: u32) {
        let pushed = self.mtp_write().try_push(height, time);
        if pushed {
            return;
        }
        let _ = self.rebuild_mtp_ring();
        let _ = self.mtp_write().try_push(height, time);
    }

    fn rebuild_mtp_ring(&self) -> Result<(), StoreError> {
        let Some(tip) = self.confirmed.tip_height() else {
            self.mtp_write().clear();
            return Ok(());
        };
        let start = tip.0.saturating_sub(10);
        let mut times = Vec::with_capacity((tip.0 - start + 1) as usize);
        for h in start..=tip.0 {
            let Some(fk) = self.confirmed.get(Height(h))? else {
                self.mtp_write().clear();
                return Ok(());
            };
            let rec = match self.headers.get(fk) {
                Ok(r) => r,
                Err(_) => {
                    self.mtp_write().clear();
                    return Ok(());
                }
            };
            times.push(rec.timestamp);
        }
        self.mtp_write().set_window(tip.0, &times);
        Ok(())
    }

    /// First fk whose `tx.head` row may sit in slot pages a power loss left
    /// with holes ([`crate::segmented_head::SegmentedTxHead::unsynced_first_fk`]).
    /// It never falls, so a value read before a head read bounds every
    /// segment that read probed.
    pub fn head_unsynced_first_fk(&self) -> u64 {
        self.txs.head_unsynced_first_fk()
    }

    /// Txids of `sorted` that `txid.body` holds at a connected fk at or
    /// above `from_fk` ([`Self::head_unsynced_first_fk`], read before the
    /// head read that missed them). After a power loss the head can miss a
    /// connected create there while its synced count still covers it; open
    /// does not see that. `stop` is polled before each chunk: a stopped scan
    /// is `Cancelled`, never a result.
    ///
    /// IO: a sequential `txid.body` read from `from_fk` to the last create:
    /// the open tail, plus the previous segment while its seal is in flight
    /// (up to about 54 M txids, 1.7 GiB, on mainnet). RAM: one 2 MiB chunk at
    /// a time. Only a reject path pays this.
    pub fn connected_in_unsynced_head(
        &self,
        from_fk: u64,
        sorted: &[[u8; 32]],
        stop: impl Fn() -> bool,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        const CHUNK: u64 = 65_536;
        debug_assert!(sorted.is_sorted(), "binary_search needs a sorted slice");
        let fence = self.height_fence_snapshot();
        let last = self.txs.count();
        let mut cur = from_fk.max(1);
        let mut out = Vec::new();
        while cur <= last {
            if stop() {
                return Err(StoreError::Cancelled("tx.head unsynced scan"));
            }
            let end = cur.saturating_add(CHUNK - 1).min(last);
            for (fk, txid) in (cur..=end).zip(self.txs.body_txid_range(cur, end)?) {
                if sorted.binary_search(&txid).is_ok() && fence.height_of(Fk(fk)).is_some() {
                    out.push(txid);
                }
            }
            cur = end + 1;
        }
        Ok(out)
    }

    /// Highest create_fk in a connected fence run (`0` if empty).
    pub fn fence_max_connected_fk(&self) -> u64 {
        self.fence().max_connected_fk()
    }

    /// Clone of the RAM fence (leftover TipOnly / in-flight prune with drain).
    pub fn height_fence_snapshot(&self) -> crate::height_fence::HeightFence {
        self.fence().clone()
    }

    /// Run count only (sizes tick — no Vec clone).
    pub fn height_fence_run_count(&self) -> usize {
        self.fence().len()
    }

    /// Highest height whose Class A run is on the RAM fence (`None` if empty).
    ///
    /// Max height on the fence. In-flight prune requires this span **and**
    /// drain-fk (`Query::head_drain_fk`).
    pub fn fence_tip_height(&self) -> Option<u32> {
        self.fence().max_height()
    }

    /// Connected create height from the RAM fence (`None` = unconnected / hole).
    pub fn tx_height_get(&self, tx_fk: Fk) -> Result<Option<u32>, StoreError> {
        if tx_fk.is_null() {
            return Err(StoreError::InvalidFk);
        }
        Ok(self.fence().height_of(tx_fk))
    }

    /// Rebuild the fence from `confirmed[]` + `header_txs` (open / tests).
    pub fn rebuild_height_fence(&self) -> Result<(), StoreError> {
        let f = HeightFence::from_confirmed(&self.confirmed, &self.header_txs)?;
        *self.fence_write() = f;
        self.rebuild_mtp_ring()
    }

    /// Append this height’s Class A run to the live fence.
    ///
    /// Confirm calls this **before** `confirmed.set_many` so a missing range
    /// cannot leave tip ahead of `height_of`. Missing or empty `header_txs` is
    /// **Corrupt** — a silent `Ok` leaves `height_of` None for that block’s
    /// creates and TipOnly leftover misses (restart rebuild from disk then heals).
    pub fn height_fence_extend(&self, height: Height, header_fk: Fk) -> Result<(), StoreError> {
        let Some((first, n)) = self.header_txs.get_range(header_fk)? else {
            return Err(StoreError::Corrupt(
                "height fence: header_txs range missing",
            ));
        };
        if n == 0 || first.is_null() {
            return Err(StoreError::Corrupt("height fence: header_txs range empty"));
        }
        let time = self.headers.get(header_fk).ok().map(|r| r.timestamp);
        self.fence_write().extend(height.0, first, n);
        match time {
            Some(t) => self.mtp_push(height.0, t),
            None => self.mtp_write().clear(),
        }
        Ok(())
    }

    /// After tip shrink: drop the disconnected height’s run.
    pub fn height_fence_pop_tip(&self, height: Height) {
        self.fence_write().pop_height(height.0);
        let _ = self.rebuild_mtp_ring();
    }

    /// Header write gate: unique by full hash; reject false `prev_fk` edges.
    /// See [`HeaderTable::ensure`].
    pub fn put_header(&self, rec: &HeaderRecord) -> Result<Fk, StoreError> {
        self.headers.ensure(rec)
    }

    /// Batch [`Self::put_header`] (one body write + chunked `header.head` insert).
    pub fn put_headers(&self, recs: &[HeaderRecord]) -> Result<Vec<Fk>, StoreError> {
        self.headers.ensure_batch(recs)
    }

    pub fn get_header(&self, fk: Fk) -> Result<HeaderRecord, StoreError> {
        self.headers.get(fk)
    }

    pub fn get_header_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<(Fk, HeaderRecord)>, StoreError> {
        self.headers.get_by_hash(hash)
    }

    /// Total Class A header rows (confirmed + unconfirmed archive path).
    pub fn header_count(&self) -> u64 {
        self.headers.count()
    }

    /// Headers that currently have a Class A body association.
    pub fn archived_block_count(&self) -> Result<u64, StoreError> {
        self.header_txs.count_bodies()
    }

    /// Flush header + body-association tables only (cheaper than full store flush).
    ///
    /// Used by the IBD archive writer so Class A survives unclean restarts without
    /// fsyncing every mega-batch of txs/ins/outs.
    ///
    pub fn flush_header_archive(&self) -> Result<(), StoreError> {
        self.headers.flush()?;
        self.header_txs.flush()?;
        Ok(())
    }

    /// Meta by fk: the same packed decode as [`Self::get_tx_meta_and_outputs`]
    /// with the outs dropped, so a reader that needs both takes the latter once.
    pub fn get_tx(&self, fk: Fk) -> Result<TxRecord, StoreError> {
        self.txs.get(fk)
    }

    /// Full Class A body by fk: zip `txout` + `seqsigwit`.
    pub fn get_tx_full(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<InputRecord>, Vec<OutputRecord>), StoreError> {
        self.txs.get_full(fk)
    }

    /// Contiguous `first..=last` Class A bodies: one txout span + one seqsigwit span.
    pub fn get_tx_full_span(
        &self,
        first: u64,
        last: u64,
    ) -> Result<Vec<crate::tx_table::PackedTx>, StoreError> {
        self.txs.get_full_span(first, last)
    }

    /// Parent-prevout hot path: meta + outputs only (no input materialization).
    pub fn get_tx_meta_and_outputs(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<OutputRecord>), StoreError> {
        self.txs.get_meta_and_outputs(fk)
    }

    /// Page-grouped `txid.body` identity for scattered create fks.
    pub fn txids_get_many(&self, fks: &[Fk]) -> Result<Vec<Option<[u8; 32]>>, StoreError> {
        self.txs.txid_sidefile().get_many(fks)
    }

    /// Class A `script_hash` values for create_fks `first..=last` (coalesced span).
    pub fn for_each_create_script_hashes_in_fk_span(
        &self,
        first: u64,
        last: u64,
        f: impl FnMut(Fk, [u8; 32]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        self.txs.for_each_script_hashes_in_fk_span(first, last, f)
    }

    /// Load: meta + input prevouts only (no script/output allocation).
    pub fn get_tx_meta_and_prevouts(
        &self,
        fk: Fk,
    ) -> Result<(TxRecord, Vec<(Fk, u32)>), StoreError> {
        self.txs.get_meta_and_prevouts(fk)
    }

    /// Consecutive `txstat.body` rows `first..=last` for one header. All-zero → `None`.
    pub fn txstat_range(
        &self,
        header_fk: Fk,
        first: u64,
        last: u64,
    ) -> Result<Vec<Option<crate::TxStatRow>>, StoreError> {
        let blob = self.txs.txstat.header_blob(header_fk)?;
        self.txs.txstat.get_range(first, last, Some(&blob))
    }

    /// Overwrite one existing `txstat` row that fits in 8 B (tests / placeholders).
    /// `n_in` from `input.loc`, or `None` when that create is unstamped.
    pub fn input_n_in(&self, fk: Fk) -> Result<Option<u32>, StoreError> {
        self.txs.input.n_in(fk)
    }

    /// Parent edges in vin order, or `None` when `input.loc` is unstamped.
    pub fn input_edges(&self, fk: Fk) -> Result<Option<Vec<crate::input::InputEdge>>, StoreError> {
        self.txs.input.edges(fk)
    }

    /// Copy parent edges onto seqsigwit records that do not store them.
    pub fn stamp_input_prevouts(
        &self,
        fk: Fk,
        ins: &mut [crate::tx_table::InputRecord],
    ) -> Result<(), StoreError> {
        self.txs.stamp_seqsigwit_prevouts(fk, ins)
    }

    pub fn write_txstat_row(&self, fk: Fk, row: &crate::TxStatRow) -> Result<(), StoreError> {
        self.txs.txstat.write_row(fk, row)
    }

    /// Stamp a confirmed block's `txstat` cells and that header's overflow blob.
    pub fn write_txstat_block(
        &self,
        header_fk: Fk,
        first_fk: u64,
        rows: &[crate::TxStatRow],
    ) -> Result<(), StoreError> {
        self.txs.txstat.write_block_rows(header_fk, first_fk, rows)
    }

    /// One `txstat.body` row, or `None` if unstamped (all-zero). Loads overflow if needed.
    pub fn txstat_row(&self, fk: Fk) -> Result<Option<crate::TxStatRow>, StoreError> {
        let cell = self.txs.txstat.get_cell(fk)?;
        match crate::txstat::parse_cell(cell)? {
            crate::txstat::CellParse::Unstamped => Ok(None),
            crate::txstat::CellParse::Complete(row) => Ok(Some(row)),
            crate::txstat::CellParse::NeedTail => {
                let h = self
                    .tx_height_get(fk)?
                    .ok_or(StoreError::Corrupt("invariant: txstat overflow missing"))?;
                let hfk = self
                    .confirmed
                    .get(Height(h))?
                    .ok_or(StoreError::Corrupt("invariant: txstat overflow missing"))?;
                let (first, _) = self
                    .header_txs
                    .get_range(hfk)?
                    .ok_or(StoreError::Corrupt("invariant: txstat overflow missing"))?;
                let blob = self.txs.txstat.header_blob(hfk)?;
                self.txs.txstat.get_row_merged(fk, first.0, &blob)
            }
        }
    }

    /// Absolute body `(offset, len)` for `fk` (for cache idx cache).
    pub fn tx_body_range(&self, fk: Fk) -> Result<(u64, u64), StoreError> {
        self.txs.body_range(fk)
    }

    /// Absolute `spent.body` `(offset, len)` for `fk` (annotate / unspent).
    pub fn tx_spent_range(&self, fk: Fk) -> Result<(u64, u64), StoreError> {
        self.txs.spent_range(fk)
    }

    /// Absolute `seqsigwit.body` `(offset, len)` for `fk`.
    pub fn tx_seqsigwit_range(&self, fk: Fk) -> Result<(u64, u64), StoreError> {
        self.txs.seqsigwit_range(fk)
    }

    pub fn prune_seqsigwit_mode(&self) -> bool {
        self.txs.prune_seqsigwit_mode()
    }

    pub fn set_prune_seqsigwit_mode(&self, on: bool) {
        self.txs.set_prune_seqsigwit_mode(on);
    }

    pub fn clear_durable_seqsigwit(&self) -> Result<(), StoreError> {
        self.txs.clear_durable_seqsigwit()
    }

    /// Append packed full-tx Class A rows (preferred archive path).
    pub fn put_tx_full_batch_indexed(
        &self,
        items: &[(TxRecord, Vec<InputRecord>, Vec<OutputRecord>)],
        index: bool,
    ) -> Result<Vec<Fk>, StoreError> {
        self.txs.put_full_batch_indexed(items, index)
    }

    /// Append Class A rows from shared pin Arc + inputs (no outs reclone).
    ///
    /// `pin` is `(TxRecord, outs)`. `spent_overlay` is per-item `(vout, spend_fk, vin)`
    /// (empty = all zeros).
    pub fn put_tx_full_batch_from_pins<P: crate::tx_table::PackedCreate>(
        &self,
        items: &[(P, Vec<crate::InputRecord>)],
        index: bool,
        spent_overlay: &[Vec<(u32, Fk, u32)>],
    ) -> Result<(Vec<Fk>, Vec<crate::create_loc::CreateLocPair>), StoreError> {
        self.txs
            .put_full_batch_from_pins(items, index, spent_overlay)
    }

    pub fn put_tx_full_batch_from_pins_with_txstat<P: crate::tx_table::PackedCreate>(
        &self,
        items: &[(P, Vec<crate::InputRecord>)],
        index: bool,
        spent_overlay: &[Vec<(u32, Fk, u32)>],
        txstat: &[crate::txstat::TxStatRow],
        header_ranges: &[(Fk, Fk, u32)],
    ) -> Result<(Vec<Fk>, Vec<crate::create_loc::CreateLocPair>), StoreError> {
        self.txs.put_full_batch_from_pins_with_txstat(
            items,
            index,
            spent_overlay,
            txstat,
            header_ranges,
        )
    }

    #[allow(clippy::too_many_arguments)] // same wave as append_stems_one_wave
    /// Class A append. `input_edges[i]` is one [`crate::InputEdge`] per vin.
    /// `encode_in` writes `seqsigwit` for that row.
    pub fn put_tx_pins_encoded<P: crate::tx_table::PackedCreate>(
        &self,
        pins: &[&P],
        index: bool,
        spent_overlay: &[Vec<(u32, Fk, u32)>],
        txstat: &[crate::txstat::TxStatRow],
        header_ranges: &[(Fk, Fk, u32)],
        input_edges: &[Vec<crate::input::InputEdge>],
        est_seqsigwit: usize,
        encode_in: impl FnMut(usize, &mut Vec<u8>),
    ) -> Result<(Vec<Fk>, Vec<crate::create_loc::CreateLocPair>), StoreError> {
        self.txs.put_pins_encoded(
            pins,
            index,
            spent_overlay,
            txstat,
            header_ranges,
            input_edges,
            est_seqsigwit,
            encode_in,
        )
    }

    pub fn get_tx_by_txid(&self, txid: &[u8; 32]) -> Result<Option<(Fk, TxRecord)>, StoreError> {
        self.txs.get_by_txid(txid)
    }

    pub fn get_txstat(&self, fk: Fk) -> Result<Option<crate::TxStatRow>, StoreError> {
        self.txstat_row(fk)
    }

    /// Annotate create outpoint as spent by `spending_tx_fk` at `spending_vin`.
    pub fn put_spend_create(
        &self,
        create_tx_fk: Fk,
        out_index: u32,
        spending_tx_fk: Fk,
        spending_vin: u32,
    ) -> Result<(), StoreError> {
        point_table::put_spend_on_create(
            &self.txs,
            &self.spenders,
            create_tx_fk,
            out_index,
            spending_tx_fk,
            spending_vin,
        )
    }

    /// Resolve `out_txid` via `tx.head`, then [`Self::put_spend_create`].
    pub fn put_spend(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
        spending_tx_fk: Fk,
        spending_vin: u32,
    ) -> Result<Fk, StoreError> {
        let create_fk = if let Some(fk) = self.txs.queued_pending_fk(out_txid) {
            fk
        } else {
            self.txs
                .probe_body_match_fk(out_txid)?
                .ok_or(StoreError::NotFound)?
        };
        self.put_spend_create(create_fk, out_index, spending_tx_fk, spending_vin)?;
        Ok(spending_tx_fk)
    }

    /// Bulk annotate by out_txid (resolves each create via `tx.head`).
    pub fn put_spend_batch(
        &self,
        edges: &[([u8; 32], u32, Fk, u32)],
    ) -> Result<Vec<Fk>, StoreError> {
        let mut out = Vec::with_capacity(edges.len());
        for &(txid, vout, spend_fk, vin) in edges {
            self.put_spend(&txid, vout, spend_fk, vin)?;
            out.push(spend_fk);
        }
        Ok(out)
    }

    /// Bulk create heights from the RAM fence (confirm write / BIP68).
    pub fn tx_height_get_batch(&self, fks: &[Fk]) -> Result<Vec<Option<u32>>, StoreError> {
        Ok(self.fence().get_batch(fks))
    }

    /// Coinbase Class A fk for each confirmed height (or `None` if tip/header missing).
    ///
    /// Uses only Class C dense tables (`confirmed` + `header_txs_first`) — **no**
    /// `tx.body`. Used by confirm write `create_h` to detect coinbase without
    /// decoding create inputs.
    pub fn coinbase_fk_at_heights(&self, heights: &[u32]) -> Result<crate::U32Map<Fk>, StoreError> {
        use rbitcoin_primitives::Height;
        if heights.is_empty() {
            return Ok(crate::U32Map::default());
        }
        let mut uniq: Vec<u32> = heights.to_vec();
        uniq.sort_unstable();
        uniq.dedup();
        let hs: Vec<Height> = uniq.iter().map(|&h| Height(h)).collect();
        let headers = self.confirmed.get_many(&hs)?;
        let mut out = crate::U32Map::with_capacity_and_hasher(uniq.len(), Default::default());
        for (i, &h) in uniq.iter().enumerate() {
            let Some(hfk) = headers[i] else {
                continue;
            };
            if let Some((first, _)) = self.header_txs.get_range(hfk)? {
                out.insert(h, first);
            }
        }
        Ok(out)
    }

    /// Annotate spends using absolute 8-byte spender-meta offsets (pin layout).
    ///
    /// Tuple: `(abs_off, create_tx_fk, vout, spending_tx_fk, spending_vin)`.
    /// Prefer io_uring RMW (read → sole/multi/promote → write); multi-list nodes
    /// go to `spent.ovf` inline on read completion. Returns edges that still
    /// need a full cold path (OOB abs).
    pub fn put_spend_batch_by_abs_meta(
        &self,
        abs_edges: &[(u64, Fk, u32, Fk, u32)],
    ) -> Result<Vec<(Fk, u32, Fk, u32)>, StoreError> {
        self.txs
            .put_spend_batch_by_abs_meta(&self.spenders, abs_edges)
    }

    /// Resolve txid → Class A fk without full body decode (head probe + body txid).
    ///
    /// **`TipThenAny`:** RPC / reconstruct (connected if present, else newest).
    pub fn get_fk_by_txid(&self, txid: &[u8; 32]) -> Result<Option<Fk>, StoreError> {
        Ok(self
            .get_fk_by_txid_batch_mode(std::slice::from_ref(txid), TxidResolveMode::TipThenAny)?
            .into_iter()
            .next()
            .and_then(|(_, hit)| hit.map(|(fk, _)| fk)))
    }

    /// Confirm / consensus: connected instance only.
    pub fn get_fk_by_txid_tip(&self, txid: &[u8; 32]) -> Result<Option<Fk>, StoreError> {
        Ok(self.get_fk_by_txid_tip_height(txid)?.map(|(fk, _)| fk))
    }

    /// The connected instance and its fence height: verifies each head
    /// candidate's body txid and does one batched fence read, no body decode.
    /// A prevout reader that needs the create height takes this once.
    pub fn get_fk_by_txid_tip_height(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<(Fk, u32)>, StoreError> {
        let fks = self.txs.fks_by_txid(txid)?;
        let heights = self.tx_height_get_batch(&fks)?;
        Ok(fks
            .into_iter()
            .zip(heights)
            .find_map(|(fk, h)| Some((fk, h?))))
    }

    /// Batch head resolve for plan stamp: txid → (fk, body_range).
    ///
    /// Confirm uses **`TipOnly`**: unconnected first-hits are dropped; a connected
    /// sibling in an older segment still wins.
    pub fn get_fk_by_txid_batch(
        &self,
        txids: &[[u8; 32]],
    ) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
        self.get_fk_by_txid_batch_mode(txids, TxidResolveMode::TipOnly)
    }

    /// Batch resolve with explicit mode (RPC may use [`TxidResolveMode::TipThenAny`]).
    ///
    /// Uses the same open-then-sealed machine as [`TxTable::get_fk_by_txid_batch`]:
    /// an unconnected hit does **not** skip older segments, and every
    /// body_txid match in a segment is considered so a connected sibling wins.
    pub fn get_fk_by_txid_batch_mode(
        &self,
        txids: &[[u8; 32]],
        mode: TxidResolveMode,
    ) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
        // Snapshot: leftover IO is 0.4–2s. Holding the fence read lock blocks
        // `height_fence_extend`. Confirm extends before `set_many`, so tip
        // cannot publish while this clone is in flight. Clone is Arc (COW on
        // the next extend if this snapshot is still live).
        let t_fence = std::time::Instant::now();
        let fence = self.fence().clone();
        crate::head_resolve_stats::add_probe(t_fence.elapsed().as_nanos() as u64);
        crate::head_resolve_denserels::resolve_fk_and_range_batch_with_tip(
            &self.txs,
            &fence,
            txids,
            matches!(mode, TxidResolveMode::TipOnly),
        )
    }

    /// Failure-time hop dump for the leftover miss txid (load leftover only).
    ///
    /// Lookup / BQ-ahead TipOnly misses must not call this — those are routine.
    pub fn diagnose_leftover_probe(&self, txid: &[u8; 32]) {
        crate::head_resolve_denserels::diagnose_and_note_leftover_probe(&self.txs, txid);
    }

    /// Sparse outs by known `txout` ranges (prep; skips loc).
    ///
    /// See [`TxTable::get_outs_by_range_batch`].
    pub fn get_outs_by_range_batch(
        &self,
        items: &[crate::tx_table::OutsByRangeJob],
    ) -> Result<crate::tx_table::OutsByRangeOut, StoreError> {
        self.txs.get_outs_by_range_batch(items)
    }

    /// Bulk Class A `create.loc` pairs (txout range + spent range + `n_out`).
    ///
    /// Dual-need callers must use this once. [`Self::tx_body_range_batch`] and
    /// [`Self::tx_spent_range_batch`] are thin wrappers for single-stem paths.
    pub fn tx_create_loc_range_batch(
        &self,
        fks: &[Fk],
    ) -> Result<Vec<Option<crate::create_loc::CreateLocPair>>, StoreError> {
        self.txs.create_loc_range_batch(fks)
    }

    /// Durable `create.loc` row count (not `tx.body` HWM).
    pub fn tx_create_loc_count(&self) -> u64 {
        self.txs.create_loc_count()
    }

    pub fn tx_body_range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        Ok(self
            .tx_create_loc_range_batch(fks)?
            .into_iter()
            .map(|p| p.map(|x| x.txout))
            .collect())
    }

    pub fn tx_spent_range_batch(&self, fks: &[Fk]) -> Result<Vec<Option<(u64, u64)>>, StoreError> {
        Ok(self
            .tx_create_loc_range_batch(fks)?
            .into_iter()
            .map(|p| p.map(|x| x.spent))
            .collect())
    }

    /// True when every spent slot in `ranges` is unspent or its spender's
    /// height is below `edge`. A multi-spender overflow is not below: the
    /// caller must keep scanning.
    pub fn spent_ranges_below(&self, ranges: &[(u64, u64)], edge: i64) -> Result<bool, StoreError> {
        let opts: Vec<Option<(u64, u64)>> = ranges.iter().copied().map(Some).collect();
        Ok(self.spent_ranges_reach(&opts, edge)?.iter().all(|hot| !hot))
    }

    /// One flag per range. True when a slot is a multi-spender or a single
    /// spender's height is at or above `edge`. `None` and an empty span are cold.
    pub fn spent_ranges_reach(
        &self,
        ranges: &[Option<(u64, u64)>],
        edge: i64,
    ) -> Result<Vec<bool>, StoreError> {
        const SLOT: u64 = 8;
        let mut reach = vec![false; ranges.len()];
        let mut offs = Vec::new();
        let mut owner = Vec::new();
        for (ri, range) in ranges.iter().enumerate() {
            let Some((start, len)) = *range else {
                continue;
            };
            if len == 0 {
                continue;
            }
            if !len.is_multiple_of(SLOT) {
                return Err(StoreError::Corrupt("invariant: spent range length"));
            }
            let n = len / SLOT;
            for i in 0..n {
                offs.push(start.saturating_add(i.saturating_mul(SLOT)));
                owner.push(ri);
            }
        }
        let mut spenders: Vec<(usize, Fk)> = Vec::new();
        for (chunk, own) in offs.chunks(4096).zip(owner.chunks(4096)) {
            let metas = self.get_spender_meta_at_abs_batch(chunk)?;
            if metas.len() != chunk.len() {
                return Err(StoreError::Corrupt("invariant: spent meta batch length"));
            }
            for (meta, ri) in metas.into_iter().zip(own.iter().copied()) {
                let Some((fk, flags, _)) = meta else {
                    continue;
                };
                if flags & crate::compact::output_flags::MULTI_SPENDER != 0 {
                    reach[ri] = true;
                    continue;
                }
                if !fk.is_null() {
                    spenders.push((ri, fk));
                }
            }
        }
        if spenders.is_empty() {
            return Ok(reach);
        }
        let fks: Vec<Fk> = spenders.iter().map(|(_, fk)| *fk).collect();
        let heights = self.tx_height_get_batch(&fks)?;
        if heights.len() != spenders.len() {
            return Err(StoreError::Corrupt(
                "invariant: spender height batch length",
            ));
        }
        for ((ri, _), h) in spenders.iter().zip(heights) {
            if i64::from(h.unwrap_or(0)) >= edge {
                reach[*ri] = true;
            }
        }
        Ok(reach)
    }

    /// Completion-driven loc→body io_uring pipeline (confirm load / prep).
    ///
    /// Jobs with pre-known `range` skip loc fill when `n_out` is already set.
    /// See [`crate::run_idx_body_pipeline`].
    pub fn idx_body_pipeline(
        &self,
        jobs: &mut [crate::IdxBodyJob],
        mode: crate::IdxBodyMode,
    ) -> Result<(), StoreError> {
        self.txs.fill_txout_job_ranges(jobs)?;
        crate::run_idx_body_pipeline(&self.txs.body, jobs, mode).map(|_| ())
    }

    pub fn idx_seqsigwit_pipeline(
        &self,
        jobs: &mut [crate::IdxBodyJob],
        mode: crate::IdxBodyMode,
    ) -> Result<(), StoreError> {
        self.txs.fill_seqsigwit_job_ranges(jobs)?;
        crate::run_idx_body_pipeline(&self.txs.seqsigwit, jobs, mode).map(|_| ())
    }

    /// Bulk 8-byte spender meta at absolute `spent.body` offsets.
    ///
    /// Backend from global `RBITCOIN_IO` (see [`crate::spend_meta_backend`]).
    pub fn get_spender_meta_at_abs_batch(
        &self,
        abs_offs: &[u64],
    ) -> Result<Vec<Option<crate::tx_table::SpenderSlot>>, StoreError> {
        self.txs.get_spender_meta_at_abs_batch(abs_offs)
    }

    /// Explicit-backend bulk meta (tests / timed structural path).
    pub fn get_spender_meta_at_abs_batch_backend(
        &self,
        abs_offs: &[u64],
        backend: crate::io_backend::ReadIoBackend,
    ) -> Result<Vec<Option<crate::tx_table::SpenderSlot>>, StoreError> {
        self.txs
            .get_spender_meta_at_abs_batch_backend(abs_offs, backend)
    }

    /// Pure-write annotate with structural-known meta (no body pread).
    ///
    /// `abs_edges`: `(abs_off, create_tx_fk, vout, spending_tx_fk, spending_vin)`.
    /// `known`: parallel `(field, flags, vin)` from structural spentness.
    pub fn put_spend_batch_by_abs_meta_known(
        &self,
        abs_edges: &[(u64, Fk, u32, Fk, u32)],
        known: &[(Fk, u8, u32)],
        backend: crate::io_backend::WriteIoBackend,
    ) -> Result<Vec<(Fk, u32, Fk, u32)>, StoreError> {
        self.txs
            .put_spend_batch_by_abs_meta_known(&self.spenders, abs_edges, known, backend)
    }

    /// Spentness by create fk (no `tx.head`). Prefer known body range when available.
    ///
    /// Sole spender: Class C strong on the spender fk. Multi-list is rare in IBD
    /// (would touch `spent.ovf`).
    pub fn has_confirmed_strong_spender_create(
        &self,
        create_tx_fk: Fk,
        out_index: u32,
        body_range: Option<(u64, u64)>,
    ) -> Result<bool, StoreError> {
        let tip = self.confirmed.tip_height().map(|t| t.0);
        self.has_confirmed_strong_spender_create_at(create_tx_fk, out_index, body_range, tip)
    }

    /// Like [`Self::has_confirmed_strong_spender_create`] with a caller-cached tip.
    pub fn has_confirmed_strong_spender_create_at(
        &self,
        create_tx_fk: Fk,
        out_index: u32,
        body_range: Option<(u64, u64)>,
        tip: Option<u32>,
    ) -> Result<bool, StoreError> {
        let (multi, field, _vin) = match body_range {
            Some((off, len)) => self.txs.get_output_spender_meta_at(off, len, out_index)?,
            None => self.txs.get_output_spender_meta(create_tx_fk, out_index)?,
        };
        if field.is_null() {
            return Ok(false);
        }
        if !multi {
            return self.is_confirmed_strong_at(field, tip);
        }
        let mut found = false;
        point_table::for_each_spender_create(
            &self.txs,
            &self.spenders,
            create_tx_fk,
            out_index,
            |spending_tx_fk, _vin| {
                if self.is_confirmed_strong_at(spending_tx_fk, tip)? {
                    found = true;
                    return Ok(false);
                }
                Ok(true)
            },
        )?;
        Ok(found)
    }

    /// Unspent subset of `vouts` on one create (wave/cache hot path).
    ///
    /// With `body_range`, **one** packed body walk for all vouts (not one walk
    /// per vout). Multi-spender lists fall back to the rare cold path.
    pub fn unspent_create_vouts(
        &self,
        create_tx_fk: Fk,
        vouts: &[u32],
        body_range: Option<(u64, u64)>,
    ) -> Result<Vec<u32>, StoreError> {
        if vouts.is_empty() {
            return Ok(Vec::new());
        }
        let tip = self.confirmed.tip_height().map(|t| t.0);
        let metas: Vec<(u32, bool, Fk, u32)> = match body_range {
            // `body_range` here is the create's **spent.body** span (schema 15).
            Some((off, len)) => self.txs.get_output_spender_metas_at(off, len, vouts)?,
            None => {
                if let Ok((off, len)) = self.txs.spent_range(create_tx_fk) {
                    self.txs.get_output_spender_metas_at(off, len, vouts)?
                } else {
                    let mut out = Vec::with_capacity(vouts.len());
                    for &v in vouts {
                        let (multi, field, vin) =
                            self.txs.get_output_spender_meta(create_tx_fk, v)?;
                        out.push((v, multi, field, vin));
                    }
                    out
                }
            }
        };
        let mut unspent = Vec::with_capacity(metas.len());
        for (v, multi, field, _vin) in metas {
            if field.is_null() {
                unspent.push(v);
                continue;
            }
            if !multi {
                if !self.is_confirmed_strong_at(field, tip)? {
                    unspent.push(v);
                }
                continue;
            }
            if !self.has_confirmed_strong_spender_create(create_tx_fk, v, body_range)? {
                unspent.push(v);
            }
        }
        // Vouts missing from body (corrupt / OOB) are treated as not live.
        Ok(unspent)
    }

    /// Batch [`Self::unspent_create_vouts`]: one spent-range walk, then one
    /// spent-body read per create that has a range.
    pub fn unspent_create_vouts_batch(
        &self,
        items: &[(Fk, Vec<u32>)],
    ) -> Result<Vec<Vec<u32>>, StoreError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let fks: Vec<Fk> = items.iter().map(|(fk, _)| *fk).collect();
        let ranges = self.txs.spent_range_batch(&fks)?;
        if ranges.len() != items.len() {
            return Err(StoreError::Corrupt("invariant: spent_range_batch length"));
        }
        let mut out = Vec::with_capacity(items.len());
        for ((fk, vouts), range) in items.iter().zip(ranges) {
            out.push(self.unspent_create_vouts(*fk, vouts, range)?);
        }
        Ok(out)
    }

    /// Multi-list node count only (sole spends do not allocate body rows).
    pub fn spender_list_count(&self) -> u64 {
        self.spenders.count()
    }

    /// True if `tx_fk` is strong **and** sits on the confirmed tip chain.
    ///
    /// Class C writes set `strong_tx` before advancing `confirmed[]` (tip is the
    /// commit point). The height fence is rebuilt/extended only from confirmed
    /// header_txs, so leftover strong bits above tip have no fence height and
    /// do not count as best-chain spent.
    pub fn is_confirmed_strong(&self, tx_fk: Fk) -> Result<bool, StoreError> {
        let tip = self.confirmed.tip_height().map(|t| t.0);
        self.is_confirmed_strong_at(tx_fk, tip)
    }

    /// Like [`Self::is_confirmed_strong`] with a caller-cached tip (connect hot path).
    #[inline]
    pub fn is_confirmed_strong_at(&self, tx_fk: Fk, tip: Option<u32>) -> Result<bool, StoreError> {
        if !self.strong_tx.is_strong(tx_fk)? {
            return Ok(false);
        }
        let Some(h) = self.fence().height_of(tx_fk) else {
            // Strong without a confirmed run: partial Class C write or orphan.
            return Ok(false);
        };
        match tip {
            Some(t) if h <= t => Ok(true),
            _ => Ok(false),
        }
    }

    /// True if any annotated spender for this outpoint is confirmed-strong.
    /// The create is the connected row for `out_txid`: a strong spender
    /// always hangs off it, so a newer never-connected row for the same txid
    /// cannot hide a confirmed spend.
    pub fn has_confirmed_strong_spender(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
    ) -> Result<bool, StoreError> {
        let tip = self.confirmed.tip_height().map(|t| t.0);
        self.has_confirmed_strong_spender_at(out_txid, out_index, tip)
    }

    /// Like [`Self::has_confirmed_strong_spender`] with a caller-cached tip.
    pub fn has_confirmed_strong_spender_at(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
        tip: Option<u32>,
    ) -> Result<bool, StoreError> {
        let Some(create_fk) = self.get_fk_by_txid_tip(out_txid)? else {
            return Ok(false);
        };
        let mut found = false;
        point_table::for_each_spender_create(
            &self.txs,
            &self.spenders,
            create_fk,
            out_index,
            |spending_tx_fk, _vin| {
                if self.is_confirmed_strong_at(spending_tx_fk, tip)? {
                    found = true;
                    return Ok(false);
                }
                Ok(true)
            },
        )?;
        Ok(found)
    }

    /// Spenders whose spending transaction is confirmed-strong on the best tip.
    pub fn spenders(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
    ) -> Result<Vec<PointRecord>, StoreError> {
        let tip = self.confirmed.tip_height().map(|t| t.0);
        self.spenders_at(out_txid, out_index, tip)
    }

    /// Spenders confirmed-strong as of `tip` (`None` = none).
    pub fn spenders_at(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
        tip: Option<u32>,
    ) -> Result<Vec<PointRecord>, StoreError> {
        let mut out = Vec::new();
        for rec in self.spenders_raw(out_txid, out_index)? {
            if self.is_confirmed_strong_at(rec.spending_tx_fk, tip)? {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// All annotated spenders on the connected create (including non-strong /
    /// reorg history). A txid with no connected row has none.
    pub fn spenders_raw(
        &self,
        out_txid: &[u8; 32],
        out_index: u32,
    ) -> Result<Vec<PointRecord>, StoreError> {
        let Some(create_fk) = self.get_fk_by_txid_tip(out_txid)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        point_table::for_each_spender_create(
            &self.txs,
            &self.spenders,
            create_fk,
            out_index,
            |spending_tx_fk, spending_vin| {
                out.push(PointRecord {
                    out_txid: *out_txid,
                    out_index,
                    spending_tx_fk,
                    spending_vin,
                    next: Fk::NULL,
                });
                Ok(true)
            },
        )?;
        Ok(out)
    }

    /// Spender tx fks for a create outpoint (no `tx.head`; includes non-strong).
    pub fn spenders_create(&self, create_tx_fk: Fk, out_index: u32) -> Result<Vec<Fk>, StoreError> {
        let mut out = Vec::new();
        point_table::for_each_spender_create(
            &self.txs,
            &self.spenders,
            create_tx_fk,
            out_index,
            |spending_tx_fk, _vin| {
                out.push(spending_tx_fk);
                Ok(true)
            },
        )?;
        Ok(out)
    }

    /// Unstrong every fk that is strong but not on the confirmed fence.
    ///
    /// Covers leftover strong above tip (kill mid-confirm) and orphan second
    /// Class A+C copies (not in `confirmed[h]` header_txs). Point rows stay;
    /// they remain invisible to [`Self::spenders`] until re-confirm.
    pub fn repair_class_c_above_tip(&self) -> Result<u64, StoreError> {
        self.repair_strong_not_on_fence()
    }

    fn repair_strong_not_on_fence(&self) -> Result<u64, StoreError> {
        let t0 = std::time::Instant::now();
        let after = self.fence().max_connected_fk();
        let holes = self.fence().unconnected_ranges(after);
        let n_bits = self.strong_tx.allocated_bits();
        let suffix_lo = after.saturating_add(1);
        let suffix_hi = self.strong_suffix_end_fk(suffix_lo, n_bits)?;
        let mut ranges = holes;
        if suffix_hi > suffix_lo {
            ranges.push((suffix_lo, suffix_hi));
        }
        let n_ranges = ranges.len();
        let mut cleared = 0u64;
        for (lo, hi) in ranges {
            let ones = self.strong_tx.count_strong_in_fk_range(lo, hi)?;
            if ones == 0 {
                continue;
            }
            self.clear_class_c_run(lo, hi)?;
            cleared = cleared.saturating_add(ones);
        }
        let ms = t0.elapsed().as_millis();
        eprintln!("rbitcoin: class_c repair cleared={cleared} ranges={n_ranges} ms={ms}");
        Ok(cleared)
    }

    /// Exclusive end fk of leftover 1s after `start_fk`, stopping at a 64 KiB
    /// all-zero bit page so slab padding is not rewritten.
    fn strong_suffix_end_fk(&self, start_fk: u64, n_bits: u64) -> Result<u64, StoreError> {
        if start_fk == 0 || start_fk.saturating_sub(1) >= n_bits {
            return Ok(start_fk);
        }
        const ZERO_PAGE: usize = 65536;
        let mut bit = start_fk - 1;
        let mut last_one_end = start_fk;
        let mut buf = vec![0u8; ZERO_PAGE];
        while bit < n_bits {
            let byte_off = bit / 8;
            let remain = n_bits.div_ceil(8).saturating_sub(byte_off);
            let take = (remain as usize).min(ZERO_PAGE);
            self.strong_tx.read_bit_bytes(byte_off, &mut buf[..take])?;
            if buf[..take].iter().all(|&b| b == 0) {
                break;
            }
            last_one_end = (byte_off + take as u64)
                .saturating_mul(8)
                .saturating_add(1)
                .min(n_bits.saturating_add(1));
            bit = byte_off.saturating_add(take as u64).saturating_mul(8);
        }
        Ok(last_one_end.max(start_fk))
    }

    fn clear_class_c_run(&self, start: u64, end: u64) -> Result<u64, StoreError> {
        if end <= start {
            return Ok(0);
        }
        let count = end - start;
        if count <= u64::from(u32::MAX) {
            self.strong_tx.set_unstrong_range(Fk(start), count as u32)?;
        } else {
            for id in start..end {
                self.strong_tx.set_unstrong(Fk(id))?;
            }
        }
        Ok(count)
    }

    /// In-RAM Class C L2 images (strong_tx bits + confirmed + header_txs).
    pub fn class_c_l2_resident_bytes(&self) -> u64 {
        self.strong_tx
            .l2_resident_bytes()
            .saturating_add(self.confirmed.l2_resident_bytes())
            .saturating_add(self.header_txs.l2_resident_bytes())
    }

    /// Flush Class C **except** `confirmed[]` (pre-tip half of the barrier).
    ///
    /// Order: `strong_tx` → `header_txs`. Used so a mid-barrier kill can leave
    /// strong durable **above** tip (repairable) without advancing tip. Prefer
    /// [`Self::flush_class_c_tip`] for the full barrier.
    fn flush_class_c_pre_tip(&self) -> Result<(), StoreError> {
        // Tip-as-commit: never flush confirmed here.
        // Headers first so conf tip cannot reference a non-durable header_fk.
        self.headers.flush()?;
        self.strong_tx.flush()?;
        self.header_txs.flush()?;
        Ok(())
    }

    /// Full Class C **connect** barrier: pre-tip tables **then** `confirmed[]` last.
    ///
    /// Complete-or-fail per table. Call **before** body-queue dequeue so a kill
    /// mid-commit can re-drive from BQ when the barrier had not finished.
    ///
    /// **Tip last on connect:** if `confirmed` were durable before `strong_tx`,
    /// a mid-barrier kill advances tip with missing strong bits; re-confirm
    /// skips those heights and `repair_class_c_above_tip` only clears leftover
    /// strong not on the fence — permanent unstrong tip txs.
    ///
    /// After confirmed is durable, publish soft [`crate::TIP_SEAL_NAME`] so open
    /// can clamp an incomplete extension that never finished this barrier.
    /// Height whose spend annotations were `sync_data`'d. Missing means none.
    pub fn spend_annotated_through(&self) -> Result<Option<u32>, StoreError> {
        Ok(crate::spend_durable::SpendDurable::load(self.path())?.map(|m| m.annotated_through()))
    }

    /// `sync_data` the stems replay and the tip window read, then publish the marker at `tip`.
    ///
    /// Open replay calls this while confirm is stopped. The periodic checkpoint
    /// uses [`Self::checkpoint_spend_through`] and does not publish a later tip.
    pub fn sync_spend_durable(&self, tip: u32) -> Result<u64, StoreError> {
        let t = std::time::Instant::now();
        let tip = match self.confirmed.tip_height() {
            Some(h) => tip.min(h.0),
            None => 0,
        };
        let gen = self
            .spend_reorg_gen
            .load(std::sync::atomic::Ordering::Acquire);
        self.txs.sync_replay_bodies()?;
        self.spenders.flush()?;
        self.store_spend_marker(tip, tip, gen)?;
        Ok(t.elapsed().as_nanos() as u64)
    }

    /// Publish the marker at `min(requested, confirmed tip)` under [`Self::spend_marker`].
    ///
    /// A disconnect bumps [`Self::spend_reorg_gen`] before it takes the same
    /// lock. A publish sampled at `gen` writes nothing when that word moved.
    fn store_spend_marker(&self, annotated: u32, durable: u32, gen: u64) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        let _g = self.spend_marker.lock().unwrap_or_else(|e| e.into_inner());
        if self.spend_reorg_gen.load(Ordering::Acquire) != gen {
            return Ok(());
        }
        let tip = self.confirmed.tip_height().map(|h| h.0).unwrap_or(0);
        crate::spend_durable::SpendDurable::new(annotated.min(tip), durable.min(tip))
            .store(self.path())
    }

    /// Record the confirmed height whose annotations have been written.
    ///
    /// This is not a durability claim. The checkpoint thread reads it before
    /// `sync_data` and publishes that height only.
    ///
    /// Stores `min(tip, confirmed tip)`. The caller may have read `tip` before
    /// a disconnect lowered the chain. A clamp that does not change the
    /// snapshot word does not retry a CAS, so after a successful store this
    /// reads the tip again and lowers the word when the chain moved.
    pub fn note_spend_snapshot(&self, tip: u32) {
        use std::sync::atomic::Ordering;
        let want_at = |live: Option<u32>| match live {
            Some(h) => u64::from(tip.min(h)) + 1,
            None => 0,
        };
        loop {
            let want = want_at(self.confirmed.tip_height().map(|h| h.0));
            let prev = self.spend_snapshot.load(Ordering::Acquire);
            if prev != want
                && self
                    .spend_snapshot
                    .compare_exchange(prev, want, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                continue;
            }
            if want_at(self.confirmed.tip_height().map(|h| h.0)) == want {
                return;
            }
        }
    }

    /// Odd for the guard's life. Callers who sample an even stamp and read
    /// coins can trust that read only when the stamp is unchanged afterward.
    pub fn hold_utxo_view(&self) -> UtxoViewGuard<'_> {
        use std::sync::atomic::Ordering;
        let prev = self.utxo_view.fetch_add(1, Ordering::AcqRel);
        debug_assert_eq!(
            prev & 1,
            0,
            "utxo view guards must not overlap; the counter would look stable"
        );
        UtxoViewGuard {
            view: &self.utxo_view,
        }
    }

    /// `Some` even generation, or `None` while [`Self::hold_utxo_view`] is held.
    pub fn utxo_view_stamp(&self) -> Option<u64> {
        use std::sync::atomic::Ordering;
        let v = self.utxo_view.load(Ordering::Acquire);
        (v & 1 == 0).then_some(v)
    }

    pub fn spend_snapshot_height(&self) -> Option<u32> {
        use std::sync::atomic::Ordering;
        match self.spend_snapshot.load(Ordering::Acquire) {
            0 => None,
            v => Some(v.saturating_sub(1) as u32),
        }
    }

    /// A confirm write from `height` may connect blocks before their spends
    /// are annotated. Keeps the lowest pending height.
    ///
    /// The returned token is the word this note stored. A later note bumps
    /// the generation in the high 32 bits, so a clear of this token does not
    /// drop the later one. The low 32 bits are `height + 1`.
    pub fn note_spend_annotate_pending(&self, height: u32) -> u64 {
        use std::sync::atomic::Ordering;
        let v = u64::from(height).saturating_add(1);
        self.spend_annotate_from
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                let cur_h = cur & 0xffff_ffff;
                let new_h = if cur_h == 0 { v } else { cur_h.min(v) };
                let mut gen = (cur >> 32).wrapping_add(1);
                if gen == 0 {
                    gen = 1;
                }
                let next = (gen << 32) | new_h;
                (next != cur).then_some(next)
            })
            .map_or(0, |prev| {
                let cur_h = prev & 0xffff_ffff;
                let new_h = if cur_h == 0 { v } else { cur_h.min(v) };
                let mut gen = (prev >> 32).wrapping_add(1);
                if gen == 0 {
                    gen = 1;
                }
                let next = (gen << 32) | new_h;
                if next == prev {
                    prev
                } else {
                    next
                }
            })
    }

    /// Lowest height whose spend annotate did not finish in this process.
    pub fn spend_annotate_pending(&self) -> Option<u32> {
        let v = self.spend_annotate_token() & 0xffff_ffff;
        match v {
            0 => None,
            h => Some(h.saturating_sub(1) as u32),
        }
    }

    /// Full in-process pending word, including the generation.
    pub fn spend_annotate_token(&self) -> u64 {
        use std::sync::atomic::Ordering;
        self.spend_annotate_from.load(Ordering::Acquire)
    }

    /// Drop the pending word only when it is still `token`.
    ///
    /// A confirm write that finished its own annotate must not clear a
    /// replacement that noted a later failure. Call only after this write's
    /// annotate or replay returned `Ok`.
    pub fn clear_spend_annotate_pending(&self, token: u64) {
        use std::sync::atomic::Ordering;
        if token == 0 {
            return;
        }
        let _ = self
            .spend_annotate_from
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                (cur == token).then_some(0)
            });
    }

    /// `sync_data` the replay stems, then publish `A = D = height` when the
    /// confirmed tip is still at least `height` and no disconnect ran during
    /// the sync. A lower tip, or a disconnect, leaves the marker.
    ///
    /// A pending spend annotate caps the published height below its first
    /// height, so open still replays it. With pending from genesis, nothing is
    /// published.
    pub fn checkpoint_spend_through(&self, height: u32) -> Result<(), StoreError> {
        self.checkpoint_spend_through_between(height, |_| {})
    }

    /// Sample the disconnect generation, then the snapshot height, then sync.
    ///
    /// A disconnect between those two reads must not publish the height that
    /// was current before it, even when the replacement is annotated during
    /// the sync.
    pub fn checkpoint_observed_spend(&self) -> Result<(), StoreError> {
        self.checkpoint_observed_spend_gap(|_| {}, |_| {})
    }

    /// [`Self::checkpoint_observed_spend`] with hooks around the two reads
    /// and the sync. Test-only callers live in [`crate::testutil`].
    pub(crate) fn checkpoint_observed_spend_gap(
        &self,
        after_first_read: impl FnOnce(&Self),
        during_sync: impl FnOnce(&Self),
    ) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        let gen = self.spend_reorg_gen.load(Ordering::Acquire);
        after_first_read(self);
        let Some(height) = self.spend_snapshot_height() else {
            return Ok(());
        };
        self.sync_spend_checkpoint(height, gen, during_sync)
    }

    /// [`Self::checkpoint_spend_through`] with `between` invoked after
    /// `sync_data` and before the marker publish.
    ///
    /// Appends above `height` do not bump the disconnect generation, so a
    /// block connected in `between` still allows the snapshot to publish.
    /// A disconnect in `between` does not.
    pub(crate) fn checkpoint_spend_through_between(
        &self,
        height: u32,
        between: impl FnOnce(&Self),
    ) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        let gen = self.spend_reorg_gen.load(Ordering::Acquire);
        self.sync_spend_checkpoint(height, gen, between)
    }

    fn sync_spend_checkpoint(
        &self,
        height: u32,
        gen: u64,
        during_sync: impl FnOnce(&Self),
    ) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        self.txs.sync_replay_data()?;
        self.spenders.sync_data_only()?;
        during_sync(self);
        if self.spend_reorg_gen.load(Ordering::Acquire) != gen {
            return Ok(());
        }
        let Some(tip) = self.confirmed.tip_height().map(|h| h.0) else {
            return Ok(());
        };
        if tip < height {
            return Ok(());
        }
        let height = match self.spend_annotate_pending() {
            Some(p) if p <= height => match p.checked_sub(1) {
                Some(h) => h,
                None => return Ok(()),
            },
            _ => height,
        };
        self.store_spend_marker(height, height, gen)
    }

    /// A disconnect below the marker lowers both heights to the new tip.
    ///
    /// The spend snapshot drops to the new tip too. A reconnect above it is not
    /// annotated until its write finishes, so the checkpoint must not publish
    /// the old snapshot over it. The generation bump is what the in-flight
    /// checkpoint observes, including when this datadir has no marker file yet.
    pub fn clamp_spend_durable(&self) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        self.spend_reorg_gen.fetch_add(1, Ordering::AcqRel);
        let _ = self
            .spend_snapshot
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                let low = self
                    .confirmed
                    .tip_height()
                    .map_or(0, |h| cur.min(u64::from(h.0) + 1));
                (low != cur).then_some(low)
            });
        let _g = self.spend_marker.lock().unwrap_or_else(|e| e.into_inner());
        let Some(marker) = crate::spend_durable::SpendDurable::load(self.path())? else {
            return Ok(());
        };
        let tip = self.confirmed.tip_height().map(|h| h.0).unwrap_or(0);
        let annotated = marker.annotated_through().min(tip);
        let durable = marker.durable_through().min(tip);
        if annotated == marker.annotated_through() && durable == marker.durable_through() {
            return Ok(());
        }
        crate::spend_durable::SpendDurable::new(annotated, durable).store(self.path())
    }

    pub fn flush_class_c_tip(&self) -> Result<(), StoreError> {
        self.flush_class_c_pre_tip()?;
        // Commit point on disk: tip advance only after strong/header_txs.
        self.confirmed.flush()?;
        self.publish_tip_seal()?;
        Ok(())
    }

    /// Flush only `confirmed[]` (tip length / tip header map).
    ///
    /// Used by **disconnect** after RAM truncate so tip shrink is durable **before**
    /// unstrong. Do not use for connect (would tip-first).
    pub fn flush_confirmed_only(&self) -> Result<(), StoreError> {
        self.confirmed.flush()?;
        self.publish_tip_seal()?;
        Ok(())
    }

    /// Class C **disconnect** post-clear barrier: strong after tip already
    /// shrunk and flushed via [`Self::flush_confirmed_only`].
    pub fn flush_class_c_after_disconnect_tip(&self) -> Result<(), StoreError> {
        self.strong_tx.flush()?;
        // header_txs unchanged on disconnect (archive association remains).
        Ok(())
    }

    /// Full durable flush: HWM + `sync_data` every table.
    ///
    /// **Host-hostile on multi‑GiB Class A** — use [`Self::flush_for_shutdown`] for
    /// process exit during IBD.
    pub fn flush(&self) -> Result<(), StoreError> {
        self.headers.flush()?;
        self.txs.flush()?;
        self.spenders.flush()?;
        self.scripthash.flush()?;
        self.flush_class_c_tip()?;
        Ok(())
    }

    /// Process-exit flush (IBD / SIGTERM). Target: seconds, not minutes.
    ///
    /// 1. Fsync tip / Class C tables only.
    /// 2. MS_ASYNC Class A bodies.
    pub fn flush_for_shutdown(&self) -> Result<(), StoreError> {
        let t0 = std::time::Instant::now();
        rbitcoin_log::info!("store: shutdown flush — fsync tip tables…");
        self.headers.flush()?;
        self.flush_class_c_tip()?;
        rbitcoin_log::info!(
            "store: shutdown flush — async Class A… elapsed={:?}",
            t0.elapsed()
        );
        self.txs.flush_async()?;
        self.spenders.flush_async()?;
        self.scripthash.flush_async()?;
        rbitcoin_log::info!("store: shutdown flush done elapsed={:?}", t0.elapsed());
        Ok(())
    }
}

fn write_meta(dir: &Path) -> Result<(), StoreError> {
    let path = dir.join("meta");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| StoreError::io(&path, e))?;
    f.write_all(&STORE_MAGIC)
        .map_err(|e| StoreError::io(&path, e))?;
    f.write_all(&SCHEMA_VERSION.to_le_bytes())
        .map_err(|e| StoreError::io(&path, e))?;
    f.flush().map_err(|e| StoreError::io(&path, e))?;
    Ok(())
}

/// Overwrite store `meta` with current [`SCHEMA_VERSION`].
fn rewrite_meta_current(dir: &Path) -> Result<(), StoreError> {
    let path = dir.join("meta");
    let tmp = path.with_extension("meta.tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| StoreError::io(&tmp, e))?;
        f.write_all(&STORE_MAGIC)
            .map_err(|e| StoreError::io(&tmp, e))?;
        f.write_all(&SCHEMA_VERSION.to_le_bytes())
            .map_err(|e| StoreError::io(&tmp, e))?;
        f.flush().map_err(|e| StoreError::io(&tmp, e))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| StoreError::io(&path, e))?;
    Ok(())
}

fn unlink_leftover_spent_off(dir: &Path) -> Result<(), StoreError> {
    let path = dir.join("spent.off");
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        std::fs::remove_dir_all(&path).map_err(|e| StoreError::io(&path, e))?;
    } else {
        std::fs::remove_file(&path).map_err(|e| StoreError::io(&path, e))?;
    }
    rbitcoin_log::warn!("store: dropping leftover spent.off (schema 22 uses create.loc)");
    Ok(())
}

fn open_layout_refuse_old(path: &Path, meta_ver: u16) -> Result<(), StoreError> {
    if (24..=25).contains(&meta_ver) {
        HeaderTable::rewrite_v24_body_to_88(path)?;
    }
    unlink_leftover_spent_off(path)?;
    Ok(())
}

fn drop_unread_store_leftovers(path: &Path) {
    let leftover_epoch = path.join("archive_epoch");
    if leftover_epoch.exists() {
        eprintln!(
            "store: dropping leftover archive_epoch (unread dual-path leftover; schema 17 does not keep it)"
        );
        let _ = std::fs::remove_file(&leftover_epoch);
    }
    let leftover_wire = path.join("wire");
    if leftover_wire.exists() {
        eprintln!("store: dropping leftover store/wire (unused; body queue is RAM-only)");
        let _ = std::fs::remove_dir_all(&leftover_wire);
        let _ = std::fs::remove_file(&leftover_wire);
    }
    if crate::sp_tweaks::SpTweaksTable::discard_legacy_files(path) {
        eprintln!(
            "store: dropping leftover sp_tweaks.idx/body files \
             (schema 17 uses segmented dirs; --sptweaks backfill regenerates)"
        );
    }
}

fn drop_leftover_tx_height(path: &Path) {
    let leftover_h = path.join("tx_height.body");
    if leftover_h.exists() {
        eprintln!(
            "store: dropping leftover tx_height.body (schema 16 uses a RAM fence from header_txs)"
        );
        let _ = std::fs::remove_file(&leftover_h);
    }
}

fn open_layout_rewrite_current(path: &Path, meta_ver: u16) -> Result<(), StoreError> {
    if meta_ver < SCHEMA_VERSION {
        rewrite_meta_current(path)?;
    }
    Ok(())
}

/// Validate store magic + schema. Returns on-disk version when openable.
fn check_meta(dir: &Path) -> Result<u16, StoreError> {
    let path = dir.join("meta");
    let bytes = std::fs::read(&path).map_err(|e| StoreError::io(&path, e))?;
    if bytes.len() < 6 {
        return Err(StoreError::Corrupt("meta too short"));
    }
    if bytes[0..4] != STORE_MAGIC {
        return Err(StoreError::BadMagic);
    }
    let ver = u16::from_le_bytes([bytes[4], bytes[5]]);
    if ver < 22 {
        return Err(StoreError::Corrupt(PRE22_WIPE));
    }
    if !schema_file_openable(ver) {
        return Err(StoreError::BadSchema(ver));
    }
    Ok(ver)
}

/// One wipe-and-IBD line for every store `meta` older than schema 22.
const PRE22_WIPE: &str = "schema before 22 refuses this datadir; wipe datadir and redo IBD";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::head_resolve_pick::LeftoverMissOn;
    use crate::tx_table::{InputRecord, OutputRecord, TxRecord};

    fn tmp() -> crate::testutil::TempDir {
        crate::testutil::TempDir::labeled("store").unwrap()
    }

    fn sh_put_create(s: &Store, rec: crate::scripthash::ScriptHashRecord) {
        let mut heads = std::collections::HashMap::new();
        s.scripthash
            .put_create_batch_append(std::slice::from_ref(&rec), &mut heads)
            .unwrap();
    }

    #[test]
    fn open_tiny_reopen_still_works() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            s.flush().unwrap();
        }
        let s = Store::open_tiny(&dir).unwrap();
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn occupied_schema23_header_body_opens_as_24() {
        use crate::file::{TableFile, FILE_HEADER_LEN};
        use crate::header_table::HeaderRecord;
        let dir = tmp();
        let hash = [0x44u8; 32];
        {
            let s = Store::create_tiny(&dir).unwrap();
            let hdr = HeaderRecord {
                prev_fk: Fk::NULL,
                version: 1,
                timestamp: 1,
                bits: 0x1d00ffff,
                nonce: 1,
                merkle_root: [1u8; 32],
                hash,
                size: 0,
                weight: 0,
            };
            s.put_header(&hdr).unwrap();
            s.flush().unwrap();
        }
        {
            let body_path = dir.join("header.body");
            let src = TableFile::open(&body_path, rbitcoin_primitives::TableKind::Header).unwrap();
            let rec = HeaderRecord::decode(&{
                let mut b = [0u8; crate::header_table::HEADER_RECORD_LEN];
                src.read_at(FILE_HEADER_LEN as u64, &mut b).unwrap();
                b
            })
            .unwrap();
            drop(src);
            let dst = TableFile::create(
                dir.join("header.body.v23tmp"),
                rbitcoin_primitives::TableKind::Header,
            )
            .unwrap();
            dst.write_at(FILE_HEADER_LEN as u64, &rec.encode()).unwrap();
            dst.set_logical_len(
                FILE_HEADER_LEN as u64 + crate::header_table::HEADER_RECORD_LEN as u64,
            )
            .unwrap();
            dst.flush().unwrap();
            drop(dst);
            std::fs::rename(dir.join("header.body.v23tmp"), dir.join("header.body")).unwrap();
            let mut meta = STORE_MAGIC.to_vec();
            meta.extend_from_slice(&23u16.to_le_bytes());
            std::fs::write(dir.join("meta"), meta).unwrap();
        }
        let s = Store::open_tiny(&dir).unwrap();
        let got = s.headers.get_by_hash(&hash).unwrap().unwrap().1;
        assert_eq!(got.hash, hash);
        assert_eq!(got.size, 0);
        assert_eq!(got.weight, 0);
        drop(s);
        let meta = std::fs::read(dir.join("meta")).unwrap();
        assert_eq!(u16::from_le_bytes([meta[4], meta[5]]), SCHEMA_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_refuses_shared_file_scripthash_body() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            s.flush().unwrap();
        }
        let body = dir.join("scripthash.body");
        std::fs::remove_dir_all(&body).unwrap();
        crate::file::TableFile::create(&body, rbitcoin_primitives::TableKind::ScriptHash).unwrap();
        match Store::open_tiny(&dir) {
            Err(StoreError::Corrupt(m)) => {
                assert_eq!(m, crate::scripthash::INDEX_REFUSE_SHARED_SH_BODY);
                assert!(m.contains("Class A kept"), "{m}");
            }
            Ok(_) => panic!("Shared scripthash.body must refuse Store::open"),
            Err(other) => panic!("expected INDEX_REFUSE_SHARED_SH_BODY, got {other}"),
        }
        assert!(dir.join("txout.body").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_refuses_pack8_paged_mode_10() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            sh_put_create(
                &s,
                crate::scripthash::ScriptHashRecord::from_fk([0x11u8; 32], Fk(1)),
            );
            s.flush().unwrap();
        }
        let ingest = dir.join("scripthash.ovf").join("ingest");
        let mut bytes = std::fs::read(&ingest).unwrap();
        let hdr = crate::file::FILE_HEADER_LEN;
        let slot = crate::scripthash_layout::SH_HEAD_SLOT_SIZE;
        let key_len = crate::scripthash_layout::SH_HEAD_KEY_LEN;
        let mode10 = ((2u64 << 62) | 4096u64).to_le_bytes();
        let mut i = hdr;
        while i + slot <= bytes.len() {
            let val = &bytes[i + key_len..i + slot];
            if val.iter().any(|&b| b != 0) {
                bytes[i + key_len..i + slot].copy_from_slice(&mode10);
            }
            i += slot;
        }
        std::fs::write(&ingest, &bytes).unwrap();
        match Store::open_tiny(&dir) {
            Err(StoreError::Corrupt(m)) => {
                assert_eq!(m, crate::scripthash_layout::INDEX_REFUSE_PAGED_SH);
                assert!(m.contains("Class A kept"), "{m}");
            }
            Ok(_) => panic!("Paged pack8 must refuse Store::open"),
            Err(other) => panic!("expected INDEX_REFUSE_PAGED_SH, got {other}"),
        }
        assert!(dir.join("txout.body").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_tiny_store_fixture_is_tiny_unique_and_drop_cleans() {
        let path;
        {
            let (dir, store) = crate::testutil::tiny_store();
            path = dir.path().to_path_buf();
            assert!(path.is_dir(), "fixture must create {path:?}");
            assert_eq!(store.headers.head_target_slots(), 64);
            assert_eq!(store.head_scale(), HeadScale::Tiny);
            let (dir2, store2) = crate::testutil::tiny_store();
            assert_ne!(dir.path(), dir2.path(), "each open must be a unique path");
            assert_eq!(store2.headers.head_target_slots(), 64);
        }
        assert!(
            !path.exists(),
            "drop must remove the Tiny store directory {path:?}"
        );
    }

    #[test]
    fn open_time_scale_is_explicit_not_env_or_cargo_test_sniff() {
        // Production constructors are Mainnet even under `cargo test`.
        let mainnet = StoreLayout::single("/tmp/rbitcoin-scale-unused");
        assert_eq!(mainnet.head_scale, HeadScale::Mainnet);
        assert_eq!(mainnet.header_slots(), 1 << 22);
        assert_eq!(mainnet.sh_shard_count(), 64);
        assert_eq!(mainnet.tx_head_bits(), crate::address_head::MAINNET_BITS);
        // Do not create those files in the default suite.

        let tiny_layout = StoreLayout::tiny("/tmp/rbitcoin-scale-unused-tiny");
        assert_eq!(tiny_layout.head_scale, HeadScale::Tiny);
        assert_eq!(tiny_layout.header_slots(), 64);
        assert_eq!(tiny_layout.sh_shard_count(), 1);
        assert_eq!(tiny_layout.tx_head_bits(), crate::address_head::TINY_BITS);

        let prev = std::env::var_os("RBITCOIN_HEAD_SCALE");
        std::env::set_var("RBITCOIN_HEAD_SCALE", "mainnet");
        let dir = tmp();
        let s = Store::create_layout(StoreLayout::tiny(&dir)).unwrap();
        assert_eq!(s.head_scale(), HeadScale::Tiny);
        assert_eq!(s.headers.head_target_slots(), 64);
        assert_eq!(s.scripthash.head_shard_count(), 1);
        assert_eq!(s.txs.head_bits(), crate::address_head::TINY_BITS);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);

        std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        let still_mainnet = StoreLayout::single("/tmp/rbitcoin-scale-unused-2");
        assert_eq!(
            still_mainnet.head_scale,
            HeadScale::Mainnet,
            "RBITCOIN_HEAD_SCALE must not win over explicit Mainnet open"
        );
        assert_eq!(still_mainnet.header_slots(), 1 << 22);
        match prev {
            Some(v) => std::env::set_var("RBITCOIN_HEAD_SCALE", v),
            None => std::env::remove_var("RBITCOIN_HEAD_SCALE"),
        }
    }

    fn coinbase_item(
        txid: [u8; 32],
        outs: Vec<OutputRecord>,
    ) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
        let n_out = outs.len() as u32;
        (
            TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: n_out,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            outs,
        )
    }

    /// Class C only: coinbase fk at height is header_txs first — no body.
    #[test]
    fn coinbase_fk_at_heights_matches_first_tx() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let hdr = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x1d00ffff,
            nonce: 1,
            merkle_root: [1u8; 32],
            hash: [2u8; 32],
            size: 0,
            weight: 0,
        };
        let hfk = s.put_header(&hdr).unwrap();
        // Two txs: coinbase + one non-cb (contiguous Class A ids).
        let (cb_tx, cb_in, cb_out) = coinbase_item(
            [10u8; 32],
            vec![OutputRecord {
                value: 50_0000_0000,
                script: vec![0x51],
                spender_field: Fk::NULL,
                multi_spender: false,
            }],
        );
        let cb_fks = s
            .put_tx_full_batch_indexed(&[(cb_tx, cb_in, cb_out)], false)
            .unwrap();
        let non_tx = TxRecord {
            txid: [11u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let non_in = vec![InputRecord {
            prev_txid: [10u8; 32],
            prev_index: 0,
            create_fk: cb_fks[0],
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        }];
        let non_out = vec![OutputRecord {
            value: 1,
            script: vec![0x51],
            spender_field: Fk::NULL,
            multi_spender: false,
        }];
        let non_fks = s
            .put_tx_full_batch_indexed(&[(non_tx, non_in, non_out)], false)
            .unwrap();
        let fks = [cb_fks[0], non_fks[0]];
        assert_eq!(fks.len(), 2);
        s.header_txs.put_range(hfk, fks[0], 2).unwrap();
        s.confirmed.set(Height(0), hfk).unwrap();
        s.rebuild_height_fence().unwrap();

        let map = s.coinbase_fk_at_heights(&[0, 1, 99]).unwrap();
        assert_eq!(map.get(&0).copied(), Some(fks[0]));
        assert!(!map.contains_key(&1)); // no confirmed height 1
        assert!(!map.contains_key(&99));
        // Non-coinbase is not first.
        assert_ne!(map.get(&0).copied().unwrap(), fks[1]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[allow(clippy::cognitive_complexity)] // one fixture, many error arms
    #[test]
    fn store_create_open_archive_spend_and_meta_errors() {
        let dir = tmp();
        // Not a directory when path is a file.
        {
            let file = dir.join("not-a-dir");
            std::fs::write(&file, b"x").unwrap();
            assert!(matches!(
                Store::create_tiny(&file),
                Err(StoreError::NotDirectory(_))
            ));
        }
        assert!(matches!(
            Store::open_tiny(dir.join("missing")),
            Err(StoreError::NotDirectory(_))
        ));
        {
            let file = dir.join("open-file-not-dir");
            std::fs::write(&file, b"x").unwrap();
            assert!(matches!(
                Store::open_tiny(&file),
                Err(StoreError::NotDirectory(_))
            ));
        }

        let s = Store::create_tiny(&dir).unwrap();
        assert_eq!(s.path(), dir.as_path());
        assert!(s.tip_height().is_none());
        assert_eq!(s.header_count(), 0);
        assert_eq!(s.archived_block_count().unwrap(), 0);
        assert_eq!(s.spender_list_count(), 0);

        let hdr = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x1d00ffff,
            nonce: 1,
            merkle_root: [3u8; 32],
            hash: [4u8; 32],
            size: 0,
            weight: 0,
        };
        let hfk = s.put_header(&hdr).unwrap();
        assert_eq!(s.get_header(hfk).unwrap().hash, [4u8; 32]);
        assert_eq!(s.get_header_by_hash(&[4u8; 32]).unwrap().unwrap().0, hfk);

        let create = coinbase_item(
            [10u8; 32],
            vec![
                OutputRecord::unspent(50, vec![0x51]),
                OutputRecord::unspent(25, vec![0x51]),
            ],
        );
        let fks = s.put_tx_full_batch_indexed(&[create], true).unwrap();
        let create_fk = fks[0];
        let _ = s.txs.sample_reset_body_decodes();
        let (meta, outs) = s.get_tx_meta_and_outputs(create_fk).unwrap();
        assert_eq!(meta.txid, [10u8; 32]);
        assert_eq!(outs.len(), 2);
        assert_eq!(
            s.txs.sample_reset_body_decodes(),
            1,
            "one packed body decode"
        );
        assert_eq!(s.get_tx(create_fk).unwrap().txid, [10u8; 32]);
        assert_eq!(
            s.txs.sample_reset_body_decodes(),
            1,
            "get_tx is the same packed decode with the outs dropped"
        );
        let full = s.get_tx_full(create_fk).unwrap();
        assert_eq!(full.2.len(), 2);
        let (m2, prevs) = s.get_tx_meta_and_prevouts(create_fk).unwrap();
        assert_eq!(m2.txid, [10u8; 32]);
        assert_eq!(prevs.len(), 1);
        assert_eq!(s.get_tx_full(create_fk).unwrap().0.txid, [10u8; 32]);
        assert_eq!(s.get_tx_meta_and_prevouts(create_fk).unwrap().1.len(), 1);
        assert_eq!(s.get_tx_meta_and_outputs(create_fk).unwrap().1.len(), 2);
        assert_eq!(
            s.txs.sample_reset_body_decodes(),
            1,
            "one outs read decodes; full and prevout reads are not outs decodes"
        );
        let mut span_hashes = Vec::new();
        s.for_each_create_script_hashes_in_fk_span(create_fk.0, create_fk.0, |_fk, sh| {
            span_hashes.push(sh);
            Ok(())
        })
        .unwrap();
        let expect: Vec<[u8; 32]> = outs
            .iter()
            .map(|o| crate::scripthash::script_hash(&o.script))
            .collect();
        assert_eq!(
            span_hashes, expect,
            "fk-span script hashes must match per-fk decode"
        );
        assert_eq!(s.get_fk_by_txid(&[10u8; 32]).unwrap(), Some(create_fk));
        assert_eq!(
            s.txs.sample_reset_body_decodes(),
            0,
            "fk resolve verifies txid.body only"
        );
        assert_eq!(s.get_tx_by_txid(&[10u8; 32]).unwrap().unwrap().0, create_fk);
        assert_eq!(
            s.txs.sample_reset_body_decodes(),
            1,
            "one decode for the returned record"
        );

        // Second tx spends create vout 0.
        let spend = (
            TxRecord {
                txid: [11u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord {
                prev_txid: [10u8; 32],
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            vec![OutputRecord::unspent(49, vec![0x51])],
        );
        let spend_fk = s.put_tx_full_batch_indexed(&[spend], true).unwrap()[0];
        s.put_spend_create(create_fk, 0, spend_fk, 0).unwrap();
        // Idempotent re-annotate same sole spender.
        s.put_spend_create(create_fk, 0, spend_fk, 0).unwrap();
        // Multi promote: second spender.
        let spend2 = (
            TxRecord {
                txid: [12u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord {
                prev_txid: [10u8; 32],
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            vec![OutputRecord::unspent(1, vec![0x51])],
        );
        let spend2_fk = s.put_tx_full_batch_indexed(&[spend2], true).unwrap()[0];
        s.put_spend_create(create_fk, 0, spend2_fk, 0).unwrap();
        assert!(s.spender_list_count() >= 2);

        // Third spender prepends multi list.
        let spend3 = (
            TxRecord {
                txid: [13u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord {
                prev_txid: [10u8; 32],
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            vec![OutputRecord::unspent(1, vec![0x51])],
        );
        let spend3_fk = s.put_tx_full_batch_indexed(&[spend3], true).unwrap()[0];
        let _ = s.txs.sample_reset_body_decodes();
        s.put_spend(&[10u8; 32], 0, spend3_fk, 0).unwrap();
        assert_eq!(
            s.txs.sample_reset_body_decodes(),
            0,
            "put_spend resolves the create by head probe only"
        );
        s.put_spend_batch(&[([10u8; 32], 1, spend_fk, 0)]).unwrap();
        s.put_spend_create(create_fk, 1, spend2_fk, 0).unwrap();
        let (soff, slen) = s.tx_spent_range(create_fk).unwrap();
        point_table::put_spend_on_create_at(
            &s.txs,
            &s.spenders,
            create_fk,
            1,
            spend3_fk,
            0,
            Some((soff, slen)),
        )
        .unwrap();
        // Re-annotate vout1 (already multi).
        point_table::put_spend_on_create_at(
            &s.txs,
            &s.spenders,
            create_fk,
            1,
            spend_fk,
            0,
            Some((soff, slen)),
        )
        .unwrap();

        // Class C: confirm spenders + heights. Body list must include spend_fk
        // (membership is part of is_confirmed_strong).
        s.confirmed.set(Height(0), hfk).unwrap();
        // Contiguous body covering create..spend (sequential put order).
        let body_first = create_fk.0.min(spend_fk.0);
        let body_last = create_fk.0.max(spend_fk.0);
        s.header_txs
            .put_range(hfk, Fk(body_first), (body_last - body_first + 1) as u32)
            .unwrap();
        s.strong_tx.set_strong(spend_fk, hfk).unwrap();
        s.rebuild_height_fence().unwrap();
        assert!(s.is_confirmed_strong(spend_fk).unwrap());
        assert!(!s.is_confirmed_strong(spend2_fk).unwrap());
        assert!(s
            .has_confirmed_strong_spender_create(create_fk, 0, Some((soff, slen)))
            .unwrap());
        let _ = s.txs.sample_reset_body_decodes();
        assert!(s.has_confirmed_strong_spender(&[10u8; 32], 0).unwrap());
        assert_eq!(
            s.txs.sample_reset_body_decodes(),
            0,
            "the spentness probe resolves the create by head probe only"
        );
        let unspent = s
            .unspent_create_vouts(create_fk, &[0, 1], Some((soff, slen)))
            .unwrap();
        // vout 0 has confirmed strong spender; vout1 multi without strong may still be unspent
        assert!(!unspent.contains(&0));
        let raw = s.spenders_raw(&[10u8; 32], 0).unwrap();
        assert!(raw.len() >= 2);
        let strong_sp = s.spenders(&[10u8; 32], 0).unwrap();
        assert_eq!(strong_sp.len(), 1);
        assert_eq!(strong_sp[0].spending_tx_fk, spend_fk);
        assert_eq!(
            s.txs.sample_reset_body_decodes(),
            0,
            "spender walks resolve the create by head probe only"
        );

        // Batch helpers
        let ranges = s.tx_body_range_batch(&[create_fk, spend_fk]).unwrap();
        assert_eq!(ranges.len(), 2);
        let full_b = s.get_tx_full(create_fk).unwrap();
        assert_eq!(full_b.0.txid, [10u8; 32]);
        let outs_b = s.get_tx_meta_and_outputs(create_fk).unwrap();
        assert_eq!(outs_b.1.len(), 2);
        let heights = s.tx_height_get_batch(&[spend_fk, create_fk]).unwrap();
        assert_eq!(heights[0], Some(0));

        assert_eq!(s.archived_block_count().unwrap(), 1);
        s.flush_header_archive().unwrap();
        s.flush_for_shutdown().unwrap();

        // repair: strong not on the fence
        s.strong_tx.set_strong(spend2_fk, hfk).unwrap();
        let cleared = s.repair_class_c_above_tip().unwrap();
        assert!(cleared >= 1);
        assert!(!s.is_confirmed_strong(spend2_fk).unwrap());

        s.flush().unwrap();
        drop(s);

        let s = Store::open_tiny(&dir).unwrap();
        assert_eq!(s.header_count(), 1);
        let s2 = Store::open_or_create_tiny(&dir).unwrap();
        assert_eq!(s2.header_count(), 1);
        drop(s2);

        // open_or_create on fresh path
        let dir2 = tmp();
        let s3 = Store::open_or_create_tiny(&dir2).unwrap();
        assert_eq!(s3.header_count(), 0);
        drop(s3);

        // meta errors
        assert!(matches!(
            check_meta(std::path::Path::new("/no/such")),
            Err(StoreError::Io { .. })
        ));
        {
            let bad = tmp();
            std::fs::create_dir_all(&bad).unwrap();
            std::fs::write(bad.join("meta"), b"xx").unwrap();
            assert!(matches!(check_meta(&bad), Err(StoreError::Corrupt(_))));
            std::fs::write(bad.join("meta"), b"XXXX\x00\x00").unwrap();
            assert!(matches!(check_meta(&bad), Err(StoreError::BadMagic)));
            let mut good_magic = STORE_MAGIC.to_vec();
            good_magic.extend_from_slice(&0u16.to_le_bytes());
            std::fs::write(bad.join("meta"), &good_magic).unwrap();
            match check_meta(&bad) {
                Err(StoreError::Corrupt(m)) => assert_eq!(m, PRE22_WIPE),
                other => panic!("meta 0: {other:?}"),
            }
            let mut v13 = STORE_MAGIC.to_vec();
            v13.extend_from_slice(&13u16.to_le_bytes());
            std::fs::write(bad.join("meta"), &v13).unwrap();
            match check_meta(&bad) {
                Err(StoreError::Corrupt(m)) => assert_eq!(m, PRE22_WIPE),
                other => panic!("meta 13: {other:?}"),
            }
            let _ = std::fs::remove_dir_all(&bad);
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn open_schema24_occupied_creates_zero_txstat() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            let item = coinbase_item([0x25u8; 32], vec![OutputRecord::unspent(50, vec![0x51])]);
            s.put_tx_full_batch_indexed(&[item], true).unwrap();
            s.flush().unwrap();
        }
        std::fs::remove_file(dir.join("txstat.body")).unwrap();
        write_store_meta_ver(&dir, 24);
        let s = Store::open_tiny(&dir).unwrap();
        assert_eq!(s.txs.txstat.count(), 1);
        assert_eq!(s.txs.txstat.get_cell(Fk(1)).unwrap(), [0u8; 8]);
        drop(s);
        assert_eq!(read_store_meta_ver(&dir), SCHEMA_VERSION);
        assert!(dir.join("txstat.body").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_meta_refuses_schema_past_this_binary() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        let mut bytes = STORE_MAGIC.to_vec();
        bytes.extend_from_slice(&(SCHEMA_VERSION + 1).to_le_bytes());
        std::fs::write(dir.join("meta"), bytes).unwrap();
        assert!(matches!(
            check_meta(&dir),
            Err(StoreError::BadSchema(v)) if v == SCHEMA_VERSION + 1
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn write_store_meta_ver(dir: &Path, ver: u16) {
        let mut bytes = STORE_MAGIC.to_vec();
        bytes.extend_from_slice(&ver.to_le_bytes());
        std::fs::write(dir.join("meta"), bytes).unwrap();
    }

    fn read_store_meta_ver(dir: &Path) -> u16 {
        let bytes = std::fs::read(dir.join("meta")).unwrap();
        u16::from_le_bytes([bytes[4], bytes[5]])
    }

    #[test]
    fn open_schema_before_22_refuses_wipe_and_ibd() {
        for ver in [21u16, 13u16] {
            let dir = tmp();
            {
                let s = Store::create_tiny(&dir).unwrap();
                s.flush().unwrap();
            }
            write_store_meta_ver(&dir, ver);
            match Store::open_tiny(&dir) {
                Err(StoreError::Corrupt(m)) => {
                    assert_eq!(m, PRE22_WIPE, "meta {ver}");
                    eprintln!("meta {ver} StoreError::Corrupt: {m}");
                }
                Ok(_) => panic!("meta {ver} opened"),
                Err(other) => panic!("meta {ver}: {other}"),
            }
            assert_eq!(
                read_store_meta_ver(&dir),
                ver,
                "meta {ver} must not rewrite"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    fn ovf_data_len(dir: &Path) -> u64 {
        let bytes = std::fs::read(dir.join("create.loc.ovf")).unwrap();
        let logical = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        logical - crate::file::FILE_HEADER_LEN as u64
    }

    fn write_legacy_create_ovf_v22(dir: &Path, rows: &[(u64, u16, u16)]) {
        use crate::file::FILE_HEADER_LEN;
        use rbitcoin_primitives::TableKind;
        let mut payload = Vec::new();
        for &(fk, st, n) in rows {
            payload.extend_from_slice(&fk.to_le_bytes());
            payload.extend_from_slice(&st.to_le_bytes());
            payload.extend_from_slice(&n.to_le_bytes());
        }
        let logical = FILE_HEADER_LEN as u64 + payload.len() as u64;
        let mut blob = vec![0u8; FILE_HEADER_LEN];
        blob[0..4].copy_from_slice(&STORE_MAGIC);
        blob[4..6].copy_from_slice(&22u16.to_le_bytes());
        blob[6..8].copy_from_slice(&TableKind::DeltaLoc.as_u16().to_le_bytes());
        blob[8..16].copy_from_slice(&logical.to_le_bytes());
        blob.extend_from_slice(&payload);
        std::fs::write(dir.join("create.loc.ovf"), blob).unwrap();
    }

    fn snapshot_create_ovf_as_v22_12b(dir: &Path) {
        use crate::file::FILE_HEADER_LEN;
        let bytes = std::fs::read(dir.join("create.loc.ovf")).unwrap();
        let logical = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let data = &bytes[FILE_HEADER_LEN..logical as usize];
        let mut rows = Vec::new();
        if data.len().is_multiple_of(16)
            && (!data.len().is_multiple_of(12) || { data.len() >= 16 && data[10..12] == [0, 0] })
        {
            for chunk in data.chunks_exact(16) {
                let fk = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                let st = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
                let n = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
                rows.push((fk, st as u16, n as u16));
            }
        } else {
            for chunk in data.chunks_exact(12) {
                let fk = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                let st = u16::from_le_bytes(chunk[8..10].try_into().unwrap());
                let n = u16::from_le_bytes(chunk[10..12].try_into().unwrap());
                rows.push((fk, st, n));
            }
        }
        write_legacy_create_ovf_v22(dir, &rows);
    }

    #[test]
    fn put_full_fat_txout_past_u16_strides() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let script = vec![0u8; 524_288];
        let item = coinbase_item([0x89u8; 32], vec![OutputRecord::unspent(0, script.clone())]);
        let fk = s.put_tx_full_batch_indexed(&[item], true).unwrap()[0];
        let (tx, _ins, outs) = s.get_tx_full(fk).unwrap();
        assert_eq!(tx.output_count, 1);
        assert_eq!(outs[0].script.len(), 524_288);
        drop(s);
        let s = Store::open_tiny(&dir).unwrap();
        let (_tx, _ins, outs) = s.get_tx_full(fk).unwrap();
        assert_eq!(outs[0].script.len(), 524_288);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_schema22_occupied_rewrites_create_ovf_12_to_16() {
        let dir = tmp();
        let n_out = 256u32;
        {
            let s = Store::create_tiny(&dir).unwrap();
            let outs = vec![OutputRecord::unspent(1, vec![0x51]); n_out as usize];
            let item = coinbase_item([0x22u8; 32], outs);
            s.put_tx_full_batch_indexed(&[item], true).unwrap();
            s.flush().unwrap();
        }
        snapshot_create_ovf_as_v22_12b(&dir);
        write_store_meta_ver(&dir, 22);
        assert_eq!(ovf_data_len(&dir), 12);
        let s = Store::open_tiny(&dir).unwrap();
        let (tx, _ins, outs) = s.get_tx_full(Fk(1)).unwrap();
        assert_eq!(tx.output_count, n_out);
        assert_eq!(outs.len(), n_out as usize);
        drop(s);
        assert_eq!(read_store_meta_ver(&dir), SCHEMA_VERSION);
        assert_eq!(ovf_data_len(&dir), 16);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_full_and_seqsigwit_prevouts_at() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let item = (
            TxRecord {
                txid: [8u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            vec![OutputRecord::unspent(1, vec![0x51])],
        );
        let fk = s.put_tx_full_batch_indexed(&[item], true).unwrap()[0];
        let (m, prevs) = s.get_tx_meta_and_prevouts(fk).unwrap();
        assert_eq!(m.input_count, 1);
        assert_eq!(prevs.len(), 1);
        assert!(s.tx_seqsigwit_range(fk).unwrap().1 > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_unlinks_scripthash_run_leftovers_and_keeps_seal() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            s.flush().unwrap();
        }
        let runs = dir.join("scripthash.runs");
        std::fs::create_dir_all(&runs).unwrap();
        std::fs::write(runs.join("000001.run"), b"not a catalog").unwrap();
        std::fs::write(runs.join("SEAL"), b"seal").unwrap();
        Store::open_tiny(&dir).unwrap();
        assert!(
            !runs.join("000001.run").exists(),
            "leftover run must be unlinked"
        );
        assert_eq!(std::fs::read(runs.join("SEAL")).unwrap(), b"seal");
        let dir2 = tmp();
        {
            let s = Store::create_tiny(&dir2).unwrap();
            s.flush().unwrap();
        }
        assert!(!dir2.join("scripthash.runs").exists());
        Store::open_tiny(&dir2).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn open_fails_when_scripthash_runs_cannot_be_read() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            s.flush().unwrap();
        }
        let runs = dir.join("scripthash.runs");
        std::fs::write(&runs, b"not a directory").unwrap();
        let msg = match Store::open_tiny(&dir) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("open must fail when leftovers cannot be read"),
        };
        assert!(
            msg.contains("scripthash.runs"),
            "open must fail when leftovers cannot be read: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn class_a_v17_roundtrip_templates() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let p2pkh = {
            let mut sc = vec![0x76, 0xa9, 0x14];
            sc.extend_from_slice(&[0x11u8; 20]);
            sc.extend_from_slice(&[0x88, 0xac]);
            sc
        };
        let p2tr = {
            let mut sc = vec![0x51, 0x20];
            sc.extend_from_slice(&[0x55u8; 32]);
            sc
        };
        let p2wsh = {
            let mut sc = vec![0x00, 0x20];
            sc.extend_from_slice(&[0x44u8; 32]);
            sc
        };
        let opreturn = {
            let data = [0xdeu8, 0xad, 0xbe, 0xef];
            let mut sc = vec![0x6a, data.len() as u8];
            sc.extend_from_slice(&data);
            sc
        };
        let p2a = vec![0x51, 0x02, 0x4e, 0x73];
        let high_ver = i32::from_le_bytes([0x00, 0x00, 0x00, 0x80]);

        let v1 = (
            TxRecord {
                txid: [1u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            vec![OutputRecord::unspent(1, p2pkh.clone())],
        );
        let v2 = (
            TxRecord {
                txid: [2u8; 32],
                version: 2,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 2,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            vec![
                OutputRecord::unspent(2, p2tr.clone()),
                OutputRecord::unspent(3, p2wsh.clone()),
            ],
        );
        let v3 = (
            TxRecord {
                txid: [3u8; 32],
                version: 3,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 2,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            vec![
                OutputRecord::unspent(0, opreturn.clone()),
                OutputRecord::unspent(4, p2a.clone()),
            ],
        );
        let hi = (
            TxRecord {
                txid: [4u8; 32],
                version: high_ver,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            vec![OutputRecord::unspent(5, vec![0x51])],
        );
        let fks = s
            .put_tx_full_batch_indexed(&[v1, v2, v3, hi], true)
            .unwrap();
        assert_eq!(fks.len(), 4);

        let (off, len) = s.txs.body_range(fks[0]).unwrap();
        let raw = s.txs.with_body_span(off, len, |b| Ok(b.to_vec())).unwrap();
        assert_eq!(raw[0] & 0x80, 0x80, "LAYOUT17 on first create");
        let (rec1, outs1) = s.get_tx_meta_and_outputs(fks[0]).unwrap();
        assert_eq!(rec1.version, 1);
        assert_eq!(outs1[0].script, p2pkh);

        let (rec2, outs2) = s.get_tx_meta_and_outputs(fks[1]).unwrap();
        assert_eq!(rec2.version, 2);
        assert_eq!(outs2[0].script, p2tr);
        assert_eq!(outs2[1].script, p2wsh);
        let (off2, len2) = s.txs.body_range(fks[1]).unwrap();
        let raw2 = s
            .txs
            .with_body_span(off2, len2, |b| Ok(b.to_vec()))
            .unwrap();
        let (_, meta_n) = TxRecord::decode_body_meta(&raw2).unwrap();
        assert_eq!(raw2[meta_n] & 0x0f, crate::compact::SCRIPT_KIND_V17_P2TR);

        let (rec3, outs3) = s.get_tx_meta_and_outputs(fks[2]).unwrap();
        assert_eq!(rec3.version, 3);
        assert_eq!(outs3[0].script, opreturn);
        assert_eq!(outs3[1].script, p2a);

        let (rec4, outs4) = s.get_tx_meta_and_outputs(fks[3]).unwrap();
        assert_eq!(rec4.version, high_ver);
        assert_eq!(outs4[0].script, vec![0x51]);

        let (soff, slen) = s.tx_spent_range(fks[1]).unwrap();
        assert_eq!(slen, 2 * OutputRecord::SPENT_SLOT_LEN as u64);
        assert_eq!(
            s.txs.get_output_spender_meta_at(soff, slen, 0).unwrap().1,
            Fk::NULL
        );

        s.flush().unwrap();
        drop(s);
        let s2 = Store::open_tiny(&dir).unwrap();
        let (_, outs) = s2.get_tx_meta_and_outputs(fks[1]).unwrap();
        assert_eq!(outs[0].script, p2tr);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mid-barrier kill: pre-tip flush only must not advance durable tip.
    ///
    /// Simulates kill after strong/height durable but before confirmed flush.
    /// Reopen: tip stays old; strong above tip is repaired; no permanent unstrong tip.
    #[test]
    fn class_c_barrier_pre_tip_only_does_not_advance_tip() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            // Genesis tip: height 0 → header fk 1, one strong tx.
            s.confirmed.set(Height(0), Fk(1)).unwrap();
            s.header_txs.put_range(Fk(1), Fk(1), 1).unwrap();
            s.strong_tx.set_strong(Fk(1), Fk(1)).unwrap();
            s.rebuild_height_fence().unwrap();
            s.flush_class_c_tip().unwrap();
            assert_eq!(s.confirmed.tip_height(), Some(Height(0)));

            // In-RAM tip extension (height 1) + strong for new txs — no full barrier.
            s.strong_tx.set_strong_range(Fk(2), 3, Fk(2)).unwrap();
            s.header_txs.put_range(Fk(2), Fk(2), 3).unwrap();
            s.confirmed.set(Height(1), Fk(2)).unwrap();
            // Mid-barrier: strong/height durable, confirmed still unflushed.
            s.flush_class_c_pre_tip().unwrap();
            // Process still sees tip 1 in RAM.
            assert_eq!(s.confirmed.tip_height(), Some(Height(1)));
            // Drop without flushing confirmed (kill mid-barrier).
        }
        let s = Store::open_tiny(&dir).unwrap();
        // Durable tip must remain 0 — confirmed was not in pre_tip flush.
        assert_eq!(
            s.confirmed.tip_height(),
            Some(Height(0)),
            "mid-barrier kill must not leave tip ahead of last full barrier"
        );
        assert!(s.strong_tx.is_strong(Fk(1)).unwrap());
        // New strong may be durable above tip; repair clears them.
        let cleared = s.repair_class_c_above_tip().unwrap();
        assert!(
            cleared >= 1,
            "strong/height above tip should be repairable (got cleared={cleared})"
        );
        assert!(!s.is_confirmed_strong(Fk(2)).unwrap());
        assert!(!s.is_confirmed_strong(Fk(3)).unwrap());
        // Tip tx still strong.
        assert!(s.is_confirmed_strong(Fk(1)).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Full barrier: tip + strong both durable; reopen matches.
    #[test]
    fn class_c_barrier_full_flush_reopen_tip_with_strong() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            s.confirmed.set(Height(0), Fk(1)).unwrap();
            s.header_txs.put_range(Fk(1), Fk(1), 1).unwrap();
            s.strong_tx.set_strong(Fk(1), Fk(1)).unwrap();
            s.rebuild_height_fence().unwrap();
            s.flush_class_c_tip().unwrap();

            s.strong_tx.set_strong_range(Fk(2), 2, Fk(2)).unwrap();
            s.confirmed.set(Height(1), Fk(2)).unwrap();
            s.header_txs.put_range(Fk(2), Fk(2), 2).unwrap();
            s.rebuild_height_fence().unwrap();
            s.flush_class_c_tip().unwrap();
        }
        let s = Store::open_tiny(&dir).unwrap();
        assert_eq!(s.confirmed.tip_height(), Some(Height(1)));
        assert_eq!(s.confirmed.get(Height(1)).unwrap(), Some(Fk(2)));
        assert!(s.is_confirmed_strong(Fk(1)).unwrap());
        assert!(s.is_confirmed_strong(Fk(2)).unwrap());
        assert!(s.is_confirmed_strong(Fk(3)).unwrap());
        assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// RPC TipOnly misses write-behind until drain. Confirm leftover is load-owned.
    #[test]
    fn get_fk_by_txid_tip_hits_pending_before_head_drain() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        s.confirmed.set(Height(0), Fk(1)).unwrap();
        s.header_txs.put_range(Fk(1), Fk(1), 1).unwrap();
        s.strong_tx.set_strong(Fk(1), Fk(1)).unwrap();
        let item = coinbase_item([0x51; 32], vec![OutputRecord::unspent(1, vec![0x51])]);
        let fks = s
            .put_tx_full_batch_indexed(&[item], /*index=*/ false)
            .unwrap();
        s.txs.head_note_pending(&[([0x51; 32], fks[0])]);
        s.rebuild_height_fence().unwrap();
        assert_eq!(
            s.get_fk_by_txid_tip(&[0x51; 32]).unwrap(),
            None,
            "pre-drain TipOnly is durable head only"
        );
        assert_eq!(s.txs.head_drain_pending().unwrap(), 1);
        assert_eq!(s.get_fk_by_txid_tip(&[0x51; 32]).unwrap(), Some(fks[0]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `confirmed.set` publishes tip HWM; fence stays at the last extend.
    /// In-flight prune must use [`Store::fence_tip_height`], not tip HWM
    /// (mainnet 945952: leftover TipOnly wiped open-head parents).
    #[test]
    fn fence_tip_height_lags_unextended_confirmed() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        s.confirmed.set(Height(0), Fk(1)).unwrap();
        s.header_txs.put_range(Fk(1), Fk(1), 1).unwrap();
        s.rebuild_height_fence().unwrap();
        assert_eq!(s.tip_height(), Some(Height(0)));
        assert_eq!(s.fence_tip_height(), Some(0));

        s.confirmed.set(Height(1), Fk(2)).unwrap();
        s.header_txs.put_range(Fk(2), Fk(2), 2).unwrap();
        assert_eq!(
            s.tip_height(),
            Some(Height(1)),
            "set_many/set publishes tip"
        );
        assert_eq!(
            s.fence_tip_height(),
            Some(0),
            "fence stays at last extend until height_fence_extend"
        );
        assert_eq!(s.tx_height_get(Fk(2)).unwrap(), None);

        s.height_fence_extend(Height(1), Fk(2)).unwrap();
        assert_eq!(s.fence_tip_height(), Some(1));
        assert_eq!(s.tx_height_get(Fk(2)).unwrap(), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Confirmed tip + missing `header_txs` range: extend must not return `Ok`
    /// and leave `height_of` None (live TipOnly hole; restart rebuild heals).
    #[test]
    fn height_fence_extend_missing_header_txs_is_not_ok_hole() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        s.confirmed.set(Height(0), Fk(1)).unwrap();
        s.header_txs.put_range(Fk(1), Fk(1), 1).unwrap();
        s.rebuild_height_fence().unwrap();

        s.confirmed.set(Height(1), Fk(2)).unwrap();
        let err = s
            .height_fence_extend(Height(1), Fk(2))
            .expect_err("missing header_txs must not silently skip");
        let msg = err.to_string();
        assert!(
            msg.contains("header_txs"),
            "shipped error must name the missing range: {msg}"
        );
        assert_eq!(
            s.tx_height_get(Fk(2)).unwrap(),
            None,
            "must not invent a connected height"
        );
        assert_eq!(s.fence_tip_height(), Some(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unknown prev_txid: no probe cands → leftover miss is `head`, not body/idx.
    #[test]
    fn tiponly_unknown_txid_miss_on_head() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let miss = [0x11u8; 32];
        let hits = s.get_fk_by_txid_batch(&[miss]).unwrap();
        assert!(hits[0].1.is_none());
        let (on, cands) = crate::head_resolve_stats::take_leftover_miss().expect("classified");
        assert_eq!(on, LeftoverMissOn::Head);
        assert_eq!(cands, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Head + txid.body exist, no fence run → TipOnly leftover miss is `fence`.
    #[test]
    fn tiponly_unconnected_identity_miss_on_fence() {
        use crate::tx_table::OutputRecord;
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let txid = [0x22u8; 32];
        let rec = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let _fk = s
            .put_tx_full_batch_indexed(
                &[(rec, vec![], vec![OutputRecord::unspent(1, vec![0x51])])],
                true,
            )
            .unwrap()[0];
        let hits = s.get_fk_by_txid_batch(&[txid]).unwrap();
        assert!(
            hits[0].1.is_none(),
            "TipOnly must drop unconnected identity"
        );
        let (on, cands) = crate::head_resolve_stats::take_leftover_miss().expect("classified");
        assert_eq!(on, LeftoverMissOn::Fence);
        assert!(
            cands >= 1,
            "open-head probe must have produced the create fk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Same-page foreigner: leftover TipOnly miss is `body`, and the shipped
    /// miss path records a hop dump (A's fk, no body match, empty stop).
    #[test]
    fn tiponly_same_page_foreigner_records_probe_diag() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let a = [0xAAu8; 32];
        let rec = TxRecord {
            txid: a,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let a_fk = s
            .put_tx_full_batch_indexed(
                &[(rec, vec![], vec![OutputRecord::unspent(1, vec![0x51])])],
                true,
            )
            .unwrap()[0];
        let bits = s.txs.head.bits();
        let mix_a = s.txs.secret.mix_txid(&a);
        let page_a = crate::address_head::page_base_for_txid(&mix_a, bits);
        let h1_a = crate::address_head::h1_in_page(&mix_a, bits);
        let mut b = [0xBBu8; 32];
        let mut found = false;
        // Tiny heads take page and h1 from 16 mixed bits (1 in 65536).
        // Half a million draws misses often enough to fail CI; the cap is
        // many times the mean, and the loop stops at the first hit.
        for i in 0u64..8_000_000 {
            b[24..32].copy_from_slice(&i.to_le_bytes());
            let mix_b = s.txs.secret.mix_txid(&b);
            if crate::address_head::page_base_for_txid(&mix_b, bits) == page_a
                && crate::address_head::h1_in_page(&mix_b, bits) == h1_a
            {
                found = true;
                break;
            }
        }
        assert!(found, "need a same-slot miss key (page+h1)");
        let hits = s.get_fk_by_txid_batch(&[b]).unwrap();
        assert!(hits[0].1.is_none(), "B is not in the head");
        let (on, n_cands) = crate::head_resolve_stats::take_leftover_miss().expect("classified");
        assert_eq!(on, LeftoverMissOn::Body);
        assert!(n_cands >= 1, "A must be a hop cand, n_cands={n_cands}");
        assert!(
            !crate::head_resolve_stats::leftover_probe_diag_recorded(&b),
            "resolve must not dump this key; leftover caller does"
        );
        s.diagnose_leftover_probe(&b);
        let diag = crate::head_resolve_stats::take_leftover_probe_diag()
            .expect("leftover miss path must record a probe dump");
        assert_eq!(diag.txid, b);
        assert_eq!(diag.page_base, page_a);
        assert!(diag.hit_empty, "hop must stop at empty");
        assert!(diag.hop_equal_second, "second page load must match first");
        assert!(
            diag.cands
                .iter()
                .any(|c| c.abs_fk == a_fk.0 && !c.body_match),
            "dump must list A's fk with body≠B, cands={:?}",
            diag.cands
                .iter()
                .map(|c| (c.abs_fk, c.body_match))
                .collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Open `tx.head` page is `page_base_for_txid(mix_txid(txid))`, not raw txid.
    #[test]
    fn open_head_page_uses_mix_txid_not_raw() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let bits = s.txs.head.bits();
        let mut txid = [0x11u8; 32];
        let mut found = false;
        for i in 0u64..100_000 {
            txid[24..32].copy_from_slice(&i.to_le_bytes());
            let mixed = s.txs.secret.mix_txid(&txid);
            let raw_page = crate::address_head::page_base_for_txid(&txid, bits);
            let mix_page = crate::address_head::page_base_for_txid(&mixed, bits);
            if raw_page != mix_page {
                s.diagnose_leftover_probe(&txid);
                let diag =
                    crate::head_resolve_stats::take_leftover_probe_diag().expect("probe dump");
                assert_eq!(diag.page_base, mix_page);
                assert_ne!(diag.page_base, raw_page);
                found = true;
                break;
            }
        }
        assert!(found, "need a txid whose mix moves the open-head page");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Lookup / BQ-ahead also use TipOnly `get_fk_by_txid_batch`. A miss there
    /// is routine (parent not published yet). Dump + WARN only on leftover.
    #[test]
    fn tiponly_resolve_miss_does_not_dump_probe_diag() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let miss = [0xCCu8; 32];
        let hits = s.get_fk_by_txid_batch(&[miss]).unwrap();
        assert!(hits[0].1.is_none(), "unknown txid must miss");
        assert!(
            !crate::head_resolve_stats::leftover_probe_diag_recorded(&miss),
            "resolve TipOnly miss must not hop-dump this key; leftover miss path only"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Kill after the tip shrink, before unstrong, is repairable.
    #[test]
    fn class_c_disconnect_tip_first_mid_barrier_is_repairable() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            // Tip 0 + tip 1 fully durable.
            s.confirmed.set(Height(0), Fk(1)).unwrap();
            s.header_txs.put_range(Fk(1), Fk(1), 1).unwrap();
            s.strong_tx.set_strong(Fk(1), Fk(1)).unwrap();
            s.confirmed.set(Height(1), Fk(2)).unwrap();
            s.header_txs.put_range(Fk(2), Fk(2), 2).unwrap();
            s.strong_tx.set_strong_range(Fk(2), 2, Fk(2)).unwrap();
            s.rebuild_height_fence().unwrap();
            s.flush_class_c_tip().unwrap();
            assert_eq!(s.confirmed.tip_height(), Some(Height(1)));

            // Disconnect tip-first: shrink tip + flush confirmed only (kill before unstrong).
            s.confirmed.disconnect_tip(Height(1)).unwrap();
            s.flush_confirmed_only().unwrap();
            // Do not unstrong — simulate kill mid-disconnect.
        }
        let s = Store::open_tiny(&dir).unwrap();
        assert_eq!(
            s.confirmed.tip_height(),
            Some(Height(0)),
            "tip shrink must be durable after flush_confirmed_only"
        );
        // Strong may still mark height-1 txs; they are not on the new fence.
        assert!(s.strong_tx.is_strong(Fk(2)).unwrap());
        let cleared = s.repair_class_c_above_tip().unwrap();
        assert!(
            cleared >= 1,
            "strong/height above new tip must be repairable (cleared={cleared})"
        );
        assert!(s.is_confirmed_strong(Fk(1)).unwrap());
        assert!(!s.is_confirmed_strong(Fk(2)).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Full disconnect barrier sequence (tip shrink → unstrong/height → flush).
    #[test]
    fn class_c_disconnect_full_sequence_reopen_clean() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            s.confirmed.set(Height(0), Fk(1)).unwrap();
            s.header_txs.put_range(Fk(1), Fk(1), 1).unwrap();
            s.strong_tx.set_strong(Fk(1), Fk(1)).unwrap();
            s.confirmed.set(Height(1), Fk(2)).unwrap();
            s.header_txs.put_range(Fk(2), Fk(2), 2).unwrap();
            s.strong_tx.set_strong_range(Fk(2), 2, Fk(2)).unwrap();
            s.rebuild_height_fence().unwrap();
            s.flush_class_c_tip().unwrap();

            // Production disconnect order (store half).
            s.confirmed.disconnect_tip(Height(1)).unwrap();
            s.flush_confirmed_only().unwrap();
            s.strong_tx.set_unstrong_range(Fk(2), 2).unwrap();
            s.height_fence_pop_tip(Height(1));
            s.flush_class_c_after_disconnect_tip().unwrap();
        }
        let s = Store::open_tiny(&dir).unwrap();
        assert_eq!(s.confirmed.tip_height(), Some(Height(0)));
        assert!(s.is_confirmed_strong(Fk(1)).unwrap());
        assert!(!s.strong_tx.is_strong(Fk(2)).unwrap());
        assert_eq!(s.tx_height_get(Fk(2)).unwrap(), None);
        assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orphan_class_c_at_tip_height_not_confirmed_strong_and_repairable() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        // Real tip body: txs 1..=2 under header 1.
        s.confirmed.set(Height(0), Fk(1)).unwrap();
        s.header_txs.put_range(Fk(1), Fk(1), 2).unwrap();
        s.strong_tx.set_strong_range(Fk(1), 2, Fk(1)).unwrap();
        s.rebuild_height_fence().unwrap();
        // Orphan second copy: txs 3..=4 strong, not in header_txs.
        s.strong_tx.set_strong_range(Fk(3), 2, Fk(99)).unwrap();
        s.flush_class_c_tip().unwrap();

        assert!(s.is_confirmed_strong(Fk(1)).unwrap());
        assert!(s.is_confirmed_strong(Fk(2)).unwrap());
        assert!(
            !s.is_confirmed_strong(Fk(3)).unwrap(),
            "orphan at tip height must not be confirmed-strong"
        );
        assert!(!s.is_confirmed_strong(Fk(4)).unwrap());

        let n = s.repair_class_c_above_tip().unwrap();
        assert!(n >= 2, "cleared={n}");
        assert!(!s.strong_tx.is_strong(Fk(3)).unwrap());
        assert_eq!(s.tx_height_get(Fk(3)).unwrap(), None);
        assert!(s.is_confirmed_strong(Fk(1)).unwrap());
        assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No tip → repair is a no-op; gapped orphans clear as separate runs.
    #[test]
    fn repair_class_c_above_tip_empty_tip_and_gapped_orphans() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
            // Tip body 1..=2; orphans 5 and 10 (non-adjacent → two clear runs).
            s.confirmed.set(Height(0), Fk(1)).unwrap();
            s.header_txs.put_range(Fk(1), Fk(1), 2).unwrap();
            s.strong_tx.set_strong_range(Fk(1), 2, Fk(1)).unwrap();
            s.rebuild_height_fence().unwrap();
            s.strong_tx.set_strong(Fk(5), Fk(99)).unwrap();
            s.strong_tx.set_strong(Fk(10), Fk(99)).unwrap();
            s.flush_class_c_tip().unwrap();
            let n = s.repair_class_c_above_tip().unwrap();
            assert_eq!(n, 2, "cleared gapped orphans");
            assert!(!s.strong_tx.is_strong(Fk(5)).unwrap());
            assert!(!s.strong_tx.is_strong(Fk(10)).unwrap());
            assert!(s.is_confirmed_strong(Fk(1)).unwrap());
            // Strong not on the fence (same repair as above-tip leftovers).
            s.strong_tx.set_strong(Fk(20), Fk(1)).unwrap();
            assert_eq!(s.repair_class_c_above_tip().unwrap(), 1);
            assert!(!s.strong_tx.is_strong(Fk(20)).unwrap());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Upgrade open paths: missing optional tables recreated; unspent without range.
    #[test]
    fn store_open_upgrade_missing_tables_and_unspent_no_range() {
        let dir = tmp();
        {
            let s = Store::create_tiny(&dir).unwrap();
            let create = coinbase_item([20u8; 32], vec![OutputRecord::unspent(10, vec![0x51])]);
            let fk = s.put_tx_full_batch_indexed(&[create], true).unwrap()[0];
            s.flush().unwrap();
            drop(s);
            // Remove optional tables so open recreate branches run.
            let _ = std::fs::remove_file(dir.join("scripthash.body"));
            let _ = std::fs::remove_dir_all(dir.join("scripthash.body"));
            let _ = std::fs::remove_dir_all(dir.join("scripthash.ovf"));
            let _ = std::fs::remove_dir_all(dir.join("scripthash.head"));
            let _ = std::fs::remove_file(dir.join("scripthash.head"));
            let _ = std::fs::remove_file(dir.join("header_txs_first.body"));
            let _ = std::fs::remove_file(dir.join("header_txs_count.body"));
            let _ = std::fs::remove_file(dir.join("tx_height.body"));
            let s = Store::open_tiny(&dir).unwrap();
            assert_eq!(s.get_tx(fk).unwrap().txid, [20u8; 32]);
            // unspent without body_range
            let u = s.unspent_create_vouts(fk, &[0], None).unwrap();
            assert_eq!(u, vec![0]);
            // empty vouts
            assert!(s.unspent_create_vouts(fk, &[], None).unwrap().is_empty());
            let batch = s
                .unspent_create_vouts_batch(&[(fk, vec![0u32]), (fk, vec![])])
                .unwrap();
            assert_eq!(batch[0], vec![0]);
            assert!(batch[1].is_empty());
            // has_confirmed without range, no spender
            assert!(!s.has_confirmed_strong_spender_create(fk, 0, None).unwrap());
            assert!(!s.has_confirmed_strong_spender(&[20u8; 32], 0).unwrap());
            assert!(s.spenders_raw(&[20u8; 32], 0).unwrap().is_empty());
            assert!(s.spenders(&[9u8; 32], 0).unwrap().is_empty());
            assert_eq!(s.repair_class_c_above_tip().unwrap(), 0);
            drop(s);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unspent_create_vouts_batch_matches_serial() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let mut fks = Vec::new();
        for i in 1u8..=4 {
            let item = coinbase_item(
                [i; 32],
                vec![
                    OutputRecord::unspent(10, vec![0x51]),
                    OutputRecord::unspent(11, vec![0x51]),
                ],
            );
            fks.push(s.put_tx_full_batch_indexed(&[item], true).unwrap()[0]);
        }
        s.flush().unwrap();
        let items: Vec<(Fk, Vec<u32>)> = fks.iter().map(|fk| (*fk, vec![0, 1])).collect();
        let batch = s.unspent_create_vouts_batch(&items).unwrap();
        assert_eq!(batch.len(), 4);
        for (i, fk) in fks.iter().enumerate() {
            assert_eq!(
                batch[i],
                s.unspent_create_vouts(*fk, &[0, 1], None).unwrap(),
                "fk {fk:?}"
            );
        }
        assert!(s.unspent_create_vouts_batch(&[]).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keep_unspent_vout_subsequence_keeps_in_order_subset() {
        let mut v = vec![0u32, 1, 2, 3];
        keep_unspent_vout_subsequence(&mut v, &[0, 2], |x| *x);
        assert_eq!(v, vec![0, 2]);

        let mut all = vec![5u32, 7];
        keep_unspent_vout_subsequence(&mut all, &[5, 7], |x| *x);
        assert_eq!(all, vec![5, 7]);

        let mut none = vec![1u32, 2];
        keep_unspent_vout_subsequence(&mut none, &[], |x| *x);
        assert!(none.is_empty());
    }

    /// Two Class A rows for one txid, the older connected and the newer not
    /// (a competing block at the same height, archived and then reorged
    /// away): the tip resolvers pick the connected row and the any-row
    /// resolve the newest. The last beat stamps a connected spender on the
    /// connected row's vout 0 at height 1; the newer row has no spenders, so
    /// the spentness probe and the spender walk must read the connected row.
    /// A store unit, not a journey: the result is pure (which row each reader
    /// picks), and reaching two rows for one txid through a session needs a
    /// competing stale block, a fixture cost with no extra observation.
    #[test]
    fn resolve_txid_prefers_connected_over_newer_unconnected() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        let txid = [0xABu8; 32];
        let rec = |lock| TxRecord {
            txid,
            version: 1,
            locktime: lock,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        let out = vec![OutputRecord::unspent(1, vec![0x51])];
        let old = s
            .put_tx_full_batch_indexed(&[(rec(1), vec![], out.clone())], true)
            .unwrap()[0];
        let new = s
            .put_tx_full_batch_indexed(&[(rec(2), vec![], out)], true)
            .unwrap()[0];
        assert_ne!(old, new);
        assert_eq!(s.get_fk_by_txid(&txid).unwrap(), Some(new));
        assert_eq!(s.get_fk_by_txid_tip(&txid).unwrap(), None);
        s.header_txs.put_range(Fk(1), old, 1).unwrap();
        s.confirmed.set(Height(0), Fk(1)).unwrap();
        s.rebuild_height_fence().unwrap();
        assert_eq!(
            s.get_fk_by_txid_tip(&txid).unwrap(),
            Some(old),
            "connected older row must win"
        );
        assert_eq!(s.get_fk_by_txid(&txid).unwrap(), Some(old));
        let batch_tip = s
            .get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipOnly)
            .unwrap();
        assert_eq!(batch_tip[0].1.map(|(f, _)| f), Some(old));
        let batch_any = s
            .get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipThenAny)
            .unwrap();
        assert_eq!(batch_any[0].1.map(|(f, _)| f), Some(old));

        let spender = s
            .put_tx_full_batch_indexed(
                &[(
                    TxRecord {
                        txid: [0xBAu8; 32],
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    vec![InputRecord {
                        prev_txid: txid,
                        create_fk: old,
                        prev_index: 0,
                        sequence: u32::MAX,
                        script_sig: vec![],
                        witness: vec![],
                    }],
                    vec![OutputRecord::unspent(1, vec![0x51])],
                )],
                true,
            )
            .unwrap()[0];
        s.header_txs.put_range(Fk(2), spender, 1).unwrap();
        s.confirmed.set(Height(1), Fk(2)).unwrap();
        s.strong_tx.set_strong(spender, Fk(2)).unwrap();
        s.rebuild_height_fence().unwrap();
        s.put_spend_create(old, 0, spender, 0).unwrap();
        assert!(
            s.has_confirmed_strong_spender(&txid, 0).unwrap(),
            "spentness is probed on the connected create, not the newest row"
        );
        assert_eq!(
            s.spenders(&txid, 0).unwrap()[0].spending_tx_fk,
            spender,
            "spenders walk the connected create"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Connected sibling in a **cold** sealed age must beat a newer unconnected
    /// hot hit (`TipThenAny` and `TipOnly`). Stopping after the unconnected
    /// newer cand would regress to that row.
    #[test]
    fn tip_then_any_connected_in_cold_beats_unconnected_hot() {
        use crate::address_head::HeadLayout;
        use crate::head_resolve_stats::sealed_age_for_fk;
        use crate::tx_table::OutputRecord;

        fn put_one(s: &Store, txid: [u8; 32], lock: u32) -> Fk {
            let rec = TxRecord {
                txid,
                version: 1,
                locktime: lock,
                input_start_fk: Fk::NULL,
                input_count: 0,
                output_start_fk: Fk::NULL,
                output_count: 1,
            };
            let out = vec![OutputRecord::unspent(1, vec![0x51])];
            s.put_tx_full_batch_indexed(&[(rec, vec![], out)], true)
                .unwrap()[0]
        }

        let dir = tmp();
        // bits=8 → 256 slots, seal ~204 keys. Five segments ⇒ oldest age ≥4.
        let s = Store::create_layout_with_head(
            StoreLayout::tiny(&dir),
            HeadLayout::with_entry_bytes(8, 4).unwrap(),
        )
        .unwrap();
        let txid = [0xCDu8; 32];
        let old = put_one(&s, txid, 1);
        let n = 204u32.saturating_mul(5);
        let mut items = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut dummy = [0u8; 32];
            dummy[0..8].copy_from_slice(&(u64::from(i) + 10).to_le_bytes());
            dummy[15] = 0xee;
            items.push((
                TxRecord {
                    txid: dummy,
                    version: 1,
                    locktime: i,
                    input_start_fk: Fk::NULL,
                    input_count: 0,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                vec![],
                vec![OutputRecord::unspent(1, vec![0x51])],
            ));
        }
        s.put_tx_full_batch_indexed(&items, true).unwrap();
        s.txs.flush_head().unwrap();
        let first = s.txs.head.first_fks_snapshot();
        let age = sealed_age_for_fk(&first, old.0).unwrap_or(0);
        assert!(
            s.txs.head.sealed_segment_count() >= 4,
            "oldest must sit behind newer sealed segments age={age} segs={} sealed={}",
            s.txs.head.segment_count(),
            s.txs.head.sealed_segment_count()
        );
        let new = put_one(&s, txid, 2);
        assert_ne!(old, new);
        let first = s.txs.head.first_fks_snapshot();
        let age_old = sealed_age_for_fk(&first, old.0).unwrap();
        let age_new = sealed_age_for_fk(&first, new.0).unwrap();
        assert!(
            age_old > age_new,
            "old fk must be older than the new row age_old={age_old} age_new={age_new}"
        );

        // Neither connected yet: newest unconnected row for TipThenAny.
        assert_eq!(s.get_fk_by_txid(&txid).unwrap(), Some(new));
        assert_eq!(
            s.get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipThenAny)
                .unwrap()[0]
                .1
                .map(|(f, _)| f),
            Some(new),
            "batch TipThenAny must keep newer unconnected when cold has no connected"
        );
        assert_eq!(
            s.get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipOnly)
                .unwrap()[0]
                .1,
            None
        );

        s.header_txs.put_range(Fk(1), old, 1).unwrap();
        s.confirmed.set(Height(0), Fk(1)).unwrap();
        s.rebuild_height_fence().unwrap();

        assert_eq!(s.get_fk_by_txid_tip(&txid).unwrap(), Some(old));
        assert_eq!(s.get_fk_by_txid(&txid).unwrap(), Some(old));
        let batch_tip = s
            .get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipOnly)
            .unwrap();
        assert_eq!(
            batch_tip[0].1.map(|(f, _)| f),
            Some(old),
            "TipOnly must take connected cold sibling, not unconnected hot"
        );
        let batch_any = s
            .get_fk_by_txid_batch_mode(&[txid], TxidResolveMode::TipThenAny)
            .unwrap();
        assert_eq!(
            batch_any[0].1.map(|(f, _)| f),
            Some(old),
            "TipThenAny must take connected cold sibling over newer unconnected hot"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_does_not_write_archive_epoch() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        assert!(
            !dir.join("archive_epoch").exists(),
            "unread leftover must not be created"
        );
        assert!(dir.join("spent.ovf").exists());
        assert!(!dir.join("spenders.body").exists());
        assert!(!dir.join("tx.body").exists());
        assert!(!dir.join("wire").exists());
        s.flush().unwrap();
        drop(s);
        std::fs::write(dir.join("archive_epoch"), b"junk").unwrap();
        std::fs::create_dir_all(dir.join("wire")).unwrap();
        std::fs::write(dir.join("wire").join("leftover"), b"x").unwrap();
        std::fs::write(dir.join("sp_tweaks.idx"), b"old-idx").unwrap();
        std::fs::write(dir.join("sp_tweaks.body"), b"old-body").unwrap();
        let s = Store::open_tiny(&dir).unwrap();
        assert!(!dir.join("archive_epoch").exists());
        assert!(!dir.join("wire").exists());
        assert!(!dir.join("sp_tweaks.idx").is_file());
        assert!(!dir.join("sp_tweaks.body").is_file());
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_does_not_write_tx_height_and_fence_has_reorg_holes() {
        let dir = tmp();
        let s = Store::create_tiny(&dir).unwrap();
        assert!(
            !dir.join("tx_height.body").exists(),
            "live create must not write tx_height.body"
        );
        s.header_txs.put_range(Fk(1), Fk(1), 2).unwrap();
        s.confirmed.set(Height(0), Fk(1)).unwrap();
        // Discarded block used fks 3..=5 under header 2 (not confirmed).
        s.header_txs.put_range(Fk(2), Fk(3), 3).unwrap();
        s.header_txs.put_range(Fk(3), Fk(6), 2).unwrap();
        s.confirmed.set(Height(1), Fk(3)).unwrap();
        s.rebuild_height_fence().unwrap();
        assert_eq!(s.tx_height_get(Fk(1)).unwrap(), Some(0));
        assert_eq!(s.tx_height_get(Fk(3)).unwrap(), None);
        assert_eq!(s.tx_height_get(Fk(5)).unwrap(), None);
        assert_eq!(s.tx_height_get(Fk(6)).unwrap(), Some(1));
        s.flush().unwrap();
        drop(s);
        assert!(!dir.join("tx_height.body").exists());
        // Leftover 15 file is unlinked on open.
        std::fs::write(dir.join("tx_height.body"), b"junk").unwrap();
        let s = Store::open_tiny(&dir).unwrap();
        assert!(!dir.join("tx_height.body").exists());
        assert_eq!(s.tx_height_get(Fk(5)).unwrap(), None);
        assert_eq!(s.tx_height_get(Fk(6)).unwrap(), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_renames_legacy_inwit_stem() {
        let dir = tmp();
        Store::create_tiny(&dir).unwrap();
        std::fs::rename(dir.join("seqsigwit.body"), dir.join("inwit.body")).unwrap();
        std::fs::rename(dir.join("seqsigwit.loc"), dir.join("inwit.loc")).unwrap();
        Store::open_tiny(&dir).unwrap();
        assert!(dir.join("seqsigwit.body").is_file());
        assert!(dir.join("seqsigwit.loc").is_file());
        assert!(!dir.join("inwit.body").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_renames_legacy_inputs_stem() {
        let dir = tmp();
        Store::create_tiny(&dir).unwrap();
        std::fs::rename(dir.join("input.loc"), dir.join("inputs.loc")).unwrap();
        std::fs::rename(dir.join("input.off"), dir.join("inputs.off")).unwrap();
        std::fs::rename(dir.join("input.body"), dir.join("inputs.body")).unwrap();
        Store::open_tiny(&dir).unwrap();
        assert!(dir.join("input.loc").is_file());
        assert!(dir.join("input.body").is_file());
        assert!(!dir.join("inputs.loc").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn split_create_puts_seqsigwit_only_on_cold() {
        let root = tmp();
        let hot = root.join("hot");
        let cold = root.join("cold");
        let s = Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
        assert_eq!(s.path(), hot.as_path());
        assert_eq!(s.cold_path(), Some(cold.as_path()));
        assert!(hot.join("txout.body").is_file());
        assert!(hot.join("spent.body").is_file());
        assert!(!hot.join("seqsigwit.body").exists());
        assert!(!hot.join("seqsigwit.loc").exists());
        assert!(cold.join("seqsigwit.body").is_file());
        assert!(cold.join("seqsigwit.loc").is_file());
        assert!(!hot.join("txstat.body").exists());
        assert!(!hot.join("input.loc").exists());
        assert!(cold.join("txstat.body").is_file());
        assert!(cold.join("input.loc").is_file());
        assert!(cold.join("input.body").is_file());
        assert!(hot.join(SEQSIGWIT_RELOC_NAME).is_file());
        drop(s);
        let s = Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
        assert_eq!(s.cold_path(), Some(cold.as_path()));
        let hot_n = dir_file_bytes(&hot);
        let cold_n = dir_file_bytes(&cold);
        assert!(hot_n > 0 && cold_n > 0);
        assert_eq!(s.datadir_bytes(), hot_n.saturating_add(cold_n));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_open_without_cold_flag_refuses_reloc() {
        let root = tmp();
        let hot = root.join("hot");
        let cold = root.join("cold");
        Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
        match Store::open_tiny(&hot) {
            Ok(_) => panic!("must refuse when seqsigwit.reloc is present"),
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("datadir-cold"), "{msg}");
                assert!(msg.contains(SEQSIGWIT_RELOC_NAME), "{msg}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_refuses_seqsigwit_left_in_hot() {
        let root = tmp();
        let hot = root.join("hot");
        let cold = root.join("cold");
        Store::create_tiny(&hot).unwrap();
        std::fs::create_dir_all(&cold).unwrap();
        match Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)) {
            Ok(_) => panic!("must refuse leftover seqsigwit in hot"),
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("move seqsigwit.body"), "{msg}");
                assert!(msg.contains("seqsigwit.loc"), "{msg}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_refuses_seqsigwit_in_both_dirs() {
        let root = tmp();
        let hot = root.join("hot");
        let cold = root.join("cold");
        Store::create_tiny(&hot).unwrap();
        std::fs::create_dir_all(&cold).unwrap();
        std::fs::copy(hot.join("seqsigwit.body"), cold.join("seqsigwit.body")).unwrap();
        match Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)) {
            Ok(_) => panic!("must refuse dual seqsigwit copies"),
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("both"), "{msg}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_refuses_blockfilter_left_in_hot() {
        let root = tmp();
        let hot = root.join("hot");
        let cold = root.join("cold");
        Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
        std::fs::create_dir_all(hot.join("blockfilter.idx")).unwrap();
        match Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)) {
            Ok(_) => panic!("must refuse blockfilter left on the hot store"),
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("blockfilter.idx"), "{msg}");
                assert!(msg.contains("move"), "{msg}");
                assert!(msg.contains(cold.to_str().unwrap()), "{msg}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_refuses_sp_tweaks_in_both_dirs() {
        let root = tmp();
        let hot = root.join("hot");
        let cold = root.join("cold");
        Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
        std::fs::create_dir_all(hot.join("sp_tweaks.body")).unwrap();
        std::fs::create_dir_all(cold.join("sp_tweaks.body")).unwrap();
        match Store::open_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)) {
            Ok(_) => panic!("must refuse sp_tweaks in both stores"),
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("sp_tweaks.body"), "{msg}");
                assert!(msg.contains("both"), "{msg}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn split_roundtrip_create_fk_and_seqsigwit_range() {
        let root = tmp();
        let hot = root.join("hot");
        let cold = root.join("cold");
        let s = Store::create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
        let item = coinbase_item([9u8; 32], vec![OutputRecord::unspent(1, vec![0x51])]);
        let fks = s
            .txs
            .put_full_batch_indexed(std::slice::from_ref(&item), true)
            .unwrap();
        assert_eq!(fks.len(), 1);
        let range = s.tx_seqsigwit_range(fks[0]).unwrap();
        assert!(range.1 > 0);
        s.flush().unwrap();
        drop(s);
        let s = Store::open_or_create_layout(StoreLayout::tiny(&hot).with_cold_dir(&cold)).unwrap();
        assert_eq!(s.txs.count(), 1);
        let range = s.tx_seqsigwit_range(fks[0]).unwrap();
        assert!(range.1 > 0);
        assert!(!hot.join("seqsigwit.body").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
