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
#[doc(hidden)]
pub const COLD_INDEX_DIRS: &[&str] = &[
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
/// [`Self::single`] / `Self::with_cold` are **Mainnet** scale (production).
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

    pub fn with_cold_dir(mut self, cold_dir: impl Into<PathBuf>) -> Self {
        self.cold_dir = Some(cold_dir.into());
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

#[doc(hidden)]
pub fn rename_legacy_pairs(dir: &Path, pairs: &[(&str, &str)]) -> Result<(), StoreError> {
    if !dir.exists() {
        return Ok(());
    }
    for (old, new) in pairs {
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

pub fn rename_legacy_input_files(dir: &Path) -> Result<(), StoreError> {
    rename_legacy_pairs(
        dir,
        &[
            ("inputs.loc", "input.loc"),
            ("inputs.off", "input.off"),
            ("inputs.body", "input.body"),
        ],
    )
}

pub fn rename_legacy_inwit_files(dir: &Path) -> Result<(), StoreError> {
    rename_legacy_pairs(
        dir,
        &[
            ("inwit.body", "seqsigwit.body"),
            ("inwit.loc", "seqsigwit.loc"),
            ("inwit.off", "seqsigwit.off"),
            ("inwit.loc.ovf", "seqsigwit.loc.ovf"),
            ("inwit.idx", "seqsigwit.idx"),
            ("inwit.reloc", "seqsigwit.reloc"),
            ("inwit.prune", "seqsigwit.prune"),
            ("inwit.window", "seqsigwit.window"),
        ],
    )
}

#[doc(hidden)]
pub fn refuse_cold_index_dirs(hot: &Path, cold: &Path) -> Result<(), StoreError> {
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

#[doc(hidden)]
pub fn seqsigwit_files_present(dir: &Path) -> bool {
    dir.join("seqsigwit.body").exists()
        || dir.join("seqsigwit.loc").exists()
        || dir.join("seqsigwit.idx").exists()
}

#[doc(hidden)]
pub fn seqsigwit_reloc_path(hot: &Path) -> PathBuf {
    hot.join(SEQSIGWIT_RELOC_NAME)
}

/// Decide the seqsigwit VarTable directory. Split stores refuse leftovers in hot
/// and dual copies; a reloc marker without `--datadir-cold` is a layout error
/// (not `Corrupt`).
#[doc(hidden)]
pub fn resolve_seqsigwit_dir(layout: &StoreLayout) -> Result<PathBuf, StoreError> {
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

#[doc(hidden)]
pub fn dir_file_bytes(root: &Path) -> u64 {
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

#[doc(hidden)]
pub fn write_seqsigwit_reloc(hot: &Path) -> Result<(), StoreError> {
    let p = seqsigwit_reloc_path(hot);
    if p.exists() {
        return Ok(());
    }
    std::fs::write(&p, b"seqsigwit\n").map_err(|e| StoreError::io(&p, e))
}

/// Top-level store handle for a datadir `store/` directory.
pub struct Store {
    pub path: PathBuf,
    /// `{datadir-cold}/store` when append-only files are split; `None` = they live in [`Self::path`].
    pub cold_path: Option<PathBuf>,
    pub head_scale: HeadScale,
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
    pub height_fence: std::sync::RwLock<HeightFence>,
    /// BIP113 window at the fence tip (extend O(1); pop rebuilds).
    pub mtp_ring: std::sync::RwLock<MtpRing>,
    /// Latest confirm height plus one. Zero means no snapshot yet.
    pub spend_snapshot: std::sync::atomic::AtomicU64,
    /// Serializes spend-marker publishes so a checkpoint cannot overwrite a clamp.
    pub spend_marker: std::sync::Mutex<()>,
    /// First height of a confirm write whose spend annotate has not finished,
    /// plus one. Zero means none.
    pub spend_annotate_from: std::sync::atomic::AtomicU64,
    /// Disconnects since process start. A checkpoint publishes only when this
    /// word is unchanged across its `sync_data` window.
    pub spend_reorg_gen: std::sync::atomic::AtomicU64,
    /// Even while confirmed spentness is stable. Odd while a confirm annotate
    /// or a disconnect is publishing a change.
    pub utxo_view: crate::sync::atomic::AtomicU64,
    /// Confirm readers wait here while a `--datadir-hdd` write holds the spindle.
    /// Flag off never locks, so [`Self::spindle_wait`] returns immediately.
    pub spindle: std::sync::Mutex<()>,
}

/// Held across one rotating-media write burst. Drop releases [`Store::spindle_wait`].
pub struct SpindleHold<'a> {
    pub _guard: Option<std::sync::MutexGuard<'a, ()>>,
}

/// Holds [`Store::utxo_view`] odd until drop.
pub struct UtxoViewGuard<'a> {
    pub view: &'a crate::sync::atomic::AtomicU64,
}

impl Drop for UtxoViewGuard<'_> {
    fn drop(&mut self) {
        use crate::sync::atomic::Ordering;
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

    pub fn create_layout_with_head(
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
            utxo_view: crate::sync::atomic::AtomicU64::new(0),
            spend_marker: std::sync::Mutex::new(()),
            spindle: std::sync::Mutex::new(()),
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
        Self::open_layout_as(layout, false)
    }

    /// Open a closed store at `dir` to read it, for an `--assumehot` source.
    ///
    /// The store must be on the current schema. No leftover is dropped (a
    /// current binary already dropped them), a missing table is refused
    /// instead of created, and `header.head` keeps the slots its file has, so
    /// no head scale or `RBITCOIN_HEAD_SLOTS_HEADER` resizes it.
    pub fn open_source(dir: &Path) -> Result<Self, StoreError> {
        Self::open_layout_as(StoreLayout::single(dir), true)
    }

    fn open_layout_as(layout: StoreLayout, source: bool) -> Result<Self, StoreError> {
        crate::file::ensure_nofile_budget();
        let path = layout.dir.clone();
        if !path.is_dir() {
            return Err(StoreError::NotDirectory(path));
        }
        let meta_ver = check_meta(&path)?;
        if source {
            refuse_unopenable_source(&path, meta_ver)?;
        } else {
            open_layout_refuse_old(&path, meta_ver)?;
            drop_unread_store_leftovers(&path);
        }
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
        if !source {
            drop_leftover_tx_height(&path);
            crate::scripthash::unlink_scripthash_run_leftovers(&path)?;
            open_layout_rewrite_current(&path, meta_ver)?;
        }
        let (txs, cold_path) = open_layout_txs(&layout)?;
        let store = Self {
            headers: if source {
                HeaderTable::open_source(&path)?
            } else {
                HeaderTable::open_with_scale(&path, layout.head_scale)?
            },
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
            utxo_view: crate::sync::atomic::AtomicU64::new(0),
            spend_marker: std::sync::Mutex::new(()),
            spindle: std::sync::Mutex::new(()),
            path,
            cold_path,
            head_scale: layout.head_scale,
        };
        store.drop_confirmed_past_creates()?;
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

    #[doc(hidden)]
    pub fn fence(&self) -> std::sync::RwLockReadGuard<'_, HeightFence> {
        self.height_fence.read().unwrap_or_else(|e| e.into_inner())
    }

    #[doc(hidden)]
    pub fn fence_write(&self) -> std::sync::RwLockWriteGuard<'_, HeightFence> {
        self.height_fence.write().unwrap_or_else(|e| e.into_inner())
    }

    #[doc(hidden)]
    pub fn mtp_write(&self) -> std::sync::RwLockWriteGuard<'_, MtpRing> {
        self.mtp_ring.write().unwrap_or_else(|e| e.into_inner())
    }

    /// BIP113 times for `height` when it is the fence tip and the ring is warm.
    pub fn mtp_times_at(&self, height: Height) -> Option<(u8, [u32; 11])> {
        self.mtp_ring
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .window_at(height.0)
    }

    #[doc(hidden)]
    pub fn mtp_push(&self, height: u32, time: u32) {
        let pushed = self.mtp_write().try_push(height, time);
        if pushed {
            return;
        }
        let _ = self.rebuild_mtp_ring();
        let _ = self.mtp_write().try_push(height, time);
    }

    #[doc(hidden)]
    pub fn rebuild_mtp_ring(&self) -> Result<(), StoreError> {
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

    /// Parent edges for contiguous creates `first..=last` (1-based ids).
    ///
    /// One locator read and one `input.body` read. `None` is an unstamped create.
    pub fn input_edges_span(
        &self,
        first: u64,
        last: u64,
    ) -> Result<Vec<Option<Vec<crate::input::InputEdge>>>, StoreError> {
        self.txs.input.edges_span(first, last)
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

    /// Main datadir is rotating media (`--datadir-hdd`). Default off.
    pub fn datadir_hdd(&self) -> bool {
        self.txs.datadir_hdd()
    }

    pub fn set_datadir_hdd(&self, on: bool) {
        self.txs.set_datadir_hdd(on);
    }

    /// Block lookup and load while this guard is alive, when `--datadir-hdd` is set.
    /// Flag off returns a guard that does not take the lock.
    pub fn spindle_hold(&self) -> SpindleHold<'_> {
        if !self.datadir_hdd() {
            return SpindleHold { _guard: None };
        }
        SpindleHold {
            _guard: Some(self.spindle.lock().unwrap_or_else(|p| p.into_inner())),
        }
    }

    /// Wait until the write thread drops [`Self::spindle_hold`]. No-op when the flag is off.
    /// The write thread must not call this.
    pub fn spindle_wait(&self) {
        if !self.datadir_hdd() {
            return;
        }
        let _guard = self.spindle.lock().unwrap_or_else(|p| p.into_inner());
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
        self.resolve_txid_batch(txids, mode, &|| false)
    }

    /// [`Self::get_fk_by_txid_batch`] that asks `cancelled` before each sealed
    /// segment and each identity shot. One open probe, one sealed walk, one
    /// `create.loc` batch. A confirm lookup wave is up to 64k cold reads; a
    /// stop now waits for one segment rather than the wave.
    pub fn get_fk_by_txid_batch_cancellable(
        &self,
        txids: &[[u8; 32]],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
        self.resolve_txid_batch(txids, TxidResolveMode::TipOnly, cancelled)
    }

    fn resolve_txid_batch(
        &self,
        txids: &[[u8; 32]],
        mode: TxidResolveMode,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<crate::tx_table::TxidFkRange>, StoreError> {
        // Snapshot: leftover IO is 0.4–2s. Holding the fence read lock blocks
        // `height_fence_extend`. Confirm extends before `set_many`, so tip
        // cannot publish while this clone is in flight. Clone is Arc (COW on
        // the next extend if this snapshot is still live).
        let t_fence = std::time::Instant::now();
        let fence = self.fence().clone();
        crate::head_resolve_stats::add_probe(t_fence.elapsed().as_nanos() as u64);
        let tip_only = matches!(mode, TxidResolveMode::TipOnly);
        if cancelled() {
            return Err(StoreError::Cancelled("txid batch"));
        }
        crate::head_resolve_denserels::resolve_fk_and_range_batch_cancellable(
            &self.txs,
            txids,
            Some(&fence),
            tip_only,
            cancelled,
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

    /// Page-RMW annotate with structural-known meta.
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
                let (off, len) = self.txs.spent_range(create_tx_fk)?;
                self.txs.get_output_spender_metas_at(off, len, vouts)?
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
                });
                Ok(true)
            },
        )?;
        Ok(out)
    }

    /// Spender `(tx fk, vin)` pairs for a create outpoint (no `tx.head`; includes non-strong).
    pub fn spenders_create(
        &self,
        create_tx_fk: Fk,
        out_index: u32,
    ) -> Result<Vec<(Fk, u32)>, StoreError> {
        let mut out = Vec::new();
        point_table::for_each_spender_create(
            &self.txs,
            &self.spenders,
            create_tx_fk,
            out_index,
            |spending_tx_fk, vin| {
                out.push((spending_tx_fk, vin));
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

    #[doc(hidden)]
    pub fn repair_strong_not_on_fence(&self) -> Result<u64, StoreError> {
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
        let write = crate::array_table::ClassCWrite::new();
        for (lo, hi) in ranges {
            let ones = self.strong_tx.count_strong_in_fk_range(lo, hi)?;
            if ones == 0 {
                continue;
            }
            self.clear_class_c_run(&write, lo, hi)?;
            cleared = cleared.saturating_add(ones);
        }
        let ms = t0.elapsed().as_millis();
        rbitcoin_log::info!("rbitcoin: class_c repair cleared={cleared} ranges={n_ranges} ms={ms}");
        Ok(cleared)
    }

    /// Exclusive end fk of leftover 1s after `start_fk`, stopping at a 64 KiB
    /// all-zero bit page so slab padding is not rewritten.
    #[doc(hidden)]
    pub fn strong_suffix_end_fk(&self, start_fk: u64, n_bits: u64) -> Result<u64, StoreError> {
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

    #[doc(hidden)]
    pub fn clear_class_c_run(
        &self,
        write: &crate::array_table::ClassCWrite,
        start: u64,
        end: u64,
    ) -> Result<u64, StoreError> {
        if end <= start {
            return Ok(0);
        }
        let count = end - start;
        if count <= u64::from(u32::MAX) {
            self.strong_tx
                .set_unstrong_range(write, Fk(start), count as u32)?;
        } else {
            for id in start..end {
                self.strong_tx.set_unstrong(write, Fk(id))?;
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
    #[doc(hidden)]
    pub fn flush_class_c_pre_tip(&self) -> Result<(), StoreError> {
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
    /// After confirmed is durable, publish soft `crate::TIP_SEAL_NAME` so open
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
    #[doc(hidden)]
    pub fn store_spend_marker(
        &self,
        annotated: u32,
        durable: u32,
        gen: u64,
    ) -> Result<(), StoreError> {
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
        use crate::sync::atomic::Ordering;
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
        use crate::sync::atomic::Ordering;
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
            .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
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
            .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
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
        self.spend_through_checkpoint(height, |_| {})
    }

    /// Sample the disconnect generation, then the snapshot height, then sync.
    ///
    /// A disconnect between those two reads must not publish the height that
    /// was current before it, even when the replacement is annotated during
    /// the sync.
    pub fn checkpoint_observed_spend(&self) -> Result<(), StoreError> {
        self.observe_spend_checkpoint(|_| {}, |_| {})
    }

    #[doc(hidden)]
    pub fn observe_spend_checkpoint(
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

    /// Appends above `height` do not bump the disconnect generation, so a
    /// block connected in `between` still allows the snapshot to publish.
    /// A disconnect in `between` does not.
    #[doc(hidden)]
    pub fn spend_through_checkpoint(
        &self,
        height: u32,
        between: impl FnOnce(&Self),
    ) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        let gen = self.spend_reorg_gen.load(Ordering::Acquire);
        self.sync_spend_checkpoint(height, gen, between)
    }

    #[doc(hidden)]
    pub fn sync_spend_checkpoint(
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
        let Some(height) = self.spend_height_within_class_a(height)? else {
            return Ok(());
        };
        self.store_spend_marker(height, height, gen)
    }

    /// [`Self::checkpoint_observed_spend`] with hooks around the two reads
    /// and the sync.
    #[cfg(debug_assertions)]
    pub fn checkpoint_observed_spend_gap(
        &self,
        after_first_read: impl FnOnce(&Self),
        during_sync: impl FnOnce(&Self),
    ) -> Result<(), StoreError> {
        self.observe_spend_checkpoint(after_first_read, during_sync)
    }

    /// [`Self::checkpoint_spend_through`] with `between` invoked after
    /// `sync_data` and before the marker publish.
    #[cfg(debug_assertions)]
    pub fn checkpoint_spend_through_between(
        &self,
        height: u32,
        between: impl FnOnce(&Self),
    ) -> Result<(), StoreError> {
        self.spend_through_checkpoint(height, between)
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
            .try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
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

    /// The tip this call sealed. A withheld locator header skips the barrier
    /// and returns `Ok(None)`, so a caller cannot treat the RAM tip as sealed.
    pub fn flush_class_c_tip(&self) -> Result<Option<Height>, StoreError> {
        // A withheld locator header is not a commit. Skip the whole barrier
        // so header_txs is not left naming creates open will truncate.
        if !self.tip_fits_durable_creates()? {
            return Ok(None);
        }
        self.flush_class_c_pre_tip()?;
        // Commit point on disk: tip advance only after strong/header_txs.
        self.confirmed.flush()?;
        self.publish_tip_seal()?;
        Ok(self.confirmed.tip_height())
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

#[doc(hidden)]
pub fn write_meta(dir: &Path) -> Result<(), StoreError> {
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
#[doc(hidden)]
pub fn rewrite_meta_current(dir: &Path) -> Result<(), StoreError> {
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

#[doc(hidden)]
pub fn unlink_leftover_spent_off(dir: &Path) -> Result<(), StoreError> {
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

/// The tx table, with its append-only files on the cold dir when `layout` is
/// split; that dir is returned for `cold_path`.
fn open_layout_txs(layout: &StoreLayout) -> Result<(TxTable, Option<PathBuf>), StoreError> {
    let path = &layout.dir;
    let seqsigwit_dir = resolve_seqsigwit_dir(layout)?;
    if layout.is_split() {
        refuse_cold_index_dirs(path, &seqsigwit_dir)?;
    }
    let txs = TxTable::open_seqsigwit(path, &seqsigwit_dir, layout.open_opts())?;
    if layout.is_split() {
        write_seqsigwit_reloc(path)?;
    }
    Ok((txs, layout.is_split().then_some(seqsigwit_dir)))
}

/// An `--assumehot` source opens as it is: on the current schema, with the
/// tables a normal open would create already there.
fn refuse_unopenable_source(path: &Path, meta_ver: u16) -> Result<(), StoreError> {
    if meta_ver != SCHEMA_VERSION {
        return Err(StoreError::BadSchema(meta_ver));
    }
    for table in ["scripthash.body", "header_txs_first.body"] {
        if !path.join(table).exists() {
            return Err(StoreError::io(
                path.join(table),
                std::io::Error::from(std::io::ErrorKind::NotFound),
            ));
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn open_layout_refuse_old(path: &Path, meta_ver: u16) -> Result<(), StoreError> {
    if (24..=25).contains(&meta_ver) {
        HeaderTable::rewrite_v24_body_to_88(path)?;
    }
    unlink_leftover_spent_off(path)?;
    Ok(())
}

#[doc(hidden)]
pub fn drop_unread_store_leftovers(path: &Path) {
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

#[doc(hidden)]
pub fn drop_leftover_tx_height(path: &Path) {
    let leftover_h = path.join("tx_height.body");
    if leftover_h.exists() {
        eprintln!(
            "store: dropping leftover tx_height.body (schema 16 uses a RAM fence from header_txs)"
        );
        let _ = std::fs::remove_file(&leftover_h);
    }
}

#[doc(hidden)]
pub fn open_layout_rewrite_current(path: &Path, meta_ver: u16) -> Result<(), StoreError> {
    if meta_ver < SCHEMA_VERSION {
        rewrite_meta_current(path)?;
    }
    Ok(())
}

/// Validate store magic + schema. Returns on-disk version when openable.
#[doc(hidden)]
pub fn check_meta(dir: &Path) -> Result<u16, StoreError> {
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
pub const PRE22_WIPE: &str = "schema before 22 refuses this datadir; wipe datadir and redo IBD";
