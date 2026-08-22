//! Electrum scripthash history / balance / UTXO.
//!
//! Index rows are create_tx_fk only ([`ScriptHashRecord`]). Expand to
//! [`ScriptHashOutpoint`] by loading Class A outputs and matching SHA256(spk).
//! Spentness/heights from spends + Class C.

use super::*;
use rbitcoin_store::{output_flags, script_hash, spent_abs, IdxBodyMode};

/// Class A expand / spend-join wave. Bounds decoded `txout` pages in RAM.
const SH_JOIN_WAVE: usize = 4096;

fn sh_join_waves<T>(items: &[T], wave: usize) -> impl Iterator<Item = &[T]> {
    items.chunks(wave.max(1))
}

/// Expanded Electrum create outpoint (Class A + height joins).
///
/// Store index only holds [`ScriptHashRecord`] (scripthash + create_tx_fk).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptHashOutpoint {
    pub scripthash: [u8; 32],
    pub create_tx_fk: rbitcoin_primitives::Fk,
    pub vout: u32,
    pub txid: [u8; 32],
    pub value: i64,
    pub create_height: u32,
}

/// Electrum `blockchain.scripthash.get_history` row (confirmed only in v1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptHashHistoryItem {
    pub height: i64,
    pub txid: [u8; 32],
    /// Class A create fk when known (confirmed SH join). `NULL` for mempool-only rows.
    pub tx_fk: rbitcoin_primitives::Fk,
}

/// Sort order for [`apply_history_filter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HistoryOrder {
    /// Electrum: ascending height.
    #[default]
    HeightAsc,
    /// Esplora chain pages: newest first (height desc, then txid desc for stability).
    NewestFirst,
}

/// Immutable filter for history lists (Electrum windows + Esplora paging).
///
/// Height window: confirmed rows with `height ∈ [from_height, to_height)` when
/// `to_height` is `Some`. `to_height: None` means no upper bound. Callers that
/// need BCH `to_height=-1` (include mempool) handle mempool separately and pass
/// `to_height: None` for the confirmed slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryFilter {
    /// Inclusive lower bound on `item.height` (default 0).
    pub from_height: u32,
    /// Exclusive upper bound on `item.height`, or open.
    pub to_height: Option<i64>,
    /// Max items after window / cursor (Esplora uses 25).
    pub limit: Option<usize>,
    /// Esplora `last_seen_txid`: after sort, drop through this txid (inclusive), keep following.
    pub after_txid: Option<[u8; 32]>,
    pub order: HistoryOrder,
}

impl Default for HistoryFilter {
    fn default() -> Self {
        Self {
            from_height: 0,
            to_height: None,
            limit: None,
            after_txid: None,
            order: HistoryOrder::HeightAsc,
        }
    }
}

impl HistoryFilter {
    pub fn open() -> Self {
        Self::default()
    }

    /// Electrum Cash-style window (`to_height` exclusive; `None` = open).
    pub fn height_window(from_height: u32, to_height: Option<i64>) -> Self {
        Self {
            from_height,
            to_height,
            limit: None,
            after_txid: None,
            order: HistoryOrder::HeightAsc,
        }
    }

    /// Esplora confirmed chain page (newest first, 25, optional cursor).
    pub fn esplora_chain_page(after_txid: Option<[u8; 32]>) -> Self {
        Self {
            from_height: 0,
            to_height: None,
            limit: Some(25),
            after_txid,
            order: HistoryOrder::NewestFirst,
        }
    }
}

/// Apply [`HistoryFilter`] to an already-built history list (no store I/O).
///
/// Does not re-sort input beyond the filter's [`HistoryOrder`]. Window is applied
/// first, then order, then `after_txid`, then `limit`.
pub fn apply_history_filter(
    items: &[ScriptHashHistoryItem],
    filter: &HistoryFilter,
) -> Vec<ScriptHashHistoryItem> {
    let from = i64::from(filter.from_height);
    let mut out: Vec<ScriptHashHistoryItem> = items
        .iter()
        .filter(|i| {
            if i.height < from {
                return false;
            }
            if let Some(to) = filter.to_height {
                if i.height >= to {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    match filter.order {
        HistoryOrder::HeightAsc => {
            out.sort_by(|a, b| a.height.cmp(&b.height).then_with(|| a.txid.cmp(&b.txid)));
        }
        HistoryOrder::NewestFirst => {
            out.sort_by(|a, b| b.height.cmp(&a.height).then_with(|| b.txid.cmp(&a.txid)));
        }
    }

    if let Some(after) = filter.after_txid {
        if let Some(pos) = out.iter().position(|i| i.txid == after) {
            out = out.split_off(pos.saturating_add(1));
        }
        // If after_txid not found, Esplora-like behavior: return from start (no skip).
    }

    if let Some(lim) = filter.limit {
        if out.len() > lim {
            out.truncate(lim);
        }
    }
    out
}

fn history_items_from_joined(
    joined: &[ShJoinedOut],
    filter: &HistoryFilter,
) -> Vec<ScriptHashHistoryItem> {
    let mut by_txid: BTreeMap<[u8; 32], (i64, Fk)> = BTreeMap::new();
    let to_excl = filter.to_height;
    for rec in joined {
        if let Some(to) = to_excl {
            if i64::from(rec.out.create_height) >= to {
                continue;
            }
        }
        let ch = i64::from(rec.out.create_height);
        by_txid
            .entry(rec.out.txid)
            .and_modify(|(h, fk)| {
                if ch < *h {
                    *h = ch;
                    *fk = rec.out.create_tx_fk;
                }
            })
            .or_insert((ch, rec.out.create_tx_fk));
        for sp in &rec.spenders {
            if let Some(to) = to_excl {
                if i64::from(sp.height) >= to {
                    continue;
                }
            }
            let sh = i64::from(sp.height);
            by_txid
                .entry(sp.txid)
                .and_modify(|(h, fk)| {
                    if sh < *h {
                        *h = sh;
                        *fk = sp.fk;
                    }
                })
                .or_insert((sh, sp.fk));
        }
    }
    let items: Vec<ScriptHashHistoryItem> = by_txid
        .into_iter()
        .map(|(txid, (height, tx_fk))| ScriptHashHistoryItem {
            height,
            txid,
            tx_fk,
        })
        .collect();
    apply_history_filter(&items, filter)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptHashBalance {
    pub confirmed: i64,
    pub unconfirmed: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptHashUtxo {
    pub tx_hash: [u8; 32],
    pub tx_pos: u32,
    pub height: u32,
    pub value: i64,
    pub create_tx_fk: rbitcoin_primitives::Fk,
}

/// One confirmed unspent from [`Query::scan_unspent_scripts`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanUtxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub height: u32,
    pub value: u64,
    pub script: Vec<u8>,
    pub coinbase: bool,
}

/// Esplora-style confirmed chain stats for a scripthash.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ScriptHashChainStats {
    pub tx_count: u32,
    pub funded_txo_count: u32,
    pub funded_txo_sum: i64,
    pub spent_txo_count: u32,
    pub spent_txo_sum: i64,
}

pub(crate) struct ShSpender {
    fk: Fk,
    txid: [u8; 32],
    height: u32,
}

pub(crate) struct ShJoinedOut {
    pub(crate) out: ScriptHashOutpoint,
    pub(crate) spent: bool,
    pub(crate) spender_fks: Vec<Fk>,
    pub(crate) spenders: Vec<ShSpender>,
}

/// Last scripthash expand+spend join for one Electrum connection.
///
/// Holds BALANCE-level outs + spentness. Identity is filled in place on
/// history / listunspent. Invalid once the published tip **hash** moves
/// (including a same-height replace).
pub struct ShJoinSlot {
    scripthash: [u8; 32],
    tip_hash: [u8; 32],
    joined: Vec<ShJoinedOut>,
}

/// Which identity sidefiles this SH join must fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShJoinNeed {
    create_identity: bool,
    spender_identity: bool,
}

impl ShJoinNeed {
    pub(crate) const HISTORY: Self = Self {
        create_identity: true,
        spender_identity: true,
    };
    pub(crate) const LISTUNSPENT: Self = Self {
        create_identity: false,
        spender_identity: false,
    };
    pub(crate) const BALANCE: Self = Self {
        create_identity: false,
        spender_identity: false,
    };
    pub(crate) const CHAIN_STATS: Self = Self::BALANCE;
}

impl std::fmt::Display for ShJoinNeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.create_identity, self.spender_identity) {
            (true, true) => f.write_str("cs"),
            (true, false) => f.write_str("c"),
            (false, true) => f.write_str("s"),
            (false, false) => f.write_str("-"),
        }
    }
}

impl Query {
    /// Expand confirmed-strong create fks in one idx→body wave (`load_creates_once`).
    fn expand_create_fks_wave(
        &self,
        scripthash: &[u8; 32],
        fks: &[Fk],
        need: ShJoinNeed,
    ) -> Result<Vec<ScriptHashOutpoint>, QueryError> {
        if fks.is_empty() {
            return Ok(Vec::new());
        }
        let loaded = super::load_creates_once(&self.store, fks, IdxBodyMode::Outs)?;
        if loaded.len() != fks.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH create body missing after load",
            ));
        }
        let txids = if need.create_identity {
            self.store.txids_get_many(fks)?
        } else {
            Vec::new()
        };
        let heights = self.store.tx_height_get_batch(fks)?;
        if need.create_identity && txids.len() != fks.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH create identity batch length",
            ));
        }
        if heights.len() != fks.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH create height batch length",
            ));
        }
        let mut out = Vec::new();
        for (i, create) in loaded.iter().enumerate() {
            if create.fk != fks[i] {
                return Err(StoreError::Corrupt(
                    "invariant: SH create load order mismatch",
                ));
            }
            let Some((_tx, outs, _rels)) = &create.decoded_outs else {
                return Err(StoreError::Corrupt(
                    "invariant: SH create missing decoded outs",
                ));
            };
            let txid = if need.create_identity {
                let Some(txid) = txids[i] else {
                    return Err(StoreError::Corrupt(
                        "invariant: SH create missing txid.body",
                    ));
                };
                txid
            } else {
                [0u8; 32]
            };
            let height = heights[i].unwrap_or(0);
            for (vout, o) in outs.iter().enumerate() {
                if script_hash(&o.script) != *scripthash {
                    continue;
                }
                out.push(ScriptHashOutpoint {
                    scripthash: *scripthash,
                    create_tx_fk: create.fk,
                    vout: vout as u32,
                    txid,
                    value: o.value,
                    create_height: height,
                });
            }
        }
        Ok(out)
    }

    fn join_out_spent(&self, rec: &ShJoinedOut) -> Result<bool, QueryError> {
        if self.spend_index_enabled() {
            Ok(rec.spent)
        } else {
            self.is_outpoint_spent(&rec.out.txid, rec.out.vout)
        }
    }

    fn confirmed_strong_in(&self, fk: Fk, view: &ChainView) -> Result<bool, QueryError> {
        self.store.is_confirmed_strong_at(fk, Some(view.height.0))
    }

    /// Confirmed-strong create outpoints plus confirmed spenders (create_fk join).
    ///
    /// When `to_height` is set, creates with Class C height `>= to_height` are not
    /// expanded (their spends cannot fall in the window). Visibility is
    /// [`Store::is_confirmed_strong_at`] against `view.height`.
    pub(crate) fn join_creates_and_spends(
        &self,
        scripthash: &[u8; 32],
        need: ShJoinNeed,
        to_height: Option<i64>,
        view: &ChainView,
    ) -> Result<Vec<ShJoinedOut>, QueryError> {
        let t_pages = std::time::Instant::now();
        let entries = self.store.scripthash.create_fks(scripthash)?;
        let pages_us = t_pages.elapsed().as_micros();
        let mut fks = Vec::new();
        for fk in entries {
            if self.confirmed_strong_in(fk, view)? {
                fks.push(fk);
            }
        }
        if let Some(to) = to_height {
            let heights = self.store.tx_height_get_batch(&fks)?;
            if heights.len() != fks.len() {
                return Err(StoreError::Corrupt(
                    "invariant: SH create height batch length",
                ));
            }
            fks = fks
                .into_iter()
                .zip(heights)
                .filter_map(|(fk, h)| {
                    if i64::from(h.unwrap_or(0)) >= to {
                        None
                    } else {
                        Some(fk)
                    }
                })
                .collect();
        }
        let mut out = Vec::new();
        let mut class_a_us = 0u128;
        let mut spends_us = 0u128;
        for wave in sh_join_waves(&fks, SH_JOIN_WAVE) {
            let t_a = std::time::Instant::now();
            let creates = self.expand_create_fks_wave(scripthash, wave, need)?;
            class_a_us = class_a_us.saturating_add(t_a.elapsed().as_micros());
            let t_s = std::time::Instant::now();
            out.extend(self.join_spends_wave(&creates, need, view)?);
            spends_us = spends_us.saturating_add(t_s.elapsed().as_micros());
        }
        let total_us = pages_us
            .saturating_add(class_a_us)
            .saturating_add(spends_us);
        if total_us >= 10_000 {
            rbitcoin_log::trace!(
                "sh_join: creates={} outs={} need={} pages_us={} class_a_us={} spends_us={}",
                fks.len(),
                out.len(),
                need,
                pages_us,
                class_a_us,
                spends_us
            );
        }
        Ok(out)
    }

    fn sh_join_slot_hit(slot: &ShJoinSlot, scripthash: &[u8; 32], view: &ChainView) -> bool {
        slot.scripthash == *scripthash && slot.tip_hash == view.hash
    }

    fn ensure_sh_join_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<ShJoinSlot>,
    ) -> Result<(), QueryError> {
        let Some(view) = self.pin_chain_view()? else {
            *slot = None;
            return Ok(());
        };
        self.ensure_sh_join_slot_in(scripthash, slot, &view)
    }

    fn ensure_sh_join_slot_in(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<ShJoinSlot>,
        view: &ChainView,
    ) -> Result<(), QueryError> {
        if slot
            .as_ref()
            .is_some_and(|s| Self::sh_join_slot_hit(s, scripthash, view))
        {
            return Ok(());
        }
        let joined = self.join_creates_and_spends(scripthash, ShJoinNeed::BALANCE, None, view)?;
        *slot = Some(ShJoinSlot {
            scripthash: *scripthash,
            tip_hash: view.hash,
            joined,
        });
        Ok(())
    }

    fn enrich_joined(&self, recs: &mut [ShJoinedOut], need: ShJoinNeed) -> Result<(), QueryError> {
        if need.create_identity {
            self.fill_create_txids(recs, false)?;
        }
        if need.spender_identity {
            self.fill_spender_identity(recs)?;
        }
        Ok(())
    }

    fn fill_spender_identity(&self, recs: &mut [ShJoinedOut]) -> Result<(), QueryError> {
        let mut fks = Vec::new();
        let mut seen = HashSet::new();
        for rec in recs.iter() {
            if rec.spender_fks.is_empty() || !rec.spenders.is_empty() {
                continue;
            }
            for fk in &rec.spender_fks {
                if seen.insert(*fk) {
                    fks.push(*fk);
                }
            }
        }
        if fks.is_empty() {
            return Ok(());
        }
        let txids = self.store.txids_get_many(&fks)?;
        let heights = self.store.tx_height_get_batch(&fks)?;
        if txids.len() != fks.len() || heights.len() != fks.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH spender identity/height batch length",
            ));
        }
        let mut id_by_fk = HashMap::new();
        for (i, fk) in fks.iter().enumerate() {
            let Some(txid) = txids[i] else {
                return Err(StoreError::Corrupt(
                    "invariant: SH spender missing txid.body",
                ));
            };
            id_by_fk.insert(*fk, (txid, heights[i].unwrap_or(0)));
        }
        for rec in recs.iter_mut() {
            if rec.spender_fks.is_empty() || !rec.spenders.is_empty() {
                continue;
            }
            let mut spenders = Vec::with_capacity(rec.spender_fks.len());
            for fk in &rec.spender_fks {
                let Some((txid, height)) = id_by_fk.get(fk).copied() else {
                    return Err(StoreError::Corrupt("invariant: SH spender identity miss"));
                };
                spenders.push(ShSpender {
                    fk: *fk,
                    txid,
                    height,
                });
            }
            rec.spenders = spenders;
        }
        Ok(())
    }

    fn balance_from_joined(&self, recs: &[ShJoinedOut]) -> Result<ScriptHashBalance, QueryError> {
        let mut confirmed = 0i64;
        for rec in recs {
            if !self.join_out_spent(rec)? {
                confirmed = confirmed.saturating_add(rec.out.value);
            }
        }
        Ok(ScriptHashBalance {
            confirmed,
            unconfirmed: 0,
        })
    }

    fn listunspent_from_joined(
        &self,
        recs: &[ShJoinedOut],
    ) -> Result<Vec<ScriptHashUtxo>, QueryError> {
        let mut out = Vec::new();
        for rec in recs {
            if self.join_out_spent(rec)? {
                continue;
            }
            out.push(ScriptHashUtxo {
                tx_hash: rec.out.txid,
                tx_pos: rec.out.vout,
                height: rec.out.create_height,
                value: rec.out.value,
                create_tx_fk: rec.out.create_tx_fk,
            });
        }
        out.sort_by(|a, b| a.height.cmp(&b.height).then(a.tx_pos.cmp(&b.tx_pos)));
        Ok(out)
    }

    fn chain_stats_from_joined(
        &self,
        recs: &[ShJoinedOut],
    ) -> Result<ScriptHashChainStats, QueryError> {
        let mut funded_n = 0u32;
        let mut funded_sum = 0i64;
        let mut spent_n = 0u32;
        let mut spent_sum = 0i64;
        let mut txs: HashSet<Fk> = HashSet::new();
        for rec in recs {
            funded_n = funded_n.saturating_add(1);
            funded_sum = funded_sum.saturating_add(rec.out.value);
            txs.insert(rec.out.create_tx_fk);
            if self.join_out_spent(rec)? {
                spent_n = spent_n.saturating_add(1);
                spent_sum = spent_sum.saturating_add(rec.out.value);
                for fk in &rec.spender_fks {
                    txs.insert(*fk);
                }
            }
        }
        Ok(ScriptHashChainStats {
            tx_count: txs.len() as u32,
            funded_txo_count: funded_n,
            funded_txo_sum: funded_sum,
            spent_txo_count: spent_n,
            spent_txo_sum: spent_sum,
        })
    }

    fn join_spends_wave(
        &self,
        creates: &[ScriptHashOutpoint],
        need: ShJoinNeed,
        view: &ChainView,
    ) -> Result<Vec<ShJoinedOut>, QueryError> {
        if creates.is_empty() {
            return Ok(Vec::new());
        }
        if !self.spend_index_enabled() {
            return Ok(creates
                .iter()
                .cloned()
                .map(|out| ShJoinedOut {
                    out,
                    spent: false,
                    spender_fks: Vec::new(),
                    spenders: Vec::new(),
                })
                .collect());
        }
        let mut uniq = Vec::new();
        let mut seen = HashSet::new();
        for c in creates {
            if seen.insert(c.create_tx_fk) {
                uniq.push(c.create_tx_fk);
            }
        }
        let ranges = self.store.tx_spent_range_batch(&uniq)?;
        let mut range_by_fk = HashMap::new();
        for (fk, range) in uniq.iter().zip(ranges.into_iter()) {
            if let Some(range) = range {
                range_by_fk.insert(*fk, range);
            }
        }
        let mut abs_offs = Vec::with_capacity(creates.len());
        let mut abs_at = vec![None; creates.len()];
        for (i, c) in creates.iter().enumerate() {
            let Some((off, _)) = range_by_fk.get(&c.create_tx_fk) else {
                continue;
            };
            abs_at[i] = Some(abs_offs.len());
            abs_offs.push(spent_abs(*off, c.vout));
        }
        let metas = self.store.get_spender_meta_at_abs_batch(&abs_offs)?;
        let mut spender_fks = Vec::new();
        let mut per_out: Vec<Vec<Fk>> = vec![Vec::new(); creates.len()];
        for (i, c) in creates.iter().enumerate() {
            let Some(mi) = abs_at[i] else {
                continue;
            };
            let Some((field, flags)) = metas.get(mi).copied().flatten() else {
                continue;
            };
            if field.is_null() {
                continue;
            }
            if flags & output_flags::MULTI_SPENDER != 0 {
                for fk in self.store.spenders_create(c.create_tx_fk, c.vout)? {
                    if self.confirmed_strong_in(fk, view)? {
                        per_out[i].push(fk);
                        spender_fks.push(fk);
                    }
                }
            } else if self.confirmed_strong_in(field, view)? {
                per_out[i].push(field);
                spender_fks.push(field);
            }
        }
        let mut id_by_fk = HashMap::new();
        if need.spender_identity && !spender_fks.is_empty() {
            let txids = self.store.txids_get_many(&spender_fks)?;
            let heights = self.store.tx_height_get_batch(&spender_fks)?;
            if txids.len() != spender_fks.len() || heights.len() != spender_fks.len() {
                return Err(StoreError::Corrupt(
                    "invariant: SH spender identity/height batch length",
                ));
            }
            for (i, fk) in spender_fks.iter().enumerate() {
                let Some(txid) = txids[i] else {
                    return Err(StoreError::Corrupt(
                        "invariant: SH spender missing txid.body",
                    ));
                };
                id_by_fk.insert(*fk, (txid, heights[i].unwrap_or(0)));
            }
        }
        let mut out = Vec::with_capacity(creates.len());
        for (i, c) in creates.iter().enumerate() {
            let spent = !per_out[i].is_empty();
            let mut spenders = Vec::new();
            if need.spender_identity {
                for fk in &per_out[i] {
                    let Some((txid, height)) = id_by_fk.get(fk).copied() else {
                        return Err(StoreError::Corrupt("invariant: SH spender identity miss"));
                    };
                    spenders.push(ShSpender {
                        fk: *fk,
                        txid,
                        height,
                    });
                }
            }
            out.push(ShJoinedOut {
                out: c.clone(),
                spent,
                spender_fks: per_out[i].clone(),
                spenders,
            });
        }
        Ok(out)
    }

    /// Confirmed Electrum-style history for a scripthash: (height, txid) pairs.
    ///
    /// Equivalent to [`Self::scripthash_history_filtered`] with [`HistoryFilter::open`].
    pub fn scripthash_history(
        &self,
        scripthash: &[u8; 32],
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        self.scripthash_history_filtered(scripthash, &HistoryFilter::open())
    }

    /// Confirmed history for `scripthash` as of `view` (open filter).
    pub fn scripthash_history_in(
        &self,
        scripthash: &[u8; 32],
        view: &ChainView,
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        self.scripthash_history_filtered_in(scripthash, &HistoryFilter::open(), view)
    }

    /// Confirmed history for a scripthash, filtered by height window / limit / cursor.
    ///
    /// Assembles the full confirmed history (creates + confirmed spenders), then
    /// applies [`apply_history_filter`]. When `filter.to_height` is set, create
    /// outpoints with `create_height >= to_height` are skipped during expand
    /// (spends of those creates are also ≥ create height, so they cannot fall
    /// inside the window). Pins the live tip.
    pub fn scripthash_history_filtered(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        let Some(view) = self.pin_chain_view()? else {
            return Ok(Vec::new());
        };
        self.scripthash_history_filtered_in(scripthash, filter, &view)
    }

    pub fn scripthash_history_filtered_in(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        view: &ChainView,
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        let joined =
            self.join_creates_and_spends(scripthash, ShJoinNeed::HISTORY, filter.to_height, view)?;
        Ok(history_items_from_joined(&joined, filter))
    }

    /// Confirmed history using a connection-local join slot when `to_height` is open
    /// or the slot already holds this scripthash at the current tip.
    pub fn scripthash_history_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<ShJoinSlot>,
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        self.scripthash_history_filtered_slot(scripthash, &HistoryFilter::open(), slot)
    }

    /// Slot-aware [`Self::scripthash_history_filtered`].
    pub fn scripthash_history_filtered_slot(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        slot: &mut Option<ShJoinSlot>,
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        let Some(view) = self.pin_chain_view()? else {
            *slot = None;
            return Ok(Vec::new());
        };
        let hit = slot
            .as_ref()
            .is_some_and(|s| Self::sh_join_slot_hit(s, scripthash, &view));
        if !hit && filter.to_height.is_some() {
            return self.scripthash_history_filtered_in(scripthash, filter, &view);
        }
        self.ensure_sh_join_slot_in(scripthash, slot, &view)?;
        let recs = &mut slot
            .as_mut()
            .ok_or(StoreError::Corrupt("invariant: SH join slot missing"))?
            .joined;
        self.enrich_joined(recs, ShJoinNeed::HISTORY)?;
        Ok(history_items_from_joined(recs, filter))
    }

    /// Confirmed txs in `height` that create or spend a posting-list out for `scripthash`.
    ///
    /// Intersects the SH posting list with the block's tx fks and input
    /// `create_fk`s. Does not expand packed `txout`.
    pub fn scripthash_tx_fks_at_height(
        &self,
        scripthash: &[u8; 32],
        height: Height,
    ) -> Result<Vec<Fk>, QueryError> {
        let entries = self.store.scripthash.create_fks(scripthash)?;
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let mut posting: Vec<u64> = entries.iter().filter_map(|fk| fk.get()).collect();
        posting.sort_unstable();
        posting.dedup();
        let block_fks = self.block_tx_fks(height)?;
        let mut out = Vec::new();
        for fk in &block_fks {
            let mut hit = false;
            if let Some(id) = fk.get() {
                if posting.binary_search(&id).is_ok() {
                    hit = true;
                }
            }
            if !hit {
                let (_, prevs) = self.store.get_tx_meta_and_prevouts(*fk)?;
                for (create_fk, _) in prevs {
                    if let Some(id) = create_fk.get() {
                        if posting.binary_search(&id).is_ok() {
                            hit = true;
                            break;
                        }
                    }
                }
            }
            if hit {
                out.push(*fk);
            }
        }
        Ok(out)
    }

    /// True when [`Self::scripthash_tx_fks_at_height`] is non-empty.
    pub fn scripthash_touched_at_height(
        &self,
        scripthash: &[u8; 32],
        height: Height,
    ) -> Result<bool, QueryError> {
        Ok(!self
            .scripthash_tx_fks_at_height(scripthash, height)?
            .is_empty())
    }

    /// Confirmed balance for a scripthash.
    pub fn scripthash_balance(
        &self,
        scripthash: &[u8; 32],
    ) -> Result<ScriptHashBalance, QueryError> {
        let Some(view) = self.pin_chain_view()? else {
            return Ok(ScriptHashBalance {
                confirmed: 0,
                unconfirmed: 0,
            });
        };
        self.scripthash_balance_in(scripthash, &view)
    }

    /// Confirmed balance as of `view`.
    pub fn scripthash_balance_in(
        &self,
        scripthash: &[u8; 32],
        view: &ChainView,
    ) -> Result<ScriptHashBalance, QueryError> {
        let joined = self.join_creates_and_spends(scripthash, ShJoinNeed::BALANCE, None, view)?;
        self.balance_from_joined(&joined)
    }

    /// Slot-aware [`Self::scripthash_balance`].
    pub fn scripthash_balance_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<ShJoinSlot>,
    ) -> Result<ScriptHashBalance, QueryError> {
        self.ensure_sh_join_slot(scripthash, slot)?;
        let Some(recs) = slot.as_ref() else {
            return Ok(ScriptHashBalance {
                confirmed: 0,
                unconfirmed: 0,
            });
        };
        self.balance_from_joined(&recs.joined)
    }

    fn fill_create_txids(
        &self,
        recs: &mut [ShJoinedOut],
        unspent_only: bool,
    ) -> Result<(), QueryError> {
        let mut fks = Vec::new();
        let mut seen = HashSet::new();
        for rec in recs.iter() {
            if unspent_only && rec.spent {
                continue;
            }
            if rec.out.txid != [0u8; 32] {
                continue;
            }
            if seen.insert(rec.out.create_tx_fk) {
                fks.push(rec.out.create_tx_fk);
            }
        }
        if fks.is_empty() {
            return Ok(());
        }
        let txids = self.store.txids_get_many(&fks)?;
        if txids.len() != fks.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH unspent identity batch length",
            ));
        }
        let mut by_fk = HashMap::new();
        for (fk, txid) in fks.iter().zip(txids.into_iter()) {
            let Some(txid) = txid else {
                return Err(StoreError::Corrupt(
                    "invariant: SH create missing txid.body",
                ));
            };
            by_fk.insert(*fk, txid);
        }
        for rec in recs.iter_mut() {
            if unspent_only && rec.spent {
                continue;
            }
            if rec.out.txid != [0u8; 32] {
                continue;
            }
            let Some(txid) = by_fk.get(&rec.out.create_tx_fk).copied() else {
                return Err(StoreError::Corrupt("invariant: SH create identity miss"));
            };
            rec.out.txid = txid;
        }
        Ok(())
    }

    /// Confirmed UTXOs for a scripthash.
    pub fn scripthash_listunspent(
        &self,
        scripthash: &[u8; 32],
    ) -> Result<Vec<ScriptHashUtxo>, QueryError> {
        let Some(view) = self.pin_chain_view()? else {
            return Ok(Vec::new());
        };
        self.scripthash_listunspent_in(scripthash, &view)
    }

    /// Confirmed UTXOs as of `view`.
    pub fn scripthash_listunspent_in(
        &self,
        scripthash: &[u8; 32],
        view: &ChainView,
    ) -> Result<Vec<ScriptHashUtxo>, QueryError> {
        let mut joined =
            self.join_creates_and_spends(scripthash, ShJoinNeed::LISTUNSPENT, None, view)?;
        self.fill_create_txids(&mut joined, true)?;
        self.listunspent_from_joined(&joined)
    }

    /// Slot-aware [`Self::scripthash_listunspent`].
    pub fn scripthash_listunspent_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<ShJoinSlot>,
    ) -> Result<Vec<ScriptHashUtxo>, QueryError> {
        self.ensure_sh_join_slot(scripthash, slot)?;
        let Some(recs) = slot.as_mut() else {
            return Ok(Vec::new());
        };
        self.fill_create_txids(&mut recs.joined, true)?;
        self.listunspent_from_joined(&recs.joined)
    }

    /// Confirmed unspents whose `scriptPubKey` is in `scripts`.
    ///
    /// With `--shindex`, this is [`Self::scripthash_listunspent`]. Without, it
    /// walks Class A `txout` + spentness per confirmed height — never
    /// [`Self::reconstruct_block_at_height`].
    pub fn scan_unspent_scripts(&self, scripts: &[Vec<u8>]) -> Result<Vec<ScanUtxo>, QueryError> {
        if self.sh_index_enabled() {
            self.scan_unspent_via_shindex(scripts)
        } else {
            self.scan_unspent_via_txout(scripts)
        }
    }

    fn scan_unspent_via_shindex(&self, scripts: &[Vec<u8>]) -> Result<Vec<ScanUtxo>, QueryError> {
        let mut out = Vec::new();
        for spk in scripts {
            let sh = script_hash(spk);
            for u in self.scripthash_listunspent(&sh)? {
                let coinbase = {
                    let fks = self.block_tx_fks(Height(u.height))?;
                    fks.first().copied() == Some(u.create_tx_fk)
                };
                if u.value < 0 {
                    continue;
                }
                out.push(ScanUtxo {
                    txid: u.tx_hash,
                    vout: u.tx_pos,
                    height: u.height,
                    value: u.value as u64,
                    script: spk.clone(),
                    coinbase,
                });
            }
        }
        Ok(out)
    }

    fn scan_unspent_via_txout(&self, scripts: &[Vec<u8>]) -> Result<Vec<ScanUtxo>, QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for h in 0..=tip.0 {
            let fks = self.block_tx_fks(Height(h))?;
            for (ti, fk) in fks.into_iter().enumerate() {
                let (tx, _ins, outs) = self.store.get_tx_full(fk)?;
                let coinbase = ti == 0;
                for (vout, o) in outs.iter().enumerate() {
                    if !scripts.iter().any(|s| s.as_slice() == o.script.as_slice()) {
                        continue;
                    }
                    if self.is_outpoint_spent(&tx.txid, vout as u32)? {
                        continue;
                    }
                    if o.value < 0 {
                        continue;
                    }
                    out.push(ScanUtxo {
                        txid: tx.txid,
                        vout: vout as u32,
                        height: h,
                        value: o.value as u64,
                        script: o.script.clone(),
                        coinbase,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Confirmed chain_stats for Esplora address/scripthash routes.
    ///
    /// One expand+spend join (same walk as history / balance / listunspent).
    pub fn scripthash_chain_stats(
        &self,
        scripthash: &[u8; 32],
    ) -> Result<ScriptHashChainStats, QueryError> {
        let Some(view) = self.pin_chain_view()? else {
            return Ok(ScriptHashChainStats {
                tx_count: 0,
                funded_txo_count: 0,
                funded_txo_sum: 0,
                spent_txo_count: 0,
                spent_txo_sum: 0,
            });
        };
        self.scripthash_chain_stats_in(scripthash, &view)
    }

    /// Confirmed chain_stats as of `view`.
    pub fn scripthash_chain_stats_in(
        &self,
        scripthash: &[u8; 32],
        view: &ChainView,
    ) -> Result<ScriptHashChainStats, QueryError> {
        let joined =
            self.join_creates_and_spends(scripthash, ShJoinNeed::CHAIN_STATS, None, view)?;
        self.chain_stats_from_joined(&joined)
    }

    /// Slot-aware [`Self::scripthash_chain_stats`].
    pub fn scripthash_chain_stats_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<ShJoinSlot>,
    ) -> Result<ScriptHashChainStats, QueryError> {
        self.ensure_sh_join_slot(scripthash, slot)?;
        let Some(recs) = slot.as_ref() else {
            return Ok(ScriptHashChainStats {
                tx_count: 0,
                funded_txo_count: 0,
                funded_txo_sum: 0,
                spent_txo_count: 0,
                spent_txo_sum: 0,
            });
        };
        self.chain_stats_from_joined(&recs.joined)
    }
}

#[cfg(test)]
mod history_filter_tests {
    use super::*;

    #[test]
    fn sh_join_waves_splits_on_wave() {
        let v = [1u8, 2, 3, 4, 5];
        let got: Vec<&[u8]> = sh_join_waves(&v, 2).collect();
        assert_eq!(got, vec![&[1, 2][..], &[3, 4][..], &[5][..]]);
        assert!(sh_join_waves(&v, 0).next().is_some());
    }

    #[test]
    fn sh_join_need_display() {
        assert_eq!(ShJoinNeed::HISTORY.to_string(), "cs");
        assert_eq!(ShJoinNeed::LISTUNSPENT.to_string(), "-");
        assert_eq!(ShJoinNeed::BALANCE.to_string(), "-");
        assert_eq!(ShJoinNeed::CHAIN_STATS.to_string(), "-");
    }

    fn item(height: i64, txid0: u8) -> ScriptHashHistoryItem {
        let mut txid = [0u8; 32];
        txid[0] = txid0;
        ScriptHashHistoryItem {
            height,
            txid,
            tx_fk: Fk::NULL,
        }
    }

    #[test]
    fn open_filter_keeps_all_height_asc() {
        let items = vec![item(10, 1), item(5, 2), item(20, 3)];
        let got = apply_history_filter(&items, &HistoryFilter::open());
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].height, 5);
        assert_eq!(got[1].height, 10);
        assert_eq!(got[2].height, 20);
    }

    #[test]
    fn height_window_inclusive_from_exclusive_to() {
        let items = vec![item(1, 1), item(5, 2), item(10, 3), item(15, 4)];
        let f = HistoryFilter::height_window(5, Some(15));
        let got = apply_history_filter(&items, &f);
        assert_eq!(
            got.iter().map(|i| i.height).collect::<Vec<_>>(),
            vec![5, 10]
        );
    }

    #[test]
    fn height_window_open_upper() {
        let items = vec![item(1, 1), item(100, 2)];
        let f = HistoryFilter::height_window(50, None);
        let got = apply_history_filter(&items, &f);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].height, 100);
    }

    #[test]
    fn newest_first_order() {
        let items = vec![item(1, 1), item(3, 2), item(2, 3)];
        let mut f = HistoryFilter::open();
        f.order = HistoryOrder::NewestFirst;
        let got = apply_history_filter(&items, &f);
        assert_eq!(
            got.iter().map(|i| i.height).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
    }

    #[test]
    fn after_txid_skips_through_cursor_then_limit() {
        // Newest first: h=30,20,10 with distinct txids
        let items = vec![item(10, 1), item(20, 2), item(30, 3)];
        let mut after = [0u8; 32];
        after[0] = 3; // tip (height 30)
        let f = HistoryFilter {
            from_height: 0,
            to_height: None,
            limit: Some(1),
            after_txid: Some(after),
            order: HistoryOrder::NewestFirst,
        };
        let got = apply_history_filter(&items, &f);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].height, 20);
        assert_eq!(got[0].txid[0], 2);
    }

    #[test]
    fn after_txid_unknown_does_not_skip() {
        let items = vec![item(10, 1), item(20, 2)];
        let f = HistoryFilter {
            from_height: 0,
            to_height: None,
            limit: Some(1),
            after_txid: Some([0xff; 32]),
            order: HistoryOrder::NewestFirst,
        };
        let got = apply_history_filter(&items, &f);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].height, 20);
    }

    #[test]
    fn esplora_chain_page_defaults() {
        let f = HistoryFilter::esplora_chain_page(None);
        assert_eq!(f.limit, Some(25));
        assert_eq!(f.order, HistoryOrder::NewestFirst);
        assert!(f.after_txid.is_none());
    }

    #[test]
    fn limit_truncates_after_window() {
        let items: Vec<_> = (1..=10).map(|h| item(h, h as u8)).collect();
        let f = HistoryFilter {
            from_height: 0,
            to_height: None,
            limit: Some(3),
            after_txid: None,
            order: HistoryOrder::HeightAsc,
        };
        let got = apply_history_filter(&items, &f);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].height, 1);
        assert_eq!(got[2].height, 3);
    }
}
