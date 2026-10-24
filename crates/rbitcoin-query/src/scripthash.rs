//! Electrum scripthash history / balance / UTXO.
//!
//! Index rows are create_tx_fk only ([`ScriptHashRecord`]). Expand to
//! [`ScriptHashOutpoint`] by loading Class A outputs and matching SHA256(spk).
//! Spentness/heights from spends + Class C.

use super::*;
use rbitcoin_store::{output_flags, script_hash, spent_abs, IdxBodyMode, SpendSlotRun};
use std::sync::Arc;

/// Class A expand / spend-join wave. Bounds decoded `txout` pages in RAM.
#[doc(hidden)]
pub const SH_JOIN_WAVE: usize = 4096;
/// Electrum Cash catch-up. About eight weeks at 144 blocks a day.
#[doc(hidden)]
pub const MAX_HISTORY_WINDOW: u32 = 8_064;
/// Strong creates read from the posting tail while the page bound is open.
#[doc(hidden)]
pub const NEWEST_TAIL_CHUNK: usize = 256;

#[doc(hidden)]
pub struct NewestPageScan {
    pub high: u32,
    pub strict: bool,
}

#[doc(hidden)]
pub struct SpendHit {
    pub spender: Fk,
    pub height: u32,
    pub parent: Fk,
    pub vout: u32,
}

/// Strong creates that can still land on a newest-first page.
///
/// `bound` is the height of the limit-th counted create. `None` means the
/// posting list is shorter than the limit, so `creates` is the whole set
/// and the caller reads those spend slots instead of scanning blocks.
#[doc(hidden)]
pub struct NewestWindow {
    pub bound: Option<u32>,
    pub creates: Vec<(u32, Fk)>,
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

/// Electrum `blockchain.scripthash.get_history` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptHashHistoryItem {
    pub height: i64,
    pub txid: [u8; 32],
    /// Class A create fk when known (confirmed SH join). `NULL` for mempool-only rows.
    pub tx_fk: rbitcoin_primitives::Fk,
    /// Electrum 1.4 `fee` on unconfirmed rows (`height` 0 or `-1`). Confirmed: `None`.
    pub fee: Option<i64>,
}

/// Light history row (mempool.space `/txs/summary` shape without `time`
/// or `tx_position`; those are filled when the row is serialized).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptHashTxSummary {
    pub txid: [u8; 32],
    pub value: i64,
    pub height: i64,
    /// Confirmed Class A fk. `NULL` when the row has no stored body.
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
    /// A missing `after_txid` keeps rows strictly older than that tx in
    /// newest-first order instead of clearing the page. `cursor_missing`
    /// stays set so the caller can see this scripthash did not contain it.
    /// Single-address pages leave this false.
    pub after_absent_keeps_older: bool,
    /// Confirmed height of `after_txid`. The newest-page walk fills this
    /// when `after_absent_keeps_older` is set. `None` keeps every row the
    /// walk already bounded.
    pub after_height: Option<i64>,
}

impl Default for HistoryFilter {
    fn default() -> Self {
        Self {
            from_height: 0,
            to_height: None,
            limit: None,
            after_txid: None,
            order: HistoryOrder::HeightAsc,
            after_absent_keeps_older: false,
            after_height: None,
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
            after_absent_keeps_older: false,
            after_height: None,
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
            after_absent_keeps_older: false,
            after_height: None,
        }
    }
}

/// Rows after [`apply_history_filter`].
///
/// `cursor_missing` is set when `after_txid` was given and that tx is not in
/// the history. `rows` is then empty, so a caller that serves them does not
/// restart the first page, unless `after_absent_keeps_older` kept the older
/// window. A cursor that is the last row is not missing: `rows` is empty and
/// `cursor_missing` is false (the next page).
#[derive(Debug)]
pub struct FilteredHistory<T> {
    pub rows: Vec<T>,
    pub cursor_missing: bool,
}

/// Apply [`HistoryFilter`] to an already-built history list (no store I/O).
///
/// Does not re-sort input beyond the filter's [`HistoryOrder`]. Window is applied
/// first, then order, then `after_txid`, then `limit`.
pub fn apply_history_filter(
    items: &[ScriptHashHistoryItem],
    filter: &HistoryFilter,
) -> FilteredHistory<ScriptHashHistoryItem> {
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

    let mut cursor_missing = false;
    if let Some(after) = filter.after_txid {
        if let Some(pos) = out.iter().position(|i| i.txid == after) {
            out = out.split_off(pos.saturating_add(1));
        } else if filter.after_absent_keeps_older {
            // Not this scripthash. Keep rows strictly older than the cursor
            // so a merged page can still use them. `cursor_missing` tells
            // the caller the cursor itself was absent.
            cursor_missing = true;
            if let Some(high) = filter.after_height {
                out.retain(|i| i.height < high || (i.height == high && i.txid < after));
            }
        } else {
            // Not this history. Empty, not the first page: a wallet that
            // retries the same cursor must not loop.
            cursor_missing = true;
            out.clear();
        }
    }

    if let Some(lim) = filter.limit {
        if out.len() > lim {
            out.truncate(lim);
        }
    }
    FilteredHistory {
        rows: out,
        cursor_missing,
    }
}

#[doc(hidden)]
pub fn history_items_from_joined(
    joined: &[ShJoinedOut],
    filter: &HistoryFilter,
) -> FilteredHistory<ScriptHashHistoryItem> {
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
            fee: None,
        })
        .collect();
    apply_history_filter(&items, filter)
}

#[doc(hidden)]
pub fn summaries_from_joined(
    joined: &[ShJoinedOut],
    filter: &HistoryFilter,
) -> FilteredHistory<ScriptHashTxSummary> {
    let FilteredHistory {
        rows: items,
        cursor_missing,
    } = history_items_from_joined(joined, filter);
    let mut net: HashMap<Fk, i64> = HashMap::new();
    for rec in joined {
        net.entry(rec.out.create_tx_fk)
            .and_modify(|v| *v = v.saturating_add(rec.out.value))
            .or_insert(rec.out.value);
        for sp in &rec.spender_fks {
            net.entry(*sp)
                .and_modify(|v| *v = v.saturating_sub(rec.out.value))
                .or_insert(0i64.saturating_sub(rec.out.value));
        }
    }
    FilteredHistory {
        rows: items
            .into_iter()
            .map(|it| ScriptHashTxSummary {
                txid: it.txid,
                value: net.get(&it.tx_fk).copied().unwrap_or(0),
                height: it.height,
                tx_fk: it.tx_fk,
            })
            .collect(),
        cursor_missing,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ScriptHashBalance {
    pub confirmed: i64,
    pub unconfirmed: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptHashUtxo {
    pub tx_hash: [u8; 32],
    pub tx_pos: u32,
    /// Confirmed: block height. Mempool: `0` (confirmed parents) or `-1` (unconfirmed parent).
    pub height: i64,
    pub value: i64,
    pub create_tx_fk: rbitcoin_primitives::Fk,
}

/// Tx fks and input `create_fk`s of one block ([`Query::block_touch`]).
#[derive(Clone, Debug, Default)]
pub struct BlockTouch {
    pub ids: std::collections::HashSet<u64>,
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

#[derive(Clone)]
pub struct ShSpender {
    pub fk: Fk,
    pub txid: [u8; 32],
    pub height: u32,
}

#[derive(Clone)]
pub struct ShJoinedOut {
    pub out: ScriptHashOutpoint,
    pub spent: bool,
    pub spender_fks: Vec<Fk>,
    pub spenders: Vec<ShSpender>,
}

/// Last scripthash expand+spend join for one Electrum connection.
///
/// Holds BALANCE-level outs + spentness. Identity is filled in place on
/// history / listunspent. Invalid once the published tip **hash** moves
/// (including a same-height replace).
#[derive(Clone)]
pub struct ShJoinSlot {
    pub scripthash: [u8; 32],
    pub tip_hash: [u8; 32],
    pub joined: Vec<ShJoinedOut>,
}

impl ShJoinSlot {
    /// Approximate packed join size for the HTTP last-bulk byte cap.
    pub fn packed_bytes(&self) -> usize {
        const BASE: usize = 64;
        const OUT: usize = 80;
        self.joined.iter().fold(BASE, |acc, o| {
            acc.saturating_add(OUT)
                .saturating_add(o.spender_fks.len().saturating_mul(8))
                .saturating_add(o.spenders.len().saturating_mul(48))
        })
    }

    /// Fixture: one out whose packed size is `64 + 80 + n×8`.
    pub fn with_spender_fk_count(n: usize) -> Arc<Self> {
        Arc::new(Self {
            scripthash: [0xab; 32],
            tip_hash: [0xcd; 32],
            joined: vec![ShJoinedOut {
                out: ScriptHashOutpoint {
                    scripthash: [0xab; 32],
                    create_tx_fk: Fk::NULL,
                    vout: 0,
                    txid: [0; 32],
                    value: 0,
                    create_height: 0,
                },
                spent: false,
                spender_fks: vec![Fk::NULL; n],
                spenders: Vec::new(),
            }],
        })
    }
}

/// Which identity sidefiles this SH join must fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShJoinNeed {
    pub create_identity: bool,
    pub spender_identity: bool,
}

impl ShJoinNeed {
    pub const HISTORY: Self = Self {
        create_identity: true,
        spender_identity: true,
    };
    pub const BALANCE: Self = Self {
        create_identity: false,
        spender_identity: false,
    };
    pub const LISTUNSPENT: Self = Self::BALANCE;
    pub const CHAIN_STATS: Self = Self::BALANCE;
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
    #[doc(hidden)]
    pub fn expand_create_fks_wave(
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
                    value: o.value as i64,
                    create_height: height,
                });
            }
        }
        Ok(out)
    }

    #[doc(hidden)]
    pub fn join_out_spent(&self, rec: &ShJoinedOut) -> Result<bool, QueryError> {
        if self.spend_index_enabled() {
            Ok(rec.spent)
        } else {
            self.is_outpoint_spent(&rec.out.txid, rec.out.vout)
        }
    }

    #[doc(hidden)]
    pub fn confirmed_strong_in(&self, fk: Fk, view: &ChainView) -> Result<bool, QueryError> {
        self.store.is_confirmed_strong_at(fk, Some(view.height.0))
    }

    #[doc(hidden)]
    pub fn order_fks_for_page(
        &self,
        fks: &mut Vec<Fk>,
        filter: &HistoryFilter,
    ) -> Result<(), QueryError> {
        let heights = self.store.tx_height_get_batch(fks)?;
        if heights.len() != fks.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH create height batch length",
            ));
        }
        let mut keyed: Vec<(u32, Fk)> = fks
            .iter()
            .zip(heights)
            .map(|(fk, h)| (h.unwrap_or(0), *fk))
            .collect();
        match filter.order {
            HistoryOrder::HeightAsc => keyed.sort_by_key(|(h, fk)| (*h, fk.0)),
            HistoryOrder::NewestFirst => {
                keyed.sort_by(|a, b| b.0.cmp(&a.0).then(b.1 .0.cmp(&a.1 .0)))
            }
        }
        *fks = keyed.into_iter().map(|(_, fk)| fk).collect();
        Ok(())
    }

    /// The limited page already has its rows, and `after_txid` is in the join
    /// when the caller asked for one.
    #[doc(hidden)]
    pub fn history_page_full(joined: &[ShJoinedOut], filter: &HistoryFilter) -> bool {
        let Some(limit) = filter.limit else {
            return false;
        };
        if let Some(after) = filter.after_txid {
            let open = HistoryFilter {
                limit: None,
                after_txid: None,
                ..filter.clone()
            };
            let seen = history_items_from_joined(joined, &open);
            if !seen.rows.iter().any(|i| i.txid == after) {
                return false;
            }
        }
        history_items_from_joined(joined, filter).rows.len() >= limit
    }

    /// How many leading `rest` creates can still change a height-ascending page.
    ///
    /// The join loop calls this once, so a full page does not re-read the tail
    /// per wave.
    #[doc(hidden)]
    pub fn history_tail_keep(
        &self,
        joined: &[ShJoinedOut],
        filter: &HistoryFilter,
        rest: &[Fk],
    ) -> Result<usize, QueryError> {
        if rest.is_empty() || filter.order != HistoryOrder::HeightAsc {
            return Ok(rest.len());
        }
        let page = history_items_from_joined(joined, filter).rows;
        let edge = page.last().map(|i| i.height).unwrap_or(0);
        let heights = self.store.tx_height_get_batch(rest)?;
        if heights.len() != rest.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH create height batch length",
            ));
        }
        Ok(heights
            .iter()
            .take_while(|h| i64::from(h.unwrap_or(0)) <= edge)
            .count())
    }

    /// Confirmed-strong create outpoints plus confirmed spenders (create_fk join).
    ///
    /// When `to_height` is set, creates with Class C height `>= to_height` are not
    /// expanded (their spends cannot fall in the window). Visibility is
    /// [`Store::is_confirmed_strong_at`] against `view.height`.
    pub fn sh_join(
        &self,
        scripthash: &[u8; 32],
        need: ShJoinNeed,
        to_height: Option<i64>,
        view: &ChainView,
    ) -> Result<Vec<ShJoinedOut>, QueryError> {
        self.sh_join_limited(scripthash, need, to_height, view, None)
    }

    pub fn sh_join_limited(
        &self,
        scripthash: &[u8; 32],
        need: ShJoinNeed,
        to_height: Option<i64>,
        view: &ChainView,
        page: Option<&HistoryFilter>,
    ) -> Result<Vec<ShJoinedOut>, QueryError> {
        let paging = page.is_some_and(|f| f.limit.is_some());
        let admit = if paging {
            None
        } else {
            Some(self.unpaged_join_admit(scripthash)?)
        };
        #[cfg(debug_assertions)]
        let _probe = admit.as_ref().map(|a| self.sh_join_probe.enter(a.heavy));
        // Release builds have no probe. Moving the guard into `_admit` keeps
        // it until this function returns. Debug drops `_probe` first.
        #[cfg(not(debug_assertions))]
        let _admit = admit;
        let t_pages = std::time::Instant::now();
        let entries = self.store.scripthash.create_fks(scripthash)?;
        let pages_us = t_pages.elapsed().as_micros();
        let mut fks = Vec::new();
        for fk in entries {
            if self.confirmed_strong_in(fk, view)? {
                fks.push(fk);
            }
        }
        for fk in self.pending_sh_create_fks(scripthash) {
            if self.confirmed_strong_in(fk, view)? && !fks.contains(&fk) {
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
        if paging {
            self.order_fks_for_page(&mut fks, page.expect("paging"))?;
        }
        let (out, class_a_us, spends_us) = if paging {
            self.join_page_waves(scripthash, &fks, need, view, page.expect("paging"))?
        } else {
            let mut creates = Vec::new();
            let mut class_a_us = 0u128;
            for wave in fks.chunks(SH_JOIN_WAVE) {
                let t_a = std::time::Instant::now();
                creates.extend(self.expand_create_fks_wave(scripthash, wave, need)?);
                class_a_us = class_a_us.saturating_add(t_a.elapsed().as_micros());
            }
            let t_s = std::time::Instant::now();
            // The whole unpaged join is this one spend-slot batch. A
            // height-ascending page flushes one peek group at a time in
            // `join_page_waves`.
            let joined = self.join_spends_wave(&creates, need, view)?;
            let spends_us = t_s.elapsed().as_micros();
            (joined, class_a_us, spends_us)
        };
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
        // Debug drops `_probe` before `admit`. Releasing the heavy lock first
        // lets the next heavy join enter the probe while this one is still counted.
        Ok(out)
    }

    /// Refuse an unpaged join above `--max-sh-creates`, then hand back the
    /// heavy-join guard when the create count is above `--heavy-sh-creates`.
    /// The guard is a blocking lock taken on the blocking pool. Its holder
    /// only reads the store and never waits on a client, so a waiter (even
    /// one in the same connection's batch window) always gets it once that
    /// join returns, on success or error.
    fn unpaged_join_admit(&self, scripthash: &[u8; 32]) -> Result<JoinAdmit<'_>, QueryError> {
        let light = JoinAdmit {
            heavy: false,
            _turn: None,
        };
        let cap = self.max_sh_creates();
        let heavy = self.heavy_sh_creates();
        if cap == 0 && heavy == 0 {
            return Ok(light);
        }
        let n = self.scripthash_create_count(scripthash)?;
        if cap > 0 && n > cap {
            return Err(StoreError::ShCreatesCap { creates: n, cap });
        }
        if heavy == 0 || n <= heavy {
            return Ok(light);
        }
        Ok(JoinAdmit {
            heavy: true,
            _turn: Some(
                self.heavy_sh_join
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
        })
    }

    /// A `from_height` above 0 scans that window and never fills the join.
    /// Any `to_height` also skips the stored join. A limited newest-first
    /// page never fills it, at every cap. A height-ascending page skips it
    /// only when the unpaged join would hit `--max-sh-creates`.
    #[doc(hidden)]
    pub fn page_without_full_slot(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        slot: &Option<Arc<ShJoinSlot>>,
        view: &ChainView,
    ) -> Result<bool, QueryError> {
        if slot
            .as_ref()
            .is_some_and(|s| Self::sh_join_slot_hit(s, scripthash, view))
        {
            return Ok(false);
        }
        // A catch-up from a later height scans that window. It must not
        // fill the join or trip `--max-sh-creates`.
        if filter.from_height > 0 {
            return Ok(true);
        }
        if filter.to_height.is_some() {
            return Ok(true);
        }
        if filter.limit.is_none() {
            return Ok(false);
        }
        if filter.order == HistoryOrder::NewestFirst {
            return Ok(true);
        }
        let cap = self.max_sh_creates();
        Ok(cap > 0 && self.scripthash_create_count(scripthash)? > cap)
    }

    #[doc(hidden)]
    pub fn sh_join_slot_hit(slot: &ShJoinSlot, scripthash: &[u8; 32], view: &ChainView) -> bool {
        slot.scripthash == *scripthash && slot.tip_hash == view.hash
    }

    #[doc(hidden)]
    pub fn ensure_sh_join_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
    ) -> Result<(), QueryError> {
        let Some(view) = self.pin_sh_chain_view()? else {
            *slot = None;
            return Ok(());
        };
        self.ensure_sh_join_slot_in(scripthash, slot, &view)
    }

    #[doc(hidden)]
    pub fn ensure_sh_join_slot_in(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
        view: &ChainView,
    ) -> Result<(), QueryError> {
        if slot
            .as_ref()
            .is_some_and(|s| Self::sh_join_slot_hit(s, scripthash, view))
        {
            return Ok(());
        }
        let joined = self.sh_join(scripthash, ShJoinNeed::BALANCE, None, view)?;
        *slot = Some(Arc::new(ShJoinSlot {
            scripthash: *scripthash,
            tip_hash: view.hash,
            joined,
        }));
        Ok(())
    }

    #[doc(hidden)]
    pub fn enrich_joined(
        &self,
        recs: &mut [ShJoinedOut],
        need: ShJoinNeed,
    ) -> Result<(), QueryError> {
        if need.create_identity {
            self.fill_create_txids(recs, false)?;
        }
        if need.spender_identity {
            self.fill_spender_identity(recs)?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn fill_spender_identity(&self, recs: &mut [ShJoinedOut]) -> Result<(), QueryError> {
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

    #[doc(hidden)]
    pub fn balance_from_joined(
        &self,
        recs: &[ShJoinedOut],
    ) -> Result<ScriptHashBalance, QueryError> {
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

    #[doc(hidden)]
    pub fn listunspent_from_joined(
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
                height: i64::from(rec.out.create_height),
                value: rec.out.value,
                create_tx_fk: rec.out.create_tx_fk,
            });
        }
        out.sort_by(|a, b| a.height.cmp(&b.height).then(a.tx_pos.cmp(&b.tx_pos)));
        Ok(out)
    }

    #[doc(hidden)]
    pub fn chain_stats_from_joined(
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

    /// Height-ascending page. Expand one create at a time. Spend slots flush
    /// when the next create has no spend slots, or those slots leave the open
    /// peek group, then the page-full stop runs. The remainder flushes once.
    #[doc(hidden)]
    pub fn join_page_waves(
        &self,
        scripthash: &[u8; 32],
        fks: &[Fk],
        need: ShJoinNeed,
        view: &ChainView,
        filter: &HistoryFilter,
    ) -> Result<(Vec<ShJoinedOut>, u128, u128), QueryError> {
        let mut out = Vec::new();
        let mut pending = Vec::new();
        let mut pending_offs = Vec::new();
        let mut run = SpendSlotRun::new();
        let mut class_a_us = 0u128;
        let mut spends_us = 0u128;
        let mut i = 0usize;
        let mut stop_at: Option<usize> = None;
        while i < fks.len() {
            if stop_at.is_some_and(|end| i >= end) {
                break;
            }
            let t_a = std::time::Instant::now();
            let created = self.expand_create_fks_wave(scripthash, &fks[i..i + 1], need)?;
            class_a_us = class_a_us.saturating_add(t_a.elapsed().as_micros());
            let offs = self.spend_abs_offs(&created)?;
            let slots: Vec<u64> = offs.iter().copied().flatten().collect();
            // An empty slot list does not extend a peek group (`accepts_all`
            // of nothing is true). Closing here is what lets the page stop
            // run when the spend index is off or the create has no range.
            let group_closed = slots.is_empty() || !run.accepts_all(&slots);
            if group_closed && !pending.is_empty() {
                let t_s = std::time::Instant::now();
                out.extend(self.join_known_offs(&pending, &pending_offs, need, view)?);
                spends_us = spends_us.saturating_add(t_s.elapsed().as_micros());
                pending.clear();
                pending_offs.clear();
                run.clear();
                if stop_at.is_none() && Self::history_page_full(&out, filter) {
                    let keep = self.history_tail_keep(&out, filter, &fks[i..])?;
                    stop_at = Some(i.saturating_add(keep));
                }
                if stop_at.is_some_and(|end| i >= end) {
                    break;
                }
            }
            run.push_all(&slots);
            pending.extend(created);
            pending_offs.extend(offs);
            i += 1;
        }
        if !pending.is_empty() {
            let t_s = std::time::Instant::now();
            out.extend(self.join_known_offs(&pending, &pending_offs, need, view)?);
            spends_us = spends_us.saturating_add(t_s.elapsed().as_micros());
        }
        Ok((out, class_a_us, spends_us))
    }

    #[doc(hidden)]
    pub fn spend_abs_offs(
        &self,
        creates: &[ScriptHashOutpoint],
    ) -> Result<Vec<Option<u64>>, QueryError> {
        if creates.is_empty() || !self.spend_index_enabled() {
            return Ok(vec![None; creates.len()]);
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
        for (fk, range) in uniq.iter().zip(ranges) {
            if let Some(range) = range {
                range_by_fk.insert(*fk, range);
            }
        }
        Ok(creates
            .iter()
            .map(|c| {
                range_by_fk
                    .get(&c.create_tx_fk)
                    .map(|(off, _)| spent_abs(*off, c.vout))
            })
            .collect())
    }

    /// One call reads every spend slot of `creates` as a single `spent.body`
    /// batch. The unpaged join passes the whole create list. A
    /// height-ascending page does not: it flushes one closed peek group
    /// through [`Self::join_known_offs`].
    #[doc(hidden)]
    pub fn join_spends_wave(
        &self,
        creates: &[ScriptHashOutpoint],
        need: ShJoinNeed,
        view: &ChainView,
    ) -> Result<Vec<ShJoinedOut>, QueryError> {
        let offs = self.spend_abs_offs(creates)?;
        self.join_known_offs(creates, &offs, need, view)
    }

    #[doc(hidden)]
    pub fn join_known_offs(
        &self,
        creates: &[ScriptHashOutpoint],
        offs: &[Option<u64>],
        need: ShJoinNeed,
        view: &ChainView,
    ) -> Result<Vec<ShJoinedOut>, QueryError> {
        if creates.is_empty() {
            return Ok(Vec::new());
        }
        if offs.len() != creates.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH spend offset batch length",
            ));
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
        let mut abs_offs = Vec::with_capacity(creates.len());
        let mut abs_at = Vec::with_capacity(creates.len());
        for off in offs {
            if let Some(off) = off {
                abs_at.push(Some(abs_offs.len()));
                abs_offs.push(*off);
            } else {
                abs_at.push(None);
            }
        }
        let metas = self.store.get_spender_meta_at_abs_batch(&abs_offs)?;
        let per_out = self.join_spends_wave_fks(creates, &abs_at, &metas, view)?;
        let mut spender_fks = Vec::new();
        for fks in &per_out {
            spender_fks.extend_from_slice(fks);
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

    #[doc(hidden)]
    pub fn join_spends_wave_fks(
        &self,
        creates: &[ScriptHashOutpoint],
        abs_at: &[Option<usize>],
        metas: &[Option<(Fk, u8, u32)>],
        view: &ChainView,
    ) -> Result<Vec<Vec<Fk>>, QueryError> {
        let mut per_out: Vec<Vec<Fk>> = vec![Vec::new(); creates.len()];
        for (i, c) in creates.iter().enumerate() {
            let Some(mi) = abs_at[i] else {
                continue;
            };
            let Some((field, flags, _vin)) = metas.get(mi).copied().flatten() else {
                continue;
            };
            if field.is_null() {
                continue;
            }
            if flags & output_flags::MULTI_SPENDER != 0 {
                for (fk, _vin) in self.store.spenders_create(c.create_tx_fk, c.vout)? {
                    if self.confirmed_strong_in(fk, view)? {
                        per_out[i].push(fk);
                    }
                }
            } else if self.confirmed_strong_in(field, view)? {
                per_out[i].push(field);
            }
        }
        Ok(per_out)
    }

    /// Confirmed Electrum-style history for a scripthash: (height, txid) pairs.
    ///
    /// Equivalent to [`Self::scripthash_history_filtered`] with [`HistoryFilter::open`].
    pub fn scripthash_history(
        &self,
        scripthash: &[u8; 32],
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        Ok(self
            .scripthash_history_filtered(scripthash, &HistoryFilter::open())?
            .rows)
    }

    /// Confirmed history for `scripthash` as of `view` (open filter).
    pub fn scripthash_history_in(
        &self,
        scripthash: &[u8; 32],
        view: &ChainView,
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        Ok(self
            .scripthash_history_filtered_in(scripthash, &HistoryFilter::open(), view)?
            .rows)
    }

    #[doc(hidden)]
    pub fn newest_limited_page(&self, filter: &HistoryFilter) -> bool {
        filter.limit.is_some() && filter.order == HistoryOrder::NewestFirst
    }

    #[doc(hidden)]
    pub fn newest_page_scan(
        &self,
        filter: &HistoryFilter,
        view: &ChainView,
    ) -> Result<Option<NewestPageScan>, QueryError> {
        let mut high = view.height.0;
        if let Some(to) = filter.to_height {
            if to <= 0 {
                return Ok(None);
            }
            let cap = u32::try_from(to.saturating_sub(1)).unwrap_or(u32::MAX);
            high = high.min(cap);
        }
        let Some(txid) = filter.after_txid else {
            return Ok(Some(NewestPageScan {
                high,
                strict: false,
            }));
        };
        let Some((fk, h)) = self.store.get_fk_by_txid_tip_height(&txid)? else {
            return Ok(None);
        };
        if h > view.height.0 || !self.confirmed_strong_in(fk, view)? {
            return Ok(None);
        }
        if let Some(to) = filter.to_height {
            if i64::from(h) >= to {
                return Ok(None);
            }
        }
        Ok(Some(NewestPageScan {
            high: h,
            strict: true,
        }))
    }

    #[doc(hidden)]
    pub fn strong_sh_creates(
        &self,
        scripthash: &[u8; 32],
        view: &ChainView,
    ) -> Result<Vec<Fk>, QueryError> {
        let mut fks = Vec::new();
        for fk in self.store.scripthash.create_fks(scripthash)? {
            if self.confirmed_strong_in(fk, view)? {
                fks.push(fk);
            }
        }
        for fk in self.pending_sh_create_fks(scripthash) {
            if !self.confirmed_strong_in(fk, view)? {
                continue;
            }
            if let Err(at) = fks.binary_search_by_key(&fk.0, |f| f.0) {
                fks.insert(at, fk);
            }
        }
        Ok(fks)
    }

    /// See [`NewestWindow`].
    #[doc(hidden)]
    pub fn newest_create_window(
        &self,
        fks: &[Fk],
        k: usize,
        high: u32,
        strict: bool,
    ) -> Result<NewestWindow, QueryError> {
        let mut rev = Vec::new();
        let mut idx = fks.len();
        let mut counted = 0usize;
        let mut bound: Option<u32> = None;
        while idx > 0 {
            let start = idx.saturating_sub(NEWEST_TAIL_CHUNK);
            let chunk = &fks[start..idx];
            let heights = self.store.tx_height_get_batch(chunk)?;
            if heights.len() != chunk.len() {
                return Err(StoreError::Corrupt(
                    "invariant: SH create height batch length",
                ));
            }
            for (fk, h) in chunk.iter().zip(heights).rev() {
                let h = h.unwrap_or(0);
                if h > high {
                    continue;
                }
                rev.push((h, *fk));
                if strict && h >= high {
                    continue;
                }
                counted = counted.saturating_add(1);
                if counted == k {
                    bound = Some(h);
                }
            }
            idx = start;
            if let Some(t) = bound {
                if rev.last().is_some_and(|(h, _)| *h < t) {
                    break;
                }
            }
        }
        let Some(low) = bound else {
            return Ok(NewestWindow {
                bound: None,
                creates: rev,
            });
        };
        rev.retain(|(h, _)| *h >= low);
        Ok(NewestWindow {
            bound: Some(low),
            creates: rev,
        })
    }

    /// Spends of a posting list shorter than the page limit.
    ///
    /// Every create that can still land on the page is in `creates`, so the
    /// spend slots of those creates are the whole answer. One
    /// [`Self::join_spends_wave`] is that batch. A spender above `high`
    /// belongs on an earlier page. This is not [`Self::sh_join`]: a short
    /// list can still sit above `--max-sh-creates`, and the page must not
    /// fill the join slot.
    #[doc(hidden)]
    pub fn spends_of_retained_creates(
        &self,
        scripthash: &[u8; 32],
        creates: &[(u32, Fk)],
        high: u32,
        view: &ChainView,
    ) -> Result<Vec<SpendHit>, QueryError> {
        if creates.is_empty() || !self.spend_index_enabled() {
            return Ok(Vec::new());
        }
        let fks: Vec<Fk> = creates.iter().map(|(_, fk)| *fk).collect();
        let need = ShJoinNeed {
            create_identity: false,
            spender_identity: true,
        };
        let mut outs = Vec::new();
        for wave in fks.chunks(SH_JOIN_WAVE) {
            outs.extend(self.expand_create_fks_wave(scripthash, wave, need)?);
        }
        let mut hits = Vec::new();
        for row in self.join_spends_wave(&outs, need, view)? {
            for spender in row.spenders {
                if spender.height > high {
                    continue;
                }
                hits.push(SpendHit {
                    spender: spender.fk,
                    height: spender.height,
                    parent: row.out.create_tx_fk,
                    vout: row.out.vout,
                });
            }
        }
        Ok(hits)
    }

    #[doc(hidden)]
    pub fn spends_of_members(
        &self,
        members: &[Fk],
        low: u32,
        high: u32,
    ) -> Result<Vec<SpendHit>, QueryError> {
        if !self.spend_index_enabled() || members.is_empty() || low > high {
            return Ok(Vec::new());
        }
        debug_assert!(
            high.saturating_sub(low) <= MAX_HISTORY_WINDOW,
            "block scan stays inside the history window"
        );
        let mut hits = Vec::new();
        for height in (low..=high).rev() {
            let (first, n) = self.tx_fk_span_at_height(Height(height))?;
            if n == 0 {
                continue;
            }
            let last = first.0.saturating_add(u64::from(n)).saturating_sub(1);
            let rows = self.store.input_edges_span(first.0, last)?;
            if rows.len() != n as usize {
                return Err(StoreError::Corrupt("invariant: input edge span length"));
            }
            for (i, edges) in rows.into_iter().enumerate() {
                let Some(edges) = edges else {
                    continue;
                };
                let spender = Fk(first.0.saturating_add(i as u64));
                for edge in edges {
                    if edge.parent.is_null() {
                        continue;
                    }
                    if members
                        .binary_search_by_key(&edge.parent.0, |fk| fk.0)
                        .is_err()
                    {
                        continue;
                    }
                    hits.push(SpendHit {
                        spender,
                        height,
                        parent: edge.parent,
                        vout: edge.vout,
                    });
                }
            }
        }
        Ok(hits)
    }

    #[doc(hidden)]
    pub fn sh_matched_outs(
        &self,
        scripthash: &[u8; 32],
        fks: &[Fk],
    ) -> Result<HashMap<Fk, Vec<(u32, i64)>>, QueryError> {
        if fks.is_empty() {
            return Ok(HashMap::new());
        }
        let loaded = super::load_creates_once(&self.store, fks, IdxBodyMode::Outs)?;
        let mut matched = HashMap::new();
        for create in loaded {
            let Some((_tx, outs, _rels)) = &create.decoded_outs else {
                return Err(StoreError::Corrupt(
                    "invariant: SH create missing decoded outs",
                ));
            };
            let mut rows = Vec::new();
            for (vout, o) in outs.iter().enumerate() {
                if script_hash(&o.script) != *scripthash {
                    continue;
                }
                rows.push((vout as u32, o.value as i64));
            }
            matched.insert(create.fk, rows);
        }
        for fk in fks {
            if !matched.contains_key(fk) {
                return Err(StoreError::Corrupt(
                    "invariant: SH create body missing after load",
                ));
            }
        }
        Ok(matched)
    }

    /// Spends that can land on a newest-first page.
    ///
    /// A gap inside [`MAX_HISTORY_WINDOW`] still scans those blocks. A wider
    /// gap reads spend slots of the page's creates and of creates below the
    /// page bound. A spender counts only at a height inside `[low, high]`.
    #[doc(hidden)]
    pub fn spends_for_newest_page(
        &self,
        scripthash: &[u8; 32],
        members: &[Fk],
        window: &NewestWindow,
        high: u32,
        view: &ChainView,
    ) -> Result<Vec<SpendHit>, QueryError> {
        let Some(low) = window.bound else {
            return self.spends_of_retained_creates(scripthash, &window.creates, high, view);
        };
        if high.saturating_sub(low) <= MAX_HISTORY_WINDOW {
            return self.spends_of_members(members, low, high);
        }
        let mut creates = window.creates.clone();
        let mut kept: Vec<u64> = window.creates.iter().map(|(_, fk)| fk.0).collect();
        kept.sort_unstable();
        let mut older = Vec::new();
        for fk in members {
            if kept.binary_search(&fk.0).is_err() {
                older.push(*fk);
            }
        }
        if !older.is_empty() {
            let heights = self.store.tx_height_get_batch(&older)?;
            if heights.len() != older.len() {
                return Err(StoreError::Corrupt(
                    "invariant: SH create height batch length",
                ));
            }
            for (fk, h) in older.iter().zip(heights) {
                let h = h.unwrap_or(0);
                if h < low {
                    creates.push((h, *fk));
                }
            }
        }
        let mut hits = self.spends_of_retained_creates(scripthash, &creates, high, view)?;
        hits.retain(|hit| hit.height >= low);
        Ok(hits)
    }

    fn newest_limited_summaries(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        view: &ChainView,
    ) -> Result<FilteredHistory<ScriptHashTxSummary>, QueryError> {
        let Some(k) = filter.limit else {
            return Err(StoreError::Corrupt("invariant: newest page limit"));
        };
        if let Some(to) = filter.to_height {
            if to <= 0 {
                return Ok(FilteredHistory {
                    rows: Vec::new(),
                    cursor_missing: filter.after_txid.is_some(),
                });
            }
        }
        let Some(scan) = self.newest_page_scan(filter, view)? else {
            return Ok(FilteredHistory {
                rows: Vec::new(),
                cursor_missing: true,
            });
        };
        let members = self.strong_sh_creates(scripthash, view)?;
        let window = self.newest_create_window(&members, k, scan.high, scan.strict)?;
        let hits = self.spends_for_newest_page(scripthash, &members, &window, scan.high, view)?;
        let mut decode = window.creates.iter().map(|(_, fk)| *fk).collect::<Vec<_>>();
        for hit in &hits {
            decode.push(hit.parent);
        }
        decode.sort_unstable_by_key(|fk| fk.0);
        decode.dedup();
        let matched = self.sh_matched_outs(scripthash, &decode)?;
        let mut net: HashMap<Fk, i64> = HashMap::new();
        let mut height_of: HashMap<Fk, u32> = HashMap::new();
        for (h, fk) in window.creates {
            let Some(outs) = matched.get(&fk) else {
                continue;
            };
            if outs.is_empty() {
                continue;
            }
            let sum = outs
                .iter()
                .fold(0i64, |acc, (_, value)| acc.saturating_add(*value));
            net.insert(fk, sum);
            height_of.insert(fk, h);
        }
        for hit in hits {
            let Some(outs) = matched.get(&hit.parent) else {
                continue;
            };
            let Some(value) = outs
                .iter()
                .find(|(vout, _)| *vout == hit.vout)
                .map(|(_, v)| *v)
            else {
                continue;
            };
            height_of.entry(hit.spender).or_insert(hit.height);
            net.entry(hit.spender)
                .and_modify(|n| *n = n.saturating_sub(value))
                .or_insert(0i64.saturating_sub(value));
        }
        let row_fks: Vec<Fk> = net.keys().copied().collect();
        let txids = self.store.txids_get_many(&row_fks)?;
        if txids.len() != row_fks.len() {
            return Err(StoreError::Corrupt("invariant: SH page txid batch length"));
        }
        let mut items = Vec::with_capacity(row_fks.len());
        for (fk, txid) in row_fks.iter().zip(txids) {
            let Some(txid) = txid else {
                return Err(StoreError::Corrupt("invariant: SH page missing txid"));
            };
            let Some(height) = height_of.get(fk).copied() else {
                return Err(StoreError::Corrupt("invariant: SH page missing height"));
            };
            items.push(ScriptHashHistoryItem {
                height: i64::from(height),
                txid,
                tx_fk: *fk,
                fee: None,
            });
        }
        let mut applied = filter.clone();
        if applied.after_absent_keeps_older && scan.strict {
            applied.after_height = Some(i64::from(scan.high));
        }
        let filtered = apply_history_filter(&items, &applied);
        let rows = filtered
            .rows
            .into_iter()
            .map(|item| ScriptHashTxSummary {
                txid: item.txid,
                value: net.get(&item.tx_fk).copied().unwrap_or(0),
                height: item.height,
                tx_fk: item.tx_fk,
            })
            .collect();
        Ok(FilteredHistory {
            rows,
            cursor_missing: filtered.cursor_missing,
        })
    }

    /// Confirmed history for a scripthash, filtered by height window / limit / cursor.
    ///
    /// A limited newest-first page walks the posting tail. When that walk
    /// counts `limit` creates and the height down to that create is inside
    /// [`MAX_HISTORY_WINDOW`], it reads `input.body` for those blocks so a
    /// spend of an older coin is included. A wider gap reads spend slots of
    /// the page's creates and of creates below that height, and keeps a
    /// spender only inside the page. When the list is shorter than the
    /// limit, it reads the spend slots of the creates it kept. Other filters
    /// assemble the confirmed history, then apply [`apply_history_filter`].
    /// Pins the SH watermark, not live tip.
    pub fn scripthash_history_filtered(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
    ) -> Result<FilteredHistory<ScriptHashHistoryItem>, QueryError> {
        let Some(view) = self.pin_sh_chain_view()? else {
            return Ok(FilteredHistory {
                rows: Vec::new(),
                cursor_missing: filter.after_txid.is_some(),
            });
        };
        self.scripthash_history_filtered_in(scripthash, filter, &view)
    }

    /// Confirmed rows in `[from_height, to_height)`.
    ///
    /// Creates below `from_height` stay as foreign keys. Spends of those
    /// coins come from [`Self::spends_of_members`] on the window's blocks
    /// (`input.body`), not from their spend slots, and not from [`Self::sh_join`].
    /// A hit counts only when that input's output pays this script.
    #[doc(hidden)]
    pub fn height_window_history(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        view: &ChainView,
    ) -> Result<FilteredHistory<ScriptHashHistoryItem>, QueryError> {
        let Some(high) = Self::window_high(filter, view) else {
            return Ok(FilteredHistory {
                rows: Vec::new(),
                cursor_missing: filter.after_txid.is_some(),
            });
        };
        let from = filter.from_height;
        if from > high {
            return Ok(apply_history_filter(&[], filter));
        }
        let span = high.saturating_sub(from).saturating_add(1);
        if span > MAX_HISTORY_WINDOW {
            return Err(StoreError::Rejected("history window too wide"));
        }
        let members = self.strong_sh_creates(scripthash, view)?;
        let heights = self.store.tx_height_get_batch(&members)?;
        if heights.len() != members.len() {
            return Err(StoreError::Corrupt(
                "invariant: SH create height batch length",
            ));
        }
        let mut height_of: HashMap<Fk, u32> = HashMap::new();
        for (fk, h) in members.iter().zip(heights) {
            let h = h.unwrap_or(0);
            if h < from || h > high {
                continue;
            }
            height_of.insert(*fk, h);
        }
        let hits = self.spends_of_members(&members, from, high)?;
        let mut parents: Vec<Fk> = hits.iter().map(|hit| hit.parent).collect();
        parents.sort_unstable_by_key(|fk| fk.0);
        parents.dedup();
        let matched = self.sh_matched_outs(scripthash, &parents)?;
        for hit in hits {
            if hit.height < from || hit.height > high {
                continue;
            }
            let Some(outs) = matched.get(&hit.parent) else {
                continue;
            };
            if !outs.iter().any(|(vout, _)| *vout == hit.vout) {
                continue;
            }
            height_of.entry(hit.spender).or_insert(hit.height);
        }
        let mut row_fks: Vec<Fk> = height_of.keys().copied().collect();
        row_fks.sort_unstable_by_key(|fk| fk.0);
        let txids = self.store.txids_get_many(&row_fks)?;
        if txids.len() != row_fks.len() {
            return Err(StoreError::Corrupt("invariant: SH page txid batch length"));
        }
        let mut items = Vec::with_capacity(row_fks.len());
        for (fk, txid) in row_fks.iter().zip(txids) {
            let Some(txid) = txid else {
                return Err(StoreError::Corrupt("invariant: SH page missing txid"));
            };
            let Some(height) = height_of.get(fk).copied() else {
                return Err(StoreError::Corrupt("invariant: SH page missing height"));
            };
            items.push(ScriptHashHistoryItem {
                height: i64::from(height),
                txid,
                tx_fk: *fk,
                fee: None,
            });
        }
        Ok(apply_history_filter(&items, filter))
    }

    /// Exclusive `to_height` clipped to the pinned view. `None` when the
    /// window is empty.
    #[doc(hidden)]
    pub fn window_high(filter: &HistoryFilter, view: &ChainView) -> Option<u32> {
        let mut high = view.height.0;
        if let Some(to) = filter.to_height {
            if to <= 0 {
                return None;
            }
            let cap = u32::try_from(to.saturating_sub(1)).unwrap_or(u32::MAX);
            high = high.min(cap);
        }
        Some(high)
    }

    pub fn scripthash_history_filtered_in(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        view: &ChainView,
    ) -> Result<FilteredHistory<ScriptHashHistoryItem>, QueryError> {
        if self.newest_limited_page(filter) {
            let page = self.newest_limited_summaries(scripthash, filter, view)?;
            return Ok(FilteredHistory {
                cursor_missing: page.cursor_missing,
                rows: page
                    .rows
                    .into_iter()
                    .map(|row| ScriptHashHistoryItem {
                        height: row.height,
                        txid: row.txid,
                        tx_fk: row.tx_fk,
                        fee: None,
                    })
                    .collect(),
            });
        }
        if filter.from_height > 0 {
            return self.height_window_history(scripthash, filter, view);
        }
        let joined = self.sh_join_limited(
            scripthash,
            ShJoinNeed::HISTORY,
            filter.to_height,
            view,
            Some(filter),
        )?;
        Ok(history_items_from_joined(&joined, filter))
    }

    /// Confirmed history using a connection-local join slot when `to_height` is open
    /// or the slot already holds this scripthash at the current tip.
    pub fn scripthash_history_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
    ) -> Result<Vec<ScriptHashHistoryItem>, QueryError> {
        Ok(self
            .scripthash_history_filtered_slot(scripthash, &HistoryFilter::open(), slot)?
            .rows)
    }

    /// Slot-aware [`Self::scripthash_history_filtered`].
    pub fn scripthash_history_filtered_slot(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        slot: &mut Option<Arc<ShJoinSlot>>,
    ) -> Result<FilteredHistory<ScriptHashHistoryItem>, QueryError> {
        let Some(view) = self.pin_sh_chain_view()? else {
            *slot = None;
            return Ok(FilteredHistory {
                rows: Vec::new(),
                cursor_missing: filter.after_txid.is_some(),
            });
        };
        self.scripthash_history_filtered_slot_in(scripthash, filter, slot, &view)
    }

    /// Slot-aware history at a caller-pinned view.
    pub fn scripthash_history_filtered_slot_in(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        slot: &mut Option<Arc<ShJoinSlot>>,
        view: &ChainView,
    ) -> Result<FilteredHistory<ScriptHashHistoryItem>, QueryError> {
        self.scripthash_filtered_slot_in(
            scripthash,
            filter,
            slot,
            view,
            Self::scripthash_history_filtered_in,
            history_items_from_joined,
        )
    }

    #[doc(hidden)]
    pub fn scripthash_filtered_slot_in<T>(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        slot: &mut Option<Arc<ShJoinSlot>>,
        view: &ChainView,
        limited: impl Fn(
            &Self,
            &[u8; 32],
            &HistoryFilter,
            &ChainView,
        ) -> Result<FilteredHistory<T>, QueryError>,
        project: impl Fn(&[ShJoinedOut], &HistoryFilter) -> FilteredHistory<T>,
    ) -> Result<FilteredHistory<T>, QueryError> {
        if self.page_without_full_slot(scripthash, filter, slot, view)? {
            return limited(self, scripthash, filter, view);
        }
        self.ensure_sh_join_slot_in(scripthash, slot, view)?;
        let recs = &mut Arc::make_mut(
            slot.as_mut()
                .ok_or(StoreError::Corrupt("invariant: SH join slot missing"))?,
        )
        .joined;
        self.enrich_joined(recs, ShJoinNeed::HISTORY)?;
        Ok(project(recs, filter))
    }

    pub fn scripthash_history_summary_filtered_in(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        view: &ChainView,
    ) -> Result<FilteredHistory<ScriptHashTxSummary>, QueryError> {
        if self.newest_limited_page(filter) {
            return self.newest_limited_summaries(scripthash, filter, view);
        }
        let joined = self.sh_join_limited(
            scripthash,
            ShJoinNeed::HISTORY,
            filter.to_height,
            view,
            Some(filter),
        )?;
        Ok(summaries_from_joined(&joined, filter))
    }

    pub fn scripthash_history_summary_filtered_slot_in(
        &self,
        scripthash: &[u8; 32],
        filter: &HistoryFilter,
        slot: &mut Option<Arc<ShJoinSlot>>,
        view: &ChainView,
    ) -> Result<FilteredHistory<ScriptHashTxSummary>, QueryError> {
        self.scripthash_filtered_slot_in(
            scripthash,
            filter,
            slot,
            view,
            Self::scripthash_history_summary_filtered_in,
            summaries_from_joined,
        )
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
        let mut posting: Vec<u64> = entries.iter().filter_map(|fk| fk.get()).collect();
        for fk in self.pending_sh_create_fks(scripthash) {
            if let Some(id) = fk.get() {
                posting.push(id);
            }
        }
        if posting.is_empty() {
            return Ok(Vec::new());
        }
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
                let prevs = self.tx_prevouts_for_fk(*fk)?;
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

    /// One block's touch set, built once and shared by many scripthash checks.
    ///
    /// Holds every tx fk in the block plus every input's `create_fk`. A
    /// scripthash is touched at that height exactly when its posting list meets
    /// this set, the same predicate as [`Self::scripthash_touched_at_height`],
    /// without reloading the block and its prevouts per scripthash.
    pub fn block_touch(&self, height: Height) -> Result<BlockTouch, QueryError> {
        let mut ids = std::collections::HashSet::new();
        for fk in self.block_tx_fks(height)? {
            if let Some(id) = fk.get() {
                ids.insert(id);
            }
            for (create_fk, _) in self.tx_prevouts_for_fk(fk)? {
                if let Some(id) = create_fk.get() {
                    ids.insert(id);
                }
            }
        }
        Ok(BlockTouch { ids })
    }

    /// Whether `scripthash` has any posting at all (durable or pending).
    ///
    /// The cheap test that lets callers skip [`Self::block_touch`] when no
    /// subscribed hash could possibly be touched.
    pub fn scripthash_has_postings(&self, scripthash: &[u8; 32]) -> Result<bool, QueryError> {
        if !self.store.scripthash.create_fks(scripthash)?.is_empty() {
            return Ok(true);
        }
        Ok(!self.pending_sh_create_fks(scripthash).is_empty())
    }

    /// [`Self::scripthash_touched_at_height`] against a prebuilt [`BlockTouch`].
    pub fn scripthash_touched_by(
        &self,
        scripthash: &[u8; 32],
        touch: &BlockTouch,
    ) -> Result<bool, QueryError> {
        if touch.ids.is_empty() {
            return Ok(false);
        }
        let entries = self.store.scripthash.create_fks(scripthash)?;
        let hit = entries
            .iter()
            .chain(self.pending_sh_create_fks(scripthash).iter())
            .filter_map(|fk| fk.get())
            .any(|id| touch.ids.contains(&id));
        Ok(hit)
    }

    /// Confirmed balance for a scripthash.
    pub fn scripthash_balance(
        &self,
        scripthash: &[u8; 32],
    ) -> Result<ScriptHashBalance, QueryError> {
        let Some(view) = self.pin_sh_chain_view()? else {
            return Ok(ScriptHashBalance::default());
        };
        self.scripthash_balance_in(scripthash, &view)
    }

    /// Confirmed balance as of `view`.
    pub fn scripthash_balance_in(
        &self,
        scripthash: &[u8; 32],
        view: &ChainView,
    ) -> Result<ScriptHashBalance, QueryError> {
        let joined = self.sh_join(scripthash, ShJoinNeed::BALANCE, None, view)?;
        self.balance_from_joined(&joined)
    }

    /// Slot-aware [`Self::scripthash_balance`].
    pub fn scripthash_balance_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
    ) -> Result<ScriptHashBalance, QueryError> {
        self.ensure_sh_join_slot(scripthash, slot)?;
        self.scripthash_balance_from_slot(slot)
    }

    /// Slot-aware [`Self::scripthash_balance`] at a caller-pinned view.
    pub fn scripthash_balance_slot_in(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
        view: &ChainView,
    ) -> Result<ScriptHashBalance, QueryError> {
        self.ensure_sh_join_slot_in(scripthash, slot, view)?;
        self.scripthash_balance_from_slot(slot)
    }

    #[doc(hidden)]
    pub fn scripthash_balance_from_slot(
        &self,
        slot: &Option<Arc<ShJoinSlot>>,
    ) -> Result<ScriptHashBalance, QueryError> {
        let Some(recs) = slot.as_ref() else {
            return Ok(ScriptHashBalance::default());
        };
        self.balance_from_joined(&recs.joined)
    }

    #[doc(hidden)]
    pub fn fill_create_txids(
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
        for (fk, txid) in fks.iter().zip(txids) {
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
        let Some(view) = self.pin_sh_chain_view()? else {
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
        let mut joined = self.sh_join(scripthash, ShJoinNeed::LISTUNSPENT, None, view)?;
        self.fill_create_txids(&mut joined, true)?;
        self.listunspent_from_joined(&joined)
    }

    /// Slot-aware [`Self::scripthash_listunspent`].
    pub fn scripthash_listunspent_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
    ) -> Result<Vec<ScriptHashUtxo>, QueryError> {
        self.ensure_sh_join_slot(scripthash, slot)?;
        self.scripthash_listunspent_from_slot(slot)
    }

    /// Slot-aware [`Self::scripthash_listunspent`] at a caller-pinned view.
    pub fn scripthash_listunspent_slot_in(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
        view: &ChainView,
    ) -> Result<Vec<ScriptHashUtxo>, QueryError> {
        self.ensure_sh_join_slot_in(scripthash, slot, view)?;
        self.scripthash_listunspent_from_slot(slot)
    }

    #[doc(hidden)]
    pub fn scripthash_listunspent_from_slot(
        &self,
        slot: &mut Option<Arc<ShJoinSlot>>,
    ) -> Result<Vec<ScriptHashUtxo>, QueryError> {
        let Some(slot_arc) = slot.as_mut() else {
            return Ok(Vec::new());
        };
        self.fill_create_txids(&mut Arc::make_mut(slot_arc).joined, true)?;
        self.listunspent_from_joined(&slot_arc.joined)
    }

    /// Durable SH create count plus pending write-behind for this key.
    pub fn scripthash_create_count(&self, scripthash: &[u8; 32]) -> Result<u32, QueryError> {
        let durable = self.store.scripthash.create_count(scripthash)?;
        let pending = self.pending_sh_create_fks(scripthash).len() as u32;
        Ok(durable.saturating_add(pending))
    }

    /// Confirmed chain_stats for Esplora address/scripthash routes.
    ///
    /// One expand+spend join (same walk as history / balance / listunspent).
    pub fn scripthash_chain_stats(
        &self,
        scripthash: &[u8; 32],
    ) -> Result<ScriptHashChainStats, QueryError> {
        let Some(view) = self.pin_sh_chain_view()? else {
            return Ok(ScriptHashChainStats::default());
        };
        self.scripthash_chain_stats_in(scripthash, &view)
    }

    /// Confirmed chain_stats as of `view`.
    pub fn scripthash_chain_stats_in(
        &self,
        scripthash: &[u8; 32],
        view: &ChainView,
    ) -> Result<ScriptHashChainStats, QueryError> {
        let joined = self.sh_join(scripthash, ShJoinNeed::CHAIN_STATS, None, view)?;
        self.chain_stats_from_joined(&joined)
    }

    /// Slot-aware [`Self::scripthash_chain_stats`].
    pub fn scripthash_chain_stats_slot(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
    ) -> Result<ScriptHashChainStats, QueryError> {
        self.ensure_sh_join_slot(scripthash, slot)?;
        let Some(recs) = slot.as_ref() else {
            return Ok(ScriptHashChainStats::default());
        };
        self.chain_stats_from_joined(&recs.joined)
    }

    /// Slot-aware [`Self::scripthash_chain_stats`] at a caller-pinned view.
    pub fn scripthash_chain_stats_slot_in(
        &self,
        scripthash: &[u8; 32],
        slot: &mut Option<Arc<ShJoinSlot>>,
        view: &ChainView,
    ) -> Result<ScriptHashChainStats, QueryError> {
        self.ensure_sh_join_slot_in(scripthash, slot, view)?;
        let Some(recs) = slot.as_ref() else {
            return Ok(ScriptHashChainStats::default());
        };
        self.chain_stats_from_joined(&recs.joined)
    }
}

/// An admitted unpaged join. A heavy one holds the node's single heavy turn
/// until this drops.
pub struct JoinAdmit<'a> {
    pub heavy: bool,
    _turn: Option<std::sync::MutexGuard<'a, ()>>,
}

/// Unpaged scripthash joins running now and their peak, light and heavy
/// apart. Off until [`ShJoinProbe::arm`]. Armed, a join waits inside (up to
/// [`SH_JOIN_PROBE_WAIT`]) for a second join of its kind, so two joins that
/// are allowed to overlap do.
#[cfg(debug_assertions)]
#[derive(Default)]
pub struct ShJoinProbe {
    armed: std::sync::atomic::AtomicBool,
    running: [AtomicU32; 2],
    peak: [AtomicU32; 2],
    entered: [AtomicU32; 2],
}

#[cfg(debug_assertions)]
pub const SH_JOIN_PROBE_WAIT: std::time::Duration = std::time::Duration::from_millis(300);

#[cfg(debug_assertions)]
pub struct ShJoinProbeGuard<'a> {
    probe: &'a ShJoinProbe,
    kind: usize,
}

#[cfg(debug_assertions)]
impl ShJoinProbe {
    pub fn arm(&self) {
        for k in 0..2 {
            self.peak[k].store(0, AtomicOrdering::SeqCst);
            self.entered[k].store(0, AtomicOrdering::SeqCst);
        }
        self.armed.store(true, AtomicOrdering::SeqCst);
    }

    /// `(light, heavy)` joins started since [`Self::arm`].
    pub fn entered(&self) -> (u32, u32) {
        (
            self.entered[0].load(AtomicOrdering::SeqCst),
            self.entered[1].load(AtomicOrdering::SeqCst),
        )
    }

    /// `(light, heavy)` peak overlap since [`Self::arm`].
    pub fn peaks(&self) -> (u32, u32) {
        (
            self.peak[0].load(AtomicOrdering::SeqCst),
            self.peak[1].load(AtomicOrdering::SeqCst),
        )
    }

    pub fn enter(&self, heavy: bool) -> Option<ShJoinProbeGuard<'_>> {
        if !self.armed.load(AtomicOrdering::SeqCst) {
            return None;
        }
        let kind = usize::from(heavy);
        self.entered[kind].fetch_add(1, AtomicOrdering::SeqCst);
        let now = self.running[kind].fetch_add(1, AtomicOrdering::SeqCst) + 1;
        self.peak[kind].fetch_max(now, AtomicOrdering::SeqCst);
        let until = std::time::Instant::now() + SH_JOIN_PROBE_WAIT;
        while self.peak[kind].load(AtomicOrdering::SeqCst) < 2 && std::time::Instant::now() < until
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Some(ShJoinProbeGuard { probe: self, kind })
    }
}

#[cfg(debug_assertions)]
impl Drop for ShJoinProbeGuard<'_> {
    fn drop(&mut self) {
        self.probe.running[self.kind].fetch_sub(1, AtomicOrdering::SeqCst);
    }
}
