//! Logical digest of the confirmed chain and its spend state.
//!
//! Two stores with the same confirmed chain give the same digest whatever
//! their `store.secret`, schema of origin, or reorg history. The walk is by
//! height and addresses every create as `(height, index in block)`, never by
//! fk: fk numbering includes orphaned creates and differs between nodes.
//! Non-strong spend annotations are skipped.

use super::*;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use rbitcoin_consensus::ChainParams;

const DOMAIN: &[u8] = b"rbitcoin hot digest v1\0";

/// Heights archived and confirmed per run by [`Query::import_hot`]. Bounds the
/// blocks held in memory (4 MB each at most).
const IMPORT_RUN: u32 = 64;

/// Digest of a store's confirmed chain at `height` (tip).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotDigest {
    pub height: u32,
    pub tip_hash: [u8; 32],
    pub digest: [u8; 32],
}

/// Why [`Query::import_hot`] refused a source.
#[derive(Debug)]
pub enum HotImportError {
    NotEmpty,
    ColdDestination,
    /// The source's append-only files live on its `--datadir-cold`.
    ColdSource,
    SourceSchema(u16),
    /// The source's tip markers are missing or behind; the reason in words.
    Unclean(String),
    Pruned,
    /// A source block fails its header or body checks.
    Invalid {
        height: u32,
        reason: String,
    },
    DigestMismatch {
        expected: [u8; 32],
        got: [u8; 32],
    },
    Store(StoreError),
}

impl std::fmt::Display for HotImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use rbitcoin_primitives::hex;
        match self {
            Self::NotEmpty => f.write_str("assumehot: destination store is not empty"),
            Self::ColdDestination => {
                f.write_str("assumehot: a cold destination (--datadir-cold) is not supported")
            }
            Self::ColdSource => {
                f.write_str("assumehot: a cold source (--datadir-cold) is not supported")
            }
            Self::SourceSchema(v) => write!(
                f,
                "assumehot: source schema {v} is not {}; open it once with this binary first",
                rbitcoin_primitives::SCHEMA_VERSION
            ),
            Self::Unclean(why) => write!(f, "assumehot: source did not shut down cleanly ({why})"),
            Self::Pruned => f.write_str("assumehot: source is pruned"),
            Self::Invalid { height, reason } => {
                write!(f, "assumehot: height {height} is invalid ({reason})")
            }
            Self::DigestMismatch { expected, got } => write!(
                f,
                "assumehot: digest mismatch (expected {}, got {})",
                hex::encode(expected),
                hex::encode(got)
            ),
            Self::Store(e) => write!(f, "assumehot: {e}"),
        }
    }
}

impl std::error::Error for HotImportError {}

impl From<StoreError> for HotImportError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl Query {
    /// [`HotDigest`] of the confirmed chain, or `None` for an empty store.
    ///
    /// Per height: height, block hash, and the witness-serialized block. Per
    /// tx: the `txstat` row, the input edges as parent `(height, index, vout)`,
    /// and each output's strong spenders as `(height, index, vin)` in order.
    /// An unstamped `txstat` or input row is hashed as absent.
    pub fn hot_digest(&self) -> Result<Option<HotDigest>, QueryError> {
        let Some(tip) = self.tip_height() else {
            return Ok(None);
        };
        let mut eng = sha256::Hash::engine();
        eng.input(DOMAIN);
        let mut tip_hash = [0u8; 32];
        for h in 0..=tip.0 {
            let block = self.reconstruct_block_at_height(Height(h))?;
            tip_hash = block.block_hash().to_byte_array();
            let wire = bitcoin::consensus::encode::serialize(&block);
            eng.input(&h.to_le_bytes());
            eng.input(&tip_hash);
            eng.input(&(wire.len() as u64).to_le_bytes());
            eng.input(&wire);
            for (fk, tx) in self.block_tx_fks(Height(h))?.into_iter().zip(&block.txdata) {
                self.hot_digest_tx(&mut eng, fk, tx.output.len() as u32, tip.0)?;
            }
        }
        Ok(Some(HotDigest {
            height: tip.0,
            tip_hash,
            digest: sha256::Hash::from_engine(eng).to_byte_array(),
        }))
    }

    /// Rewrite every confirmed height of `src` into this empty store, then
    /// refuse unless this store's [`Self::hot_digest`] equals `expected`.
    pub fn import_hot(
        &self,
        src: &Query,
        params: &ChainParams,
        expected: [u8; 32],
    ) -> Result<(), HotImportError> {
        if self.tip_height().is_some() {
            return Err(HotImportError::NotEmpty);
        }
        let Some(tip) = src.tip_height() else {
            return Err(StoreError::NotFound.into());
        };
        let mut prev_fk = Fk::NULL;
        for run_start in (0..=tip.0).step_by(IMPORT_RUN as usize) {
            let run_end = run_start.saturating_add(IMPORT_RUN - 1).min(tip.0);
            let mut run = Vec::with_capacity((run_end - run_start + 1) as usize);
            for h in run_start..=run_end {
                let block = Arc::new(src.reconstruct_block_at_height(Height(h))?);
                let hash = block.block_hash().to_byte_array();
                let txids = hot_import_check_block(src, params, Height(h), &block)?;
                prev_fk = self.ensure_header(&crate::convert::header_to_record(
                    prev_fk,
                    &block.header,
                    hash,
                ))?;
                run.push((Height(h), prev_fk, hash, block, txids));
            }
            let need: Vec<WirePlanNeed<'_>> = run
                .iter()
                .map(|(_, fk, _, block, txids)| (*fk, block, txids.as_slice()))
                .collect();
            self.archive_class_a_from_wire(&need)?;
            let mut prepared = Vec::with_capacity(run.len());
            for (height, header_fk, hash, _, _) in &run {
                let tx_fks = self
                    .store
                    .header_txs
                    .get_list(*header_fk)?
                    .ok_or(StoreError::Corrupt("assumehot: archived block has no body"))?;
                prepared.push(ConfirmPrepared {
                    height: *height,
                    header_fk: *header_fk,
                    tx_fks,
                    hash: *hash,
                });
            }
            self.confirm_blocks_run(&prepared)?;
            self.annotate_spends_for_confirmed(&prepared)?;
            self.apply_sh_pending()?;
        }
        let got = self.hot_digest()?.map(|d| d.digest).unwrap_or_default();
        if got != expected {
            return Err(HotImportError::DigestMismatch { expected, got });
        }
        Ok(())
    }

    fn hot_digest_tx(
        &self,
        eng: &mut sha256::HashEngine,
        fk: Fk,
        n_out: u32,
        tip: u32,
    ) -> Result<(), QueryError> {
        match self.store.txstat_row(fk)? {
            None => eng.input(&[0]),
            Some(r) => {
                eng.input(&[1]);
                eng.input(&r.fee_sat.to_le_bytes());
                eng.input(&r.base.to_le_bytes());
                eng.input(&r.wit_extra.to_le_bytes());
            }
        }
        match self.store.input_edges(fk)? {
            None => eng.input(&[0]),
            Some(edges) => {
                eng.input(&[1]);
                eng.input(&(edges.len() as u32).to_le_bytes());
                for e in edges {
                    if e.parent.is_null() {
                        eng.input(&[0]);
                        continue;
                    }
                    let (h, index) = self.hot_digest_position(e.parent)?;
                    eng.input(&[1]);
                    eng.input(&h.to_le_bytes());
                    eng.input(&index.to_le_bytes());
                    eng.input(&e.vout.to_le_bytes());
                }
            }
        }
        for vout in 0..n_out {
            let mut strong = Vec::new();
            for (spender, vin) in self.store.spenders_create(fk, vout)? {
                if self.store.is_confirmed_strong_at(spender, Some(tip))? {
                    let (h, index) = self.hot_digest_position(spender)?;
                    strong.push((h, index, vin));
                }
            }
            strong.sort_unstable();
            eng.input(&(strong.len() as u32).to_le_bytes());
            for (h, index, vin) in strong {
                eng.input(&h.to_le_bytes());
                eng.input(&index.to_le_bytes());
                eng.input(&vin.to_le_bytes());
            }
        }
        Ok(())
    }

    /// `(height, index in block)` of a connected create.
    fn hot_digest_position(&self, fk: Fk) -> Result<(u32, u32), QueryError> {
        let h = self.store.fence().height_of(fk).ok_or(StoreError::Corrupt(
            "hot digest: create not on the confirmed chain",
        ))?;
        let (first, n) = self.tx_fk_span_at_height(Height(h))?;
        let index = rbitcoin_store::HeaderTxsTable::index_in_span(first, n, fk).ok_or(
            StoreError::Corrupt("hot digest: create outside its block span"),
        )?;
        Ok((h, index))
    }
}

/// Header and body checks for one source block, with txids recomputed from
/// the rebuilt transactions. The digest covers what the publisher stored; these
/// tie it to the chain. The header is checked against the source's parent,
/// which was itself checked one height earlier, so the walk from genesis is a
/// chain of checked headers.
fn hot_import_check_block(
    src: &Query,
    params: &ChainParams,
    height: Height,
    block: &Block,
) -> Result<Vec<[u8; 32]>, HotImportError> {
    use rbitcoin_consensus::block::{validate_block_structure_hashed, ValidationContext};
    let invalid = |reason: String| HotImportError::Invalid {
        height: height.0,
        reason,
    };
    crate::header_read::validate_header(src, params, height, &block.header)
        .map_err(|e| invalid(e.to_string()))?;
    validate_block_structure_hashed(block, &ValidationContext::archive_structure(params))
        .map_err(|e| invalid(e.to_string()))
}

/// Import the store at `src` into a new store at `dst`, checked by digest.
///
/// The source must be on the current schema and have shut down cleanly:
/// `tip_seal` and `spend_durable` at its tip. A current schema means a current
/// binary already opened it and dropped older leftovers, so its open here
/// writes nothing. The destination is built in `<dst>.import` and renamed to
/// `dst` only after [`Query::import_hot`] matched, with both tip markers
/// published after a full sync so its first open checks only the tip window.
pub fn import_hot_store(
    src: StoreLayout,
    dst: StoreLayout,
    params: &ChainParams,
    expected: [u8; 32],
) -> Result<HotDigest, HotImportError> {
    use rbitcoin_store::integrity::TipSeal;
    use rbitcoin_store::spend_durable::SpendDurable;

    if dst.cold_dir.is_some() {
        return Err(HotImportError::ColdDestination);
    }
    // The node's datadir setup creates an empty `store/`; anything in it is
    // refused.
    if dst.dir.exists() {
        let mut entries = std::fs::read_dir(&dst.dir).map_err(|e| StoreError::io(&dst.dir, e))?;
        if entries.next().is_some() {
            return Err(HotImportError::NotEmpty);
        }
    }
    if rbitcoin_store::store::seqsigwit_reloc_path(&src.dir).exists() {
        return Err(HotImportError::ColdSource);
    }
    let ver = rbitcoin_store::store::check_meta(&src.dir)?;
    if ver != rbitcoin_primitives::SCHEMA_VERSION {
        return Err(HotImportError::SourceSchema(ver));
    }
    let seal = TipSeal::load(&src.dir)?
        .ok_or_else(|| HotImportError::Unclean("tip_seal is missing".into()))?;
    let marker = SpendDurable::load(&src.dir)?
        .ok_or_else(|| HotImportError::Unclean("spend_durable is missing".into()))?;
    let durable = marker.annotated_through().min(marker.durable_through());
    if durable != seal.tip_height {
        return Err(HotImportError::Unclean(format!(
            "spend_durable is at {durable}, tip is {}",
            seal.tip_height
        )));
    }
    let src = Query::open_or_create_layout(src)?;
    let tip = src.tip_height().map(|h| h.0);
    let tip_hash = match src.tip_header_fk()? {
        Some(fk) => Some(src.get_header(fk)?.hash),
        None => None,
    };
    if tip != Some(seal.tip_height) || tip_hash != Some(seal.tip_hash) {
        return Err(HotImportError::Unclean(
            "tip_seal does not match the tip".into(),
        ));
    }
    if src.prune_seqsigwit() {
        return Err(HotImportError::Pruned);
    }

    let mut name = dst.dir.file_name().unwrap_or_default().to_os_string();
    name.push(".import");
    let staging = dst.dir.with_file_name(name);
    if staging.exists() {
        // Left by an import that did not finish; never renamed, so never used.
        std::fs::remove_dir_all(&staging).map_err(|e| StoreError::io(&staging, e))?;
    }
    let built = (|| {
        let q = Query::open_or_create_layout(StoreLayout {
            dir: staging.clone(),
            ..dst.clone()
        })?;
        q.import_hot(&src, params, expected)?;
        q.store.flush()?;
        q.store.sync_spend_durable(seal.tip_height)?;
        Ok::<_, HotImportError>(())
    })();
    if let Err(e) = built {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    if dst.dir.exists() {
        // Empty (checked above); `remove_dir` refuses anything else.
        std::fs::remove_dir(&dst.dir).map_err(|e| StoreError::io(&dst.dir, e))?;
    }
    std::fs::rename(&staging, &dst.dir).map_err(|e| StoreError::io(&dst.dir, e))?;
    Ok(HotDigest {
        height: seal.tip_height,
        tip_hash: seal.tip_hash,
        digest: expected,
    })
}
