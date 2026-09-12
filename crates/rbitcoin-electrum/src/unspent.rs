//! Shared Electrum / Esplora scripthash UTXO + mempool overlay.

use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Fk;
use rbitcoin_query::{ChainView, Query, QueryError, ScriptHashUtxo, ShJoinSlot};
use rbitcoin_store::script_hash;

/// Confirmed SH UTXOs plus mempool funding, minus mempool spends (Electrum rules).
pub fn scripthash_utxos_with_mempool_slot(
    query: &Query,
    mempool: Option<&MempoolHub>,
    sh: &[u8; 32],
    slot: &mut Option<ShJoinSlot>,
) -> Result<Vec<ScriptHashUtxo>, QueryError> {
    let mut out = query.scripthash_listunspent_slot(sh, slot)?;
    overlay_mempool_utxos(query, &mut out, mempool, sh)?;
    Ok(out)
}

/// Slot UTXOs at a caller-pinned view, then the same mempool overlay.
pub fn scripthash_utxos_with_mempool_slot_in(
    query: &Query,
    mempool: Option<&MempoolHub>,
    sh: &[u8; 32],
    slot: &mut Option<ShJoinSlot>,
    view: &ChainView,
) -> Result<Vec<ScriptHashUtxo>, QueryError> {
    let mut out = query.scripthash_listunspent_slot_in(sh, slot, view)?;
    overlay_mempool_utxos(query, &mut out, mempool, sh)?;
    Ok(out)
}

fn overlay_mempool_utxos(
    query: &Query,
    out: &mut Vec<ScriptHashUtxo>,
    mempool: Option<&MempoolHub>,
    sh: &[u8; 32],
) -> Result<(), QueryError> {
    let Some(mp) = mempool else {
        return Ok(());
    };
    out.retain(|x| {
        let op = OutPoint {
            txid: bitcoin::Txid::from_byte_array(x.tx_hash),
            vout: x.tx_pos,
        };
        !mp.spends_outpoint(&op)
    });
    for item in mp.scripthash_mempool(sh) {
        if query.tx_fk_by_txid_tip(&item.txid)?.is_some() {
            continue;
        }
        let tid = bitcoin::Txid::from_byte_array(item.txid);
        let Some(tx) = mp.get_tx(&tid) else {
            continue;
        };
        for (vout, o) in tx.output.iter().enumerate() {
            if script_hash(o.script_pubkey.as_bytes()) != *sh {
                continue;
            }
            let op = OutPoint {
                txid: tid,
                vout: vout as u32,
            };
            if mp.spends_outpoint(&op) {
                continue;
            }
            out.push(ScriptHashUtxo {
                tx_hash: item.txid,
                tx_pos: vout as u32,
                height: item.height,
                value: o.value.to_sat() as i64,
                create_tx_fk: Fk::NULL,
            });
        }
    }
    Ok(())
}

/// Esplora `mempool_stats` for a scripthash (same funding/spend loops as listunspent).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MempoolShStats {
    pub tx_count: u32,
    pub funded_txo_count: u32,
    pub funded_txo_sum: i64,
    pub spent_txo_count: u32,
    pub spent_txo_sum: i64,
}

pub fn scripthash_mempool_stats_slot(
    query: &Query,
    mp: &MempoolHub,
    sh: &[u8; 32],
    slot: &mut Option<ShJoinSlot>,
) -> Result<MempoolShStats, QueryError> {
    let items = mp.scripthash_mempool(sh);
    let mut stats = MempoolShStats::default();
    for u in query.scripthash_listunspent_slot(sh, slot)? {
        let op = OutPoint {
            txid: bitcoin::Txid::from_byte_array(u.tx_hash),
            vout: u.tx_pos,
        };
        if mp.spends_outpoint(&op) {
            stats.spent_txo_count = stats.spent_txo_count.saturating_add(1);
            stats.spent_txo_sum = stats.spent_txo_sum.saturating_add(u.value);
        }
    }
    for item in items {
        if query.tx_fk_by_txid_tip(&item.txid)?.is_some() {
            continue;
        }
        stats.tx_count = stats.tx_count.saturating_add(1);
        let tid = bitcoin::Txid::from_byte_array(item.txid);
        let Some(tx) = mp.get_tx(&tid) else {
            continue;
        };
        for (vout, o) in tx.output.iter().enumerate() {
            if script_hash(o.script_pubkey.as_bytes()) != *sh {
                continue;
            }
            let op = OutPoint {
                txid: tid,
                vout: vout as u32,
            };
            if mp.spends_outpoint(&op) {
                continue;
            }
            stats.funded_txo_count = stats.funded_txo_count.saturating_add(1);
            stats.funded_txo_sum = stats.funded_txo_sum.saturating_add(o.value.to_sat() as i64);
        }
    }
    Ok(stats)
}
