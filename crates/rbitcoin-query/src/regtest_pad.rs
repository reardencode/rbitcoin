//! Regtest helpers that open a [`Query`].

use rbitcoin_consensus::{mine_regtest_paying_bits, ChainParams, Milestone};

use crate::accept_and_connect_block;
use rbitcoin_primitives::Height;

use crate::Query;

/// Connect empty blocks `from_h..=last`. Returns tip hash/time and coinbase txids
/// for heights `1..=collect_coinbases` (empty if `collect_coinbases == 0`).
pub fn pad_empty_from(
    query: &Query,
    params: &ChainParams,
    mut tip: bitcoin::BlockHash,
    mut tip_time: u32,
    from_h: u32,
    last: u32,
    collect_coinbases: u32,
) -> (bitcoin::BlockHash, u32, Vec<bitcoin::Txid>) {
    let ms = Milestone::NONE;
    let mut cbs = Vec::new();
    for h in from_h..=last {
        let time = tip_time + 600;
        let bits = crate::expected_next_bits(query, params, Height(h), time).unwrap();
        let b = mine_regtest_paying_bits(
            tip,
            time,
            h,
            bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            Vec::new(),
            bits,
        );
        if h >= 1 && h <= collect_coinbases {
            cbs.push(b.txdata[0].compute_txid());
        }
        accept_and_connect_block(query, params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    query.apply_sh_pending().unwrap();
    (tip, tip_time, cbs)
}
