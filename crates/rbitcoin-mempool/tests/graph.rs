use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
use bitcoin::{OutPoint, Transaction, Txid};
use rbitcoin_mempool::graph::*;
use std::collections::BTreeSet;

fn txid_n(n: u8) -> Txid {
    Txid::from_byte_array([n; 32])
}

fn make_tx(spend: Option<(Txid, u32)>, n_out: u32, seed: u8) -> Transaction {
    let prev = spend.unwrap_or_else(|| (txid_n(0xee), 0));
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.0,
                vout: prev.1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: (0..n_out)
            .map(|i| TxOut {
                value: Amount::from_sat(1000 + u64::from(i) + u64::from(seed)),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, seed, i as u8]),
            })
            .collect(),
    }
}

fn entry_for(tx: &Transaction, fee: u64, slot: u32) -> TxEntry {
    TxEntry {
        txid: tx.compute_txid(),
        wtxid: tx.compute_wtxid(),
        fee_sat: fee,
        weight: tx.weight().to_wu(),
        sigop_cost: 0,
        slot,
        parents: BTreeSet::new(),
        children: BTreeSet::new(),
    }
}

#[test]
fn component_rep_is_the_least_txid() {
    let mut g = TxGraph::new();
    let parent = make_tx(None, 1, 2);
    let pe = entry_for(&parent, 500, 0);
    let pid = pe.txid;
    g.insert(pe, &parent);
    let child = make_tx(Some((pid, 0)), 1, 1);
    let ce = entry_for(&child, 500, 1);
    let cid = ce.txid;
    g.insert(ce, &child);
    let least = pid.min(cid);
    let greater = pid.max(cid);
    assert_ne!(least, greater);
    let mut seen = std::collections::BTreeSet::new();
    assert_eq!(g.component_rep(greater, &mut seen), Some(least));
}

#[test]
fn single_tx_cluster() {
    let mut g = TxGraph::new();
    let tx = make_tx(None, 1, 1);
    let e = entry_for(&tx, 1000, 0);
    let id = e.txid;
    g.insert(e, &tx);
    let (n, _) = g.connected_weight(&std::collections::BTreeSet::from([id]));
    assert_eq!(n, 1);
    let c = g.cluster_of(&id).unwrap();
    assert_eq!(c.members.len(), 1);
    assert_eq!(c.linearization, vec![id]);
    assert_eq!(c.chunks.len(), 1);
}

#[test]
fn wtxid_index_insert_remove_and_loser_collision() {
    let mut g = TxGraph::new();
    let a = make_tx(None, 1, 1);
    let b = make_tx(None, 1, 2);
    let ea = entry_for(&a, 100, 0);
    let eb = entry_for(&b, 100, 1);
    let wa = ea.wtxid;
    let wb = eb.wtxid;
    let ida = ea.txid;
    let idb = eb.txid;
    assert_ne!(wa, wb);
    g.insert(ea, &a);
    g.insert(eb, &b);
    assert!(g.contains_wtxid(&wa));
    assert!(g.contains_wtxid(&wb));
    assert_eq!(g.txid_for_wtxid(&wa), Some(ida));
    assert_eq!(g.txid_for_wtxid(&wb), Some(idb));
    assert!(g.remove(&ida, &a).is_some());
    assert!(!g.contains_wtxid(&wa));
    assert_eq!(g.txid_for_wtxid(&wb), Some(idb));

    let c = make_tx(None, 1, 3);
    let d = make_tx(None, 1, 4);
    let ec = entry_for(&c, 10, 2);
    let mut ed = entry_for(&d, 10, 3);
    let collide = ec.wtxid;
    ed.wtxid = collide;
    let idc = ec.txid;
    let idd = ed.txid;
    g.insert(ec, &c);
    g.insert(ed, &d);
    assert_eq!(g.txid_for_wtxid(&collide), Some(idd), "last insert wins");
    assert!(g.remove(&idc, &c).is_some());
    assert_eq!(
        g.txid_for_wtxid(&collide),
        Some(idd),
        "removing the loser must not drop the winner"
    );
    assert!(g.remove(&idd, &d).is_some());
    assert!(!g.contains_wtxid(&collide));

    let e = make_tx(None, 1, 5);
    let ee = entry_for(&e, 1, 4);
    let we = ee.wtxid;
    g.rebuild_from(vec![(ee, std::sync::Arc::new(e.clone()))]);
    assert_eq!(g.txid_for_wtxid(&we), Some(e.compute_txid()));
    assert!(!g.contains_wtxid(&wb));
}

#[test]
fn stock_above_matches_weight_above_on_best_first_chunks() {
    let chunks = [
        Chunk {
            txids: vec![],
            fee_sat: 5_000,
            weight: 4_000,
        },
        Chunk {
            txids: vec![],
            fee_sat: 1_000,
            weight: 8_000,
        },
        Chunk {
            txids: vec![],
            fee_sat: 100,
            weight: 12_000,
        },
    ];
    let stock = StockAbove::from_best_first(&chunks);
    for rate in [0u64, 99, 100, 101, 999, 1_000, 1_001, 5_000, 5_001] {
        assert_eq!(
            stock.above(rate),
            weight_above_from_chunks(&chunks, rate),
            "rate {rate}"
        );
    }
    assert_eq!(StockAbove::from_best_first(&[]).above(0), 0);
}

#[test]
fn frontier_prefers_high_rate_chunks_and_depth() {
    let mut g = TxGraph::new();
    let a = spend_op([1u8; 32], 50_000, 40_000); // fee 10k, high rate
    let b = spend_op([2u8; 32], 50_000, 49_000); // fee 1k, low rate
    let wa = a.weight().to_wu();
    let wb = b.weight().to_wu();
    g.insert(entry_for(&a, 10_000, 0), &a);
    g.insert(entry_for(&b, 1_000, 1), &b);
    let chunks = g.mining_chunks_best_first();
    assert!(chunks.len() >= 2);
    assert!(chunks[0].fee_rate_sat_per_kvb() >= chunks[1].fee_rate_sat_per_kvb());
    // Small target hits high-rate chunk.
    let r_hi = g.frontier_feerate_sat_per_kvb(1).unwrap();
    let r_deep = g.frontier_feerate_sat_per_kvb(wa + wb).unwrap();
    assert!(r_hi >= r_deep);
    assert!(g.weight_above_feerate(0) >= wa);
    let ch = g.mining_chunks_best_first();
    assert_eq!(
        frontier_feerate_from_chunks(&ch, 1),
        g.frontier_feerate_sat_per_kvb(1)
    );
    assert!(
        frontier_feerate_from_chunks(&ch, wa + wb + 1).is_none(),
        "under-full target must not use last_chunk as a far-horizon rate"
    );
    assert_eq!(weight_above_from_chunks(&ch, 0), g.weight_above_feerate(0));
    let a2 = g.mining_chunks_best_first();
    let b2 = g.mining_chunks_best_first();
    assert_eq!(a2, b2, "a second walk reuses the cached chunks");
}

#[test]
fn select_block_txids_empty_parent_before_child_and_weight_cap() {
    let g = TxGraph::new();
    assert!(select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0).is_empty());
    assert!(select_ids(&g, budget(0), |_| 0).is_empty());

    let mut g = TxGraph::new();
    let parent = spend_op([1u8; 32], 50_000, 40_000);
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(30_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    g.insert(entry_for(&parent, 1_000, 0), &parent);
    g.insert(entry_for(&child, 10_000, 1), &child);
    let order = select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0);
    assert_eq!(
        order,
        vec![parent.compute_txid(), child.compute_txid()],
        "parent before child even if child chunk is hotter: {order:?}"
    );

    let mut g = TxGraph::new();
    let hi = spend_op([2u8; 32], 50_000, 40_000);
    let lo = spend_op([3u8; 32], 50_000, 49_000);
    let wh = hi.weight().to_wu();
    let wl = lo.weight().to_wu();
    g.insert(entry_for(&hi, 10_000, 0), &hi);
    g.insert(entry_for(&lo, 1_000, 1), &lo);
    let only_hi = select_ids(&g, budget(wh), |_| 0);
    assert_eq!(only_hi, vec![hi.compute_txid()]);
    let both = select_ids(&g, budget(wh.saturating_add(wl)), |_| 0);
    assert_eq!(both, vec![hi.compute_txid(), lo.compute_txid()]);
    assert!(select_ids(&g, budget(wh.saturating_sub(1)), |_| 0).is_empty());

    let hid = hi.compute_txid();
    let lid = lo.compute_txid();
    let depri = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
        if id == hid {
            -10_000
        } else {
            0
        }
    });
    assert_eq!(
        depri,
        vec![lid, hid],
        "zero modified fee stays selectable; hotter lid ranks first"
    );
    let depri_neg = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
        if id == hid {
            -10_001
        } else {
            0
        }
    });
    assert_eq!(depri_neg, vec![lid], "negative modified fee is not mined");
    let bump = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
        if id == lid {
            86 * 100_000_000
        } else {
            0
        }
    });
    assert_eq!(bump[0], lid, "i64-sized delta reorders selection");
    let bumped = g.select_block_template(
        budget(TxGraph::template_tx_weight()),
        |id| {
            if id == lid {
                86 * 100_000_000
            } else {
                0
            }
        },
        |_| false,
    );
    assert_eq!(bumped[0].fee_sat, 1_000, "selection reports the base fee");

    // Child deprioritised to 0 stays out even when it shares a package with parent.
    let mut g = TxGraph::new();
    let parent = spend_op([4u8; 32], 50_000, 40_000);
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(30_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    g.insert(entry_for(&parent, 10_000, 0), &parent);
    g.insert(entry_for(&child, 1_000, 1), &child);
    let cid = child.compute_txid();
    let pid = parent.compute_txid();
    let only_p = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
        if id == cid {
            -1_000
        } else {
            0
        }
    });
    assert_eq!(
        only_p,
        vec![pid, cid],
        "zero-modified child stays selectable with parent"
    );
    let only_p_neg = select_ids(&g, budget(TxGraph::template_tx_weight()), |id| {
        if id == cid {
            -1_001
        } else {
            0
        }
    });
    assert_eq!(
        only_p_neg,
        vec![pid],
        "negative-modified child is not mined with parent"
    );
}

/// Base-fee chunking merges a paying parent with a hotter child. A negative
/// `prioritisetransaction` on the child splits that chunk: the parent stays
/// in the template and `chunk_of` reports the parent's own modified fee.
/// A positive delta on a cheap child does the reverse and reports one chunk.
#[test]
fn modified_fee_rechunks_parent_and_child() {
    let mut g = TxGraph::new();
    let parent = spend_op([0x51u8; 32], 0, 40_000);
    let pid = parent.compute_txid();
    let child = make_tx(Some((pid, 0)), 1, 0x52);
    let cid = child.compute_txid();
    g.insert(entry_for(&parent, 1_000, 0), &parent);
    g.insert(entry_for(&child, 50_000, 1), &child);
    assert_eq!(
        g.cluster_of(&pid).unwrap().chunks.len(),
        1,
        "base fees merge the paying parent with the hotter child"
    );
    let drop = |id: Txid| {
        if id == cid {
            -(50_000 + 1_000 + 1)
        } else {
            0
        }
    };
    assert_eq!(
        select_ids(&g, budget(TxGraph::template_tx_weight()), drop),
        vec![pid],
        "a negative child delta drops the child and keeps the parent"
    );
    let (fee, weight, txs) = g.chunk_of(&pid, drop).unwrap();
    assert_eq!(txs, vec![pid]);
    assert_eq!(fee, 1_000);
    assert_eq!(weight, parent.weight().to_wu());
    let (cfee, _, ctxs) = g.chunk_of(&cid, drop).unwrap();
    assert_eq!(ctxs, vec![cid]);
    assert_eq!(cfee, 50_000 - (50_000 + 1_000 + 1));

    let mut g = TxGraph::new();
    let parent = spend_op([0x71u8; 32], 0, 40_000);
    let pid = parent.compute_txid();
    let child = make_tx(Some((pid, 0)), 1, 0x72);
    let cid = child.compute_txid();
    g.insert(entry_for(&parent, 0, 0), &parent);
    g.insert(entry_for(&child, 100_000, 1), &child);
    let floor = SelectBudget {
        min_sat_kvb: 1_000,
        ..budget(TxGraph::template_tx_weight())
    };
    assert_eq!(select_ids(&g, floor, |_| 0), vec![pid, cid]);
    let drop = |id: Txid| if id == cid { -100_001 } else { 0 };
    assert_eq!(
        select_ids(&g, floor, drop),
        Vec::<Txid>::new(),
        "a deprioritised child no longer carries a parent under the floor"
    );

    let mut g = TxGraph::new();
    let parent = spend_op([0x61u8; 32], 0, 40_000);
    let pid = parent.compute_txid();
    let child = make_tx(Some((pid, 0)), 1, 0x62);
    let cid = child.compute_txid();
    let rival = spend_op([0x63u8; 32], 0, 30_000);
    let rid = rival.compute_txid();
    g.insert(entry_for(&parent, 1_000, 0), &parent);
    g.insert(entry_for(&child, 100, 1), &child);
    g.insert(entry_for(&rival, 5_000, 2), &rival);
    let alone = select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0);
    assert_eq!(
        alone.first().copied(),
        Some(rid),
        "without a delta the rival outranks the parent: {alone:?}"
    );
    let boost = |id: Txid| if id == cid { 80_000 } else { 0 };
    let picked = select_ids(&g, budget(TxGraph::template_tx_weight()), boost);
    assert_eq!(picked[..2], [pid, cid]);
    let (fee, _, txs) = g.chunk_of(&pid, boost).unwrap();
    assert_eq!(txs, vec![pid, cid]);
    assert_eq!(fee, 1_000 + 100 + 80_000);
}

/// Core `TestChunkBlockLimits`: a chunk that would overflow weight is
/// skipped and later, smaller chunks still fill the block.
#[test]
fn select_skips_overweight_chunk_and_continues() {
    let mut g = TxGraph::new();
    let hot = spend_op([5u8; 32], 50_000, 40_000);
    let big = make_tx(Some((txid_n(6), 0)), 40, 6);
    let cold = spend_op([7u8; 32], 50_000, 49_000);
    g.insert(entry_for(&hot, 100_000, 0), &hot);
    g.insert(entry_for(&big, 100_000, 1), &big);
    g.insert(entry_for(&cold, 100, 2), &cold);
    let cap = hot.weight().to_wu() + cold.weight().to_wu();
    assert!(big.weight().to_wu() > cold.weight().to_wu());
    assert_eq!(
        select_ids(&g, budget(cap), |_| 0),
        vec![hot.compute_txid(), cold.compute_txid()]
    );
}

/// Sigop budget starts at the caller's reserve. A running cost of
/// exactly 80_000 fits; a chunk that would pass 80_000 is skipped and a
/// later, cheaper chunk still fits. Each pick carries the base fee and
/// sigop cost it was budgeted with.
#[test]
fn select_budgets_sigops_skip_and_continue() {
    let heavy = spend_op([8u8; 32], 50_000, 40_000);
    let light = spend_op([9u8; 32], 50_000, 49_000);
    let (hid, lid) = (heavy.compute_txid(), light.compute_txid());
    let pool = |heavy_cost: u64| {
        let mut g = TxGraph::new();
        // Budget only: keep heavy ranked first by raw feerate.
        g.set_bytes_per_sigop(0);
        let mut e = entry_for(&heavy, 10_000, 0);
        e.sigop_cost = heavy_cost;
        g.insert(e, &heavy);
        let mut e = entry_for(&light, 1_000, 1);
        e.sigop_cost = 1;
        g.insert(e, &light);
        g
    };
    let at = |g: &TxGraph, reserved_sigops| {
        let b = SelectBudget {
            reserved_sigops,
            ..budget(TxGraph::template_tx_weight())
        };
        select_ids(g, b, |_| 0)
    };
    let full = |heavy_cost| at(&pool(heavy_cost), COINBASE_SIGOPS_RESERVE);
    assert_eq!(full(79_601), vec![lid], "400 + 79_601 passes 80_000");
    assert_eq!(
        full(79_600),
        vec![hid],
        "400 + 79_600 equals 80_000 and fits"
    );
    assert_eq!(
        full(79_599),
        vec![hid, lid],
        "light's +1 lands on 80_000 and fits"
    );
    assert_eq!(full(u64::MAX), vec![lid], "unknown cost never selected");

    let g = pool(79_598);
    assert_eq!(
        g.select_block_template(budget(TxGraph::template_tx_weight()), |_| 0, |_| false),
        vec![
            Selected {
                txid: hid,
                fee_sat: 10_000,
                sigop_cost: 79_598
            },
            Selected {
                txid: lid,
                fee_sat: 1_000,
                sigop_cost: 1
            },
        ]
    );
    assert_eq!(at(&g, 402), vec![hid], "a larger reserve drops the tail");
    assert_eq!(at(&g, 403), vec![lid], "skips heavy, still takes light");
    assert_eq!(at(&g, 0), vec![hid, lid]);
}

fn budget(max_weight_wu: u64) -> SelectBudget {
    SelectBudget {
        max_weight_wu,
        reserved_sigops: COINBASE_SIGOPS_RESERVE,
        min_sat_kvb: 0,
    }
}

fn select_ids(g: &TxGraph, budget: SelectBudget, delta: impl Fn(Txid) -> i64) -> Vec<Txid> {
    g.select_block_template(budget, delta, |_| false)
        .into_iter()
        .map(|s| s.txid)
        .collect()
}

fn spend_op(seed: [u8; 32], _inv: u64, outv: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(seed),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(outv),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

#[test]
fn insert_parent_after_child_wires_reorg_edges() {
    let mut g = TxGraph::new();
    let parent = make_tx(None, 1, 2);
    let pid = parent.compute_txid();
    let child = make_tx(Some((pid, 0)), 1, 3);
    let cid = child.compute_txid();
    g.insert(entry_for(&child, 1000, 0), &child);
    assert_eq!(g.graph_stats(&cid).unwrap().ancestorcount, 1);
    g.insert(entry_for(&parent, 1000, 1), &parent);
    assert_eq!(g.graph_stats(&cid).unwrap().ancestorcount, 2);
    assert_eq!(g.graph_stats(&pid).unwrap().descendantcount, 2);
}

#[test]
fn parent_child_same_cluster_linearized() {
    let mut g = TxGraph::new();
    let parent = make_tx(None, 1, 2);
    let pe = entry_for(&parent, 500, 0);
    let pid = pe.txid;
    g.insert(pe, &parent);

    let child = make_tx(Some((pid, 0)), 1, 3);
    let ce = entry_for(&child, 5000, 1); // higher fee rate child
    let cid = ce.txid;
    g.insert(ce, &child);

    let c = g.cluster_of(&pid).unwrap();
    assert_eq!(c.members.len(), 2);
    assert_eq!(c.linearization, vec![pid, cid]);

    let ps = g.graph_stats(&pid).unwrap();
    let cs = g.graph_stats(&cid).unwrap();
    assert_eq!(ps.ancestorcount, 1);
    assert_eq!(ps.descendantcount, 2);
    assert_eq!(cs.ancestorcount, 2);
    assert_eq!(cs.descendantcount, 1);
    assert_eq!(cs.ancestorfees, 500 + 5000);
    assert_eq!(ps.descendantfees, 500 + 5000);
    // Hot child pulls the cheap parent into one chunk (CPFP).
    assert_eq!(c.chunks.len(), 1);
    assert_eq!(c.chunks[0].txids, vec![pid, cid]);
}

#[test]
fn graph_stats_size_sums_per_tx_virtual_size() {
    let mut g = TxGraph::new();
    let parent = make_tx(None, 1, 2);
    let mut pe = entry_for(&parent, 500, 0);
    pe.weight = 1;
    let pid = pe.txid;
    g.insert(pe, &parent);
    let child = make_tx(Some((pid, 0)), 1, 3);
    let mut ce = entry_for(&child, 5000, 1);
    ce.weight = 5;
    let cid = ce.txid;
    g.insert(ce, &child);
    let ps = g.graph_stats(&pid).unwrap();
    let cs = g.graph_stats(&cid).unwrap();
    assert_eq!(
        ps.ancestorsize,
        bitcoin::Weight::from_wu(1).to_vbytes_ceil()
    );
    assert_eq!(
        ps.descendantsize,
        bitcoin::Weight::from_wu(1).to_vbytes_ceil() + bitcoin::Weight::from_wu(5).to_vbytes_ceil()
    );
    assert_eq!(
        cs.ancestorsize,
        bitcoin::Weight::from_wu(1).to_vbytes_ceil() + bitcoin::Weight::from_wu(5).to_vbytes_ceil()
    );
    assert_eq!(
        cs.descendantsize,
        bitcoin::Weight::from_wu(5).to_vbytes_ceil()
    );
    assert_ne!(ps.descendantsize, (1 + 5) / 4);
}

#[test]
fn diamond_cheap_parent_hot_children_cheap_sink_two_chunks() {
    // a (cheap, 2 outs) → b,c (hot) → d (cheap). Prefix-maximal: [a,b,c] then [d].
    let mut g = TxGraph::new();
    let a = make_tx(None, 2, 1);
    let ae = entry_for(&a, 2_000, 0);
    let aid = ae.txid;
    g.insert(ae, &a);
    let b = make_tx(Some((aid, 0)), 1, 2);
    let be = entry_for(&b, 31_200, 1);
    let bid = be.txid;
    g.insert(be, &b);
    let c = make_tx(Some((aid, 1)), 1, 3);
    let ce = entry_for(&c, 31_200, 2);
    let cid = ce.txid;
    g.insert(ce, &c);
    let d = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: bid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint { txid: cid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    g.insert(entry_for(&d, 1_000, 3), &d);
    let did = d.compute_txid();
    let cl = g.cluster_of(&aid).unwrap();
    assert_eq!(cl.members.len(), 4);
    assert_eq!(cl.chunks.len(), 2, "chunks: {:?}", cl.chunks);
    let first: BTreeSet<Txid> = cl.chunks[0].txids.iter().copied().collect();
    assert_eq!(first, [aid, bid, cid].into_iter().collect());
    assert_eq!(cl.chunks[1].txids, vec![did]);
    let (fee, w, txs) = g.chunk_of(&aid, |_| 0).unwrap();
    assert_eq!(fee, 2_000 + 31_200 + 31_200);
    assert_eq!(w, cl.chunks[0].weight);
    assert_eq!(txs.len(), 3);
    let (d_fee, _, d_txs) = g
        .chunk_of(&did, |id| if id == bid { 9_999 } else { 0 })
        .unwrap();
    assert_eq!(d_txs, vec![did]);
    assert_eq!(d_fee, 1_000, "d's chunk fee ignores sibling deltas");
}

#[test]
fn oversize_cluster_detected() {
    let mut g = TxGraph::new();
    let mut prev_id = txid_n(0xee);
    let mut last = txid_n(0);
    for i in 0..MAX_CLUSTER_COUNT {
        let tx = make_tx(Some((prev_id, 0)), 1, i as u8);
        let e = entry_for(&tx, 100, i as u32);
        prev_id = e.txid;
        last = e.txid;
        g.insert(e, &tx);
    }
    let c = g.cluster_of(&last).unwrap();
    assert_eq!(c.members.len(), MAX_CLUSTER_COUNT);
    let parents: BTreeSet<Txid> = [last].into_iter().collect();
    assert!(g.cluster_would_exceed(&parents, 1, 100));
}

#[test]
fn cluster_limits_overlay_count() {
    let mut g = TxGraph::new();
    g.set_cluster_limits(Some(1), None);
    let parent = make_tx(None, 1, 1);
    let pe = entry_for(&parent, 100, 0);
    let pid = pe.txid;
    g.insert(pe, &parent);
    let mut parents = BTreeSet::new();
    parents.insert(pid);
    assert!(
        g.cluster_would_exceed(&parents, 1, 400),
        "count limit 1 must reject a child"
    );
    g.set_cluster_limits(Some(2), None);
    assert!(!g.cluster_would_exceed(&parents, 1, 400));
}

#[test]
fn cluster_weight_cap_matches_core_101kvb() {
    // Core DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 → 101_000 vB → 404_000 WU.
    assert_eq!(MAX_CLUSTER_VSIZE, 101_000);
    assert_eq!(MAX_CLUSTER_WEIGHT, 404_000);
    let g = TxGraph::new();
    let empty = BTreeSet::new();
    assert!(!g.cluster_would_exceed(&empty, 1, 200_000));
    // Single-tx 405 kWU exceeds (would also fail MAX_STANDARD_TX_WEIGHT=400k).
    assert!(g.cluster_would_exceed(&empty, 1, 405_000));
    // Just over old wrong 101 kWU cap must still be allowed.
    assert!(!g.cluster_would_exceed(&empty, 1, 102_790));
}

#[test]
fn conflict_set_fee_weight_remove_and_worst() {
    let mut g = TxGraph::new();
    let parent = make_tx(None, 1, 10);
    let pe = entry_for(&parent, 100, 0);
    let pid = pe.txid;
    g.insert(pe, &parent);

    let child = make_tx(Some((pid, 0)), 1, 11);
    let ce = entry_for(&child, 50, 1);
    let cid = ce.txid;
    g.insert(ce, &child);

    assert!(g.cluster_of(&txid_n(0xff)).is_none());

    let direct = vec![pid];
    let set = g.conflict_set(&direct);
    assert!(set.contains(&pid));
    assert!(set.contains(&cid));
    let (fee, w) = g.set_fee_weight(&set);
    assert_eq!(fee, 150);
    assert!(w > 0);

    assert!(g.worst_chunk().is_some());

    assert!(g.remove(&cid, &child).is_some());
    assert!(!g.contains(&cid));
    assert!(g.remove(&pid, &parent).is_some());
    assert!(g.worst_chunk().is_none());
    assert!(g.remove(&pid, &parent).is_none());
}

#[test]
fn worst_chunk_index_picks_lowest_rate_then_repairs() {
    let mut g = TxGraph::new();
    let cheap = spend_op([1u8; 32], 50_000, 49_000);
    let dear = spend_op([2u8; 32], 50_000, 40_000);
    g.insert(entry_for(&cheap, 1_000, 0), &cheap);
    g.insert(entry_for(&dear, 10_000, 1), &dear);
    let (rep, ch) = g.worst_chunk().expect("non-empty");
    let cheap_id = cheap.compute_txid();
    let dear_id = dear.compute_txid();
    assert_eq!(rep, cheap_id);
    assert_eq!(ch.txids, vec![cheap_id]);
    assert!(g.remove(&cheap_id, &cheap).is_some());
    let (rep2, ch2) = g.worst_chunk().expect("dear remains");
    assert_eq!(rep2, dear_id);
    assert_eq!(ch2.txids, vec![dear_id]);
    let child = make_tx(Some((dear_id, 0)), 1, 9);
    g.insert(entry_for(&child, 1, 2), &child);
    let (rep3, ch3) = g.worst_chunk().expect("merged cluster");
    let members: BTreeSet<Txid> = ch3.txids.iter().copied().collect();
    assert!(members.contains(&dear_id) || rep3 == dear_id.min(child.compute_txid()));
    assert!(g.remove(&child.compute_txid(), &child).is_some());
    let (rep4, _) = g.worst_chunk().expect("split back to dear");
    assert_eq!(rep4, dear_id);
}

#[test]
fn rebuild_from_orders_parents_first() {
    let mut g = TxGraph::new();
    // Both spenders sort before the parent. A readiness bug inserts them
    // first, and `insert` backfills only the last tx recorded on that
    // output, so one spender loses the parent edge.
    let (parent, a, b) = (1..250u8)
        .find_map(|seed| {
            let parent = make_tx(None, 1, seed);
            let pid = parent.compute_txid();
            let a = make_tx(Some((pid, 0)), 1, seed.wrapping_add(1));
            let b = make_tx(Some((pid, 0)), 1, seed.wrapping_add(2));
            (a.compute_txid() < pid && b.compute_txid() < pid).then_some((parent, a, b))
        })
        .expect("two spender txids that sort before the parent");
    let pid = parent.compute_txid();
    let items = vec![
        (entry_for(&a, 10, 1), std::sync::Arc::new(a.clone())),
        (entry_for(&b, 10, 2), std::sync::Arc::new(b.clone())),
        (
            entry_for(&parent, 10, 0),
            std::sync::Arc::new(parent.clone()),
        ),
    ];
    g.rebuild_from(items);
    assert_eq!(g.cluster_of(&pid).unwrap().members.len(), 3);
    for child in [&a, &b] {
        assert!(
            g.get(&child.compute_txid()).unwrap().parents.contains(&pid),
            "rebuild links every spender after the parent is inserted"
        );
    }
}

/// Core `GetSigOpsAdjustedWeight`: `max(weight, sigop_cost × bytes_per_sigop)`.
#[test]
fn adjusted_weight_is_max_of_weight_and_sigop_bytes() {
    let tx = make_tx(None, 1, 1);
    let mut e = entry_for(&tx, 0, 0);
    e.weight = 400;
    e.sigop_cost = 21;
    assert_eq!(e.adjusted_weight(20), 420);
    e.sigop_cost = 19;
    assert_eq!(e.adjusted_weight(20), 400);
    e.sigop_cost = 21;
    assert_eq!(e.adjusted_weight(0), 400, "0 B/sigop disables");
    e.sigop_cost = u64::MAX;
    assert_eq!(e.adjusted_weight(2), u64::MAX);
}

/// Chunk feerate, template order and eviction rank on sigop-adjusted size;
/// re-configuring bytes-per-sigop re-ranks the live set.
#[test]
fn chunk_rank_uses_sigop_adjusted_weight() {
    let mut g = TxGraph::new();
    let heavy = spend_op([1u8; 32], 0, 1);
    let light = spend_op([2u8; 32], 0, 2);
    let (hid, lid) = (heavy.compute_txid(), light.compute_txid());
    let mut he = entry_for(&heavy, 2_000, 0);
    he.sigop_cost = 1_000; // 20_000 WU at 20 B/sigop
    g.insert(he, &heavy);
    g.insert(entry_for(&light, 1_000, 1), &light);
    let order = |g: &TxGraph| select_ids(g, budget(TxGraph::template_tx_weight()), |_| 0);
    assert_eq!(order(&g), vec![lid, hid]);
    assert_eq!(g.worst_chunk().unwrap().1.txids, vec![hid]);
    assert_eq!(g.mining_chunks_best_first()[1].weight, 20_000);
    g.set_bytes_per_sigop(0);
    assert_eq!(order(&g), vec![hid, lid]);
    assert_eq!(g.worst_chunk().unwrap().1.txids, vec![lid]);
    assert_eq!(
        g.mining_chunks_best_first()[0].weight,
        heavy.weight().to_wu()
    );
}

#[test]
fn block_min_fee_matches_core_getfee() {
    // 200 vB paying 1 sat meets 1 sat/kvB (1e3 >= 200) and any zero floor.
    assert!(meets_block_min_feerate(1, 800, 1));
    assert!(meets_block_min_feerate(0, 800, 0));
    assert!(!meets_block_min_feerate(0, 800, 1));
    assert!(meets_block_min_feerate(250, 1000, 1000));
    assert!(!meets_block_min_feerate(249, 1000, 1000));
    // 40 sat/kvB on 111 vB (5 sat) must not meet a 50 sat/kvB floor.
    assert!(!meets_block_min_feerate(5, 444, 50));
}

/// Core applies `-blockmintxfee` to the chunk feerate: a zero-fee parent
/// rides in with its CPFP child (never the child alone), and a lone tx is
/// in at exactly the floor and out one sat/kvB above it.
#[test]
fn block_min_fee_floors_whole_chunk() {
    let mut g = TxGraph::new();
    let p = spend_op([0x41u8; 32], 0, 50_000);
    let pid = p.compute_txid();
    let c = make_tx(Some((pid, 0)), 1, 0x42);
    let lone = spend_op([0x43u8; 32], 0, 40_000);
    let lv = lone.weight().to_wu().div_ceil(4);
    g.insert(entry_for(&p, 0, 0), &p);
    g.insert(entry_for(&c, 100_000, 1), &c);
    g.insert(entry_for(&lone, lv, 2), &lone);
    let sel = |min| {
        select_ids(
            &g,
            SelectBudget {
                min_sat_kvb: min,
                ..budget(TxGraph::template_tx_weight())
            },
            |_| 0,
        )
    };
    let (cid, lid) = (c.compute_txid(), lone.compute_txid());
    assert_eq!(sel(1_000), vec![pid, cid, lid]);
    assert_eq!(sel(1_001), vec![pid, cid]);
}

/// The block weight budget counts raw weight: two sigop-dense txs whose
/// adjusted weight overflows the cap still both fit on raw weight.
#[test]
fn select_weight_budget_is_raw_not_adjusted() {
    let mut g = TxGraph::new();
    let a = spend_op([0x31u8; 32], 0, 1);
    let b = spend_op([0x32u8; 32], 0, 2);
    for (i, tx) in [&a, &b].into_iter().enumerate() {
        let mut e = entry_for(tx, 10_000, i as u32);
        e.sigop_cost = 1_000; // 20_000 WU adjusted, far above raw
        g.insert(e, tx);
    }
    let cap = a.weight().to_wu() + b.weight().to_wu();
    assert!(cap < 20_000);
    assert_eq!(select_ids(&g, budget(cap), |_| 0).len(), 2);
}

/// Post-migrate recompute: filling an unknown (`u64::MAX`) cost re-ranks
/// the cluster, so eviction and mining see the real feerate.
#[test]
fn set_sigop_cost_reranks_cluster() {
    let mut g = TxGraph::new();
    let rich = spend_op([3u8; 32], 0, 1);
    let poor = spend_op([4u8; 32], 0, 2);
    let (rid, pid) = (rich.compute_txid(), poor.compute_txid());
    let mut re = entry_for(&rich, 100_000, 0);
    re.sigop_cost = u64::MAX;
    g.insert(re, &rich);
    g.insert(entry_for(&poor, 100, 1), &poor);
    assert_eq!(g.worst_chunk().unwrap().1.txids, vec![rid]);
    assert_eq!(
        select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0),
        vec![pid]
    );
    g.set_sigop_cost(&rid, 0);
    assert_eq!(g.worst_chunk().unwrap().1.txids, vec![pid]);
    assert_eq!(
        select_ids(&g, budget(TxGraph::template_tx_weight()), |_| 0),
        vec![rid, pid]
    );
}

/// Core `mempool_sigoplimit.py`: ancestor/descendant sizes sum the
/// sigop-adjusted vsize.
#[test]
fn graph_stats_sizes_use_sigop_adjusted_vsize() {
    let mut g = TxGraph::new();
    let parent = make_tx(None, 1, 2);
    let pid = parent.compute_txid();
    let child = make_tx(Some((pid, 0)), 1, 3);
    let cid = child.compute_txid();
    let pv = bitcoin::Weight::from_wu(parent.weight().to_wu()).to_vbytes_ceil();
    g.insert(entry_for(&parent, 500, 0), &parent);
    let mut ce = entry_for(&child, 500, 1);
    ce.sigop_cost = 69; // 1_380 WU → 345 vB
    g.insert(ce, &child);
    let cs = g.graph_stats(&cid).unwrap();
    assert_eq!((cs.ancestorsize, cs.descendantsize), (pv + 345, 345));
    let ps = g.graph_stats(&pid).unwrap();
    assert_eq!((ps.ancestorsize, ps.descendantsize), (pv, pv + 345));
}

/// Libre divergence from Core `test_sigops_package`: cluster limits count
/// raw weight, so a tx at 50,000 sigop cost (1,000,000 WU adjusted, far
/// past 101 kvB) still takes a child; only feerate uses adjusted size.
#[test]
fn cluster_limits_use_raw_weight() {
    let mut g = TxGraph::new();
    let parent = make_tx(None, 1, 2);
    let pid = parent.compute_txid();
    let mut pe = entry_for(&parent, 500, 0);
    pe.sigop_cost = 50_000;
    g.insert(pe, &parent);
    let raw = parent.weight().to_wu();
    assert_eq!(g.cluster_of(&pid).unwrap().total_weight, raw);
    assert_eq!(g.mining_chunks_best_first()[0].weight, 1_000_000);
    let parents = BTreeSet::from([pid]);
    assert!(!g.cluster_would_exceed(&parents, 1, 1));
    let room = MAX_CLUSTER_WEIGHT - raw;
    assert!(!g.cluster_would_exceed(&parents, 1, room));
    assert!(g.cluster_would_exceed(&parents, 1, room + 4));
}

/// Empty-pool cluster cap. `getmempoolinfo` on an empty pool does not
/// report this constant. The first admit compares the new tx against it.
#[test]
fn empty_graph_reports_the_cluster_weight_cap() {
    let g = TxGraph::new();
    assert!(g.is_empty());
    assert_eq!(g.total_weight(), 0);
    assert_eq!(g.cluster_weight_limit(), MAX_CLUSTER_WEIGHT);
    let tx = make_tx(None, 1, 9);
    let mut g = g;
    g.insert(entry_for(&tx, 1, 0), &tx);
    assert!(!g.is_empty());
    assert!(g.total_weight() > 1);
}
