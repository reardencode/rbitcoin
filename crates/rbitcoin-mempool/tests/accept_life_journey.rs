/// Confirmed UTXO view that the journey's blocks move. A coin a block spent
/// is `KnownUnavailable`. An outpoint the chain never saw is `Unknown`.
#[derive(Default)]
struct LifeChain {
    unspent: HashMap<OutPoint, Coin>,
    spent: HashMap<OutPoint, Coin>,
    funded: u32,
}

impl LifeChain {
    fn fund(&mut self, value: u64) -> OutPoint {
        self.fund_at(value, 1, false)
    }

    fn fund_at(&mut self, value: u64, height: u32, is_coinbase: bool) -> OutPoint {
        self.funded += 1;
        let mut id = [0xc0; 32];
        id[..4].copy_from_slice(&self.funded.to_le_bytes());
        let op = out(Txid::from_byte_array(id), 0);
        let txout = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        self.unspent.insert(
            op,
            Coin {
                create_height: height,
                is_coinbase,
                ..coin(txout)
            },
        );
        op
    }

    fn spend(&mut self, op: OutPoint) {
        if let Some(c) = self.unspent.remove(&op) {
            self.spent.insert(op, c);
        }
    }

    fn confirm(&mut self, tx: &Transaction, height: u32) {
        for inp in &tx.input {
            self.spend(inp.previous_output);
        }
        let txid = tx.compute_txid();
        for (vout, txout) in tx.output.iter().enumerate() {
            self.unspent.insert(
                out(txid, vout as u32),
                Coin {
                    create_height: height,
                    ..coin(txout.clone())
                },
            );
        }
    }

    fn disconnect(&mut self, tx: &Transaction) {
        let txid = tx.compute_txid();
        for vout in 0..tx.output.len() {
            self.unspent.remove(&out(txid, vout as u32));
        }
        for inp in &tx.input {
            if let Some(c) = self.spent.remove(&inp.previous_output) {
                self.unspent.insert(inp.previous_output, c);
            }
        }
    }
}

impl UtxoProvider for LifeChain {
    fn get_coin(&self, op: &OutPoint) -> Option<Coin> {
        self.unspent.get(op).cloned()
    }

    fn chain_prevout(&self, op: &OutPoint) -> ChainPrevout {
        match self.unspent.get(op) {
            Some(c) => ChainPrevout::Unspent(c.clone()),
            None if self.spent.contains_key(op) => ChainPrevout::KnownUnavailable,
            None => ChainPrevout::Unknown,
        }
    }
}

/// One mempool, the chain it accepts against, and that chain's tip.
struct Life {
    mp: ActiveMempool,
    chain: LifeChain,
    tip: ChainTipCtx,
}

impl Life {
    fn accept(&mut self, tx: &Transaction) -> Result<AcceptResult, AcceptError> {
        self.mp.accept_tx(tx, &self.chain, self.tip)
    }

    fn package(&mut self, txs: &[Transaction]) -> Result<Vec<AcceptResult>, AcceptError> {
        self.mp.accept_package(txs, &self.chain, self.tip)
    }

    fn live(&self, tx: &Transaction) -> bool {
        self.mp.graph.contains(&tx.compute_txid())
    }

    fn live_set(&self) -> BTreeSet<Txid> {
        self.mp.graph.iter().map(|(t, _)| *t).collect()
    }

    fn cluster_len(&self, tx: &Transaction) -> usize {
        self.mp
            .graph
            .cluster_of(&tx.compute_txid())
            .map_or(0, |c| c.members.len())
    }
}

fn out(txid: Txid, vout: u32) -> OutPoint {
    OutPoint { txid, vout }
}

/// One OP_TRUE output of `out_value`, spending every `ops`.
fn spend_all(ops: &[OutPoint], out_value: u64) -> Transaction {
    let mut tx = spend_tx(ops[0], out_value);
    tx.input = ops
        .iter()
        .map(|op| TxIn {
            previous_output: *op,
            ..tx.input[0].clone()
        })
        .collect();
    tx
}

/// One OP_TRUE output per value in `values`.
fn fan_out(op: OutPoint, values: &[u64]) -> Transaction {
    let mut tx = spend_tx(op, 0);
    tx.output = values
        .iter()
        .map(|v| TxOut {
            value: Amount::from_sat(*v),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        })
        .collect();
    tx
}

/// Zero-value `OP_RETURN` followed by `nops` OP_NOPs.
fn op_return_pad(nops: usize) -> TxOut {
    let mut script = vec![0x6a];
    script.resize(1 + nops, 0x61);
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn with_annex(mut tx: Transaction) -> Transaction {
    tx.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]);
    tx
}

/// The child arrives first and parks in RAM. The re-announce is not fresh.
/// A dry-run sibling does not park. The parent promotes the parked child
/// into one cluster, and a spend of the parent's missing vout is a reject.
fn orphan_parks_then_promotes(life: &mut Life) {
    let parent = spend_tx(life.chain.fund(100_000), 99_000);
    let pid = parent.compute_txid();
    let child = spend_tx(out(pid, 0), 98_000);
    assert!(matches!(
        life.accept(&child),
        Err(AcceptError::Orphaned { fresh: true, .. })
    ));
    assert!(matches!(
        life.accept(&child),
        Err(AcceptError::Orphaned { fresh: false, .. })
    ));
    assert_eq!((life.mp.orphan_count(), life.mp.live_count()), (1, 0));
    let dry = spend_tx(out(pid, 0), 97_000);
    let err = life
        .mp
        .prepare_admit(
            &dry,
            &life.chain,
            life.tip,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: false,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
},
        )
        .unwrap_err();
    assert!(matches!(err, AcceptError::MissingPrevout(_)), "{err}");
    assert_eq!(life.mp.orphan_count(), 1);

    life.accept(&parent).expect("parent");
    assert_eq!(life.mp.orphan_count(), 0);
    assert!(life.live(&child));
    assert!(!life.live(&dry));
    assert_eq!(life.cluster_len(&parent), 2);
    let err = life.accept(&spend_tx(out(pid, 9), 1_000)).unwrap_err();
    assert!(matches!(err, AcceptError::MissingPrevout(_)), "{err}");
    assert_eq!(life.mp.orphan_count(), 0);
}

/// A child of an invalid parent, and a spend of a coin a block already
/// spent, are hard rejects, not orphans.
fn invalid_or_spent_parent_does_not_park(life: &mut Life) {
    let mut dup = spend_tx(life.chain.fund(100_000), 99_000);
    dup.input.push(dup.input[0].clone());
    assert!(matches!(
        life.accept(&dup),
        Err(AcceptError::InputsDuplicate)
    ));
    let err = life
        .accept(&spend_tx(out(dup.compute_txid(), 0), 1_000))
        .unwrap_err();
    assert!(matches!(err, AcceptError::MissingPrevout(_)), "{err}");

    let spent = life.chain.fund(100_000);
    life.chain.spend(spent);
    let err = life.accept(&spend_tx(spent, 1)).unwrap_err();
    assert!(
        matches!(err, AcceptError::MissingPrevout(op) if op == spent),
        "{err}"
    );
    assert_eq!(life.mp.orphan_count(), 0);
}

/// Full RBF replaces a conflict, and the replaced tx cannot come back. The
/// hub prepares under the read lock and commits under the write lock, so a
/// conflict that lands in between fails the commit closed. Returns the
/// replaced coin and the live replacement.
fn full_rbf_and_staged_commit(life: &mut Life) -> (OutPoint, Txid) {
    let d = life.chain.fund(100_000);
    let low = spend_tx(d, 99_000);
    let high = spend_tx(d, 50_000);
    life.accept(&low).unwrap();
    let r = life.accept(&high).expect("full RBF");
    assert_eq!(r.replaced, vec![low.compute_txid()]);
    assert!(!r.replaced_scripthashes.is_empty());
    assert!(!life.live(&low));
    let err = life.accept(&low).unwrap_err();
    assert!(matches!(err, AcceptError::RbfInsufficient), "{err}");

    let e = life.chain.fund(100_000);
    let first = spend_tx(e, 50_000);
    let second = spend_tx(e, 99_000);
    let prep = life
        .mp
        .prepare_admit(
            &second,
            &life.chain,
            life.tip,
            PrepareOpts {
                fee_delta: 0,
                report_orphans: false,
                min_relay: None,
                waive: false,
                ephemeral_ok: false,
},
        )
        .expect("prevout free at prepare");
    life.accept(&first).unwrap();
    let err = life.mp.commit_after_script(&second, prep).unwrap_err();
    assert!(matches!(err, AcceptError::RbfInsufficient), "{err}");
    assert!(life.live(&first));
    assert!(!life.live(&second));
    (d, high.compute_txid())
}

/// Pure RBFR: fee 1,500 loses BIP125's absolute fee to the 2,000 parent and
/// child, but pays 1.25x the direct conflict and unpins both. One conflict
/// may be replaced by spending that conflict's parent.
fn replacements_unpin_and_leave_the_cluster_count(life: &mut Life) {
    let f = life.chain.fund(1_000_000);
    let pinned = spend_tx(f, 999_000);
    let pin_child = spend_tx(out(pinned.compute_txid(), 0), 998_000);
    life.accept(&pinned).unwrap();
    life.accept(&pin_child).unwrap();
    let r = life.accept(&spend_tx(f, 998_500)).expect("pure RBFR");
    assert_eq!(r.replaced.len(), 2);
    assert!(!life.live(&pin_child));

    let mut pairs = Vec::new();
    for _ in 0..2 {
        let coin = life.chain.fund(100_000);
        let p = spend_tx(coin, 90_000);
        let k = spend_tx(out(p.compute_txid(), 0), 80_000);
        life.accept(&p).unwrap();
        life.accept(&k).unwrap();
        pairs.push((coin, p, k));
    }
    for (coin, p, k) in &pairs {
        assert!(life.live(k));
        let bump = spend_tx(out(p.compute_txid(), 0), 10_000);
        life.accept(&bump)
            .expect("one conflict may spend that conflict's parent");
        assert!(!life.live(k));
        let gone = spend_tx(*coin, 1);
        life.accept(&gone).expect("confirmed-input RBF");
        assert!(!life.live(p));
        assert!(!life.live(&bump));
    }
}

/// 3,000 outputs is ~30 kvB: over the old 101 kWU bug, under the 101 kvB
/// cap. Then `mempool_cluster.py` `test_cluster_merging_size`: ten
/// singletons and a merger padded to four vB over what is left of the cap.
fn cluster_vsize_cap(life: &mut Life) {
    let wide = fan_out(life.chain.fund(350_000), &[100; 3_000]);
    let w = wide.weight().to_wu();
    assert!(w > 101_000 && w <= MAX_CLUSTER_WEIGHT, "weight {w}");
    life.accept(&wide).expect("large single tx");

    let mut ten = Vec::new();
    let mut ten_vsize = 0u64;
    for _ in 0..10 {
        let mut s = spend_tx(life.chain.fund(1_000_000), 900_000);
        s.output.push(op_return_pad(9_880));
        ten_vsize += s.vsize() as u64;
        life.accept(&s).unwrap();
        ten.push(out(s.compute_txid(), 0));
    }
    let remaining = MAX_CLUSTER_VSIZE - ten_vsize;
    let mut merger = spend_all(&ten, 100_000);
    merger.output.push(op_return_pad(0));
    while (merger.vsize() as u64) < remaining + 4 {
        merger.output[1] = op_return_pad(merger.output[1].script_pubkey.len());
    }
    let err = life.accept(&merger).unwrap_err();
    assert!(
        matches!(err, AcceptError::ClusterTooLarge { count: 11, weight }
            if weight.div_ceil(4) > MAX_CLUSTER_VSIZE),
        "{err}"
    );
}

/// Packages go parent first, and a CPFP pair shares one cluster. A failed
/// child rolls back its RBF parent and restores the victim. Returns the
/// CPFP coin and the live pair.
fn packages_accept_and_roll_back(life: &mut Life) -> (OutPoint, [Txid; 2]) {
    let h = life.chain.fund(100_000);
    let cp = spend_tx(h, 99_000);
    let cc = spend_tx(out(cp.compute_txid(), 0), 90_000);
    let err = life.package(&[cc.clone(), cp.clone()]).unwrap_err();
    assert!(matches!(err, AcceptError::PackageNotTopo), "{err}");
    assert_eq!(
        life.package(&[cp.clone(), cc.clone()]).expect("CPFP").len(),
        2
    );
    assert_eq!(life.cluster_len(&cp), 2);

    let i = life.chain.fund(100_000);
    let victim = spend_tx(i, 99_000);
    life.accept(&victim).unwrap();
    let repl = spend_tx(i, 50_000);
    let bad = with_annex(spend_tx(out(repl.compute_txid(), 0), 1_000));
    let err = life.package(&[repl.clone(), bad]).unwrap_err();
    assert!(matches!(err, AcceptError::Policy("libre annex")), "{err}");
    assert!(!life.live(&repl));
    assert!(life.live(&victim));
    (h, [cp.compute_txid(), cc.compute_txid()])
}

/// A block double-spends two live coins and confirms the rest of the pool.
/// The conflicts leave with their descendants.
fn block_evicts_conflicts_and_confirms_the_rest(
    life: &mut Life,
    conflicted: [OutPoint; 2],
    spenders: BTreeSet<Txid>,
) {
    let gone: BTreeSet<Txid> = life
        .mp
        .evict_conflicts_with(&conflicted)
        .into_iter()
        .collect();
    assert_eq!(gone, spenders);
    for op in conflicted {
        life.chain.spend(op);
    }
    let rest: Vec<Txid> = life.live_set().into_iter().collect();
    assert_eq!(life.mp.remove_live_txids(&rest).unwrap(), rest.len());
    assert_eq!(life.mp.live_count(), 0);
}

/// Block 200 confirmed `zp`. A seq=1 spend of its output and a coinbase
/// spend that matures at 201 enter. Disconnecting 200 puts `zp` back in the
/// pool: the seq=1 child is BIP68 non-final behind an unconfirmed parent,
/// and the coinbase spend is immature again. The next block 200 confirms
/// `zp` once more.
fn reorg_readmits_and_evicts_nonfinal(life: &mut Life) {
    let zp = spend_tx(life.chain.fund_at(100_000, 150, false), 99_000);
    life.chain.confirm(&zp, 200);
    let mut seq1 = spend_tx(out(zp.compute_txid(), 0), 98_000);
    seq1.input[0].sequence = Sequence::from_consensus(1);
    let cb_spend = spend_tx(life.chain.fund_at(50_0000_0000, 101, true), 49_0000_0000);
    life.accept(&seq1).expect("parent one block deep");
    life.accept(&cb_spend).expect("mature at 201");

    life.chain.disconnect(&zp);
    life.tip.height = 199;
    let back = life
        .mp
        .reorg_disconnect_reaccept(std::slice::from_ref(&zp), &life.chain, life.tip);
    assert!(back[0].is_ok(), "{:?}", back[0].as_ref().err());
    assert!(!life.live(&seq1));
    assert!(!life.live(&cb_spend));
    assert_eq!(life.live_set(), BTreeSet::from([zp.compute_txid()]));

    life.chain.confirm(&zp, 200);
    life.tip.height = 200;
    assert_eq!(life.mp.remove_live_txids(&[zp.compute_txid()]).unwrap(), 1);
}

/// With -minrelaytxfee at 50 sat/vB a parent below it goes to the extra
/// pool. A one-sat child does not carry it; a paying child with a confirmed
/// second input does. An unrelated low-fee tx does not ride a package's
/// waiver. A child that fails after its parent was admitted leaves a
/// parked spender of that parent in the orphanage.
fn raised_min_relay_one_parent_one_child(life: &mut Life) {
    life.mp.set_min_relay_sat_kvb(50_000);
    let lp = fan_out(life.chain.fund(100_000), &[49_900, 49_900]);
    let lpid = lp.compute_txid();
    assert!(matches!(
        life.accept(&lp),
        Err(AcceptError::Policy("min relay fee"))
    ));
    let missing = BTreeSet::from([lpid]);
    let sib = spend_tx(out(lpid, 0), 49_899);
    assert!(life
        .mp
        .try_one_parent_package(&sib, &missing, &life.chain)
        .is_none());
    let payer = spend_all(&[out(lpid, 1), life.chain.fund(100_000)], 1_000);
    assert_eq!(
        life.mp
            .try_one_parent_package(&payer, &missing, &life.chain)
            .map(|p| p.compute_txid()),
        Some(lpid)
    );

    let extra = spend_tx(life.chain.fund(100_000), 99_800);
    let wp = spend_tx(life.chain.fund(100_000), 99_800);
    let wc = spend_tx(out(wp.compute_txid(), 0), 1_000);
    let err = life.package(&[extra, wp, wc]).unwrap_err();
    assert!(matches!(err, AcceptError::Policy("min relay fee")), "{err}");
    assert_eq!(life.mp.live_count(), 0);

    let two = fan_out(life.chain.fund(100_000), &[50_000, 49_800]);
    let spender = spend_tx(out(two.compute_txid(), 0), 1_000);
    assert!(matches!(
        life.accept(&spender),
        Err(AcceptError::Orphaned { .. })
    ));
    let bad = with_annex(spend_tx(out(two.compute_txid(), 1), 1_000));
    let err = life.package(&[two, bad]).unwrap_err();
    assert!(matches!(err, AcceptError::Policy("libre annex")), "{err}");
    assert_eq!((life.mp.live_count(), life.mp.orphan_count()), (0, 1));
    assert!(life.mp.orphanage.contains(&spender.compute_txid()));
}

/// Room for three 61 vB txs. Over budget with the new tx as the worst
/// chunk, the pass removes nothing and stops. The next arrival evicts the
/// worst chunks, and the CPFP pair leaves together.
fn full_pool_evicts_worst_chunks(life: &mut Life) {
    life.mp.max_weight = 3 * spend_tx(OutPoint::null(), 0).weight().to_wu();
    let p = spend_tx(life.chain.fund(100_000), 100_000 - 3_700);
    let c = spend_tx(out(p.compute_txid(), 0), 100_000 - 3_700 - 12_200);
    let s1 = spend_tx(life.chain.fund(100_000), 100_000 - 18_300);
    let l = spend_tx(life.chain.fund(100_000), 100_000 - 3_400);
    for tx in [&p, &c, &s1, &l] {
        life.accept(tx).unwrap();
    }
    assert_eq!(life.mp.live_count(), 4);
    assert!(life.mp.graph.total_weight() > life.mp.max_weight);
    assert_eq!(
        life.mp.mempool_min_fee_sat_kvb(),
        50_000 + INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB,
        "a pass that evicts nothing does not raise the floor"
    );

    let s2 = spend_tx(life.chain.fund(100_000), 100_000 - 19_500);
    life.accept(&s2).unwrap();
    assert_eq!(
        life.live_set(),
        BTreeSet::from([s1.compute_txid(), s2.compute_txid()])
    );
    assert!(life.mp.graph.total_weight() <= life.mp.max_weight);
}

fn drop_live(mp: &mut ActiveMempool) {
    let ids: Vec<Txid> = mp.graph.iter().map(|(t, _)| *t).collect();
    if !ids.is_empty() {
        mp.remove_for_block(&ids).unwrap();
    }
}

fn restore_sigop_knobs(mp: &mut ActiveMempool) {
    mp.set_bytes_per_sigop(rbitcoin_mempool::graph::DEFAULT_BYTES_PER_SIGOP);
    mp.set_block_reserved_sigops(rbitcoin_mempool::graph::COINBASE_SIGOPS_RESERVE);
    mp.max_weight = DEFAULT_MAX_MEMPOOL_WEIGHT;
}

/// Admitted vsize is `max(ceil(sigops × bps / 4), serialized vsize)`.
fn sigop_adjusted_vsize_boundary(life: &mut Life) {
    for (bps, n) in [(20u64, 69usize), (20, 222), (43, 101), (81, 142)] {
        let target = (n as u64 * bps).div_ceil(4);
        let base = vsize_of(&witness_sigops_spend(n, 256).1);
        let pad = 256 + usize::try_from(target - base).unwrap();
        for (bytes, want) in [(pad, target), (pad + 1, target + 1), (pad - 1, target)] {
            let (utxos, tx) = witness_sigops_spend(n, bytes);
            if bytes == pad {
                assert_eq!(vsize_of(&tx), target, "padding lands on the boundary");
            }
            life.mp.set_bytes_per_sigop(bps);
            let r = life.mp.accept_tx(&tx, &utxos, TIP_OK).expect("admits");
            assert_eq!(
                bitcoin::Weight::from_wu(r.weight).to_vbytes_ceil(),
                want,
                "bps={bps} n={n} pad={bytes}"
            );
            life.mp.remove_for_block(&[tx.compute_txid()]).unwrap();
        }
    }
    restore_sigop_knobs(&mut life.mp);
}

fn sigop_min_relay_and_pool_floor(life: &mut Life) {
    let (utxos, mut tx) = witness_sigops_spend(222, 1);
    // 100 sat pays the raw size at 0.1 sat/vB, not 1_110 adjusted vB.
    tx.output[0].value = Amount::from_sat(1_000_000 - 100);
    assert!(matches!(
        life.mp.accept_tx(&tx, &utxos, TIP_OK),
        Err(AcceptError::Policy("min relay fee"))
    ));
    life.mp.set_bytes_per_sigop(0);
    life.mp.accept_tx(&tx, &utxos, TIP_OK).expect("raw vsize pays");
    drop_live(&mut life.mp);

    life.mp.max_weight = policy::MAX_STANDARD_TX_WEIGHT - 1;
    restore_sigop_knobs_keep_weight(&mut life.mp);
    assert!(life.mp.mempool_min_fee_sat_kvb() > life.mp.min_relay_sat_kvb());
    assert!(matches!(
        life.mp.accept_tx(&tx, &utxos, TIP_OK),
        Err(AcceptError::Policy("mempool min fee"))
    ));
    life.mp.set_bytes_per_sigop(0);
    life.mp
        .accept_tx(&tx, &utxos, TIP_OK)
        .expect("raw vsize pays");
    drop_live(&mut life.mp);
    restore_sigop_knobs(&mut life.mp);
}

/// `restore_sigop_knobs` also resets `max_weight`. The floor beat needs the
/// tight cap left in place.
fn restore_sigop_knobs_keep_weight(mp: &mut ActiveMempool) {
    let weight = mp.max_weight;
    restore_sigop_knobs(mp);
    mp.max_weight = weight;
}

fn sigop_rbf_package_and_cluster(life: &mut Life) {
    let (op, _, utxos) = chain_utxo(100_000);
    let old = spend_tx(op, 99_000);
    let mut heavy = multisig_outputs_tx(op, 10);
    heavy.output[0].value = Amount::from_sat(100_000 - 3_000 - 9);
    for (bps, replaces) in [(20u64, false), (0, true)] {
        life.mp.set_bytes_per_sigop(bps);
        life.mp.accept_tx(&old, &utxos, TIP_OK).unwrap();
        let r = life.mp.accept_tx(&heavy, &utxos, TIP_OK);
        if replaces {
            assert_eq!(r.unwrap().replaced, vec![old.compute_txid()]);
        } else {
            assert!(matches!(r, Err(AcceptError::RbfInsufficient)));
        }
        drop_live(&mut life.mp);
    }
    restore_sigop_knobs(&mut life.mp);

    let (parent, child) = cpfp_heavy_child(op);
    let pkg = [parent.clone(), child.clone()];
    let min = policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB;
    assert!(!life.mp.package_meets_min_relay(&pkg, &utxos, min, 20));
    assert!(life.mp.package_meets_min_relay(&pkg, &utxos, min, 0));
    assert!(matches!(
        life.mp.accept_package(&pkg, &utxos, TIP_OK),
        Err(AcceptError::Policy("min relay fee"))
    ));
    life.mp.set_bytes_per_sigop(0);
    assert_eq!(
        life.mp.accept_package(&pkg, &utxos, TIP_OK).unwrap().len(),
        2
    );
    drop_live(&mut life.mp);
    restore_sigop_knobs(&mut life.mp);

    let pid = parent.compute_txid();
    let missing = BTreeSet::from([pid]);
    assert!(matches!(
        life.mp.accept_tx(&parent, &utxos, TIP_OK),
        Err(AcceptError::Policy("min relay fee"))
    ));
    assert_eq!(
        life.mp.try_one_parent_package(&child, &missing, &utxos),
        None
    );
    life.mp.set_bytes_per_sigop(0);
    assert_eq!(
        life.mp.try_one_parent_package(&child, &missing, &utxos),
        Some(parent)
    );
    restore_sigop_knobs(&mut life.mp);

    let (wide_op, _, wide_utxos) = chain_utxo(1_000_000);
    let mut wide = multisig_outputs_tx(wide_op, 501);
    wide.output[0] = TxOut {
        value: Amount::from_sat(900_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let wid = wide.compute_txid();
    let wide_child = spend_tx(OutPoint { txid: wid, vout: 0 }, 800_000);
    let r = life
        .mp
        .accept_tx(&wide, &wide_utxos, TIP_OK)
        .expect("parent admits");
    assert_eq!(bitcoin::Weight::from_wu(r.weight).to_vbytes_ceil(), 200_000);
    life.mp
        .accept_tx(&wide_child, &wide_utxos, TIP_OK)
        .expect("child admits");
    assert_eq!(
        life.mp.graph.cluster_of(&wid).unwrap().total_weight,
        wide.weight().to_wu() + wide_child.weight().to_wu()
    );
    drop_live(&mut life.mp);
}

fn sigop_block_budget(life: &mut Life) {
    let (op, _, utxos) = chain_utxo(100_000);
    let err = life
        .mp
        .accept_tx(&multisig_outputs_tx(op, 1001), &utxos, TIP_OK)
        .unwrap_err();
    assert!(
        matches!(err, AcceptError::TooManySigops { cost: 80_080 }),
        "got {err}"
    );
    assert_eq!(err.to_string(), "bad-txns-too-many-sigops");
    assert_eq!(life.mp.live_count(), 0);
    let fits_default = multisig_outputs_tx(op, 994);
    let exact_default_budget = multisig_outputs_tx(op, 995);
    life.mp
        .accept_tx(&fits_default, &utxos, TIP_OK)
        .expect("79,520 fits beside the default reserve");
    assert_eq!(
        life.mp
            .select_block_template(life.mp.template_budget(0), |_| 0)
            .len(),
        1
    );
    life.mp
        .remove_for_block(&[fits_default.compute_txid()])
        .unwrap();
    life.mp
        .accept_tx(&exact_default_budget, &utxos, TIP_OK)
        .expect("79,600 beside the default reserve is exactly 80,000");
    assert_eq!(
        life.mp
            .select_block_template(life.mp.template_budget(0), |_| 0)
            .len(),
        1
    );
    life.mp
        .remove_for_block(&[exact_default_budget.compute_txid()])
        .unwrap();
    assert!(matches!(
        life.mp
            .accept_tx(&multisig_outputs_tx(op, 996), &utxos, TIP_OK),
        Err(AcceptError::TooManySigops { cost: 79_680 })
    ));
    life.mp.set_block_reserved_sigops(0);
    let fits_without_reserve = multisig_outputs_tx(op, 999);
    let exact_block = multisig_outputs_tx(op, 1000);
    life.mp
        .accept_tx(&fits_without_reserve, &utxos, TIP_OK)
        .expect("79,920 fits when the template reserve is zero");
    life.mp
        .remove_for_block(&[fits_without_reserve.compute_txid()])
        .unwrap();
    life.mp
        .accept_tx(&exact_block, &utxos, TIP_OK)
        .expect("80,000 fits when the template reserve is zero");
    assert_eq!(
        life.mp
            .select_block_template(life.mp.template_budget(0), |_| 0)
            .len(),
        1
    );
    life.mp
        .remove_for_block(&[exact_block.compute_txid()])
        .unwrap();
    assert!(matches!(
        life.mp.accept_tx(&multisig_outputs_tx(op, 1001), &utxos, TIP_OK),
        Err(AcceptError::TooManySigops { cost: 80_080 })
    ));
    assert_eq!(life.mp.live_count(), 0);
    restore_sigop_knobs(&mut life.mp);
}

fn sigop_reopen_and_compact(life: &mut Life, dir: &rbitcoin_store::testutil::TempDir) {
    let (utxos, p2sh, p2wsh) = p2sh_p2wsh_multisig_spends();
    life.mp.accept_tx(&p2sh, &utxos, TIP_OK).unwrap();
    life.mp.accept_tx(&p2wsh, &utxos, TIP_OK).unwrap();
    life.mp.flush().unwrap();
    life.mp = ActiveMempool::open_or_create(dir).unwrap();
    assert_eq!(live_sigops(&life.mp, &p2sh), 8);
    assert_eq!(live_sigops(&life.mp, &p2wsh), 2);
    life.mp.compact().unwrap();
    assert_eq!(live_sigops(&life.mp, &p2sh), 8, "compact re-ingest");
    drop_live(&mut life.mp);

    let (op, _, cutxos) = chain_utxo(100_000);
    let tx = spend_tx(op, 90_000);
    life.mp.set_bytes_per_sigop(7);
    life.mp.set_block_reserved_sigops(12);
    life.mp.accept_tx(&tx, &cutxos, TIP_OK).unwrap();
    life.mp.remove_for_block(&[tx.compute_txid()]).unwrap();
    let _ = life.mp.maybe_compact().unwrap();
    assert_eq!(life.mp.graph.bytes_per_sigop(), 7);
    assert_eq!(life.mp.graph.block_reserved_sigops(), 12);
    restore_sigop_knobs(&mut life.mp);
    assert_eq!(life.mp.live_count(), 0);
}

/// Sigop-adjusted size, the block sigop budget, and reopen/compact. Each
/// beat restores an empty pool. This is not the accept-life story: nothing
/// here is a coin that story later spends.
#[test]
fn sigop_adjusted_size_budget_and_reopen() {
    let dir = tmp_dir();
    let mut life = Life {
        mp: ActiveMempool::open_or_create(&dir).unwrap(),
        chain: LifeChain::default(),
        tip: ChainTipCtx {
            height: 200,
            mtp: u32::MAX,
        },
    };
    sigop_adjusted_vsize_boundary(&mut life);
    sigop_min_relay_and_pool_floor(&mut life);
    sigop_rbf_package_and_cluster(&mut life);
    sigop_block_budget(&mut life);
    sigop_reopen_and_compact(&mut life, &dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A parked chain that fills the cluster cap promotes when the root is
/// admitted. Every descendant is live, in one cluster.
#[test]
fn orphan_chain_promotes_to_the_cluster_cap() {
    let dir = tmp_dir();
    let mut life = Life {
        mp: ActiveMempool::open_or_create(&dir).unwrap(),
        chain: LifeChain::default(),
        tip: ChainTipCtx {
            height: 200,
            mtp: u32::MAX,
        },
    };
    let descendants = MAX_CLUSTER_COUNT - 1;
    let mut value = 100_000 + (descendants as u64) * 1_000;
    let root = spend_tx(life.chain.fund(value + 1_000), value);
    let mut parent = root.compute_txid();
    let mut parked = Vec::with_capacity(descendants);
    for _ in 0..descendants {
        value -= 1_000;
        let child = spend_tx(out(parent, 0), value);
        parent = child.compute_txid();
        parked.push(child);
    }
    for child in parked.iter().rev() {
        let err = life.accept(child).unwrap_err();
        assert!(
            matches!(err, AcceptError::Orphaned { fresh: true, .. }),
            "{err}"
        );
    }
    assert_eq!(life.mp.orphan_count(), descendants);
    life.accept(&root).expect("root promotes the chain");
    assert_eq!(life.mp.orphan_count(), 0);
    assert_eq!(life.mp.live_count(), MAX_CLUSTER_COUNT);
    assert_eq!(life.cluster_len(&root), MAX_CLUSTER_COUNT);
    assert!(life.live(parked.last().unwrap()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// An unconfirmed input must already be a parent of the direct conflicts.
/// Several of those conflicts may be replaced together. A single-conflict
/// CPFP of that parent stays allowed.
#[test]
fn replacement_unconfirmed_inputs_follow_libre_rule() {
    let dir = tmp_dir();
    let mut life = Life {
        mp: ActiveMempool::open_or_create(&dir).unwrap(),
        chain: LifeChain::default(),
        tip: ChainTipCtx {
            height: 200,
            mtp: u32::MAX,
        },
    };

    let coin = life.chain.fund(200_000);
    let parent = spend_tx(coin, 190_000);
    life.accept(&parent).unwrap();
    let child = spend_tx(out(parent.compute_txid(), 0), 180_000);
    life.accept(&child).unwrap();
    let bump = spend_tx(out(parent.compute_txid(), 0), 100_000);
    life.accept(&bump)
        .expect("one conflict may spend that conflict's parent");
    assert!(!life.live(&child));
    assert!(life.live(&parent));

    let c = life.chain.fund(100_000);
    let extra = life.chain.fund(100_000);
    let extra_tx = spend_tx(extra, 90_000);
    life.accept(&extra_tx).unwrap();
    let low = spend_tx(c, 90_000);
    life.accept(&low).unwrap();
    let high = spend_all(&[c, out(extra_tx.compute_txid(), 0)], 50_000);
    let err = life.accept(&high).unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("adds unconfirmed input")),
        "{err}"
    );
    assert!(life.live(&low));
    assert!(life.live(&extra_tx));

    let own = life.chain.fund(100_000);
    let victim = spend_tx(own, 90_000);
    life.accept(&victim).unwrap();
    let spends_victim = spend_all(&[own, out(victim.compute_txid(), 0)], 50_000);
    let err = life.accept(&spends_victim).unwrap_err();
    assert!(
        matches!(err, AcceptError::Policy("bad-txns-spends-conflicting-tx")),
        "{err}"
    );
    assert!(life.live(&victim));

    let wide_coin = life.chain.fund(300_000);
    let wide = fan_out(wide_coin, &[100_000, 100_000]);
    life.accept(&wide).unwrap();
    let k0 = spend_tx(out(wide.compute_txid(), 0), 90_000);
    let k1 = spend_tx(out(wide.compute_txid(), 1), 90_000);
    life.accept(&k0).unwrap();
    life.accept(&k1).unwrap();
    let merger = spend_all(
        &[out(wide.compute_txid(), 0), out(wide.compute_txid(), 1)],
        50_000,
    );
    life.accept(&merger)
        .expect("several conflicts may be replaced by spending their parent outputs");
    assert!(!life.live(&k0) && !life.live(&k1));
    assert!(life.live(&wide));
    assert!(life.live(&merger));
    assert_eq!(life.cluster_len(&merger), 2);

    // A full chain plus a separate conflict. Spending the chain tip and the
    // conflict's confirmed input would join the full cluster. Core reports
    // the cap. The conflict stays.
    let mut value = 100_000 + (MAX_CLUSTER_COUNT as u64) * 1_000;
    let mut tip = spend_tx(life.chain.fund(value + 1_000), value);
    life.accept(&tip).unwrap();
    for _ in 1..MAX_CLUSTER_COUNT {
        value -= 1_000;
        let next = spend_tx(out(tip.compute_txid(), 0), value);
        life.accept(&next).unwrap();
        tip = next;
    }
    assert_eq!(life.cluster_len(&tip), MAX_CLUSTER_COUNT);
    let capped = life.chain.fund(100_000);
    let capped_victim = spend_tx(capped, 90_000);
    life.accept(&capped_victim).unwrap();
    let over = spend_all(&[out(tip.compute_txid(), 0), capped], 1_000);
    let err = life.accept(&over).unwrap_err();
    assert!(
        matches!(err, AcceptError::ClusterTooLarge { .. }),
        "{err}"
    );
    assert!(life.live(&capped_victim));
    assert!(life.live(&tip));
    assert!(!life.live(&over));
    let _ = std::fs::remove_dir_all(&dir);
}

/// One mempool from the first orphan to a full pool: relay order, RBF,
/// cluster caps, packages, a block, a reorg, a raised `-minrelaytxfee`, and
/// eviction, against one chain view.
#[test]
fn mempool_accept_life() {
    let dir = tmp_dir();
    let mut life = Life {
        mp: ActiveMempool::open_or_create(&dir).unwrap(),
        chain: LifeChain::default(),
        tip: ChainTipCtx {
            height: 200,
            mtp: u32::MAX,
        },
    };
    orphan_parks_then_promotes(&mut life);
    invalid_or_spent_parent_does_not_park(&mut life);
    let (rbf_coin, rbf_winner) = full_rbf_and_staged_commit(&mut life);
    replacements_unpin_and_leave_the_cluster_count(&mut life);
    cluster_vsize_cap(&mut life);
    let (cpfp_coin, [cp, cc]) = packages_accept_and_roll_back(&mut life);
    block_evicts_conflicts_and_confirms_the_rest(
        &mut life,
        [rbf_coin, cpfp_coin],
        BTreeSet::from([rbf_winner, cp, cc]),
    );
    reorg_readmits_and_evicts_nonfinal(&mut life);
    raised_min_relay_one_parent_one_child(&mut life);
    full_pool_evicts_worst_chunks(&mut life);
    let _ = std::fs::remove_dir_all(&dir);
}
