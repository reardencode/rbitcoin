# Consensus split: rbitcoin accepts a block whose transactions are not in topological order

**Component:** `rbitcoin-consensus` (`block.rs`, in-block prevout resolution)
**Commit:** `1ec7e42` (2026-08-07), with `rbitcoin-tx-version-signedness.patch` applied
**Severity:** **high — consensus split.** rbitcoin accepts a block Bitcoin Core rejects as
invalid, and the two nodes fork at the same height.
**Found by:** fuzzamoto differential campaign (Bitcoin Core primary vs rbitcoin reference,
`oracle_consensus`)
**Status:** fixed — reject same-block spends of later parents in assemble walk (see remediation commits)

**Regression:** `rbitcoin-test` `consensus_rules::header_and_spending_boundaries` — child-before-parent same-block spend must not advance tip.

## Summary

Bitcoin consensus requires the transactions in a block to appear in topological order: a
transaction may only spend an output created by an *earlier* transaction in the same block,
or by a previous block. Core enforces this implicitly by applying each transaction to the
view in order, so a child that precedes its parent fails with
`bad-txns-inputs-missingorspent`.

rbitcoin accepts such a block and makes it its tip. The two nodes then sit at the same
height on different chains.

## Observed

The campaign produced two competing blocks at height 201:

```
Core:
  [validation] BlockChecked: block hash=3ab25a39fa3ca433ad11769de86753250105311a4678884fc6e9a2ec3f8dafcc
               state=bad-txns-inputs-missingorspent,
               CheckTxInputs: inputs missing/spent in transaction 46ed0c866eadb62f218282545ee14a57a403fd68787f5b04163ec14a4a684be9
  InvalidChainFound: invalid block=3ab25a39… height=201
  UpdateTip:  new best=18864891db70fdb87ee12aa42a855f6e94cde84f8fc23ca89cef60ebc079b39b height=201   (its own mined block)

rbitcoin:
  UpdateTip:  new best=3ab25a39fa3ca433ad11769de86753250105311a4678884fc6e9a2ec3f8dafcc height=201 tx=3
```

Both at height 201, different blocks — a fork.

## The triggering block

From the IR program (`testcases/timeout-00351862a88dbfb3`, 211 instructions), the block is
assembled as:

```
BeginBlockTransactions -> v108
  AddTx(v108, v90)      <- child, added FIRST
  AddTx(v108, v66)      <- parent, added SECOND
v109 <- EndBlockTransactions(v108)
```

and `v90` spends an output of `v66`:

```
v76 <- TakeTxo(v66)          # an output of v66
  AddTxInput(v82, v76, v83)  # …consumed by the tx that becomes v90
v90 <- EndBuildTx(v81, v84, v89)
```

So the block contains parent and child, with the child first. Core, walking the block in
order, has not yet created `v66`'s outputs when it validates `v90`, so `v90`'s input is
missing — which is exactly the transaction Core names in its rejection.

## Mechanism (hypothesis)

There is no explicit topological-order check in `block.rs`. In-block parents are meant to be
resolved through `same_block`, which *is* built correctly in order — entries are inserted at
the **end** of each iteration (`block.rs:1183-1188`), so when transaction *i* is validated the
map holds only transactions `0..i-1`:

```rust
for (v, _) in tx.output.iter().enumerate() {
    if !create_fk.is_null() {
        pending_creates.insert((txid, v as u32), create_fk);
    }
}
same_block.insert(txid, ti);
```

But that is not the only way an input's parent gets resolved. `block.rs:1002-1010` consults a
`thin` edge first:

```rust
let prev_fk = thin
    .as_ref()
    .and_then(|t| t.get(ii))
    .and_then(|e| e.create_fk.map(rbitcoin_primitives::Fk))
    .or_else(|| pending_creates.get(&key).copied())
    .or_else(|| query.tx_fk_by_txid(op.txid.as_byte_array()).ok().flatten());
```

`thin` holds "thin create_fk edges from this confirm batch", produced by the archive batch
planner. That planner resolves parents from a `batch_map` covering the **whole batch at
once**, with no ordering constraint (`rbitcoin-query/src/archive.rs:455-463` — the same code
whose failure mode is [002](./002-store-corrupt-record-on-invalid-block.md)). If the planner
resolves the child's input to the parent's `create_fk` because both are in the batch, the
consensus walk accepts an edge that the ordered `same_block` map would have rejected.

**This is inference from reading the code, not a proven trace.** The competing explanation is
that the durable spentness/existence check is skipped in `AssembleMode::Optimistic`
(`block.rs:1019-1022` gates it on `mode == AssembleMode::Full`) and the deferred structural
pass does not re-establish it. Distinguishing the two requires instrumenting a run; I have
not done that.

## Impact

A miner can split the network with a single block: rbitcoin nodes follow a chain Core nodes
consider invalid. Unlike [001](./001-disconnect-on-invalid-block.md) this is not a peer
management issue — the two implementations genuinely disagree about block validity.

Topological ordering is not an obscure rule; it is why Core's `CheckTxInputs` runs against a
view updated transaction by transaction. Any block template built by ordinary software will
satisfy it, so this will not trigger by accident — it requires a deliberately malformed
block, which is precisely the adversarial case.

## Note

This was found *after* applying `rbitcoin-tx-version-signedness.patch`, so it is independent
of [003](./003-bip68-version-signedness-consensus-split.md) and
[004](./004-csv-nop-and-scriptnum-width.md). It reproduces against both the patched and
unpatched node.

