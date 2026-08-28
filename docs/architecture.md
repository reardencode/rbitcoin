# Architecture: how rbitcoin differs

This page explains *why* the node is built this way and how it compares to
Bitcoin Core and to external Electrum indexers. The documentation map is
[`docs/README.md`](./README.md). Normative layouts and role tables live in
the linked owner docs.

**Status:** experimental 0.x. On-disk format and APIs are **unstable until 1.0**.

---

## One-screen picture

```text
  Peers (BIP324 v2)
        │
        ▼
  IBD densify getdata ──► in-RAM body queue (process-local FIFO)
        │                              │
        │                              ▼
        │                    Confirm lookup → load → scripts → write
        │                    (sole Class A appender + Class C tip)
        │                              │
        └──── Mempool / tip follow ────┘
                                       │
                 Reconstruct wire ◄────┤
                 Electrum joins   ◄────┘  Class A + SH + mempool
```

**IBD height-ordered path (current):** peer **offers raw framed wire into the
body queue** and notes readiness on the confirm feed; confirm **lookup** decodes,
TipOnly-resolves, and **`take_raw` onto loadq**; **load** stamps with that
`pres` then pins; **scripts** are pure CPU; **write** is the only Class A
appender. Roles: [`concurrency.md`](./concurrency.md).

**Invariant — Class A never leads tip:** there is no dual-track “archive Class A
far ahead of confirmed tip.” Wire plan + Class A append + Class C tip advance
are one confirm-write era. Do not reintroduce plan-time “archive lead” heuristics
(e.g. body `posix_fadvise(DONTNEED)` when body count ≫ tip) — under this path
just-written body pages stay tip-hot. **No** ContigPark / archive-job fallback
for unknown-height bodies (mark missing → re-getdata).

- **Storage center** is a **transaction-relational archive** on **map-free**
  tables (pread/pwrite + fallocate; no process `mmap` of Class A/B/C), not a
  UTXO set + LevelDB chainstate. IO modality: [`io-modality.md`](./io-modality.md).
- **Consensus scripts** are verified in **pure Rust** (secp256k1 only as the
  crypto primitive via the rust-bitcoin stack — **no** `libbitcoinconsensus`
  dual-eval).
- **Electrum** is **native** to the store (optional **scripthash** tables via
  `--shindex`, default off), not a second process re-indexing blk files.
  Tip-follow does **not** wait on SH materialize; Electrum/Esplora do.
  SH tip materialize is unsorted per-shard files then unique-sort; cold megakey pages
  stream into 4 KiB delta pages (schema 17).
- **JSON-RPC** (optional) is a Core-class **subset** over archive + mempool —
  see [`rpc.md`](./rpc.md).

---

## How we differ

### vs Bitcoin Core

| Concern | rbitcoin | Bitcoin Core (typical) |
|---------|----------|------------------------|
| Primary store | **Map-free** Class A/B/C tables (fd pread/pwrite + heads; page cache L0) | `blocks/blk*.dat` + `undo` + LevelDB `chainstate` (UTXO) |
| Historical block serve | **Reconstruct** from `txout`+`inwit`; tip uses body queue + peer wire | Serve raw blk files / undo |
| Spentness | Annotations on create outputs (+ rare multi-list); no mutable UTXO set as truth | Coins view / UTXO mutations |
| Concurrency during IBD | Fixed **roles** (one Class A appender, separate confirm pipeline); HWM publish order — **no map epochs** | More global chainstate coupling |
| Transport | **BIP324 v2 only** | v1 + v2 |
| Script verification | Pure Rust in-tree (`rbitcoin-consensus::script`) | libbitcoinconsensus / script interpreter in C++ |
| Electrum | In-process index on confirm | External (Fulcrum, ElectrumX, …) |
| IBD vs “current” | Dedicated densify loop exits when the **connected work path** has no remainder and is at (or one chatter block from) advertised peer height; then disconnect and `enter_tip_mode`. Relay / RPC `initialblockdownload` after the switch is Core-like: `-minimumchainwork` + `-maxtipage` (24h). | Same header/block pipeline throughout. `IsInitialBlockDownload` latches false on min chain work + tip timestamp recency (`nMaxTipAge`). btcd/libbitcoin also latch on tip time, not empty getdata. |
| Product scope | Full node + Electrum backend; **no** wallet/mining/GUI/prune | Full Core product surface |

Product / wire intentional differences: [`COMPAT.md`](../COMPAT.md).

### vs Fulcrum / ElectrumX-style indexers

| Concern | rbitcoin | Typical external indexer |
|---------|----------|--------------------------|
| Data source | Same process as the validating node; Class A is authoritative | Reads Core RPC or blk files after the fact |
| SH index | Written on confirm (runs in Direct IBD → bulk at tip) | Separate DB built by scanning history |
| Unconfirmed | Mempool attached in-process | Depends on Core mempool RPC |
| Consensus | This binary validates blocks/scripts | Trusts the node it indexes |

### vs other full nodes (Hornet, satd)

Core / Fulcrum stay in the tables above. Snapshot of **Hornet Node** and
**satd** (tests, designs, explicit non-copies):
[`peer-clients.md`](./peer-clients.md). Do not paste that comparison here.

---

## Novel on-disk model

Deep layout and schema 17 freeze: [`SCHEMA.md`](../SCHEMA.md). Crash / tip
commit: [`docs/crash-recovery.md`](./crash-recovery.md).

### Class A / B / C (intuition)

| Class | Role | Mutation style |
|-------|------|----------------|
| **A** | Canonical archive: headers, split txs (`txout` / `inwit` / `spent` + `txid.body` / `tx.head/`) | Append bodies; publish via HWM / heads (**allocate-then-publish**) |
| **B** | Forever-open indexes (e.g. Electrum scripthash) | Append + head updates; may grow forever per key |
| **C** | Tip / confirmation: `confirmed[]`, `strong_tx`, height fence | Tip advance is the **commit**; may lead/lag slightly across crash |

Spend model: **do not rewrite old output rows** as a UTXO set. Spends are
recorded as annotations (and rare multi-spender lists), with best-chain
visibility defined by confirmation / strong flags — not by deleting coins from
a LevelDB bag.

### Reconstruct (no live wire ring)

- **Historical blocks** are rebuilt from Class A (zip `txout` + `inwit`) rather
  than kept forever as raw wire `blk` files.
- Tip serve / reorg uses the **in-RAM body queue** and **peer wire**.
  There is no on-disk tip wire ring (`rbitcoin-wire-cache` is gone).
- **Epoch finalize** fsyncs buried archive prefixes in steady state; IBD itself
  does not promise Core-class durability mid-catch-up.

### Most-work chain selection (IBD + tip-follow)

The node follows the **fully valid** chain with **strictly most cumulative
work** (Bitcoin rule). Header work only **ranks candidates**; full block
connect decides the tip. IBD reorg depth is **any** (DoS/RAM caps only).
Tip-follow pending cap is **128** (`MAX_PENDING_BLOCKS`) so a ≥99-block
divergence can still be assembled. Catch-up `getdata` is windowed to
**16** (`MAX_SERVE_BLOCKS`) so it matches per-session reconstruct serve;
drain continues the header path after that window connects. Writer
saturating-subs `serve_inflight` so unpaired compact tip announce cannot
wrap the counter; announce itself is not counted on that cap.

```text
# IBD
headers prove heavier branch
    → rewind_to_height(LCA)   (DisconnectTip per dropped block)
    → plant winning hashes as the linear work path
    → lookup → load → scripts → write (normal confirm)

# Tip-follow
headers / pending
    → MostWorkSelector (skip invalid-marked)
    → gather bodies (held-by-hash · Class A)
    → ChainHub::accept_branch (snapshot → disconnect → connect)
```

Two layers:

```text
# Layer 1 — candidate ranking (headers only)
prefer A over B iff sum(header.work() along A) > sum(header.work() along B)
  and no apply-path hash is invalid-marked

# Layer 2 — most-work *valid* (full blocks)
apply only if every block connects. On fail: restore tip; mark path invalid; re-rank.
```

| Path | Behavior |
|------|----------|
| **IBD** | Any depth. When headers prove a **strictly heavier** branch, **rewind** the confirmed tip to the LCA (`ChainHub::rewind_to_height`) and plant that branch as the linear work path. The shipped lookup→load→scripts→write pipeline then confirms it — no side-channel gather, no `HELD_CAP` apply, no `accept_branch` of 40 mid bodies. Resume seed does this before confirm starts. BadPrev / competing tip+1 is the same helper (backstop). Work-path slots stay **first-wins and prev-anchored**. Offer will not stamp tip+1 unless `prev ==` store tip. Do **not** `mark_missing` the winning-path hash. `lookup_taken_hi` rewinds to the LCA. |
| **Tip-follow** | Pending cap 128. Complete bodies: `accept_received_block` → hold by hash → `accept_branch`. |
| **Resume** | `resume_work_path_after_tip`: child score = subtree header work, then depth; Class A body only tie-breaks. A greater-work sibling **rewinds to the LCA** and becomes the linear path. Body preference alone must never re-elect an archived losing fork. |
| **Invalid heavy** | Heavier header path that fails connect does not win; re-rank remaining candidates (may adopt a third valid chain). Invalid marks are **process-local**. |

```text
L = current tip, valid, work 100
M = peer header chain, work 150, connect fails mid-path
N = other peer chain, work 120, all blocks valid
Attempt M → fail → tip restored to L; M invalid-marked → re-rank → tip = N
```

IBD may disconnect on **header work** (losing bodies stay in Class A; the
winner is confirmed through the pipeline). Tip-follow still gathers bodies
before `accept_branch`. Orchestration only — never confirm
lookup/load/scripts/write. Code: `most_work`, `ChainHub::rewind_to_height`,
`accept_branch`, `ibd::reorg`.

Do **not** reintroduce soft-only BadPrev handling for a **known competing**
prev — that livelocked confirm on a losing sibling tip.

### Identity without fat keys

`tx.head/` is a **segmented keyless address table** (mixed txid → relative
create_fk; verify on **`txid.body`**). Header hashes use `header.head`
(`HashHead`). Scripthash uses a third shape. Which module/file:
[`docs/heads.md`](./heads.md). Bytes: SCHEMA.

---

## Concurrent IBD / IO model

Roles and locks: [`docs/concurrency.md`](./concurrency.md). IO modality:
[`docs/io-modality.md`](./io-modality.md). Process RAM budgets:
[`docs/ibd-memory.md`](./ibd-memory.md).

### Design principles

1. **Roles, not a global store mutex.** At most one Class A appender and one
   spend annotator per process; **N readers** of published ranges are free.
2. **Allocate-then-publish.** Write body → idx → count/HWM (Release); readers
   use Acquire. Incomplete records are invisible.
3. **Confirm pipeline** splits **lookup (stamp) → load (body-queue wire + pin) → scripts
   (CPU only) → write** so disk work, script verify, and Class A/C publish
   overlap without pausing queries under a map lock. Confirm write is the
   **sole Class A appender** on the unified IBD path.
4. **Request-bounded wire memory.** Body-queue **soft time-depth** and the
   1 GiB densify assign-stop limit new `getdata` (holes in the fetched range
   still fill) — **not** peer TCP accept of already-requested blocks (see
   ibd-memory).
5. **Bulk IO vs table transport.** `RBITCOIN_IO=uring|pread` selects **bulk
   batch** backends for `txout` pin, `txid.body` identity, `spent` annotate, spend paths
   (thread-local ring depth 128). **Table files** are always **fd** (page-/chunk-
   coalesced pread/pwrite); compact Class C is **L2 write-behind**; mempool is
   private InRam+sidecar. Head resolve **page-batches multi-key probes**.
   Historical host A/B: naive uring head insert ~5× slower than page RMW —
   production uses coalesced pages, not per-slot uring. Fuse8 builds in process
   RAM on seal. See [`docs/io-modality.md`](./io-modality.md).

### Capacity growth / durability

Store tables: fallocate only (no maps). Class C tip flush
(`flush_class_c_tip`) completes before body-queue dequeue. Mempool durability is
**InRam + private sidecars** under `{datadir}/mempool/` (not Class A).

---

## Pure-Rust consensus (secp exception)

| Piece | Implementation |
|-------|----------------|
| Headers, structure, connect, BIP68, sigops, … | `rbitcoin-consensus` |
| Script interpreter + typed paths (P2PKH/WPKH/WSH/TR/…) | `rbitcoin-consensus::script` (**no** `bitcoinconsensus` / libbitcoinconsensus) |
| ECDSA / Schnorr primitives | **secp256k1** via the **rust-bitcoin** dependency stack only |
| Types / wire at edges | rust-bitcoin |

Consensus workarounds where rust-bitcoin is not Core-faithful: living list
[`rust-bitcoin-limitations.md`](./rust-bitcoin-limitations.md).

Workspace Cargo.toml explicitly avoids enabling bitcoin’s `bitcoinconsensus`
feature. Script verification is a pure function of `(tx, input_index, prevout)`
after connect resolves prevouts.

**Milestone (assumevalid-style):** by default mainnet skips **script/sig**
checks at/below `--milestone` (840000). Prevouts, double-spend, maturity, and
fees still run. Use `--milestone 0` for full historical scripts. This is an
honest speed tradeoff, not a claim that all historical scripts were checked
under the default flag.

Test matrix for rules we own: [`docs/consensus-tests.md`](./consensus-tests.md).

---

## Pipeline summary (IBD)

Peer → body queue → **lookup** (stamp) → **load** (pin) → **scripts** → **write**
(sole Class A appender). Stage IO:
[`invariants.md`](./invariants.md). Roles, pack size, pins:
[`concurrency.md`](./concurrency.md). Heads used on lookup:
[`heads.md`](./heads.md).

Tip follow adds compact blocks (BIP152 v2), wtxid relay (BIP339), and
libre-class mempool policy — see COMPAT and the experimental mainnet runbook.

---

## Further reading

| Doc | Contents |
|-----|----------|
| [`SCHEMA.md`](../SCHEMA.md) | Current on-disk tables, schema 17 freeze, what forces 18 |
| [`docs/invariants.md`](./invariants.md) | Confirm stage IO, leftover union, store start states |
| [`docs/crash-recovery.md`](./crash-recovery.md) | Tip commit, SEAL/HWM, crash resume |
| [`docs/concurrency.md`](./concurrency.md) | Who may write which table |
| [`docs/heads.md`](./heads.md) | Which head file / module (tx / header / SH) |
| [`docs/experimental-mainnet.md`](./experimental-mainnet.md) | Lab mainnet ops |
| [`OPERATOR.md`](../OPERATOR.md) | Knobs, logging, memory budgets |
| [`COMPAT.md`](../COMPAT.md) | Product surface vs Core / Electrum methods |
