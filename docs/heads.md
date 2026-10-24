# Which head file is which

One map for `address_head` / `hashhead` / `segmented` / `scripthash_head`.
Confirm stages (lookup / load / scripts / write) and allowed IO live in
[`invariants.md`](./invariants.md). Roles: [`concurrency.md`](./concurrency.md).
On-disk bytes: [`SCHEMA.md`](../SCHEMA.md).

## Picture

```text
header.hash ──► header.head          HashHead gen 0 (2²² mainnet; 64 tiny)
            ──► header.head.gN       overflow gens (same slots; probe newest first)
                    16 B prefix + 8 B fk; .mlt if multi

txid mix    ──► tx.head/             AddressHead inside SegmentedTxHead
                    open: 4 B rel, page-local mix_txid; seal: MPHF+fuse8
                    (fuse mmap from .fuse8, heap 0; packed BDZ g FdOnly 4 KiB pages; index = rel-1)

spk hash    ──► scripthash.head/NN.mphf+.val  sealed BDZ3 main (2-bit g + rank; pack8; tags, no fuse)
            ──► scripthash.body/NN     dir-variant main slabs/pages (file variant: scripthash.body)
            ──► scripthash.ovf/ingest  incremental + post-seal new keys (key16+pack8)
            ──► scripthash.ovf/body    dir-variant ingest + sealed ovf slabs
            ──► scripthash.ovf/NNNNNN  L0 SHSR pack8; compact once → L1 MPHF+fuse8
```

## When to use which

| Module | On disk | Key → value | Who reads it |
|--------|---------|-------------|--------------|
| `HashHead` | `header.head` (+ `.gN`) | header **hash prefix** → header fk (`.mlt` if several) | Header ensure / `has_block` / prev walk |
| `AddressHead` + `SegmentedTxHead` | `tx.head/` (`meta`, open `NNNNNN`, sealed `.mphf|.fuse8`) | **mixed txid** → relative **create_fk** (body-verify on `txid.body`). Live OA rolls at 80% slots; wipe-rebuild seals **2²⁵** keys/range in parallel (no OA). Lookup maps `.fuse8` read-only (heap `fuse8=0`); packed BDZ `g` is FdOnly (4 KiB page stream); MPHF output is `rel−1`. The open OA is keyless, but each 4 B slot carries a 7-bit fingerprint of the mixed key in its spare bits. Probes and inserts hop a read-only `MAP_SHARED` view of the slot file; an insert pwrites the page. A meta v1 head (no fingerprints) gets them written from `txid.body` on first open, then meta v2 marks it tagged. The seal sidecar collects keys from `txid.body`. | Confirm **lookup** stamp after live pin miss |
| Sealed SH main | `scripthash.head/NN.mphf` + `.val` | Electrum **scripthash prefix** → pack8 locators. Compact BDZ3: packed 2-bit `g` FdOnly; occupancy mapped (prefix through occ, not tags); tags/val FdOnly. Pass-1 extract BDZ writes this path (`inline_one` vs Empty) before pack; **`MphfHead::exists` is not pack-done** (RAM unsealed until `publish_packed_shard`). | After tip bulk |
| Ingest + L0/L1 ovf | `scripthash.ovf/ingest`, L0 `SHSR`, L1 MPHF, `ovf/body` | Same pack8 key for incremental / post-seal new keys | Tip; lookup ingest → L0 → L1 → main |

`tx.head` is **not** a `HashHead`. Header slots come from `HeadScale` (`RBITCOIN_HEAD_SLOTS_HEADER` override). Sorted/MPHF SH shards are `sh_main_shard_count` (tiny=1, mainnet=64), not a HashHead. Leftover 256-way `header.head/` is Layout refuse.

## Lookup path (txid → create_fk)

1. Live pipeline pin by prev_txid (same Weak as outs).
2. **Open** wave: every unsealed OA (insert tail + in-flight seal), newest-first — one probe through the mapped slots (no syscall; the fingerprint drops most foreign occupants), then two-shot `txid.body`. Retire keys whose create is fence-connected.
3. Still unfinished: each **sealed** segment, newest first. Fuse + one MPHF batch (or the sealed OA), then the same two-shot identity, then retire. A fence-connected hit skips every older segment. An unconnected body match does not.

`TipThenAny` / `TipOnly` still walk older segments after an unconnected earlier
hit so a connected sibling can win.

## Sealed-age probe split (not page-cache)

`sealed_age_from_index` vs `HEAD_PROBE_HOT_MAX_AGE` (3) still labels sealed
age for stats and for the `SealedHot` / `Cold` probe-coverage split. Lookup
does not union ages 1..=3 before identity. It is not an IO flag.
`RWF_DONTCACHE` is retired ([`SCHEMA.md`](../SCHEMA.md) Schema 17 freeze).

## Confirm stages (head contact only)

Allowed/Forbidden IO and in-flight prune: [`invariants.md`](./invariants.md).
Roles: [`concurrency.md`](./concurrency.md).

**lookup** is the only stage that probes `tx.head`: BQ-ahead TipOnly
`get_fk_by_txid_batch_cancellable` in pieces of 4096 (each piece is one
open wave, then each sealed segment newest-first; a segment runs only for
keys still unfinished). One fence snapshot covers every piece. The confirm
cancel is asked before each piece; a live sync never sets it. In-page hop keeps 8
`(depth, fk)` on the stack and spills past that. The open OA hop reads a
read-only map of the slot file; sealed `g` pages still stream on the ring.
Combined `head_loc` cdf3 was ~90% on late-mainnet — not enough to pay a
full-depth probe for every key. Revisit if leftover-split `wave` cdf3 is
&lt;60%. Write inserts via `head_insert_many` on `ibd-confirm-head` (Drain ∥
Class C). RPC `get_fk_by_txid` hits durable head only until that drain.
