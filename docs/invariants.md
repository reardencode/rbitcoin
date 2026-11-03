# Confirm-path invariants vs multi-path fallbacks

## Goal

On hot paths (especially Direct IBD confirm lookup → load → scripts → write), prefer
**one correct path** after lookup/load, not silent colder alternate paths when those
stages were supposed to guarantee a fact.

If lookup or load missed a fact that the normal path needs, that is a **bug**: fail hard
with `Err(…Corrupt("invariant: …"))` (and `debug_assert!` where useful). Do
**not** silently fall through to a slower store/idx walk that hides the bug.

## Classification

| Kind | Examples | Policy |
|------|----------|--------|
| **Load miss** | Spend annotate without `spent_range` abs; body decode without idx range; pin without outs for need_vouts; ensure without abs for a spend edge | Assert / hard Err; fix lookup/load |
| **Environment** | bulk IO backend uring vs pread/pwrite (single backend trait) | Keep modality only |
| **Protocol** | BIP30 multi-spender confirmed-strong walk; same-block spends; coinbase null create | Real branches (not soft recovery) |
| **Format migrate** | Occupied 22 rewrites `create.loc.ovf` 12 B→16 B; occupied 24/25 strips `header.body` 96 B→88 B (an 88 B body stays 88 B); occupied 24 zero-extends `txstat.body`; `meta` to live `SCHEMA_VERSION`. Leftover fuse8 v1 / flat idx / Shared SH body / Paged pack8 **refuse** | Soft migrate (tmp+rename) or explicit wipe/rebuild |
| **API / product** | RPC body from store; Electrum mempool after chain; compact → getdata | Keep |

**One path.** Do not reintroduce a silent colder alternate when lookup or load
was supposed to guarantee the fact. Test-only adapters stay in `*_testutil`;
do not grow production APIs around fixture shapes.
Retired dual-path names live in [`errata.md`](./errata.md). The rule is the
sentence above.

## Failure style

- **Release / node:** `StoreError::Corrupt("invariant: …")` (or consensus wrap).
  No silent cold path. Operators get a log line; process need not abort.
- **Debug:** `debug_assert!` on the same facts when free.

Peer/wire corruption stays ordinary `Corrupt` / `BadBlock` — never assert on
untrusted input. Invariants apply only to **our** pipeline (load pin, denserels,
header plan after lookup planned it, stamped `create_fk`, etc.).

## Direct IBD stage table (enforced)

```
wire / body-queue
  → lookup (stamp create_fk + parent txout/spent ranges + parent txid;
            IO: tx.head, create.loc, txid.body — NEVER outs/seqsigwit decode)
  → load / pin (BatchParents outs by known txout range only;
            IO: txout.body — NEVER head / loc / txid.body / seqsigwit)
  → scripts (pure CPU — NEVER any store IO)
  → Class A commit (if ArchiveWritePlan present; wire seqsigwit encoded at write)
  → ensure abs (holes only: same-batch after Class A / missing stamp; post-condition: every spend has abs)
  → structural spentness (pin abs bulk pread of spent.body; multi-list protocol cold only)
  → Class C tip
  → index append (filter and tweak bytes from the scripts stage; no store read)
  → abs spend annotate (put_spend_batch_by_abs_meta on spent.body only)
```

Startup, before this pipeline, may `read_index_window` to seal a filter or tweak
gap of at most one IBD write drain. The confirm write thread does not.

IBD thread split (same IO table): lookup **thread** is decode + TipOnly +
`take_raw` onto loadq. Structure + plan_batch (`confirm_wire_lookup_stamp`)
run on the **load** thread and consume `LoadBatch.pres` — they do not read
`block_queue_resolved`. Leftover TipOnly on that stamp is still **lookup-stage
IO** (head / create.loc), not load pin, and only on **plan=None / S0**. After lookup
puts parent P on the load-batch skeleton, load stamp of a child spending P has
**zero** leftover TipOnly for P (`head_need_n=0`). Pack stays on load; do not
move `plan_batch` onto lookup.

IBD stamp does not build `TxApply`. Wire rows may leave packed `ins` empty.
Write encodes seqsigwit from the wire transaction and SpendEdges. A records
row with empty ins is `Corrupt("invariant: packed ins empty at write")`.
Prune mode materializes `InputRecord`s from the wire tx into the RAM window
at commit only. SpendEdges + CreatePin survive freeze. Write encodes Class A
outs from `Arc<Block>` + those edges (no plan-time `scriptPubKey` copy). The wire
pin shares that block until Class A commit publishes one packed output blob and
clears the shared slot. A `PinOuts` taken while the slot was full keeps its own
`Arc<Block>` until that snapshot is dropped. Load still does not head/idx.

| Stage | Allowed IO | Forbidden |
|-------|------------|-----------|
| **lookup** | `tx.head`, `create.loc` (fk + body+spent ranges + `n_out`), `txid.body`, headers | **`txout.body`** (outs or spent-range peeks) / **`seqsigwit` decode** |
| **load** | **`txout.body` outs by range** (from lookup stamp). A lone block's stamp miss reads `tx.head` once at the tip, and on a miss `txid.body` over every unsealed `tx.head` segment ([089](./external_findings/089-missing-parent-verdict.md)) | head, loc, `txid.body`, `seqsigwit` on the stamp and pin path |
| **scripts** | none | any store IO |

| Stage | Invariant | Soft path allowed? |
|-------|-----------|--------------------|
| Lookup parent stamp | Every external spent parent has create_fk + body_range (or offline in_flight CreatePin) + reverse txid. Archived parents also have computed `spent.body` range on the stamp (same-wave in-flight outs skip loc, miss OK; later-wave InFlight takes loc from the same `CreatePin` Arc write set at Class A, or skeleton TipOnly loc). IBD (`skeleton = Some`) never loc-by-fk: pin loc unset leaves spent unset for write TLS. The one exception is an all-archived retry (plan=None): a parent with no body is an archived create (this batch's own, or an earlier chunk's of the same wave), and only the store can range it. plan=None leftover still `fill_missing_parent_ranges` | Missing → hard Err at stamp / pin contract. **No** `finish_archive_plan` `fill_missing` after stamp loc. **No** IBD load `create.loc` |
| Parent create_fk | **same-batch** planned fks (offline at pin) → **in-flight** (lookup snapshots `drain_and_fence_hi` **before** the wave's TipOnly read and passes it on the last load batch; load drops tagged map rows with pack height **below** that snapshot after that batch's in-flight read; equality keeps; not Class C tip, not `class_a_hi`, not write freeze; one load-thread HashMap, insert after stamp) → **skeleton** (`BatchParentIds` on the `LoadBatch`: lookup TipOnly fk + body_range + spent_range + per-chunk need-vouts) → **Corrupt** on IBD miss. plan=None / S0 (`skeleton = None`) is in-flight → leftover TipOnly. One helper: [`stamp_external_parents`](../crates/rbitcoin-query/src/stamp.rs). No leftover pending map, no process pin FIFO, no BQ-side hits map, no parent-store create_fk on stamp, no published live_union. Same-wave creates are omitted from TipOnly need. Header-cache GC polls store tip each load pack. In-flight and skeleton maps stay one fk per txid (last write). That limit is only those RAM maps ([`errata.md`](./errata.md)), not a consensus rule for this write. | Miss of in-flight and skeleton → `Corrupt("parent create_fk unresolved")`. A batched miss isolates; a lone block's miss is an **engine fault** (requeue once, then halt IBD; never blacklist), unless the block extends the tip, `tx.head` holds every connected create (`Query::head_covers_fence`; open starts the drain at the head's last create, after its rebuild or tail backfill), and a fresh TipOnly read of its parents on the load thread (reject path only) still misses: that is `ConsensusInvalid`, unless `txid.body` holds the txid at a connected fk in an unsealed `tx.head` segment (the open tail or the in-flight seal), whose slot pages may hold a power-loss hole (`Corrupt("invariant: tx.head misses a connected create")`, engine fault) ([089](./external_findings/089-missing-parent-verdict.md)). A lone block whose parent is not the tip within 10 s is a `Cascade` retry. Identity without loc range → `Corrupt("invariant: loc range missing after identity")`, not a miss |
| io_uring harvest | TLS session fail-closed ([`io-modality.md`](./io-modality.md)) | **No** silent success. `Corrupt("invariant: io_uring …")` (not `bdz g page bad slot`). Ring-unavailable still pread-fallback |
| Load body outs | By `txout` range only from lookup stamp; incomplete outs → hard Err. Pin **copies** lookup `spent_range` (no loc IO). Later-wave InFlight loc comes from the CreatePin Arc (Class A `set_loc`) | **No** loc cold outs on load; **no** `seqsigwit` on pin; **no** IBD loc-by-fk |
| Ensure (write) | Every non-null spend edge has `spent_range` abs after ensure returns. Lookup stamped archived parents; same-batch from append RAM loc; just-written from write-thread loc packs kept until write of the last height whose TipOnly had started at note (`lookup_started_hi`; `keep_until` never bumped; fill of that write already ran). Later-wave InFlight takes CreatePin loc set at Class A. Missing abs → `invariant:` | **No** write `create.loc` read |
| Structural spentness | Abs required for every non-null spend create_fk after load; multi-list → confirmed-strong walk (reorg protocol) | **No** unpinned “wire-corrected create_fk” soft spentness. Multi flag alone is **not** hard `Err` |
| Structural header hash | BIP30's BIP34 ancestor is resolved once per write: this write's prepared header when the write contains that height, otherwise the hash remembered from the confirmed chain. A cold memory reads `header_at_height` once. The memory drops only when that block is disconnected. | Not `get_header_plan`. Not a second store bit: the header row is the durable record. A miss leaves BIP30 on. It does not skip. |
| Pin create identity | Pin must carry non-zero create txid from **lookup stamp** (plan reverse map / wire prev_txid / `txid.body`) | Soft zero-identity pin → assemble mismatch → cold recovery is **forbidden** |
| Tip already-archived | `plan=None`: lookup still stamps parent pin material; load `txout` by range | Soft spentness recovery for zero pin identity is **not** OK |
| Tip-ahead cascade | `fk mismatch` / `connect height not tip+1` after tip+1 fail | **Soft requeue** (not permanent blacklist) |
| Spend annotate | Structural emits abs+meta jobs; `post_commit` `put_spend_batch_by_abs_meta` only (no pin `get_spender_abs`). Class A commit does not annotate. Cold OOB/IO is hard Err. Annotate RMW is **`spent.body` only** (no `RWF_DONTCACHE`) | No ranged/by_create annotate tiers; no second spend walk; **no** `txout.body` annotate; **no** Class A `put_spend_batch` |
| Tip scripts | Optional `ScriptPreverified` (mempool) | IBD empty set |
| Reorg | Disconnect outside confirm; connect tip+1 with normal pipeline | — |

RPC, Electrum, and standalone tools may still use store cold paths.
Connect tests use `accept_and_connect_block` (same pipeline as IBD).
Spentness / maturity / BIP68 run in `structural_validate_spends` after
optimistic assemble.

## Process open (before P2P / confirm)

Normative write-order and repair: [`crash-recovery.md`](./crash-recovery.md).
Short sequence:

| Step | Action |
|------|--------|
| 1 | `Store::open` + schema gates |
| 2 | Soft `tip_seal` clamp (if present) |
| 3 | Trim trailing null `confirmed[]` slots, then tip-window revalidate. A missing `spend_durable` walks from genesis. A present marker widens the window to `(D, tip]` (6 stays the floor). `checkblocks=0` still walks from genesis. Shrink/clear on a stored mismatch; rebuild fence. A failed read stops open and changes nothing. The walk logs `store: tip revalidate` and progress every 10 seconds |
| 4 | One `repair_class_c_above_tip` (fence complement: holes + short suffix) |
| 5 | Replay spend annotations above annotated-through. A missing marker replays from genesis. `sync_data` the stems that were rewritten, publish the marker at the surviving tip |
| 6 | Then node may densify / extend tip |

`create.loc` is body-only deltas plus RAM checkpoints; a loc/off size mismatch
on open is `Corrupt` (wipe + IBD). Historic schema-≤14 idx double-append
repair (`scripts/repair-idx-double-append.py`) does not apply to schema 22.

## Store start states (intake at confirm start)

| State | Class A for tip+1 | Headers | Parent head | Handler (lookup cleans) |
|-------|-------------------|---------|-------------|-------------------------|
| **S0 fresh tip+1** | absent | present | parents on head | plan=Some: plan_batch stamps fk+txout/spent range+txid + parent vouts; load `txout` by range, copies spent_range |
| **S1 already-archived** | body present (plan=None) | present | parents on head | lookup still stamps parent fk+ranges+txid (idx/head); load `txout` only |
| **S2 tip-ahead pack** | prior pack uncommitted | — | parents in in_flight | plan uses in_flight create_fk; **must** also stamp ranges (idx) when body exists, or use offline CreatePin |
| **S3 short catch-up** | mixed need-body / already-bodied over a height-ordered prefix | present | mostly cold | two (or more) homogeneous batches: lookup splits loadq at `header_txs.has_body`; write drain stops on `archive_plan` polarity. Load/scripts are not splitters. Mixed stamp is `Corrupt("invariant: confirm batch mixed archived")`. Write vs tip is all-old no-op, all-new fill, or `Corrupt("invariant: write batch spans tip")` — no prefix strip |
| **S4 cascade fail** | tip+1 unconfirmable or write failed | — | — | tip-ahead write may hit `fk mismatch` / `connect height not tip+1` → **Cascade requeue**, not blacklist. Only a consensus-invalid block is blacklisted. Store invariant → **EngineFault** (requeue once, then halt). |

| Error | State | Root | Fix |
|-------|-------|------|-----|
| `lookup stage miss (load cold denserels forbidden)` | S0/S3 | Load Forbid + parents without plan range | Lookup always fills `external_parents` body; load outs by `txout` range only |
| `invariant: confirm batch mixed archived` | S3 | One stamp/load list spans need-body and already-bodied | Split at the `has_body` change (IBD lookup) or call one-shot twice. Do not hitchhike `get_list` on `plan=Some` |
| `put_full_batch fk mismatch` | S4 cascade | Tip-ahead plan after tip+1 reject | Soft requeue for fk mismatch / connect height not tip+1 |
| `parent create_fk unresolved` | S2 | Skeleton / in-flight miss | **Engine fault** on a lone block. Requeue once, then halt IBD. Do not blacklist. Exception: a lone tip+1 block that a fresh TipOnly read still misses once `tx.head` holds every connected create is `ConsensusInvalid` (`missing prevout: parent … is not on the connected chain`, [089](./external_findings/089-missing-parent-verdict.md)). |
| Lookup 8 consecutive non-session `Io` | live | Read-side store IO | **EngineFault** reject: `apply_engine_fault_reject` **dequeues** that height's body-queue payload and requeues the hash once; a second occurrence on the same hash **halts** IBD. Session-fault recover does **not** dequeue. Do not emit a reject when the feed has no ready hash. |
| false PrevoutSpent | identity | schema-13 zero pin id | plan reverse map / lookup `txid.body` only |

## Why there is no leftover pending map

In-flight is the only RAM `txid → create_fk` cache for **planned** creates
(plus `CreatePin` outs). Archived parents ride the load-batch skeleton.
Lookup snapshots drain+fence **before** TipOnly and rides that height on
the last load batch of the wave. Load drops map rows with pack height
below the snapshot **after** that batch's in-flight read. Stamp skips
`body_range` when in-flight still has outs (n−1); pin needs those outs.
Skeleton / leftover TipOnly is the home once the pack is gone.
Last-write identity and write-phase reject of an out-of-order in-flight
bind: [`errata.md`](./errata.md).

Equality (`pack height == snapshot`) keeps the row. Disconnect drops
packs at/above the leaving **pack** height **before** the next bind.

## Related code

- Confirm write annotate / ensure: `rbitcoin-query` `confirm_run::{post_commit,collect_spend_abs_after_fill,ensure_spend_abs_layouts,pin_for_wire_batch}`
- Structural: `rbitcoin-query` `block_pipeline::structural_validate_spends` (rule decisions it calls live in `rbitcoin-consensus` `block::facts`)
- Pin / denserels: `rbitcoin-query` `confirm_load`, `BatchParents`, `pin_for_wire_batch` (cold range / adopt)
- Abs annotate: `rbitcoin-store` `put_spend_batch_by_abs_meta`

## Regression tests (shipped)

| Test | Entry |
|------|--------|
| `pin_for_wire_missing_parent_is_invariant_error` | `pin_for_wire_batch` missing spent parent |
| `pin_for_wire_incomplete_outs_is_invariant_error` | `pin_for_wire_batch` incomplete outs → cold miss |
| `post_commit_missing_denserels_is_invariant_error` | `post_commit` abs-only annotate |
| `ensure_spend_abs_incomplete_is_invariant_error` | `ensure_spend_abs_layouts` post-condition |
| `collect_spend_abs_after_fill_is_one_walk` | one `spend_abs_jobs` after fill; vout past the range is ensure Corrupt; duplicate abs is one job |
| `write_ensure_stamps_spent_range_after_load_pin` / `pin_and_ensure_journey` / `fill_same_batch_abs_from_append_loc_ram` / `fill_just_written_survives_until_last_started_write` / `fill_stamp_spent_hole_from_write_tls` / `pin_and_ensure_from_pin_loc_without_tls` | load pin copies lookup spent range; missing stamp is Corrupt; same-batch abs from append RAM; just-written loc until write of last started height; stamp spent hole filled by write TLS; pin loc after TLS prune (no write loc pread) |
| `fill_missing_parent_ranges_stamps_spent_idx_for_archived` / `inflight_hit_adopts_skeleton_loc` / `inflight_hit_skeleton_miss_leaves_spent_unset_despite_disk_loc` / `plan_inflight_skeleton_miss_leaves_spent_unset_despite_disk_loc` / `inflight_hit_uses_pin_loc_without_disk` | leftover TipOnly still loc-fills archived spent; InFlight takes skeleton loc; IBD skeleton miss leaves spent unset (no loc-by-fk); pin loc binds without disk |
| `spend_abs_jobs_unique_and_missing_is_corrupt` | pin arithmetic abs list; missing → Corrupt |
| `already_archived_schema13_pin_identity_tip_follow` | archive then `confirm_wire_run` plan=None + rapid tip accept |
| `store_start_states_lookup_load_confirm` | S0 new Class A + S1 plan=None via lookup→load |
| `plan_inflight_creates_only_fills_parent_body_range` / `plan_inflight_creates_only_ibd_skeleton_miss_does_not_loc_fill` / `pin_creates_only_ibd_skeleton_miss_is_lookup_stage_miss` | leftover creates-only still stamps body_range; IBD skeleton miss does not loc-fill; pin of that miss is lookup stage miss |
| `optimistic_assemble_unstamped_parent_is_invariant` | Optimistic assemble: pin miss is lookup invariant, not head recover |
| `parent_pin_stamp_take_from_plan_moves_maps` | S0 `take_from_plan` leaves `resolved` empty (no txid→fk invert) |
| `plan_batch_one_fill_missing_when_parents_already_stamped` | one `fill_missing_parent_ranges` when packed adds no new fks |
| `direct_write_skips_create_pin_map_idx_without_recent` | Direct skips `write_create_pins`; Class A idx holds body range |
| `pin_takes_stamp_parent_vouts` / `plan_batch_same_header_vouts_skipped_cross_height_pinned` | pin takes stamp vouts; same-header creates not pinned |
| `ibd_confirm_pin_fault` | IBD load: child spend of just-written pack (187); same-wave intervening writes (496); later-wave intervening write still has InFlight so TipOnly loc must ride the stamp (905); lookup-ahead child wave (133433) |
| `load_engine_fault_near_the_tip_retakes_the_wave` | load stamp store fault on the last path block: the wave goes back to lookup under a re-arm and connects with no later wave to re-arm it |
| `ibd_bad_prev_fork` | fk mismatch / connect height not tip+1 cascade requeue; store invariant engine-fault (requeue once then halt); only consensus-invalid blacklisted |
