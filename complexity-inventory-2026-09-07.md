# Excess-complexity inventory — every crate (2026-09-07)

Working document for a simplification program. Audited on
`ibd/reorg-reject-policy`; refreshed 2026-09-11 against `origin/master`
after **#426** (C-06) / **#427** (Q-06) merged. Remainder §16 Should
rows are `quality/remainder`; Must leftovers **X-03 / C-03 / Q-21**
are this stacked branch. Earlier landmarks: [#395](https://github.com/reardencode/rbitcoin/pull/395)
(cmpct fuzz recipe), [#396](https://github.com/reardencode/rbitcoin/pull/396),
[#397](https://github.com/reardencode/rbitcoin/pull/397),
[#411](https://github.com/reardencode/rbitcoin/pull/411)–[#414](https://github.com/reardencode/rbitcoin/pull/414)
(X-06), [#420](https://github.com/reardencode/rbitcoin/pull/420) (X-01 steps 2–3,
merged). Resolved rows are marked **done (#N)**. ~190k first-party Rust LOC
across 14 crates (inline tests included).

Method: every crate read against its owner docs (`AGENTS.md`, `docs/quality.md`
Won't-fix / Open, `docs/io-modality.md`, `docs/heads.md`, `docs/invariants.md`,
`docs/concurrency.md`, `SCHEMA.md`, `COMPAT.md`, `docs/rpc.md`,
`docs/env-knobs.md`). Every "unused" claim was verified with `rg` over the whole
`crates/` + `fuzz/` tree; line numbers were read, not guessed. Items the project
has explicitly rejected (flatten io_uring machines, split `interpreter.rs`,
reintroduce CreateResidency / pin FIFO / ContigPark, headerless SH interiors,
restore script coordinators, Esplora LRU, tracing, rayon) are **not** proposed.

Each row: **ID · title · evidence · proposal · est. LOC · trade-off · confidence.**
LOC is rough and counts deletions unless marked *move*.

---

## 0. Honest framing

Most of the tree is load-bearing product (consensus rules, store machines,
P2P dialect for the Core functional harness, wallet APIs). The realistic
deletable band is **~9–14k LOC (~5–7%)** plus **~3k relocated** out of
production crates and **~5–8k of tests consolidated/moved**. The larger win is
*structural*: a handful of cross-cutting patterns (global perf statics, ambient
test knobs, triple config representation, hand-rolled fixtures, over-wide `pub`
surface) generate most of the accidental complexity and most of the
`#[cfg(test)]` forks in production code. Section 1 lists those first; they
should be done before per-crate peels because they delete the *reason* many
per-crate items exist.

---

## 1. Cross-cutting (highest leverage)

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| **X-01** | **Process-global perf counters → instance-owned stats** **done (#405+#410+#420)** | ~160 distinct `pub static … AtomicU64` names across `query/lib.rs` (104 statics; 5 `*_stats` modules), `consensus/lib.rs` (75, `confirm_phase_stats` ~506 lines), `confirm_run/lookup.rs` (20), `ibd/confirm/mod.rs` (17), `store/head_resolve_stats.rs` (13), `segmented_head.rs`, `serve_perf.rs`. Each is hand-mirrored into a `Sample` struct + `sample_and_reset()` listing every field again. Because they are process-global, tests need a `#[cfg(test)] exclusive::with` mutex (`query/lib.rs:425–448`, `confirm_run/lookup.rs:565–579`) and a `#[cfg(not(test))]` no-op twin. `ibd/perf_log.rs` (2.9k) is mostly the consumer of these. Never-incremented: `COLD_DECODE_NS`, `COLD_IDX_N/NS`, `PIN_ADOPT_NS`, `PIN_PUBLISH_NS`, `PARENT_CACHE_HITS`, `FULL_TX_READS`, `MISSING_PARENTS`, `HEADER_NS`, `BODY_DECODE_NS`, `CACHE_PUT_NS`, `EDGE_*`, `PIN_NEW_META_NS`, `CREATES` (query); `RECONSTRUCT_NS`, `RECONSTRUCT_WIRE_NS`, `WRITE_RECENT_*`, `ASM_PREV_*`, `SPEND_ANNOTATE_IDX/SKIP`, `RESOLVE_NS`, `UNPIN_NS`, `CACHE_TIP_NS`, `SPEND_ANN_PREAD` (consensus); `HeadLookupStats` (store) never read; pstore `0,0,0` still passed and printed (`ibd/confirm/mod.rs:71`, `perf_log.rs:1878`). | (1) Delete every never-written counter and its `Sample` field/format token (I-05, C-01, Q-01–Q-03, S-02). (2) Replace the remaining statics with one `ConfirmStats` struct owned by the confirm engine and passed by `&`; `Sample` becomes `std::mem::take`. Deletes the test mutex + `cfg(not(test))` twins. (3) Table-drive `perf_log` formatting from a `&[(name, fn(&Sample)->u64)]` list so adding a meter is one line. Keep every **live** named lookup/load/scripts/write timer (AGENTS.md rule). | ~900–1,400 (≈300 dead counters + ≈600–1,000 boilerplate) | `ibd: perf` / `ibd: sizes` DEBUG token set shrinks — note in CHANGELOG; do not drop live stage tokens. Passing a stats handle through confirm APIs is churn across consensus/net/query. | high (dead) / medium (restructure) |
| **X-02** | **`HeadScale` is ambient env + cargo-test detection + thread-local** | `store/hashhead.rs:91–155`: `running_as_cargo_test_binary()` sniffs `/deps/` in `current_exe`; `RBITCOIN_HEAD_SCALE` env; `#[cfg(test)] TEST_HEAD_SCALE` thread-local; `HeadScale::from_env()` called from `scripthash.rs:376`, `scripthash_head.rs:70`, `hashhead.rs:182,189`. ~140 test sites do `if env::var_os("RBITCOIN_HEAD_SCALE").is_none() { set_var(...,"tiny") }` (peer_tests 44, write_idempotent_tests 36, tx_relay 32, server_tests 18, …). Same shape: `TEST_SOFT_SPAN_OVERRIDE` (`tx_idx.rs:1246`), `TEST_REBUILD_SEAL_BITS` / `TEST_REBUILD_WORKERS` (`tx_table/mod.rs:14–16`), `TEST_FORCE_SESSION_FALSE` (`bulk_io.rs:334`). | Make scale (and rebuild workers / seal bits / soft span) fields of `StoreLayout`/open options with `Mainnet` default; tests construct `StoreLayout::tiny()`. Delete env sniffing, cargo-test detection, thread-locals, and all ~140 `set_var` sites. Keep `RBITCOIN_HEAD_SCALE` only if an operator needs it (env-knobs.md says tests only → delete). | ~350–500 | Explicit parameter threads through `Query::open` / `ChainHub::new` call sites (mechanical). Removes a real production hazard (a binary under a `deps/` path silently gets 64-slot heads). | high |
| **X-03** | **Test-only probes/hooks in production store code** **done (this PR)** | SQE counts, page writes, SH page IOs, and BQ raw clones live on the session/table/queue that did the IO. `get_tx_full` spies are Store debug instance logs. TLS `test_take_*` / `TEST_FORCE_SESSION_FALSE` / crate-root `take_raw_clone_n` deleted. | — | — | IO-shape pins use session stats or file state. | high |
| **X-04** | **`pub` surface far wider than cross-crate use** | Re-exports in `lib.rs` with **zero** users outside their crate: store ≈140 names (`AddressHead`, `SegmentedTxHead`, `UringSession`, `IoHandle`, `SortedHead*`, all slab/page codecs, `decode_packed_tx*` ×6, …), net ≈90 (`NetConfig`, `P2PHandle`, `PeerRateLimiter`, `DialRequest`, `LivePeer`, fuzz encoders, …), consensus ≈40 (`confirm_bq_resolve_wave`, `drive_script_waves`, `block_to_apply*`, `validate_block_structure_*` ×3, …), query ≈17, mempool ≈40 constants/helpers, rpc ≈18, electrum 11, esplora 10. `pub fn` counts: store 1,059, net 779, query 361. | Mechanical pass: everything not imported by another crate becomes `pub(crate)`; then let `-D warnings` (dead_code) report what is truly dead and delete it. Do the pass per crate, lowest first. | ~200–400 direct; unlocks rustc dead-code detection for everything below | Out-of-tree consumers: none in tree (fuzz crate needs a `pub` list — see N-07/N-13). | high |
| **X-05** | **Node config has three representations of every knob** **done (#418)** | `node/cli.rs:12–128` `CliAccum` (~50 fields + `_set` booleans) ← 120 CLI match arms (`cli_main`, `cli.rs:135–~1300`, one ~1,150-line function) → ~180-line field-by-field copy into `NodeConfig` (`cli.rs:1017–1201`) ∥ `config.rs:497–713` `apply_kv` (37 conf arms). `rg apply_kv cli.rs` → no matches: CLI never reuses the conf setter. `DatadirOpts` carries `Deref`/`DerefMut`/`PartialEq<PathBuf>`/`AsRef`/`From` just to keep `.join()` call sites unchanged (`config.rs:28–63`). | Parse CLI `--key[=value]` into the same `(key, value)` stream and run `apply_kv` with precedence conf → CLI; keep CLI-only sugar (`--smoke`, `--help`, log init). Delete `CliAccum` and the copy block. Replace `DatadirOpts` Deref tricks with a plain field + `fn path()`. | ~400–600 | **High regression risk** on the OPERATOR flag contract and Core functional harness (`=value`, bool forms, override order, aliases). Needs a flag-matrix test first (Red). | high (dup real) / medium (safe reclaim) |
| **X-06** | **Hand-rolled test fixtures ×262** **done (#411)** | Leaf shipped: `rbitcoin_store::testutil::{TempDir, tiny_store, tiny_store_labeled}`, `rbitcoin_query::testutil::{tiny_query, tiny_query_labeled}`. Named `tmp_dir` / `temp_query` / `tmp_hub` / `tmp_store` in store/query/consensus/mempool/net/electrum/esplora now call those. Hub opener **N-04** is #412; leftover named inlines **I-14 / A-21 / C-14 / Q-17 / SH-15 / N-03** are #414. Remaining: 1-line wrappers still named locally; inline `temp_dir().join` in store unit files (`file.rs` / `var_table` / `tx_table` / `bulk_io` / heads), consensus overlay/pad/header, query `sh_builder`, node `run.rs` tests. Fuzz `fuzz/src/lib.rs` `tmp_dir` is not this. | Do not re-roll Tiny store/query. Optional later: convert leftover store-unit `temp_dir().join`. | remaining leftover inlines | Fixture behavior stays tiny (TESTING.md). | high |
| **X-07** | **Fuzz/differential harness compiled into the node** **done (#416)** | Moved: `fuzz/src/block_diff.rs`, `fuzz/src/cmpct_fuzz.rs`, recipe fixtures under `fuzz/fixtures/`. Net keeps `ChainHub` accept, `try_reconstruct`, `shortid_map_from_txs`, `prefilled_indexes_ok`, `classify_v2_cmpct_peer`, `encode_v2_contents`, `drain_pending_now`, `PendingBlocks`. `cargo fmt --all` still formats `fuzz/` via never-compiled rbitcoin-log test anchors (fuzz stays its own cargo-fuzz workspace so `bitcoinconsensus` is not in the product graph). | — | ~3,400 *moved* | Coverage is workspace `rbitcoin-net` production, not the fuzz crate. First CI run on #416 was green including coverage. | high |
| **X-08** | **Clippy allow-list hides the complexity signals** | `Cargo.toml` `[workspace.lints.clippy]`: **66** `= "allow"` incl. `cognitive_complexity`, `too_many_arguments`, `type_complexity`, `large_enum_variant`, `result_large_err`, `collapsible_if`, `needless_return`, `if_same_then_else`, `while_let_loop`. | Not a code delete. After the per-crate passes, re-enable in batches (style ones first: `collapsible_if`, `needless_return`, `redundant_*`, `manual_*`); leave `cognitive_complexity` allowed per quality.md. | 0 | Each batch forces drive-by edits → separate PRs; noise vs. signal is a judgment call. | medium |
| **X-09** | **Legacy enum variants / constants kept as code** **done (#415)** | `primitives::TableKind::{Input, Output, Point, TxHeight}` never constructed anywhere (only the declaration). `HeadRole` has one variant (`hashhead.rs:75–77`). `HEAD_LOAD_WARN`/`HEAD_LOAD_CEILING` unused. `INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB` duplicates `policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB`. `DEFAULT_MAX_INBOUND = 125` defined in both `net/peer_dos.rs:11` and `node/config.rs:10`. | Reserve retired on-disk ids in a doc comment (`// 4,5,6,12 reserved (retired)`), delete the variants; delete `HeadRole`; single owners for the two constants. | ~60–90 | none | high |

---

## 2. `rbitcoin-store` (non-scripthash) — 51.8k total, ~38k outside SH

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| S-01 | Test-only page-RMW machine  **done (#415)** | `bulk_io.rs:56–64` `#[cfg(test)] PageRmw`, `:271–282` `page_rmw_pipelined`, `:849+` `page_rmw_serial`; `docs/io-modality.md:146` says not the head path; `rg` → only `bulk_io.rs`. | Delete; keep real `pread_batch`/session tests. | ~300–400 | Coverage: replace with thinner session pins if LH dips. | high |
| S-02 | `HeadLookupStats` never consumed | Written `segmented_head.rs:732–962`; sample/snapshot `:46–82`; only `segmented_head.rs` + `lib.rs`. | Delete (or wire into `ibd: perf` if wanted). Part of X-01. | ~80–120 | none | high |
| S-03 | Dead load constants + unused roll helpers | `HEAD_LOAD_WARN`/`CEILING` (`address_head.rs:106–108`) unused; `load_needs_roll`/`layout_for_count` defs+tests only; roll threshold re-inlined `segmented_head.rs:1203`. | Delete constants; call `load_needs_roll` from `segmented_head` or delete both. | ~25–40 | none | high |
| S-04 | Fuse8 v1 soft-migrate / `always_probe` dual read  **done (index-refuse)** | Open refuses v1 with wipe/rebuild line; `always_probe` / `NeedsRewrite` / rewrite queue deleted. | — | — | SCHEMA/OPERATOR same strings as errors. | high |
| S-05 | Two `RBITCOIN_IO` parsers  **done (#415)** | `io_backend.rs:32–46` (`parse_read_token`/`parse_write_token`, folds pool/iocp→Uring) vs `bulk_io.rs:103–134` (`IoToken`, keeps them distinct). | One parser → `SessionKind \| Libc`; derive read/write backend from it. | ~40–80 | Token aliases must stay (`docs/env-knobs.md`). | high |
| S-06 | `SpendMetaBackend` / `SpendAnnBackend` 1:1 aliases  **done (#415)** | `tx_table/mod.rs:406–418`, `spend_annotate_uring.rs:297–310`, facades `store.rs:924–944`. | Callers take `ReadIoBackend`/`WriteIoBackend` directly. | ~30–50 | Rename churn in consensus. | high |
| S-07 | `repair_orphan_class_c` alias  **done (#415)** | `store.rs:1212–1218` calls `repair_strong_not_on_fence`; only tests use it; production uses `repair_class_c_above_tip`. | Delete. | ~10 | none | high |
| S-08 | Dead packed helpers | `next_tx_body_start`, `is_packed_tx_payload`, `clear_output_spender_fields`, `TXID_PAGE_MAX_OFF` (`packed.rs:447–456, 810–820`) — defs + tests only. | Delete or `pub(crate)`; unexport. | ~40–60 | none | high |
| S-09 | `HeadRole` one-variant enum  **done (#415)** | `hashhead.rs:75–77`. | Delete (X-09). | ~15–30 | none | high |
| S-10 | `store.rs` 3,437 = 1.5k prod + 1.9k inline tests; ~21 one-liner table facades | `mod tests` at `:1536`; facades `put_header`, `get_tx`, ranges… | Peel tests to `store/tests.rs` (*move*); drop facades only where callers already hold `store.txs`. | 0 deleted; 1.9k moved | R-10: peel only for a seam — this is a readability peel. | medium |
| S-11 | `put_spend_create_at`, `Store::create_with_head_layout` unused outside crate | `rg` → store only. | `pub(crate)` / test-only. | ~0–20 | none | high |
| S-12 | Flat `*.idx.meta` soft-migrate  **done (index-refuse)** | `ensure_idx_layout` refuses leftover flat `*.idx.meta`; no rename. Operator places files under `{stem}.idx/`. | — | — | SCHEMA/OPERATOR. | high |
| S-13 | ~~Docs describe a deleted `rbitcoin-store-bench`~~ **done (#397)** | `io-modality.md` and `reproducible-builds.md` no longer name the binary. | — | docs | none | — |
| S-14 | Probe-depth sample API only tested | `address_head.rs:112–120`; warn log at `:148–155,941` is the live part. | Keep warn; delete/`pub(crate)` sample+snapshot. | ~20–40 | none | high |
| S-15 | `PointRecord.spending_input_index` always 0  **done (this PR)** | Field and ignored `put_spend` arg deleted. Esplora `/outspend(s)` omit `vin`. COMPAT documents explorer gap (cold `inwit` to recover). | — | — | COMPAT product gap. | high |
| S-16 | Pool / IOCP / uring backends | `uring_session.rs` shared harvest contract (`:105–123, 290–527`); pool 225, iocp 306. | **Keep.** Optional later: Windows on pool (perf/platform call). | 0 | — | high (not excess) |
| S-17 | `flush_class_c_pre_tip` needlessly `pub` | `store.rs:1302`; only caller `:1324`. | `fn`. | 0 | none | high |
| S-18 | Re-export sprawl of head internals | `lib.rs:59–65`, `:137–146` (six `decode_packed_tx*`). | X-04 pass. | ~30 | none | high |

**Not excess (checked):** `bdz.rs`, `binary_fuse8`+`fuse8_filter` layering, `tx_head_mphf`, `HashHead` vs `AddressHead`/`SegmentedTxHead` (different keys), `open_address.rs`, `pending_head.rs`, `head_resolve_denserels` machines, `spend_annotate_uring`/`sp_tweaks_uring`, `head_resolve_stats` timers + leftover diag (consumed by `perf_log.rs:926` and stamp/reject), `compact`, `int_map`, `block_wire`, `store_secret`, `height_fence`, `error`, schema-refuse tests, `IoCtx`.

---

## 3. `rbitcoin-store` scripthash family — ~12.6k incl. tests

Shipped shape (schema 20): cold `--shindex` → unsorted shards → pack → body slabs/pages → `scripthash.head/NN.mphf+.val` (BDZ3, pack8). Tip: `put_create_batch_append` → body append + in-place head; new keys → `ovf/ingest` OA → seal @0.80 → L0 SHSR+fuse → compact 8→ L1 MPHF. Lookup: ingest → L0 → L1 → main. Body: **Sharded** only; leftover Shared file **refused**. pack8 modes: Empty | Inline | Slab | Extent(11); leftover Paged(10) **refused**.

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| SH-01 | `LiveShardTable` + cold OA install path orphaned | Cold seal uses `MphfHead::write_pack8` (`scripthash.rs` ~1839, 2582, 2611, 3350). `LiveShardTable` only in `scripthash_head.rs` + `lib.rs`; `ShardedScriptHashHead` already `#[cfg(test)]` (`:1086–1232`). | Delete `LiveShardTable`, `install_cold_image`, `install_live_shard`, the cfg(test) sharded facade. | ~350–500 | Coverage dip on deleted APIs only. | high |
| SH-02 | 16-byte `ShHeadValue::encode/decode` dual codec is test-only  **done (#415)** | Durable is pack8 (`SH_HEAD_VALUE_LEN = 8`); `encode()` only in `scripthash_layout.rs` tests (330–467); `sh_encode_*`/`sh_decode_*`/`sh_head_value_mode` (`scripthash_pages.rs:158–269`) feed only that. Module rustdoc still describes schema-14 (`:1–39`). | Delete 16-B path + helpers; rewrite page-module docs. | ~200–350 | Keep one corrupt-refuse pin. | high |
| SH-03 | Remap/copy body helpers only tested | `remap_sh_head_value`, `copy_sh_body_range`, `remap_copied_page_chain` (`scripthash.rs:2629–2676`); sole caller `scripthash_tests.rs:1180–1217`. | Delete + unexport. | ~130–170 | none | high |
| SH-04 | `contains_create` / `entries` near-dead | Join uses `create_fks` (`query/scripthash.rs:397,836`); `contains_create` only `scripthash.rs:1442` + tests; `entries` only `catchup.rs:605` emptiness assert. | Delete `contains_create`; `entries` → test-only. | ~40–60 | none | high |
| SH-05 | `put_create` / `put_create_batch` wrappers unused in production | Shipped tip path is `put_create_batch_append` (`connect.rs:434`, `catchup.rs:364`); wrappers only in `store.rs` refuse fixtures. | `#[cfg(test)]` or call the real API in tests. | ~30–50 | none | high |
| SH-06 | Shared (file) body layout: never written, still read  **done (index-refuse)** | `detect_sh_body_layout` refuses file `scripthash.body`. `ShBodyLayout::Shared` and Shared read/write arms deleted. | — | — | SCHEMA/OPERATOR. | high |
| SH-07 | `ShHeadValue::Paged` (mode 10) write-dead  **done (index-refuse)** | `unpack8` / `pack8` refuse mode 10; Tiny ingest scan on open. Paged variant still exists for flags/tests. | Optional: delete Paged variant + linked-page walk (keep Extent). | leftover walk | SCHEMA/OPERATOR. | high |
| SH-08 | `scripthash_overflow.rs` is a retired mono-OA test harness  **done (#415)** | Banner `:1–6`; `ShOverflowStack`/`OvfSegment` `#[cfg(test)]` (`79–106`); production import is only `wipe_legacy_fullsize_overflow`. | Keep wipe + constants (~50); delete ~700 test-only stack. | ~650–720 | Leftover-OA refuse already pinned in `scripthash_tests.rs:647–667, 809–830`. | high |
| SH-09 | `SortedHeadFilter::None` + `SortedHeadWriter` non-shipped | Production always `Fuse8` (`scripthash.rs:482, 1755`); writer/`install_head_part` `#[cfg(test)]` (`scripthash_sorted_head.rs:276–381`). | Hard-code fuse; delete enum + writer. | ~120–180 | Lose incremental SHSR writer test path. | high |
| SH-10 | `ScriptHashHead::get_many` unwired | Tip seed loops `locate_head` (`scripthash.rs:1534–1541`); `get_many` only def+tests; comment at `:341` claims otherwise. | Delete (or wire, which is perf work not simplification). | ~80–120 | Forgoes a possible tip-seed IO win (Won't-fix micro-opt class). | high |
| SH-11 | Unused `ScriptHashHead` bulk APIs | `reserve_additional`, `bulk_fill_empty`, `insert_many_no_rehash`, `insert_many_full_no_rehash` — not on ingest path. | Delete after SH-01/SH-08. | ~150–250 | Head unit-test rewrites. | high |
| SH-12 | Two page-chunk models | `sh_page_chunk_ranges` (real, `scripthash_pages.rs:562`) vs `sh_page_count_for_entries` (`549–554`) → `page_alloc_bytes_for_n_fks` (lib-exported, unused outside). | Delete the estimate pair. | ~40–80 | none | high |
| SH-13 | Vec-allocating codec wrappers duplicate `*_into` | `encode_slab_payload`, `decode_slab_payload`, `encode_fk_delta_stream` (`scripthash_slabs.rs:105–196`) — tests only. | `#[cfg(test)]` or delete; unexport. | ~40–60 | none | high |
| SH-14 | Inflated `lib.rs` SH exports | See X-04. | Narrow to `ScriptHashTable` (via `Store`), `script_hash`, `ShHeadValue`, `sh_heads_insert_capped`, materialize entrypoints. | ~20–40 | none | high |
| SH-15 | `scripthash_tests.rs` 2,357 / 62 tests + ~1.5–2k inline | **partial (#414)** `tmp()` is store `TempDir`. Bulk/extent/unsorted edge-packing and `create_fks_matches_entries` kept (one pin per those shipped paths). | Optional later: drop remaining bulk megakey twins only if LCOV still covers. | remaining twins | Coverage gate; keep edge-packing pins. | medium |
| SH-16 | Stale comments/docs sustain the dual-path illusion | `scripthash.rs:3328` "install live OA image"; `scripthash_pages.rs` rustdoc. | Fix with SH-01/SH-02. | docs | none | high |
| SH-17 | `ScriptHashRecord::is_tombstone` vestigial | `scripthash.rs:202–204`; tests only; batch path inlines the check (`1522`). | Delete or use once. | ~10 | none | high |
| SH-18 | `MaterializeStageNs` / `UnsortedShardCollect` over-exposed | Internal-only but `pub`. | `pub(crate)`. | 0 | none | high |

**Not excess (checked):** four-tier lookup, `put_create_batch_append` + `AppendTiming` (consumed by `connect.rs:436`), `MphfHead` BDZ3 + pack8, L0 SHSR+fuse, ingest OA core, inline/slab/extent geometry, page `ver=1/2` (Won't fix), unsorted collect/materialize, leftover OA refuse, `sh_heads_insert_capped`, `unlink_create` (reorg), freelist/SHAL/64 KiB grow. `soft_densify.rs` is not SH.

---

## 4. `rbitcoin-query` — 17.7k

Real layer, not a pass-through: BQ + resolved wire, stamp/`InFlight`/`BatchParents`/header plans, Class A plan+commit, Class C + SH write-behind, `IndexMode`, `ChainView`, wallet SH joins, reconstruct/merkle, SP-tweak serve. Excess is meters, facade tax, a dual Class A planner, and tests.

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| Q-01 | Dead pstore fields on `ibd: sizes` | `ProcessOwnedSizes` doc says always 0 (`lib.rs:72–75`); `process_mem_stats::note` (`:109–122`); `ibd/confirm/mod.rs:71` passes `0,0,0`; `perf_log.rs:1878,1971–1972` prints them. | Drop fields + format tokens. | ~70 | Size-line shape changes. | high |
| Q-02 | `confirm_load_stats` never-written meters | `lib.rs:180,189,193,201,212–218,220–228` (see X-01 list); `perf_log.rs:300–304,1063–1078,1517–1524` still samples them. | Delete (X-01). | ~120–180 | `ibd: perf` field set shrinks. | high |
| Q-03 | `ConfirmLoadStats` test-only scaffolding | `confirm_load.rs:14–46`; `note` is `#[cfg(test)]` (`lib.rs:369–402`); no outside user. | Delete; fold remaining `confirm_load.rs` into `confirm_parent_cache.rs`. | ~80–100 | none | high |
| Q-04 | Micro-modules | `wave_prevout.rs` (10), `resolved_wire.rs` (23), `confirm_load.rs` (61), `run_builder_core.rs` (99, used only by `sh_builder`). | Fold into their sole consumers. | ~30–50 | none | medium-high |
| Q-05 | `archive_filter_need_bodies` dead  **done (#415)** | `archive.rs:412` def; only a test comment `:2329`; IBD uses `archive_filter_need_header_fks` (`lookup.rs:415`); doc claims "used by IBD prep" (false). | Delete + fix comment. | ~25–40 | none | high |
| Q-06 | Dual Class A planners (wire vs `TxApply`/store)  **done (#427)** | IBD and `commit_class_a_block`/`_run` plan with `archive_class_a_from_wire` (from_wire + fill). `archive_plan_batch_from_store` deleted. | — | — | Packed-ins pin is `commit_class_a_only_writes_packed_ins_from_wire`. **Q-21** moves remaining TxApply conversion out of `Query`. | high |
| Q-07 | `archive`/`catchup`/`connect` are not three confirms | Roles: Class A plan/commit; `IndexMode` + SH finalize; Class C tip + SH enqueue/disconnect. | Rustdoc only. | ~0–20 | Do not collapse. | high (not excess) |
| Q-08 | Three parent structures are three jobs | `BatchParents` (batch outs), `InFlight` (tip-ahead creates), `ConfirmParentCache` (header plans only). | Rename `ConfirmParentCache` → `HeaderPlanCache`. | 0 | Merging would violate plan/batch-only pins. | high (not excess) |
| Q-09 | `tx_precompute` not duplicated | Consensus `block/tx_precompute.rs` is tests only re-exporting query's type. | Move tests; delete empty consensus module. | ~65 (file) | none | high |
| Q-10 | SP tweaks: store table / query serve / consensus crypto | Correct ownership. | none | 0 | — | high |
| Q-11 | SH: store tables vs query join | Layered. `soft_densify.rs` is BQ assign policy (could live in net). | none / optional move. | 0 | dep change | high |
| Q-12 | `lib.rs` 2.45k anatomy | Re-exports 1–167; `confirm_load_stats` 173–403 (bloated); `archive_phase_stats` 411–887; `class_c_phase_stats` 888–1023; `wave_fill_stats` 1025–1054; `Query` core 1058–1446; BQ/index wrappers 1455–2000; store pass-throughs 2003–2450. | After X-01, peel stats to `stats.rs` (*move*); delete dead meters. | ~150–250 deleted; ~900 moved | — | high |
| Q-13 | Thin store pass-throughs | `tip_height`, `fence_tip_height`, `put_header`/`get_header`, `get_tx→get_tx_class_a→store.get_tx` (`2052–2059`), `put_spend`/`spenders*` (`2116–2150`), `flush_header_archive`, probe counters (`1907–1932`). Esplora already uses `query.store()` (`handlers.rs:315,466,496`). | Callers use `query.store()` for pure reads; keep policy-adding methods (txid gate, header overlay, strong spentness). | ~80–150 | API churn in electrum/rpc/net. | medium |
| Q-14 | Dead / test-only pub APIs **partial (#415)** | `is_outpoint_spent_create`, `backfill_point_spends` (+`point_edge_count`), `tx_fence_max_connected_fk`, `is_header_archived`, `sample_reset_thin_tweak_body_bytes`, `format_disconnect_tip_line`, `SharedParentPin`, `SPENDER_REL_UNKNOWN`, `ExternalParentStamp`, `apply_history_filter` export, `BQ_ASSIGN_STOP_BYTES`/`BQ_SOFT_CONFIRM_SECS`/`soft_assign_stopped`. | `pub(crate)` or delete. `backfill_point_spends` (~60) is a repair tool with no caller — delete or put behind a CLI subcommand. | ~120–200 | Losing a manual repair tool nobody calls. | high |
| Q-15 | `id_map.rs`, `chain_view.rs` | Needed seams (hot maps; wallet pin A-B-A). | keep | 0 | — | high |
| Q-16 | Env knobs | `RBITCOIN_BLOCK_QUEUE_*`, `RBITCOIN_SH_FORCE_REBUILD` — documented. | none | 0 | — | high |
| Q-17 | Test mass | **done (#414)** `catchup` inlines use `tiny_query_labeled`. Named `temp_query` wrappers from #411. `connect_chain_query_surface` kept (only `height_of_hash` / `tx_output_at_fk` / `merkle_proof` journey). | Optional later surface trim if another pin lands. | remaining surface | Coverage gate. | medium |
| Q-18 | `get_tx` / `get_tx_class_a` alias | `lib.rs:2052–2059`, comment about removed pin FIFO. | One name. | ~5 | none | high |
| Q-19 | `FkMap`/`U64Map` re-exported through query | `batch_parents.rs:31`; consensus imports from query though store owns them. | Import from store. | ~5 | none | high |
| Q-20 | Layering vs `confirm_run` | Consensus orchestrates; query owns structures + store IO. | keep | 0 | — | high |
| Q-21 | Class A-without-tip dummy `Block` adapter  **done (this PR)** | `tx_apply_to_tx` / `block_from_applies` / `FixtureChain` live in `rbitcoin_query::testutil`. Production `Query` has no `connect_block` / `commit_class_a_only` / `archive_prepared_*`. Packed-ins pin still holds. | — | — | Fixtures still call `q.connect_block` via the test trait. | high |

---

## 5. `rbitcoin-consensus` — 30.3k (~15k production)

Pinned `bitcoin` resolves to **0.32.102** (`Cargo.toml` says `0.32.101`; `docs/rust-bitcoin-limitations.md:7–8` says 0.32.101). RB-001–RB-009 re-checked and still hold.

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| C-01 | Never-incremented `confirm_phase_stats` meters | `lib.rs:93–598` (65 statics); dead list in X-01; live examples `ASM_PREVOUT_NS` (`block/mod.rs:1444`), `LOAD_NS` (`lookup.rs:252`). | Delete dead statics + sample slots (X-01). | ~80–120 | none | high |
| C-02 | `lib.rs` = meters + thin wrappers | ~506 meters, ~180 wrappers, ~280 tests, ~80 re-exports; `mod coverage_tests` (`:795`) exists to paint lines. | After C-01 move stats out; delete wrappers in C-03. | ~50–100 | import churn in `perf_log`. | high |
| C-03 | Thin / test-only pub APIs  **done (this PR, archive-prep)** | `prepare_block_for_archive` is the one CPU-side Class A helper; `_new` private; `_with_txids` deleted; `validate_block_structure_precomputed` is `pub(crate)`. `check_block_wire` / `verify_tx_scripts_detached_forks` stay pub (fuzz). Confirm_run wave/phase names stay crate-pub (IBD pipeline). | — | — | Live IBD stage names are not archive-prep twins. | high |
| C-04 | Typed script fast paths (`p2pkh`/`p2wpkh`/`p2wsh`/`p2tr`/`nested`) | Single dispatch (`script/mod.rs:86–168`); P2PKH bare fallback only on scriptSig shape error (`:135–140`, Core parity). Prod sizes small; tests dominate (`p2tr` 159/934, `nested` 157/688). | **Keep.** Collapsing to interpreter-only is a second consensus rewrite. Optional: document host A/B. | 0 | HIGH if removed. | high (not excess) |
| C-05 | Duplicated SPK template predicates | `script/classify.rs:57–80` vs `silent_payments.rs:473–508` vs `block/mod.rs:389–398` (sigops) vs `core_vectors.rs:513`. | One `spk` helper set used by silent-payments and sigops. | ~35–50 | BIP352 eligibility must stay exact. | high |
| C-06 | `AssembleMode::Full` + `validate_block_connect` dual assemble  **done (#426)** | Optimistic assemble + `structural_validate_spends` only. Connect tests use `accept_and_connect_block`. `verify_scripts_pool` deleted; ACS skip pinned on shipped `verify_one_script_job`. | — | — | Immature pin is `c5_immature_coinbase_spend_rejected`. Remainder **C-19**: `try_for_each_parallel` still `#[cfg(test)]`. | high |
| C-07 | `confirm_run` vs `ibd/confirm` | Layered (stages vs threads/queues). `bq_resolve.rs` ≈431 prod / 1,053 test; one TipOnly wave. | none for architecture. | 0 | — | high (not excess) |
| C-08 | `script_pool.rs` | ≈443 prod / 752 test; 11 `unsafe`; Won't-fix says no coordinators. | Keep; trim over-covered steal/unpark permutation tests after LCOV check. | 0 prod; ~100–300 test | HIGH if swapped for rayon. | high |
| C-09 | `silent_payments.rs` | ≈624 prod / 777 test; crypto here, index in store, serve in query. | C-05 only. | ~30–40 | — | high |
| C-10 | `signet` / `regtest_pad` / `block_866342` / `milestone` | Proportionate; heavy external use. | none | 0 | — | high |
| C-11 | `block/tx_precompute.rs` | Tests only (see Q-09). | Rename/move. | 0 | none | high |
| C-12 | Sigops layering OK; tests duplicated | `structure_rule_tests.rs:769+` repeats primitives cases. | Delete duplicated primitive asserts. | ~25–40 test | none | high |
| C-13 | `pad_empty_from` ×2 | `consensus/regtest_pad.rs:120` vs `rbitcoin-test/src/chain_fixture.rs:84`. | Test crate calls consensus. | ~20 | none | high |
| C-14 | Test file mass | **done (#414)** structure-rule Tiny opens use `tiny_query`; BIP34 encoding in `bip34_tests`; structure-rule keeps wrong-encoding reject. write_idempotent converted in #411. | Optional: `tests_verify.rs` mass. | remaining verify mass | Coverage ≥90%. | medium-high |
| C-15 | Over-abstraction / knobs | No traits; flags concrete; env = test/corpora only. | none | 0 | — | high |
| C-16 | Doc pin drift | `rust-bitcoin-limitations.md` 0.32.101 vs lock 0.32.102. | Fix doc. | docs | none | high |
| C-17 | `error.rs` variants | all live. | none | 0 | — | high |
| C-18 | `convert.rs` | on hot/test paths. | none | 0 | — | high |
| C-19 | C-06 leftover: `#[cfg(test)]` script-pool twins  **partial (#426)** | `verify_scripts_pool` deleted; ACS skip is `verify_one_script_job`. Remainder: `try_for_each_parallel` is still `#[cfg(test)]` (`script_pool.rs`) because steal-permutation tests call blocking `run_wave(false)`. Production IBD uses `start_for_each_owned`; silent-payments uses `try_for_each_parallel_idle`. | Retarget steal tests onto `start_for_each_owned` / `try_for_each_parallel_idle`; delete `try_for_each_parallel`. Do **not** keep `#[cfg(test)]` production fns to paint lines. | ~20–40 + test retarget | Coverage of deleted wrappers is expected; CI coverage job is the gate. | high |

**Not excess (checked):** `interpreter.rs` opcode match (R-10), local sighash/DER-lax/BIP143 midstates (RB-002/003/004/009 still needed), in-tree engine vs `bitcoinconsensus` (RB-008), Core vector runners, `params`/`policy`/`header`/`clock`.

---

## 6. `rbitcoin-net` (non-IBD) — ~31k incl. 6.7k `peer_tests.rs`

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| N-01 | Dead `NetConfig` / `P2PHandle` / `handle()` | `service.rs:28–46, 73–77, 212–220`; re-exported `lib.rs:84`; only a unit assert `:622` uses `NetConfig::for_regtest`. | Delete. | ~55 | none | high |
| N-02 | Unused re-exports | `PeerRateLimiter`, `DEFAULT_MAX_BYTES/MSGS_PER_SEC`, `QueryUtxoProvider`, `magic_for*`, `TipAcceptShInput`/`format_tip_accept_sh_line` (`chain.rs:2293–2320`). | X-04. | ~15–25 | none | high |
| N-03 | `handle_peer_frame_for_test` flat-arg shim | **done (#414)** Tests hold `PeerFollowState` and call shipped `handle_peer_frame`. Unpacking shim deleted. | — | — | none | high |
| N-04 | `peer_tests.rs` fixture sprawl | **done (#412)** `tiny_regtest_hub` / `tiny_regtest_hub_labeled` compose Tiny query + shipped `ChainHub::new`+regtest. `peer_tests` 69 hubs and named `tmp_hub` in `chain.rs` / `ibd/reorg.rs` / `ibd/assign.rs` call it. Query-only peer tests keep `tiny_query_labeled`. IBD leftover hubs converted in #414 (I-14). | Skip: fuzz `diff_regtest_params`, dersig/cltv overlays, production `P2PNode`. | — | none | high |
| N-05 | Near-duplicate long integration tests | `disconnect_clears_far_side…` / `…after_tip_sync…` (`6322–6524`); `compact_tip_announce_must_not_wrap…` / `…consume_serve_slots` (`5824–6039`); 591-line `handle_peer_frame_control_and_inv_paths` (`2214–2804`). | Parameterize pairs; split kitchen-sink only if maintenance bites. | ~150–250 | Flaky timing; keep wall-clock asserts. | medium |
| N-06 | Compact fill reconstructs twice on miss  **done (#415)** | `on_cmpctblock` → `try_fill_cmpct` then `try_cmpct_missing` (`peer.rs:2749, 2782`), both rebuild short-id map + `compact::try_reconstruct` (`1667–1687`). | One helper returning `Full(Block) \| Missing(Vec<u64>)`. | ~15–25 | Hot path; preserve getblocktxn fallbacks. | high |
| N-07 | `block_diff.rs` in the node crate  **done (#416)** | See X-07. | — | 3,149 *moved* | coverage scope | high |
| N-08 | Dual `DEFAULT_MAX_INBOUND` | X-09. | One owner. | ~5–10 | none | high |
| N-09 | `ChainHub` mixes RPC/mining admin into the P2P hub | Fields `chain.rs:228–270`; RPC-only: `generate_lock` + `generate_to_script`/`assemble_block_to_script` (`1234+`, ~70), `MiningKnobs`, `chaintips` (`623–809`, ~187), `invalidate`/`reconsider`/`precious` (`1303–1527`, ~225). | Extract a `MiningHub`/chain-admin type behind the same `connect_lock` **only when a Q-row needs the seam** (R-10). | 0 deleted; ~400–500 moved | tip-accept ownership; high regression risk. | medium |
| N-10 | `LivePeer` / `PeerHub` field sprawl | `peers.rs:100–179+, 868–903`. | Group into composed sub-structs (readability). | ~0–50 | `getpeerinfo` mapping. | medium |
| N-11 | `P2PNode.cache` duplicates `hub.cache` | `service.rs:111`; used by multinode tests only. | Tests use `node.hub.cache`. | ~10–20 | test edits | medium |
| N-12 | AddrMan picker matrix | `take_outbound`, `_occupied`, `_offset`, `_offset_occupied` (`seeds.rs:523–557`). | `take_dial_candidates` + one occupied API with offset param. | ~30–50 | dial diversity in `run.rs`. | medium |
| N-13 | Fuzz-only encoders exported (grew in #395)  **done (#416)** | Recipe + v2 encode wrappers live in `fuzz/src/cmpct_fuzz.rs`. Fixtures under `fuzz/fixtures/`. | — | ~230 *moved* | fuzz.yml unchanged | high |
| N-14 | `v2_handshake_timeout_log` double wrap  **done (#415)** | `v2.rs:64` rewrapped `peer.rs:238–239`. | Call `v2::` directly. | ~5 | none | high |

**Not excess (checked):** `reactor.rs` (real seam), `tip_accept.rs`, `most_work.rs`, `asked_blocks` vs `requested_blocks`, tip vs IBD locators, `accept_block` layering, INV helper trio, mempool `try_*` vs blocking, `codec`+`msg_decode`, `BlockCache` vs `held_bodies`, `write_v2_msg` vs `_offload`, `PeerConnType` variants, `V2PlainSession`, `seeds.rs`/`asmap.rs`, Core log-needle helpers, `NetError` variants, `getblocks`, `versionbits_warn`/`serve_perf`/`eviction`/`netgroup`/`peer_dos`.

---

## 7. `rbitcoin-net/src/ibd` — ~36k incl. tests

Shipped pipeline: `run.rs` → `sync_cancellable`; IBD dials own peers; raw frames → body channel; main loop cadences assign ≤50 ms / headers ≤500 ms / hygiene ≤1 s; assign issues getdata under BQ soft window; confirm OS threads lookup → load → scripts → write (consensus owns phases); most-work reorg is **header rewind** to LCA + linear confirm (not gathered `accept_branch`); `archive.rs` = restart Class A→BQ rehydrate.

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| I-01 | Dead `AwaitingBodies` / `set_awaiting` state machine  **done (#415)** | `set_awaiting` callers are only inside `#[cfg(test)] mod tests` (`assign.rs` tests start `:1004`, callers `:1243,2026,2194,2554`; `exit.rs` tests start `:180`, caller `:463`; `reorg.rs` tests start `:907`, caller `:1445`). Production branches on it at `mod.rs:519`, `exit.rs:45`, `assign.rs:146/654/938`; `try_complete_awaiting_reorg` (`events/mod.rs:820–825`) is an alias of `try_apply_exploration`. | Delete `AwaitingBodies`, `set_awaiting`, `awaiting()`, `awaiting_need_getdata`, `is_awaiting_held_tip`, the gates, and the main-loop poll (I-19). | ~150 prod + ~400 test | Reorg behavior unchanged (header rewind stays). | high |
| I-02 | `held_bodies: HashMap<BlockHash, Block>` but only `contains_key` is read in production  **done (#415)** | Write `events/mod.rs:402` `hold_body` (decodes a full Block); `get_held` only in tests; `need_getdata` (`reorg.rs:206–214`) uses presence only; comment `reorg.rs:174–178` admits it. | `HashSet<BlockHash>` (or drop the hold entirely). RAM-positive. | ~80 prod + ~200 test | Not ContigPark/archive-sticky. | high |
| I-03 | `#[cfg(test)]` body-gather / `accept_branch` stack in `reorg.rs`  **done (#415 / already gone)** | `candidate_from_blocks` / `apply_reorg_branch` / `try_apply_best_candidate` are gone. Shipped path is header rewind. | — | — | `classify_bad_prev` kept as I-14 pin helper. | high |
| I-04 | IBD `held_bodies` vs tip `HeldBodies` naming | Different products; after I-02 rename IBD set to `explore_have`. | rename | ~0–50 | none | high |
| I-05 | Always-zero perf meters on the IBD surface | `IbdPerfSample` has **239** fields; `RECONSTRUCT_*`, `WRITE_RECENT_*` never `fetch_add`; `docs/ibd-memory.md:129` already says `pstore=`/`recent=` stay 0; format paths still emit `recon_ms`/`wf_body_store`/`sh_collect_pin` via `append_nz` (`perf_log.rs:1401+, 1656+`). | Delete with X-01. | ~400–700 perf_log + ~50–100 consensus | DEBUG token set shrinks; keep live inventory. | high |
| I-06 | `perf_log.rs` machinery  **done (#420 write-stage table)** | 2,869 (≈2,023 prod); `WriteStageSample::stage_ms`/`stage_ns` duplicate field lists (`:111–146`); `sample()` pulls 17 `sample_*` helpers; three hand-rolled formatters. | Table-driven tokens (X-01 step 3). | ~300–500 | Macro opacity; log-contract tests. | medium |
| I-07 | Stale "archive" vocabulary | `archive_pipeline_saturated` (`assign.rs:184–190`, ignores `_pending_len`), unused `_archive_write_next` (`:201`), `drain_ready_peer_and_archive_events`, `arch_ahead`, startup log `archive: 1 OS prep + 1 OS writer` (`mod.rs:271`, false — I-22). | Rename to body-queue/densify/write-next; delete dead params; fix log. | ~20–40 | none | high |
| I-08 | `assign.rs` vs `assign_plan.rs` | Not a dual path; `assign.rs` is ~1,003 prod + ~1,660 test. | Move tests (*move*). | ~300–600 moved | none | high (not excess) |
| I-09 | `progress`/`status`/`rate`/`cadence` | Four distinct jobs. `progress.rs:388+` re-tests `soft_confirm_window_n` already pinned in query. | Drop duplicate asserts only. | ~30–50 test | none | high |
| I-10 | `exit.rs` | Irreducible except the `awaiting` clause (`:45`). | with I-01. | ~5 | none | high |
| I-11 | IBD dial vs `PeerHub::dial` | Phase split, not duplication. | none | 0 | coupling risk if merged | high (not excess) |
| I-12 | IBD headers vs tip headers | Intentional. | none | 0 | — | high |
| I-13 / I-23 | Reject class: typed `from_consensus`/`from_net` + substring `from_err_str` | `confirm/mod.rs:363–405` vs `:407+`; typed used at send sites (`1536, 1622, 1801, 1942`). | Restrict the string map to Store `Corrupt` messages; assert typed path elsewhere. | ~40–80 | Wrong class → blacklist vs cascade; keep the reject-surface pin. | medium |
| I-14 | `confirm_reject_tests.rs` 3,284 + fixture farm | **done (#414)** Remaining Tiny+hub IBD tests call `tiny_regtest_hub_labeled`. Blacklist vs cascade vs BadPrev pins stay. | Optional later: one pin per reject class (test mass). | remaining test mass | Keep the only pin for blacklist vs cascade vs BadPrev rewind. | medium-high |
| I-15 | `confirm/tests.rs` 1,283 | Engine-wiring pins; some overlap with consensus/scenarios. | Trim duplicate policy pins only. | ~100–200 | — | medium |
| I-16 | Env knobs | none new. | — | 0 | — | high |
| I-17 / I-18 | `archive.rs` rehydrate + `BodyPresence::mark_archived` | Shipped restart path; names mislead. | Rename `rehydrate.rs`, `mark_class_a`. | rename | none | high |
| I-19 | Main-loop `awaiting` poll  **done (#415)** | `mod.rs:519–522` never true in production. | with I-01. | ~10 | none | high |
| I-20 | dial/assign/reorg test ratio 50–62% | under I-14. | — | — | — | medium |
| I-21 | Over-abstraction | none (one `FnMut` in write drain). | — | 0 | — | high |
| I-22 | False startup log | `mod.rs:271`. | fix string | ~3 | none | high |
| I-24 | Single-use caps | product-documented (`TIP_HOLE_MAX`, `CONTIG_DENSIFY_AHEAD`, …); only `_pending_len` is dead. | — | ~5–15 | — | high |

**Not excess (checked):** cadence split, exit matrix (guards a real mid-chain all-peers-dead bug), named stage timers, soft densify / never-refuse-enqueue, four-thread confirm engine, `BodyPresence` bookkeeping, relative-slow/stall disconnect, `RBITCOIN_BLOCK_QUEUE_*`.

---

## 8. `rbitcoin-rpc` / `rbitcoin-electrum` / `rbitcoin-esplora` — ~20.6k

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| A-01 | ~~COMPAT says decode RPCs "done"; node rejects them~~ **done (#397)** | Node now ships `methods/decode.rs` (66 lines: `decoderawtransaction`, `decodescript`, `validateaddress` subset); `COMPAT.md:63`, `docs/rpc.md`, `core-functional.md`, `inventory.toml` describe the node/proxy split. Never-list shrank to `createrawtransaction` / `signrawtransactionwithkey` / `createmultisig` / `combinerawtransaction` / `deriveaddresses` / `gettxoutsetinfo`. | — | — | Proxy still owns Core wrap/miniscript/`error_locations`; `rpc_decodescript.py` stays `run` via proxy. | — |
| A-02 | Seven `METHOD_LIST` methods undocumented  **done (#424)** | `docs/rpc.md` names `getnettotals`, `ping`, `addpeeraddress`, `getnodeaddresses`, `estimaterawfee`, `getnetworkhashps` (dummy 2-work-per-block), `mockscheduler`. | — | — | Q-59 rest **done (#428)**. | high |
| A-03 | Electrum surface = COMPAT 1.4.2 (+asof) | dispatch `server.rs:1196–1525`; stubs `donation_address`, `peers.subscribe` are client-probed. | none | 0 | — | high (not excess) |
| A-04 | No graphical-explorer Esplora endpoints exist | routes `esplora/server.rs:374–451`. | none | 0 | — | high |
| A-05 | Auth/limits not triple-copied | RPC alone has cookie/Basic; Electrum+Esplora share `ServeLimits`. | none | 0 | — | high |
| A-06 | `TipNotify` thin wrapper beside `TipEvent` | `electrum/server.rs:191–197`; bridge `run.rs:1219–1228`; Esplora consumes `TipEvent` directly. | Electrum subscribes to `TipEvent`; drop `TipNotify` + bridge. | ~20–40 | payload must stay identical. | medium |
| A-07 | Dual `sh_at_view` | `electrum/server.rs:1155–1179`, `esplora/handlers.rs:525–554`. | Optional shared helper in query; small payoff. | ~20–40 | callback noise if forced | medium-low |
| A-08 | Script classification ×2 (vocabulary now explicit after #397) | RPC `script_core_type` + `is_p2anchor` (`mine.rs:55–86`, Core names `pubkeyhash` / `witness_v0_keyhash` / `anchor` / `nonstandard`) vs Esplora `classify_script` (`script_fields.rs:36–65`, `p2pkh` / `v0_p2wpkh` / `unknown`); both sit on the same rust-bitcoin `is_p2*` predicates. Inline asm still in `chain.rs:471–474, 527`. | One `ScriptKind` enum in `rbitcoin-primitives` (or query) with `core_name()` / `esplora_name()`; both crates map from it. `gettxout` / `getblock` inline asm go through `script_pubkey_json`. | ~40–70 | do not unify full tx JSON; Core `anchor` vs Esplora `v1_p2a` naming must stay per-schema. | medium |
| A-09 | Two tx→JSON serializers | Core `tx_to_json` (`mine.rs:985–1024`) vs Esplora `tx_json.rs`. | **Keep both** (different wallet schemas). | ~0–30 | merging breaks Sparrow/Casa vs Core verbose | high (not excess) |
| A-10 | SH history/UTXO joins | single owner (`query/scripthash.rs`; electrum `unspent.rs` overlay reused by Esplora). | none | 0 | — | high |
| A-11 | Esplora address/scripthash twin handlers ×6 | `handlers.rs:556–779, 953+` — resolve address → identical `sh_*` body. | `with_sh(resolve)` wrapper; one body per pair. | ~100–180 | none | high |
| A-12 | Repeated error/response mapping | ≈100 `into_response`/`store_err`/`spawn_join`/`maybe_attach_view` sites. | Finish the existing helper set. | ~50–100 | keep status codes | medium |
| A-13 | `esplora/server.rs` is ~72% inline tests | 2,356 total; `mod tests` from `:653` → ~652 prod / ~1,704 test. | Move to `server_tests.rs` (*move*). | 1,704 moved | none | high |
| A-14 | `electrum/server.rs` density | `handle_client` 321, `serve_tweaks_subscribe` 205, `dispatch_pinned` 349 — protocol, not dead code. | Peel only for a seam (R-10). | 0 | — | high |
| A-15 | Tweaks-stream logging boilerplate | 8 `api_call` blocks `server.rs:690–744…`. | local `log_and_err` closure. | ~40–80 | none | medium-high |
| A-16 | `tweaks.rs` | Cake/kiss-bdk protocol on top of `query/sp_tweaks.rs`; COMPAT-required. | keep; `pub(crate)` helpers. | 0 | — | high |
| A-17 | `blockstats.rs` 573 | `rpc_getblockstats.py` is `run`; helpers `pub` but file-local (`PER_UTXO_OVERHEAD`, `truncated_median`, …). | visibility only. | 0 | none | high |
| A-18 | `RpcParams` named-arg boilerplate | Core dialect tax (`reject_unknown` chain 24 / mempool 25 / mine 31 / net 12). | none | 0 | — | high |
| A-19 | Over-abstraction | `RpcRegtest` has two impls; no one-impl traits. | none | 0 | — | high |
| A-20 | `submitblock` regtest clamp vs docs  **done (#424)** | Live `ChainHub` on all networks (same receive path as P2P). | — | — | `generate*` / `setmocktime` stay regtest-only. | high |
| A-21 | Test harness duplication | **done (#414)** RPC leftover `temp_dir` inlines use `TempDir`. Electrum `tmp_store` / Esplora `temp_query` wrap `tiny_query` (#411). | `run_electrum` / `http_get` stay production vs protocol-local. | leftover protocol clients | WS/subscribe timing flake | medium |
| A-22 | Crate-public helpers used only internally | `post_rpc`, `basic_auth_header` (tests only), `EsploraScriptFields`, `PER_UTXO_OVERHEAD`, … | X-04. | 0 | none | high |
| A-23 | Duplicate rustdoc lines | `net.rs:201–202`, `mempool.rs:61–62`. | delete | 2 | none | high |
| A-24 | Electrum flat dispatch | fine as-is. | — | 0 | — | high |
| A-25 | Knob sprawl | low; `ServeLimits` are compile-time. | — | 0 | — | high |
| A-26 | Never-method reject list | intentional fence (`methods/mod.rs:471–476`); decode names left it in #397, remaining six are wallet/coins-DB. | keep | 0 | — | high |

---

## 9. `rbitcoin-mempool` — 5.7k

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| M-01 | Over-exported constants/helpers | ~40 names in `lib.rs:34–58` re-exports unused outside the crate (`pure_rbfr_pays`, `rbf_*`, `MapUtxoProvider`, `MAX_PACKAGE_*`, `RBFR_RATIO_*`, `fee_est` helpers, `MEM_MAGIC`/`MEM_SCHEMA`, …). | X-04. | ~0–20 | none | high |
| M-02 | `FeeFlowMeter` confirm/evict EMA never read; `note_evict` never called  **done (#415)** | `fee_flow.rs:19–20, 67–73, 95–99`; only `admit_rates_wu_s` is read (`tx_relay.rs:1383–1384`); `rg note_evict` → definition only. | Delete confirm/evict channels + `note_evict`. | ~40–70 | none (doc describes admit EMA only) | high |
| M-03 | `fee_est` vs `fee_flow` | capacity math vs EMA meter; not two estimators. | none | 0 | — | high |
| M-04 | Duplicate min-relay constant | `accept.rs:104` = `policy.rs:15`. | alias (X-09). | ~3–5 | keep Core's "incremental" name | high |
| M-05 | Accept policy is Libre + structure; no dead Core standardness | `accept.rs:612–615` → `check_libre_admission_at`; dust/OP_TRUE allowed by test. | none | 0 | — | high |
| M-06 | `accept.rs` 2,693 ≈ 1,273 prod + 1,420 test | — | peel tests (*move*) if a seam is needed. | 0 | — | high |
| M-07 | Cluster graph | matches 64 / 101 kvB caps + GBT/prioritise. | none | 0 | — | high |
| M-08 | Private mempool sidecar | intentional (`rBMP`); Q-58 owns persist order. | none | 0 | — | high |
| M-09 | `bucket_index` redundant scan | `fee_est.rs:23–47`. | single edge walk. | ~10–15 | none | medium |

---

## 10. `rbitcoin-node` — 5.8k

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| D-01 | CLI `CliAccum` vs conf `apply_kv`  **done (#418)** | See X-05. | — | ~400–600 | high harness risk | high/medium |
| D-02 | OPERATOR flag table lags shipped CLI  **done (#424)** | OPERATOR documents shipped knobs; `--permitbaremultisig` is not a node flag. | — | — | — | high |
| D-03 | `--permitbaremultisig` is display-only  **done (#424)** | Flag deleted. `getmempoolinfo.permitbaremultisig` is always `true`. Core-functional shim still ignores `-permitbaremultisig`. | — | — | Do not add Core standardness. | high |
| D-04 | Electrum/Esplora start/shutdown glue | `run.rs:1235–1331` parallel bodies; shutdown `928–947`. | one `ServiceStart` table for the two SH services. | ~40–80 | SH-ready gating | medium |
| D-05 | `inhibit.rs` | small, used. | none | 0 | — | high |
| D-06 | `regtest_rpc.rs` | `RpcRegtest` adapter, not a second server. | optional move next to hub. | 0 | — | high |
| D-07 | `run_p2p` ≈1,617 prod + 815 test | orchestration; `TipModeGates`/`CatchUp` already named. | peel only for a seam. | 0 | R-10 | high |
| D-08 | Over-exported node types | `SuspendInhibit`, `HubRegtest`, `*Opts`, `NodeError`, `NodeHandle`, `inbound_from_maxconnections`, `ConfApply`, `parse_minimum_chain_work`. | `pub(crate)` except what `rbitcoin-test` uses. | ~0–10 | none | high |
| D-09 | `--minrelaytxfee` parse failure silently ignored  **done (#424)** | Garbage and negatives fail at config parse (`0` is still no floor). | — | — | — | high |

---

## 11. `rbitcoin-log` (657), `rbitcoin-primitives` (628), `rbitcoin-cli` (416), `rbitcoin-test` (406 + 4k tests), `rbitcoin-bench` (2.9k, optional)

| ID | Item | Evidence | Proposal | LOC | Trade-off | Conf. |
|----|------|----------|----------|-----|-----------|-------|
| L-01 | Custom logger vs `tracing` | zero deps; Q-32 Won't-fix. | keep | 0 | — | high |
| L-02 | Two capture mechanisms  **done (#415)** | `#[cfg(test)] LAST_LOG` (`lib.rs:64–96`, 3 uses) alongside `CAPTURE`/`CAPTURED` (used by 5 crates). `info_bold!` has exactly one caller. | Delete `LAST_LOG`/`take_last_log`; keep `capture_logs`. | ~20 | none | high |
| L-03 | `api_log.rs` | operator `--api-log`; retired micro-opt. | keep | 0 | — | high |
| P-01 | `hex.rs` | intentional zero-dep + display-order helpers (104 uses). | keep | 0 | — | high |
| P-02 | `median_time.rs` (20 lines) | file for one fn. | inline (marginal). | ~0–20 | none | low value |
| P-03 | Dead `TableKind` variants | X-09. | X-09. | ~10 | none | high |
| T-01 | `rbitcoin-cli` | lean HTTP JSON-RPC; bench `jsonrpc.rs` is line-JSON for Electrum/Esplora — not a duplicate. | keep | 0 | — | high |
| T-02 | Bench private `hex.rs` duplicates primitives  **done (#415)** | `bench/src/hex.rs` (48); bench has no primitives dep. | depend on primitives; delete. | ~48 | tiny dep | high |
| T-03 | Bench suite/progress/stats | host A/B tooling, Won't-fix out of default-members. | out of scope | — | — | high |
| T-04 | `rbitcoin-test` fixtures barely reused | **partial (#411):** `rbitcoin-test::TempDir` re-exports store `testutil::TempDir`; `TestDatadir` wraps it. Low crates use store/query `testutil` directly (node dep still blocks them from `rbitcoin-test`). Hub reuse **N-04** #412 + **I-14** #414; electrum/RPC leftover inlines **A-21** #414. Remaining: `rbitcoin-test` mine / `chain_fixture` (node-level). | Keep node-level mine in `rbitcoin-test`. | leftover mine | — | high |
| T-05 | Doc cites nonexistent `RBITCOIN_TEST_NO_SUCH_CAP` | `docs/env-knobs.md:53` only. | fix doc | docs | none | high |

---

## 12. Totals and sequencing

| Bucket | Deleted LOC | Moved LOC |
|--------|------------:|----------:|
| X-01 dead counters + stats restructure (incl. I-05, C-01, Q-01–03, S-02) | 900–1,400 | ~900 (query stats → `stats.rs`) |
| X-02 `HeadScale` + ambient test knobs | 350–500 | — |
| X-03 test probes in production | 150–250 | — |
| X-04 `pub(crate)` pass + rustc dead-code fallout (S-08/11/14/17/18, SH-14, Q-14, N-01/02/13, M-01, D-08, A-22) | 400–700 | — |
| X-05 node config single representation | 400–600 | — |
| X-06 shared fixtures (N-03/04, I-14, A-21, C-14, Q-17, SH-15) | 2,500–4,500 (tests) | — |
| X-07 fuzz harness out of net (incl. #395 recipe code) | — | ~3,400 |
| Store non-SH (S-01, S-03–S-09, S-12) | 550–750 (+300–500 with S-04/S-12 product calls) | 1,900 (S-10) |
| Store SH (SH-01–SH-13, SH-17) | 1,800–2,800 | — |
| Query (Q-04–06, Q-13, Q-18–19) | 350–700 | — |
| Consensus (C-03, C-05, C-12, C-13; C-06 optional) | 150–250 (+80–150 C-06) | — |
| Net non-IBD (N-05–N-14) | 250–400 | 400–500 (N-09 optional) |
| IBD (I-01–I-03, I-07, I-13, I-19, I-22) | 900–1,500 | 300–600 (I-08) |
| API crates (A-06, A-08, A-11, A-12, A-15) | 250–450 | 1,700 (A-13) |
| Mempool / node / small (M-02, M-04, M-09, D-04, L-02, T-02, X-09) | 200–350 | — |
| **Total** | **≈9–14k deleted** | **≈8–9k moved** |

Suggested order (each a worktree PR, Red→Green→Refactor per `docs/how-we-plan.md`; several steps are pure deletion and need only the existing suite green):

1. **X-04 visibility pass** per crate (store → query → consensus → mempool → net → api → node). Zero behavior change; rustc then lists the truly dead items — delete them in the same PR.
2. **X-01 step 1 + I-05 / C-01 / Q-01–Q-03 / S-02**: delete never-written meters and their format tokens.
3. **X-02**: `HeadScale`/rebuild/soft-span as open-time parameters; remove ~140 `set_var` sites.
4. **X-06**: leaf fixture module (#411); then N-04 hub (#412); then N-03 / I-14 / A-21 / C-14 / Q-17 / SH-15 leftover inlines (#414). **Done.**
5. **Per-crate dead paths**: I-01/I-02/I-03/I-19, SH-01/SH-02/SH-03/SH-08/SH-09/SH-11, S-01/S-03/S-05–S-09, Q-05/Q-14, N-01/N-06/N-14, M-02, L-02, T-02, X-09.
6. **X-07** move `block_diff` + fuzz encoders to `fuzz/` (check coverage scope first).
7. **X-05** node config (write the flag-matrix test first).
8. **X-01 step 2–3** instance-owned stats + table-driven `perf_log`. **Done (#420 merged).**
9. **Product-gated** SCHEMA/COMPAT + honesty dual paths: S-04/S-12/SH-06/SH-07 leftover index refuse **done (#422)**. S-15 Esplora `vin` omit **done (#423)**. A-02/A-20/D-02/D-03/D-09 Q-59 honesty **done (#424)**; Q-59 rest **done (#428)**. C-06 Full assemble **done (#426)**. Q-06 one planner **done (#427)**. A-01 and S-13 landed in #397.
10. **Before X-08 remainder** — §16. Dual-path / `#[cfg(test)]` production forks / leftover dead that the program named but did not schedule, plus C-06's cfg(test) wrappers.
11. **X-08** re-enable clippy lints in batches once the remainder lands.

---

## 13. Inspected and judged not excess (consolidated)

Consensus: `interpreter.rs`, typed script fast paths, local sighash/DER/BIP143 (RB-*), in-tree engine, `script_pool`, `confirm_run` stage split, `bq_resolve`, `silent_payments` crypto, signet/regtest_pad/milestone/params/policy/header/clock/error/convert, Core vector runners.
Store: BDZ/fuse layering, `tx_head_mphf`, head roles per `heads.md`, `open_address`, `pending_head`, all io_uring/pool/IOCP machines and the shared harvest session, `head_resolve_stats` live timers + leftover diag, compact/int_map/block_wire/store_secret/height_fence, schema-refuse pins; SH four-tier lookup, `put_create_batch_append`, MphfHead/SortedHead/ingest OA, slab/extent geometry, materialize, leftover refuse, `unlink_create`, allocator.
Query: `BatchParents`/`InFlight`/`ConfirmParentCache` (three jobs), stamp helper, `TxPrecompute`, SP-tweak split, SH join/`ShWriteBehind`, `ChainView`, `IdMap`, wire planner + Class A commit, `connect`/`catchup`, `IndexMode`, reconstruct/merkle.
Net: `reactor`, `tip_accept`, `most_work`, dedupe sets, locators, accept layering, INV helpers, `try_*` getters, codec/msg_decode, `BlockCache`, v2 writers, conn types, `V2PlainSession`, seeds/asmap, log needles, `NetError`, `getblocks`, small modules; IBD cadence split, exit matrix, named stage timers, soft densify, confirm engine, `BodyPresence`, relative-slow logic, rehydrate.
API: Electrum 1.4.2 surface + tweaks stream, Esplora route set + wallet WS, shared `ServeLimits`, `RpcParams`, `RpcRegtest`, `METHOD_LIST`, `getblockstats`, mining RPC, regtest generate/descriptor/scantxoutset, two tx-JSON schemas.
Mempool/node/small: Libre admission, cluster graph, private sidecar, `fee_est`+`fee_flow`, `inhibit`, `regtest_rpc`, `run_p2p` orchestration, error enums, `UtxoProvider`, custom logger + `api_log`, primitives hex/schema/Fk/Network/sigops, `rbitcoin-cli`, bench (optional).

## 14. Constraints honored

No proposal flattens an io_uring machine, splits the interpreter opcode match, reintroduces CreateResidency / OutFifo / ContigPark / archive sticky / process pin FIFO / map epochs, adds headerless SH interiors, restores script coordinators, adds an Esplora LRU, swaps the logger for `tracing`, or swaps `script_pool` for rayon. Every SCHEMA-touching item (S-04, S-12, SH-06, SH-07) is marked as a product decision requiring a `SCHEMA.md` row and an explicit refuse message, never a silent wipe. Every item that removes a named `ibd: perf` timer is restricted to timers that are never incremented.

---

## 15. Completed-items inventory

Status vs current `origin/master` (Merge #427). GitHub numbers
are the PRs that landed the work.

| ID | What shipped | PR | Notes |
|----|--------------|----|-------|
| **X-04** | Crate-root `pub` only if another crate imports it; unused → `pub(crate)` or delete; rustc `-D warnings` then dead items gone. No `#[cfg(test)]` wrappers for unused production APIs. | [#406](https://github.com/reardencode/rbitcoin/pull/406) merged `5dfb69e4` | Unlocks intra-crate `dead_code`. Follow-ups: I-01 `awaiting()`, fuzz keep-list. |
| **X-01 step 1** | Delete never-written confirm/query/store meters + sample fields + `ibd: perf` / `ibd: sizes` tokens (`recon`/`wire`/`resolve`, `parent_io`, `miss_p`, `cold_idx`, `pstore`, `recent=` occupancy, …). Live lookup/load/scripts/write timers kept. | [#405](https://github.com/reardencode/rbitcoin/pull/405) merged `6b9b4dcf` | Steps 2–3 (instance-owned `ConfirmStats` + table-driven `perf_log`) are **not** this; they remain suggested-order step 8. |
| **S-02** | `HeadLookupStats` deleted with X-01 step 1. | #405 | — |
| **Q-01** (pstore token) | `pstore` / always-zero heap `recent=` occupancy dropped from sizes/format. | #405 | — |
| **Q-02** (original never-written list) | `COLD_DECODE`, window `PIN_ADOPT`/`PIN_PUBLISH`, `PARENT_CACHE_HITS`, … gone from sample/format. | #405 | — |
| **C-01** (original never-written list) | `RECONSTRUCT_NS`, `WRITE_RECENT_*`, `RESOLVE_NS`, `UNPIN_NS`, … gone. Live `ASM_PREV_*` / `SPEND_ANN_PREAD_SKIP` kept. | #405 | — |
| **I-05** (original always-zero tokens) | `recon_ms` / `wf_body_store`-as-dead claim was stale: reconstruct `BODY_STORE` and `SH_COLLECT_PIN` **are live**. Those stayed. Dead reconstruct/write-recent tokens dropped in #405. | #405 | — |
| **X-02** | `HeadScale` / rebuild seal bits / workers / idx soft-span are `StoreLayout` / `HeadOpenOpts` open-time fields. Production default Mainnet. Tests `StoreLayout::tiny` / `Query::open_or_create_tiny` / `NodeConfig::with_tiny_heads()`. `--smoke` Tiny. No `RBITCOIN_HEAD_SCALE`, no cargo-test `/deps/` sniff, no `TEST_HEAD_SCALE` TLS. ~140 test `set_var` sites gone. | [#407](https://github.com/reardencode/rbitcoin/pull/407) merged `a41b2329` | Operator env still honored at open: `RBITCOIN_TX_HEAD_REBUILD_*`, `RBITCOIN_TX_IDX_SOFT_SPAN`, `RBITCOIN_TX_HEAD_BITS`, `RBITCOIN_HEAD_SLOTS_HEADER`. |
| **X-01 step 1 leftovers + Q-03** | Always-zero `parent_cache_perf_snapshot` four-tuple (`thru=` / `load thru=` / `bodies=`) deleted; occupancy is `conf_plans=` / `plans=` from `process_owned_size_snapshot`. Last-pin `adopt` / `publish` dropped (`note_last_pin` always stored 0); slow-load INFO uses `LastPinPhases::format_slow_pin`. Snapshot helper folded; `SpendEdges` stays in `confirm_load.rs`. | [#410](https://github.com/reardencode/rbitcoin/pull/410) merged `75bed331` | Keep live `SH_COLLECT_PIN`, `ASM_PREV_*`, `SPEND_ANN_PREAD_SKIP`, reconstruct `BODY_STORE`. |
| **X-06** | Shared Tiny drop-clean fixtures below `rbitcoin-test`: `rbitcoin_store::testutil::{TempDir, tiny_store, tiny_store_labeled}`, `rbitcoin_query::testutil::{tiny_query, tiny_query_labeled}`. Named `tmp_dir` / `temp_query` / `tmp_hub` / `tmp_store` in store, query, consensus, mempool, net, electrum, esplora now call those (wrappers remain 1-liners). `rbitcoin-test::TempDir` re-exports store helper; `TestDatadir` wraps it. Production default Mainnet. Core JSON spot twins deleted (`core_script_spot_*`, `core_tx_spot_first_valid_accepts`); `*_all_rows` remains the corpus pin. Coverage ≥90% held. `TESTING.md` names the helpers. | [#411](https://github.com/reardencode/rbitcoin/pull/411) merged `b6da097d` (`1e3a0aa6`) | Leaf module. Follow-ups landed: **N-04** hub opener (#412), **I-14 / A-21 / C-14 / Q-17 / SH-15 / N-03** leftover inlines (#414). Still leftover: store-unit `temp_dir().join` (`file.rs` / `var_table` / `tx_table` / `bulk_io` / heads), consensus overlay/pad/header, query `sh_builder`, node `run.rs` tests. Fuzz `fuzz/src/lib.rs` `tmp_dir` is not this. |
| **T-04** (leaf reuse) | `rbitcoin-test::TempDir` re-exports store `testutil`; low crates open Tiny via store/query `testutil` (no node dep). | #411 | Hub reuse: N-04 (#412) + I-14 (#414). Electrum/RPC leftover inlines: A-21 (#414). Remaining: `rbitcoin-test` mine / `chain_fixture`. |
| **N-04** | Tiny-regtest net hub opener: `tiny_regtest_hub` / `tiny_regtest_hub_labeled` compose Tiny query + shipped `ChainHub::new(..., ChainParams::regtest(), Milestone::NONE)`. `peer_tests` (69) and named `tmp_hub` in `chain.rs` / `ibd/reorg.rs` / `ibd/assign.rs` call it. Query-only peer tests keep `tiny_query_labeled`. Production default Mainnet. Coverage bar is the required `coverage` job. | [#412](https://github.com/reardencode/rbitcoin/pull/412) merged `09b7aec3` | Skip: fuzz `diff_regtest_params`, dersig/cltv overlays, production `P2PNode`. IBD leftover hubs: I-14 (#414). |
| **I-14** | Remaining IBD Tiny+hub tests call `tiny_regtest_hub_labeled` (`confirm_reject_tests`, parent_height, path, progress, archive, dial, confirm engine). Query-only merkle pin uses `tiny_query_labeled`. Blacklist vs cascade vs BadPrev pins stay. | [#414](https://github.com/reardencode/rbitcoin/pull/414) merged `6e1037c1` | Optional later: one pin per reject class (test mass). |
| **A-21** | RPC `methods_tests` / `server` leftover `temp_dir` inlines use `TempDir`. Electrum `tmp_store` / Esplora `temp_query` wrap `tiny_query` (from #411). | #414 | electrum `run_electrum` / esplora `http_get` stay production vs protocol-local. |
| **C-14** | structure-rule Tiny opens use `tiny_query`. BIP34 encoding twins live in `bip34_tests` (0..=16, 17, 128, 255, 256). structure-rule keeps wrong-encoding reject pin. write_idempotent converted in #411. | #414 | Optional: `tests_verify.rs` mass. |
| **Q-17** | `catchup` 14× `temp_dir` → `tiny_query_labeled`. Named `temp_query` wrappers from #411. | #414 | `connect_chain_query_surface` kept (only `height_of_hash` / `tx_output_at_fk` / `merkle_proof` journey). |
| **SH-15** | `scripthash_tests` `tmp()` is store `TempDir`. Bulk/extent/unsorted edge-packing pins kept. | #414 | `create_fks_matches_entries` kept (only `create_fks` pin). |
| **N-03** | Peer tests hold `PeerFollowState` and call shipped `handle_peer_frame`. 11-arg unpacking shim deleted. | #414 | |
| **I-01 / I-19** | `AwaitingBodies` never assigned `Some`. Field, `awaiting()` / `is_awaiting_held_tip` / `awaiting_need_getdata`, main-loop poll, exit remainder, assign gates deleted. | [#415](https://github.com/reardencode/rbitcoin/pull/415) merged `f113974f` | Most-work stays header rewind. |
| **I-02** | Production hold is `HashSet<BlockHash>` (presence only). `hold_body` still takes a `Block` then stores the hash. | #415 | Not ContigPark. |
| **I-03** | cfg(test) gather / `accept_branch` stack already gone on master. `classify_bad_prev` kept as I-14 pin helper. | already gone / #415 | — |
| **SH-02** | 16-byte `ShHeadValue::encode/decode` and `sh_encode_*` / `sh_decode_*` deleted. Durable is pack8. | #415 | Leftover-OA refuse + pack8 pins stay. |
| **SH-08** | `ShOverflowStack` / `OvfSegment` cfg(test) stack deleted. `wipe_legacy_fullsize_overflow` + `OVERFLOW_DIR` / `LEGACY_*` kept. | #415 | `open_wipes_legacy_fullsize_ovf_head` + leftover OA refuse stay. |
| **SH-01 / SH-03 / SH-09** | `LiveShardTable`, remap helpers, `SortedHeadFilter`/`Writer` already gone. | already gone | — |
| **SH-11** | Skipped: `HashHead::reserve_additional` / `bulk_fill_empty` used on insert. | skip | — |
| **S-01** | `PageRmw` + `page_rmw_pipelined` / `serial` deleted. `pread_batch` / `pwrite_batch` tests stay. | #415 | — |
| **S-03 / S-08** | `HEAD_LOAD_*` / packed helpers already gone. | already gone | — |
| **S-05** | One `RBITCOIN_IO` token parse in `bulk_io`; `io_backend` maps to Read/Write. Token aliases stay. | #415 | pool/iocp still distinct `SessionKind`. |
| **S-06** | `SpendMetaBackend` / `SpendAnnBackend` deleted; callers take `ReadIoBackend` / `WriteIoBackend`. | #415 | — |
| **S-07** | `repair_orphan_class_c` alias deleted; tests call `repair_class_c_above_tip`. | #415 | — |
| **S-09** | One-variant `HeadRole` deleted. Header slots from `HeadScale` + `RBITCOIN_HEAD_SLOTS_HEADER`. | #415 | — |
| **Q-05** | `archive_filter_need_bodies` deleted. IBD uses `archive_filter_need_header_fks`. | #415 | — |
| **Q-14** | Deleted `tx_fence_max_connected_fk`, `is_outpoint_spent_create`, `backfill_point_spends`, `is_header_archived`. Kept production `apply_history_filter`, `BQ_*`, `format_disconnect_tip_line`, `sample_reset_thin_tweak_body_bytes`. | #415 | — |
| **N-01** | `NetConfig` / `P2PHandle` already gone. | already gone | — |
| **N-06** | `try_fill_cmpct` + `try_cmpct_missing` merged to one `try_reconstruct_cmpct`. | #415 | getblocktxn fallbacks stay. |
| **N-14** | `peers.rs` calls `v2::v2_handshake_timeout_log`; peer wrap deleted. | #415 | — |
| **M-02** | Unread confirm/evict EMA + `note_evict` / `note_fee_flow_confirm` deleted. Admit EMA stays. | #415 | — |
| **L-02** | `LAST_LOG` / `take_last_log` deleted. `api_log` tests use `capture_logs` / `take_logs`. | #415 | — |
| **T-02** | Bench-private `hex.rs` deleted; uses `rbitcoin_primitives::{hex_encode, hex_decode}`. | #415 | — |
| **X-09** | `TableKind::{Input,Output,Point,TxHeight}` deleted; `from_u16` returns None for 4/5/6/12. Incremental relay aliases `MIN_RELAY`. Node `DEFAULT_MAX_INBOUND` aliases net. | #415 | — |
| **X-07 / N-07 / N-13** | `block_diff` + compact recipe/v2 encode helpers live in `fuzz/`. Net keeps shipped accept/reconstruct/v2/`drain_pending_now`/`PendingBlocks`. Recipe fixtures under `fuzz/fixtures/`. `cargo fmt --all` visits `fuzz/` via rbitcoin-log fmt-anchor tests. | [#416](https://github.com/reardencode/rbitcoin/pull/416) merged `90f57239` | Fuzz crate is not a coverage member. |
| **X-05 / D-01** | CLI `--key[=value]` and conf share `apply_kv` (conf then CLI). `CliAccum` copy gone. `DatadirOpts::path()`. `--smoke`/`--help`/`--log-level` CLI-only. Explicit `--milestone 0` sticks (`operator_config_from_args`). | [#418](https://github.com/reardencode/rbitcoin/pull/418) merged `f7a38b60` | — |
| **X-01 steps 2–3 / I-06** | Confirm/query/IBD window meters on `Query` as `ConfirmStats`; note via `&`; `perf_log::sample` take-and-reset that instance. `exclusive::with` twins gone. Write-stage inventory is one name+extractor table. Live lookup/load/scripts/write tokens stay. Store head-resolve window meters remain process-global. | [#420](https://github.com/reardencode/rbitcoin/pull/420) merged `0d80e48e` parent | — |
| **S-04 / S-12 / SH-06 / SH-07** | Leftover **index** layouts refuse on open: fuse8 v1, flat `*.idx.meta`, Shared file `scripthash.body`, pack8 Paged (mode 10). One-line wipe/rebuild; Class A kept. No always-probe / flat rename / Shared read. | [#422](https://github.com/reardencode/rbitcoin/pull/422) | — |
| **S-15** | `PointRecord.spending_input_index` and ignored `put_spend` input-index arg deleted. Esplora `/outspend(s)` omit `vin`. COMPAT documents explorer gap. | [#423](https://github.com/reardencode/rbitcoin/pull/423) | — |
| **A-02 / A-20 / D-02 / D-03 / D-09** | `submitblock` live hub all networks; `--minrelaytxfee` garbage/negatives error; `--permitbaremultisig` gone; METHOD_LIST leftovers + dummy `getnetworkhashps` documented. | [#424](https://github.com/reardencode/rbitcoin/pull/424) merged `3eccac25` | Q-59 rest (`gettxout` mempool-spent, JSON-RPC batch cap, `maxfeerate`/`maxburnamount`) **done (#428)**. |
| **C-06** | `AssembleMode::Full` + `validate_block_connect` deleted. Confirm is optimistic assemble then `structural_validate_spends`. Connect tests use `accept_and_connect_block`. `verify_scripts_pool` deleted. | [#426](https://github.com/reardencode/rbitcoin/pull/426) merged | **C-19** (`try_for_each_parallel`) landed in this remainder branch. |
| **Q-06** | `archive_plan_batch_from_store` deleted. `commit_class_a_block`/`_run` call `archive_class_a_from_wire`. Confirm write fills packed ins on the plan. | [#427](https://github.com/reardencode/rbitcoin/pull/427) merged | **Q-21** (this PR): TxApply conversion is testutil-only. |

Suggested-order progress:

1. **X-04** — done (#406).
2. **X-01 step 1 + I-05 / C-01 / Q-01–Q-03 / S-02** — done (#405 + #410 leftovers).
3. **X-02** — done (#407).
4. **X-06** leaf — done (#411). **N-04** hub opener — done (#412). **I-14 / A-21 / C-14 / Q-17 / SH-15 / N-03** — done (#414). Suggested-order step 4 complete.
5. Per-crate dead paths — done ([#415](https://github.com/reardencode/rbitcoin/pull/415) merged `f113974f`).
6. **X-07** fuzz out of net — done ([#416](https://github.com/reardencode/rbitcoin/pull/416) merged `90f57239`).
7. **X-05** node config — done ([#418](https://github.com/reardencode/rbitcoin/pull/418) merged `f7a38b60`).
8. **X-01 steps 2–3** ConfirmStats + table-driven `perf_log` — done ([#420](https://github.com/reardencode/rbitcoin/pull/420) merged).
9. Product-gated SCHEMA/COMPAT + honesty — leftover index refuse (#422), S-15 `vin` omit (#423), Q-59 (#424 + #428), **C-06** (#426), **Q-06** (#427). Suggested-order step 9 complete.
10. **Before X-08 remainder** — §16. Should rows on `quality/remainder`: C-19, I-22, I-07, SH-04/05, SH-10/12 already gone, S-11/14/17, C-13, C-16, Q-09/C-11, Q-18. Must leftovers **X-03 / C-03 / Q-21** on this stacked branch.
11. **X-08** clippy batches — not started.

---

## 16. Before X-08 remainder (2026-09-11)

Suggested-order **1–9 is the program** (#426/#427 merged). This remainder PR
lands the Should rows plus **C-19** / **Q-09**. **Do not** treat quality.md Open
(Q-41, Q-57–Q-60, R-10 god-files) as this inventory.

X-08 re-enables clippy `allow`s. §16 Must leftovers on this stacked
branch: **X-03** (store IO probes), **C-03** (archive-prep twins),
**Q-21** (TxApply→dummy Block out of production `Query`).

### Must (same sins the program opened with)

| ID | Why it is this program | Contract |
|----|------------------------|----------|
| **X-03** | **done:** SQE/page-write/SH-page-IO/BQ-raw-clone counters on the session/table/queue; `get_tx_full` spies are Store debug logs. TLS `test_take_*` / `TEST_FORCE_SESSION_FALSE` / crate-root `take_raw_clone_n` deleted. | — |
| **C-19** | **done (remainder PR):** `try_for_each_parallel` deleted. Steal tests use `try_for_each_parallel_idle`; idle-vs-foreground uses `start_for_each_owned`. `run_wave` is idle-only. | — |
| **C-03** | **done:** `prepare_block_for_archive` is the one CPU-side Class A helper; `_new` private; `_with_txids` deleted; `validate_block_structure_precomputed` is `pub(crate)`. `check_block_wire` / `verify_tx_scripts_detached_forks` stay pub (fuzz). Confirm_run wave/phase names stay crate-pub (IBD pipeline). | — |
| **Q-21** | **done:** `tx_apply_to_tx` / `block_from_applies` / `FixtureChain` in `rbitcoin_query::testutil`. Production `Query` has no `connect_block` / `commit_class_a_only` / `archive_prepared_*`. Packed-ins pin still holds. | — |

### Should (high-confidence dead / honesty, small)

| ID | Item |
|----|------|
| **I-22** | **done:** startup log is `body queue: in-process`. |
| **I-07** | **done:** `bq_pipeline_saturated` (no unused pending_len); `drain_ready_peer_and_body_events`; `buf_ahead` (operator token was already `buf_ahead=`); assign no longer takes write-next; `BodyPresence::pending_len` deleted. `archive_write_next` Atomic still used for densify window in events. |
| **SH-04 / SH-05** | **done:** `contains_create` / `put_create` / `put_create_batch` deleted. Tests call `create_fks` / `put_create_batch_append`. |
| **SH-10 / SH-12** | **already gone:** no `ScriptHashHead::get_many`; no `sh_page_count_for_entries` / `page_alloc_bytes_for_n_fks`. |
| **S-11 / S-14 / S-17** | **done:** `Store::put_spend_create_at` / `Store::create_with_head_layout` deleted (tests call `point_table::put_spend_on_create_at` / `create_layout_with_head`). Probe sample/snapshot deleted. `flush_class_c_pre_tip` is private. `TxTable::create_with_head_layout` stays (in-crate opener). |
| **C-13** | **done:** `rbitcoin-test::pad_empty_from` delegates to consensus. |
| **C-16** | **done:** limitations doc names lock 0.32.102. |
| **Q-09 / C-11** | **done:** consensus `block/tx_precompute.rs` deleted. Connect-only bip143 pin is `script::verify_routing_tests::from_tx_connect_bip143_fails_closed_without_midstate`. |
| **Q-18** | **done:** `Query::get_tx` is the one name. |

### Not this remainder

- **C-05** SPK predicate duplication — consensus correctness, not an unused twin.
- **A-08 / A-09 / A-11** — two wallet JSON schemas (keep) / Esplora address wrappers (optional).
- **N-09** MiningHub extract — only if a quality.md Q-row needs the seam (R-10).
- **N-05** long peer_tests twins — medium; flaky timing.
- **Q-04** micro-module fold — readability, not a dual path.
- quality.md **Q-41 / Q-57–Q-60 / Q-54–Q-56 / R-10**.

