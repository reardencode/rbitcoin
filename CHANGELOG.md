# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for the **0.x** experimental line (breaking on-disk and API changes are expected
before 1.0).

## [Unreleased]

### Changed

- **Workspace version 0.8.99:** in-tree toward 0.9.0.
  Published GitHub Releases remain 0.8.0; `v0.8.x` is the patch branch.
- **RPC submit admits `nVersion` 3.** `sendrawtransaction`, `testmempoolaccept`,
  and `submitpackage` still reject every other version. P2P still admits any
  version. Version 3 is the TRUC number Bark captaind broadcasts.
- **Version 3 follows BIP 431 TRUC on admission.** One unconfirmed ancestor,
  one unconfirmed descendant, 10,000 vB, and 1,000 vB as a child of an
  unconfirmed parent. Other versions are unchanged. A replacement of the
  existing child is not a second descendant. A non-conflicting second child
  is rejected (`truc-descendant-count`) rather than evicted.
- **One 0-value spendable output can enter with a package.** The transaction
  fee must be 0, and a later package member must spend that output. A child
  that spends the parent and leaves the output is `missing-ephemeral-spends`.
  A fee-paying transaction, a second 0-value output, and a lone submit stay
  `dust`. `OP_RETURN` and outputs of 1 sat or more are unchanged.

## [0.8.0] — 2026-10-09

Named published **0.8** line. **Not 1.0.** Patch branch is `v0.8.x`. Schema 26
opens a schema 24 or 25 datadir in place (`header.body` 96 B → 88 B, `meta`
rewritten to 26). A store older than schema 22 refuses (wipe + IBD), including
occupied **0.6.x**. Default mainnet `--milestone` still names height 840000
and skips scripts only on that header path once chain work meets the minimum.
Signet’s default milestone is 0. `--sh-index` default off. BIP324 v2-only.
GitHub Release: Linux musl (operator) + Windows CRT-static PE + Darwin aarch64.

### Highlights

- **Schema 26 opens a 0.7 datadir in place.** Schema 24 and 25 rewrite
  `header.body` from 96 B to 88 B and `meta` to 26. A store older than schema
  22, including occupied 0.6.x, refuses with one wipe-and-IBD line.
- **Mainnet script skip is path-anchored.** The default milestone still names
  height 840000 and block
  `0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5`. Scripts
  skip only on that header path once chain work meets Core
  `nMinimumChainWork`. Signet’s default milestone is 0 (every script). An
  explicit `--milestone HEIGHT` stays height-only.
- **Initial sync keeps moving on ordinary connections.** One peer serves
  headers. The others download blocks, at most 64 blocks or 16 MiB in
  flight, sized from recent bodies. A peer holding the tip block is
  replaced only after 5 seconds, and only when a free peer would finish
  it in half the time. A full serve queue waits out the rest of a
  `getdata` instead of dropping it.
- **Consensus checks match Bitcoin Core where they used to disagree.**
  BIP30 is off only when the header at BIP34 height is that network’s
  BIP34 block, and it is always on from height 1,983,702. A confirm batch
  cannot spend an output created by a later block in that batch. The
  genesis coinbase is not a spendable coin. An empty signature in legacy
  `CHECKMULTISIG` deletes `OP_0` from scriptCode. A bad copy of a valid
  block is requested again and is not cached as invalid.
- **Peers and RPC fail closed under load.** Counts above 50,000 in `inv`,
  `getdata`, and `notfound` fail decode. Compact-block and block
  transaction counts are rejected before allocation. The RPC body cap is
  2 MiB, and a full work queue is HTTP 503 before the handler. A session
  pauses once its outbound queue passes 4 MiB. An unpaged scripthash join
  above `--max-sh-creates` (default 10000) is refused.
- **Wallets, Lightning nodes, and explorers have a setup guide.**
  `docs/wallets.md` and `docs/lightning.md`. Electrum and Esplora serve
  Electrum, Sparrow, Liana, Specter, Cake Wallet, BlueWallet, BitBox App,
  Envoy, and BDK (including Alby Hub). Wasabi’s full-node path uses
  `getblockfilter` and `--rpc-cookie-file` (HTTP Basic on TCP).
  `getnetworkinfo.version` stays 190000 (Core 0.19’s client integer); the
  semver stays in `subversion`. CLN (`bcli` and `sauron`), ldk-node
  (Esplora, Electrum, or REST), and LND with `bitcoind.rpcpolling` use
  this node as the chain source. Esplora `/internal/*` on the unix socket
  is the mempool.space electrs drop-in. `/fee-estimates` keeps the
  estimator’s precision. `/fees/recommended` and `/ws` are 404.
- **Feerate uses sigop-adjusted size.** Admission, RBF, eviction, estimates,
  and `-blockmintxfee` use `max(weight, sigop_cost × bytes_per_sigop)`
  (default 20, `--bytes-per-sigop`, `0` disables). A transaction whose sigop
  cost reaches the template budget is rejected. Template selection applies
  the mintxfee floor per chunk and keeps the block sigop cap.
- **Fee quotes follow a log grid and a fullness blend.** About 100 steps per
  decade from min relay (0.1 sat/vB) through 1000 sat/vB, plus one open
  bucket above that. The published rate is `(1−α)·history + α·live flow`.
  α is decayed admitted weight over about 1.44M WU (150s half-life). History
  is filled from `txstat` (at most 1 GiB; each block’s vsize-weighted p10
  of individual rates). `estimatesmartfee` returns `{feerate, blocks}`, or
  `{errors, blocks}` with no `feerate` when it has no estimate, and
  `feerate` is at least `mempoolminfee`.
- **Block filters and silent-payment tweaks build during IBD, and after
  it when they are behind.** With the index on from the start, each
  confirmed block is built on the script pool and appended on the confirm
  write. A restart gap of at most 2,016 blocks is sealed before confirm.
  A larger gap, including an index enabled on an already synced datadir,
  is built afterward by `rbtc-idx-wb` (`index: build`) and does not hold
  the node in initial download. `NODE_COMPACT_FILTERS` is advertised once
  filters reach the tip. With `--datadir-cold`, `blockfilter` and
  `sp_tweaks` must sit on the cold store.
- **Spend annotations recover after a crash past the tip seal.** A missing
  spent slot stays unspent until open replays above the `spend_durable`
  marker. `rbtc-spend-sync` checkpoints about every ten minutes, and once
  more on shutdown.

Thanks to @otaliptus for the security review, and to @dergoegge, @rob1ham, and @1440000bytes for earlier findings.

Thanks to @benthecarman, @average-gary, @bobberb, @Hero-Gamer, @bkeroack, @xstoicunicornx, and @RandyMcMillan for changes in this release.

### Fixed

- **`-blockmintxfee` floors whole chunks:** `getblocktemplate` / `generate`
  apply the floor to each chunk's modified feerate (Core `BlockAssembler`)
  instead of filtering txs one by one after selection, which could drop a
  low-fee CPFP parent and keep its child (`bad-txns-inputs-missingorspent`).

- **Sigop-adjusted policy size:** feerate, RBF, min relay, package min
  relay, chunk ranking, eviction, fee estimation and `-blockmintxfee` use
  Core's `max(weight, sigop_cost × bytes_per_sigop)` (default 20, new
  `--bytes-per-sigop`, `0` disables). `getmempoolentry` /
  `testmempoolaccept` `vsize` and `getmempoolcluster` weights report it;
  `weight` and the block weight budget stay raw. Cluster and package limits
  also stay raw, unlike Core, so a sigop-dense tx is priced higher but not
  capped below the block sigop limit. A sigop-dense tx no longer looks
  cheaper than it is.

- **Mempool sigop cost:** admission rejects a tx whose BIP16+BIP141 sigop
  cost reaches the template budget (80,000 minus `--block-reserved-sigops`,
  default 400), using the same strict limit as template selection. The reserve
  is configurable from 0 to 80,000. Every live entry records its full cost.
  The sidecar is schema 3; schema 2 pools soft-migrate on open and the hub
  recomputes the cost, dropping entries whose inputs no longer resolve.
- **An invalid script from a peer adds 10 to that peer's ban score.**
  Consensus block flags are unchanged. There is no 16_000 standard sigop
  cap (Libre policy); the only sigop reject is the whole-block limit above,
  checked before the interpreter.
- **Full-mempool fee floor follows evicted feerate.** While the mempool is
  at the weight cap the static bump remains, and an evicted chunk raises
  the floor one sat/kvB above that chunk so the same-rate transaction cannot
  re-enter. Below the cap the bump decays by half every 12 hours.
- **Cluster limits are one walk per insert.** A transaction that spends
  several mempool parents no longer rebuilds the cluster once per input.
- **Orphan admission when every parked tx is inside a per-peer reserve.**
  Eviction still prefers orphans outside that reserve, then drops the
  oldest reserved one so a newer orphan is not refused. Peer weight is
  kept per announcer. An orphan older than 20 minutes is dropped on the
  next insert. Non-standard shape (weight, dust, scriptPubKey, annex) is
  rejected before the tx is parked.
- **Spend annotations survive a crash after the tip seal.** A missing
  spent slot is unspent, so open replays annotations above the
  `spend_durable` marker (a missing file replays from genesis) and only
  then advances the marker. `rbtc-spend-sync` `sync_data`s those stems
  about every ten minutes, and once more on shutdown, not on every Class C
  barrier. The tip
  window stays at least 6 blocks and reaches back to the durable-through
  height. `tip_seal`, `tx.head` meta, and the marker `fsync` their parent
  directory after rename.
- **Addr relay no longer goes to every peer.** Each address is sent to
  one or two neighbors. A peer can relay 1000 addresses, then the bucket
  refills at a tenth of an address per second.

- **Tor cookie auth is SAFECOOKIE only.** A control port that does not
  advertise it, or a cookie that is not 32 bytes, does not send the raw
  cookie. A new datadir is mode `0700` and is not chmodded if it already
  exists. `rpc.sock` and the Esplora unix socket take their mode at bind.
  A loopback `--net-permission` does not cover an onion or I2P address.

- **Per-peer send buffer:** each session stops serving the next request
  once its outbound queue is past 4 MiB (headers, inv, notfound, tx, addr,
  and block bodies all count). The reader waits until the writer drains.
  One block reply may still land past the cap. `getaddr` is answered once
  per connection.
- **Milestone anchor:** signet’s default milestone is 0, so signet IBD runs
  every script (slower on purpose). The mainnet default still names height
  840000, and it skips scripts only when the header path contains block
  `0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5` at that
  height, this block is the path hash at its own height, and header-chain
  work meets Core `nMinimumChainWork`. A low-work fork that only shares a
  height does not skip. Explicit `--milestone HEIGHT` stays height-only.
  Omitted mainnet `--min-chain-work` is that same floor.
- **P2PKH policy flags, RPC token, and inv cap:** `LOW_S`, `STRICTENC`,
  and `NULLFAIL` on a P2PKH input use the generic interpreter. The RPC
  token compare does not stop at the first differing byte, and a new
  token file is created mode 0600. `inv` / `getdata` / `notfound` counts
  above 50,000 fail decode. Peer command text in a log line cannot
  insert a raw newline.
- **Tip-accept lifetime:** the async accept job is `'static` and holds an
  `Arc` of the hub. Dropping a peer session does not free that hub under
  the job. Shutdown waits for the lane to go idle before the store flush.
  Dropping the node still aborts connect-retry.
- **RPC and Esplora limits:** bearer auth runs before the body is read
  (401 with no body bytes). The HTTP body cap is `RPC_MAX_HTTP_BODY`
  (2 MiB, 413 above it). `--rpc-work-queue` defaults to 16 (HTTP 503 when
  full). `0` and an omitted value are that same queue of 16. `waitforblock`,
  `waitforblockheight`,
  `waitfornewblock`, and `getblocktemplate` longpoll wait off the blocking
  pool. Esplora `X-Rbitcoin-Client` is a join key only for a unix socket
  or with join-header trust; loopback alone is not.
- **Scripthash join:** the default `--max-sh-creates` is 10000. An unpaged
  join above that is refused (`scripthash join exceeds --max-sh-creates
  (default 10000)`). **0** stays unlimited. A history request that names a
  page is still served and stops expanding creates once the page is full.
- **Electrum public surface:** silent-payment subscribe logs do not include
  the scan secret. The API log file is mode 0600. A missing or zero scan
  start is the last 256 blocks. The historical scan runs off the connection
  task, a few hundred heights at a time, behind 3 process-wide permits, and
  only one scan per connection. Outpoint subscriptions use the scripthash
  subscription cap. Tip restatus of those outpoints runs off the connection
  task.
- **BIP30:** enforced unless the header at BIP34 height is that network's
  BIP34 hash, and always from height 1_983_702. Signet and regtest have no
  BIP34 hash, so every block is checked. The two mainnet repeats stay
  exceptions. The txid batch is inside the structural `spent=` timer.
- **Witness padding:** witness commitment and unexpected-witness checks run
  before the block weight check. Those two failures are mutations, so the
  block hash is not cached invalid. A weight failure after a matching
  commitment may still be cached. One mutation classifier serves connect
  and both IBD reject paths.
- **IBD header and body intake:** a headers batch that fails validation
  does not grow the work path or explore lists (each list is capped at
  64). An unsolicited or already-queued body is dropped before the
  payload copy. Assign prices a new getdata hash at the largest received
  wire length among the most recent 32 bodies, never above 4 MiB. Until
  eight bodies have been recorded the charge stays 4 MiB. A hash already
  in flight on another peer is still issued and does not add another
  charge. A body that was requested is still queued.
- **Header accept:** a failed `ensure_header` does not hold the body or
  enter tip accept. A non-genesis block whose previous hash is all zeros
  is rejected while a tip exists. Work sums report overflow instead of
  wrapping, and a zero target is not turned into work.
- **Compact blocks:** a transaction count above the block weight limit
  divided by the minimum transaction weight is rejected before the slot
  vector is built. A peer keeps one partial. Another hash from that peer
  is a full `getdata`, not a second vector and not a ban.
- **Block decode tx count:** `decode_block_precomputes` rejects a count
  larger than the remaining payload divided by 10 before it allocates.
  A one-transaction block still decodes.
- **Signet solution:** a non-minimal CompactSize is a bad block. A witness
  count larger than the remaining bytes fails before allocation.
  PUSHDATA4 is parsed, and non-minimal pushes are re-encoded the way
  Core writes the modified coinbase.
- **Tapleaf `0x50` and a false witness program:** a future leaf whose
  version byte is the annex prefix commits and is not executed. An
  all-zero or negative-zero witness program fails before anyone-can-spend
  success, including inside P2SH. Tapscript still runs.
- **Corrupt store lengths:** a uleb128 payload wider than one bit at
  shift 63 is overflow. A seqsigwit script or witness length that does
  not fit the buffer is `Corrupt`, not a capacity panic. A BDZ file with
  a zero modulus or zero vertex count is `Corrupt` instead of a divide
  by zero. Truncating a sealed mmap after it is mapped is fatal external
  corruption.
- **CI quick checks share one runner.** Job `qc` runs fmt, ast-grep,
  deny, the script self-tests, clippy, then nixos-module-eval. `test`,
  `windows`, and `macos` stay on their own runners. Coverage waits for
  `qc` and `test`. Mutants are a nightly run, not a pull-request check.

- **Input backfill reads `seqsigwit.body` in 16 MiB spans.** Open used
  to `pread` the locator window and the body once per create. A chunk
  of 16384 creates now shares one locator read, and contiguous bodies
  share one pread. A partial `input.loc` resumes that walk when the
  next record still has an inline prevout.

- **Failed connects enter the stall cooldown.** An EOF or timeout takes
  the same strike ban as a relative-slow kick, so dead seeds stop
  occupying the only dial slots. Relative-slow does not disconnect
  while every address outside cooldown failed its last connect.

- **IBD redial breaks an all-cooldown book:** when more peers are
  needed and every candidate is cooling, dial the one tried least
  recently anyway. A successful connect clears that cooldown. Never
  tried sorts ahead of any attempt.

- **IBD eviction ages a peer's saved speed:** a quiet in-flight gap no
  longer rewrites the transfer EWMA. Relative-slow and tip-hole eviction
  score `ewma * 15s / (15s + age)` from the last qualifying rx, so a
  frozen high rate cannot hold the median up while peers that are still
  delivering get disconnected.

- **Store I/O lifetimes:** `push_pread` / `push_pwrite` are `unsafe` and
  require the buffer to stay live until the completion is harvested.
  `HeadDrainHandle` borrows the store until join. An `io_uring` enter
  failure with completions still in flight aborts, matching the drain
  hard cap, instead of returning into a buffer free.

- **Mempool script skip requires the wtxid:** a block transaction is not
  treated as already checked just because its txid is in the mempool.
  A script job whose prevout count does not match its inputs fails closed.

- **Block template sigop budget:** `getblocktemplate` / `generate` selection
  starts at the 400 coinbase sigop reserve and skips a chunk that would reach
  80,000 (Core `TestChunkBlockLimits`). Weight overflow also skips and keeps
  trying later chunks instead of stopping, so a sigop-heavy pool no longer
  yields a `bad-blk-sigops` template.

- **`getblocktemplate` `sigops`:** each row reports the entry's full
  BIP16+BIP141 sigop cost recorded at admission (Core
  `GetTransactionSigOpCost`), not legacy sigops × 4. P2SH and P2WSH spends
  were under-reported.

- **Weekday script-verify fuzz skip floor is 0.3%:** the 600s job lands
  near 0.43% real comparisons (2026-09-21..23). The 0.5% bar was the
  Sunday hour, which just clears it. A mute run still fails.

- **`cmpct_differential` extra `getblocktxn`:** agree whenever Core's
  indexes are a subset of ours, not only recipe `[1, 4]` vs `[1]`.
  Nightly `[0, 251, 229, 55, 51, 13, 10]` is ours `[2, 4]` vs Core `[2]`.
  Omitting an index Core requested still panics.

- **Unreachable I2P stays out of addrman:** without `--i2p-sam`, an addrv2
  I2P row is relayed and not stored. `getnodeaddresses` `network=i2p` is
  empty. Core `p2p_addrv2_relay`.

- **Orphan parent GETDATA flush cap is 100:** Core
  `MAX_PEER_TX_REQUEST_IN_FLIGHT`. A 25-tx ancestor package's missing
  parents fit one GetData (was 16).

- **create.loc SIMD is SSE2-only:** inclusive `u8 << 3` extracts the low
  prefix carry with `_mm_cvtsi128_si32(_mm_srli_si128(_, 12))`.
  `_mm_extract_epi32` is SSE4.1; nightly Miri rejected it (`unavailable
  target features: sse4.1`). Hosts with SSE4.1 already matched the scalar
  oracle.

- **sendraw / testmempoolaccept / submitpackage junk hex is `-22`:**
  those three share `decode_tx_hex` (`TX decode failed:`).
  `decoderawtransaction` is `TX decode failed` with no colon.
  Core `testmempoolaccept(['ff00baar'])`. String `rawtxs='ff00baar'` stays
  `-32602 rawtxs array required` (inventory skip).

- **`testmempoolaccept` confirmed spend is `txn-already-known`:**
  Active-chain lookup (`tx_fk_by_txid_tip` + `is_confirmed_strong`) before
  `test_accept`. Live mempool dups stay `txn-already-in-mempool`;
  archive-only after `invalidateblock` is not already-known.


- Mainnet BIP30 turns off above height 227931 only when the confirmed header
  there is Bitcoin Core's BIP34 block. The previous constant was a different
  hash, so every later block kept scanning txids for an unspent overwrite.


- **Compact fuzz shares Core's mock clock.** Header stamps stay within
  two hours of regtest genesis, and the follow accept uses that same
  clock. A split panic includes Core's `submitblock` reason.


- **Compact fuzz oracle clears a sticky invalidate.** After a compared
  accept, Core `invalidateblock` keeps the header invalid. The next
  `submitblock` of that body is `duplicate-invalid`. The harness
  `reconsiderblock`s once and scores the second reply. A reason that
  remains is still a disagreement.


- **BIP30 ignores unspendable outputs.** A repeated txid whose earlier
  instance has every spendable output spent is accepted even when that
  instance also carries an `OP_RETURN` or over-10,000-byte output.
  Bitcoin Core never adds those outputs to the coin view, so they could
  not be overwritten; rbitcoin rejected the block as `bad-txns-BIP30`.
- **The genesis coinbase is not spendable.** Bitcoin Core never adds the
  genesis block's coinbase to the coin view. A block that spends it is now
  rejected as a missing prevout on every connect path, with or without
  script checks. The transaction stays indexed for RPC and Electrum.


- **`--connect` peers are `manual`, as in Core.** `getpeerinfo` reported a
  `--connect` peer as `outbound-full-relay`. Core counts `manual` peers as
  preferred download peers, and so does this node now: one whose outbound
  peers all come from `--connect` or `addnode` replaces a stalling
  headers-sync peer instead of waiting on it. As in Core, a `--connect` peer
  is no longer dropped for missing `NODE_NETWORK`, and `--seednode` is not
  dialled under `--connect`.


- **A `--connect` address is redialled when its session drops.** Only
  `--connect` hostnames were retried. An IP, onion, I2P or CJDNS target got
  one dial at startup, so a node whose `--connect` peer restarted or was
  disconnected stayed without peers until it was restarted. As in Core,
  once the node follows the tip, every `--connect` target without a live
  session is redialled every 2 s, including any that the startup dial
  skipped (it dials at most three).
- **A redial does not stack while a dial is still connecting.** The 2 s
  redial of `--connect` and `addnode add` targets skips a target whose
  previous dial has not finished connecting. Before, a target behind a slow
  SOCKS circuit or a host that drops SYNs got a new dial every pass, and
  each one that connected became its own session. An outbound connect now
  gives up after 8 s (90 s for I2P), as IBD and tip-follow dials already
  did, so a proxy that never answers cannot hold a target forever.


- **Signet `OP_TRUE` can be mined on demand.** `generatetoaddress` /
  `generate` / `generateblock` work on regtest and on a signet whose
  challenge is exactly `OP_TRUE` (signet bits, empty BIP325 solution).
  `getblockchaininfo.signet_challenge` is present on signet. A signet
  solution failure is reported as `bad-signet-blksig`.
- **`getblockfilter` serves a sealed row, or one block past a sealed
  parent.** A best-chain height already in the index uses that row. A
  block whose parent filter header is sealed, including a stale branch
  walked back to that fork point, is rebuilt from the body. An unsealed
  best-chain gap is “Filter not found. Block filters are still in the
  process of being indexed.” An unknown `filtertype` is `-5`. REST
  `/rest/blockfilter/` stays watermark-only.
- **`submitpackage` package-evaluates a child-with-parents remainder.**
  Members that failed static min relay, the dynamic mempool floor, or
  missing inputs are retried together, including when the child spends a
  parent already in the mempool. The dynamic floor is waived when the
  remainder meets static min relay. Effective feerate for that remainder
  is the summed modified fees over the summed vsizes. Trim runs once
  after the package; a tx that was admitted and then dropped is
  `mempool full`. Package-admitted txs use the same relay-age clock as
  an individual admit, and `prioritisetransaction` deltas count in the
  feerate announced to peers. A member whose own feerate is above
  `maxfeerate` is rejected and does not rescue the rest of the package.
  An individual admit still reports the transactions it replaced.
- **`getmempoolinfo.maxmempool` is the virtual-size byte cap.** The hub
  budget stays weight (`--mempool-size-mb` × 1_000_000). The Core field is
  that budget divided by 4, the same unit as `bytes`.
  `rbitcoin_mempool_max_weight` still reports weight.
- **An unspendable output is still a coin.** A script that starts with
  `OP_RETURN`, or is longer than 10_000 bytes, resolves and fails in the
  script. Core functional `generateblock` text for that spend is shim-only.


- **Misbehavior no longer disconnects `noban` peers.** A peer with the
  `noban` permission (`--trusted`, or `noban` in `--net-permission` /
  `--net-permission-bind`) that sends an invalid block or header is
  logged and kept, as in Core.
- **Rejected block headers log Core's reason.** A block whose header fails
  contextual checks logs `bad-version(0x…)` or `time-too-new` again.
- **Relayed addresses go out in one `addrv2` per peer.** Previously each
  address was sent as its own message.
- **Parked RPC waits show in `getrpcinfo`.** `waitfor*` and a
  `getblocktemplate` longpoll are listed in `active_commands` while they
  wait, and a longpoll logs its request when it arrives.
- **A compact-block peer is not stuck on an old partial.** A peer's pending
  partial for a block that connected through another peer is dropped, so
  the peer's next compact block still gets `getblocktxn`.
- **Header sync on a fork no longer slows down with its length.** Each
  `headers` message stores only headers not already stored.
- **Ping timeouts wait for `--peer-timeout`, as in Core.** A mock-clock
  jump inside the peer timeout no longer drops a peer.


- **A same-slot store probe and a full RPC work queue no longer fail when the schedule is unlucky.** The probe keeps drawing until the mixed key shares the page, and a full work queue answers HTTP 503. A live follow session counts an unknown BIP324 short id as `*other*` and stays connected.


- **A taken Esplora port no longer fails the cross-surface journey.** The journey binds `127.0.0.1:0` and reads the address the node publishes under `{datadir}/run/*.addr`. A failed Electrum or Esplora bind is not retried on the tip loop.


- **Operator and schema docs match the node.** Blocks in transit per peer
  are 64. `--mempool-size-mb` is N × 1_000_000 weight units. Scripthash
  extract workers are one per 1.5 GiB. Confirm commits the height fence
  and `confirmed[]` before scripthash write-behind. Schema file headers
  are version 26, including block-filter kind 24 and `input.*`.
- **IBD and mempool operator notes match the code.** Densify is 32
  hashes per peer (64 for a fast outlier). Cluster caps are 64 txs and
  101 kvB. The mempool sidecar is schema 3. `tip: accept` is DEBUG.
  Linux falls back to pread when io_uring cannot open.
- **CLI names in the product docs are `--sh-index` and `--sp-tweaks`.**
  Electrum and Esplora start with the scripthash index off. `generate*`
  also runs on an `OP_TRUE` signet. Electrum `protocol_max` is 1.6.
  SV2 template-provider plans A–C are landed. CLN and ldk-node chain
  backends are the contract in `lightning.md` (Q-69 closed).


- **Operator schema upgrade matches schema 26.** Opening a schema 24 or 25
  datadir shrinks `header.body` from 96 B to 88 B and rewrites `meta` to 26.
  The operator table no longer describes a rewrite that stops at 25 or grows
  headers from 88 B to 96 B.
- **Finding 085 is closed on IBD.** A coinbase-less 64-byte body is a bad
  copy: IBD drops it and asks again, and does not cache the hash as invalid.


- **Electrum: an unused scripthash has status `null`, not `""`.**
  `blockchain.scripthash.subscribe` answered `""` for a script with no
  history, and a push for a script whose history emptied (an RBF victim)
  sent `""` too. The protocol says `null`, and wallets read any non-null
  status as a used address: Sparrow kept deriving past its gap limit
  (`../0/2542` on a wallet whose last used index is far lower) and filled
  the per-connection subscription cap. The subscribe reply and both
  notification paths now send `null`, and a subscribe that answered `null`
  still deduplicates a later push that is still empty.


- **Esplora paged address history is served above `--max-sh-creates`.**
  `/txs`, `/txs/chain`, and `/txs/summary` return their page when a script
  has more creates than the cap. Unpaged stats and `/utxo` still return 503.
- **`/txs/summary` rows include `tx_position`**, and `?asof=` is accepted on
  that route. The page stays 25 rows.
- **Esplora tx JSON omits an empty `witness`.** `inner_redeemscript_asm` is
  only the P2SH redeem script, and `inner_witnessscript_asm` is only a
  P2WSH witness script or a Taproot script-path leaf.
- **`/block/:hash/txs/:start` at or past the last tx is 404**
  `start index out of range`.


- **Fee estimates answer confirm targets between the computed depths.**
  The estimator still prices 1, 2, 3, 4, 5, 6, 10, 20, 144, 504, and 1008
  blocks. Any other target from 1 to 1008 is the straight line between the
  computed rates on either side, in whole sat/kvB, or the last defined rate
  past the far end. `estimatesmartfee`, `estimaterawfee`, and Electrum
  `blockchain.estimatefee` use that curve. Esplora `/fee-estimates` includes
  each integer from 1 through 25, plus 144, 504, and 1008, when that target
  has a rate.


- **Consensus: an empty signature in legacy `CHECKMULTISIG` deletes `OP_0`
  from scriptCode.** Core's FindAndDelete of an empty signature removes
  every `OP_0` opcode before the other signatures are hashed. We left
  scriptCode unchanged, so a spend that mixed an empty signature with
  signed and malformed ones could get the opposite result from Core,
  in either direction.


- **Consensus: a block that spends an output created by a later block is
  rejected in IBD and catch-up.** When several blocks were confirmed in
  one batch, an input could bind to a transaction in a later block of
  that batch. Bitcoin Core connects one block at a time and rejects the
  block with `bad-txns-inputs-missingorspent`; rbitcoin accepted it, and
  a later block could then spend the same output again. The batch is now
  rejected, and the retry names the spending block. A spend slot that
  names a confirmed spender below the output's own height is now a store
  invariant error, not an unspent output.


- **`getblocktemplate` fees come from the selection.** Each
  transaction's `fee` and `sigops`, and the `coinbasevalue`, are read
  under the same mempool lock that selected it. A transaction evicted
  while the template was built no longer reports `fee: 0` and
  understates `coinbasevalue`.


- **`gettxout` and `scantxoutset` no longer report the genesis coinbase.**
  Bitcoin Core never adds the genesis block's coinbase output to the UTXO
  set. `gettxout` for that outpoint now returns `null`, REST `getutxos`
  reports it as missing, and `scantxoutset` leaves it out of `unspents`
  and `total_amount`. Electrum and Esplora are unchanged; Esplora matches
  Blockstream/mempool electrs, which index genesis.
- **`getrawtransaction` refuses the genesis coinbase txid.** It returns
  Core's `-5` "The genesis block coinbase is not considered an ordinary
  transaction and cannot be retrieved". REST `/rest/tx/` answers `404`
  `<txid> not found` for that txid, as Core does.


- **`getblockfilter` does not rebuild an unsealed index gap.** A best-chain
  block whose parent filter header is not sealed returns “Filter not found.
  Block filters are still in the process of being indexed.” A block whose
  parent header is already sealed is still built, and a stale branch is
  rebuilt only back to that sealed fork point.


- **`getblock` verbosity 1 carries `size`, `strippedsize`, and `weight`**,
  as Bitcoin Core does. They come from `txstat` (no block reconstruct) and are
  left out only when the body is unavailable. Stock mempool's block indexer
  stores `size` NOT NULL, so without them every block failed to save
  (`Column 'size' cannot be null`) and its tip, fees, and block list stalled.


- **A `getdata` past the serve queue waits; it is not dropped.** When 16
  served blocks or 4 MiB were already queued to a peer, the rest of its
  `getdata` was dropped without a `block` or `notfound`. The peer waited
  until its stall timer, and an rbitcoin IBD peer then disconnected an
  honest node. As in Core, the session now keeps the rest of the request,
  sends the `notfound` it has, and serves every hash in order once the
  writer drains. No new message from that peer is read until then, but
  pings and the ping timeout still run. At most 16 served blocks sit in
  one peer's queue. A compact tip announce does not take a serve slot.
  A `getblocktxn` reply (`blocktxn` or the full block) does, until the
  writer drains.


- **A side branch with a bad header no longer rewinds the tip.** Headers on a
  held branch are checked before any disconnect. A later block that claims
  enormous work without a valid proof of work is remembered invalid, and a
  heavier valid held branch can still become the tip. A store fault during
  that check is not cached as an invalid block.


- **A header peer that does not answer is not asked forever.** One header
  request is in flight. The same peer serves the walk and the queue refill:
  refill while the download queue is under 16,000 headers, walk while it is
  above that and still under the 64,000 soft cap. When the ask expires, the
  reservation moves; a second miss disconnects that peer. A late reply from
  the peer that was asked still extends the header walk when it builds on
  the tip, and that accept is logged. A confirmed reorg below the milestone
  drops the latched block 840,000 hash and logs that script checks stay on;
  the old hash is not put back. A restart whose `header.adopt` is missing
  or does not parse does not restore checkpoints, and still notes queued
  headers that link from the confirmed tip, which can turn script skip back
  on. Checkpoints from a file that does not parse are not used.


- **A headers batch whose first header does not connect skips the longer
  prefix search.** After the full batch failed, IBD tried about ten longer
  prefixes even when the first header could not be stored. The search now
  stops after that first header fails. A connected first header still
  binary-searches the rest of the batch.


- **Header download refills while the walk runs ahead.** One peer does
  both lanes, and only one of them is in flight. Below 16,000 queued
  headers that peer refills from the stored tail; above that it walks.
  An empty queue is rebuilt from headers still on the work path before
  that refill. A reply is classified by the hash it builds on: a walk
  continuation is a checkpoint while the walk is ahead, and a stored
  header once the walk has caught that top.


- Header look-ahead stops asking a peer after one short reply that does not
  extend the candidate, once checkpoint work meets the floor. A full
  2,000-header window can still build a lighter fork, and a later block
  `inv` puts the peer back on the walk. The download queue still stops
  at 64,000 headers, and only one header request is in flight.


- Header look-ahead starts at the stored tip on the first ask. A solicited
  continuation of that tip is a checkpoint, so the walk runs ahead of the
  download queue and the `ibd: headers` line is logged.


- **IBD retries a wave after a local store fault in load, scripts, or
  write.** Load offered the wave's bodies back but left lookup's consume
  mark past them. Scripts and write, and an io_uring session recover in any
  of the three, did not offer them back at all. Lookup never took those
  heights again unless a later wave, a disconnect, or a reorg re-armed it,
  so near the tip IBD stalled. Each stage now re-arms lookup at the tip and
  then offers the bodies back. The retry keeps the whole wave, except a
  pin-stage fault in a multi-block wave, which retries one block at a time.


- **A peer can no longer make IBD give up on a valid block by sending a
  bad body for it.** A body with no transactions, garbage transactions,
  a repeated tail (CVE-2012-2459), a first transaction that is not a
  coinbase plus any 64-byte transaction, or witness data the coinbase
  does not commit to marked the block hash invalid, and IBD never asked
  for it again. Block checks now test the merkle root before the other
  body rules, as Bitcoin Core does. IBD treats these failures as a bad
  copy of the block: it drops the body and requests the block again.
  That request is no longer skipped: before, near the end of IBD, a
  block whose bad body was dropped could wait forever.
  When the bad body is checked in a batch with other blocks, IBD retries
  the batch one block at a time, so only the bad body is dropped.
- **IBD no longer stalls after a confirm reject.** A reject puts the
  bodies of the retried blocks back on the body queue and restarts the
  confirm lookup at the tip. A lookup pass that started before the reject
  could then move the restart point past those bodies, so they were never
  confirmed and IBD waited on blocks it already had.
- **IBD retries a rejected batch from the bodies it already has.** When
  a batch fails in the script or write stage and is retried one block
  at a time, its bodies go back on the body queue. Before, IBD
  downloaded them again.
- **IBD disconnects a peer that sends a mutated block.** The peer's
  address also cools down, so the block is requested from another peer
  when one is available. A `noban` peer stays connected, as in Bitcoin
  Core. Unlike Core, and unlike tip-follow, a manual (`--connect`) peer
  is also disconnected. Tip-follow `misbehaving` leaves a manual peer
  connected.
- **A block with a second coinbase or a repeated transaction is now
  remembered as invalid.** These blocks reported `bad-txns-duplicate`,
  the reason Bitcoin Core keeps for a mutated body, so the node did not
  remember them and asked for them again. They now report Core's
  `bad-cb-multiple` and `bad-txns-inputs-missingorspent`.


- **IBD no longer stalls when a peer re-sends stored headers.** Headers
  the IBD already stored keep the store row they were accepted with.
  Checking them again walked each one back to the connected tip, and a
  fresh mainnet sync from one peer stopped after 16 blocks.


- A restart at the validated tip leaves IBD once no connected peer can
  extend that tip. An advertised `version.start_height` on a chain nobody
  serves no longer keeps the node out of tip mode.
- A header the walk already holds is fetched even when every peer's
  connect-time `version.start_height` is still the previous tip. A block
  announced after restart is downloaded instead of leaving the walk one
  above the confirmed tip.


- **A re-sent header run past the height walk cap is one walk.** When the
  first stored header cannot resolve a height within 10,000 ancestor steps,
  that miss is kept on the batch. Later headers in the same run do not each
  walk to the cap again.


- IBD treats a tip gap as a hole once the body queue meets any of: a quarter
  of the confirm-time block window, a quarter of the configured assign-stop
  (default 1 GiB), or 1000 blocks. Below all three the gap is the frontier:
  tip+1 gets one peer and densify keeps filling ahead. Gaps in the queue
  count. The 100 MiB free floor remains the densify horizon only.


- **IBD no longer re-requests a tip-hole block from a peer that still owes
  it.** Dropping a tip-hole owner forgot the getdata it was sent, so the
  next assign pass asked the same peer again. Peers answer every getdata,
  so on signet with 30 peers they spent 77–85% of upload re-sending blocks
  already stored, and tip+1 waited behind those copies for up to 55s. A
  dropped owner now keeps the request and is not asked for that hash again.
  Peers who still owe the block count toward its race cap, so dropping one
  does not free a slot for a peer that was never asked.
- **A tip-hole owner with other getdata queued is dropped only when it
  is actually slow.** Every peer has several blocks in flight during IBD,
  so the owner was dropped and replaced on every 50ms assign pass. It is
  now dropped only after holding the hash for 5s, and only when a free
  peer's expected drain time is at most half the owner's.
- **Blocks held by a dropped peer are requested again right away.** A
  peer disconnected as stalled or relative-slow, or a notfound, freed its
  blocks, but densify had already moved its scan cursor past them, so they
  were requested again only once they held up the tip.   The cursor now moves
  back to the lowest freed height.
- **A hung densify block keeps its getdata when no faster peer has a free
  slot.** Erasing that record let a later pass ask the same peer again. The
  owner stays retired, and another peer is asked once a slot is free, even
  when the getdata window is already full.
- **An extra racer on a later gap waits on the current owner's ask.** The
  30s age was the time since the hash was first requested, so a peer asked
  just now could look 30s old after an earlier owner was dropped.


- **IBD no longer stalls on an undecodable block body.** A peer that
  answered `getdata` with the real header and transactions that do not
  parse left the body queued forever, so the honest copy was dropped and
  confirm stopped at that height until restart. Intake now refuses such a
  body and disconnects the sender, and lookup drops any queued row that
  does not decode. The hash is requested again and is never marked
  invalid.
- **A block with Core's 10-byte empty transaction is invalid, not
  undecodable.** Core reads an empty input list followed by segwit flag 0
  as a transaction with no inputs and no outputs and rejects the block.
  rbitcoin now decodes that encoding the same way and marks the block
  invalid, instead of refetching it and dropping every peer that serves
  it.


- **A peer that asks for a block this node cannot serve gets `notfound`.**
  Silence held that getdata until the 30s stall floor, so a lighter fork
  peer could pin a heavier tip for two stall waits. An unknown hash, a
  header-only row, and a pruned body are `notfound`. The peer is asked
  again later: a `notfound` before they have the block is not a ban.


- IBD enters tip mode once the proven header walk is at the confirmed tip
  and every peer that advertised a taller `version.start_height` has failed
  to extend it. One peer advertising a height no chain has no longer keeps
  the node in IBD after the last block confirms.
- A block announcement during IBD asks that peer for headers even when
  its connect-time `version.start_height` is below the header walk. New
  blocks found during a long catch-up are no longer ignored until tip
  mode.
- The `ibd: progress` percent, ETA, and `horizon=` count toward the header
  walk tip or the tallest connected peer still on the walk. A disconnected
  peer, or one that could not extend the walk, no longer sets the horizon.


- **Coinbase maturity holds inside one confirm batch.** When a coinbase and
  a transaction that spends it were in different blocks of the same write
  batch (IBD, catch-up, or reorg connect), the 100-block maturity check
  did not run, so a block that Bitcoin Core rejects with
  `bad-txns-premature-spend-of-coinbase` was accepted. The batch now marks
  each block's coinbase itself instead of reading `confirmed`, which is
  not yet written for those heights.


- **Index build refuses a parent or witness span past the published body.**
  The block's own txout span was checked against the file end. A parent
  txout, or a seqsigwit span for a P2TR output, was still read from the
  slab after that end had moved backward.


- **Scripthash index survives power loss.** Write-behind now syncs the
  scripthash tables before advancing the durable inclusion watermark.
  Before, an OS crash or power cut could leave the watermark claiming
  outputs whose index bytes were lost, so those addresses' histories
  stayed incomplete. DEBUG `tip: accept` is one JSON object; the sync
  time is `sh.sync_ns`.
- **Silent-payment tweak index survives crashes.** Each write is synced,
  and on start the index is trimmed to the chain tip and its last record
  checked. Before, a crash during a reorg could keep serving tweaks for
  blocks no longer on the chain, and a power cut could turn tweaks into
  "none" or make a height unreadable.


- **`invalidateblock` activates the most-work remaining fork.** Candidates
  were ranked by the work of their side branch alone, so an older, longer
  fork could outrank an equal-work sibling of the new tip and leave the
  node on the parent.


- **`invalidateblock` of the tip honors `preciousblock` on an equal-work fork.**
  The same tie rule as an ordinary reorg applies: more total work still wins,
  then the precious branch, then the earlier held tip.


- **Electrum and Esplora listen when `--sh-index` is off.** Address and
  scripthash methods still fail closed. With the index on, the listeners
  still wait until scripthash is caught up.


- **Tip-follow does not punish a manual peer for misbehavior, as in Core.**
  A `--connect` or `addnode` peer that sends an invalid block, an oversized
  `inv`, `getdata` or `addrv2`, or a bad compact block stays connected and
  its address is not refused. A mutated body during IBD still drops that
  peer unless it is `noban`. Protocol violations that Core answers with a
  plain disconnect, such as `sendaddrv2` after `verack` or a `tx` to a
  `--blocks-only` node, still drop a manual peer.
- **`addnode` opens no second session to a connected address.** `addnode
  onetry` or `add` of an address with a live session, or one still being
  dialled, dialled it again, and each dial that connected became its own
  session. As in Core, the RPC now succeeds without dialling. A dial now
  counts from the moment it is queued, so an `addnode` or `--connect`
  redial right behind another dial to the same address adds nothing.


- **A torn mempool sidecar no longer stops the node from starting.**
  The 5-second admit persist and shutdown flush sync `tx.body` before
  publishing `LIVE` slots, then sync slots before `meta`. Open keeps
  transactions still inside the logical body and drops the tail. An
  unreadable `meta` / `slots` / `tx.body` (bad magic, unknown schema, or a
  payload that does not decode or whose txid does not match the slot) is
  moved under `mempool/torn-<unix>/` and the node starts with an empty
  mempool. `fee_history` stays in place.


- **A replacement that pays the incremental minimum is no longer rejected for sharing a truncated sat/kvB bucket.** RBF requires a strictly higher true feerate, including when `fee × vsize` exceeds 2^64.
- **Advertised minimums match the fee the mempool enforces.** `getmempoolinfo.minrelaytxfee` and Electrum `minrelaytxfee` follow `--min-relay-tx-fee`. `mempoolminfee`, Electrum `blockchain.relayfee`, and the BIP133 feefilter follow the live floor, including the near-full bump and its decay.
- **An admission that evicts other transactions and then fails still publishes that higher floor.** `mempoolminfee`, Electrum `blockchain.relayfee`, and the feefilter update immediately, including when the failed transaction was the first member of a package.


- **A lower `--min-relay-tx-fee` is the fee peers are told.** The rolling floor starts at the configured minimum. It no longer stays at the default 100 sat/kvB, so the BIP133 feefilter drops with `-minrelaytxfee` once the node leaves IBD. An eviction that already raised the floor still holds.


- **Consensus: IBD marks a block that spends an unknown txid invalid.**
  A block on the best header chain that spends a transaction the
  connected chain does not have halted IBD as an engine fault, and the
  hash was never marked invalid. Bitcoin Core rejects it with
  `bad-txns-inputs-missingorspent` and follows another valid chain.
  IBD now re-reads the block's parents once the block extends the tip
  and the transaction index covers the chain, and marks the block
  invalid when a parent is still missing. A parent the index lost after
  a power loss is a store fault, not a verdict. A block whose parent
  miss is a store fault goes back for one retry instead of stalling
  IBD, and the check works right after a restart.


- The nightly mutants job no longer stops when a batch catches every mutant, and it no longer fails by copying the cursor file onto itself.


- A reconstructed tip block is announced as `cmpctblock` before connect to
  peers who sent `sendcmpct` announce=1 and already have the parent. Peers
  we only selected as compact sources no longer receive that announce.


- **NixOS index options no longer crash-loop the node.** `scripthashIndex`,
  Electrum, and Esplora pass `--sh-index`. `silentPaymentIndex` passes
  `--sp-tweaks`. The old spellings were rejected at startup, and systemd
  restarted the unit every 10 seconds.


- **Consensus: a P2SH spend whose scriptSig leaves 1000 stack items is
  invalid.** Core runs the P2SH scriptPubKey `HASH160 <20> EQUAL` on the
  scriptSig stack, and its 20-byte push goes past the 1000-item stack
  limit. We only compared the hash, so we accepted a spend that Core
  rejects.


- **A package is trimmed once, after every member is in.** A parent that is
  under the fee floor alone is not evicted before its paying child commits,
  so `submitpackage` does not answer `mempool full` for a package that fits.
  A package that does not survive that trim is rolled back, so the conflicts
  it replaced stay.


- **A txid parent is requested after the same peer's wtxid window ends.**
  Expiry matched the first announcement for that peer. When that row was
  the waiting txid parent, the in-flight wtxid window stayed indexed and
  no getdata followed.


- **Esplora `after_txid` is 422 when that tx is not in the script's history.**
  A cursor that exists somewhere else on the chain used to restart page 1.
  `/txs`, `/txs/chain`, `/txs/summary`, the address routes, and a multi
  POST now return `after_txid not found` and no rows.
- **`estimatesmartfee`, `estimaterawfee`, and Electrum `blockchain.estimatefee`
  use the 2-block rate for target 2.** Target 0 is still the next-block
  horizon. Target 1 stays the 1-block rate.
- **A shared orphan survives the other announcer's reserve.** Evicting
  peer B drops only B. Peer A's copy is still delivered when the parent
  arrives.
- **A tip shrink clamps the spend-durable marker.** Open revalidation and
  spend replay lower a marker that sits above the surviving tip, so a
  later confirm still annotates spends. A checkpoint cannot publish the
  pre-disconnect height over that clamp.
- **A newest-first scripthash page stops at the page edge.** An unspent
  tail no longer re-reads every older create.
- **A tip or compact block with a repeated transaction pair is not a
  block.** The merkle root can still match (CVE-2012-2459). Tip follow
  disconnects that peer. Compact reconstruction returns the hash to
  `getdata`.
- **`submitblock` of a sibling that spends a coin the tip also spent is
  inconclusive.** That header is not cached as `duplicate-invalid`.
- **A refused local I2P SAM port does not rotate the session.** The dial
  error is no longer classified as a dead `STREAM CONNECT`. A SAM reply
  of `INVALID_ID` still is.
- **Outbound dial keeps one onion or I2P seat when clearnet fills the
  batch.** A dead overlay peer is recorded on its real address. An
  unspecified version socket is not inserted into addrman.
- **An Esplora singleflight join does not put an older scripthash back
  over a newer last-1** for the same client. That includes a leader that
  is still inside its handler when the newer script finishes, and a waiter
  that resumes after it.


- A store whose `meta` is older than schema 22, empty or occupied, refuses
  with one wipe-and-IBD line before any table parser runs. Schema 22 and
  later still open, including the `create.loc.ovf` widen, the header
  size/weight rewrite, the inwit rename, and the `txstat` zero-extend.


- **A block proposal whose fees do not fit in `u64` is rejected.** Output
  totals, input totals, and the fee sum use checked addition. An overflowing
  sum is `bad-txns-txouttotal-toolarge`, `bad-txns-inputvalues-outofrange`,
  or `bad-txns-fee-outofrange` instead of a successful template check.


- **`getblocktemplate` proposal mode rejects an immature coinbase spend.**
  Spending this block's coinbase, or a coinbase still inside the maturity
  window, is `bad-txns-premature-spend-of-coinbase` before fees are summed.
  That spend no longer inflates the fee total returned to a template
  provider, and it no longer hides `bad-cb-amount`. An output whose
  creating transaction is no longer on the best chain is
  `bad-txns-inputs-missingorspent` rather than a mature input. Structure
  checks still run first.


- **A block proposal with a failing script is rejected.** After the coinbase
  amount check, proposal mode runs the block's script flags on the prevouts
  it already resolved. No second parent decode and no UTXO write. P2SH and
  witness sigops count toward the 80_000 block limit.


- **Spentness is probed on the connected create.** `gettxout`, mempool accept,
  the proposal check, and the Electrum and Esplora spent checks read the
  spender slots of the row on the best chain; a newer never-connected row for
  the same txid no longer hides a confirmed spend.


- **Pure replace-by-fee-rate compares the full product.** A replacement whose
  `new_fee * 4 * old_vsize` or `direct_fee * 5 * new_vsize` exceeds `u64`
  is held to 1.25× in `u128`, instead of a saturating multiply that can
  accept a rate below the rule.


- **Regtest enforces BIP34 from height 1, like Bitcoin Core.** Regtest kept
  rust-bitcoin's BIP34 height of 100000000, so a coinbase without the block
  height push was accepted where Core rejects it.
  `-testactivationheight=bip34@N` still moves the height. BIP30 stays
  enforced on regtest, because regtest has no BIP34 hash.


- **A spend of an output index past the parent's output count is a
  block reject.** A block that spends `(txid, vout)` where `txid` is
  confirmed, or created earlier in the same batch, but has no output at
  `vout` is rejected with `bad-txns-inputs-missingorspent`, as in Core.
  Before, load reported store corruption, IBD retried the block without
  end, and the tip path cached a store error string as the reject reason.
- **A store fault during tip connect or `submitblock` does not mark the
  block invalid.** A store IO error or a store invariant failure is no
  longer cached as an invalid block, and neither is a connect cancelled
  by shutdown. Before, the valid block was refused for the rest of the
  process. Consensus rejects are still cached. `submitblock` answers a
  store fault, including one reading the parent or tip header or a
  spent output, with RPC error `-25` (`RPC_VERIFY_ERROR`), as Core does
  for `state.IsError()`.
  A cancelled connect answers `inconclusive`, as Core does when
  shutdown interrupts the block check. Consensus rejects still return
  their BIP22 reason string.


- **A failed replacement keeps the transactions it conflicted with.** If the new transaction does not stay in the mempool, one-transaction submit and package submit put those conflicts back, including a conflict under the fee floor and a parent that only paid its fee together with its child.


- **Block header and block RPC match Bitcoin Core's JSON for inactive
  headers, genesis, and difficulty text.** `getblockheader` and `getblock`
  return a stored header that is no longer on the active chain
  (`confirmations: -1`, its own `previousblockhash`, and a Class A body when
  one exists). Genesis omits `previousblockhash`. `getblockheader` includes
  `nextblockhash` and `target`. `getblockchaininfo` includes `bits` and
  `target`. Difficulty uses 16 significant digits. `validateaddress` reports
  `isscript` for P2TR and P2A and omits witness fields on pay-to-anchor.
  `getmempoolinfo` includes `fullrbf`, `maxdatacarriersize` (null), and the
  cluster limits. BTC amounts print as 8-decimal numbers.


Script engine behaviour under policy flags now matches Core. Mempool
admission does not change: it still runs with consensus flags only.

- **NULLFAIL in witness v0 `CHECKMULTISIG` applies after the key walk.**
  A P2WSH multisig signature that matches a later key is no longer
  rejected when NULLFAIL is set.
- **STRICTENC and WITNESS_PUBKEYTYPE check the pubkey for an empty
  signature**, in `CHECKSIG` and in each `CHECKMULTISIG` pair checked.
- **DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM matches Core.** Pay-to-anchor
  and a v1 32-byte program before Taproot are exempt. P2SH-wrapped
  v1+ programs are discouraged.
- **P2WPKH applies LOW_S and the STRICTENC hashtype check** when those
  flags are set, native and P2SH-wrapped.


- **WITNESS and TAPROOT script flags apply on every block, as in Core.**
  They no longer wait for the segwit or taproot height. Core's two
  mainnet exception blocks keep their replacement sets: the BIP16
  exception (170060) runs with no P2SH, WITNESS, or TAPROOT, and block
  692261 runs without TAPROOT.
  Witness sigops count on every block with the WITNESS flag. On a regtest
  chain with a later `-testactivationheight=segwit@N`, a v0 witness
  program spend below `N` is now held to the witness rules.
- **P2PKH spends enforce the 520-byte push limit.** The P2PKH fast path
  accepted a scriptSig push over 520 bytes (for example a pre-BIP66
  signature with junk before the hashtype). It now falls back to the
  interpreter, which rejects it as Core does.
- **P2WPKH signatures follow the DERSIG flag.** The P2WPKH fast path
  (native and P2SH-nested) required strict DER on every block. Core
  applies strict DER to v0 witness signatures only when BIP66 is active,
  and caps each witness element at 520 bytes. Both now match Core; this
  shows on a regtest chain with dersig activated after segwit.


- **`--sh-index` on an empty chain seals scripthash shards without reading
  the empty ingest table.** That walk is 2^25 slots per shard and was
  holding tip entry past the RPC cookie window.


- A scripthash pass-1 MPHF without `scripthash.head/NN.packed` is not a durable head. Restart after `DONE.keys` resumes pass 2 and pack instead of reporting Electrum-ready on an index that has no multi-script history. A finished unmarked head is soft-migrated.
- Electrum stays down when a durable scripthash head's inclusion floor is behind the tip, and the same process binds it once write-behind catches up. A cancelled extract names `scripthash.cold_progress` or `scripthash.unsorted` only when that path is on disk.
- A tip append onto an unsealed pass-1 head no longer hides the packed multi-script chain. Packing the shard drops that ingest row once main owns the key.


- **A signet block with no solution is checked against any challenge.** As
  in Bitcoin Core, a coinbase commitment without the signet section spends
  the challenge with an empty scriptSig and witness, and the challenge
  script decides. Before, such a block was rejected unless the challenge was
  exactly `OP_TRUE`.
- **The signet commitment rewrite matches Bitcoin Core byte for byte.** A
  zero-length `OP_PUSHDATA1/2/4` in the witness commitment is kept as its
  bare opcode, and a push longer than 65535 bytes is re-encoded with
  `OP_PUSHDATA4`. Before, the empty push became `OP_0` and the long push got
  a truncated `OP_PUSHDATA2` length, so the modified merkle root and the
  signet signature hash differed from Core.


- **Block sigop cap includes 80,000.** Admission and template selection
  allow a running cost of exactly 80,000, with `--block-reserved-sigops`
  counted in that total. A cost that would pass 80,000 is still
  `bad-txns-too-many-sigops`.


- **A re-connected block records its spends of earlier-archived outputs.**
  Confirm skipped the spent-slot read and annotation when a spend's parent
  was created in the same run, trusting a Class A pre-fill. A parent stored
  by an earlier batch (for example one rejected after its bodies were
  stored, then re-driven after a reorg) never got that pre-fill, so the
  slot stayed empty and a later block could spend the same output again.
  Only outputs this batch's Class A append wrote now skip the read.
- **A failed write after the tip commit no longer lets the next block
  validate without its spends.** If a confirm write failed after the tip
  advanced (for example in the spend annotate or the live index seal), the
  next batch read spent slots that were never written and could accept a
  double spend. The next write now replays the missing annotations first
  and logs `confirm: replay spend annotations`. If that replay fails, the
  batch is not validated.
- **A reorg no longer lets the spend checkpoint claim heights it did not
  annotate.** After a disconnect, `rbtc-spend-sync` could still publish the
  snapshot height from before the reorg. If the reconnect had not finished
  its spend annotate, a crash then reopened above those heights and did not
  replay their spends. A disconnect now lowers the snapshot to the new tip,
  a confirm write cannot raise it back over the tip, and the checkpoint
  stays below any height whose spend annotate is still pending.


- **A restart totals header work with two sequential reads of `header.body`.** One read ranks a stored side chain against the tip. The next fills chain work through the tip, from `nBits` alone. Catch-up finishes without a separate read of every header row. A header that arrives while that read is starting does not abort the search. A failed chain-work total does not keep a partial sum.


- **`submitblock` runs CheckBlock before inputs when the parent is known.**
  An equal-work sibling that fails CheckBlock is rejected and remembered.
  A second submit is `duplicate-invalid`. A block that will not connect
  used to be held as `inconclusive` when the failure was not in the cheap
  input checks. A valid sibling stays `inconclusive`. Merkle and witness
  mismatches are still not remembered.


- **`submitblock` reports `bad-cb-height` for a wrong BIP34 coinbase
  height.** It returned `bip34 height encoding`, which is not a Bitcoin
  Core reason. The block is still remembered as invalid.
- **A coinbase scriptSig shorter than two bytes is `bad-cb-length` once
  BIP34 is active.** The height check ran first and reported the BIP34
  failure. Bitcoin Core checks the length first.
- **`submitblock` checks the merkle root before the transactions.** A
  body the header does not commit to reported a transaction reason such
  as `bad-cb-missing` or `bad-txns-duplicate`. It now reports
  `bad-txnmrklroot`, as Bitcoin Core does.
- **`submitblock` reports Bitcoin Core's reason for a repeated
  transaction.** Every repeated txid was `bad-txns-duplicate`. Core keeps
  that reason for a repeat that leaves the merkle root unchanged. A second
  coinbase is now `bad-cb-multiple`, and any other repeat is
  `bad-txns-inputs-missingorspent`.
- **A transaction with no outputs or no inputs gets Bitcoin Core's reason.**
  `submitblock` and the block reject log said `no outputs` and `no inputs`.
  They now say `bad-txns-vout-empty` and `bad-txns-vin-empty`. The pre-check
  applies that before comparing input and output values, so an empty input
  list with an output is not `bad-txns-in-belowout`.
- **A block that spends an immature coinbase reports
  `bad-txns-premature-spend-of-coinbase`.** It said `coinbase immature`.
  The pre-check reports the same reason before `bad-txns-in-belowout`, for
  a same-block coinbase and for a confirmed coinbase inside the maturity
  window.
- **A cheap `submitblock` consensus reject is remembered.** A second submit
  of that header is `duplicate-invalid`. A merkle mismatch and a mutated
  duplicate are not remembered.
- **A block over the weight limit reports `bad-blk-weight`.** It said
  `block weight too large`.


- **Tapscript validation is linear in script, witness, and input count.**
  A leaf with deeply nested `OP_IF`s, many signature checks over a large
  leaf script, annex, or SIGHASH_SINGLE output, or many script-path inputs
  in a tx with large spent scriptPubKeys, cost quadratic CPU to validate,
  so one relayed transaction or block could stall script checks. The IF
  condition stack, the per-input sighash hashes, and the per-tx spent-output
  hashes now follow Bitcoin Core. Accept and reject results are unchanged.


- **Testnet3 BIP16 exception.** The testnet3 block Bitcoin Core exempts
  from script checks (`00000000dd30457c…a432b105`) no longer enforces
  P2SH, so full script validation accepts that historical block.
- **Testnet3 default milestone is anchored.** The omitted `--milestone` on
  testnet3 now requires Bitcoin Core's assumeutxo block at height 2500000
  and Core's testnet3 minimum chain work before it skips scripts, like
  mainnet. An omitted milestone previously checked every testnet script
  and testnet had no default minimum chain work. A chain that does not
  contain the anchor still checks every script. Testnet3 now uses Core's
  default minimum chain work, which also gates IBD state, relay, and
  low-work header handling until the chain reaches it.
- **Testnet3 header batches after a min-difficulty block.** A header
  within 20 minutes of a min-difficulty parent now takes the last
  non-min-difficulty `nBits` even when that header sits earlier in the
  same `headers` reply, as Bitcoin Core does. Before, the walk expected
  the min-difficulty limit, rejected the batch, and dropped the peer.


- **A miner can no longer get a valid block refused at the tip by first
  sending a fake body for its header.** A body with no coinbase that holds
  a 64-byte transaction can be the block's inner merkle nodes read as a
  transaction, so it matches the header's merkle root. The tip path cached
  that hash as invalid and then refused the real block. As in Bitcoin
  Core, such a body is now a mutated block on the tip, P2P `block`,
  compact block, and `submitblock` paths: a `block` message is dropped
  and its peer punished, a compact block falls back to a full download,
  and the hash is not marked invalid. `submitblock` also no longer caches
  a mutated body (for example padded witness bytes) as an invalid block.
  The IBD body path is covered by a separate change.


- **Tip-follow picks the held branch with the most total chain work.**
  Held side branches were ranked by work from their own fork point. A
  later branch with more total work could lose a tie to an earlier
  branch and never be tried. A branch that fails connect no longer
  hides a lighter valid branch that still beats the tip.
- **A failed block keeps the heavier valid part of its branch.** When a
  block in a side branch fails connect, the node stays on the blocks
  before it if they have more work than the old tip, as Core does. The
  failure is no longer reported for the valid block that triggered the
  reorg, so `submitblock` accepts it. The failed block itself is still
  rejected.
- **A side block's header is checked before the tip moves.** A sibling
  of the tip that claimed more work with wrong `nBits` disconnected the
  tip before it was validated and was not restored. `submitblock` and
  compact blocks could rewind the tip this way, one block per sibling.


- **`tx.head` no longer drops entries after a gap in Class A:** a confirm
  write that appends its bodies and then rejects on the planned-fk check
  leaves bodies the head never indexes. Segments rolled on entry count while
  the seal re-reads an fk range, so such a gap made the next seal cover the
  wrong range and lose that many real entries. IBD then halted on
  `missing prevout (leftover … leftover_n=0)` at every restart. Segments now
  own an fk span. Heads that already lost entries need `store/tx.head` moved
  aside once, so open rebuilds it from Class A (#843).


- **One peer is asked for an announced transaction.** A second
  announcement of the same wtxid or txid waits. Disconnect or `notfound`
  from the peer that was asked makes the waiting peer due. An inbound
  announcement is still requested immediately.


- **Mainnet no longer warns `Unknown new rules activated (versionbit 0)`,
  `(versionbit 1)` and `(versionbit 2)`.** The unknown-bit check counted
  blocks from genesis, so the CSV, SegWit and Taproot signalling periods
  looked like unknown rules. As in Core, blocks below `MinBIP9WarningHeight`
  (711,648 on mainnet, 2,013,984 on testnet3) no longer count, and mainnet
  needs 1815 of 2016 blocks (90%) instead of 1512.


- The Warnet kind image tag is the release `28.0.0` (not an rbitcoin
  version). Helm `semverCompare ">=0.17.0"` is true for that tag, so the
  chart writes `[regtest]` before the tank's RPC and `addnode` lines.
  `0.7.99` and any prerelease of it compare below `0.17.0` and omit the
  section. The compose example stays `rbitcoin-warnet:local`.
- Lab tanks copy node log lines to stdout when `RBITCOIN_LOG_STDOUT=1`,
  and the RPC proxy accepts Warnet's fork-observer `rpcauth` login for
  its whitelisted chain methods while the tank `rpcpassword` user stays
  unrestricted. A tank whose conf omits `head_scale` uses tiny heads
  inside the lab image; `head_scale=mainnet` still selects mainnet heads.


- **`getnetworkinfo`, `getblockchaininfo`, and `getmininginfo` answer
  quickly again.** Their `warnings` check read every header since genesis
  once per version bit on each call (about 4.7 s at mainnet tip). It now
  keeps its place and reads each completed 2016-block period once.

### Changed

- **Hostname `--connect` / `addnode`:** clearnet names resolve at each dial
  (`localhost` and a missing port use the network P2P default) on a blocking
  thread, and retry until a live session exists. `--connect` does not enable
  seed redial. If the first catch-up accepts nothing and the tip is still 0,
  the node enters tip-follow (16 blocks in flight, no return to the IBD
  window) so a late short-chain peer can attach. A non-zero tip stays in IBD.
  Relay stays gated below `--min-chain-work`.
  Label `warnet` runs a two-tank Docker example that starts the connecting
  tank first and waits until its height matches the miner and `getpeerinfo`
  shows the resolved address
  ([`docs/core-functional.md`](docs/core-functional.md)).

- **Tor SAFECOOKIE HMAC is `bitcoin_hashes`.** There is no `hmac` or
  `sha2` crate, and no `tokio-tungstenite` (Esplora has no WebSocket).
  `bitcoin` is 0.32.102. `getrandom` 0.4 is the direct dependency;
  `rand_core` still pulls `getrandom` 0.2.

- **Pruned SH materialize is two-pass extract:** each collect worker owns a
  contiguous create-fk span and unsized maps capped at 1.5 GiB
  (`SH_EXTRACT_WORKER_RAM_BYTES`; 64 B/key pass 1, `80n+8f` pass 2). After
  each 64 k-fk loc/body batch, spill the largest shard map while over
  budget (`SHKSP01` under `keys/NN/`, first-fk delta singles). Collect spills
  are tmp+rename without `sync_all` (no `DONE.keys` still wipes unsorted).
  Merge folds those spills into one map, one walk to pack8
  `scripthash.head/NN` (singles `inline_one`, multis Empty; file exists is
  not pack-done) and fuse8 of dupes to `multi/NN.fuse8` (on disk so other
  shards do not keep it resident), then unlinks `keys/NN/`. The folded
  map is consumed into the pack8 records and dropped before fuse8 and BDZ.
  Pass 2 keeps fuse8 only (no BDZ): same static spans; fuse-hit creates
  fold into per-worker `key16 → Vec<fk>` maps and spill-largest as
  `SHPST01` under `post/NN/`. A `post/NN` file, or a spill whose magic is
  not `SHPST01`, is Corrupt. Pack folds those spills into one map
  (~0.3–0.5 GiB/shard; a few GiB for 8 workers), then `slot_for_key16` +
  2+ bodies (grouped by MPHF slot); `len == 1` after fold is `fp_singles`. `DONE.post` is
  `SHPOST02` last_fk. Keys already unlinked when Class A grows before
  pack: full recollect (MPHF tags are not key16). All extract phases
  share `sh_extract_workers()` = min(CPUs, max(1, free RAM / 1.5 GiB));
  `RBITCOIN_SH_MERGE_WORKERS` still overrides. Collect maps are the
  1.5 GiB worker cap (spilled and dropped before merge BDZ). Progress is
  `scanned=` finished fks. Output and hit counters flush once per 64 k-fk
  batch. Spills share one writer (1-slot queue). One
  `keys merge start`; live `keys merge shard=` with `fold=` `bdz=`; pack
  shard lines when each worker finishes. Previous `DONE` / 24 B `NN`
  unsorted is deleted and pass 1 restarts.

- **Electrum/Esplora no longer require `--sh-index` to bind.** Address and
  scripthash methods return `scripthash index disabled` (Electrum JSON-RPC
  error; Esplora HTTP 503). Txid/outpoint/block/fees work. Channel watches
  do not need Class B.

- **Schema 26 keeps the schema 25 econ stems.** `txstat.body` stays
  8 B/create: three ULEBs (`fee_sat`/`base`/`wit_extra`) plus per-header
  remaining-byte overflow. `n_in` is `input.loc` (u16). `input.body` is
  the parent edge (create fk and vout) per input. `seqsigwit` is the old
  `inwit` stem (sequence, scriptSig, witness); open renames those files.
  `txstat.*` and `input.*` sit next to `seqsigwit` (cold when split).
  Open with no `input.loc` backfills the edges from `seqsigwit` prevouts.
  A four-ULEB cell that started with `n_in` is not rewritten; resync that
  datadir. Opening schema 24 or 25 also shrinks `header.body` from 96 B
  to 88 B and rewrites `meta` to 26. Leftover `txfixed.body` is unlinked.
  A 25 binary refuses 26 `meta`.

- **Core functional `mempool_packages.py`:** inventory `run`. Verbose mempool
  `vsize` / ancestor-descendant size use Core ceil-vsize; `wtxid` is on both
  `getmempoolentry` and verbose `getrawmempool`; non-verbose txid list is
  display-hex sorted.

- **Core functional `p2p_invalid_block.py`:** inventory `run` (v2 twin only).
  Coinbase excess is `bad-cb-amount`. Mutated / time-too-new rejects forget
  `asked_blocks` and do not cache `BLOCK_FAILED`.

- **Core functional `mempool_package_limits.py`:** inventory `run`.
  `testmempoolaccept` of a multi-tx package reports `package-error:
  too-large-cluster` when the package plus in-mempool parents would exceed
  cluster limits, and otherwise evaluates later package txs against earlier
  ones.

- **Core functional `p2p_orphan_handling.py`:** inventory `run`. Orphan
  parent GETDATA follows inbound NONPREF+TXID delay, skips parents that
  arrived or are known-invalid, prefers outbound announcers, and maps
  `missingorspent`. `testmempoolaccept` missing prevouts are `missing-inputs`.

- **Core functional `rpc_packages.py`:** inventory `run`. `submitpackage`
  accepts each transaction on its own, then package-evaluates a min-relay
  or orphan remainder of at least two (Core `AcceptPackage`). `conflict-in-package`
  and related package-error shapes match the official script. Non-OP_RETURN
  scripts over 10 000 bytes are `scriptpubkey`. `mempoolminfee` rises when live
  weight plus `MAX_STANDARD_TX_WEIGHT` exceeds the cap. The harness maps
  Core `-maxmempool=N` onto a 4× weight budget so `fill_mempool` evicts like
  Core 5 MB RAM. Abort-class `testmempoolaccept` blanking is proxy JSON;
  child-with-parents topology and in-package maxfeerate overlay are
  `RBITCOIN_RPC_PACKAGE_DIALECT` (shim). RPC-submit still rejects `"version"`;
  P2P Libre does not.

- **Libre P2P admits any nVersion:** `check_libre_admission` no longer maps
  nVersion outside 1/2 to policy `"version"`. `sendrawtransaction` /
  `testmempoolaccept` / `submitpackage` still reject those txs as RPC-submit
  only (same layer as `maxfeerate` / `maxburnamount`). Production
  `testmempoolaccept` package rows stay sequential. Production `submitpackage`
  admits a 3-gen chain when fees/policy allow. A missing-inputs child that
  package-evaluation can pair with its parents is admitted with that
  remainder; a child that stays a lone orphan is still
  `bad-txns-inputs-missingorspent`.

- **Q-68:** create.loc window SIMD (`deinterleave_pairs_u8x8`,
  `inclusive_u8x8_times_8`) lives in `rbitcoin-primitives` with a scalar
  oracle. Store calls those fns directly. Nightly `miri.yml` stays
  primitives-only (**Q-53**).

- **Q-56:** shipped scriptnum (encode/decode/is_minimal, width 4 and 5) and
  pack-ints (CompactSize + ULEB128) live in `rbitcoin-primitives`. Interpreter,
  store, and mempool call those fns directly (`From` maps crate errors). Signet
  walks CompactSize with `read_compact_size_from` and decodes the default
  challenge with primitives hex. `cfg(miri)` extra loops on those fns. Nightly
  `miri.yml` stays primitives-only (**Q-53**).

- **Per-slice local CI:** each plan step runs the workspace suite after Green
  and the other required gates except coverage after Refactor, then commits
  before the next slice. Same *commands* as CI, not the GitHub Actions `env:`.
  Coverage and native `windows` / `macos` stay GitHub Actions. See
  [`docs/how-we-plan.md`](docs/how-we-plan.md).

- **Agent routing:** Core-facing work starts at [`COMPAT.md`](COMPAT.md).
  Extracts move (not copy): [`docs/code-shape.md`](docs/code-shape.md).
  Suite/clippy logs stay out of the session: [`docs/how-we-plan.md`](docs/how-we-plan.md).

- **0.8 electrs HTTP drop-in:** `/internal/*` is **unix listen only** (TCP
  GET/POST `/internal` → 404). `GET /mempool` count/vsize/total_fee come from
  the fee snapshot (no body clones). Unix `/internal` mempool-tx pages still
  lazy-build a published tx-body snapshot (≤ one extra live-pool of
  `Arc<Transaction>` + JSON `OnceLock`; dirty/singleflight; not FIFO/LRU).
  Core RPC for that stack is TCP plus `--rpc-cookie-file` (HTTP Basic,
  alongside Bearer). The unix `{datadir}/rpc.sock` `socketPath` patch stays
  optional. Address-prefix stays 404.
  Surface: [`COMPAT.md`](COMPAT.md).

- **`getnetworkhashps` matches Core:** chainwork delta over min/max header
  time in the lookup window; `nblocks<=0` uses the difficulty retarget
  length. Not dummy 2-work-per-block. [`docs/rpc.md`](docs/rpc.md).

- **Esplora `?after_txid=`:** GET `/address|scripthash/…/txs` and `/txs/summary`
  skip through a known txid (mempool then chain). Unknown or unparseable →
  **422** `after_txid not found`.

- **Esplora multi-script POST:** `POST /addresses|scripthashes/txs` and
  `/txs/summary` merge unique scripts (max 300; over → **422**).

- **Esplora broadcast test:** `GET /broadcast?tx=` admits like `POST /tx`.
  `POST /txs/test` is dry-run `test_accept` with electrs `maxfeerate` BTC/kvB.

- **Esplora tx JSON `sigops`:** BIP16+BIP141 cost via `tx_sigop_cost` (same as
  Core `GetTransactionSigOpCost`).

- **Esplora HTTP SH join:** last-1 GET + last-bulk POST share 16 MiB packed/client
  (oversize last-1 is used for that request and not retained). Keyed by
  `X-Rbitcoin-Client` only on a unix socket or when join-header trust is
  on (30s idle; 256 clients). Loopback alone is not trust. Public TCP
  ignores the header. Not an 8-script LRU and not a >5s process whale
  cache.

- **Esplora REST sends `X-Powered-By: rbitcoin-esplora/<version>-<hex>`.**
  There is no wallet WebSocket. `/ws` and `/v1/ws` are 404.



- **The API log truncates a large params body before copying it.** A
  secret that overlaps the logged prefix is still redacted. A `submitblock`
  body with no secret in that prefix is no longer copied in full on the
  work-queue thread.


- Connect names the sigop-cost cap and subtracts fees with checked
  arithmetic. An output sum above `MAX_MONEY` is still rejected in
  structure validation (`bad-txns-txouttotal-toolarge`) before that sum
  is cast. Thanks to @Hero-Gamer.


- **Block filters and silent-payment tweaks build as blocks confirm, or after a large gap.** With the index already at the tip, including a fresh sync, each block is built on the script pool after script verification and appended on the confirm write. At startup a gap through the tip of at most 2,016 heights (one IBD write drain: queue 14 × confirm cap 144) is sealed before confirm and live append turns on. A larger gap stays off the confirm path and is built after catch-up by `rbtc-idx-wb`, which logs `index: build` and reads stored chain data. Follow, relay, and Electrum do not wait for that build. Shutdown during it is prompt; the next start resumes. Enabling the index on an existing datadir does not stall IBD exit.
- **Filters build on `--prune-seqsigwit` nodes.** They read output and
  spent-prevout scripts from stored chain data, not reconstructed blocks.
- **Filter storage is indexed.** Any height's filter is two reads; filter
  hashes and headers are one. Writes are crash-consistent, and on open
  slots for blocks no longer on the best chain are dropped.
- **BIP157 serving matches Core on bad ranges.** `getcfilters` /
  `getcfheaders` with start past stop, or more than 1000 / 2000 heights,
  disconnect the peer instead of returning a clamped batch.
- **`tip: accept`** is one JSON object. Filter time and lag are `bf_ns`
  and `bf_lag`. There is no `tweaks=` field.


- **Unreleased notes live in `changelog.d/`.** Feature pulls add one
  fragment there and leave `CHANGELOG.md` alone. `release-cut.sh`
  folds the fragments into `## [Unreleased]` and deletes them before
  cutting the version section.


- `--datadir-cold` is the append-only volume: `seqsigwit`, `txstat`,
  `input`, and, once enabled, `blockfilter` and `sp_tweaks`.
  `--prune-seqsigwit` still only drops historical seqsigwit and keeps
  its 288-height window on the hot store. A split datadir that still
  has `blockfilter.*` or `sp_tweaks.*` on the hot store refuses to open
  until those directories are moved next to seqsigwit.


- **`NODE_COMPACT_FILTERS` waits for the filters.** With
  `--block-filter-index`, the node advertises compact filters only once
  its filters first reach the tip, logging `blockfilter: caught up …`.
  Before, it advertised from startup and answered filter requests past
  its progress with silence while the first build ran. `getnetworkinfo`
  now names `COMPACT_FILTERS` in `localservicesnames`.


- **Master coverage JSON lists each production crate.** The Shields badge
  stays the workspace total. `badges/coverage.json` also records per-crate
  lines hit and found from that same run.


- **Coverage LCOV floor 93%:** production `LH*100 >= LF*93` (was 92%). Green
  master has stayed above that gate since 2026-10-06; `e3a8eb25` is 93.32%
  (150469/161235). Still no never-falls ratchet.


- **Workspace tests no longer sleep the two-minute `waitforblock` cap.**
  The journey uses a short deadline and still returns the tip. The numeric
  cap stays a unit test. Live P2P journeys in one process may overlap;
  each script stage registers its thread and wakes with the others.


- **Electrum subscription cap is 10000 per connection and configurable**
  (`--electrum-max-subs N`, conf `electrum_max_subs=`, NixOS
  `services.rbitcoin.electrum.maxSubs`). The old fixed 1000 refused an
  ordinary Sparrow wallet mid-sync (`too many scripthash subscriptions`),
  because a wallet subscribes every receive and change address up to its gap
  limit. Per-event costs that grew with the subscription count are gone: a
  mempool accept probes the subscription set with the tx's scripthashes; a new
  block builds its touch set once (`Query::block_touch`) instead of reloading
  the block and its prevouts per subscribed hash; requests move the sub sets
  instead of cloning them; and unsubscribe drops its last-sent status exactly.
  A reorg (or a tick gap > 32) still restatuses every subscription in full.


- **A full RPC work queue answers HTTP 503 before the handler runs.**
  The body is `Work queue depth exceeded`. The call is not paused.


- **`estimatesmartfee` returns Core's result shape.** With an estimate:
  `{feerate, blocks}`. Without one: `{errors: ["Insufficient data or no
  feerate found"], blocks}` and no `feerate`, instead of `feerate: -1`.
  The extra `errors: null` and `rbitcoin_model` keys are gone.
  Like Core, `feerate` is at least `mempoolminfee`, so a full mempool
  never gets a rate it would evict.


- **Fee history survives restarts and is blended with live flow by
  fullness.** The quote is `(1−α)·cold + α·warm`. α is decayed admitted
  weight divided by about 1.44M WU (one block every 10 minutes, held in
  a 150s half-life), clamped to 1. A quiet stretch decays α back toward
  history. A missing warm side stays on history. Flow with no history
  answers only at α = 1. The 1-block confirm-memory floor applies only
  on the warm side. Historical windows still have to look like the
  recent blocks, so an old fee spike does not hold estimates up for
  months. Far history uses the 95% quantile, interpolated in log-rate
  between hurdles. Flow confidence stays 99.9% at one block and 99%
  farther out. A target without an answer is insufficient data. The
  history is a snapshot plus a per-block journal in the mempool directory.

- **Block fee history is read from `txstat`, not from this pool's own
  transactions.** When relay turns on, the node walks back from the tip
  through at most 1 GiB of `txstat` rows (fee and weight only; no spent
  data and no tx bodies). Each block's sample is the vsize-weighted p10
  of individual transaction rates at or above min relay. A block counts
  even if this node never saw its transactions.


- **Esplora fee answers keep the estimator's precision.** `/fee-estimates`
  serves sat/vB to 0.001 (whole sat/kvB) instead of rounding to 0.1.
- **Esplora no longer serves `/fees/recommended` or
  `/v1/fees/recommended` (404).** Those are mempool.space's backend API
  (`/api/v1/`), not Esplora's. Use `/fee-estimates`, or mempool's backend
  in front of rbitcoin.
- **Esplora no longer invents a 1 sat/vB fee.** `/fee-estimates` leaves
  out targets the estimator cannot answer and returns **503** `fee
  estimates unavailable` when none has an answer. Electrum `blockchain.estimatefee` keeps the protocol's `-1`.


- Header look-ahead and the download-queue refill use one peer, the
  lowest time to a first block byte among peers that have not failed the
  walk. Other peers download blocks. A short reply that does not extend
  the candidate moves that reservation. A block announcement from another
  peer is one challenge: the reservation moves only when the reply beats
  the candidate. One missed header ask moves the reservation; a second
  miss disconnects. Less work does not disconnect.


- Header look-ahead keeps one tip, one hash lookup, and one rewind.
  `header.adopt` is the same file as before.
- Writing a header batch does not spend the ask window of a lane that is
  still waiting on its peer.


- During IBD a peer may have 64 blocks in flight, or 16 MiB of estimated
  block payload, whichever is reached first. The estimate is the median
  size of recent bodies, and 1 KiB until eight bodies have arrived, so
  early small blocks fill the count. The 1,024-block download window is
  unchanged.


- IBD makes a block eligible for another request when its last in-flight
  peer disconnects, reports `notfound`, or loses ownership to a faster peer.


- **Satisfied-block pruning judges each in-flight hash once.** The reader
  set is then replaced with that decision, so a confirm between two passes
  cannot leave the initial-block-download reader and the assign loop
  disagreeing about the next body.


- **Filters and tweaks share one builder while they are behind.**
  `rbtc-idx-wb` reads each window once (io_uring, IOCP, or the macOS
  pool) and builds both `--block-filter-index` and `--sp-tweaks` from
  it. Progress logs as `index: build`. Once the index is live, each new
  block is built on the script pool after script verification (one
  filter job; tweak ranges of at most 32 transactions) and appended on
  the confirm write. `NODE_COMPACT_FILTERS` is advertised when the
  filter watermark passes the tip (`blockfilter: caught up`, or
  `blockfilter: already at tip` when it already does).
- **A missing spent output is an error, not an ineligible tx.** Tweak
  computation used to skip a transaction whose spent output could not be
  found; it now reports store corruption.


- **Fee-flow buckets are a log grid from min relay through 1000 sat/vB.**
  About 100 steps per decade. A 0.26 sat/vB inflow quotes its own step
  instead of 0.2. Rates above 1000 sat/vB share one open bucket. The
  inclusion search reads one suffix sum of those buckets.


- Confirm lookup retires a fence-connected txid after each sealed head
  segment. An unconnected identity still searches later segments.
- Witness txid and sighash midstates are hashed from the block payload.
  BIP143 double-SHA is filled on first use. BIP341 keeps the single SHA-256.
- Lookup decodes the queued block frame in place. Load queue-depth bytes
  are the header, the transaction count, and each transaction's wire length.


- **Mempool expiry scans the oldest accepts first.** Each pass still visits
  at most 256 live transactions. The headers poll skips the pass when that
  index is busy, and still runs off the async worker.


- **Mempool accept decodes a confirmed parent once per coin lookup.** Resolving
  a spent coin reads the parent's packed outputs once; the fk resolve verifies
  `txid.body` only and coinbase-ness comes from the block's first tx, not a
  second decode of the parent's inputs. The `getblocktemplate` proposal check
  shares that lookup and re-reads the create's fence height before spending
  the cached output, so a disconnect during the check cannot price a coin
  that has left the best chain. A failed coinbase-table read leaves the
  mempool coin unavailable instead of treating it as a non-coinbase.


- Linux CI test binaries are capped at 6 GiB of address space (`RBTC_TEST_AS_MB`). A mutant that allocates without bound dies in that process instead of shutting down the hosted runner.
- The nightly mutants run is two 4 hour jobs again (8 hours total), starting at 00:47 UTC (17:47 Pacific during PDT). Each job still stops itself with 30 minutes of slack under the 6 hour hosted-job cap. The second job does not open another new-mutant window.


- Mutants are a nightly workspace run, not a pull-request check. New
  code is first in the queue, then a cursor walks older mutants. A
  `MISSED` line is an artifact. It does not fail the night or the PR.


- The nightly mutants job examines one source file per invocation, so
  struct-field deletes are not retested across the whole workspace.
  The checked-in mutants snapshot is gone; the night's artifact is the
  miss list.


- Nightly mutants skip `rbitcoin-bench`. It is an optional host client, not a test gate. `#[mutants::skip]` marks an expression that cargo-mutants will not report as missed.



- The nightly mutants run starts at 00:47 UTC (17:47 Pacific during PDT) and keeps going for 8 hours, as two jobs so a hosted runner stays under its 6 hour cap. While new mutants and backlog mutants both remain, new batches stop once half of that job's budget has elapsed and the rest of the job walks the backlog. The second job does not open another new window after that half is used. Time the new queue does not use goes to the backlog.
- The backlog cursor and `MISSED` lines are stored on the `mutants-state` branch, so they outlive the 14-day artifact. A failed push of that branch fails the run. `MISSED` does not.


- Tests pin the index write-behind caught-up height, a resumed build
  span, a short one-window tail, and that a pass held across the progress
  interval logs the later window, and the header checkpoint an empty
  rewind returns to.


- **Contributor docs keep one owner per fact.** `AGENTS.md` points at the owner. Structure witnesses stay in `docs/consensus-tests.md`. The Hornet checklist cites those rows.


- **A rejected peer transaction is one info line.** The line keeps the
  Core `was not accepted` sentence and the `txrelay: reject` tag. The
  extra debug line is gone.


- **IBD and tip perf lines are one JSON object.** DEBUG `ibd: perf`,
  `tip: perf`, and `tip: accept` each print a timestamped JSON object
  (`ts` is unix milliseconds, zeros included) instead of hand-written
  tokens. `ibd: sizes` and `ibd: perf_dbg` are gone; those counters are
  fields on the `ibd: perf` object. `ibd: progress` and `tip: best` are
  unchanged. A full IBD is every `ibd: perf` line in a debug log.


- IBD parent pin no longer reads `input.loc` once per parent.
  `txstat` fees are the ones assemble already checked, so connect
  does not walk prevouts again to stamp them.


- A held or pending block of exactly 4,000,000 bytes is parked; one byte
  over is refused. The cap is the block count. Mempool meta is fsynced on
  the meta file.


- **`getblocktemplate` proposal mode prices the coinbase.** A proposal whose
  coinbase pays more than the block subsidy plus fees is rejected as
  `bad-cb-amount`, after the structure checks, as Bitcoin Core's
  `TestBlockValidity` does. The check now lives on `ChainHub`
  (`check_block_proposal`, returning the fee total) so other front ends
  such as the SV2 template provider run the same code as the RPC.


- **Packed body decodes are counted at the decode site.** The counter the
  mempool and block-proposal pins read sits on the tx table's outs decoder, so
  every per-fk decode is seen; the confirm write stage's full decoder is not
  counted.
- **Txid and spender resolution no longer decode the body.** Resolving a txid
  to its row, probing whether an output is spent, and recording a spend read
  the `txid.body` identity only; the packed decode runs only for a reader that
  needs the record.
- **A block proposal keeps only the parent outputs it spends.** The check
  resolves each confirmed parent on the connected chain, decodes it once, and
  holds only the spent outputs until it returns; a row that exists only in a
  reorged-out block is not an input.


- **A block proposal decodes each confirmed parent once.** `getblocktemplate`
  proposal mode resolves a fan-out parent's fk once and decodes its packed
  outputs once per check, not once per spending input.


- Ship-version PRs now run overlay functional and the Warnet example
  alongside Core functional, and `release-extra` fails unless all three
  succeed.


- **`getnetworkinfo.version` is `190000`.** That is Bitcoin Core 0.19.0's
  client integer, so typed RPC clients take the modern response path.
  `bitcoincore-rpc` `get_blockchain_info` otherwise requires the
  pre-0.19 `bip9_softforks` map and fails on our object. The rbitcoin
  semver stays in `subversion`. `protocolversion` stays `70016`.


- **rust-bitcoin gaps are grouped as an upstream queue.** `docs/rust-bitcoin-limitations.md` lists the bitcoin 0.32.102 workarounds by who they hit. Three false-reject bugs are filed (RB-004, RB-015, RB-019). The rest of that queue is not.


- `getblocktemplate` and the SV2 Template Provider select transactions as
  the mempool's own shared bodies instead of copying every selected
  transaction on each call.


- **Store open unlinks `scripthash.runs` leftovers except `SEAL`.** The
  sorted-run writer and header parser are gone. Tip materialize does not
  write those files. A missing runs directory still opens. Open fails if a
  leftover cannot be read or removed. Resume a cancelled scripthash
  materialize from `scripthash.unsorted` or `scripthash.cold_progress`.


- During IBD, confirm does not flush spend annotations or the Class A
  bodies replay reads. `rbtc-spend-sync` syncs those files about every
  10 minutes and records that pre-sync snapshot in `spend_durable`.
  Shutdown does one sync at the latest snapshot before the tip flush.
- Opening a store with no `spend_durable` file revalidates and replays
  spends from genesis. A present file is the cursor open rechecks above.
  A cookie inside a data file, or a clean page cache, is not that cursor.


- Spend annotation replay logs height progress every 10 seconds.


- **`--sp-tweaks` and `--prune-seqsigwit` are refused together.** Tweaks
  read input public keys from scriptSig and witness data, which pruning
  drops. The node now refuses the pair at startup, refuses to enable
  pruning while tweaks are on (and tweaks on a datadir that was pruned),
  and a pruned node answers tweak requests with an error instead of
  computing them from data it claims not to keep.


- Confirm write reuses the spentness scratch across blocks in a batch
  and passes those annotate slots through without copying them into a
  second edge list.


- Linux CI and nightly mutants run test binaries with a private `TMPDIR`
  on `/dev/shm` (`scripts/tmpfs-test-runner.sh`). Store fsyncs no longer
  dominate suite wall time. The two `sp_tweaks` u32-roll tests no longer
  allocate 4–5 GB of disk each.


- Confirm stamps txstat size from the lookup precompute instead of walking
  each transaction again on the write thread.
- New `header.body` rows are 88 bytes. Opening a schema 24 or 25 store strips
  the old size/weight tail. Block size and weight are summed from txstat.


- **Wire confirm encodes scriptSig and witness once.** The write plan no
  longer keeps a second copy. Commit writes those bytes from the wire
  transaction and the spend edges. A records row that arrives with no inputs
  is still corrupt.
- **Script checks borrow spent scriptPubKey bytes.** Same-block spends read
  the wire block on the job. Historical spends read the parent pin. Taproot
  sighash hashes those borrows and does not build a second output.
- **Pruned nodes keep confirmed inputs from the wire transaction.** Connect
  serves the seqsigwit RAM window from that commit cache instead of reading
  each transaction back.


- Confirm write collects each block's spend absolute offsets once, reuses
  the structural scratch and the in-batch double-spend set, and looks up
  create heights by foreign-key span when every block in the batch is
  contiguous. The tip event carries the wire header already validated on
  the write path.

### Added


- Nightly fuzz compares script verification and chain-review shapes with
  Bitcoin Core: policy and pre-activation flag words in-process, and hub
  submits for milestone, genesis, BIP30, maturity, BIP68, mutation, and
  reorg respend.


- Nightly fuzz executes a structured script grammar. Our verifier has a
  100 ms thread-CPU budget, confirmed by a second sample. Seeds come from
  Core `script_tests.json` or the committed fixture when that file is
  absent. A same-hash mutant is replayed as the honest block only after
  both sides reject it. A full compact reconstruct follows the honest body
  through `drain_pending_now` and scores that body against Core without
  invalidating the hash first. P2P sequences are tagged steps. Tx compares
  on the hub mempool. Empty getheaders, feefilter, and inv are not Core
  comparisons; a local drop on feefilter or inv fails the input. Sunday
  runs block-spend under ASan with a 90 s input timeout. `store_reorg`
  drops its hub and reopens the same datadir once per input. The tip hash
  must match. It does not ask Core.


- **Health probes.** `--health-listen [ADDR]` (default `127.0.0.1:9332`)
  binds before the store opens and serves `GET /healthz` (200 in every
  phase) and `GET /readyz` (200 once the node follows the tip with every
  configured listener up, the tip within 6 blocks of the best header, the
  tip fresher than `--max-tip-age`, and the scripthash index within 6
  blocks of the tip; otherwise 503 with the reason). The stale-tip check
  does not latch like `initialblockdownload`, so a node that loses every
  peer after IBD goes unready. RPC, Electrum, and Esplora bind only after
  catch-up, so a probe on those would restart a node in the middle of a
  migration or IBD.
- **Prometheus metrics.** `--metrics` adds `GET /metrics` on the health
  listener. Gauges equal their RPC fields (`blocks`, `headers`,
  `initialblockdownload`, connections, mempool size). Counters are the
  `tip: perf` meters (Esplora and Electrum requests, historical block
  serves, mempool accepts and rejects), which now count up for the life
  of the process; the 5 s DEBUG line still prints the change since the
  previous line.


- **More Prometheus gauges.** `/metrics` also exposes verification progress,
  tip age, difficulty, peer counts by network, outbound time offset, P2P
  byte totals, and mempool min fee (sat/vB), weight cap, orphans, and
  unbroadcast count. Fee rates on this scrape are sat/vB. The Core RPC
  fields stay BTC/kvB.
- **NixOS health and metrics.** `services.rbitcoin.health.enable` passes
  `--health-listen` (default `127.0.0.1:9332`). `services.rbitcoin.metrics`
  passes `--metrics` and adds a Prometheus scrape job when
  `services.prometheus.enable` is set.


- **`GET /progress` on the health listener.** JSON for the long stage
  running now (`tx.head` rebuild and tail backfill and input backfill
  while the store opens; the scripthash index build passes while
  indexing; the block filter and silent payment tweak index builds,
  each counted in heights): `phase`, `stage`, `done`, `total`, `percent`,
  `elapsed_secs`, and a linear `eta_secs`, plus `finished` for the stage
  that ended last, at any `--log-level`. `--metrics` exports
  `rbitcoin_progress_done` / `_target` / `_start_time_seconds` with a
  `stage` label. `/readyz` is unchanged. The `tx.head` rebuild now counts
  each sealed range as it lands; its INFO line still prints only at the
  end.


- **Initial block download can see the header chain before those blocks are downloaded.** The 64,000-block download queue stays full. Headers past it are checkpoints in `header.adopt` (hash, height, total work, the last header of each reply, and the difficulty period at that hash), not rows in `header.body`. One competing chain is kept the same way until its work passes the candidate, including when that takes more than one reply. An explicit `--milestone HEIGHT` skips scripts by height. The default mainnet milestone skips only when the header path has block 840,000's hash at that height, this block is the path hash at its own height, and chain work meets the minimum. A short refill that continues the queue is stored. A short reply on a proven walk already above the work floor is not. A chain that dies before the floor is abandoned. A heavier chain replaces the checkpoints, including one that forks from a header already stored between checkpoints, and one that forks from a confirmed ancestor while that ancestor is still below `-minimumchainwork`. Script skip follows the chain that wins. A peer that delivers more than 4,000 stored headers off the download path, below the work floor, is disconnected. A look-ahead that breaks the proof-of-work rules disconnects that peer. `header.adopt` records the block the checkpoints were built on; a restart ignores the file when that height has a different hash, and a reorg below it deletes the file. An older `header.adopt` does not parse, so its checkpoints are not restored. Queued headers that link from the confirmed tip are still noted, and that can turn script skip back on.


- **Core cookie auth on TCP RPC:** `--rpc-cookie-file PATH` (conf
  `rpc_cookie_file=`, NixOS `services.rbitcoin.rpc.cookieFile`) accepts an
  existing Core-format `username:password` file as HTTP Basic on the TCP
  listener, alongside the Bearer token, so stock mempool `CORE_RPC.COOKIE`
  authenticates without a patch; the unix-socket `socketPath` patch is now
  optional. The node never creates the file. It must have no trailing
  newline (mempool sends the raw bytes, so one would 401 forever) and needs
  `--rpc-listen`; either mistake fails the launch. The TCP 401 challenge is
  `Basic` when a cookie is configured, `Bearer` otherwise.
- **Core-shaped confirmed transaction JSON:** confirmed verbose
  `getrawtransaction` adds `confirmations`, `blockhash`, `blocktime`, and
  `time`. This also fixes the coinbase input in `getrawtransaction` /
  `decoderawtransaction` / `getblock` verbosity 2: it is now
  `{"coinbase": <hex>, "sequence": n}` (plus `n`) instead of a
  `txid`/`vout` pair that never existed. mempool needs both to index
  blocks.
- **No panic reading a table during disconnect:** `ArrayTable::get`
  checked the length before taking its read lock, so a concurrent
  truncate (block disconnect) could panic a reader such as an RPC
  `header_at_height` lookup. It now re-checks under the lock and reads
  the shorter table.


- **`--rpc-socket PATH` (conf `rpc_socket=`).** Binds the unix JSON-RPC
  socket at PATH with mode 0660 instead of `{datadir}/rpc.sock` (0600).
  A client running as another user in rbitcoin's group, such as
  mempool's Node, can connect without reaching into the 0700 datadir.
  Implies `--rpc`. `rbitcoin-cli --rpc-socket PATH` talks to it.
  NixOS: `services.rbitcoin.rpc.socketPath` (directory created 0750).


- **Stratum v2 Template Provider.** `--sv2-tp-listen ADDR` serves the
  SV2 Template Distribution Protocol over Noise. A JDC or pool gets a
  template on every tip, can fetch its transactions, and can submit a
  solved block, which the node accepts like any other block.
  `--sv2-tp-authority-sec-file` (or `--sv2-tp-authority-sec`) sets the
  signing key. `--sv2-tp-cert-validity` and `--sv2-tp-stale-grace` tune
  the certificates and old-tip templates. NixOS:
  `services.rbitcoin.sv2.tp.*`. Default off.


- **SV2 TP build counters.** With `--sv2-tp-listen`, `/metrics` exports
  `rbitcoin_sv2_fee_checks_total`, `rbitcoin_sv2_template_builds_total`,
  and `rbitcoin_sv2_template_build_seconds_total`, and the DEBUG
  `tip: perf` JSON gains `sv2_checks`, `sv2_builds`, `sv2_build_avg_us`,
  and `sv2_build_max_us`.


- **SV2 TP fee-gain templates.** With the tip unchanged, a session gets a
  new template once its fees gain `--sv2-tp-fee-delta` sats (default
  1000) over the last one sent, checked every
  `--sv2-tp-template-interval` seconds (default 5). NixOS:
  `services.rbitcoin.sv2.tp.{feeDelta,templateInterval}`.


- **Wallet and Lightning backend guide.** `docs/wallets.md` lists which
  wallets speak Electrum, Esplora, or the RPC cookie, including Wasabi's
  full-node path. `docs/lightning.md` covers CLN, ldk-node, and LND
  `rpcpolling` versus Neutrino and ZMQ.


### Removed


- **Esplora WebSocket (`/ws`, `/v1/ws`).** It copied mempool.space's
  `/api/v1/ws`, which is mempool's backend surface; Esplora and electrs
  have no WebSocket. Both paths now 404. Watch wallets over Electrum
  subscriptions, or run mempool's backend in front of this Esplora.
  `EsploraConfig` drops the `max_ws_*` / `max_track_*` caps and
  `run_esplora` drops its tip-broadcast argument.


### Security


- **A lost spend-edge tail is no longer spendable after restart.** If the
  parent-edge bytes for confirmed outputs are short or zeroed, reopen does
  not publish those outputs as unspent. The tip moves back past the first
  such output, or the node refuses to start. A checkpoint that saw a
  disconnect does not publish through the replacement block at that height.
- **A peer that never reads cannot pin compact-block transaction serving.**
  `getblocktxn` waits on the same send budget as other served blocks, and
  `blocktxn` is charged by its real size. The reconstruct runs off the
  peer task.
- **Mempool eviction drops the relay indexes with the transaction.** Fee
  and slot-table eviction, expiry past a run of already-removed entries,
  and a rolled-back package or one-parent package clear the scripthash,
  expiry, and wtxid maps for every transaction that left, including one
  the rolled-back member had evicted. A prioritisation delta stays until
  the transaction is mined, including when it had already left the mempool
  and when relay is still off. A reorg removes a parent and its children
  before a template can select the child. A coin that is spent while its
  script is checked is not admitted. That recheck reads the coin before
  taking the mempool write lock, unless a block connect or disconnect is
  changing spentness.
- **Bad compact blocks and oversized transaction counts are refused before
  the expensive work.** Once the tip meets minimum chain work, a
  `cmpctblock` with bad proof of work is scored like a bad block. It does
  not scan the mempool or update that peer's header state. A `tx`,
  `block`, `cmpctblock`, or `blocktxn` whose witness count cannot fit in
  the payload is misbehavior. Those four relay messages are walked twice
  — inputs, outputs, and witnesses — before `consensus_decode`. IBD block
  frames skip that pre-walk. `merkleblock` is ignored.
- **Electrum mempool status no longer runs on the connection.** With
  Electrum enabled, a mempool payment or replacement of a subscribed
  scripthash still pushes the new status, and the history join is off the
  session task.


- A fuse8 segment length that is not a power of two is rejected as corrupt.
- A var-table or create.loc read past the published end is corrupt.
- Dropping an undrained io_uring session fails closed instead of freeing
  buffers a completion may still own. The drain hard cap is unchanged.
- A sorted-run manifest or txstat blob longer than the file is corrupt
  and is not allocated.
- The datadir `.lock` is created mode 0600 and is not followed if it is
  a symlink.
- Pool write jobs read the caller buffer through a shared slice.
- Findings write-ups: 067, 068, 069, 070, 071, 072.


- Omitted `--milestone` on testnet checks every script. An explicit
  `--milestone HEIGHT` stays height-only, and omitted mainnet stays
  anchored. NixOS `services.rbitcoin.milestone` passes the flag when set.
- An empty median-time window is an error. A height-0 BIP68 time lock
  uses the genesis median.
- The version nonce comes from the CSPRNG. The recent-reject set and the
  invalid-hash set stop at 4096 entries instead of clearing.
- Mempool expiry walks at most 256 entries per call and also runs on the
  headers poll, so a quiet pool still expires.
- A tip-follow pending block or held body larger than 4,000,000 bytes is
  not parked. One peer's orphans stay within that peer's reserve.
- `StoreSecret` and RPC auth debug output is redacted. `store.secret`
  and the API log are created mode 0600. A Tor control password that
  contains CR, LF, or NUL is refused, and passing it on the command
  line warns once. A conf error names the file and line and does not
  echo the raw line. A group- or world-readable RPC cookie warns once.
- Findings write-ups: 073, 074, 075, 076, 077, 078, 079, 080, 081, 082, 083.


- Thanks to Stephan Livera for the 2026-10-02 review of P2P resource
  accounting, inbound eviction, REST, and silent-payment logging.
  Status board: docs/external_findings/052-livera-review-index.md.


- Inbound eviction keeps a share of the longest-connected peers and
  disconnects the newest peer in the largest netgroup. The netgroup is
  fixed when the peer is accepted.
- A misbehavior disconnect refuses that address for one day, in memory
  only. Rate-limit, oversize, and score-threshold exits record the same
  refusal. A loopback peer is disconnected and is not recorded, so one
  local failure does not block every other local connection. During
  initial download, that death cools the dial even after a block body. A
  netgroup that just lost an inbound slot waits ten minutes. The set
  does not grow past its cap.
- During initial download, only a block this node requested moves the
  stall clock or is queued. Other frames are rate-limited. Light
  decodes do not wait on the reader.
- Findings write-ups: 060, 061, 062.


- Cap the parent-request tracker per peer and process-wide. A full
  process-wide table skips the new announcement and does not disconnect
  the peer. Only a peer at its own cap is disconnected. A wtxid
  announcement is re-requested as a wtxid and does not change another
  peer's txid parent. While that request is in flight, the same hash is
  not asked again as a txid.
- Charge outbound getdata and tx announcements against the per-peer send
  budget, and stop serving blocks once that budget is already over.
- The per-peer rate window keeps the previous second so a boundary does
  not grant a second full budget.
- Count v2 decoy packets and unknown message types in the per-peer rate
  window on tip-follow and IBD. One decoy that does not fit adds the
  rate-limit score. The peer is disconnected at the same threshold as
  other frames.
- Batch mempool transaction announcements into one inv per thousand,
  still charged against the per-peer send budget.
- Findings write-ups: 053, 054, 055, 056, 057, 058, 059.


- `/rest/` on the RPC listener is off unless `--rest` or `rest=` is set.
  It uses its own queue, and the body is read before that permit is taken.
- A silent-payment subscribe scans at most the recent 256-block window,
  including when the client passes a start height. The scan stops when
  the client hangs up.
- RPC waits are capped at two minutes inside the handler, so a long-poll
  that hits the cap still returns a JSON-RPC body. The listener drops a
  new connection once 256 are open. A long-poll does not hold a
  work-queue slot.
- API logs strip `xprv` / `tprv` material and silent-payment scan secrets.
- Findings write-ups: 063, 064, 065, 066.

## [0.7.0] — 2026-09-18

Named published **0.7** line. **Not 1.0.** Patch branch is `v0.7.x`. Schema 24
is still bumpable (named refuse/wipe, no silent wipe). Occupied **0.6.x**
(schema 20) stores **refuse** — wipe the datadir and redo IBD. Default mainnet
`--milestone 840000` skips historical script/sig checks (`--milestone 0` is
full scripts). `--sh-index` default off. BIP324 v2-only. GitHub Release: Linux
musl (operator) + Windows CRT-static PE + Darwin aarch64.

### Highlights

- **Wipe 0.6.x stores:** schema **24** refuses occupied schema-20 Class A
  (`wipe datadir and redo IBD`). Do not open a populated 0.6.x datadir in
  place. Empty 0.6 indexes rewrite `meta`.
- **Faster IBD:** loc rides the InFlight pin (load never loc-by-fk); body-queue
  `header_fk` skips header ensure; tip+1 hole racing by drain time; sequential
  `header.body` size/weight; BIP30 same-txid across a load wave.
- **Smaller store:** schema 22 `create.loc` + `seqsigwit.loc` (no three Class A
  `*.idx`); compact txout amounts; sealed fuse8 + SH occupancy mmap (heap
  `fuse8=` / `mphf_occ=` only).
- **Mempool persist:** packed schema 2 — 5 s dirty tail, one-record DEAD
  `pwrite`, no full `tx.body` rewrite on block strip. Leftover schema 1
  converts on open.
- **Frigate silent payments:** Electrum `blockchain.silentpayments.subscribe`
  (session scan key) plus `--sp-tweaks` / `silentpayments.unsubscribe`.
- **Wallet protocols:** Electrum **1.6** (`broadcast_package`, `mempool.get_info`,
  `outpoint.*`) and **1.7** leftovers; cheap Esplora `/blocks` from stored
  size/weight (schema 24).
- **Operator CLI / RPC:** kebab-only (`--sh-index`, `--sp-tweaks`,
  `--rpc-listen`); TCP auth is Bearer `{datadir}/rpc.token` (no `--rpcuser` /
  `.cookie`).
- **Testing:** catalog journeys absorb leftover twins; Core functional `run` is
  production-only; live P2P IBD in default CI; production LCOV floor **92%**.
- **CRAP:** required `coverage` runs `cargo crap --fail-above 30` with a chewed
  allowlist (P2P / IBD / RPC / store extracts).
- **Windows:** positional IO on IOCP handles no longer heap-corrupts on
  seal-roll / query smoke.

### Added

- **Wallet-protocol leftovers:** Electrum **1.6** `blockchain.transaction.broadcast_package`
  (local `accept_package`) and `mempool.get_info`; `protocol_max` **1.6** with
  1.6 `block.headers` as a list. Electrum **1.7** `blockchain.outpoint.*`.
  Frigate `blockchain.silentpayments.subscribe` (session scan key). Esplora
  `/fees/recommended` (sat/vB). Parked (not now): Electrum TLS/Tor in-binary
  (**Q-63**), GBT longpoll/Sv2 (**Q-64**), BIP157 filters (**Q-65**).

- **Esplora cross-surface leftover HTTP:** `esplora_broadcast_visible_in_rpc_and_electrum`
  pins `/blocks` start past tip (clamps), `/block/:hash/txs` one-past last page
  as `[]` (not 404), plus `/txids`, coinbase merkle-proof, and unspent
  `outspend/0` on the mined tip.

### Fixed

- **IBD loc-hole EngineFault:** load stamp no longer treats a live InFlight
  pin + `create.loc` miss as `invariant: create.loc hole after count`.
  Rereading loc count after the miss raced Class A append (mainnet 369k /
  407k). Miss stays same-wave (write fill / late `set_loc`).

### Changed

- **IBD tip-hole race at large blocks:** only **tip+1** gets the 4-peer race;
  later contiguous fetch holes get one racer until the prefix is in hand.
  Racers rank by expected drain time (`(queue+1)/EWMA`), not inflight count, so
  a fast peer with leftover densify beats an idle slow peer. An owner whose
  FIFO is still on other getdata is dropped from the hole hash (ticks are not
  progress on that hash) so an empty/faster peer can race. Mainnet ~912k sat
  `hole=1` with `conf blks=0` while BQ grew far bodies.

- **Q-54 Won't-fix:** ast-grep named-cap rules. Caps stay in
  [`docs/ibd-memory.md`](docs/ibd-memory.md) and production evict.
  Pinning `const = 128` is a second clippy. **Q-51** already owns
  shapes.

- **Coverage LCOV floor 92%:** production `LH*100 >= LF*92` (was 91%). Master
  has held ~92.0–92.2% since 2026-09-16. Still no never-falls ratchet.

- **Catalog journeys absorb leftover twins:** mature confirm pins Class A then
  accept and `confirm_wire_run` double-spend; unified wire pins empty
  `confirm_wire_run`; Electrum TCP pins `id_from_pos` pos OOB and mempool
  verbose `transaction.get`; cross-surface pins mempool-child `listunspent`
  `height=-1`; CLI smoke refuses dropped Core `--rpcuser`/`--rpcport` names.
  Dispatch/crate twins of those contracts are gone.

- **Catalog journeys absorb remine-pad confirm extras:** `three_stage` pins
  header-plan BIP68 MTP, same-run create then spend, and 546-shaped 2-vout
  merge; `confirm_load_ahead_of_write_does_not_badprev` pins tip-GC store MTP;
  one `wire_prep_parent_layout_and_load_ahead` pad covers load-ahead parent
  fill, already-archived plan=None annotate, and cold Class A denserels.

- **Catalog journeys absorb resume / hub-reorg / Esplora HTTP leftovers:**
  mature reconstruct pins `resume_work_path_after_tip` Class A after
  disconnect; `reorg_same_height_then_multi_block_branch` pins competing-spend
  multi-list (not `multi-spender`); live `esplora_broadcast` pins block
  JSON/raw/status/txid, outspends, merkleblock-proof, and scripthash
  info/summary/utxo/chain pages. Crate Esplora tests keep no-hub mempool/fees
  and reconstruct meters.

- **Catalog journeys absorb Electrum dispatch / Esplora tip-404 leftovers:**
  TCP `electrum_server_version_history_balance` pins `CARGO_PKG_VERSION`,
  `protocol_min` / `asof_protocol` / `server_version`; crate TCP no-hub
  covers Cake `tweaks.subscribe [0,1,false]`, `estimatefee` `-1.0`, and
  empty histogram. Live `esplora_broadcast` pins `/block-height`,
  `/block/:hash/header`, and `/tx` status/JSON (unknown OP_TRUE type).
  Dispatch twins of those contracts are gone.

- **Catalog journeys absorb RPC remine generate / gettxout twins:**
  live `esplora_broadcast` pins generate parent-before-child order and
  `scantxoutset` dropping a spent coinbase. Crate leftover `gettxout`
  covers include_mempool hide/show; `generate_selects_chained_mempool_parent_first`
  keeps the 3-tx index + immature + scan needles on `pad_empty_from`.
  `submitpackage_child_fail_keeps_parent` stays a crate unit (LCOV; the live
  pad has no spare mature coinbase after generate).

- **Crate connect spend rejects share one fixture:**
  `header_and_spending_boundaries` remains the catalog pin for same-block
  double spend, child-before-parent, `in < out`, subsidy+1, and immature
  coinbase. Four remine `accept_and_connect_block` twins collapse into
  `accept_rejects_connect_spend_rules` (one store; LCOV). The same-block
  double-spend arm uses distinct txids (the #593 twin was two copies of
  one tx and failed as `duplicate txid`). Store-less
  `rejects_coinbase_excess_value_fast` stays next to `p1_block_subsidy_halvings`.

- **IBD plan allows BIP30 same-txid across headers in one wave:**
  `archive_plan_batch_from_wire` rejects duplicate txid only inside one
  block. Cross-header repeats (mainnet 91842/91880 vs 91812/91722) keep
  both Class A rows; `batch_map` binds spends to the later fk. A 144-block
  load wave that used to `Corrupt("duplicate txid in block body")` at the
  first height of the batch (logged `@91699`) can IBD past that era.

- **IBD stamp skips header ensure when BQ carries `header_fk`:** header-sync
  already stored the row. Load stamp uses the BQ fk/hash (store row must
  match); hash mismatch is `BadBlock`. `ibd: perf` `header_skip=`. Wire
  planner fills packed ins from the stamp edge walk. Empty ins at Class A
  commit is `Corrupt` (write does not refill from wire).

- **Confirm size/weight is a sequential `header.body` rewrite:** contiguous
  header-fk runs are one 96-byte-record write (`put_size_weight_run`), no
  insert `put_lock`. Header-sync insert still stores zeros. `set_size_weight`
  remains for query lazy-fill of leftover zeros.

- **IBD load stamp never `create.loc`:** TipOnly miss of an InFlight parent
  leaves spent unset. Later-wave spent is `CreatePin::set_loc` or write TLS
  (mainnet 133433). plan=None leftover still `fill_missing_parent_ranges`.

- **Class A loc rides on the InFlight `CreatePin` Arc:** write `set_loc`
  after append; later-wave stamp binds spent/body from the pin. IBD load
  never loc-by-fk. EngineFault stamp fail reoffers the full batch and does
  not `request_single_block` or rewind `lookup_taken_hi` (the 352k Cascade
  isolate crawl).

- **RPC tip wait is one in-flight accept:** `getblockcount` /
  `getbestblockhash` / `wait_height` wait for the tip-accept job that was
  running when the call arrived (a queued follow-on connect may still be
  in flight). Unstable `RBITCOIN_RPC_WAIT_TIP_IDLE=1` restores lane-empty
  wait; the Core-functional bitcoind shim sets it. Not a production knob.

- **Stop paying Core harness in production:** P2P logs use a `p2p:` prefix;
  `debuglog_map.toml` is the Core debug.log dialect. TCP RPC is Bearer-only
  (the test proxy still accepts TestNode Basic and forwards Bearer). Named
  `args` peel is `echo` only on the node; the functional proxy expands
  AuthServiceProxy mixed `{args: […], maxfeerate: …}` into a positional list
  before forwarding. Hidden `getorphantxs` stays (operator dump of
  parked txs + announcer peer ids; `rpc_orphans.py` is `run`).
  `estimaterawfee` is the native 10-minute object (no fake Core
  `short`/`decay` tree). `NodeError::Init` carries exit 1 and the `Error:`
  prefix (**Q-66**). `getblockstats` reconstruct miss is
  `block body not in store` (shim still maps dummy `blk00000.dat` absence
  to Core's disk phrase). In-tree TCP tests send Bearer. Labeled
  `test_runner` prints **72** jobs (**66** inventory `run`; **201** skip).
  `echo` stays.

- **P2P shutdown waits a short grace** before aborting session tasks so a
  still-running P2P job cannot use the store after drop. Lingering tasks
  are still aborted (bounded). CI `rpc_invalidateblock` stop SIGSEGV.

- **Core functional `run` is production-only:** skip scripts whose asserts
  were only the bitcoind shim (`feature_help`, `feature_blocksdir`,
  `feature_dirsymlinks`, `feature_filelock`, `tool_rpcauth`) or Core
  decode/`validateaddress` dialect the node does not ship
  (`rpc_decodescript`, `rpc_invalid_address_message`). Live proxy no longer
  intercepts `decoderawtransaction` / `decodescript` / `validateaddress`.
  `feature_filelock.py` stays skip (`harness`). Labeled `test_runner` prints
  **72** jobs (**66** inventory `run`; Core expands transport twins and
  `wallet_txn_*` flags; **201** skip).

- **Sealed fuse8 mmap + no retained `open_keys`:** lookup maps every sealed
  `.fuse8` fingerprint array read-only (`fuse8=` heap **0** after
  `write_then_map` / `open_file`). Open OA is keyless; the seal sidecar
  collects keys from `txid.body` (crash-reopen still collects on open).
  Kernel reclaim of idle fuse is drop of file pages, not swap. Packed MPHF
  `g` stays FdOnly (mapped miss is one fault per lookup thread; `KIND_MPHF_G`
  keeps 128 pages in flight). `strong_tx` and mempool stay process `Vec`.
  `ibd: sizes` / `tip: perf` `fuse8=` is heap only; mapped fuse RSS is
  `file=`. After IBD, leftover `anon − accounted` can be mimalloc arenas
  (`free` ≠ `munmap`); optional operator `MIMALLOC_PURGE_DELAY=0`. Do not
  `malloc_trim` a mimalloc process. PR `windows` / `macos` smoke maps a
  sealed `.fuse8` and confirms a few blocks (`connect_chain_query_surface` /
  spend-edge).

- **SH BDZ3 occupancy mmap:** compact `read_compact_from` maps the
  `NN.mphf` prefix through occ (not tags). Rank popcounts mapped bytes
  (`HEADER+g` is not 8-aligned). Heap after open is the superblock table
  (`mphf_occ=`); packed `g` stays FdOnly. Windows/macOS smoke runs the
  compact packed-fd roundtrip.

- **Windows positional IO on IOCP handles:** `IoHandle` pread/pwrite sets the
  low bit of `OVERLAPPED.hEvent` so the packet is not queued to the completion
  port. A stack OVERLAPPED on a bound handle was harvested with `Box::from_raw`
  (`STATUS_HEAP_CORRUPTION` on seal-roll and query confirm smoke). A failed
  IOCP `push_*` (handle already bound to another thread's port) rolls back
  session pending so SH collect libc-completes instead of drain-hanging.
  A failed pending rollback poisons the session. The positional wait event
  is closed when the thread exits.
  Sealed `.mphf` is synced at write; `flush` only `sync_data`s the mutable
  `.val` (Windows `FlushFileBuffers` on a read-only handle is Access denied).

- **Mempool packed incremental persist (schema 2):** admits dirty RAM only;
  `persist_due` every 5 s writes the body tail then slots+meta (no fsync).
  Shutdown `flush` still fsyncs. DEAD of a durable slot is a one-record
  `pwrite`. Packed live records store fee/weight/txid/wtxid, a Class A–style
  packed tx, and per-vin `script_hash` / optional `create_fk`. Load uses stored
  hashes and one `Arc<Transaction>`. SH reindex and tip-entry purge batch
  Class A instead of per-vin `get_txout` / `chain_prevout`. Leftover schema 1
  converts to packed on open (vin aux empty; SH reindex batch-fills). Packed
  size is not promised smaller than bitcoin serialize (vin aux adds bytes).
  The 5 s path appends the body tail and `pwrite`s only new LIVE slot records
  (full slot table still on flush/grow/compact).

- **Same-peer compact retry:** a second `cmpctblock` for a hash already in
  `pending_cmpct` does not take another BIP152 fill slot or send a second
  `getblocktxn`. Two inbound peers can still fill the same hash.

- **Class A does not annotate spends:** Tip used to `put_spend_batch` (per-vin
  `tx.head` + spent RMW) and then confirm `post_commit` annotated the same
  slots. Direct already skipped that. Both modes now share the confirm abs-meta
  path only (`arch_write_spend_ns == 0`). `Query::confirm_block` (fixture
  `connect_block`) annotates after Class C the same way.

- **Wire plan trusts lookup parent loc:** `finish_archive_plan` no longer
  inserts `ParentIdent::new` / `fill_missing_parent_ranges` after
  `stamp_external_parents` already bound body+spent. `fill_missing_n` counts
  actual loc batches, not empty walks.

- **CRAP chew (P2P/IBD/scripts/tweaks):** drop allowlist entries for
  `on_block`, `on_blocktxn`, `on_tx_announce`, `need_any_valid_body_download`,
  `plant_valid_tip_child`, `rehydrate_class_a_into_body_queue`,
  `drive_script_waves_with`, and `serve_tweaks_subscribe` after extracts
  (block/cmpct accept, announce fee-gate, IBD need/plant/rehydrate, script
  wave start/drain, tweaks subscribe waves).

- **CRAP chew (confirm/chain/peer):** drop allowlist entries for
  `handle_peer_frame`, `ChainHub::accept_branch_inner`,
  `Query::resume_work_path_after_tip_excluding`, `assemble_block_prevouts`,
  `structural_validate_spends`, and `on_cmpctblock` after extracts (peer
  decode vs sync match, branch precheck/connect, resume index/walk,
  assemble non-cb inputs, structural meta/pending/BIP68, compact reconstruct).

- **CRAP chew (RPC/CLI/store/lookup):** drop allowlist entries for `method_help`,
  `operator_config_from_args`, `apply_peer_event`,
  `ScriptHashTable::apply_head_upserts`, `Store::open_layout`, and
  `wire_lookup_phase` after coverage pins and extracts (RPC help arms, conf/log
  argv, peer-event match, SH home upserts, open-layout migrate/leftovers,
  lookup contiguous/bind).

- **Tip-mode mempool purge after catch-up drops conflicts and persists DEAD:**
  leftover txs whose inputs were spent by a different confirmed txid are
  evicted at `set_relay_enabled(true)`, and slot deaths are written even when
  compact does not fire. Same-txid confirmed leftovers still drop; a child of
  a now-confirmed parent stays. `analog_milestone_and_mempool_persist` pins
  restart → catch-up → relay-on.

- **Mempool block strip no longer dumps `tx.body`:** DEAD marks persist
  slots+meta once (`persist_if_dirty`) instead of rewriting the whole sidecar
  every 32 deaths. That was `mp_strip=` 5–8s on a ~70k pool (thousands of
  full-file writes per block). Admits still coalesce body writes at 32.

- **Electrum verbose `transaction.get` matches electrs timestamps:** confirmed
  verbose objects include `time`/`blocktime`/`confirmations`/`blockhash` plus
  `vin`/`vout`/`size`/`version`/`locktime`/`hash`. Mempool verbose is
  `confirmations: 0` with no block stamp. `id_from_pos` third arg `merkle=true`
  returns `{tx_hash, merkle}`. Cake was dating confirmed txs as today because
  `{hex,txid}` is a non-empty map without `time`.

- **CRAP chew (getdata/store/asmap):** drop allowlist entries for
  `serve_getdata`, `Store::check_confirmed_height`, `assemble_run`,
  `Query::join_spends_wave`, `ScriptHashTable::unlink_create`,
  `SegmentedTxHead::probe_candidates_batch_wave`,
  `ChainHub::reconsider_block_inner`, and `sanity_check_bits` after coverage
  pins and extracts (getdata block/compact/wtx, header-tx range, assemble
  MTP/bits, spend-join fks, unlink home write, probe unsealed/sealed waves,
  asmap opcode helpers, invalidated-path take).

- **Rust-style CLI, default RPC ports, and token auth:** operator flags are
  two-dash kebab (`--rpc-listen`, `--rpc-url`); short flags are `-h`/`-V` only.
  `--shindex` / `--sptweaks` are `--sh-index` / `--sp-tweaks`. JSON-RPC is
  `--rpc` (`{datadir}/rpc.sock`) and optional `--rpc-listen` (default
  `127.0.0.1` and Core-matching 8332/18332/38332/18443). TCP auth is Bearer
  `{datadir}/rpc.token`; `--rpcuser` / `--rpcpassword` / `.cookie` are gone.
  `rbitcoin-cli` uses `--datadir` / `--network` / `--rpc-url` /
  `--rpc-token-file`. The functional shim still writes Core `.cookie` from
  the token. [`OPERATOR.md`](OPERATOR.md), [`docs/rpc.md`](docs/rpc.md).

- **No concatenated `rbitcoin-node` aliases:** kebab CLI / snake_case conf only
  (`--prefill-compact` / `prefill_compact=`). Concatenated Core spellings
  (`--prefillcompact`, `--minrelaytxfee`, `--rpcworkqueue`, …) are unknown.
  The functional shim still maps Core names.

- **Fee estimates hold the last defined rate into far depths:** when the
  pool is thinner than N blocks and block-p10 history is empty, 144/504/1008
  keep the faded mid rate instead of Esplora `1.0` (insufficient sentinel).
  Empty pool is still `-1` / `1.0`.

- **CRAP chew (WS/RPC/script):** drop allowlist entries for
  `cheap_submit_tx_reject`, `getnodeaddresses`, `handle_client_msg`,
  `parse_client_msg`, `backfill_sp_tweaks_cancellable`, `checksig_legacy`,
  `confirm_write_phase`, `BinaryFuse8::try_from_keys`, and `run_all_script_rows`
  (exclude `core_vectors.rs` — `#![cfg(test)]` fixture runner). Coverage pins
  plus extracts (`parse_*_track`, CHECKSIG encodings, already-committed write,
  archive-plan commit, fuse8 geometry/peel).

- **CRAP chew (next 8):** drop allowlist entries for `TxTable::backfill_head_from`,
  `scripthash_index_data_present`, `Store::revalidate_tip_window_n`,
  `Query::load_thin_tweaks_range`, `op_checkmultisig`,
  `validate_block_structure_with_pres`, `read_proc_rss`, and `getblock`
  after coverage pins and small extracts (`HeightPlan`, checkmultisig match
  loop, block tx layout, `/proc` RSS parsers, `getblock` unknown-hash).
  `StrongTxTable::count_ones_bits` stays allowlisted (file-backed walk is
  unused while the bit image stays L2).

- **CRAP chew (10 easiest):** drop allowlist entries for `stamp_external_parents`,
  `gbt_proposal_connect`, `gbt_chain_txout`, `header_head_occupied`,
  `ConfirmStats::miss_on_from_code`, `ConfirmRejectClass::from_net`,
  `prevout_from_block_or_query`, `force_announce_txid`,
  `ScriptHashTable::publish_sorted_shard`, and `bit_is_active` after coverage
  pins (and a stamp in-flight extract) put each ≤30.

- **Operator CLI kebab + conf snake_case:** leftover concatenated Core spellings
  (`--prefillcompact`, `--minrelaytxfee`, `--rpcworkqueue`, …) are advertised as
  kebab (`--prefill-compact`, `--min-relay-tx-fee`, `--rpc-work-queue`). Conf
  keys are snake_case with `=` (`max_inbound=`). Concatenated aliases still
  apply. Help notes end with
  a period; duration placeholders are `SECS`.

- **Fee estimates bias for inclusion confidence:** N=1 inverts at 99%
  (80% of the next block, 2× admit-EMA, confirm-memory p90 clip). Confidence
  fades linearly to 90% at N=6 and holds (95% fill, 1× EMA, p90 of per-block
  p10s). Same Electrum/Esplora numbers.
  [`docs/mempool-fee-estimation.md`](docs/mempool-fee-estimation.md).

- **Electrum `silentpayments.unsubscribe` drops the session scan:** a later
  tip no longer walks that scan key (mismatch address leaves it). Catalog
  journeys pin outpoint tip notify, confirmed vs mempool spent JSON, package
  success, SP start clamped to tip, live `startingheight` at the seeder tip
  with `synced_*` still `-1` until a header hash is known, and `/fee-estimates`
  depths.

- **Catalog journeys own yesterday's operator pins:** Electrum **1.6**
  outpoint / silent-payments TCP, `broadcast_package` success, live
  `getpeerinfo` clock/sync fields, and Esplora `/fees/recommended` sit on
  existing catalog pads. Dispatch/TCP twins of those contracts are gone.
  Mock-clock / connecting / header-only `getpeerinfo` guts stay.

- **Coverage 91% LCOV floor + CRAP fail-above 30:** drop the never-falls
  LCOV ratchet (llvm-cov hit counts jitter). Floor is unrounded
  `LH*100 >= LF*91`. After LCOV, `cargo crap --fail-above --threshold 30`
  with today's production CRAP>30 functions allowlisted in
  `.cargo-crap.toml` (chew through later). No `--fail-regression`.
  [`TESTING.md`](TESTING.md).

- **`getpeerinfo` / `getnetworkinfo` clock and sync fields are session state:**
  per-peer `timeoffset` is VERSION time minus connect time (`0` before
  handshake). `synced_headers` is the height of the peer's advertised best
  block when we know it, else `-1`; `synced_blocks` is that height only when
  the hash is on our best chain. `getnetworkinfo.timeoffset` is the median of
  outbound handshake-complete offsets (`0` if none). Connecting rows report
  `startingheight` `-1`.

- **`syncwithvalidationinterfacequeue` is not a node method:** `-32601`
  Method not found (no wallet/index callback queue). The functional proxy
  still returns `null` so Core `sync_mempools` keeps working.

- **Compact `blocktxn` apply owns first-pass slots:** pending compact keeps
  mempool/extra/orphan hits from the initial short-id walk. `blocktxn`
  overlays only the missing indexes and does not re-query the live map, so a
  mempool write or eviction during the RTT cannot force a full `getdata`.
  [`COMPAT.md`](COMPAT.md).

- **Fee estimates blend live flow with block history:** Near targets invert
  stock + capped admit-EMA (0.1 sat/vB candidates; under-full pool with live
  stock answers min-relay for N=1–5, not a last-chunk far rate). Far targets
  (144/504/1008) follow per-block p10 of confirmed packages (insufficient
  without history). Mid depths use `w=exp(-(N-1)/6)`. Confirm-memory clips
  N=1 only. Esplora `/fee-estimates` rounds to 0.1 sat/vB.
  [`docs/mempool-fee-estimation.md`](docs/mempool-fee-estimation.md).

- **Operator logs:** tip-follow and P2P INFO/TRACE use rbitcoin lines
  (`tip: best=`, `p2p: headers sync`, `p2p: getdata wtx`, `p2p: received tx`,
  `p2p: accept dropped … (prev not found)`). A store tip more than two hours
  ahead of the clock aborts in store language (not Core `-reindex-chainstate`).
  Core functional `assert_debug_log` / InitError needles stay in
  `scripts/core-functional/debuglog_map.toml` (no `--log-dialect` flag).

- **Operator CLI is kebab-only:** `--min-chain-work`, `--max-tip-age`,
  `--max-inbound`, `--blocks-only`, `--trusted` / `--always-relay` / `--relay`,
  `--ua-comment`, `--peer-timeout`, `--signet-challenge`. No Core aliases on
  `rbitcoin-node` (no `--maxconnections` / `--whitelist` / `--assumevalid-height`).
  Core names stay on the functional `bitcoind` shim (`N−11` inbound from
  `-maxconnections`). Densify/`enter_tip_mode` is catch-up; relay-inhibited
  after the switch is `--min-chain-work` + `--max-tip-age`; RPC
  `initialblockdownload` is the Core alias for that latch.

- **Dialect:** crate/README/IBD text says **relational archive** / Class A/B/C /
  densify (not “libbitcoin-class”). Production rustdoc states local invariants
  instead of Core C++ field names. Script comments use BIP/rule language.
  Disconnect score in P2P logs (not banlist). Native serve/cmpct lines use
  `tx=` (not Hungarian `ntx=`).

- **Core functional `run` is production-only:** skip scripts whose asserts
  were only the bitcoind shim (`feature_help`, `feature_blocksdir`,
  `feature_dirsymlinks`, `feature_filelock`, `tool_rpcauth`) or Core
  decode/`validateaddress` dialect the node does not ship
  (`rpc_decodescript`, `rpc_invalid_address_message`). Live proxy no longer
  intercepts `decoderawtransaction` / `decodescript` / `validateaddress`.
  `feature_filelock.py` stays skip (`harness`). Labeled `test_runner` prints
  **72** jobs (**66** inventory `run`; Core expands transport twins and
  `wallet_txn_*` flags; **201** skip).

- **Core `-bind`/`-port` map to `--listen`:** bare `-port` binds `0.0.0.0`
  plus onion `127.0.0.1:port+1`; TestNode `bind=127.0.0.1` stays loopback.
  `Bound to` matches those sockets. `feature_port.py` is `run`.

- **`--check-blocks N`:** store-open revalidate window (default 6;
  `0` / negative = whole chain). Shim maps Core `-checkblocks`.

- **Datadir exclusive lock:** `rbitcoin-node` flocks `{datadir}/.lock`.
  Dummy Core `blocks/blk00000.dat` is shim-only (`rpc_getblockstats`
  rename needle). No live-node `blocks/.lock` and no fake SQLite `-wallet`
  InitError.

- **Orphan park / `EraseForPeer`:** announcer peer ids on parked txs;
  handshake/INV stay off the tokio reactor write lock. Hidden
  `getorphantxs` dumps the park.

- **CIDR / bind net permissions:** shim `-whitelist` / `-whitebind` → `--net-permission` /
  `--net-permission-bind` (implicit flags, in/out, `--net-permission-relay` /
  `--net-permission-force-relay`). Operator `--trusted` / `--always-relay` / `--relay`
  stay global inbound knobs (not promoted from a CIDR/bind grant).
  Headers-sync stall timeout uses session `noban` (CIDR or `--trusted`).
  `getpeerinfo.permissions` is per-peer. 0-value
  spendable outputs are `dust` (Libre still admits 1-sat). Forcerelay and
  `--always-relay` recent-rejects skip ATMP on the second send (cleared on
  tip connect; fee / cluster-limit rejects stay reconsiderable). IPv6 CIDR
  grants (`noban@::1`, `2001:db8::/32`). Conf `net_permission_bind=`
  listens (same sockets as `--listen`). Shim `-whitebind` is bind-only
  (no synthesized CIDR `--net-permission`).
  `p2p_permissions.py` is `run`.

- **Coverage ratchet is merge-base, not tip of master:** PRs must not lower
  the **displayed 2-decimal** production LCOV percent vs the **highest**
  green-`master` snapshot whose SHA is an ancestor of
  `git merge-base(PR tip, origin/master)`. Raw LH jitters a few hits under
  llvm-cov; a wobble that still prints the same `91.25%` is a pass. Master
  jobs that landed after the branch forked are ignored. History:
  `badges/coverage-history.jsonl`. [`TESTING.md`](TESTING.md).

- **SCHEMA.md matches live 24:** common-header version is 24; loc freeze
  names `create.loc.ovf` u32/u32; empty-open paths rewrite `meta` to 24.

- **Owner docs match open():** `docs/invariants.md` names occupied-22/23
  payload rewrites; `OPERATOR.md` occupied 22/23 rewrite **`meta` first**,
  then ovf / `header.body`.

- **IBD tip-hole assign:** densify issues no new far getdata while `hole=` is
  open; tip-hole races prefer short inflight queues; an aged hole owner is
  dropped when another peer exists. After the confirm prefix is in hand, at
  most one extra racer on the first in-window gap, and only if that owner is
  missing, aged, or a quarter-median lemon. Repeat stall/relative-slow kicks
  lengthen AddrMan cooldown (10m / 30m / 2h) and force the SLOW flag.
  [`OPERATOR.md`](OPERATOR.md) notes `--max-outbound 8` on a constrained
  uplink (IBD floor; no new per-peer flag).

- **`height_by_hash` tip delta:** merged confirm and multi-height shrink
  extend/retain the in-process hash→height map. A full `0..=tip` header walk
  remains open / `invalidate` only. A miss **at or below** the live tip is
  `Corrupt("invariant: height_by_hash confirmed header missing")`. A request
  past the live tip (stale snapshot / concurrent disconnect) retries the
  live tip so RPC/Esplora get `None`, not Corrupt.

### Fixed

- **Unknown-parent compact asks for headers; unsolicited unknown-parent
  block disconnects:** `cmpctblock` whose prev is missing keeps the header
  in-session (`pending_headers`) and retries `getheaders` even if one is
  already in flight (`p2p_sendheaders` `mine_reorg`, `feature_bip68_sequence`
  catch-up) without storing garbage hashes. Reconstruct and hold the
  body even when one-block work looks weaker than a tall tip. Catch-up
  `getdata` uses witness bodies for hashes not on our validated tip
  (compact is tip-relay); a requested compact is not ignored as
  low-work. Held side-branch bodies stay capped at 320; in-flight
  getdata hashes are not FIFO-evicted. An unsolicited
  `block` with a missing prev is `AcceptBlock FAILED (prev-blk-not-found)`
  and disconnects (`p2p_mutated_blocks`). A *requested* unknown-parent
  body stays parked for drain and getheaders from our locator. HB
  `sendcmpct` is written as soon as a peer is selected.
  Completion-session drain-on-drop matches `UringSession` drop (no
  process abort if the kernel has not harvested CQEs).

- **Compact extra-pool is not compact prefills:** Core extra-compact holds
  rejects/orphans/replacements. Prefills from a failed compact must not
  complete a later `cmpctblock` of the same spends (`p2p_compactblocks`
  `test_multiple_blocktxn_response`).

- **IBD recently-confirmed ring:** `accept_block` only records wtxid AlreadyHave
  when mempool relay is on, matching `note_confirmed_tip`. Txs confirmed
  during IBD are requested again after tip-follow (`p2p_ibd_txrelay.py`).

- **RPC `submitpackage` is sequential ATMP then package remainder:** a later
  member fail keeps already admitted txs. Min-relay / missing-input remainders
  are re-evaluated as a package (CPFP parent below min-relay + paying child).

- **Package rollback restores RBF victims:** a later package member fail
  re-admits txs the accepted members had replaced.

- **Pending-fork headers check nBits and MTP:** `ensure_header` no longer
  persists a header-only child on claimed POW alone. Wrong bits or
  `time <=` parent MTP is rejected; a persist walk stops at the first error.

- **Package admit is all-or-nothing:** `accept_package` / RPC `submitpackage`
  rollback uses `remove_txid_tree` (hub `unindex_evicted`). Min-relay waiver
  is a child-with-parents ancestor tree only.

- **Compact fill + isolate:** a full `block` for a pending compact releases
  the Q-60 fill slot. Unique-fill merkle fail counts as a failed compact
  (second attempt disconnects; hash is not `BLOCK_FAILED`). Isolate after a
  multi-block consensus fail stays one-block until confirmed tip passes the
  original wave’s last height.

- **Store/query fail-closed:** poisoned held identity pread does not
  libc-complete; loc 8-wide prefix-sum is SSE2; negative output encode is
  Corrupt; loc-by-fk miss after Class A is Corrupt; reject rewind moves
  lookup-started-high with consume-high.

- **RPC honesty:** `maxfeerate` is sat/vB (default 10000; `>= 100000` is
  `-8`). sendraw over-cap is `-25` configured-max (`testmempoolaccept`
  stays `max-fee-exceeded`); `--rpcworkqueue` full permit is HTTP 503
  (one POST is one slot); `-blocksonly` sendraw of a valid tx still admits.
  Core BTC/kvB `maxfeerate` is the functional-harness proxy only.

- **`preciousblock`:** equal-work sibling still activates; an error path
  does not leave the preference set.

### Added

- **Esplora cross-surface leftover HTTP:** `esplora_broadcast_visible_in_rpc_and_electrum`
  pins `/blocks` start past tip (clamps), `/block/:hash/txs` one-past last page
  as `[]` (not 404), plus `/txids`, coinbase merkle-proof, and unspent
  `outspend/0` on the mined tip.

- **Cheap Esplora pages (schema 24):** `header.body` stores BIP144 size and
  BIP141 weight so `/blocks` and `GET /block/:hash` JSON skip reconstruct
  (`/raw` still rebuilds). Occupied 23 rewrites 88→96 B rows. Optional
  `--max-sh-creates N` (default 0 = unlimited) refuses Electrum/Esplora SH
  joins over N creates (503 / JSON-RPC error, no truncated stats).
  `GET /address|scripthash/…/txs/summary` is a compact dialect (not
  Blockstream Esplora `API.md`; mempool.space-shaped `{txid,value,height,time}`,
  confirmed `/txs/chain` paging). `--esplora-block-template` enables
  `GET /block-template` (default 404). Surface: [`COMPAT.md`](COMPAT.md).

- **Compact reconstruct stats and extra prefill:** each compact
  reconstruct logs one INFO `cmpct reconstruct` line from the fill that
  built the block (not a later mempool snapshot). `--prefillcompact`
  / conf `prefillcompact=` (default **on**; `=0` disables) packs extra BIP152
  prefills (10 KiB cap, extra-pool last) on high-bandwidth announce and
  CompactBlock getdata, including generate / `submitblock` / full-block
  NewPoWValid when packing does not delay forward (`try_read` only).
  Receive any well-formed inbound prefills either way.

- **Process Electrum/Esplora on `--blocksonly`:** `node_run_p2p_short` listens
  Electrum + Esplora after catch-up. `broadcast` / `POST /tx` junk is a
  decode error; a consensus-invalid tx is hub `broadcast reject` / HTTP 400
  — not `mempool not available` and not `relay disabled`. P2P/RPC `-blocksonly`
  pins stay.

- **Subsidy interval=2 overlay; H8 stays the header unit:**
  `header_and_spending_boundaries` overlays `ChainParams` halving interval=2:
  empty at interval−1 is still 50 BTC; at interval 25 BTC; `subsidy+1` at
  the new floor rejects. H8 exact +2h stays
  `h8_timestamp_exactly_two_hours_accepts_plus_one_rejects` (not duplicated
  with `with_now` on the connect pad). Subsidy **table** stays
  `p1_block_subsidy_halvings`.

- **Held 16 vs 17 park + genesis disconnect + leftover identity:**
  `reorg_same_height_then_multi_block_branch` parks 16 and 17 equal-work
  siblings as `valid-headers` (product held cap 320 does not FIFO at 17).
  `chain_connect_reorg_and_growth` disconnects to genesis, reconnects the
  suffix, then a poisoned merkle in the last 6 confirmed heights shrinks
  tip on `Query::open`. `resume_tx_head_resolves_external_prev` leftover
  TipOnly stamp is the one connected fk; RAM leftover map clobber stays
  one slot. Held 320 FIFO stays `hold_body_caps_at_320_fifo`.

- **Genesis+1 IBD + empty headers EOF vs lag:** `two_node_header_and_block_sync`
  is genesis+1 (8-block dual-seeder stays `ibd_two_peers`). Empty `headers`
  with lag keeps header sync; drained most-work path latches `headers_done`.
  Inflight-16 is B7.

- **Serve window 16 vs 17:** inbound `getdata` of 20 witness blocks serves
  `MAX_SERVE_BLOCKS` (16); the 17th is not queued
  (`getdata_skips_reconstruct_when_serve_inflight_at_cap`). Compact live pad
  stays 2-tx / merkle-fail / orphan. Catch-up window guts stay.

- **Feeler silence + inbound eviction rank:** `p2p_feeler_completes_and_closes`
  still completes VERSION then closes; `run_feeler_timed` on a silent socket
  is `Timeout`. `p2p_inbound_full_rejects_extra` still refuses the extra
  follow at `max_inbound=1`; `select_inbound_eviction` 21-cand ranking picks
  an unprotected slow peer. Inbound/outbound/plain silence and noban guts stay.

- **Same-process body-queue residue:** `serve_after_restart_via_reconstruct`
  restart RAM queue is empty. Planted leftover then
  `rehydrate_block_queue_residue` drops at/below tip, skips empty payloads,
  keeps above-tip wire, unknown height stays queued. `has_block` /
  known-archived keep and tip+1 gap `missing` stay crate guts.

- **CLI unknown conf key + `--peertimeout=1`:** `node_cli_and_surface_smoke`
  `--conf` with `unknown_key=1` still `--smoke`s. Conf `minrelaytxfee=-1`
  and `network=nope` fail start. `--peertimeout=1` smokes; `0` still
  InitError. Conf parse guts stay.

- **Mempool leftover `slots.tmp`:** `analog_milestone_and_mempool_persist`
  plants leftover `slots.tmp` after a clean flush; `MempoolHub` open
  finishes the rename and live count matches. Truncated `tx.body` vs
  slots refuses (not a silent empty pool). Compact crash guts stay.

- **RPC exact `maxfeerate` / `maxburnamount` + scantxoutset arms:**
  `sendrawtransaction` at default 0.10 BTC/kvB accepts; one sat over is
  `max-fee-exceeded`; `maxfeerate=0` still admits the huge-fee tx.
  `maxburnamount` equal to the OP_RETURN sat accepts; amount−1 rejects.
  `scantxoutset` `abort` / `status` / empty scanobjects / unknown action.

- **Process Esplora `/blocks` paging + one WS:** `esplora_broadcast_visible_in_rpc_and_electrum`
  `GET /blocks` is 10 newest; `/blocks/0` is genesis-only; `/blocks/:tip`
  starts at the tip. `/block/:hash/txs/25` last page is shorter than 25;
  unknown hash is 404. Same process: WS `want: blocks` and `track-tx`
  confirm on the pad `generate`. Caps 64 vs 65 stay crate tests.

- **Process wait/longpoll + getblock edges:** `esplora_broadcast_visible_in_rpc_and_electrum`
  `waitforblockheight` timeout=0 while behind returns the live tip;
  `waitfornewblock` / `waitforblockheight` and GBT current `longpollid`
  wake on the pad `generate` (stale id stays immediate). `getblockhash`
  tip ok / tip+1 is `-8`; unknown `getblock` is `-5`; verbosity 0 is hex
  and 2 has vin/vout. Wait-on-stop units stay.

- **Connect-path H4/H6 and BIP68 time:** `header_and_spending_boundaries`
  accepts a matching height-1 checkpoint, rejects a mismatch, and
  `validate_header` of a too-easy compact against mainnet `pow_limit` is
  `target above pow limit`. Same pad: BIP68 time-type `nSequence` of the
  height-101 child is `bad-txns-nonfinal` while prev MTP is short, then
  accepts after empty pads raise MTP. `finality_tests` / H8 units stay.

- **Process `-blocksonly` on live `run_p2p`:** `node_run_p2p_short` sets
  `mempool.blocksonly` and `-maxtipage` (so the 3-block 2011 pad leaves
  `IsInitialBlockDownload`). After catch-up, `getnetworkinfo` `localrelay`
  and `getmempoolinfo` `relay_enabled` stay false; `sendrawtransaction` is
  not the serving-only refuse; a seeder inbound `tx` disconnects the session.
  PeerHub `p2p_blocksonly` units stay.

- **`preciousblock` equal-work + held `getchaintips`:** RPC
  `invalidate_reconsider_tip` parks an equal-work sibling (`submitblock`
  `inconclusive`), `preciousblock` the loser then the original tip, ignores
  less work, and unknown hash is `-5` `Block not found`. Hub
  `reorg_same_height_then_multi_block_branch` pins `valid-fork` vs `active`,
  held `valid-headers`, FIFO parks, and the same precious/unknown needles.
  Held cap 320 FIFO stays `hold_body_caps_at_320_fifo`.

- **Live compact unique-fill merkle fail:** `p2p_compact_hb_getblocktxn_and_orphan`
  plants a mempool bait under a compact short-id whose header merkle is a
  different extra tx. Reconstruct GetDatas the hash (not `getblocktxn` /
  `accept_branch`); the header is not `BLOCK_FAILED`; the honest full `block`
  then connects. Live mutated `block` still disconnects in `on_block`
  (`bad-txnmrklroot`). Reconstruct units stay.

- **Electrum TCP line cap, merkle height, history window:**
  `electrum_server_version_history_balance` pins request line at
  `max_request_bytes` vs one-past `-32600` `request line too long`,
  `get_merkle` of a known txid at the wrong height, and `get_history`
  `from_height` / exclusive `to_height` / `to_height=-1` (subscribe status
  stays full). Leftover-mempool TCP pins `broadcast` non-hex and
  consensus-invalid with a hub attached.

- **Package count/weight and CPFP min-relay:** `submitpackage` refuses more
  than 25 hexes and over-weight packages with `package too large` (same needle
  as Esplora `POST /txs/package`). `accept_package` admits a below-min-relay
  parent when the combined ancestor package meets min-relay. Cross-surface pins
  25/26, over-weight, exact incremental RBF, exact 100 sat/kvB, and HTTP 1p1c
  CPFP.

- **Confirm reject isolate at emit:** `emit_confirm_reject` downgrades a
  multi-block consensus fail to Cascade and requests a one-block retry.
  `isolate_if_batched` stays the class table.

- **Process `submitpackage` after IBD leave:** `esplora_broadcast_visible_in_rpc_and_electrum`
  keeps serving-only `submitpackage` refuse (stale tip, relay off), then `generate`
  latches IBD false and enables relay. `submitpackage` then pins maxfeerate reject,
  1p1c success, and already-in-mempool continue. Same pad also pins process
  `getmempoolancestors` / `getmempooldescendants` / `getmempoolcluster` /
  `gettxspendingprevout` / `getmempoolfeeratediagram` / verbose `getrawmempool`
  on the Esplora 1p1c. Dispatch maxburn fail stays a unit.

- **Process `getpeerinfo` on live `run_p2p`:** `node_run_p2p_short` `--connect`s to a
  seeder, then JSON-RPC `getpeerinfo` (v2 outbound-full-relay), `getconnectioncount` /
  `getnetworkinfo` / `getnettotals` / `ping`, `addconnection inbound` refuses,
  `disconnectnode` clears the session, and `addnode onetry` reconnects as `manual`.
  Exit via `stop`. `max_run_secs=0` stays a node-crate unit.

- **Process package + live mempool HTTP:** `esplora_broadcast_visible_in_rpc_and_electrum`
  pins Esplora `POST /txs/package` 1p1c success, process `gettxout` (confirmed,
  mempool create, mempool-spent hide), `getchaintips`, live `GET /mempool` /
  `/mempool/txids` / `/mempool/recent` / `/fee-estimates`, and serving-only
  `submitpackage` refusing while relay is off (`sendraw` still admits).
  Package JSON errors and dispatch `gettxout` stay units.

- **P2P getblocks / feefilter / bloom:** live follower `getblocks` is answered
  with `inv`, inbound BIP133 `feefilter` is recorded, and `filterload`
  disconnects (bloom off). Oversize locator and MemPool/`filteradd`/`filterclear`
  stay units.

- **IBD BQ residue:** same-process `rehydrate_block_queue_into_confirm` drops
  at/below tip, keeps above-tip wire even if `has_block` / known-archived,
  skips empty payloads, and marks unknown-height plus tip+1 gaps missing
  for densify. Process restart still starts with an empty RAM queue.

### Fixed

- **`p2p_timeout_getaddr_and_keepalive_ping` follow handshake:** shrink
  `peertimeout` to 1s only after the live follow (BIP324 + VERSION). Setting it
  first let a unix-second heartbeat drop the inbound mid-handshake
  (`v2 length prefix eof`). v1-magic / pre-verack still use 1s.

- **`cmpct_differential` missing-index split:** Core extra-txn can fill a
  duplicate-txid short-id we still `getblocktxn` (018). Recipe
  `[2, 203, 4, 63]` is ours `[1, 4]` vs Core `[1]`. Agree when Core's indexes
  are a subset of ours; still panic if we filled a slot Core requested.

### Changed

- **Schema 23:** `create.loc.ovf` is 16 B (`fk:u64` + u32 strides / `n_out`) so a
  consensus-valid ~1 MiB txout (mainnet 896696 OP_RETURN) and `n_out > 65535`
  store. Occupied schema 22 rewrites 12 B ovf rows and `meta`. Occupied 15–21
  Class A still refuses. Spent vin stays u16. A 22 binary refuses 23 `meta`.

- **llvm-cov drops `rbitcoin-bench`:** optional host client crate is not a
  coverage gate (`cargo llvm-cov test --exclude` + LCOV IGNORE).
  `cargo test --workspace` still runs its lib tests.

- **Live P2P IBD in default CI:** hop serve, dual live seeders (8-block),
  post-IBD tip follow, getheaders gap fill, and product `run_p2p --connect`
  run in `cargo test --workspace` and `coverage.sh`. 48-block dual-seeder,
  20-block combo, and 4-node mesh are gone. `scripts/integration.sh` is gone
  (**Q-38** completed). [`TESTING.md`](TESTING.md).

- **Tier A IBD in default CI:** `serve_after_restart_via_reconstruct` and
  `ibd_skips_dead_peer` run in `cargo test --workspace` and `coverage.sh`.
  The separate `multinode` job is gone. [`TESTING.md`](TESTING.md).

- **No loc-count echo:** packed decode already walks loc `n_out` / seqsigwit
  `input_count`; drop the tautological len==count Corrupt. `spent_record_len(0)`
  is `0×8` (no special case). Delete unused no-op `head_reserve_additional`.

- **Coverage gate:** LCOV `LH`/`LF` counts **production files** only (test
  modules / `rbitcoin-test` / `testutil` excluded).
  `two_node_header_and_block_sync` runs under `coverage.sh`.
  [`TESTING.md`](TESTING.md).

- **Schema 22:** `create.loc` + `seqsigwit.loc` (no Class A `{txout,spent,seqsigwit}.idx`).
  LAYOUT17 omits `output_count` (decode `n_out` from loc). Spent slot is flags +
  u40 spend fk + u16 vin. `txout` amount is flags bits 4–7 = decimal
  exponent (0–9) + ULEB mantissa (`sats = mantissa × 10^e`; canonical compact,
  messy amounts stay `e=0`). Occupied 15–21 Class A with creates refuses
  (`wipe datadir and redo IBD`). Empty 15–21 rewrite `meta` to 22 and
  unlink leftover `spent.off` and leftover `*.idx`. A 21 binary refuses 22
  `meta`. Esplora `/outspend(s)` emits `vin` from the slot (mempool overlay uses
  the hub tx input index). First-wave Outs guess is `4+(max_vout+1)×38`.
  Drop `HeadOpenOpts::idx_soft_span` / `StoreLayout::with_idx_soft_span` /
  `RBITCOIN_TX_IDX_SOFT_SPAN` (unread after loc; `tx.head` still rolls at OA
  80% only).

### Added

- **Live coverage badge:** Shields endpoint from the last green `master`
  `coverage` job (`badges` branch `coverage.json`).
  [`TESTING.md`](TESTING.md).

- **asmap ASan fuzz:** nightly `asmap` target runs Core `SanityCheckAsmap` then
  `Interpret` (`AsMap::from_bytes`, leftover 16-byte IP). Junk must not panic
  or hang.

- **`--sptweaks-dust SATS`** (conf `sptweaks_dust=`): Electrum
  `blockchain.tweaks.subscribe` omits P2TR `output_pubkeys` with
  `value <= SATS` and drops txs that then have none. Default **1000**.
  `0` serves every value. **546** matches Cake electrs `sp_min_dust`.
  Index is unchanged (serve-time only). [`OPERATOR.md`](OPERATOR.md) /
  [`COMPAT.md`](COMPAT.md).

### Fixed

- **Head-resolve loc after identity:** three probe+identity waves pick fk
  only; **one** `create.loc` batch runs after TLS drops (FdOnly / standalone
  bulk). Loc is not on the held probe ring: probe poison / empty-CQ retry /
  live-ring libc-complete stay on the probe session; loc shorts libc-complete
  on their own batch and do not consume probe recover credit. `range_batch_ctx`
  on a still-held session keeps poison fail-closed. Window extract is a running
  sum + SIMD deinterleave (zero bytes in the same 16-byte load), not prefix
  `Vec`s plus a separate sentinel scan.

- **io_uring wait Ready requires a CQE:** `submit_and_wait_one` peeks the
  CQ after enter. `io_uring_enter` returns SQEs submitted; an empty CQ is
  TimedOut on the drain budget, not Ready. Live harvest (held pread/pwrite,
  probe, BDZ g-pages, spend annotate, SP tweaks) waits then retries; one
  empty harvest is not batch death or `io_uring wait timeout`. libc-complete
  on a live ring remains last-resort for leftover submit/push fail.

- **Mixed `create.loc` windows:** a no-ovf running sum bails to
  `decode_create_pair` when the 16-byte SIMD load contains a zero (overflow
  sentinel). Same pairs as scalar. About half of mainnet windows near height
  896k have at least one overflow slot.

- **Held loc pread live-ring fail is not recover-abort:** empty CQ / submit
  fail on an unpoisoned ring returns `Ok(true)` so loc libc-completes those
  windows. That used to be `io_uring held pread failed`, which consumed the
  once-per-1000 recover credit and aborted IBD (`ibd-confirm-lookup` at tip
  902337). Poison / leftover CQEs stay fail-closed.

- **Held loc pread errno is not session death:** per-op short/errno on a live
  io_uring ring returns `Ok(true)` so loc libc-completes that window (same
  as `txid.body`). Poison / leftover CQEs stay fail-closed.

- **IBD stamp loc by fk on InFlight TipOnly miss:** lookup can run a later
  wave before the parent is in `tx.head`, so the skeleton is empty while
  InFlight still holds the pin and write loc is already pruned. Stamp fills
  spent from `create.loc` by fk (miss is OK for same-wave). Mainnet 133433
  `ensure denserels/abs incomplete for spend edge`.

- **Esplora `POST /txs/package` 1p1c:** `MempoolHub::accept_package` commits each
  member before the next admit so a child can spend an in-package parent
  (same sequential shape as `ActiveMempool::accept_package`). Prepare-all
  left the child orphaned.

- **Coverage `integration_multinode` SIGABRT:** live `P2PNode` tests serialize
  on a process mutex so overlapping `shutdown` abort cannot smash the shared
  `rbtc-scripts` pool under llvm-cov.

- **`open_seals_unsealed_nontail_after_copied_roll`:** crash-copy skips
  ENOENT / `.tmp` so a live seal worker unlinking the OA cannot fail the
  snapshot. Live table drops before cleanup.

- **Write loc RAM:** Class A append returns loc pairs; write keeps them in
  height-tagged **thread-local** packs (no `Query` mutex) until write of the
  last height whose TipOnly had started at note (`lookup_started_hi`).
  `keep_until` is stamped once and never bumped. Fill of that write runs
  first. Later-wave InFlight identity still takes TipOnly loc. Same-batch /
  just-written abs stamp from that RAM (packed pin outs). Disconnect is polled
  on the write thread. Write does not pread `create.loc`. Missing stamp is
  `Corrupt`. `ibd: sizes` `wloc=`.

- **`create.loc` leftover stamp:** lookup reads/sums only through the highest
  fk in each 1024-create window, preads those windows as one bulk batch (held
  head-resolve session or `pread_batch`), and prefix-sums every window with
  SIMD then ovf correction (SSE2 on x86_64, NEON on aarch64). No cross-window
  loc cache.

- **`store_reorg` overnight ASan OOM:** sibling ops no-op at 16 parked
  `held_bodies` and the tiny hub is not reopened. Recycle-every-16 grew
  libFuzzer RSS to the 2048 MiB cap (~45 min into the Sunday 1h job)
  with a 48 MiB live heap.

- **Compact reconstruct merkle-checks before `Ok`:** a unique short-id (or
  `blocktxn`) fill is not a block until the txs match the compact header
  merkle (BIP152 `FinishBlock`). Empty missing → `getdata`, not
  `accept_branch`. `cmpct_wtxid_shortid_collision_held_fork_journey` is a
  pre-ground v2 48-bit collision (orphan unique-match on a held fork).
  Defense in depth: a merkle/`bad-txnmrklroot` that still reaches
  `accept_branch` is not cached `BLOCK_FAILED` (ConnectFailed wrap used to
  poison the hash; mainnet 966500/966501, 2026-09-11). True consensus
  rejects (`bad-txns-inputs-missingorspent`) still mark `BLOCK_FAILED`.

- **`p2p_timeouts.py --v2transport`:** VERSION handshake timeout needles are
  logged for every connecting peer (id order) before TCP teardown, and a
  pre-verack ping does not skip the `peer=0` line. Core's `assert_debug_log`
  uses `timeout=0`.

- **Electrum 1.4 leftover:** `blockchain.scripthash.unsubscribe` returns whether
  the connection was watching (frees the per-connection cap). `get_history`
  unconfirmed rows include `fee`; confirmed rows (including genesis height 0)
  omit it. `listunspent` mempool height is `-1` when a parent is still in the
  mempool (otherwise `0`).
- **Wallet overlay leftover:** Electrum `get_balance` / `get_mempool` skip
  hub txs already connected on the tip (`tx_fk_by_txid_tip`, not an SH
  join). `listunspent` skips a mempool create already in the confirmed UTXO
  set. IBD / `-blocksonly` (relay off, `remove_for_block` is a no-op) cannot
  double-count confirmed value. Esplora `GET /tx/:txid/status` returns
  `{confirmed: false}` for mempool-only txs; live `/outspend(s)` overlay
  mempool spends (`?asof=` still omits them). `gettxout` uses the connected
  instance: a leftover still in the hub is confirmed, not
  `confirmations: 0`; a disconnected archive row is `null`.
- **Packed P2TR scan:** `scan_packed_p2tr_outs` fails closed on an output
  value above `i64::MAX` (`Corrupt("output value too large")`), matching
  `OutputRecord::decode_at_secret`.
- **Class C `flush_dirty`:** packed dirty-epoch (`0` = clean). Snapshot stays under the `data` read lock; persist IO is unlocked; CAS `e0→0` so a racing `set` is not marked clean. Wrap of `u64::MAX` stays dirty (never publishes 0).
- **fuse8:** `decode_body` refuses fingerprint arrays shorter than `hash_of_hash` geometry. `contains` is unchanged.
- **Spender overflow:** `for_each_spender_create` stops after `spenders.count()` hops (`Corrupt` on a cycle).
- **Index seal:** `meta` / `.mphf` / SH `.idx` install is sibling tmp + `sync_all` then rename (empty truncate of the live name is not a seal).
- **`list_runs`:** catalog scan does not unlink. Residual `*.run` files are discarded with the leftover dir (open-time SH `key_len` and leftover-run **count** do not delete).
- **Mempool persist order:** admit `persist_all` writes body, then LIVE slots, then meta. A crash after a grown body and before new slots loses admits; it does not claim LIVE ranges past durable `tx.body`. Packed compact uses tmp+`sync_all`+rename, then meta only, so packed body cannot mix with old slots.
- **Worst-chunk eviction:** `evict_worst_chunk_once` uses `remove_txid_tree` so a parent-only chunk cannot leave a child without its mempool parent.
- **Same-block coinbase maturity:** a later tx in the same block that spends
  the coinbase is `coinbase immature` (Core `nHeight < coinbaseHeight + 100`).
  Assemble already maps this block’s txids (`txid_index`); parent index 0
  is the coinbase. Durable maturity still uses `create_fk == first_tx_fk`.
- **IBD `lookup_taken_hi` rewind:** merkle/witness SoftWire, Cascade,
  EngineFault, and ConsensusInvalid rewind the lookup consume high-water to
  the confirmed tip so densify can re-getdata. Previously only BadPrev did.
- **SH overflow compact / tip append:** `compact_sealed_ovf` installs L1
  before dropping L0 so `locate_head` never sees both empty. Occupancy walk
  includes compacted L1. Tip append probes sealed heads when `live_count == 0`
  but head slots are still occupied (crash mid-finish).
- **Equal-length reorg work:** `disconnect_to` truncates `chain_work_prefix` to
  `keep_height+1` so the next most-work compare is rebuilt from the new branch.
- **Header anti-DoS:** `ensure_header` runs POW / nBits / MTP when the parent is
  on the best chain (claimed POW otherwise). Pending ranking and getdata skip
  headers whose claimed nBits the hash does not meet, and fail closed on a
  pending-header hole.
- **IBD stamp/pin fail:** re-offer the rest of the wave into the **body
  queue** (lookup never reads `feed.ready` wire), `clear_all` in-flight
  identity, rewind `lookup_taken_hi` to the confirmed tip, and bump the feed
  epoch so later same-wave loadq chunks are stale (those chunks re-offer on
  drop).
- **IBD session-fault resume:** after Class C, a uring session fault on spend
  annotate or `tx.head` drain finishes annotate+drain on the write thread
  (tip `connect_at` retries `finish_post_commit`; IBD does the same in place
  when every hash is connected). Load recover after `note_lookup_ok` rebuilds
  create-fk HWM from durable Class A (`clear_all`) so retried plans are not
  stamped past an abandoned pack.
- **1p1c child-fail rollback:** rolling back a below-min-relay parent also
  evicts mempool txs that spend it (a concurrent spender in that window
  cannot stay).
- **RPC `maxfeerate`:** prevout-sum overflow is over-cap (reject), not
  fail-open. Missing prevouts still skip the cap so `accept_tx` can say
  missing-inputs.
- **P2P caps (Q-60):** AddrMan learned/`peers`/`addpeeraddress` stay at 8192
  (evict incompat, then failed last-connect, then oldest new). 4096 was
  below Core's GetAddr cache floor (`1000 / 0.23`), so
  `p2p_getaddr_caching` could not fill 1000. `--connect` / DNS inject may
  exceed when only tried addrs remain. Shutdown `merge_from` trims to
  8192 (tried first). `announced_wtx` and `from_this_peer`
  insertion-order FIFO-roll at 50k instead of `clear()`. Compact `cmpct_fills`
  decrement on reconstruct fail, getdata expire, and unregister (Accepted still
  clears the hash).
- **IBD io_uring drain stall:** `drain_all` no longer returns after 5 s with
  leftover SQEs (that freed in-flight buffers). Every TLS session waits while
  CQEs arrive; a 120 s zero-completion stall aborts explicit drain (session
  `Drop` does not abort). Write/lookup/load/scripts and tip-connect recover once
  per 1000 heights (credit only; Class C leftover waits for open repair)
  instead of a 19h warn loop. Restart with `RBITCOIN_IO=pread` if completions
  cannot complete. [`OPERATOR.md`](OPERATOR.md)
  / [`docs/io-modality.md`](docs/io-modality.md).
- **`cmpct_differential` fill vs Core extra-txn:** Core v31 latches IBD in
  `UpdateIBDStatus` (`LoadChainTip` / connect), not `setmocktime`. A fresh
  regtest genesis stays in IBD under the default 24h `-maxtipage`, so P2P
  `tx` is dropped and the fill seed panics `ours=[] core=[1]`. P2P
  `bitcoind` now gets `-maxtipage=999999999`.
- **`store_reorg` overnight ASan timeout:** equal-work siblings park in
  `held_bodies` and `try_apply_held` walks all of them. The fuzz hub is
  reopened every 16 applies so a 4-byte unit cannot run past `-timeout=30`.

### Changed

- **Journey-first tests:** `header_and_spending_boundaries` is the one connect
  pin for MTP, immature coinbase, `in < out`, subsidy+1, same-block double
  spend, and parent/child order (skinny remine twins removed). Electrum TCP
  journeys cover confirmed history `fee` omit, scripthash subscribe notify,
  subscribe cap/unsubscribe, leftover mempool, and connection/idle caps.

  pair. Body queue is in-process; confirm is lookup+load+scripts+write OS
  threads.
- **RPC / CLI honesty (Q-59 rest):** `gettxout` default `include_mempool`
  returns `null` when a live mempool tx spends the confirmed out.
  `sendrawtransaction` / `testmempoolaccept` / `submitpackage` enforce
  Core-shaped `maxfeerate` (default 0.10 BTC/kvB, `0` unlimited, `>1`
  BTC/kvB is a parameter error) and `maxburnamount` (default 0) **on RPC
  submit only** — P2P `accept_tx` is not capped. JSON-RPC array batches
  longer than `--rpcworkqueue N` (when set) are HTTP 500; unset stays
  unlimited. `getmininginfo.blockmintxfee` is `sat_btc_json` BTC/kvB.
  [`docs/rpc.md`](docs/rpc.md) / [`OPERATOR.md`](OPERATOR.md).
- **One assemble path:** `AssembleMode::Full` and `validate_block_connect` are
  gone. Confirm is optimistic assemble then `structural_validate_spends`
  (spentness, coinbase maturity, BIP68). Connect tests use
  `accept_and_connect_block`. [`docs/invariants.md`](docs/invariants.md).
- **One Class A planner:** `archive_plan_batch_from_store` is gone. IBD and
  Class A-without-tip fixtures plan with `archive_plan_batch_from_wire`;
  write fills packed ins from the wire block + spend edges.
- **Store IO probes (X-03):** SQE counts, page writes, SH page IOs, and BQ
  raw clones live on the session/table/queue that did the IO. TLS
  `test_take_*` / `TEST_FORCE_SESSION_FALSE` / crate-root `take_raw_clone_n`
  are gone.
- **Archive-prep twins (C-03):** `prepare_block_for_archive` is the one
  CPU-side Class A helper; `_new` is private; `_with_txids` deleted;
  `validate_block_structure_precomputed` is crate-private.
- **Class A fixture conversion (Q-21):** `tx_apply_to_tx` /
  `block_from_applies` live in `rbitcoin_query::testutil`. Production
  `Query` no longer converts TxApply to a dummy Block (`connect_block` /
  `commit_class_a_only` / `archive_prepared_*` gone).
- **Dated crate-complexity inventory removed:** the 2026-09 program is
  [`docs/quality.md`](docs/quality.md) Completed. Dual-path / probe
  rules live in What to protect, [`docs/invariants.md`](docs/invariants.md),
  [`CONTRIBUTING.md`](CONTRIBUTING.md) principle 11, and
  [`TESTING.md`](TESTING.md). Clippy: no workspace `allow` list; leftover
  lints are site-local with a reason
  ([`docs/code-shape.md`](docs/code-shape.md)).
- **Clippy `cognitive_complexity`:** workspace `warn` (nursery).
  Core-faithful loops and dense surface tests keep a site allow. Do not
  peel **R-10** to silence. [`docs/code-shape.md`](docs/code-shape.md).
- **RPC / CLI honesty (Q-59 slice):** `submitblock` uses the live chain hub
  on all networks (same receive path as P2P; `generate*` / `setmocktime`
  stay regtest-only). `--minrelaytxfee` / `--blockmintxfee` reject garbage
  and negatives at config parse (`0` is still no floor).
  `--permitbaremultisig` is gone; `getmempoolinfo.permitbaremultisig` is
  always `true` (Libre has no Core `IsStandard` bare-multisig gate). The
  Core-functional `bitcoind` shim still ignores `-permitbaremultisig`.
  `getnetworkhashps` is labeled dummy 2-work-per-block / elapsed (not Core
  chainwork hashrate). [`docs/rpc.md`](docs/rpc.md) / [`OPERATOR.md`](OPERATOR.md).
- **Esplora outspend includes `vin`:** `/tx/:txid/outspend/:vout` and
  `/outspends` emit the spending input index from the schema-22 spent
  slot (`PointRecord.spending_vin`). Mempool overlay uses the hub tx’s
  input index. Unspent remains `{spent:false}` with no `vin`.
  [`COMPAT.md`](COMPAT.md).
- **Leftover index layouts refuse on open:** fuse8 **v1** sealed filters, flat
  `tx.head.meta`, flat `*.idx.meta`, Shared (file) `scripthash.body`, and pack8
  **Paged** (mode 10) fail closed with a one-line wipe/rebuild message (Class A
  kept). No always-probe fuse rewrite, no flat-idx/head rename, no Shared body
  read. Shared SH read/write arms deleted.
  [`SCHEMA.md`](SCHEMA.md) / [`docs/operator/storage.md`](docs/operator/storage.md#schema-upgrade).
- **CLI and conf share one setter:** `--key[=value]` and conf `key=value` both
  run `NodeConfig::apply_kv` (conf then CLI). `CliAccum` and the field copy
  are gone. `--smoke` / `--help` / `--version` / `--conf` / `--log-level` stay
  CLI-only. `DatadirOpts` is a path field plus `path()` (no Deref). Explicit
  `--milestone 0` / `--assumevalid-height 0` / conf `milestone=0` stays 0
  (full scripts); omitted milestone still uses the network default.
- **Fuzz/differential harness is not compiled into the node:** `block_diff`
  and compact recipe/v2 encode helpers live in the `fuzz` crate. Net still
  exposes `ChainHub` accept, `try_reconstruct`, `encode_v2_contents`,
  `drain_pending_now`, and `PendingBlocks`. `cargo fmt --all` still formats
  `fuzz/` (workspace fmt-anchor tests; fuzz stays its own cargo-fuzz
  workspace so `bitcoinconsensus` is not in the product graph).
- **Suggested-order 5 dead paths:** IBD awaiting-bodies / full-Block hold gone
  (presence-only hashes; most-work stays header rewind). Leftover SH
  16-byte head codec and `ShOverflowStack` test harness deleted (wipe +
  leftover-OA refuse stay). Test-only page-RMW, `HeadRole`,
  `repair_orphan_class_c`, and 1:1 spend IO aliases gone. One
  `RBITCOIN_IO` token parse. Compact reconstructs once. Query
  `archive_filter_need_bodies` / unused pubs, unread fee-flow confirm/evict
  EMA, last-log capture beside `capture_logs`, bench-private hex, and
  retired `TableKind` variants deleted.
- **Suggested-order 4 test fixtures:** IBD Tiny+hub tests call
  `tiny_regtest_hub_labeled`. RPC / query catchup / consensus structure-rule
  leftover `temp_dir` inlines use `TempDir` / `tiny_query`. BIP34 encoding
  twins live in `bip34_tests` only (structure-rule keeps the wrong-encoding
  reject pin). Peer tests hold `PeerFollowState` and call `handle_peer_frame`;
  the 11-arg unpacking shim is gone. SH tests use store `TempDir`.
- **Tiny-regtest net hub fixture:** `tiny_regtest_hub` /
  `tiny_regtest_hub_labeled` compose Tiny query + shipped `ChainHub::new`
  with regtest params. `peer_tests` and named `tmp_hub` copies call it.
- **Shared Tiny test fixtures:** `rbitcoin_store::testutil::{TempDir, tiny_store}`
  and `rbitcoin_query::testutil::tiny_query` own unique-path drop-clean Tiny
  opens. Named `tmp_dir` / `temp_query` / `tmp_hub` copies now use them.
  Deleted Core JSON spot-check twins (`core_script_spot_*`,
  `core_tx_spot_first_valid_accepts`); `*_all_rows` remains the corpus pin.
- **`ibd: perf` / `ibd: sizes` drop leftover always-zero parent-cache slots:**
  `thru=` / `load thru=` / `bodies=` on the sizes line were the four-zero
  `parent_cache_perf_snapshot` tuple (only `plans=` is live). Slow-load INFO
  `ibd: confirm load slow` no longer prints `adopt=` / `publish=` (production
  `note_last_pin` always stored 0). Live lookup / load / scripts / write
  timers stay.
- **Head scale is open-time, not process env:** `StoreLayout::single` /
  `with_cold` are Mainnet; tests use `StoreLayout::tiny` /
  `Query::open_or_create_tiny`. `RBITCOIN_HEAD_SCALE`, cargo-test `/deps/`
  sniffing, and `HeadScale::test_with` are gone. Tx-head rebuild seal bits /
  workers and idx soft-span are the same open options (production still reads
  `RBITCOIN_TX_HEAD_REBUILD_*` / `RBITCOIN_TX_IDX_SOFT_SPAN` once at open).
  `NodeConfig` production `store_layout` is Mainnet; tests use
  `with_tiny_heads()`; `--smoke` opens Tiny heads (CI / windows / macos).
- **Store crate-root surface:** drop re-exports other crates never import
  (`AddressHead`, packed decode aliases, SH remap/slab Vec codecs, sorted-run
  catalog helpers, …). Tests use the remaining production insert/probe/decode
  paths; rustc `dead_code` then deleted the unused wrappers.
- **Visibility policy:** unused crate-root `pub` is forbidden (no out-of-tree
  library API today). `#[cfg(test)]` on production items is a smell; fuzz-only
  exports are the same smell. Owner: CONTRIBUTING principle 11.
- **Workspace crate-root surface:** drop re-exports other crates never import
  from query, consensus, mempool, net, rpc, electrum, esplora, node, and log.
  Types that appear in remaining public signatures stay `pub`. Fuzz keep-list
  on `rbitcoin_net` (ChainHub, compact v2 encode helpers, `store_reorg_*`,
  `prepare_cmpct_fuzz_*`, …). rustc `dead_code` then deleted unused wrappers
  (`ScriptsPhaseHandle` / feed-ahead, `select_most_work` / `WorkCandidate`,
  `ConfirmLoadStats`, `cmpct_missing_empty_mempool`, `handle_request`,
  `magic_for`, `max_level`, `drive_script_waves` wrapper, `NetConfig` /
  `P2PHandle` / `handle()`, `SortedHeadWriter` / idx-only open). Tests drive
  the remaining production entries (`drive_script_waves_with`,
  `confirm_bq_resolve_wave_capped`, `dispatch` / `run_rpc`, `enabled`,
  `hold_body` / `register_explore`, `SortedHead::write`/`open`). Dropped
  crate-root names are denied by ast-grep (`crate-root-dropped-pub`).
- **Workspace version 0.6.99:** in-tree toward 0.7.0.
  Published GitHub Releases remain 0.6.1; `v0.6.x` is the patch branch.
- **`ibd: perf` / `ibd: sizes` drop never-written meters:** DEBUG no longer
  prints `recon`/`wire`/`resolve`, `parent_io`, `miss_p`, `cold_idx`,
  `tip_gc`, `recent_pub`, annotate `pread=`, `spend_mix i=/skip=`,
  `pstore`, or always-zero heap `recent=` occupancy. Slow-batch INFO
  `ibd: confirm write slow` also drops `tip_gc=` (write no longer GCs
  header plans). Live lookup / load / scripts / write stage tokens stay.
  `write=` is Class A + ensure + structural + class_c + SH + spend +
  tweaks + pins + head_sub + drain_join + dequeue.

## [0.6.0] — 2026-09-08

Named published **0.6** line. **Not 1.0.** Patch branch is `v0.6.x`. Schema 20
is still bumpable (named refuse/wipe, no silent wipe). Default mainnet
`--milestone 840000` skips historical script/sig checks (`--milestone 0` is
full scripts). `--shindex` default off. BIP324 v2-only. GitHub Release: Linux
musl (operator) + Windows CRT-static PE + Darwin aarch64.

### Highlights

- **Schema 20:** sealed `tx.head` is packed BDZ2; sealed SH is BDZ3. Occupied
  schema 18/19 `tx.head` or `scripthash*` is refused (wipe those index dirs,
  keep Class A). Empty 18/19 indexes rewrite `meta` to 20.
- **RPC decode on the node:** `decoderawtransaction`, `decodescript`, and
  `validateaddress`. Verbose `getrawtransaction` / `getblock` v2 vin include
  `scriptSig`; `scriptPubKey` includes Core-style `type`.
  `getnetworkinfo.version` is `600`.
- **P2P / IBD:** Core asmap outbound diversity (`--asmap` /
  `{datadir}/ip_asn.dat`; `getpeerinfo.mapped_as`); learned book 4096 with
  last-resort eviction; handshake-then-die is a failed connect; IBD follows
  most-work (not max advertised height); unanswered getdata retried after
  10s; compact HB announce before tip-accept; IBD getdata serve reconstructs
  from Class A spans.
- **Tip-follow does not stall the reactor:** mempool accept is
  `spawn_blocking`; session never parks on mempool `inner`; FeeFilter overlay
  is atomic; tip connect runs on a dedicated `tip-accept` OS thread.
- **`--shindex` after IBD:** unsorted-shard materialize is the default (nCPU
  collect, in-place unique-sort, sealed heads kept on SIGINT). Pack workers
  auto-tune to free RAM.
- **Core functional / fuzz:** 71 unmodified v31.1 scripts `run` (14 at 0.5.0).
  Nightly differential fuzz vs Core v31.1 is continuous (Q-30: block / spend /
  fork / compact / script / BIP324).

### Added

- **RPC decode subset:** `decoderawtransaction`, `decodescript`, and
  `validateaddress` on the node (see [`docs/rpc.md`](docs/rpc.md)). Verbose
  `getrawtransaction` / `getblock` v2 vin now include `scriptSig`;
  `scriptPubKey` includes Core-style `type`. Core dialect wrap / miniscript /
  `error_locations` stay on the functional-test proxy.

### Fixed

- **Host A/B docs:** [`docs/io-modality.md`](docs/io-modality.md) no longer
  tells operators to build `rbitcoin-store-bench` (removed from the default
  graph). Head-insert A/B is musl `rbitcoin-node` plus `ibd: perf`. Mimalloc
  in [`docs/reproducible-builds.md`](docs/reproducible-builds.md) is node/cli
  only.
- **`store_reorg` extend after a heavier held fork:** `try_apply_held` may
  return `Accepted` above the next height; that is not store corruption.

### Changed

- **`cmpct_differential` encodes a structured BIP152 recipe:** extra-tx
  count, prefill mask, fill/duplicate/corrupt flags, then grind+short-ids.
  Raw consensus bytes remain one arm (`data[0] % 8 == 7`). Fill sends those
  txs before `cmpctblock`; empty missing (full reconstruct) counts as a
  comparison. Seeds and `fuzz/dict/cmpct.dict` ship with the job. Skip-rate
  is 0.5% of libFuzzer execs again (the unstructured mute-rate no longer
  applies).
- **IBD outbound diversity stays, but last-resort no longer fills the spare slot:**
  unused-netgroup preference is per dial tier; a handshake with no block
  bytes is a failed connect plus 10-minute cooldown; recently attempted
  addrs are skipped while others remain; redial asks for at least two
  peers when below target. Learned book cap is 4096, evicting
  incompatible/failed entries when full so getaddr can still grow the
  pool (DNS seeds already exceeded the old 256 cap).
- **Release process:** [`docs/releases.md`](docs/releases.md) (via
  [`AGENTS.md`](AGENTS.md)) owns tag / `vX.Y.x` / `.99` bump. Ship PRs
  write CHANGELOG `### Highlights`; `./scripts/release-notes.sh` is the
  GitHub Release text. `release-extra` runs Core functional on ship PRs.
- **Confirm/net rejects are typed at the sender:** IBD matches
  `ConfirmRejectClass` (not English). Side blocks, unknown parents, mutated
  compact bodies, and duplicate mempool txs keep the same log/RPC strings.
  `io_uring` not available logs as `io_uring unavailable` (no `corrupt record:`
  prefix).
- **One-shot confirm load is stamp then pin:** `confirm_wire_load_phase`
  is `confirm_wire_lookup_stamp` + `confirm_wire_load_from_plan` (same
  as IBD after BQ TipOnly). Script jobs carry `ScriptVerifyFlags`.
  CLI flags and IBD cadence unchanged.
- **Mempool admit/evict helpers:** conflict scan is shared by prepare and the
  write-lock re-check; eviction is one worst-chunk loop; P2P staged admit
  is `admit_staged`. Policy strings and persist order unchanged.
- **Query SH write-behind is `ShWriteBehind`:** same mutexes and condvar as
  before (confirm enqueue vs Electrum join stay separate). `IndexMode`
  names the archive-spend and SH-enqueue products. Body-txid head probe is
  `TxTable::probe_body_match_fk`.
- **ChainHub holds side bodies in one `HeldBodies` map:** first-seen seq
  lives next to the body (one `RwLock`, cap 320 FIFO). Invalidated hashes,
  header-only tips, and mining knobs are named types. RPC/P2P façades
  unchanged.
- **IBD confirm-event drain is `apply_confirm_events`:** the main loop still
  drains before assign and after `offer_confirm_ready` (plus the stall tick).
  Headers apply is named stages; a repeated header window does not grow the
  header table. Confirm reject no longer clones unused wire.
- **Workspace version 0.5.99:** in-tree toward 0.6.0. Published GitHub
  Releases remain 0.5.1; 0.5.2 is the 0.5.1 maintenance branch.
- **`NodeConfig` is composed option groups:** `DatadirOpts` / `ListenOpts` /
  `MempoolOpts` / `RpcOpts`. CLI flags and `apply_kv` keys unchanged.
  `config.datadir` still `Deref`s to the process datadir `PathBuf`.
- **P2P inbound dispatch and session `select!` arms are named functions:**
  `handle_peer_frame` calls `on_ping` / `serve_getdata` / `on_cmpctblock` / …
  Session stages are `on_heartbeat` / `on_tip_event` / `run_writer_task`.
  `LivePeer::peer_hub()` is the `PeerHub` accessor (`hub` in `peer.rs` is
  `ChainHub`).
- **RPC handlers live in domain modules:** `methods/{chain,net,mempool,mine}.rs`.
  `METHOD_LIST` and `dispatch_inner` stay in `methods/mod.rs`.
- **Electrum session is `ElectrumConn`:** `dispatch_pinned` takes one
  session bag. Tests live in `server_tests.rs`.
- **RPC `help` / `getrpcinfo.methods` list every dispatched method**,
  including `generate`, `mockscheduler`, `addpeeraddress`, and
  `getnodeaddresses`. Electrum genesis hex and Esplora WS txid / tip `id`
  use `display_hash_hex`.
- **Node start catch-up is a `CatchUp` enum:** not four independent bools.
  Indexes, IBD, and Electrum/Esplora start are named phases. Electrum and
  Esplora share one hub-tip broadcast bridge.
- **P2P follow session is `PeerFollowState`:** `handle_peer_frame` takes one
  session bag instead of twelve mut maps. Compact `sendcmpct` preference is
  `PendingSendCmpct::{None, Lb, Hb}` (`AtomicU8` payload unchanged). Tx and
  wtxid GetData share `serve_mempool_getdata`.
- **Esplora asof/live scripthash reads share `sh_at_view`:** utxo,
  chain page, and combined txs no longer copy the pin fork.
- **Electrum asof/live scripthash reads share `sh_at_view`:** history,
  balance, and listunspent no longer copy a 4-way pin fork.
- **CLI / conf share `NodeConfig::apply_kv`:** argv still has its own
  flag match and help text; conf `key=value` goes through one setter.
  Parsed flags live in `CliAccum` instead of ~40 `mut` locals.
- **Display-order 32-byte hash hex** lives in `rbitcoin-primitives`
  (`display_hash_hex` / `parse_display_hash32`). RPC, Electrum, and Esplora
  call that pair instead of each reversing then encoding.
- **Code shape:** [`docs/code-shape.md`](docs/code-shape.md) owns control
  flow, naming, and composition (CONTRIBUTING principle 10).
  [`docs/quality.md`](docs/quality.md) **Q-61** named extracts landed
  (Completed); residual god-file peels are **R-10**.
- **Release builds skip store/query IO spies:** `tx_full_gets` /
  `body_ok_reads` increment only under `debug_assertions`, not on the
  operator hot path.
- **Tip-hole getdata races four peers immediately:** `IMMEDIATE` already
  equalled `MAX`, so the 5s third-peer delay never ran.
- **getheaders stale hashstop uses `is_block_archived`:** presence is the
  Class A `header_txs` check IBD already uses, not a full archive reconstruct.

### Fixed

- **Fuzz harness: `cmpct_differential` compiles, kernel always sets P2SH, store_reorg does not require the submitted sibling to be tip:** `BlockOracle` was used without import. `script_kernel_differential` passed `VERIFY_WITNESS` without `VERIFY_P2SH`, which `libbitcoinconsensus` asserts. `store_reorg` treated `Accepted` as “this hash is tip” after `try_apply_held` connected a heavier held/archive path.
- **`getpeerinfo` omits a completed peer after TCP FIN even with unread bytes:**
  `peek==0` missed the far-side close while the session was still draining
  (`mempool_reorg` `disconnect_nodes` 5s). Linux uses `POLLRDHUP`.
- **Held consensus-invalid children are not retried on the next sibling:**
  `try_apply_held` skipped `invalidateblock` hashes but not a missing-prevout
  child that failed mid-branch. That child stayed in `held_bodies` and the
  next equal-work `accept_received_block` re-applied it (`side reject` on
  `block_fork_differential`). Failed branch tips are marked invalid and
  dropped; `accept_branch` refuses invalidated hashes. Fork-diff `setup_side`
  parks the sibling without applying held work.
- **Catch-up child-before-parent bodies connect after the parent:** a
  child whose parent header was already stored is `gap above tip`, not
  `unknown parent`, so it was dropped. `asked_blocks` also kept the hash
  after receive, so drain would not re-ask. Hold that body like an
  unknown parent, apply held children when the parent connects, and
  forget `asked_blocks` on successful accept or hold, not on consensus
  reject (`feature_bip68_sequence` activateCSV `sync_blocks` 60s;
  `feature_csv_activation` BIP113 must not re-getdata a rejected body).

- **Reorg-n differential parks tip on stem after reject:** `compare_fork_n_one`
  left the hub on the side chain when the child was rejected, so the next
  input could fail harness `side extend`. Reject paths now rewind + precious
  the stem; side extend prefers `accept_branch`.

- **Mempool accept no longer panics on overflowing output sums:** fuzzer
  txs can have `u64` output totals that wrap `.sum()` in debug. Checked add
  returns `bad-txns-txouttotal-toolarge`.

- **Mempool/script-verify fuzz skips Core `mempool-script-verify-flag-failed`:**
  v31.1 `PolicyScriptChecks` always runs STANDARD flags and uses that
  prefix (not `non-mandatory-script-verify-flag-failed`). CLEANSTACK extra
  items on OP_TRUE/SHA1 spends were reported as consensus splits.

- **Mempool/script-verify fuzz `testmempoolaccept` uses `maxfeerate=0`:**
  Core v31 treats `0` as accept-any fee rate. Values above 1 BTC/kvB are
  rejected as RPC parameters; `10000` made every oracle call `RpcError` and
  muted both targets (zero comparisons). Default 0.10 remains skipped as
  `max feerate exceeded` when the arg is omitted.

- **Tip-follow `getdata` that a peer never answers is retried:** inflight
  hashes sat in `requested` / `asked_blocks` with no timeout, so a serve-cap
  skip (or compact miss) stalled catch-up for the rest of the session.
  `rpc_createmultisig` `generate(149)` then 3-node `sync_blocks` 60s could
  leave node0's tip off node1/node2. After 10s without a body, those hashes
  are forgotten and the header path is asked again.

### Added

- **Core functional `run` 68 → 71:** unmodified `p2p_v2_misbehaving`
  (EARLY_KEY_RESPONSE holds ellswift until v1-prefix mismatch, V2 handshake
  timeout, garbage-terminator / decrypt logs), `p2p_addrv2_relay`
  (post-verack `sendaddrv2` disconnect, addrv2 relay, oversized 1010), and
  `p2p_leak_tx` (`getpeerinfo.last_inv_sequence` / `inv_to_send`, batched
  `notfound`, serve an announced tx from the tip block).

- **IBD `getdata` serve reconstructs from Class A spans:** contiguous
  `header_txs` loads `txout.body` + `seqsigwit.body` as libc sequential preads
  (not per-tx `get_tx_full`), off the session reactor. Host probe:
  `scripts/ibd-serve-bench.py`.

- **Core functional `run` 67 → 68:** unmodified `p2p_addr_selfannouncement`
  (`-externalip` in `getnetworkinfo.localaddresses`, first addr message is
  the self-announce, mocktime re-announce). `IsInitialBlockDownload` latches
  false after the first leave (Core `m_cached_finished_ibd`).

- **Core functional `run` 66 → 67:** unmodified `p2p_leak` (no pre-verack
  pong, VERSION `addrFrom` 0.0.0.0:0, sendaddrv2/wtxidrelay only for
  nVersion ≥70016, obsolete version 31799 disconnect).

- **Core functional `run` 65 → 66:** unmodified `p2p_timeouts` (mocktime
  VERSION/VERACK timeout, `-peertimeout=3`, ping-before-handshake logs).

- **Core functional `run` 62 → 65:** unmodified `p2p_ibd_txrelay` (IBD
  MAX_MONEY feefilter, no tx getdata/accept), `p2p_fingerprint` (month-old
  stale serve withhold), and `p2p_mutated_blocks` (`getpeerinfo.inflight`
  plus merkle-mutated / missing-parent disconnect).

- **Tip-follow compact relay matches Core `NewPoWValidBlock`:** a
  reconstructed or received body whose header has valid PoW and extends
  the current tip is announced as `cmpctblock` to other high-bandwidth
  peers **before** `tip-accept` connect. Invalid body still keeps the
  session. `tip: accept` now names `lookup=` / `struct=` / `drain=` /
  `mp_strip=` / `other=` so the connect wall is not a silent remainder.

- **Q-30 height-1 differential fuzz vs Core v31.1:** nightly
  `block_differential` mutates a regtest height-1 block, runs in-process
  `ChainHub::accept_received_block`, and `submitblock`s the same bytes to
  official `bitcoind` (downloaded tarball, SHA256 in
  `scripts/core-functional/inventory.toml`). Compare accept vs reject only.
  Default `cargo test` does not fetch Core. Not a required PR check.

- **Q-30 mature-pad spend differential:** nightly `block_spend_differential`
  mines a byte-identical 100-block empty pad, then compares height-101
  blocks that spend the mature height-1 `OP_TRUE` coinbase. Same oracle and
  verdict-only contract. Default-suite pins use a 3-block pad for rewind
  keep-height only. Q-30 stays Open (BIP324 / P2P still later).

- **Q-30 2-block fork differential:** nightly `block_fork_differential`
  holds an equal-work sibling of a pad+1 stem, then compares the heavier
  child (reorg). Same v31.1 `bitcoind` oracle and verdict-only contract.
  Q-30 stays Open (BIP324 / compact P2P still later).

- **Q-30 BIP324 `v2_contents` ASan:** nightly libFuzzer feeds post-decrypt
  v2 application contents through `parse_v2_contents` + `try_decode`
  (`--sanitizer address`, no `bitcoind`). Q-30 stays Open.

- **Q-30 BIP324 session vs live Core v2 peer:** nightly `v2_session`
  completes VERSION/VERACK with official v31.1 `bitcoind` (`-listen=1`
  `-v2transport=1`), then encrypts fuzzed application contents on that
  session (`V2PlainSession`). Finding = our crash / ASan / failed
  handshake; Core dropping TCP on garbage is expected. Not a
  `submitblock` accept/reject compare. Q-30 stays Open.

- **Q-30 compact reconstruct vs live Core:** nightly `cmpct_differential`
  sends `sendcmpct` then a fuzzed BIP152 `cmpctblock` and compares
  empty-mempool `try_reconstruct` missing indexes to Core `getblocktxn`.
  Malformed compact that Core drops is skip. Not accept/reject; not a
  two-node reorg. Q-30 stays Open.

- **Q-30 script-mutating vs Core `submitblock`:** nightly `script_differential`
  spends the mature pad `OP_TRUE` coinbase into a fuzzer-owned scriptPubKey,
  then spends that output in the same block so the interpreter runs the
  bytes. Accept vs reject only. JSON corpora stay static. Q-30 stays Open
  (two-node compact reorg later).

- **Q-30 compact reorg via `drain_pending` vs Core:** nightly
  `cmpct_reorg_differential` mines the same pad+stem fork as
  `block_fork_differential`, but the hub inserts child then parent into
  pending and drains once (014/020). Core `submitblock`s parent then child.
  Accept vs reject of C / final tip only. **Q-30 Completed.**

### Fixed

- **Mempool/script-verify diffs skip Core standardness:** `scriptpubkey`,
  `nonstandard`, and non-mandatory script flags join fee/dust/RBF as
  COMPAT skip (not a consensus finding). RPC-only fuzz `bitcoind` uses
  `-acceptnonstdtxn=1` so OP_TRUE pad spends compare consensus. Skip-heavy
  jobs (`cmpct_differential`, mempool, script-verify) require ≥1
  comparison when runs ≥1000, not 10.

- **Weekly ~1h fuzz + compounding corpus cache:** `fuzz.yml` runs Sunday
  07:17 UTC with `-max_total_time=3600` (nightly stays 600s). Per-job
  corpus cache restore/save and crasher artifacts. New target jobs
  (N-reorg, CSV, mempool, script-verify, addrv2, inv/getdata, Electrum
  JSON). **Operator must push this workflow** (GitHub App cannot).

- **Q-31 fuzz seeds:** tiny existing `signet_block_*.bin` and
  `mainnet_block_290329.bin` merge into `block_wire` / `block_differential`
  corpora (copy-if-absent, remine onto regtest). Electrum hermetic packs
  still Open.

- **ASan parser jobs:** `addrv2_wire`, `inv_getdata_wire` (`parse_v2_regtest_named`),
  and `electrum_json` (`parse_electrum_request_line`). Junk must not panic.
  Nightly jobs wait on operator-pushed `fuzz.yml`.

- **Interpreter-only differential:** `verify_tx_scripts_detached` vs Core
  `testmempoolaccept` of the parent+spend package. No `submitblock` / remine
  per exec. Policy skips same as the mempool oracle.

- **Mempool differential vs Core `testmempoolaccept`:** same raw spend,
  `MempoolHub::test_accept` vs Core. **Consensus-class only** — Libre
  policy (dust, min-relay, RBF, cluster) is skip, not a finding (COMPAT).

- **N-block reorg and BIP68 CSV-age differentials:** `compare_fork_n_one`
  (side chain length 3 vs a 1-block stem) and `compare_csv_age_one`
  (version-2 spend of a mature coin with relative-height `nSequence`)
  vs Core `submitblock`. Nightly jobs land when the operator pushes
  `fuzz.yml`.

- **Differential fuzz mutates consensus fields:** leftover fuzzer bytes
  overlay extra-tx `nVersion` / `nLockTime` / `nSequence` / scriptSig /
  witness / taproot annex and same-block order. `script_differential`
  reads a version+witness prefix (`0x80`); a bare `OP_TRUE` seed is
  unchanged.

- **Nightly fuzz corpus compounds:** `fuzz-run.sh` merges committed seeds
  into an existing corpus (does not overwrite grown inputs), prints and
  passes libFuzzer `-seed`, copies `fuzz/artifacts` into `fuzz/crashers`
  on failure, and fails Core-oracle jobs whose skip-rate is mute
  (`Done N runs` with N≥1000 and fewer than 10 comparisons; skip-heavy
  cmpct/mempool/script-verify jobs need ≥1).

- **Inbound `tx` log is TRACE:** default INFO stays `ibd: progress`
  (Q-36). `p2p_ibd_txrelay.py` still matches `received: tx` because
  TestNode passes `-loglevel=trace`.

- **Nightly fork/cmpct-reorg Core rewind:** `reconsiderblock(side)` resets
  **descendant** fail flags, so the first unique child becomes tip again and
  the next child is equal-work `inconclusive` (`core not at pad tip`). Do not
  invalidate the side. After each child, `invalidateblock(child)` then
  `preciousblock(stem)`. Side stays a valid parked sibling.

- **Nightly Core-oracle uniquify extra txs and `reconsiderblock`:** corpus
  `tx[1]` still reused one spend txid after coinbase extraNonce, so BIP30
  filled a 1024-slot OA page (spend probe-exhaust). Every extra tx gets an
  output-script suffix. `invalidateblock` is sticky: unique fork/cmpct-reorg
  children then hit `bad-prevblk` (`core not at pad tip`). Stem/side restore
  `reconsiderblock`s before `submitblock`. Core-oracle jobs drop
  `RBITCOIN_TX_HEAD_BITS=21` and use tiny 16-bit `tx.head`.

- **Nightly Core-oracle coinbase extraNonce and RPC keep-alive:** same-height
  harness coinbases reused one txid, so rewind+reaccept BIP30-filled one
  1024-slot OA page (`block_spend` / `block_fork` probe-exhaust / `side
  reject`). Candidates stamp a BIP34 extraNonce (scriptSig ≤100, else first
  output). Core JSON-RPC uses one TCP connection (`Connection: keep-alive`)
  so rewind after ~15k height-1 accepts does not burn ephemeral ports.

- **Nightly Core-oracle rewind and default-spend uniqueness:** Core keeps
  every `submitblock` body; `invalidateblock` of the tip can activate
  another sibling at the **same** height, so rewind progress is a hash
  change (no 128-step cap; same-hash is stuck). Default missing-tx[1]
  spend appends a unique `OP_TRUE` script suffix so BIP30 does not fill
  one 1024-slot OA probe chain (`mix_txid` is SHA256(secret‖txid) and
  already spreads distinct txids). Core-oracle jobs use
  `RBITCOIN_TX_HEAD_BITS=21`.

- **Nightly fork/cmpct-reorg/spend differential harness:** Core
  `submitblock` of an equal-work sibling returns `inconclusive` (parked,
  not tip). Side-submit treated that as fatal (`side submit` on the first
  corpus item). Core-oracle jobs keep tiny **header** heads and set
  `RBITCOIN_TX_HEAD_BITS=20` so rewind loops do not fill 16-bit `tx.head`
  OA (probe-exhaust stays fail-closed).

- **Tip-follow FeeFilter no longer panics on the reactor:** session handshake
  called `min_relay_sat_kvb()`, which took a blocking `inner` read after
  #320's `assert_not_reactor`. The overlay is an atomic; `rebroadcast_unbroadcast`
  uses `try_contains` instead of blocking `contains`.

- **Tip-follow reactor never parks on mempool `inner`:** INV/getdata/compact
  use `try_read` (busy write skips that item). Accept commit, orphan
  promote, package, and reorg strip no longer hold `inner` write across
  Query or script verify. Compact fill clones matching bodies only, not
  the live set. Dropping a `tip-accept` join detaches instead of
  condvar-waiting on the worker. Esplora WS announce and mempool HTTP
  enter `BlockingRegion` on `spawn_blocking` (same assert as P2P).

- **Leftover hop-dump is not cleared by the next head-resolve batch:**
  `clear_leftover_miss` wiped `diag=1` at the start of every TipOnly
  resolve. Parallel `cargo test` failed `leftover_miss_dumps_probe_diag`;
  the operator reject line could also lose the dump. Miss classification
  is still per-batch.

- **Mempool accept does not run on a tokio worker:** P2P `tx` and Esplora
  `POST /tx` used `accept_tx` on the session/axum thread, holding
  `inner` write across store UTXO lookups. All workers parked; timers and
  P2P died. Accept is `spawn_blocking` (`BlockingRegion`); prepare uses a
  graph **read** lock. The node runtime caps blocking threads at nCPU
  (min 4).

- **IBD tip is most-work, not max advertised height:** a higher-height
  less-work fork (or bogus `version.start_height`) is `register_explore`
  only and does not raise the work-path horizon. Empty `headers` at a
  drained most-work path is EOF even if `max_peer_height` is hundreds
  ahead — restart-at-tip no longer chases that height.

- **IBD empty-headers lag no longer reseeds a live work path:** `getheaders`
  empty while peers advertise ahead still re-asks, but
  `seed_work_path_from_store` (full header-graph walk) runs only when
  `ordered` is empty. Latter mainnet IBD was walking ~1M headers every ~2s
  (0.5–1.2s each) while already holding 12k–64k ordered hashes. The matching
  WARN is `trace` unless the path is empty.

### Changed

- **IBD `getdata` span IO:** `txout.body` and `seqsigwit.body` span preads run
  in parallel (SSD one volume, or `--datadir-cold` split). BIP324
  `write_v2_contents` takes owned bytes (no extra `to_vec` on the serve writer).

- **Historical `getdata` serve meters on `tip: perf`:** per-block DEBUG
  `p2p: serve` is gone. The 5s line adds
  `serve n= bytes= ntx= avg_us= max_us=` (reconstruct+encode; not BIP324 send).

- **Tip-follow accept/relay CPU:** the 50 ms session INV tick no longer
  walks every live wtxid/`accept_at` once any tx is 30 s old. Age-INV is an
  append-only due log plus a per-peer cursor (inbound 30 s gate and
  `clock_due` / unbroadcast unchanged). Accept caches tip MTP until the
  header fk changes; `get_coin` skips create MTP unless a BIP68 time lock
  is present and skips `block_tx_fks` when the create's input-0 record
  exists; `index_txid` hashes prepare prevouts instead of re-Querying.
  Expiry skips the live walk while nothing can be old enough.

- **IBD main loop cadences housekeeping off the event path:** getdata
  assign (≤50 ms, immediate if inflight empty), main-loop `getheaders`
  locator walks (≤500 ms, empty path immediate), peer stall/relative-slow
  (≤1 s), and work-path hygiene (≤1 s) no longer run after every peer
  frame. Drain and confirm-offer stay event-driven. Full 2000-header
  continuation still fires from the Headers event. Cuts CPU/IO that was
  competing with confirm (64 k densify scans and `locator_hashes`
  header-table walks at event rate).

- **Tip connect runs on a dedicated `tip-accept` OS thread:** P2P reconstruct
  and RPC generate/submitblock no longer take `connect_lock` or run
  `confirm_wire_run_preverified` on a tokio worker. The peer awaits a oneshot;
  scripts still steal on `rbtc-scripts-*`. Not the IBD body-queue pipeline.

- **Electrum `blockchain.tweaks.subscribe`:** pre-taproot empty heights go out
  as **one notify** with ≤1024 keys (Cake last-key progress), not one line per
  height. Cake `historicalMode=false` (param `[2]`) **cut-through**: omit
  confirmed-spent P2TR outs (and txs with none left). Spentness is one
  `spent.idx` batch plus one spent-body walk per create, not a serial
  idx+body per eligible tx. `true` keeps spent outs
  for restore. Probe `[0,1,false]` is still `{"0": {}}`. `{"message":"done"}`
  ends a **chunk** (60s wall at a wave boundary, or the requested `count` if
  sooner) so Cake resubscribes; it is not “`count` through tip”.

### Added

- **Hornet block-validation matrix:** happy-path and boundary pins for every
  Hornet `spec.h` / spec.html rule (H01–S09), in the existing structure /
  header / connect suites (stripped-size 1 MB, per-tx oversize, duplicate
  inputs, null prevouts). Map: [`docs/peer-clients.md`](docs/peer-clients.md).
  Selector: `./scripts/test-hornet-rules.sh`.

- **Unsorted-shard SH materialize is the default:** tip finalize does one Class A
  `txout` pass into unsorted `scripthash.unsorted/NN` (nCPU collect, 1 MiB
  per-shard buffers, offset-ordered pwrite, 64 MiB fallocate extents), then
  unique-sorts each file **in place** and seals `head/NN` (~2 GiB per pack
  worker). Catalog k-way merge and Class A catalog recollect/spill are
  removed (`RBITCOIN_SH_RECOLLECT_WORKERS` / `RBITCOIN_SH_RECOLLECT_SPILL_BYTES`
  deleted). Leftover `scripthash.runs` are discarded at tip (never rematerialized).
  Collect workers are always nCPU. Class A collect body IO is libc `pread`
  (16 MiB spans), not TLS uring. SIGINT keeps sealed shards; missing `DONE`
  restarts collect.

- **Unsorted SH recs store the 16-byte head prefix:** each file rec is 24 B
  (`prefix16` + `create_fk`), matching the sealed head. `DONE` magic is
  `SHUNSRT3` and records the inclusive Class A create_fk scanned. Leftover
  `SHUNSRT2` / `SHUNSRT1` files restart collect. If Class A grows after `DONE`
  with no sealed shards, collect appends the tail into the unsorted files;
  if any `head/NN` is already sealed, pack finishes then Direct Class A tail
  backfill fills the gap (write-behind no-ops until Tip).

- **SH collect body IO is libc pread:** nCPU workers read coalesced 16 MiB
  `txout.body` spans with blocking `pread`. The TLS uring 5 s wait is a
  lost-CQE fence for 4 KiB lookup/g-page machines — not this path. Avoids
  `undrained pending=1` when n workers share the disk.

- **Peer full-node notes:** [`docs/peer-clients.md`](docs/peer-clients.md)
  compares Hornet Node and satd (tests and ideas to consider later, and
  explicit non-copies). Not a quality.md Open list.

- **Write `other=` classification:** `ibd: perf` names `pins=take+map`
  (plan Arc copies + create-pin FkMap) and `head_sub=` (tx.head drain
  submit). They join the write inventory so `other=` is the leftover
  residual. [`crates/rbitcoin-net/src/ibd/perf_log.rs`](crates/rbitcoin-net/src/ibd/perf_log.rs).

- **Structural lint / CRAP / Miri:** required `ast-grep` scan for discarded
  `tokio::spawn`, `mem::forget`/`Box::leak`, and dropped `thread::spawn`;
  `coverage.sh` prints a cargo-crap summary after the ≥90% LCOV gate (no
  CRAP-30 fail); nightly Miri on `rbitcoin-primitives` only. Further work
  is **Q-54–Q-56** in [`docs/quality.md`](docs/quality.md);
  how to run is [`TESTING.md`](TESTING.md).

- **Confirmed-tx chain view:** Electrum/Esplora responses for confirmed
  txs are built at one published tip and stamp that tip for the client
  (`X-Bitcoin-Chain-Tip` on Esplora; JSON-RPC `chain_tip` on Electrum).
  Same-height reorgs invalidate the SH join cache and change Electrum
  status (block hash in the preimage). Yuval raised the A-B-A hole;
  shape from [mempool#6584](https://github.com/mempool/mempool/issues/6584)
  and [electrum-protocol#2](https://github.com/spesmilo/electrum-protocol/pull/2).
  [`COMPAT.md`](COMPAT.md), [`docs/concurrency.md`](docs/concurrency.md).

- **As-of ancestor snapshot:** `?asof=<blockhash>` (Esplora) and a trailing
  Electrum `asof:<blockhash>` string on `get_balance` / `listunspent` /
  `get_history` / `transaction.get` / `transaction.get_merkle` return
  confirmed data as of a still-live best-chain block (scripthash reads
  are also capped at visible SH). Thanks again to Yuval — this is the
  buried-height half of binding confirmations to a chain. Stamp is the
  asof hash; unknown/disconnected → 404 / `asof not on chain`. The
  `asof:` prefix cannot be a later official hash/string arg. Clients
  negotiate protocol `1.4.2-asof` (`server.features.asof_protocol`);
  Electrum `protocol_max` stays dotted-int `1.4.2`.

- **Road to 1.0:** [`docs/road-to-1.0.md`](docs/road-to-1.0.md) owns 1.0
  product gates (claimed Core functional, Core-parity fuzz, selected
  crates.io libraries, SH/RSS, eclipse/DoS, fee validation, schema freeze).
  [`docs/quality.md`](docs/quality.md) stays the living Open backlog.

### Changed

- **Electrum thin tweaks serve:** indexed `blockchain.tweaks.subscribe`
  joins packed eligible create_fks with one `txid.body` range pread and
  a sequential idx walk, batches consecutive `sp_tweaks` heights (one
  idx + one body pread per segment), loads the JSON-RPC first height in
  the same Class A `txout` span as the first notifies, overlaps the next
  wave's load with the previous TCP flush, and skips zero-fill on the
  span pread. Default wave cap is **16384** eligible txs (128 heights
  unchanged). No `sp_tweaks` schema change.

- **Parallel `tx.head` wipe-rebuild:** ranges seal concurrently,
  min(CPUs, free RAM / **1 GiB**, range count). Distinct from SH
  materialize (1.5 GiB/worker). `RBITCOIN_TX_HEAD_REBUILD_WORKERS`
  overrides (`1` = serial).

- **`tx.head` seal uses less RAM:** uniqueness is an in-place sort (no
  per-key `HashMap<Vec>`), BDZ peel is XOR-degree with reused scratch
  (no CSR+edge list), fuse builds from the unique key vec, packed BDZ2
  streams `g[]` in 4 KiB pages. Wipe-rebuild default range is **2²⁵**
  keys (`RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS=26` still available). Same
  on-disk BDZ2. Live IBD roll-seal uses the same path.

- **`header.head` open-grow is sibling then rename:** undersized single-gen
  rewrite writes `header.head.grow`, fsyncs, then rename over the live file
  (`.mlt` kept). Crash during rewrite leaves the previous OA. A target-sized
  empty gen0 with a non-empty `header.body` / `.mlt` is Layout refuse
  (wipe `header.head`, `header.head.mlt`, `header.body`).
  [`SCHEMA.md`](SCHEMA.md), [`docs/concurrency.md`](docs/concurrency.md).

- **Tip-follow catch-up getdata matches serve cap:** connecting headers
  asked the whole path while a peer reconstructs at most 16 bodies.
  Extra hashes stayed in `requested` and were never re-asked
  (`sync_blocks` 60s overnight: `feature_minchainwork`,
  `rpc_createmultisig`, `feature_bip68_sequence`, …). First ask and
  drain continuation use `MAX_SERVE_BLOCKS`. Accepting a `CmpctBlock`
  (node-to-node `MSG_CMPCT_BLOCK` getdata) also drops the hash from
  `requested` so the next window can be asked. Writer saturating-subs
  `serve_inflight` so unpaired compact tip announce cannot wrap to
  `usize::MAX`. Announce does not occupy reconstruct slots (a burst of
  16 would skip later getdata). Coinbase-only compact fills from
  prefilled txs without a mempool.

- **Nightly Miri installs nightly:** `miri.yml` asked the CodeQL-pinned
  1.95.0 `dtolnay/rust-toolchain` snapshot for `components: miri` (that
  action has no `toolchain` input). First scheduled run died in 9s.
  Nightly + miri is a `rustup` step; product rustc stays 1.95.

- **IBD exits to tip follow at the peer horizon:** leftover off-path
  `getdata` is dropped so catch-up can complete; if peers then advertise
  a higher tip (`lag > 2`), `headers_done` unlatches and `getheaders`
  resumes. Near-tip (`lag ≤ 2`) still does not re-fan.

- **In-flight drop after last load batch of a wave:** lookup snapshots
  `drain_and_fence_hi` before TipOnly and passes it on the last load
  batch. After that batch's in-flight read, load drops map rows with
  pack height below the snapshot (equality keeps). Not Class C tip;
  `class_a_hi` is not a drop gate. Stamp walks the load-thread `InFlight`
  map then skeleton (IBD); leftover TipOnly for plan=None / S0.
  [`docs/invariants.md`](docs/invariants.md),
  [`docs/concurrency.md`](docs/concurrency.md).

- **In-flight is a load-thread map:** one `txid → fk` / `fk → CreatePin`
  HashMap with a height index (not `InFlightLog` layer snapshots). Insert
  after stamp so the current pack is invisible to that stamp. Disconnect
  `drop_from_height` on pack height.

- **Load-batch parent skeleton:** lookup TipOnly-fills `BatchParentIds`
  (fk + body/spent ranges + per-chunk need-vouts) onto each `LoadBatch`.
  Load binds same-batch → in-flight → skeleton → `Corrupt`. Published
  `live_union` / `PublishedIds` are gone. plan=None / S0 still leftover
  TipOnly. Lookup `wave=… spent=` is `tx_spent_range_batch` for those hits.

- **Confirm Class A kind per batch:** a load/write batch is all need-body
  (`plan=Some`) or all already-bodied (`plan=None`). Lookup splits loadq
  at `header_txs.has_body`; write drain stops on plan polarity. Mixed
  stamp is `Corrupt("invariant: confirm batch mixed archived")`. Write
  vs tip is all-old (`Ok([])`), all-new (fill zip), or
  `Corrupt("invariant: write batch spans tip")` — no prefix strip.
  [`docs/invariants.md`](docs/invariants.md),
  [`docs/concurrency.md`](docs/concurrency.md).

- **Pin `merge_outs` no-op Arc:** empty / already-covered `checked`+`live`
  keep the outs Arc (assemble sticky `ptr_eq`). RCU compose borrows `live`
  instead of cloning script bytes on every retry.

- **IBD Class A ins at write:** `confirm_wire_lookup_stamp` plans from
  wire (`archive_plan_batch_from_wire`) without `TxApply`. Packed ins stay
  empty; SpendEdges + CreatePin remain. Write encodes ins from `Arc<Block>`
  + those edges. CreatePin outs stay stamp-time for in-flight.

- **Retire `docs/algo-review.md`:** remaining worth-fixing items are
  **Q-57–Q-60** in [`docs/quality.md`](docs/quality.md) (store publish/flush,
  mempool persist/eviction, RPC/CLI honesty, P2P caps). Inventory, gotchas,
  and micro-opts are not a second backlog.

- **`load_thr stamp=` nest:** `ibd: perf` prints
  `stamp=Nms(pack=Xms head=Yms)`. `head=` is leftover TipOnly
  (`prep_head_fk_ns`). After a lookup wave publishes a parent, load
  stamp leftover for that parent is 0 — pack stays on load.

- **Held tx.head `.rel` pread:** after fail-closed `begin_batch` (`f07415b5`),
  a poisoned leftover ring made `pread_batch_on_ctx` return false and
  `read_rels_batch` opened a second TLS uring — nested panic on
  `ibd-confirm-lookup`. Held failure is now `Corrupt`; `pread_batch` only
  when `IoCtx` has no session.

- **Algo-review S-H1:** HashHead / ScriptHashHead no longer rewrite occupied
  tables while serving. Mainnet `header.head` creates at 2²² slots (~96 MiB
  sparse). Overflow rolls `header.head.gN`. Undersized single-gen files
  rewrite on open. Ingest SH seals at 0.80. `ShardedHashHead`,
  `HeadRole::ScriptHash`, and `rehash_gate` are deleted. Leftover 256-way
  `header.head/` is Layout refuse.
  ([#248](https://github.com/reardencode/rbitcoin/pull/248)).

- **Algo-review P7/P8/P10/P16:** leftover TipOnly fence snapshot is
  `Arc` (COW on extend). Densify assign resumes after the BQ-ready
  prefix. BIP324 v2 decode is command+payload (no sha256d checksum, no
  v1 reframe). Fence-tip BIP113 MTP is an 11-slot ring.
  ([#245](https://github.com/reardencode/rbitcoin/pull/245)).

- **Algo-review P1–P3:** BIP339 wtxid inv is a `TxGraph` map (no mempool
  scan under the lock). Best-chain cumulative work is a RAM prefix
  (~32 B × tip), not a genesis walk per unrequested body / `chainwork`.
  Mempool `worst_chunk` is an ordered cluster-rate index.
  ([#244](https://github.com/reardencode/rbitcoin/pull/244)).

- **BQ assign-stop 1 GiB:** `RBITCOIN_BLOCK_QUEUE_GB` / `_BYTES` no longer
  refuse enqueue. Default 1 GiB densify assign-stop (`0` = unlimited): fill
  holes through the already-fetched height horizon; do not grow past it.
  [`docs/ibd-memory.md`](docs/ibd-memory.md).

- **Idx fill windows io_uring SQ:** unique `tx.idx` page preads harvest when
  the session is at in-flight cap (same shape as BDZ / bulk_io). SQ full is
  `BudgetFull`, not `corrupt record`. Lookup retries it at debug, not WARN.

- **RecentCreates layers:** write publishes one Arc layer per Class A batch
  (shared splice with live_union; no full-map clone). Drop when Class A has
  covered `lookup_started_hi` at publish. Stamp carries CreatePin so pin does
  not re-walk the ring. [`docs/ibd-memory.md`](docs/ibd-memory.md).

- **Headers sync locator:** a full 2000-header reply continues `getheaders`
  from that last hash (not our tip locator). Periodic poll skips a peer
  whose best-known header is already on our chain behind tip, or a
  connecting fork that cannot beat us. [`docs/ibd-memory.md`](docs/ibd-memory.md).

- **Tip-follow peer set:** disconnect sessions whose connecting header tip
  cannot beat us and is more than 288 blocks behind (BIP-110-class minority
  forks). Stale-tip extras no longer grow past `max_outbound`; at cap a
  random outbound is rotated for a new addrman addr. GetData reconstruct
  queues at most 16 full blocks per session; per-peer `pending_blocks`
  evicts at 128. [`docs/ibd-memory.md`](docs/ibd-memory.md).

- **Cargo.lock compatible bumps:** `bitcoin-consensus-encoding` 1.2.0,
  `cc` 1.4.4, `find-msvc-tools` 0.1.11, `futures-channel` 0.3.34,
  `http-body-util` 0.1.5, `log` 0.4.34, `rand` 0.8.8, `syn` 3.0.4,
  `zerocopy`/`zerocopy-derive` 0.8.56. Direct crates already at latest
  compatible; skipped `bitcoin_hashes` 1.x and `tokio-tungstenite` 0.30
  (axum 0.8 still on 0.29).

- **Two SH methods only:** a durable scripthash head stays Tip (short
  catch-up uses write-behind, leftover runs discarded). No head: Direct
  defers SH; post-IBD Class A recollect + FullCold/ColdResume. Removed the
  IBD memtable→runs worker and WarmOnly apply-onto-live-head (mainnet
  2026-08-25 `fk stream zero delta` on a 12-block catch-up).

- **Tip accept does not wait on scripthash:** Class C publishes `confirmed[]`
  then enqueues collected SH records onto a RAM head; `rbtc-sh-wb` seeds the
  durable index only after tip announce (`release_sh_writebehind`). Wallet SH
  reads join that RAM head at live tip so mempool can drop confirmed txs
  without a hole. Reorg reaccepts into the mempool overlay before dropping
  pending. Headers subscribe stays live tip. `tip: accept` now `sh_lag=`
  and `tweaks=`; worker logs `sh: apply h= wall= lag=`.

- **SH workers follow free RAM:** recollect and k-way materialize default to
  at most **one worker per 1.5 GiB** host free RAM (Linux `MemAvailable`,
  Darwin free+inactive pages, Windows `AvailPhys`; unknown OS → 1 worker).
  Unset env is auto; `RBITCOIN_SH_RECOLLECT_WORKERS` /
  `RBITCOIN_SH_MERGE_WORKERS` still override (`1` = serial). Start logs
  include `free_GiB=`.

### Removed

- **RecentCreates ring and `PipelineParentStore`:** write no longer clones
  a second identity+outs layer list; IBD never used the Weak pin registry.
  `ibd: sizes` `recent=` / `pstore=` stay 0. CreatePin outs live on
  in-flight keep-until and batch-local `BatchParents`.

- **Dead production APIs:** SH catalog materialize is always k-way (no
  fan-in reduce / CHECKPOINT / READY, no `RBITCOIN_SH_MERGE_FANIN` /
  `TARGET_RUN_BYTES` / `MAX_DIRECT_MERGE`). One catalog write policy (no
  L0 / paced IBD / DURABLE alias). Unused Store `*_at` body helpers,
  `header_head_occupied`, `header_body_contains`, `flush_index_tables`,
  `for_each_strong`, `BlockQueue::load_all`. `RBITCOIN_IO=mmap` is no
  longer a silent pread. No-op SH `stop_and_drain_spills` and unused
  `archive_plan_batch_from` / `archive_plan_batch_owned` wrappers.
  Unused `NodeClock::mock_value`, `ChainParams::min_difficulty_target`,
  `outbound_for_ibd`, `InvalidHashSet::{mark_path,is_invalid_fn}`,
  `MempoolHub::mining_frontier_snapshot`, `ConfirmParentCache::get_header_plan_arc`,
  `NodeConfig::with_datadir_cold`.

### Fixed

- **IBD catch-up complete ignores leftover explore/orphan getdata and
  competing `hash_height`:** exit uses connected-path remainder vs peer
  height (one-block version chatter). Empty path with a missing tip+1
  keeps `getheaders` instead of latching `headers_done` two blocks short
  of the horizon.

- **Esplora mempool-only tx JSON includes vin/vout/size/weight:** Class A
  miss uses the mempool wire body (`GET /tx`, `/txs`, `/txs/mempool`, WS
  address-transactions). No more txid+fee stub.

- **Mempool `relay_seq` / `accept_at` drop on unindex:** confirm, RBF, and
  eviction no longer leak per-admit INV maps for the process lifetime.

- **Electrum subscribe status row order matches `get_history`:** confirmed
  height-asc, then mempool tail (no `sort_by_key` on height). Extra
  confirming `blockhash` in the preimage is unchanged (A-B-A).

- **`testmempoolaccept` is dry-run:** `MempoolHub::test_accept` runs
  prepare + scripts + RBF/cluster checks without commit, announce, or
  conflict eviction.

- **RPC `getrpcinfo` active list is id-keyed:** concurrent `dispatch`
  no longer `pop()`s the wrong in-flight command.

- **Headers-sync stall timeout runs in production:** the 50 ms session
  tick calls `PeerHub::on_session_heartbeat` →
  `check_headers_sync_timeouts`.

- **Inbound VERSION/VERACK handshake has a 60 s bound:** timeout is
  `NetError::Timeout` and drops the `max_inbound` permit.

- **Script-pool wave `failed` is Acquire/Release:** a worker cannot enter
  a wave after the publisher observed `in_wave == 0` (ARM).

- **Signet matches Core BIP141 last-commitment + challenge flags:** last
  exact 38-byte `6a24aa21a9ed` output; verify with P2SH, WITNESS, DERSIG,
  NULLDUMMY (not CLEANSTACK / Base-only eval).

- **Assemble checks future-time and BIP34/66/65 nVersion on every block,**
  not only headers-first `validate_header` (pipelined / multi-block confirm).

- **Witness sigops only after segwit:** `GetTransactionSigOpCost` witness
  component is gated on `segwit_active_at` (pre-segwit P2WPKH-shaped prevouts
  no longer add 1).

- **P2SH sigops match Core GetSigOpCount(scriptSig):** opcode `> OP_16` yields 0.

- **Regtest subsidy halves every 150 blocks** (Core `nSubsidyHalvingInterval`).

- **Coinbase (and every tx) with empty vout is rejected:** Core
  `bad-txns-vout-empty`, including the coinbase.

- **Testnet 20-minute min-difficulty:** off-interval headers with
  `time > prev + 2×spacing` use powLimit bits; otherwise walk back to the last
  non-min-diff block (Core `GetNextWorkRequired`).

- **P2SH scriptSig matches Core EvalScript + IsPushOnly:** `OP_1NEGATE` is a
  valid push; scriptSig >10 000 bytes is rejected. Finding 006 520-byte pin kept.

- **BIP342 tapscript validation-weight budget:** script-path CHECKSIG /
  CHECKSIGADD with a non-empty signature subtracts 50 from
  `50 + witness_serialized_size`; remaining `< 0` fails (Core
  `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT`).

- **Truncated PUSHDATA2/4 no longer counts leftover opcodes as sigops:**
  `script_sigop_count` stops when the length field or body overruns, matching
  Core `GetOp` / `GetSigOpCount` (`[0x4d, 0xac]` is 0, not 1).

- **SIGINT after `clean exit` no longer waits on peer header walks:** tip-follow
  sessions walked pending headers with a store lookup per step (`knows_header` /
  `header_height`), so a 2000-header stale-fork reply could peg the Tokio
  runtime for ~90s after shutdown logged (mainnet 2026-08-25, `disconnect stale
  fork tip announced=961638`). Walks are RAM-first (one store lookup at the
  join). Shutdown `request_disconnect`s live peers, aborts nested inbound/dial
  sessions, timeout-joins, and the process runtime uses `shutdown_timeout(2s)`.

- **io_uring drain fail-closed:** `drain_all` treats unmatched CQEs and CQ
  overflow as `Corrupt` (no longer ignored). `begin_batch` returns `Err` on a
  poisoned session or leftover that cannot drain. Held idx fill (`fill_idx_pages`)
  propagates that error instead of libc-falling back on a dirty TLS ring (that
  mixed `KIND_BULK_PREAD`/`KIND_IDX` into BDZ g-page harvest as
  `bdz g page bad slot` / leftover CQE). Invariant WARNs fire on every hit with
  `pending=` / `epoch=` / `thread=`. [`docs/concurrency.md`](docs/concurrency.md).

- **Tip `--sptweaks` write-through:** after backfill completes, every tip
  block indexed tweaks on the confirm wall. A pin miss on a *non-P2TR* tx
  failed the whole height into `tweaks_for_height` (Class A + secp). Ineligible
  txs now skip the prevout walk; spend lookup is a map. `tip: accept` shows
  `tweaks=`. Regression:
  `ineligible_external_spend_does_not_fail_the_height`.

- **Held io_uring leftover CQE vs BDZ g-pages:** lookup TipOnly resolve shares one TLS ring across OA probe, idx, sealed MPHF `g` pages, and rel preads. A swallowed `drain_all` left `KIND_BULK_PREAD` in `pending`; the next `stream_g_pages` harvested it as `bdz g page bad slot` and could park on unbounded `submit_and_wait`. `begin_batch` now drains leftover SQEs first; machines match `(kind, epoch, slot)`; undrained/unexpected/wait-timeout poison the session and drop the TLS ring. Caps `submit_and_wait_one` at 5 s.

- **Nightly fuzz vs musl cargo-fuzz:** `taiki-e/install-action`'s
  `cargo-fuzz` is a musl binary, so `cargo fuzz run` defaulted
  `--target x86_64-unknown-linux-musl` and ASan refused
  (`sanitizer is incompatible with statically linked libc`).
  `scripts/fuzz-run.sh` now passes rustc's host triple (gnu on the
  GHA runner).

## [0.5.2] — 2026-08-23

Tagged on the **0.5.1** maintenance line (`v0.5.x`), not as a master ancestor.
The same tapscript fix is on master.

### Fixed

- **Tapscript initial witness stack ([023](docs/external_findings/023-tapscript-initial-stack-limits.md)):**
  after the BIP342 OP_SUCCESS scan, tapscript now rejects an initial
  stack over 1000 items (`stack size`) and any initial element over 520
  bytes (`PUSH_SIZE`), matching Core `ExecuteWitnessScript`. OP_SUCCESS
  still overrides both. Regression:
  `script_path_rejects_initial_stack_over_max_size`.

## [0.5.1] — 2026-08-22

Workspace version **0.5.1**. Consensus + Electrum serve fixes on the 0.5 line.

### Fixed

- **Script stack size vs altstack ([022](docs/external_findings/022-stack-altstack-share-max-size.md)):**
  `push()` and `OP_TUCK` counted only the main stack against `MAX_STACK_SIZE`.
  Core shares 1000 across **stack + altstack** on every push (including
  `PushBytes`). Combined overflow now rejects (`stack size`). Regression:
  `stack_and_altstack_share_max_size_on_pushdata`.

- **Electrum silent-payment tweak serve:** indexed join is one sequential
  `txout` span per wave (not one body pread per eligible tx). Pre-taproot
  empty Cake maps flush in ≤1024-height waves. `server.ping` does not drop
  an in-flight wave.

### Changed

- **PR CI OS smoke:** `ci.yml` `windows` / `macos` jobs run native store
  platform tests (TableFile, SH free-RAM probe, pool/IOCP session, default
  `RBITCOIN_IO` kind) + `--smoke` on every PR and master push. Operator
  binaries are GitHub Releases only (`release.yml`). Snapshot workflows
  `musl.yml` / `windows.yml` / `macos.yml` and the `static-binaries` label
  are gone.

- **`getnetworkinfo.version`:** `rpc_client_version("0.5.1") == 501`.

- **Release script:** `./scripts/release.sh` on clean `master` checks
  Cargo/nix/CHANGELOG, creates annotated `vX.Y.Z`, and pushes **master
  + the tag** (`release.yml` builds the snapshots). `--dry-run` /
  `--no-push`.

## [0.5.0] — 2026-08-22

First **named published** 0.x line. **Not 1.0.** Schema 19 is still bumpable
(named refuse/wipe, no silent wipe). Default mainnet `--milestone 840000`
skips historical script/sig checks (`--milestone 0` is full scripts).
`--shindex` default off (required for Electrum/Esplora). BIP324 v2-only.
GitHub Release: Linux musl (operator) + Windows CRT-static PE + Darwin
aarch64 binaries + SHA256SUMS (ad-hoc signed, not notarized). In-tree `fuzz/` `block_wire`
nightly job (not a required PR check). P2P DoS is not Core-parity.

### Added

- **Fuzz (Q-30 min):** isolated `fuzz/` workspace, `block_wire` target on
  `check_block_wire` (consensus-encoded block → archive structure). Nightly
  `.github/workflows/fuzz.yml` (not a required PR check). Operator may need
  to push the workflow file.

- **Tag GitHub Release:** `.github/workflows/release.yml` on `v*.*.*` builds
  musl + Windows + Darwin snapshots and attaches them (Linux SBOM included).
  `workflow_dispatch` builds artifacts only. Operator may need to push the
  workflow file.

- **`rbitcoin-bench`:** optional Electrum/Esplora **client** benchmark (not
  default-members, not musl). Casa sequential median (`get_balance` /
  `get_history` / `listunspent`), Sparrow batched subscribe+history, fat-key
  `hot` suite. Embedded `--corpus` lists: `hot` (P2A + public high-tx
  addresses), `casa`/`sparrow` unique scripts sampled from 77 heights
  genesis→tip on a mainnet store (not one 200-block window).
  Stderr progress: 5% steps plus at most one line per 15s, with ETA.
  `--out FILE` writes a per-key CSV (heights, tx/utxo counts, warm
  latencies per query). `--suite clients` runs N concurrent small-wallet
  loads on one OS thread (`--clients`, default 8; corpus default
  `sparrow`; keys over `--max-txs`/`--max-utxos` dropped).
  `cargo run -p rbitcoin-bench --features cli --release`.

- **CI Windows / Darwin snapshots:** after a green `ci` run on
  `master`/`main` (and on `workflow_dispatch`, and on PRs labeled
  `static-binaries`), workflows `windows` and `macos` upload CRT-static
  PE and system-dylib Darwin `rbitcoin-node` / `rbitcoin-cli` +
  `SHA256SUMS` (90 days). Not required checks. `musl` uses the same
  label. Linux musl stays Nix; Darwin/Windows are native runners.

- **`generateblock submit=false`:** mine one block without connecting it
  and return `{hash,hex}` for `submitheader`. `output` accepts `raw()`
  descriptors.

- **`getblockstats`:** reconstruct the block and return Core fee / UTXO /
  weight fields (`hash_or_height`, `stats`). Genesis is excluded from
  actual UTXO counts; `OP_RETURN` is unspendable. Even `medianfee` is the
  integer mean of the two middle scores (Core `CalculateTruncatedMedian`).

- **`docs/errata.md`:** RAM leftover maps are one fk per txid. Pre-BIP30
  clobber is correct enough; post-BIP30 a disconnected sibling in those
  maps is an unlikely visibility hole, not the n−1 leftover miss.

- **`getmempoolcluster`:** cluster weight, tx count, and mining chunks
  (modified fees) from the live graph.
- **Test RPC proxy** (Core functional suite only): utility RPCs
  (`createrawtransaction`, `signrawtransactionwithkey`, `createmultisig`,
  `combinerawtransaction`, decode helpers) and an Esplora-backed wallet
  façade (`createwallet`, `importdescriptors`, `send`, `listunspent`, …)
  live in the bitcoind shim, not on `rbitcoin-node`.
- **Mempool verbose fees:** `getrawmempool` / `getmempoolentry` emit
  `fees.{base,modified,ancestor,descendant,chunk}` and `chunkweight`.
  `prioritisetransaction` deltas flow into modified/ancestor/descendant/chunk
  and into min-relay admission (free tx + delta can enter).

- **Core `-testactivationheight` overlay:** `name@height` (regtest) is parsed
  on `rbitcoin-node` and applied in `ChainParams` (`csv` / `segwit` / `bip34`
  / `dersig` / `cltv`). Script flags still follow the getters in a later
  confirm step. Shim forwards consensus/mempool/peer flags
  (`whitelist`, `blocksonly`, `minrelaytxfee`, `permitbaremultisig`,
  `limitcluster*`, `peertimeout`, `maxconnections`, `persistmempool`,
  `minimumchainwork`) instead of dropping them. `-minimumchainwork` keeps
  the node in IBD (no relay) until tip work meets the hex floor. There is
  no `-txindex` flag: Class A always looks up by txid. Core v31.1
  ancestor/descendant limit flags stay ignored (they are no-ops there).

- **Core functional coverage:** analog scenarios for `--milestone` skip-below /
  check-above, reconstruct after lost RAM head, and durable mempool reopen
  (`crates/rbitcoin-test/tests/core_analogs.rs`). Inventory `analog=` is
  required on `rpc-missing` as well as prune / LevelDB / UTXO-set skips.

- **MiniWallet + receive-block path:** `generatetodescriptor` (`raw(HEX)`),
  `scantxoutset` over Class A, `gettxout`, `getindexinfo` (Class A tx
  lookup), `getchaintips` (active tip), `waitforblock*`. Generate includes
  mempool txs then `remove_for_block`. `sendrawtransaction` maps accept
  rejects to Core `-26` strings. `submitblock` and P2P `block` share
  `ChainHub::accept_received_block` (hold never-confirmed side bodies,
  `accept_branch` on more work). Once-confirmed losers stay in Class A.
  Not a coins-DB / GBT product.

- **Core functional `run` set:** 14 unmodified scripts (first-green nine plus
  `rpc_getchaintips.py`, `rpc_invalidateblock.py`, `rpc_preciousblock.py`,
  `feature_csv_activation.py`, `feature_bip68_sequence.py`).
  `feature_nulldummy.py` is run (stateless raw-tx + ignored `-addresstype`).

- **`echo` + mixed `{args, argN}`:** Core testing RPC and AuthServiceProxy
  mixed named+positional. Inventory marks `rpc_named_arguments.py` `run`.

- **rbitcoin 199-block cache:** `create_cache.py` mines 199 via `generate`
  into `scripts/core-functional/cache/store`. `run.sh` preseeds empty Core
  `blocks/`+`chainstate/` and `--keepcache`; the shim copies our store into
  cache-shaped dests only.

- **`invalidateblock` / `reconsiderblock` / `preciousblock`:** disconnect
  via `ChainHub`; reconsider reconstructs from Class A; precious prefers
  an equal-work sibling (held or archive).

- **Debug.log mapper:** `scripts/core-functional/debuglog_map.toml` plus
  shim line pump. First extra Core script: `rpc_uptime.py` (setmocktime
  range + uptime ignores mock).

- **Regtest `setmocktime`:** `NodeClock` (AtomicI64; `0` = wall). Generate
  timestamps and future-header checks honor the mock. Not a process
  `time()` hook (log stamps stay wall).

- **Live `getpeerinfo` / `addnode` / `disconnectnode` / `addconnection`:**
  sessions register after BIP324 handshake. `addnode onetry` dials via the
  same outbound path as tip-follow. `subver` is the peer's version UA
  (our `-uacomment` is advertised on our `version`). `bytesrecv_per_msg.pong`
  is counted so Core `connect_nodes` can wait for handshake.

- **`syncwithvalidationinterfacequeue`:** no-op `null`. Core’s framework
  calls it from `sync_mempools`; we have no wallet/index callback queue.

- **First unmodified Core functional scripts:** inventory marks
  `feature_help.py` and `feature_uacomment.py` `run`.
  `scripts/core-functional/run.sh` invokes those two via Core’s
  `test_runner.py` (still never from default `cargo test`).

- **Regtest generate / submitblock (harness only):** `generatetoaddress`,
  `generateblock`, `generate`, and `submitblock` mine or accept through
  `ChainHub::accept_block` (same confirm path as P2P). Refused on mainnet /
  signet / testnet. Not a mining product (no GBT).

- **Core v31.1 submodule is the JSON source:** `third_party/bitcoin` is a
  shallow gitlink at `9be056a`. `cargo test` hard-links or copies
  `script_tests.json` / `tx_valid.json` / `tx_invalid.json` from
  `src/test/data` into `$CARGO_TARGET_DIR/core-data` every run (no in-tree
  copies). Missing pin: the fixture helper and `scripts/coverage.sh` run
  `./scripts/core-functional/init-submodule.sh` (sparse ~16 MiB).
  `sync-core-fixtures.sh --check` requires the three files in the submodule
  and none under `tests/fixtures/`.

- **Local extras after the v31.1 pin:** rust units for CHECKSIGVERIFY /
  CHECKMULTISIGVERIFY then `OP_1` (VERIFY must abort), empty-stack CLTV,
  and CLTV/CSV `0x80` (scriptnum −0) not taking the negative branch.

- **Core functional nightly job:** `.github/workflows/core-functional.yml`
  runs `scripts/core-functional/nightly.sh` on cron, `workflow_dispatch`,
  and PRs labeled `core-functional`. Unlabeled PRs keep cargo gates only.
  The job warns — does not fail — when a newer final Bitcoin Core release
  exists than `inventory.toml` `pin` (semver of published finals, not
  GitHub `/releases/latest`). Bump the submodule, fixtures, and inventory
  when it fires.

- **Core functional bitcoind shim:** `scripts/core-functional/bitcoind`
  starts `rbitcoin-node` from TestNode argv (`-datadir` → `DIR/regtest`
  so the cookie is `{datadir}/regtest/.cookie`). Clean chain:
  `getblockcount` is 0; RPC `stop` shuts down. Not the operator CLI.

- **Core functional runner:** `scripts/core-functional/run.sh` invokes Core
  `test_runner.py` only for inventory `run` names (`--v2transport`,
  `--exclude` every skip). A skip name fails `not in run set`. `--list` /
  `--dry-run` need no node. Default `cargo test` does not call it.

- **Core functional inventory (v31.1):** `scripts/core-functional/inventory.toml`
  classifies every Bitcoin Core `test/functional/*.py` (`run` / `skip` +
  reason; `analog` required for prune / LevelDB / UTXO-set skips).
  `python3 scripts/core-functional/check_inventory.py` fails on an unknown
  or incomplete row. See [`docs/core-functional.md`](docs/core-functional.md).
  No Core scripts run in default `cargo test` yet.

- **`--datadir-cold PATH`:** Class A `seqsigwit.body` / `seqsigwit.idx/` (cold; ~486 GiB
  on mainnet) live under `{PATH}/store` when set. `--datadir` still holds every
  other file (`txout`, `spent`, heads, mempool, peers, cookie). Omit the flag
  and both hot and cold files stay in `--datadir`. Conf: `datadir-cold=`.
  Existing split: move `seqsigwit.body` + `seqsigwit.idx/` yourself; the hot store
  records `seqsigwit.reloc` so a later open without the flag refuses.

- **CI musl artifacts:** after a green `ci` run on `master`/`main`, workflow
  `musl` builds `nix build .#rbitcoin-musl` and uploads
  `rbitcoin-node` / `rbitcoin-cli` + `SHA256SUMS` (90 days). Not a required
  PR check. Manual retry: Actions → musl → Run workflow.

- **IBD write meters:** `tweaks=` on `ibd: perf` / `perf_dbg` and `confirm write slow`
  (BIP-352 index wall after spend annotate). Makes the `--sptweaks` write-thread
  cost visible in the fat-era IBD hole.

- **`--sptweaks`:** optional thin BIP-352 index (`sp_tweaks.idx` / `.body`).
  Persist is `len:tweak` only (0 or 33-byte compressed `A_tweak`). Cake outs
  join `txout`. Confirm appends; reorg truncates; background backfill.
  Electrum still serves naive when the flag is off or a height is a hole.


### Changed

- **0.5 operator voice:** README / SECURITY / experimental-mainnet treat
  **0.5.x** as the named published 0.x line (not 1.0, not a soak badge).
  Default milestone skip, `--shindex` off, and schema refuse/wipe stay
  unmissable. Workspace version **0.5.0**.

- **`getnetworkinfo.version`:** pin `rpc_client_version("0.5.0") == 500`
  (`major*10000+minor*100+patch`, same as `0.1.0` → `100`).

- **Core functional inventory:** skip reason `rpc-dialect` for COMPAT-done
  methods whose unmodified script still fails on type-check / field zoo.
  `rpc-missing` is only “method not implemented.” Analog required.

- **Schema upgrade one-pager:** [`docs/operator/storage.md`](docs/operator/storage.md#schema-upgrade)
  copy-paste for 17 populated `tx.head` / `scripthash*` (wipe those dirs, keep
  Class A), 18→19 `meta` rewrite, and kill-9 → crash-recovery. Byte layout
  stays [`SCHEMA.md`](SCHEMA.md).

- **RPC docs:** permanent gaps no longer call GBT a non-goal. Template RPC is
  the cluster-chunk selector (no stratum / testdummy); `generate*` stays
  regtest harness. Matches [`COMPAT.md`](COMPAT.md).

- **SH materialize resume:** [`OPERATOR.md`](OPERATOR.md) `--shindex` section
  documents abort/resume: keep `scripthash.runs`, sealed shards stay, restart
  packs unsealed shards only. Not a schema bump.

- **SH decode-into + drop ShEntry:** page/slab decode appends into a caller
  `Vec<Fk>`. Collect, tip pack, and `put_chain` work on `Fk`. Query history
  uses `create_fks`. `ShEntry` / `ScriptHashEntry` are gone. On-disk pack8 /
  slab / page bytes are unchanged.

- **SH pack write-behind:** sequential slabs append to a 16 MiB session
  `body_buf` (one `pwrite` per flush; HWM persist at shard seal). Slab and
  page encode write into a caller buffer; 1-FK keys stay head-only with no
  heap collect; megakey pages encode the delta stream once. `recs` hold
  `u64` pack8 through `MphfHead::write_pack8`. Stage timers
  (`merge`/`pack`/`mphf`/`body_flush`) are disjoint; pack-only
  `head_fill_ns` is 0. On-disk pack8 / slab / page bytes are unchanged.

- **SH recollect / tip materialize:** catalog spill writes outside `runs_io`,
  a bounded writer queue overlaps Class A scan with catalog fsync, pack
  reuses one FK scratch, and BDZ peel uses CSR adjacency (same `BdzMphf::build`
  for SH and `tx.head`). Stage timers (`merge`/`pack`/`mphf`/`body_flush`)
  are real. Catalog and SH head bytes are unchanged.
  `RBITCOIN_SH_RECOLLECT_SPILL_BYTES` overrides the 128 MiB default
  (16–512 MiB).

- **Quality reaudit (2026-08-21).** [`docs/quality.md`](docs/quality.md)
  refreshed against #177: schema **19**, Core functional **44/267**,
  confirm no-coord / park / head-drain and SH last-page extent called
  Completed. Open ranking unchanged (Q-30 fuzz still rank 1). Won't-fix
  adds headerless SH interiors, script coordinators, flattening uring
  machines, process pin FIFO, and `rbitcoin-bench` in required CI.

- **Quality cheap wins:** confirm queue owner docs match **14/4/14**.
  **Q-34** first hour is [`OPERATOR.md`](OPERATOR.md) (regtest mine →
  Electrum → Esplora). **Q-36** default INFO is `ibd: progress`;
  `ibd: perf` / `ibd: sizes` are DEBUG. **Q-50** closed (named `other=`
  residual). Inline tests moved out of `peer.rs` / `methods.rs` /
  `scripthash.rs`. Dead `ConfirmEvent::BodyMissing` removed.

- **tx.head drain thread:** confirm write-behind insert runs on a process-wide
  `ibd-confirm-head` OS thread overlapping structural + Class C, instead of a
  per-batch `thread::scope` spawn.

- **Script coordinators removed:** `ibd-confirm` publishes script waves itself
  (lock-free `next` / `in_wave` / `failed`), writes completed batches in
  height order, and feeds `scriptq` when steal is empty (up to 4 in-flight).
  A script reject finishes leftover inflight heights without write and keeps
  taking `scriptq` (cancel still stops); start-fail keeps the batch meta.
  `SCRIPT_NS` is publish → first complete (not write-queue pop). Steal
  workers unpark the publisher on wave complete; load unparks on `scriptq`
  send. No `rbtc-script-coord-*` threads.

- **Query-path `api:` / `sh_join` / tweaks timing are TRACE:** one line per
  Electrum/Esplora/RPC call (and per slow SH join) flooded DEBUG during
  wallet/bench load. `--api-log` JSONL is unchanged. Connect/disconnect
  stay INFO.

- **Serve lean (Electrum / Esplora / RPC):** block txids, merkle proofs, and
  `getblock` verbosity 1 read `txid.body` (no packed `txout`). Esplora `/txs`
  uses SH join fks. `/utxo` matches Electrum mempool listunspent. History
  `to_height` skips Class A expand for later creates. Parent prevouts are
  outs-only. Electrum scripthash subscribe restatuses on confirming tip
  when the block creates or spends that hash (posting-list probe).

- **Esplora `/utxo`:** status comes from the SH join height plus unique
  headers (`block_hash` / `block_time`). No per-coin `tx.head` or
  Class A `get`. Balance / `/address` stats skip `txid.body`; listunspent
  loads create identity for unspent creates only. `sh_join` debug adds
  `need=`.

- **Electrum fat-SH join:** `listunspent` identity is unspent-only. Tip
  subscribe no longer full-joins every subscribed hash on each block.
  Each TCP connection reuses the last scripthash outs+spent join until
  tip height changes (`get_balance` → `get_history` → `listunspent`).
  Packed `txout` expand is unchanged (no schema bump). Re-run Casa on
  the operator host; do not treat VM times as product numbers.

- **Esplora fat-SH join:** REST reuses one last-scripthash outs+spent join
  until tip height changes (`/scripthash` stats + mempool_stats, `/txs`
  pages, `/utxo`). WS `block-transactions` probes the posting list against
  the new block instead of a full history window.

- **Per-item `received getdata for: wtx` is TRACE:** one line per peer
  `MSG_WTX` getdata is too noisy at DEBUG. Counts stay on `tip: perf`.
  Core functional still sees the needle: the bitcoind shim maps
  `-loglevel=trace` (TestNode always passes it) to `--log-level trace`.

- **`tx.head` shards by create count:** live OA rolls at 80% of slots
  (~26.8 M at 25-bit); wipe-rebuild ranges are `2^bits` (default 2²⁶).
  Idx `RBITCOIN_TX_IDX_SOFT_SPAN` (16 GiB) no longer cuts head shards.
  `.rel` stays `n×4` 1-based relative to `first_fk` in `tx.head/meta`.

- **Sealed MPHF `g` is FdOnly:** `Store::open` no longer copies BDZ
  graphs into process heap (~4.92 B/key). Lookup streams unique 4 KiB
  `g` pages on the held uring session (`KIND_MPHF_G`), same shape as
  open `tx.head` OA page probes. Fuse8 fingerprints stay in RAM (~9
  bits/key). `ibd: sizes` adds `mphf_g=` (0 after open).

- **Tip-follow INV tick:** `queue_due_tx_invs` no longer `list_live()`
  (clone every mempool body + `compute_wtxid`) on the 50 ms session
  poll. Idle ticks return after a cheap due-check; flushes walk stored
  graph wtxids.

- **`--sptweaks` backfill:** one-core completion machine (`txout`, then
  `seqsigwit`/parents only for P2TR) and batched height-blob + idx writes.
  Mainnet origin→tip on SSD is typically **about 1–2 hours** (was several
  hours at ~15–25 h/s serial `get_tx_full`). INFO every 10 s:
  `sptweaks: backfill next=… tip=… rate=…/s remain=…`.

- **`--sptweaks` backfill CPU:** `tweak_from_tx` runs on idle
  `rbtc-scripts-*` steal workers (`try_for_each_parallel_idle`). Block
  script waves and mempool `run_detached_join` still take the pool
  first. The uring load machine stays one-core.

- **`sp_tweaks` roll at u32 start:** a height blob may extend past 4 GiB
  as long as its idx **start** fits in `u32`. `put_blocks` rolls a new
  `NNNNNN` pair when the next start would overflow (including mid-batch)
  instead of `Corrupt("sp_tweaks body exceeds u32 off")`.

- **SH tip materialize is sliced k-way:** one worker per CPU core
  (clamped to shard count) k-way-merges one prefix shard's catalog
  slices with a loser tree of stable 256 KiB double-buffered cursors.
  Dir-variant `scripthash.body/NN` + `scripthash.ovf/body` (schema 17
  orientation, not a version bump): workers write the shard file
  directly; publisher only seals `scripthash.head/NN` in order so
  `scripthash.cold_progress` (`SHCOLDP1`) is still a prefix HWM.
  Legacy file `scripthash.body` stays one writer (`workers=1` for pack).
  No temp `pack*.body`. No extra 64-file catalog pass.
  `RBITCOIN_SH_MERGE_WORKERS=1` stays the serial oracle.
  Status is a 10 s observer of global pack/seal counters
  (`keys` / `creates` / unpublished `pending` / `shards` sealed /
  `rate`) rather than a per-worker session log.
  On the dir variant each pack worker seals its own `head/NN` (no
  ordered publisher). SIGINT keeps sealed holes; resume packs only
  unsealed shards. Shared file body stays prefix `SHCOLDP1`. Pack
  threads use default IO priority — tip materialize is the work.
  Pack streams `head/NN.part` (no in-RAM rec vec). Class A recollect
  walks `txout` fk-spans, not per-fk get. Seal progress uses observer
  atomics (not `entry_count()`). Sealed-main lookup is per-shard
  `RwLock` (not one process mutex). k-way merge submits 256 KiB ahead
  pages on the pack thread's TLS completion session (`io_uring` /
  process-shared `pool` / IOCP) and waits only if that page is still
  inflight at promote; `RBITCOIN_IO=pread` stays blocking.
  Bulk pack picks slab class from the ULEB payload size (not `n×8`
  geometric cap) and carves 4 KiB page-align gaps onto the relocating
  freelist so later slabs fill the hole.

- **Load stamp reuses lookup `TxPrecompute`:** `LoadBatch` carries the
  decode-time `pres` Arc; `confirm_wire_lookup_stamp` must not `from_tx`
  again (`stamp_sub struct_txid=` is 0 on IBD). BQ is not a decoded stash
  after `take_raw`.

- **Confirm queue caps:** `loadq=14` · `scriptq=4` · `writeq=14`
  (was loadq=8 · writeq=20).

- **Core functional Wave E / thin leftovers.** Official unmodified
  `p2p_getdata.py` is `run` (37→**38**). Invalid GETDATA inv type 0
  does not stall the session; a later MSG_BLOCK getdata of the tip
  is served. `p2p_invalid_block.py` stays skip at `--v1transport`
  magic-bytes mismatch (`:44`). `feature_chain_tiebreaks.py` stays
  skip at missing-parent B7 getdata (`:86`). `mempool_accept.py`
  stays skip at `testmempoolaccept` type-check dialect (`:98`)
  after `getmempoolinfo.permitbaremultisig` and `incrementalrelayfee`
  match Core. Q-41 is 38/267.

- **Lookup→load queue:** explicit `loadq=8` of load-sized batches.
  Lookup walks BQ in height order, dequeues raw on emit, and parks
  decoded `Block`+pres on the queue. Densify skips `H <= lookup_taken_hi`.
  RecentCreates horizon is EWMA(`lookup_taken_hi − tip`)+25% (floor 32,
  cap 32×144). `ibd: sizes` keeps `union=` / `h2h=` / `fence=` /
  `recent= live=/pub=/ov= fifo=` and adds loadq wire to `accounted`.
  `ready=` / `bq_dec=` are no longer queue tokens.

- **v2-only peer discovery (Q-49):** DNS queries `x809.<seed>`
  (`NETWORK|WITNESS|P2P_V2`) before the unfiltered name; learned
  `addr`/`addrv2` requires `P2P_V2`; dial ranking omits known-v1
  (`INCOMPATIBLE`) while any better candidate remains.

- **Core functional leftover-P2P follow-up.** Official unmodified
  `p2p_compactblocks_blocksonly.py` and `p2p_blocksonly.py` are `run`
  (35→**37**). `-blocksonly`
  does not select HB; it getdata's `MSG_WITNESS_BLOCK` while relay
  peers getdata `MSG_CMPCT_BLOCK` after `sendcmpct` v2. Handshake
  advertises BIP155 `sendaddrv2` before verack. Low-work header
  announces log Core `Ignoring low-work chain (height=N)` /
  `Synchronizing blockheaders, height: N` (pending-path height, not
  one-header-from-genesis); non-noban does not persist a low-work
  headers tree; noban stores headers-only. INV of a known fork header
  may getdata missing bodies on that path. `p2p_headers_sync_with_minchainwork.py`
  stays skip at the ~2032-block `generatetoaddress` 120s timeout
  (`:112`). `p2p_invalid_messages.py` stays skip at empty addrv2 Core
  logs (`:203`). `p2p_unrequested_blocks.py` stays skip at
  wait_for_disconnect on an immature-coinbase fork (`:275`). Known-header
  INV does not getdata (sendheaders `inv_node`). `-blocksonly` reports
  `localrelay=false`, disconnects P2P txs/tx-invs, and exposes
  `relaytxes`; RPC sendraw is still accepted and INVs inbound peers.
  `getpeerinfo.permissions` exposes whitelist `relay`. `testmempoolaccept`
  rolls back admits while relay is off so sendraw can note unbroadcast.
  Inbound + relay-on keeps the 30s INV/GetData gate on a brand-new sendraw
  after a mocktime jump (`mempool_reorg.py:122`). Q-41 is 37/267.

- **Lookup wave intake + write drain:** `wave_intake` classifies raw vs
  promoted heights with **no payload clone**; decode pulls `raw_payload`
  per height. Peer offer copies wire **before** the BQ lock.
  `lookup_thr wave=` nests `head=` (TipOnly `get_fk_by_txid_batch`);
  `lookup_sub head=` is that token, not load stamp. Collect sets use
  `TxidHasher`. Write merges at most **¼ of writeq** (5 of 20) so scripts
  keep empty slots; RecentCreates expire once per write. Pstore
  `size_snapshot` is insert/gc counters (no slot walk); pin names `thin=`.
  Restart leftover is still empty RAM identity (not a horizon miss).

- **Confirm pack / leftover / lookup meters:** load waits on `feed.cv` when
  tip+1 is ready but BQ resolve is incomplete (no retain+BQ spin). Write
  notes RecentCreates **per prepared height**; published identity layers
  stay while `tip − hi < 2×soft_win` after the span leaves the BQ.
  In-flight / pstore `size_snapshot` is O(1) occupancy (no per-pack pin
  script walk). Lookup wave names `decode=` / `precompute=` / `collect=`
  under `lookup_thr wave=`. BQ keeps a height→id map; load pack takes
  one feed collect, one `block_queue_pack_snapshot`, one inflight mark
  (stored hash vs feed; no happy-path `block.block_hash()`). Script
  steal is unchanged — decode stays on the lookup thread.

- **Docs remotes + lookup:** `origin` fetch is HTTPS, `pushurl` is SSH
  (`AGENTS.md`). `OPERATOR.md` lookup row includes the hard min 8000
  inputs. Living pointers use `block/mod.rs` / `structure_rule_tests.rs`.

- **Lookup wave min 8000 inputs:** do not publish a TipOnly layer under
  8000 Σ `tx.input` when more unresolved BQ heights can still join,
  including `ready=0` / load-frontier / unknown window. Last available
  thin wave still emits. Max remains 64000 inputs / 1080 blocks.

- **Core functional leftover-P2P.** Official unmodified
  `p2p_initial_headers_sync.py` and `p2p_compactblocks.py` are `run`
  (33→**35**). Initial `getheaders` goes to one `NODE_NETWORK` peer
  until the tip is within 24h; each new block INV may add one extra
  peer; headers-download timeout disconnects a stalling peer unless
  whitelist `noban`. BIP152: tip INV is `MSG_BLOCK`; `sendcmpct(1)`
  announces `cmpctblock`; getdata type 4; getblocktxn depth 10;
  compact getdata depth 5; OOB getblocktxn disconnects; HB max 3
  with 2 inbound + 1 outbound fill slots; cached-invalid child
  compact is `bad-prevblk`; a second failed `blocktxn` disconnects.
  v2 length-prefix reject logs `V2 transport error: packet too large`
  and disconnects; unknown short/long type logs and stays connected
  (`*other*` raw size). `getnettotals` counts raw TCP when a session
  has `WireBytes`. `p2p_invalid_messages.py` stays skip at inbound
  `sendaddrv2` (`:188`). Q-41 is 35/267.

- **Script steal claim + join:** `rbtc-scripts-*` claim a published
  wave snapshot (`ArcSwap`) instead of locking `WAVES` per job;
  steal is **32-wide chunks** (`in_wave` = in-flight chunks, AcqRel).
  After feed-ahead submits N+1, scripts join blocks instead of
  `recv_timeout(200µs)` for the rest of N. `script=` is still
  verify/`wait_done` wall, not the poller.

- **Confirm structure one-pass + lookup stash:** `TxPrecompute::from_tx`
  (txid + wtxid + weight + BIP143/BIP341 common SHA256 midstates) lives
  on Query. Lookup decodes each BQ height once, promotes to decoded-only
  (drops raw; `bytes()` keeps `max(payload, decoded)` charge; one mutex
  per wave), and load pack / structure reuse `Arc<Block>` + pres.
  Script jobs carry that pres (no job `from_tx` / `finish_spent`;
  WitnessV0 does not rehash per CHECKSIG). `SighashCache` is lazy
  (P2WPKH does not construct one). Stamp loads published/recent once
  per pack (`TxidHasher` on remaining txid maps); lookup keep uses a
  height `BTreeSet` (`range`, not `lo..=hi` / `list_meta`). Assemble
  confirmed-parent skips `validate_header` after the MTP walk; one
  `pending_spent` set; assemble clocks flush once per block.
  `ibd: sizes` adds `bq_dec=`. BIP143 P2WPKH/P2WSH / interpreter consume
  those midstates. `stamp_sub` adds `struct_txid=` / `struct_walk=`.
  rust-bitcoin remains the test oracle. Taproot still uses `SighashCache`.

- **Assemble meters and maps:** prevout path counts flush once per block
  (no per-input `Instant` / atomics). Same-block outs use `txid_index`
  (`TxidHasher`); pack `pending_creates` is `txid → fk`. `ibd: perf`
  assemble tokens stay; `us/in` is still `ASM_PREVOUT_NS / ASM_IN_N`.

- **Core functional field leftovers.** Official `rpc_net.py` stays
  skip: dual-connect `getconnectioncount` now counts inbound+outbound
  PeerHub sessions; `getpeerinfo` emits `last_block` /
  `last_transaction` / `minfeefilter`; `addnode` is `manual`; nodes
  send/record BIP133 `feefilter`; `getblockchaininfo` has tip `time`
  and `mediantime`. First remaining official fail is pre-version
  `getpeerinfo` (`rpc_net.py:138` — v1 magic / v2 `wait_for_new_peer`).
  Inventory still **33 run**. Q-41 table matches 33/267.

- **Store IoCtx:** head-resolve / identity / idx page fill share one
  `IoCtx` (`held` session or standalone). Crate-private
  `probe_candidates_batch_{open,sealed_hot,cold}_on_session` twins are
  one `probe_candidates_batch_wave`. Machines still hold TLS; nested
  `with_thread_local` still panics. Public `*_on_session` wrappers remain.

- **IBD write sample nest:** `IbdPerfSample.write` is a `WriteStageSample`
  of the eight inventory tokens (`class_a+ensure+struct+class_c+sh+spend+tweaks+tip_gc`).
  `write=` still equals `write_stage_ms`. INFO/DEBUG token strings unchanged.

- **Recent-create identity ring:** write publishes `txid → (create_fk,
  body_range)` after Class A + idx. Load stamp probes it after published
  live-union and before leftover TipOnly. Height-FIFO expire is
  `2 × soft_confirm_window` (floor 256). Identity only — no outs / not a
  process pin FIFO. `ibd: perf` adds `recent=` / `recent_ms=`; `ibd: sizes`
  adds `recent=Nh/Nk≈NMiB`.

- **Stamp identity union:** load/plan stamp no longer accepts a BQ-ahead
  hits map. Facts come from in-flight → published `live_union` →
  recent-creates → TipOnly.
  Deleted `BqParentHits` and `confirm_wire_lookup_stamp_with_hits`.
  Pin denserels read only `ParentPinStamp` (no `plan.external_parent_*`
  fallback). S0 plan and plan=None rehydrate share
  `stamp_external_parents` (query). `archive_plan_batch_from_store` no
  longer takes a parent-store argument — pstore is outs, not create_fk.

- **Core functional Wave D leftovers.** Official unmodified
  `interface_rpc.py` and `mempool_reorg.py` are now `run` (33 inventory
  run names). HTTP JSON-RPC 2.0 batch, notifications (204), and
  version/HTTP status dialect match Core v31.1. `getnettotals` sums live
  peer byte counters. Mempool GetData follows Core `info_for_relay`
  (entry sequence < last INV); reorg-reaccept uses sequence 0 so
  disconnected-block txs are servable without INV, and a later regular
  submit of the same wtxid is `notfound` until announced.

- **`ibd: perf` load/script tokens:** `load=` is pin+assemble only.
  `load_thr pack/stamp/pin/asm/prune` is the load OS thread (leftover
  TipOnly is `stamp=`; in-flight drop after scriptq is `prune=`). `script=`
  is verify ns (`jobs=`/`skip=`), not submit-to-join. `lookup_thr keep=`
  times live-union splice.

- **Store completion session:** `IoSession` backends — Linux `io_uring`
  (default), portable `RBITCOIN_IO=pool` (Darwin default), Windows IOCP.
  Spend-annotate, head-resolve, and bulk fill stay multi-stage machines.
  kqueue / POSIX AIO / `dispatch_io` are not file SQ/CQ rings.
  `RBITCOIN_IO=pread` still disables the session.

- **Confirm parent identity:** lookup prepends one `IdLayer` per resolve
  wave (`lo..=hi`) and `Arc`-bumps the chain head (`PublishedIds`). Get
  walks the chain (txid identity hasher; no union `reindex`). Drop is
  splice when no height in the span remains on the BQ. While `ready` is
  over half the 1-min BQ window, lookup holds short waves so it does not
  mint one layer per newly fetched block, unless the first unresolved
  height is in the load-facing half of that window (O(1) vs `path_lo`). Disconnect stores `None`
  immediately. `pin_txid=` counts published-union hits. IBD lookup
  TipOnly-resolves up to **64000** inputs (include-overshoot) or **1080**
  blocks per wave (8× load's 8000-input cap; ~1 week of 10-minute blocks).

- **Head resolve identity:** each probe wave fills `txid.body` in two shots
  (first four cands, then the rest if still unfinished). A connected win
  skips the tail. Sealed-hot probes only unfinished keys, same mask as cold.

- **Confirm pin outs:** `ArchiveWritePlan.external_parent_outs` and
  `ensure_external_parent_denserels_from_plan` are gone. IBD pin is
  `pin_for_wire_batch` (in-flight / same-batch / pstore adopt / cold
  range). Plan keeps ranges+txids until `freeze_after_pin`.

- **One SH durable dialect.** Incremental creates go to ingest OA (then
  sealed `SHSR` ovf). Live OA main / `ShOverflowStack` writes are gone.
  Leftover OA at `scripthash.head` or non-`SHSR` `ovf/NNNNNN` refuses
  open — wipe `store/scripthash*` and restart with `--shindex`.

- **`getblockchaininfo` disk / progress:** `size_on_disk` is a walk of
  store file lengths (plus cold seqsigwit when split). `verificationprogress`
  is `blocks / headers` (1.0 when headers is 0), not a dummy 0.5 / 1.0.

- **No soak program.** Signet-first remains ordinary run advice. Q-35 is
  won't-fix. Docs no longer title a gated “soak” checklist.

- **SH on/off:** COMPAT and README point at the OPERATOR cost table.
  Disable-after-on leaves SH files on disk; tip follow stays up.

- **Electrum `electrs` UA + versions:** COMPAT documents why
  `server.version[0]` contains `electrs` (Cake `getNodeIsElectrs()`).
  README no longer hardcodes `0.1.0`; shipped strings stay
  `workspace.package.version`.

- **Quality:** **Q-47** closed (honest chaininfo). **Q-48** is BIP331 when
  rust-bitcoin grows the types — no private `rbtpkg` stand-in.

- **COMPAT GBT:** template RPCs (`getblocktemplate` / `getmininginfo` /
  `prioritisetransaction`) are shipped. COMPAT no longer lists GBT as
  never. Stratum / wallet keys stay non-goals.

- **Head resolve is three waves, no rank rounds.** Probe+identity is
  open, then sealed ages 1..=3, then sealed age ≥4. Each wave fills
  `txid.body` in two shots (first four cands, then the rest if still
  unfinished) and walks newest-first (fence-connected wins). Sealed-hot
  and cold probe only unfinished keys. Unconnected identity still
  continues to later waves. TipOnly still strips unconnected at the end.

- **Leftover probe dump.** A leftover miss (load leftover, not lookup /
  BQ-ahead TipOnly) logs hop + every cand (`txid.body` prefix, match,
  rel/abs fk) once. The reject line adds `diag=1`.

- **Quality reaudit (2026-08-17).** [`docs/quality.md`](docs/quality.md)
  Open list re-ranked. Q-37 (suite ≤3 min) closed on CI `test` ~85 s.
  Won't-fix: CODEOWNERS, crates.io publish, rustdoc site, structured
  logs, tier-C in default CI. New: honest chaininfo disk/progress
  (**Q-47**), BIP331 rust-bitcoin types (**Q-48**), v2 peer discovery
  (**Q-49**).

- **Withdrawn: open `tx.head` page seqlock (#82 / #84).** Leftover misses
  are old parent txids with a long hop of cands (`miss_on=body`, ~25–34).
  A torn old/new page still holds those occupants; seqlock cannot explain
  that miss. The 250 ms odd-page `Corrupt` aborted lookup waves and dumped
  more work onto leftover. Per-page `AtomicU32`s are gone; insert is again
  sole-writer page-coalesced `pwrite`.

- **Tests assert behavior, not the repo.** Default-suite tests no longer
  `include_str!` production sources or `CONTRIBUTING.md` to grep
  identifiers. Query open leftover-strong repair is pinned by
  `Query::open_or_create` reopen. CONTRIBUTING principle 8.

- **Documentation map.** [`docs/README.md`](docs/README.md) is the only
  index (one audience, one start file; one fact, one owner). Coverage
  policy lives in `TESTING.md`. Schema 17 freeze tables live in
  `SCHEMA.md`. Confirm start states live in `docs/invariants.md`.
  Most-work reorg rules live in `docs/architecture.md`. `AGENTS.md` is
  the slim harness contract. Removed `COVERAGE.md`,
  `docs/store-format.md`, `docs/startup-states.md`,
  `docs/design-ibd-most-work-reorg.md`, and `docs/future-features/`.

- **Source-code comments are a smell.** `CONTRIBUTING.md` now states that
  a comment restating *what* the next code does, *why* it exists, or a
  *weird* approach usually means names, signatures, or the library fit
  are unclear. Most `//` comments should not exist; remaining ones name
  an invariant, protocol, `SAFETY` requirement, or library quirk. First-party
  production sources were cleaned to that bar.

- **Core functional Wave D.** Future-tip load abort (Core 2h
  `MAX_FUTURE_BLOCK_TIME` vs `-mocktime`). `getblock(verbose=2)`
  `scriptPubKey.address`. `getrpcinfo.active_commands` + `logpath`.
  Official leftovers stay skip with first-failure analogs:
  `rpc_blockchain` missing `time` (`:157`), `rpc_generate` `combo()`
  (`:55`), `interface_rpc` JSON-RPC 2.0 batch (`:151`),
  `rpc_getblockfrompeer` method (`:69`), `mempool_reorg` unannounced
  getdata (`:94`), `rpc_net` dual connections (`:100`). Inventory still
  **31** `run`.

- **Core functional Wave C.** Official unmodified
  `p2p_sendheaders.py` and `p2p_compactblocks_hb.py` are now `run`
  (31 inventory run names). Header announce follows Core
  `pindexBestHeaderSent` (inv after a large reorg until the peer
  catches up; getblocks does not resume). Block bodies are requested
  from header announcements or getheaders replies, not from inv.
  Unrequested anti-dos:
  minwork header skip, weaker forks stay headers-only, missing parent
  header disconnects, 288-height window. `p2p_unrequested_blocks.py`
  / headers-sync / `p2p_invalid_messages.py` / `p2p_compactblocks.py`
  stay skip with first official-failure analogs. Compact **filters**
  stay skip.

- **Core functional Wave B.** Official unmodified
  `mempool_unbroadcast.py` is now `run` (29 inventory run names).
  Unbroadcast set persists across restart; `mockscheduler` re-INVs it.
  GBT/submitheader field zoo, `-blockversion` / `-blockmintxfee`, and
  GBT sigops shipped. `mining_basic.py` stays skip (first remaining
  official failure is `test_block_max_weight` empty mempool /
  reserved-weight). `rpc_net.py` / `rpc_getblockfrompeer.py` /
  `rpc_blockchain.py` stay skip with first-failure analogs.

- **Core functional Wave A.** Official unmodified
  `feature_dersig.py` / `feature_cltv.py` / `p2p_ping.py` /
  `feature_minchainwork.py` / `tool_rpcauth.py` are now `run` (28
  inventory run names). Compact block filters stay skip.

- **Core debug.log campaign (Step 21).** BIP34/66/65 outdated `nVersion`
  is `bad-version(0x…)`. Connect script fail logs
  `Block validation error: …` (`SIG_DER` / five CLTV parens).
  `testmempoolaccept` emits `reject-details`. Ping/pong logs Core
  `Short payload` / `Nonce mismatch` / `Nonce zero` / `ping timeout`
  and `getpeerinfo` RTT fields. Confirming an unbroadcast local tx
  logs Core's removal line. V2 unknown type and redundant version
  log the `p2p_invalid_messages` needles.

- **Height fence extend is fail-closed.** Missing or empty `header_txs` for
  the header is `Corrupt`, not `Ok` with a live `height_of` hole (TipOnly
  leftover miss that restart rebuild then heals). Confirm publishes the
  fence run **before** `confirmed[]` so a failed extend cannot leave tip
  ahead of `height_of`.

- **Invalidate evicts immature coinbase spends.** `QueryUtxoProvider`
  now ORs the input-null coinbase signal with first-in-block, so
  `evict_after_reorg` sees `ImmatureCoinbase` after `invalidateblock`
  drops tip below maturity. Creates whose Class A height is above tip
  are not chain coins, so children of a reorged spend leave too.
  Re-accepting a disconnected parent wires edges to children that were
  already live (`ancestorcount` 2).

- **`-minimumchainwork` is live on P2P.** Below the floor: stay in IBD
  (also if tip age > 24h), do not announce blocks, ignore inbound
  `getheaders`. Tip-follow still runs so later blocks can raise work.
  `getblockheader` / `getblockchaininfo` report real header `chainwork`
  (regtest 2 per block), not `""`. Download (getdata/accept) waits until
  the peer's best-known path meets the floor.

- **IBD leftover miss names the table:** stamp reject lines include
  `miss_on=head|body|idx|fence` and `miss_cands=` so a TipOnly miss is not
  read as a bare missing prevout (`body` is `txid.body` identity).

- **Load pin hygiene (scriptq feed).** Sparse need-vouts are binary-searched
  (sorted decode outs). Stamp maps move off the plan (`take_from_plan`)
  instead of cloning two ~100k U64Maps. Archive bind is one walk
  (in-flight → pin_txid → BQ → TipOnly). `pin_txid` is one Weak-map lock
  per pack (`bulk_lookup_txid`), not one mutex per remaining prev_txid.
  Load pin no longer `tx_spent_range_batch`s the parent set — write
  `ensure_spend_abs_layouts` is the sole `spent.idx` stamper. IBD
  `pread_skip` on write may drop; `scriptq` is the customer. Leftover
  TipOnly vs BQ leakage is still a host spike (no pending map, no
  soft-requeue).
- **io_uring harvest is fail-closed.** Unmatched/duplicate CQEs, leftover
  undrained SQEs, CQ overflow, and identity-without-idx-range are
  `Corrupt("invariant: io_uring …")` / `idx range missing after identity`,
  not a quiet TipOnly `MissingPrevout`. Distinct `user_data` kinds + epoch
  so a leftover probe slot cannot complete an identity pread. Spend
  annotate drains before slot buffers drop. Pwrite unfilled ops fail
  closed to libc retry. Uring resolve no longer swallows Corrupt into
  pread (ring-unavailable still falls back).

- **Mempool block connect evicts conflicts:** a confirmed block that
  spends a mempool tx's inputs (without including that tx) drops the
  conflict and its descendants. `wallet_txn_*` reorgs need this.
- **Mempool accessors:** `getmempoolancestors` / `getmempooldescendants` /
  `getmempoolfeeratediagram` / `submitpackage` / `gettxspendingprevout`.
  `-limitclustercount` / `-limitclustersize` overlay the live graph
  and survive `maybe_compact` rebuilds. Cluster overflow is
  `too-large-cluster`. `getmempoolinfo.optimal` is true (we linearize
  on insert). `sendrawtransaction` of a live mempool tx returns the
  txid (Core no-op), not `-26 txn-already-in-mempool`.
- **GBT proposal:** Core reject needles without writing UTXO / requiring
  PoW. `submitblock` maps `high-hash` / `prev-blk-not-found`.
- **BIP152 / inbound:** handshake `sendcmpct` is v2 low-bandwidth;
  HB (`send_compact: true`) is selected when we accept a tip from the
  peer (max 3). Announce compact with coinbase prefill. `getpeerinfo`
  reports `bip152_hb_to` / `bip152_hb_from`. Feeler outbounds send
  `relay=0` and close after version. Empty-locator `getheaders` is a
  single-hashstop request.

- **No leftover pending map.** Parent identity is in-flight until
  drain-fk **and** fence after pin + scripts handoff (n−1 outs).
  Prune-after-bind dropped those outs before pin (mainnet 187
  `load parent without body_range denserels`). Fence alone dropped
  layers during `tx.head` seal (269204 leftover 1121/1120).
  Disconnect drops in-flight layers at that height. Header-cache GC
  polls store tip every load pack. Store `PendingHeadInserts` is a
  write-local drain `Vec`. Not a leftover soft-requeue.

- **`tx.head` insert has no mmap-era CPU fence:** `insert_many` / page
  probe no longer `SeqCst`/`Acquire` fence. Tables are fd `pwrite`/`pread`;
  visibility is the syscall and `published_len` Release. VarTable seqlock
  and Class C `sync_data` are unchanged. Not a leftover-prevout fix.

- **Pending `tx.head` snap lives until insert and fence:** drain
  inserts head for probe; `forget_if_fenced` skips still-queued keys.
  Write forgets after `drain.join()` *and* `height_fence_extend` — not
  from Class C while insert is in flight. Fence-first (early IBD huge
  packs) dropped pending before `tx.head` published (`67438`
  leftover_n=11 hit=4). Drain-first hole was `327331` leftover_n−1.
  No leftover soft-requeue — union miss stays Corrupt.

- **IBD lookup wave select is one BQ lock:** unresolved heights come from
  `block_queue_unresolved_heights` (in-entry `resolve_complete`, capped).
  The old `list_meta` + per-height `is_resolve_complete` scan was O(n²)
  at a few thousand queued bodies (`lookup_thr other=` pegged at ~140k).

- **IBD connecting search only from a competing tip+1:** `consider` no
  longer walks `max_ordered`. A linear tip+1 (parent is the tip) is a
  download hole, not a fork. Most-work search still runs when tip+1's
  parent is some other known header.

- **IBD connecting search needs a connected LCA:** a capped ancestor walk
  from a far header-only horizon (early IBD, tip at a few thousand, headers
  at `max_ordered`) is not a disconnected fork. The old `!has_block(join)`
  shortcut treated that mid as a disconnected fork and getdata-stormed
  32 connecting hashes. Real forks still search when the join is on the
  best chain.

- **Tip-follow stale redial:** a persistent 60s interval plus the 5s
  `tip: perf` wake now run the extra-outbound check. The previous one-shot
  sleep in the same `select!` was reset by every perf/RPC tick, so a node
  that lost its last follow peer (mainnet 962723) never redialed.

- **Class A idx rolls:** each stem (`txout` / `seqsigwit` / `spent`) rolls its
  own idx at the soft span. SeqSigWit no longer forces hot idx splits.
- **`strong_tx`:** always L2 (1 bit/fk). `RBITCOIN_CLASS_C_INRAM_MAX_MB`
  still caps `confirmed` / `header_txs_*` only.
- **Schema 17 freeze note:** [`SCHEMA.md`](SCHEMA.md)
  (hot set, widths, kinds without wipe, what forces 18).

- **`getdeploymentinfo`:** buried `bip34` / `bip66` / `bip65` / `csv` /
  `segwit` / `taproot` from `ChainParams` (including the activation-height
  overlay). `active` is Core `DeploymentActiveAfter` (next block). No BIP9.

- **Confirm overlay:** `-testactivationheight` changes BIP68/CSV/CLTV/DERSIG
  and BIP147/WITNESS (with `segwit`) on the same `ChainParams` confirm uses.

- **Confirm reject log:** BIP113 uses the same `bad-txns-nonfinal` needle as
  BIP68. Script-flag rejects emit Core `block-script-verify-flag-failed (…)`
  on the receive path (P2P / `submitblock`).

- **`scantxoutset`:** `raw(script)` uses `--shindex` `scripthash_listunspent`
  when the index is on; otherwise Class A txout + spent. Never reconstructs
  every block.

- **Block selector:** `generate*` includes mempool txs via
  `TxGraph::select_block_txids` (best-chunk order, parent-before-child,
  block-weight cap). Same helper will feed `getblocktemplate`.
  Chunks are prefix-maximal feerate (cheap parent + hot children stay
  together; a cheap descendant does not dilute a hotter prefix).

- **`getblocktemplate` / `getmininginfo`:** template from the selector on
  every network. `rules` must include `segwit`. Proposal validates without
  connecting. No BIP9 testdummy version bit. `longpollid` waits for a new
  tip or a mempool/priority update (same production template).

- **`prioritisetransaction`:** additive i64 sat fee delta by txid (even if
  not in the mempool). Dummy must be 0. Selector / generate / GBT rank by
  modified fee; non-positive modified fee is not mined. Min-relay and RBF
  use the incoming modified fee. Mined txs drop the delta.
  `getprioritisedtransactions` reports the map.

- **`-persistmempool=0`:** start with an empty live set (do not reload the
  durable sidecar). The flag was already parsed; it now takes effect.

- **Mempool BIP68:** confirmed inputs use the parent create MTP (not 0).
  `getblockheader.mediantime` is real MTP.

- **`submitheader`:** same `ensure_header` path as P2P headers. Header-only
  children show up in `getchaintips` as `headers-only`. `getblockchaininfo.headers`
  is the best known header height. `invalidateblock` of an unknown hash is
  Core `-5 Block not found`; after invalidate the next most-work fork is
  applied. `preciousblock` breaks equal-work ties only (not less work).
  `generatetodescriptor` accepts `addr(ADDRESS)#checksum`.

- **`getchaintips`:** active tip plus losing `valid-fork` (archive after
  reorg) and held never-confirmed `valid-headers`. Hashes only — not a
  block index.

- **Mempool RPC graph fields:** `getmempoolentry` / verbose `getrawmempool`
  ancestor and descendant counts (and size/fee sums) come from the cluster
  graph, not stub `1`. `getmempoolinfo.unbroadcastcount` and per-entry
  `unbroadcast` track `sendrawtransaction` until a peer `getdata`s the tx.
- **`rbitcoin-cli`:** cookie / `--rpcuser` HTTP client for the documented
  JSON-RPC subset (plain HTTP, same as the node).
- **`--maxinbound`:** passed into `P2PNode` as a field. `RBITCOIN_P2P_MAX_INBOUND`
  is parse-time input only (no `set_var`).
- **`getnetworkinfo` / `getmempoolinfo`:** `version` is rbitcoin (`0.1.0` →
  `100`); `localservices` match advertised flags; `maxmempool` is the hub
  weight budget.

- **Schema 17 (durable) — wipe the datadir and redo IBD.** Opening a
  store that already has Class A creates (schema 15/16 16-byte meta /
  9-byte spent) or leftover `key_len=32` SH runs is refused. Empty
  Class A still soft-opens. This is meant to be the last full-datadir
  reindex for the Class A / B / C layout; later work (seqsigwit Δfk, a new
  consensus script kind) would be schema 18 and should not require
  another wipe of `txout` / `spent` / heads. Layout in 17: SH runs
  unique `(scripthash, create_fk)` at `key_len=40`; megakey pages are
  uleb fk0+deltas; thin LAYOUT17 `txout` meta; script kinds 0–9; 8-byte
  spent slots; overflow is `spent.ovf`; reserved seqsigwit bits 4–7 and
  spent flags other than `MULTI_SPENDER` are Corrupt. Leftover
  `archive_epoch`, `store/wire`, and single-file `sp_tweaks.idx` /
  `sp_tweaks.body` are unlinked on open. Tweaks (when `--sptweaks`) are
  segmented dirs: tip-only `off:u32` (no `header_fk`), original `0`/`33`
  body, new `NNNNNN` pair when the next body start would exceed `u32`.

- **IBD lookup is BQ-ahead TipOnly `head_fk`:** the lookup thread resolves
  external parents for at most **8** ready body-queue heights in one
  `get_fk_by_txid_batch` wave and attaches hits on the BQ record. Load claims
  only resolve-complete heights (soft **8000** inputs, typically 1–3 dense
  blocks — not a ~32-block pack) and stamps from those hits plus a leftover
  TipOnly `tx.head` for parents not in live caches (almost all open head; the
  rest ages ≤3 sealed). No `TipThenAny` last-chance on the confirm path.
  One-shot `accept_branch` / `confirm_wire_run` still stamp in-process with
  TipOnly. Progress/sizes print **`ready=`** (BQ resolve-complete count), not
  a fake `loadq=n/8`. Load leftover head is `leftover_n/hit/ms/pend/cdf`;
  lookup wave wall is `lookup_thr wave=`.

- **Confirm write path:** Class C `strong_tx` flush already wrote only the dirty
  suffix — now pinned. Class A `txout`/`seqsigwit`/`spent` bodies submit as one
  `pwrite_batch` wave. `tx.head` insert is write-behind (page-grouped drain
  overlaps structural/Class C); resolve hits a pending txid→fk map until drain.
  Crash-open backfills a lagging head from Class A.
- **`ibd: sizes` residual:** `fuse8=` / `open_keys=` / `class_c_l2=` enter
  accounted. Sealed fuse fingerprints (~9 bits/create) were the ~1.6 GiB gap
  at 1.42 B creates — see [`docs/ibd-memory.md`](docs/ibd-memory.md).
- **Agent delivery:** plans land on a worktree topic branch as many small
  commits and **one PR**. Full workspace test/coverage is GitHub Actions, not
  a local plan-end ritual; poll the PR to green. Musl install stays
  post-merge on `master`. Leave `origin` on SSH (operator auth); the App
  fetch/push uses an explicit HTTPS URL. See `AGENTS.md` and
  `docs/how-we-plan.md`.

- **Docs honesty:** root `/api.jsonl` is gitignored. SCHEMA `archive_epoch.wire_depth`
  is an unread leftover field (no tip wire ring). `page_rmw_pipelined` is
  documented as test-only. io-modality no longer describes a map hatch;
  OPERATOR densify is body-queue soft depth (no archive-queue cap).
- **Table flush:** `TableFile::flush` always `sync_data` after a dirty persist.

- **Docs Q-14:** [`docs/heads.md`](docs/heads.md) is the head-module glossary.
  Pipeline details stay in `concurrency.md`; architecture / OPERATOR / AGENTS
  link instead of restating. SCHEMA tree uses `tx.head/` (not flat names).

- **Lookup stamp:** consult live `PipelineParentStore` by prev_txid before
  `tx.head` (`pin_txid=` / `pin_txid%` / `pin_txid_ms` / `head_n` /
  `us/pin_txid` on `ibd: perf`). Remaining head `txout.idx` fills are
  page-grouped on the held resolve session. `pin_hit%` is adopt/plan
  reuse only (this-window range-fills stay `pin_new`).

- **Schema 16:** drop `tx_height.body` (~5 GiB). Create height is a resident
  fence from `confirmed[]` + `header_txs_*` (O(blocks), RAM bsearch). Reorg
  holes return unconnected. Schema 15 stores soft-open (unlink leftover file).
  Old binaries refuse 16 (they still write `tx_height`).

- **Script pool:** `try_for_each_parallel` steals on process-wide
  `rbtc-scripts-*` workers (no per-batch `thread::scope`). Confirm phases run
  on two `rbtc-script-coord-*` threads so a steal worker is not blocked inside
  the phase. Pool wait uses a condvar deque (not `recv` under mutex).

- **`--sptweaks` during IBD:** Direct confirm no longer write-throughs the
  thin BIP-352 index (it was 50–80% of fat-era write). After tip, SH
  materialize (if `--shindex`) then a sequential backfill to live tip;
  Tip write-through only when `height == next_height`. Restart resumes
  from `next_height`.

- **Schema 15 Class A split:** `txout.body` (outs) + `seqsigwit.body` (ins+witness)
  + `spent.body` (9 B×n_out). Packed `tx.body` with creates is refused. Pin/SH
  read outs only; annotate RMW is `spent_off+9×vout`. Working-set census in
  [`SCHEMA.md`](./SCHEMA.md).
- **Schema 15 Class B SH:** geometric slabs + megakey pages; sealed
  sorted+idx main (**no** main fuse); global ingest OA; sealed ovf keeps
  fuse8. Tip lookup is overflow (ingest + ovf fuse) then main. Open
  rematerialized SHSR shards via an OA stub; sealed ovf files are not
  opened as OA. Unlink writes the home `locate_head` found. Cold bulk
  streams packed recs (no per-shard OA image). Page-era durable SH is
  refused. The OA global `scripthash.head.fuse8` builder is gone.
- **Electrum / RPC:** skip O(mempool) API walks; overlap Electrum dispatch;
  thin `--sptweaks` serve is idx→body uring, not a packed span.
- **Electrum `server.version`:** first element is `rbitcoin-electrs <ver>` so
  Cake Wallet’s `getNodeIsElectrs()` will probe `blockchain.tweaks.subscribe`.
- **CLI-first config:** `--maxinbound`/`--maxconnections`, `--conf`,
  Core-like aliases (`--assumevalid-height`, `--maxmempool`, `--chain`).
- **Tip-follow logging:** every accepted tip block logs Core-like `UpdateTip: …`.
- **Fee snapshot / mempool APIs:** published fee table and mining chunks so
  Electrum/Esplora estimates do not block accepts (R-01–R-04).
- **Quality gates:** `cargo deny` on PR (Q-20); coverage uses prebuilt
  `cargo-llvm-cov` (Q-22); `scripts/sbom.sh` emits CycloneDX from Cargo.lock.


### Fixed

- **Fuzz CI nightly:** `scripts/fuzz-run.sh` / `fuzz.yml` set
  `RUSTUP_TOOLCHAIN=nightly` so `rust-toolchain.toml` 1.95 cannot feed
  cargo-fuzz (`-Zsanitizer` is nightly-only).

- **SH materialize last page:** megakey chunking sizes the last extent page
  for the `ver=2` 24 B header (4072 B stream), not the `ver=1` 4088 B cap.
  A key whose delta stream sat in 4073..=4088 B overflowed
  `scripthash page pack: entries exceed page capacity` and aborted bulk
  materialize.

- **Script pool wake:** idle `rbtc-scripts-*` workers `park` with an epoch +
  `unpark` permit (wave publish / detached job). A worker that misses steal
  and parks after the wake still runs the work. Jobs mutex stays the
  detached-job queue only.

- **Script steal last-chunk:** `in_wave` increments before `next.fetch_add`,
  so `is_complete` cannot free wave ctx under a claimer about to `apply`.
  A lost claim decrements `in_wave` and re-checks completion.

- **Darwin / Windows smoke:** schema 17 dir-variant SH body is
  `scripthash.body/NN` + `scripthash.ovf/body`. Snapshot jobs now accept
  that layout (legacy file body still ok). Default `--datadir` is
  `Path::new(".").join("datadir")` so Windows does not mix `./datadir\store`.

- **Lookup wave at-least-unless-tip:** the 8000-input floor still
  holds a thin *far* layer while more BQ heights can join, but a
  single block at store tip+1 emits so load can take it.

- **IBD most-work rewind:** a heavier header branch (resume sibling
  fork, competing tip+1, or BadPrev) disconnects to the LCA and the
  normal confirm pipeline extends the winner. Gather-then-`accept_branch`
  could not converge: awaiting was overwritten, `HELD_CAP=32` evicted
  mids, and lookup stamped disconnected BQ heights (`…f972` @ 961635
  while tip stayed on the loser).

- **IBD BadPrev / fork child at tip+1:** work-path slots are first-wins
  and prev-anchored. After `take_raw`, Reject carries the wire so
  CompetingPath still classifies; `lookup_taken_hi` rewinds to tip;
  the losing slot identity is evicted (not `mark_missing` / re-get
  the same hash). Reorg apply clears the path suffix.

- **Tip-hole / densify / receive share one in-hand rule:** confirmed,
  matching BQ hash, or `H ≤ lookup_taken_hi`. Taken loadq heights are
  not fetch holes and do not re-getdata or `mark_pending`.

- **Lookup walk after loadq take:** `block_queue_unresolved_heights`
  starts after `lookup_taken_hi`. Taken BQ rows are not a fetch hole,
  so lookup can fill loadq ahead of tip. A missing height *above*
  that high-water still stops the walk.

- **Windows / Darwin store smoke `--release` compile:** `take_raw_clone_n`
  and the raw-clone meter are `cfg(any(test, debug_assertions))`. Native
  `cargo test --release -p rbitcoin-store --lib` (windows.yml / macos.yml)
  compiles the whole test crate; the meter stays off in production
  `--release` node builds.

- **Windows store create (os error 87):** table files open
  `FILE_FLAG_OVERLAPPED` for IOCP. `TableFile::create` / `open` / trailing
  header used std `Write`/`Read`/`Seek`, which call `WriteFile`/`ReadFile`
  with a NULL `OVERLAPPED` and fail with `ERROR_INVALID_PARAMETER` on the
  first file (`scripthash.body`). Header IO is positional `IoHandle`
  pread/pwrite; grow uses `SetFileInformationByHandle`. IOCP associate no
  longer treats every 87 as success (tracked same-port rebind only).
  `windows.yml` / `macos.yml` smoke `TableFile` create/open and
  `--smoke` until `store/scripthash.body` exists. Darwin zips are ad-hoc
  `codesign -s -` (not notarized).

- **Core functional proxy ports:** Esplora binds `rpcport+20000`, not
  `node_rpc+1`. Consecutive Core `-rpcport` values made the next node's
  internal RPC land on the previous node's Esplora (`HTTP 404` on
  `getblockcount` in multi-node tests).

- **`sp_tweaks` rolls a new 4 GiB body instead of dying at `u32` off:**
  mainnet backfill hit `store: corrupt record: sp_tweaks body exceeds u32
  off` once a single body crossed 4 GiB. Schema 17 keeps the original
  `0`/`33` records and stores only a per-segment `u32` start (no
  `header_fk`). The next put whose start would exceed `u32::MAX` opens
  `sp_tweaks.{idx,body}/NNNNNN`. Leftover single files are dropped;
  backfill regenerates.

- **SH bulk materialize heartbeats during a megakey:** status INFO only ran after
  `put_chain` (unique-key boundary). One scripthash can absorb tens of millions
  of creates with no key change — mainnet shard 1 went ~6.5 min silent
  (`keys≈36.6M→38.6M`, `creates≈92.7M→155.6M`) and looked stalled. The loop now
  samples the 10 s interval every 64 Ki recs of the same key and prints
  `pending≈` (in-progress chain) so `creates`/`pct` keep moving.

- **IBD tip no longer storms getheaders / re-admits:** already-known 1-header
  announces (inflight, BQ-pending, or height ≤ tip) stay off `ordered`. Empty
  `ordered` near the peer horizon marks `headers_done` instead of fanning
  getheaders to 4 peers every loop. That loop was ~1k INFO lines/s at mainnet
  tip and blocked catch-up complete → SH → tip follow. Mid-sync 292k re-admit
  of drained-but-still-needed headers is unchanged.

- **Disconnecting a confirmed block logs `DisconnectTip` at warn:**
  `Query::disconnect_tip` (every reorg / tip restore) emits
  `DisconnectTip: hash=… height=… tx=…` so leaving the best chain is
  never silent.

- **IBD searches connecting blocks for a heavier disconnected header chain:**
  if competing tip+1 does not meet the current tip, walk prev to the
  best-chain LCA and getdata the shortest prefix whose work beats the
  losing tip (then `accept_branch`). Do not wait for the dead fork to grow.
- **Leftover pending needs no fence; in-flight prune waits for fk span:**
  write-behind `pending_fk` is already a Class A identity — TipOnly leftover
  no longer requires `height_of`. In-flight drops a layer only when
  `covers_fk_span` of that pack's create fks (not fence max height).
  Mainnet **950545** `leftover_n=1752 hit=1751` after PR #37.

- **Class C open repair is a fence complement, not a full-bit walk:**
  `Query::open` revalidates the tip window first (last six heights now also
  require those `header_txs` runs to be all-strong), rebuilds the fence on
  shrink, then runs **one** `repair_class_c_above_tip`. Repair unstrongs holes
  between fence runs plus a short suffix (stop at a 64 KiB zero page) instead
  of `for_each_strong` + `height_of` on every set bit (~1.4 B visits × 2 on
  mainnet, ~1 minute pegged CPU even after a clean shutdown). Logs
  `class_c repair cleared= ranges= ms=` even when nothing is cleared.

- **In-flight prune is fence coverage, not confirmed tip HWM:** leftover
  TipOnly accepts a create iff `fence.height_of` is `Some`. `confirmed.set_many`
  publishes tip before `height_fence_extend`, and leftover held the fence lock
  across head IO — prune-on-tip dropped just-committed layers while TipOnly
  still saw the old fence. Open-head hits wiped; valid tip+1 blacklisted
  (mainnet **945952**, `leftover_n=3546 hit=2811`, age0=100, pend=0). Prune
  now uses `fence_tip_height`; leftover clones the fence before resolve.
  Occupied-HWM form of the same implication was **929462** / **931147** /
  **933474**.

- **In-flight prune is confirmed tip, not head occupied:** planned creates stay
  until `tip >= pack max_height`. Occupied/fence_max prune dropped tip-ahead
  parents after drain while leftover TipOnly still required `height_of` — valid
  tip+1 blacklisted (mainnet **929462**, **931147**, **933474**). Leftover
  remains connected-head only. Stamp reject logs `leftover_n/hit` for the fail
  pack.

- **Load leftover parents are TipOnly `tx.head`, not an invariant:** after the
  BQ wave, some externals remain (same-batch / in-flight / not yet in the
  wave hits). Treating those as `Corrupt("external parent missing BQ TipOnly
  hit")` rejected a valid mainnet block at 928640 and stalled IBD. Load now
  TipOnly-heads leftovers; a true miss is still unresolved (not TipThenAny).

- **Lookup nested io_uring on write-behind pending hits:** IBD
  `ibd-confirm-lookup` panicked (`nested thread-local io_uring`) when stamp
  resolved a parent still in the `tx.head` pending map — `record_range` opened a
  second TLS ring inside the plan machine. The window is long while drain
  **seals** a full segment. Pending hits now run **before** the plan
  `with_thread_local` (same serial `record_range` as before).

- **Tests:** head and `tx.idx` share one thread-local soft-span override.
  `HeadScale::test_with` pins tiny/mainnet without process-global `set_var`.

- **Head resolve 2-wave:** wave 1 is open + sealed ages ≤3 again. The spend-only
  DONTCACHE change had made `head_or_idx_segment_index` always false, so hot
  probed every segment and cold was empty. Unconnected hot hits still run
  wave 2 so `TipThenAny` / `TipOnly` can take a connected sibling in age ≥4.

- **Tests:** scripts-phase steal-worker pin records the coordinator thread on
  the handle (not a process-global name). Archive plan/commit wall stats sample
  under an exclusive lock so parallel `sample_and_reset` cannot steal the
  window. Head soft-span override is thread-local so a sibling
  `test_set_soft_span_bytes(0)` cannot reset another test's 48-byte roll
  window (`tip_then_any_connected_in_cold_beats_unconnected_hot`).

- **Findings 012–021** (fuzzamoto differential): identity/BIP30 cluster,
  tapleaf, compact-block, reorg drain — all closed with named regressions.
- **Mainnet BIP30:** skip the two Core `IsBIP30Repeat` overwrites (91842 /
  91880 hashes). Those coinbases were overwritten while still unspent, not
  fully spent. IBD `bad-txns-BIP30` at logged `@91859` was the first height
  of a write batch that contained 91880.
- **Electrum tweaks subscribe:** stream remaining heights as notifications
  and finish with Cake’s `{"message":"done"}`. A one-shot 8-height result left
  the scan isolate idle after `[restore, remaining, false]`.
- **Electrum `get_balance`:** unconfirmed delta uses the mempool scripthash
  index instead of store-resolving every live chain input. Empty Cake keys were
  ~1.5 s each on a mainnet mempool.


### Removed

- **Host forensics and cargo benches:** `examples/diag_*`, `dump_wit`,
  all `[[bench]]`, `rbitcoin-store-bench`, `freeze_benches`,
  `reader_contention`, `diag_tip961461`, and ignored page-group / SH-head
  wall microbenches. Default graph is product + suite
  (`scripts/check_default_targets.test.sh`). Host A/B is musl + `ibd: perf`.

- **Unused spend-annotate wrappers:** `Store::put_spend_batch_by_create` and
  `_ranged`. Confirm write is abs-meta only
  (`put_spend_batch_by_abs_meta_known`). `put_spend` / `put_spend_batch`
  (txid) stay for `connect_block` / archive commit.

- **`script_bench` facade:** detached script verify and fixture tests use
  `ScriptCheckJob` + `verify_scripts_pool` / `verify_job_all_inputs`.

- **`rbtpkg` P2P command.** Homegrown len-prefixed package inject is gone.
  Packages stay on RPC `submitpackage` and Esplora `POST /txs/package`.

- **`RWF_DONTCACHE`:** first-party flag, capability probe, and
  `dontcache_policy`. `spent.body` is its own file; evicting those pages
  does not protect `txout`. Uring machines stay.
- Unused Core-style `check_tx_standard` (admit is Libre only).
- Path-named IO backend aliases and always-true `class_a_append_uses_pwrite`.
- `crate_name()` / `smoke_crate_names` coverage theater.

- **Dead store APIs / duplicate benches:** refuse-only `TxTable::put` /
  `Store::put_tx` / `Query::put_tx`, `body_txid_at`, and
  `head_resize_in_progress`. Deleted `script_parallel{,_ab,_focus}` and
  `rayon_audit` (they duplicated `script_pool` / `script_hotpath`).

- **Zero meters:** `WRITE_STICKY` / `WRITE_DONTNEED`, `ASM_PREV_RES_*`,
  `pin_spent_ns` / `unpin_spent_parent_outs`, `archive_resolve_stats` alias,
  and mmap-half `sample_spend_*_ab_*` helpers.

- **Hash-only confirm:** `confirm_archived_*`, hash `confirm_load_phase` /
  `confirm_script_phase`, `wire_rebuild`, and `ChainHub::confirm_hash` /
  `confirm_run`. Confirm is wire-only (`confirm_wire_*`). Store fixtures
  `Query::connect_block` / `confirm_blocks_run` stay.

- **Archive queue budget:** uncharged `ArchiveQueueBudget` / `--archive-queue-mb` /
  `RBITCOIN_ARCHIVE_QUEUE_MB`. Densify is gated by body-queue soft depth only.

- **`rbitcoin-wire-cache`:** unused tip wire-format ring crate. Node no longer
  opens `{datadir}/wire`. Reconstruct + body queue + peer wire serve tip/reorg.
  On-disk `archive_epoch.wire_depth` bytes stay unread.

- **FdOnly ceremony / leftover ghost surface:** `TableAccess` / ignored
  `RBITCOIN_TX_HEAD_ACCESS` / bench `--access`. `ibd_io_policy` (always-false
  defer). Always-empty `denserels_from_packed_records`, test-only packed
  spender-rel helpers, unused `head_insert_many_sole`, no-op
  `ConfirmParentCache::from_env`. Unprinted `connect_prevout_stats` and
  always-zero `HeadResizeSizeSnapshot` shadow fields. Printed `ibd: sizes` /
  `ASM_PREV_*` unchanged.

- **Hash-load confirm twin:** `Query::load_confirm_parents`, ConfirmParentCache
  scan watermark, and `BatchFullBodies`. Confirm load is wire-only
  (`pin_for_wire_batch` + `load_creates_once`). Reconstruct always reads
  Class A from the store. Header plans stay for MTP.

- **Dead wrappers after archive-ahead / hash-confirm:**
  `confirm_wire_lookup_and_ensure_denserels`, `ChainHub::confirm_wire_lookup_phase`
  / `_pipelined_cold` / `confirm_scripts` / `is_archived`,
  `prepare_block_for_archive_ibd`, header `put_raw`/`rewrite`, unread
  `archive_epoch` mutators, fused `get_fk_and_outs_by_txid_batch`, always-false
  `txid.body` DONTCACHE and confirm load-retry hook, no-op
  `warm_scripthash_create_index`, always-true `IndexMode::uses_durable_spends`.

- **Ghost meters those paths fed:** plan `sticky_ns` / `head_dens`, unused
  `last_stamp`, `lookup_thr resolve=` (always 0). `last_plan_batch`
  leftover_n/hit stays for stamp-reject. Live leftover `head_fk` /
  `pin_txid` / leftover CDF stay.

- **Public archive-without-confirm:** `Query::archive_block`,
  `accept_and_archive_block`, and `ChainHub::archive_block`. Confirm is sole
  Class A (`archive_plan_batch_*` + `archive_commit_plan`). Crash / `plan=None`
  tests use `commit_class_a_only`. `Query::connect_block` stays as the cheap
  store fixture. Plan stamp is TipOnly; store `TipThenAny` remains for RPC.

- **Dead DONTCACHE / IO aliases:** head/idx probe no longer threads an always-false
  DONTCACHE flag. `sealed_age_from_index` lives with winner-age stats.
  Dropped `get_outs_denserels_by_range_batch`, `spend_meta_backend_next`,
  `load_needs_resize`, `HeadRole::Tx` / `RBITCOIN_HEAD_SLOTS_TX`, and
  `RBITCOIN_IO_URING` (`RBITCOIN_IO=pread` is the only pread hatch).

## [0.1.0] — 2026-07-26

### Experimental first public packaging

Initial **0.x** packaging of an experimental Bitcoin full node in Rust:

- Multi-peer IBD and tip follow over **BIP324 v2-only** P2P
- Relational Class A/B/C archive (reconstruct historical blocks; tip wire ring + tip durability after catch-up; store later fully map-free — see `docs/io-modality.md`)
- **Pure-Rust** consensus/script path (secp256k1 via rust-bitcoin only; no libbitcoinconsensus dual-eval)
- Confirm pipeline (load / scripts / write), Direct index mode during IBD, native scripthash + in-process **Electrum** after tip
- Libre-class mempool admission with script checks on accept; BIP152 v2 compact blocks and BIP339 wtxid relay on tip sessions
- Operator docs for **signet lab first** and **experimental mainnet** (default milestone skips scripts ≤ 840000)

### Documentation

- Architecture overview for unique store / IO / consensus design (`docs/architecture.md`)
- Security policy (`SECURITY.md`), this changelog, dual MIT OR Apache-2.0 licenses

### Notes

- On-disk schema is **unstable until 1.0** (reindex on incompatible changes).
- Completing a full mainnet IBD on an operator host is **out of band** for this
  release packaging; experimental mainnet remains lab-only.
- Workspace package metadata does not claim a public `repository` URL until one
  is published.
