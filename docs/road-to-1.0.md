# Road to 1.0

What an operator or library user should be able to **count on** at **1.0**.
Day-to-day ranked work stays in [`quality.md`](./quality.md).

**Today (0.6.99):** in-tree toward **0.7.0**. Last published tag is **0.6.0**
(`v0.6.x` patch line). Schema **20**
(BDZ2 `tx.head` / BDZ3 SH) can still refuse a named index wipe.
Electrum/Esplora need `--shindex` (default off). BIP324 v2-only. Install is
a GitHub Release (Linux musl; Windows/Darwin snapshots). Nightly
differential fuzz vs Core v31.1 is continuous (**Q-30**). Core functional
inventory is **71** `run` / **196** `skip` (**Q-41**). Findings **001–023**
are fixed.

1.0 is the first **frozen-format, support-windowed** line. Not a Bitcoin
Core clone, not a soak badge, not a desktop wallet.

0.6.99 / 0.7 can ship any remaining gate without freezing the store.

---

## Promises

| You should get | 1.0 |
|----------------|-----|
| **Datadir** | Every **1.x.x** opens a **1.0.0** store. No silent wipe. |
| **Chain** | No known consensus divergences from Core. |
| **Wallets** | Electrum / Esplora work for the clients we claim, on a node that finished IBD + SH index. |
| **Index time** | `--shindex` after IBD is a known, resume-safe wait — not an unbounded hour-loss. Faster than 0.5 is the point. |
| **IBD** | Typical block connect about **1 s** on a laptop-class SSD. |
| **RAM** | **2 GiB** process RSS is enough for IBD, SH build, and tip-follow (knobs may trade wall time, e.g. serial SH build). Heap, not “the disk is in page cache.” |
| **Fees** | The 10-minute inclusion estimate is aimed at txs that actually get in, not Core’s historical estimator. |
| **P2P** | A single network neighborhood should not own your tip; junk peers / compact-block spam should not knock the node over. Outbound peers use **Core asmap** ASN buckets when `ip_asn.dat` is loaded, else IPv4 `/16` / IPv6 `/32`. |
| **Support** | [`SECURITY.md`](../SECURITY.md) names **1.0.x** with a real window. |
| **Install** | Still the musl GitHub Release. Useful **libraries** may also be on crates.io. |

---

## Not 1.0

Things people sometimes expect from “a Bitcoin node” that we are **not**
taking on for 1.0:

- Wallet keys, GUI, prune, ZMQ, IPC, plaintext v1 P2P, explorer search APIs
- Every Bitcoin Core functional test (no wallet / prune / v1 scripts)
- Matching Core `estimatesmartfee` numbers
- Apple notarization
- A gated “we soaked mainnet for N days” badge
- Publishing the store / node on crates.io

---

## Work that makes those promises true

### Claimed behavior actually runs

COMPAT **done** RPCs, P2P, and mempool should be covered by the Core
functional harness **or** an explicit “we differ on purpose” note (fee
product, error codes, our mempool files). First green was 9 scripts; **71**
unmodified v31.1 scripts `run` now. Remaining growth is claimed
wallet-client / P2P / mempool / buried-activation scripts, not the
product-never skips (`no-wallet`, prune, v1). Labeled dummy
`getnetworkhashps` is documented in [`rpc.md`](./rpc.md). Remaining
claimed-surface `run` growth is [`quality.md`](./quality.md) **Q-41**.
Owner: [`core-functional.md`](./core-functional.md).

| Done | Step |
|:----:|------|
| [x] | Harness + inventory + nightly / labeled `core-functional` job |
| [x] | 71 unmodified v31.1 scripts `run` (was 9) |
| [ ] | Claimed COMPAT-done surface is `run` or an explicit dialect/differ note (**Q-41**) |

### Fuzz until junk input is boring

**Q-30 Completed.** Nightly `fuzz.yml` (not a required PR check) feeds
BIP324 parser + live Core v2 session, header/block `submitblock`
(height-1 / spend / fork / N-reorg / BIP68 CSV-age), compact reconstruct
vs Core `getblocktxn`, compact reorg via `drain_pending`, mempool /
script-verify vs `testmempoolaccept`, and ASan wire parsers (`block_wire`,
`addrv2`, `inv`/`getdata`, Electrum JSON). Crashes →
`docs/external_findings/` + named regression. JSON corpora stay static.
Frozen signet/mainnet **Electrum** packs are still **Q-31** (fuzz already
merges tiny block bins).

Keep this in-tree (cargo-fuzz + pinned Core v31.1 tarball). Do not move it
to [bitcoinfuzz](https://github.com/bitcoinfuzz/bitcoinfuzz): that project
diffs library parse/eval APIs in-process. Ours is a live Core node oracle.

### Libraries other people can import

The operator binary is not crates.io. Two things *are* worth publishing:

| Crate | Why a stranger would care | Today |
|-------|---------------------------|-------|
| **Consensus engine** | Same job as `libbitcoinkernel`: structure, connect, scripts, headers, policy — **without** our store | `rbitcoin-consensus` still depends on query/store |
| **`rbitcoin-bench`** | Electrum/Esplora **client** load tool (Casa / Sparrow / concurrent wallets) | Optional crate; not crates.io. Host-only vs Fulcrum/electrs too |

Store, P2P, RPC, Electrum server, the node — stay in this repo. Revisit
**Q-25** only for the published crates.

| Done | Step |
|:----:|------|
| [ ] | Split consensus off query/store, then crates.io |
| [ ] | Publish `rbitcoin-bench` (optional; does not block the operator binary) |

### Faster scripthash, less RAM

Operators feel **wall-clock after IBD** (`--shindex`) and **RSS** while
syncing, while building the index, and at tip with wallets connected.
Target **2 GiB** process RSS in all three phases; knobs may slow the
machine to hit it. Measure on a real SSD. Page cache is not a leak
([`ibd-memory.md`](./ibd-memory.md)).

Resume is already the contract: SIGINT keeps sealed SH heads; restart
packs unsealed shards only ([`OPERATOR.md`](../OPERATOR.md) § Scripthash).
Pack workers auto-tune to **one per 2 GiB** host free RAM (`RBITCOIN_SH_MERGE_WORKERS`
override). Collect is nCPU. `tx.head` wipe-rebuild is one worker per 1 GiB.
Operator copy still says post-IBD SH is **tens of minutes to a few hours**;
enable-after-tip is often multi-hour. 1.0 needs a named host number that
beats 0.5, not a new resume design.

| Done | Step |
|:----:|------|
| [x] | Resume-safe SH materialize (sealed heads kept; unsealed shards only) |
| [x] | Auto-tune SH pack workers: at most **one per 2 GiB** host free RAM (Linux / Darwin / Windows; env still overrides) |
| [x] | Auto-tune `tx.head` wipe-rebuild: one worker per **1 GiB** free RAM |
| [ ] | 2 GiB process RSS in IBD, SH build, and tip-follow (host measure) |
| [ ] | Named post-IBD SH wall-clock on laptop SSD, faster than 0.5 |

### Faster IBD

Connecting a typical mainnet block during catch-up should be about **1
second** on a laptop-class SSD.

The “often 2–10 s” line this doc used at 0.5.0 is stale. Last instrumented
fat-era catch-up was **6.4 blk/s** at #126 (2026-08-18). That has **not**
been re-baselined after IBD cadence, tip-accept OS thread, reactor-safe
mempool accept, or schema 20. 1.0 is a named host measurement on a
laptop-class SSD — not another in-tree cadence tweak unless that number
misses ~1 s.

| Done | Step |
|:----:|------|
| [x] | IBD cadence, tip-accept off the reactor, confirm without coordinator threads |
| [ ] | Host-measured typical IBD block connect ~1 s (or confirm 6.4 blk/s still holds) |

### Harder to eclipse or DoS

Landed since 0.5.0: 125 inbound + rate windows + compact misbehavior score;
v2-only discovery (**Q-49**); Core-style inbound eviction (protect
prefix netgroup / recent block / recent tx / min-ping, then longest-connected —
not newest-wins); `{datadir}/peers` persist with connected/fast/slow flags
so restart does not redraw solely from DNS; compact prefill monotonic +
in-bounds; `held_seq` FIFO; `requested_blocks` 10 s expire; Electrum/Esplora
caps always-on. Outbound IBD and tip-follow prefer unused **netgroups**
(Core asmap ASN when `ip_asn.dat` is loaded, else IPv4 `/16` / IPv6 `/32`);
when the outbound set is full, a stale extra evicts a duplicate-group peer
before a unique one; `--connect` skips the filter. Map path and load
warnings: [`OPERATOR.md`](../OPERATOR.md) § P2P. Inbound protect stays
prefix groups (asmap is outbound-only).

Still 1.0: AddrMan tried/new **caps** so the book cannot grow without bound;
`announced_wtx` must roll instead of `clear()` at 50k (INV burst). Those
leftovers are **Q-60**. Dedicated Core `anchors.dat` can wait if
`{datadir}/peers` already ranks last-good outbounds. Tor can wait.

| Done | Step |
|:----:|------|
| [x] | v2-only discovery; inbound cap + rate windows; compact score |
| [x] | Inbound eviction is not newest-wins (Core protect-then-oldest) |
| [x] | `{datadir}/peers` persist + rank last-good / fast |
| [x] | Compact prefill monotonic; held FIFO; getdata retry on unanswered |
| [x] | IBD / tip-follow outbound diversity (asmap ASN or prefix); stale evict prefers duplicate groups (**Q-60**) |
| [ ] | AddrMan caps + `announced_wtx` roll (**Q-60**) |

### Fee estimates that match inclusion

Engine v2 is shipped: 10-minute inclusion under live stock + inflow EMA,
cold start on the frontier, confirm-memory floor
([`mempool-fee-estimation.md`](./mempool-fee-estimation.md)). That is the
product. 1.0 still needs a **recorded inclusion success rate** against that
target (cold / after a fee spike) on a real mempool — not a soak badge
(**Q-35** stays Won't-fix) and not Core `estimatesmartfee` numbers.

| Done | Step |
|:----:|------|
| [x] | 10-minute inclusion estimator (v2) on Electrum / Esplora |
| [ ] | Recorded inclusion success rate vs that target (cold + fee-spike) |

### Freeze the store last

When the rest is true, tag 1.0 so **every 1.x.x opens a 1.0.0 store**.
Older-than-1.0 or corrupt files can still refuse with a one-line message.

Do not freeze while Class C / sidecar / fuse8 can lose a `set` or index
OOB (**Q-57**), or while mempool persist claims LIVE slots before the body
is durable (**Q-58**). Schema 20 is the current bytes; 0.x may still bump.

| Done | Step |
|:----:|------|
| [x] | No silent wipe; refuse names the dirs ([`SCHEMA.md`](../SCHEMA.md)) |
| [ ] | Q-57 / Q-58 fail-closed on the durable path |
| [ ] | Tag 1.0.0; `SECURITY.md` names a 1.0.x window |

---

## After 1.0 (unless it falls out earlier)

- BIP331 package relay, if rust-bitcoin still has no types (**Q-48**); then Electrum protocol 1.6/1.7 ([`COMPAT.md`](../COMPAT.md) § Protocol versions)
- Tor
- Publishing the store as a crate
