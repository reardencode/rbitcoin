# Road to 1.0

What an operator or library user should be able to **count on** at **1.0**.
Day-to-day ranked work stays in [`quality.md`](./quality.md).

**Today (0.5.x):** first published line. On-disk format can still refuse a
named wipe. Electrum/Esplora need `--shindex` (default off). BIP324 v2-only.
Install is a GitHub Release (Linux musl; Windows/Darwin snapshots).

1.0 is the first **frozen-format, support-windowed** line. Not a Bitcoin
Core clone, not a soak badge, not a desktop wallet.

---

## Promises

| You should get | 1.0 |
|----------------|-----|
| **Datadir** | Every **1.x.x** opens a **1.0.0** store. No silent wipe. |
| **Chain** | No known consensus divergences from Core. |
| **Wallets** | Electrum / Esplora work for the clients we claim, on a node that finished IBD + SH index. |
| **Index time** | `--shindex` after IBD is a known, resume-safe wait — not an unbounded hour-loss. Faster than 0.5 is the point. |
| **IBD** | Typical block connect about **1 s** on a laptop-class SSD (today often 2–10 s). |
| **RAM** | **2 GiB** process RSS is enough for IBD, SH build, and tip-follow (knobs may trade wall time, e.g. serial SH build). Heap, not “the disk is in page cache.” |
| **Fees** | The 10-minute inclusion estimate is aimed at txs that actually get in, not Core’s historical estimator. |
| **P2P** | A single network neighborhood should not own your tip; junk peers / compact-block spam should not knock the node over. Peer diversity aims at **Core asmap utility** (not necessarily the same implementation). |
| **Support** | [`SECURITY.md`](../SECURITY.md) names **1.0.x** with a real window. |
| **Install** | Still the musl GitHub Release. Useful **libraries** may also be on crates.io. |

0.6 / 0.7 can ship any of this without freezing the store.

---

## Not 1.0

Things people sometimes expect from “a Bitcoin node” that we are **not**
taking on for 1.0:

- Wallet keys, GUI, prune, ZMQ, IPC, plaintext v1 P2P, explorer search APIs
- Every Bitcoin Core functional test (no wallet / prune / v1 scripts)
- Matching Core `estimatesmartfee` numbers
- Apple notarization
- A gated “we soaked mainnet for N days” badge

---

## Work that makes those promises true

### Claimed behavior actually runs

COMPAT **done** RPCs, P2P, and mempool should be covered by the Core
functional harness **or** an explicit “we differ on purpose” note (fee
product, error codes, our mempool files). Today: **44 / 267** `run`; the
interesting leftovers are dialect, not missing methods. Owner:
[`core-functional.md`](./core-functional.md), Open **Q-41**.

### Fuzz until junk input is boring

Peers and blocks should not crash the node. 0.5 has one nightly
`block_wire` job. 1.0 wants continuous coverage of **headers, blocks,
scripts, BIP324, compact blocks** — crashes become a numbered finding plus
a regression. Open **Q-30**; frozen corpora **Q-31**.

### Libraries other people can import

The operator binary is not crates.io. Two things *are* worth publishing:

| Crate | Why a stranger would care |
|-------|---------------------------|
| **Consensus engine** | Same job as `libbitcoinkernel`: structure, connect, scripts, headers, policy — **without** our store. Today `rbitcoin-consensus` is wired into IBD/query; that has to come apart first. |
| **`rbitcoin-bench`** | Electrum/Esplora **client** load tool (Casa / Sparrow / concurrent wallets). Already optional; works against Fulcrum/electrs too. |

Store, P2P, RPC, Electrum server, the node — stay in this repo. Revisit
**Q-25** only for the published crates.

### Faster scripthash, less RAM

Operators feel **wall-clock after IBD** (`--shindex`) and **RSS** while
syncing, while building the index, and at tip with wallets connected.
Target **2 GiB** process RSS in all three phases; knobs may slow the
machine to hit it. Measure on a real SSD; keep resume. Page cache is
not a leak ([`ibd-memory.md`](./ibd-memory.md)).

| Done | Step |
|:----:|------|
| [x] | Auto-tune SH recollect / materialize workers: at most **one per 1.5 GiB** host free RAM (Linux / Darwin / Windows; env still overrides) |
| [ ] | 2 GiB RSS in IBD, SH build, and tip-follow |
| [ ] | SH wall-clock after IBD (resume-safe) |

### Faster IBD

Connecting a typical mainnet block during catch-up should be about **1
second** on a laptop-class SSD, not the 2–10 s we often see now.

| Done | Step |
|:----:|------|
| [ ] | Typical IBD block connect ~1 s |

### Harder to eclipse or DoS

Today: 125 inbound, rate windows, compact-block score, v2-only discovery.
1.0 should match **Core asmap utility** (a diverse outbound set so one
netgroup cannot own the tip) even if the mechanism is not Core’s asmap
file. Also: something like **anchors** so a restart doesn’t redraw the
whole peer graph from DNS, inbound eviction that isn’t “newest wins.”
Tor can wait.

Electrum/Esplora connection caps stay always-on.

### Fee estimates that match inclusion

Product is **“in about 10 minutes under this mempool”**
([`mempool-fee-estimation.md`](./mempool-fee-estimation.md)). We cannot
prove that in general. 1.0 runs the node long enough to **record
inclusion success rate** against a stated target (and how it behaves
cold / after a fee spike). No need to mimic Core’s multi-horizon API.

### Freeze the store last

When the rest is true, tag 1.0 so **every 1.x.x opens a 1.0.0 store**.
Older-than-1.0 or corrupt files can still refuse with a one-line message.

---

## After 1.0 (unless it falls out earlier)

- BIP331 package relay, if rust-bitcoin still has no types (**Q-48**); then Electrum protocol 1.6/1.7 ([`COMPAT.md`](../COMPAT.md) § Protocol versions)
- Tor
- Publishing the store as a crate
