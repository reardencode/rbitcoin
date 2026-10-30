# Experimental mainnet runbook

**Status:** **0.8.99** (pre-0.9.0) is lab-to-operator: **early production / high-scrutiny**,
not a soak-certified badge. **Not** 1.0. **Not** a Bitcoin Core or Fulcrum
replacement. Default mainnet milestone is block 840000
(`0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5`): script/sig
checks skip only on that header path once it contains that hash and the
block is the path hash at its height.
Signet’s default milestone is 0 (every script).
Schema can still refuse a named index wipe ([`SCHEMA.md`](../SCHEMA.md)).
Design overview: [`architecture.md`](./architecture.md).

This node can perform multi-peer IBD, tip follow, Electrum (post-tip,
`--sh-index`), and Libre-class mempool participation. Treat consensus and ops
as **under active hardening**. Completing any particular full mainnet IBD is
an **operator-side** job and is **not** a packaging gate — resume catch-up on
the same datadir until tip, then run tip follow with monitoring before
trusting Electrum.

## Prerequisites

1. **Signet lab first** (below) until restart/resume and basic Electrum look sane.
2. Dedicated disk with multi‑100 GiB free (Class A grows large; `tx.head` is sparse
   but page cache / resize can pressure RAM+swap).
3. Understand **milestone** defaults (script skip) before claiming “validated mainnet.”

## Build

Musl install: [`OPERATOR.md`](../OPERATOR.md) (Build). Binary:
`./target/release/rbitcoin-node`.

## Signet lab first

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-signet \
  --network signet \
  --sh-index \
  --listen 127.0.0.1:38333 \
  --electrum-listen 127.0.0.1:50001 \
  --log-level info
```

Time-box a run with `--max-run-secs` if desired. Prefer local listen + reverse
proxy TLS for Electrum; do not expose plain Electrum to the internet.

## Mainnet catch-up (typical)

```bash
# Prefer a dedicated disk; large Class A archive.

./target/release/rbitcoin-node \
  --datadir /path/to/datadir-mainnet \
  --network mainnet \
  --listen 0.0.0.0:8333 \
  --max-outbound 16 \
  --mempool-size-mb 300 \
  --inhibit-suspend \
  --log-level info
```

Default mainnet **does not** pass `--electrum-listen` — enable Electrum only
after tip (see below). Slow or constrained uplinks: [`OPERATOR.md`](../OPERATOR.md)
(Slow / constrained uplink) — `--max-outbound 8` is the IBD floor.

### Milestone (script validation)

| Flag | Meaning |
|------|---------|
| *(default mainnet)* | Height **840000** anchored to `0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5`. Script/sig checks skip when this block and that anchor hash are the header-path occupants at their heights. Chain work is not required. Prevouts, double-spend, maturity, and fees still run, and an unspendable output is still not a coin. The difference from Core assumevalid is in [`COMPAT.md`](../COMPAT.md). |
| `--milestone HEIGHT` | Height-only skip at/below `HEIGHT` (operator speed switch). |
| `--milestone 0` | Full script validation for all heights (slower; signet’s default; use for consensus labs). |
| `--trust-peer ADDR` | Compare against one peer. Consensus checks still run and warn; this is not a faster sync. The fault list is [`COMPAT.md`](../COMPAT.md). |

Default is an **assumevalid-style speed tradeoff**, not “we validated all
historical scripts.” State this honestly when reporting experimental mainnet
results.

## Interrupt and resume

1. Prefer **SIGTERM** / Ctrl+C (clean flush of tip tables + mempool, exit 0). A scripthash or index write-behind IO error uses that same flush and then exits non-zero.
2. Same `--datadir` on restart — catch-up continues; no special “resume” flag.
3. Class A archive is largely durable mid-IBD; tip is Class C. Hard `kill -9`
   can lose the last unflushed pages.
4. Incomplete IBD **does not** enter tip mode; restart continues catch-up.
5. Ongoing first full mainnet sync may take days; stop/start is expected.

See also [`crash-recovery.md`](./crash-recovery.md).

## When Electrum is safe

Electrum is for **after** catch-up completes:

1. Node enters tip mode (SH bulk materialize + indexes).
2. Start with `--electrum-listen 127.0.0.1:50001` (TLS via reverse proxy if needed).
3. During Direct IBD, durable scripthash history may be empty/incomplete — **do
   not** point wallets at a mid-IBD node.

## Tip follow

After tip: few outbound follow peers, getheaders / inv / block accept.
Hopeless minority-fork tips (connecting path weaker than us and **>288**
blocks behind) are disconnected; stale extras rotate inside `max_outbound`.
A full 2000-header reply continues from that last hash; 120s poll skips
peers whose best-known header cannot beat our tip.
Heap caps: [`docs/ibd-memory.md`](./ibd-memory.md) (tip-follow / P2P serve).

**Compact blocks (BIP152 v2):** we advertise `sendcmpct` high-bandwidth version 2.
Incoming `cmpctblock` is reconstructed from the live mempool, orphanage, and
`extra_compact` ring ([`COMPAT.md`](../COMPAT.md)); missing txs use
`getblocktxn` / `blocktxn`. A second compact from the same peer while that
hash is already pending does not take another fill slot. The first-pass slot
bodies stay on the pending compact until `blocktxn` overlays the holes (apply
does not re-query mempool). Full `getdata` MSG_WITNESS_BLOCK remains the fallback when the
header merkle fails or `blocktxn` does not complete the holes. We serve `getblocktxn` and
`MSG_CMPCT_BLOCK` getdata from store/cache. Outbound extra prefill (10 KiB
cap) is on; `--prefill-compact=0` is coinbase-only. Generate / submit / full-block
NewPoWValid pack txs that were not in the live mempool without delaying
forward. A PoW-valid header that
extends our tip is announced as `cmpctblock` to peers who sent
`sendcmpct` announce=1 and already have the parent **before**
connect (Core `NewPoWValidBlock`); connect failure does not take that back.

**WTx (BIP339):** handshake sends `wtxidrelay` (protocol ≥70016). When the peer
also sends it, we announce and request `MSG_WTX` inventory.

**Packages:** RPC `submitpackage` admits each tx, then package-evaluates a
child-with-parents remainder (package feerate). Esplora `POST /txs/package`
is atomic `accept_package`. No P2P package command. BIP331 `NetworkMessage`
needs a rust-bitcoin upgrade.

**Misbehavior:** per-session disconnect score (threshold 100) for malformed or bad compact
payloads and oversized pending-cmpct pressure; disconnects the peer. An unsolicited compact
block from a peer that is not high-bandwidth is not misbehavior: its header is stored and the
full block is fetched (Core #32606).

**BIP324 v2 only** — discovery is v2-filtered (`x809` DNS + `P2P_V2` gossip);
see [`OPERATOR.md`](../OPERATOR.md) § P2P transport. Expect fewer usable
peers than a dual-stack Core node. The user-agent is `/rbitcoin:VERSION/`, which some peers still refuse.

## Ops risks

| Risk | Notes |
|------|--------|
| Disk / RAM | Multi‑100 GiB Class A; segmented 25-bit `tx.head.*` + mapped `.fuse8` (~1.5 GiB `RssFile`, heap `fuse8=0`); SH BDZ3 occ mapped (~150 MiB `file=` at ~1 B keys); sealed BDZ `g` FdOnly (not anon heap) |
| `tx.head` seal | Segment roll builds fuse8 on seal (~27 M keys); watch seal begin/done logs — not a mono-head shadow fill |
| Peer scarcity | [`OPERATOR.md`](../OPERATOR.md) § P2P transport (`x809` seeds + `P2P_V2` gossip). `/rbitcoin:VERSION/` is not a Core user-agent, so some peers still refuse inbound |
| Mempool | Libre policy (0.1 sat/vB, full RBF + pure RBFR 1.25×, no dust ban, Libre annex); cluster **64 / 101 kvB**; **scripts verified on accept** |
| Confirm lookup/load | **Load** recvs load-sized batches (soft **8000** inputs / hard **144** blocks) from `loadq=14`. Dense mainnet is typically **a few blocks per batch**. IBD **lookup** TipOnly-resolves at most **64000** inputs or **1080** BQ-ready heights per wave, in order from `path_lo`. Real queues loadq=14 · scriptq=4 · writeq=14 |
| Not Core/Fulcrum | No production SLA; 0.8.99 is high-scrutiny 0.x; schema unstable until 1.0; schema 24/25 open in place (rewrite to 26); occupied 0.6.x stores refuse (wipe + IBD) |

## Related docs

- Architecture (store / IO / consensus uniqueness): [`architecture.md`](./architecture.md)
- Operator knobs, custom Signet flags, 16 GiB RAM, consensus notes: [`OPERATOR.md`](../OPERATOR.md)
- Product scope / Electrum methods: [`COMPAT.md`](../COMPAT.md)
- Security reporting: [`SECURITY.md`](../SECURITY.md)
