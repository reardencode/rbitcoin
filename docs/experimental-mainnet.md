# Experimental mainnet runbook

**Status:** **0.5** is lab-to-operator: **early production / high-scrutiny**,
not a soak-certified badge. **Not** 1.0. **Not** a Bitcoin Core or Fulcrum
replacement. Default `--milestone 840000` skips historical script/sig checks.
Schema can still refuse a named index wipe ([`SCHEMA.md`](../SCHEMA.md)).
Design overview: [`architecture.md`](./architecture.md).

This node can perform multi-peer IBD, tip follow, Electrum (post-tip,
`--shindex`), and Libre-class mempool participation. Treat consensus and ops
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
after tip (see below).

### Milestone (script validation)

| Flag | Meaning |
|------|---------|
| *(default mainnet)* | `--milestone` defaults to **840000**: **script/sig checks skipped** at/below that height. Prevouts, double-spend, maturity, fees still run. |
| `--milestone 0` | Full script validation for all heights (slower; use for consensus labs). |

Default is an **assumevalid-style speed tradeoff**, not “we validated all
historical scripts.” State this honestly when reporting experimental mainnet
results.

## Interrupt and resume

1. Prefer **SIGTERM** / Ctrl+C (clean flush of tip tables + mempool).
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
Incoming `cmpctblock` is reconstructed from the mempool short-id map; missing txs
use `getblocktxn` / `blocktxn`. Full `getdata` MSG_WITNESS_BLOCK remains the
fallback when mempool is cold or fill fails. We serve `getblocktxn` and
`MSG_CMPCT_BLOCK` getdata from store/cache. A PoW-valid header that extends
our tip is announced as `cmpctblock` to other HB peers **before** connect
(Core `NewPoWValidBlock`); connect failure does not take that back.

**WTx (BIP339):** handshake sends `wtxidrelay` (protocol ≥70016). When the peer
also sends it, we announce and request `MSG_WTX` inventory.

**Packages:** `accept_package` via RPC `submitpackage` / Esplora
`POST /txs/package`. No P2P package command. BIP331 `NetworkMessage` needs a
rust-bitcoin upgrade.

**Misbehavior:** per-session ban score (threshold 100) for unsolicited/bad compact
payloads and oversized pending-cmpct pressure; disconnects the peer.

**BIP324 v2 only** — discovery is v2-filtered (`x809` DNS + `P2P_V2` gossip);
see [`OPERATOR.md`](../OPERATOR.md) § P2P transport. Expect fewer usable
peers than a dual-stack Core node (experimental user-agent still limits inbound).

## Ops risks

| Risk | Notes |
|------|--------|
| Disk / RAM | Multi‑100 GiB Class A; segmented 25-bit `tx.head.*` + fuse8 in RAM (~1.5 GiB); sealed BDZ `g` FdOnly (not anon heap) |
| `tx.head` seal | Segment roll builds fuse8 on seal (~27 M keys); watch seal begin/done logs — not a mono-head shadow fill |
| Peer scarcity | [`OPERATOR.md`](../OPERATOR.md) § P2P transport (`x809` seeds + `P2P_V2` gossip). Experimental user-agent still limits inbound |
| Mempool | Libre policy (0.1 sat/vB, full RBF + pure RBFR 1.25×, no dust ban, Libre annex); cluster **64 / 101 kvB** (Core-class); **scripts verified on accept** |
| Confirm lookup/load | **Load** recvs load-sized batches (soft **8000** inputs / hard **144** blocks) from `loadq=14`. Dense mainnet is typically **a few blocks per batch**. IBD **lookup** TipOnly-resolves at most **64000** inputs or **1080** BQ-ready heights per wave, in order from `path_lo`. Real queues loadq=14 · scriptq=4 · writeq=14 |
| Not Core/Fulcrum | No production SLA; 0.5 is high-scrutiny 0.x; schema unstable until 1.0; reindex on incompatible layout changes |

## Related docs

- Architecture (store / IO / consensus uniqueness): [`architecture.md`](./architecture.md)
- Operator knobs and IBD log lines: [`OPERATOR.md`](../OPERATOR.md)
- Product scope / Electrum methods: [`COMPAT.md`](../COMPAT.md)
- Security reporting: [`SECURITY.md`](../SECURITY.md)
