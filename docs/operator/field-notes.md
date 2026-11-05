# Labs and constrained hosts

## Signet lab

Signet is a place to try a wallet or a short connectivity run. It is not a
gate in front of mainnet. The mainnet runbook, including when to turn
Electrum on and how SIGTERM resume works, is [`mainnet.md`](mainnet.md). Prefer
SIGTERM over `kill -9` (last uncommitted mempool batch may be lost on hard
kill). Same `--datadir` resumes tip from the relational archive.

### Custom Signet

A custom Signet derives its P2P message magic from the challenge. Default
Signet seeds are not used, so provide at least one peer with `--connect`.
Use a dedicated datadir for each challenge.

```bash
mkdir -p ./datadir-custom-signet
./target/release/rbitcoin-node \
  --datadir ./datadir-custom-signet \
  --network signet \
  --signet-challenge 51 \
  --signet-block-time 60 \
  --connect 192.0.2.1:38333 \
  --listen 0.0.0.0:38333 \
  --milestone 0 \
  --log-level info
```

One trusted signet peer, with listen left off. The warn list is
[`COMPAT.md`](../../COMPAT.md); the flag is
[`operations.md`](operations.md). A Bitcoin Core peer that is still under
its minimum chain work needs a download whitelist on Core's side; that
grant is in [`operations.md`](operations.md).

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-signet \
  --network signet \
  --trust-peer 192.0.2.1:38333
```

The equivalent conf-file keys are `signet_challenge` and `signet_block_time`.
Replace the illustrative `OP_TRUE` challenge and documentation-only peer with
the parameters supplied by the custom Signet operator.

## 16 GiB RAM / sluggish disk (mainnet)

The ordinary command, the milestone rule, and when to attach a wallet are
[`mainnet.md`](mainnet.md). Full-validation IBD can be disk-bound and make a
shared desktop disk sluggish.
Prefer a dedicated volume. The example below lowers the mempool weight budget;
`--mempool-size-mb` is **not** a hard process-RAM limit.

Script validation uses the in-process `rbtc-scripts-*` worker pool, initialized
from `std::thread::available_parallelism()` (fallback: 4). There is no node
worker-count option, and `RAYON_NUM_THREADS` does not configure this pool.

```bash
# The omitted --milestone uses the anchored mainnet checkpoint at 840000.
# Use --milestone 0 for full historical script validation.
nice -n 10 ionice -c 3 ./target/release/rbitcoin-node \
  --datadir /mnt/dedicated/datadir-mainnet \
  --network mainnet \
  --max-outbound 12 \
  --mempool-size-mb 200 \
  --log-level info
```

Hash-head in-place rehash is gone. An undersized leftover `header.head` may
be rewritten once at open via `header.head.grow` then rename
(`store: header.head open-grow`). An empty target-sized `header.head` with a
non-empty `header.body` is refused (wipe those files and reindex).

## Slow / constrained uplink (IBD)

`--max-outbound` / `max_outbound` is the IBD download peer count (default **16**).
IBD `target_peers` is that value clamped to **8..=32**, so `--max-outbound 4`
still dials 8 catch-up peers. Concurrent block getdata is about `N × 64`
(`IbdConfig::per_peer` is code-only 64; a 16 MiB payload cap stops one
peer holding 64 large bodies; the 1024-hash window still bounds the total;
there is no `--maxblocksperpeer`).

On a typical home uplink use **8**. That is also the floor on a tight link:
more peers will not raise a saturated wire and can make `relative-slow` peel a
mixed pack. A quiet `relative-slow` log on a uniformly slow line is intended
(cluster gate). `--connect` a known-fast peer if you have one. While `hole=` is
open, densify issues no new far getdata and tip+1 races the peers that will
drain first — that is recovery on a slow line, not a reason to raise outbound.

## Consensus notes (historical mainnet)

Full validation has fixed several pre-soft-fork script edges:

| Height / class | Issue |
|----------------|--------|
| High-S ECDSA | normalize before verify (never consensus-fail) |
| Hashtype 0 | raw byte, not `from_consensus` → ALL |
| Lax DER pre-BIP66 | always `from_der_lax`; BIP66 is encoding check |
| High-bit S, `from_der`≠lax | never prefer strict-first |
| CODESEPARATOR in scriptSig | full EvalScript(scriptSig) for bare |
| Pre-BIP16 P2SH shape | bare HASH160/EQUAL; Core BIP16Exception @ 170060 (testnet3 `00000000dd30…b105`) |

In-memory **confirm reject blacklist** clears only on process restart after a binary fix.
