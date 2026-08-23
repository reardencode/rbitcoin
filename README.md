# rbitcoin

Bitcoin **full node** in Rust aimed at **production server-side** use: multi-peer
IBD, tip follow, block/tx relay (tip mode), optional **Core-class JSON-RPC**, and
in-process **Electrum + optional Esplora REST for wallet clients** (scripthash
index via `--shindex`, default off; not a graphical block-explorer stack) — built
around a **libbitcoin-class relational archive** and a **pure-Rust
consensus/script** path.

> **0.5.2** is the current **named published** 0.x line (GitHub Release:
> Linux musl + Windows CRT-static + Darwin aarch64). **Not 1.0:** schema can
> still refuse a named wipe ([`SCHEMA.md`](./SCHEMA.md), [`OPERATOR.md`](./OPERATOR.md));
> default mainnet **`--milestone 840000` skips historical script/sig checks**
> (`--milestone 0` is full scripts); Electrum/Esplora need **`--shindex`**
> (default off) after tip. Run **signet first**, then mainnet with monitoring.
> Report security issues privately: [`SECURITY.md`](./SECURITY.md). Runbook:
> [`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

| | |
|--|--|
| **License** | MIT OR Apache-2.0 ([`LICENSE-MIT`](./LICENSE-MIT), [`LICENSE-APACHE`](./LICENSE-APACHE)) |
| **Version** | **0.5.2** — [`CHANGELOG.md`](./CHANGELOG.md) |
| **Platform** | **Linux musl** is the operator path. Windows / Darwin are published snapshots (no IoRing; Darwin not notarized) |
| **Security** | [`SECURITY.md`](./SECURITY.md) — **0.5.x** supported published line; no LTS until 1.0 |
| **Design** | [`docs/architecture.md`](./docs/architecture.md) — why this node is different |

## Why this node is different

Most full nodes center a **UTXO set + block files** (Bitcoin Core). Most Electrum
backends are **external indexers** of another node. rbitcoin does neither:
**no UTXO set** (libbitcoin-class archive), **Electrum + txindex in-process**.

Operator-order facts (mainnet tip moves; treat as ballpark, not a warranty):

- **~200 GiB** hot pin/annotate set after schema 17 (`txout` + `spent` + idx +
  `txid` + `tx.head`); **~700 GiB** if you keep cold `inwit` for reconstruct.
  Optional `--shindex` is extra (Electrum/Esplora require it; on/off costs in
  [`OPERATOR.md`](./OPERATOR.md)). Ballpark, not a warranty — census in
  [`SCHEMA.md`](./SCHEMA.md)
- **Core-class JSON-RPC subset** (default off): [`docs/rpc.md`](./docs/rpc.md)
- **Under ~30 h** IBD on a laptop-class host with **`--milestone 0`** (full scripts)
- **Modest RAM** during sync — no multi‑GiB `dbcache`, no long “flush the cache”
  pauses (confirm is lookup → load → scripts → write)
- **Segmented `tx.head`** — **newer** txs resolve hottest (tip-local traffic wins)
- **Pure-Rust** consensus/scripts on rust-bitcoin (**no** `libbitcoinconsensus`)
- **Reproducible static musl** builds for ordinary Linux hosts

1. **On-disk archive** — **map-free** Class A/B/C tables (pread/pwrite + fallocate
   grow; kernel page cache as L0): split Class A (`txout` / `inwit` / `spent`),
   keyless `tx.head`, spend annotations, native scripthash. Historical blocks are **reconstructed** from
   the archive; tip serve / reorg uses the in-RAM body queue and peer wire.
   Confirm/mempool prevouts use the archive (and in-mempool parents), not a
   separate UTXO hash table. Layout: [`SCHEMA.md`](./SCHEMA.md); IO:
   [`docs/io-modality.md`](./docs/io-modality.md); concurrency:
   [`docs/concurrency.md`](./docs/concurrency.md).
2. **Concurrent IBD / IO** — fixed writer roles (one Class A appender),
   allocate-then-publish HWMs (no map epochs), confirm as **lookup → load →
   scripts → write**, bulk **io_uring** where available (pread/pwrite fallback).
   Linux-shaped IO; porting needs work. Map:
   [`docs/concurrency.md`](./docs/concurrency.md).
3. **Pure-Rust consensus** — structure, connect, and **script verification in
   Rust**; only **secp256k1** (via rust-bitcoin) as the crypto primitive — **no**
   `libbitcoinconsensus` dual-eval. Tests: [`docs/consensus-tests.md`](./docs/consensus-tests.md).

Full narrative and Core / Fulcrum contrasts: **[`docs/architecture.md`](./docs/architecture.md)**.
Product surface: [`COMPAT.md`](./COMPAT.md).

## Status

Core pipelines exist (store, consensus, P2P IBD, tip follow, scripthash,
Electrum, Esplora REST, libre mempool) for the **server-side / wallet-client
backend** role. **0.5 mainnet** is early production / high-scrutiny — not a
Core or Fulcrum replacement, not a soak badge. Run **signet first**, then
mainnet with monitoring ([`OPERATOR.md`](./OPERATOR.md)). First hour on
regtest (mine → Electrum → Esplora): [`OPERATOR.md`](./OPERATOR.md#first-hour-regtest).
Finishing any one operator’s first full mainnet sync is **not** a gate for
using or packaging this tree. 1.0 gates:
[`docs/road-to-1.0.md`](./docs/road-to-1.0.md).

**Non-goal:** powering a **graphical block explorer** (search boxes,
address-prefix autocomplete, explorer-only catalogue APIs). Product surface:
[`COMPAT.md`](./COMPAT.md).

**Authorship:** first-party code is **AI-written** (Grok / xAI) under
**Brandon Black** ([@reardencode](https://github.com/reardencode)) prompting —
details in [`SECURITY.md`](./SECURITY.md).

**Milestone (default mainnet 840000):** at/below `--milestone`, **script/sig
checks are skipped** on block connect (assumevalid-style speed tradeoff).
Prevouts, double-spend, maturity, and fees still run. Use **`--milestone 0`**
for full script validation.

```bash
# Portable static release (preferred)
nix build .#rbitcoin-musl
install -m 755 result/bin/rbitcoin-node result/bin/rbitcoin-cli target/release/

# Signet lab (time-boxed)
./target/release/rbitcoin-node --datadir ./datadir-signet --network signet \
  --listen 127.0.0.1:38333 --milestone 200000 --max-run-secs 120
```

Custom Signets are supported with `--signetchallenge` and
`--signetblocktime`; see the [custom Signet example](./OPERATOR.md#custom-signet).

## Build

### Portable static release (recommended)

Pinned **nixpkgs + Cargo.lock** produce a **fully static, portable**
`rbitcoin-node` / `rbitcoin-cli` (musl) that runs on ordinary Linux hosts without
Nix or a matching glibc. Byte-identical digests for a given revision + target.
Not NixOS-specific — any machine with [Nix](https://nixos.org/download/) + flakes:

```bash
nix build .#rbitcoin-musl          # default package; fully static
# or: ./scripts/repro-build.sh
install -m 755 result/bin/rbitcoin-node result/bin/rbitcoin-cli target/release/
./scripts/repro-build.sh           # day-to-day musl install (crane-layered)
./scripts/repro-check.sh           # release only: two clean rebuilds; compare digests
```

Do **not** use `cargo build --release` inside `nix-shell` / `nix develop` as the
operator binary — that links against the Nix store glibc and fails outside the
store (`No such file or directory` at exec). Details:
[`docs/reproducible-builds.md`](./docs/reproducible-builds.md).

### Dev / CI path

Requires Rust **1.95** (workspace `rust-version`, matching Nix/CI). Prefer the
**same pin** as release builds for tests and clippy:

```bash
nix develop   # or: nix-shell  (both use flake.lock, not floating <nixpkgs>)
cargo build --workspace
cargo test --workspace
./scripts/coverage.sh   # PR bar (Actions); see CONTRIBUTING.md / AGENTS.md
```

Agents implement on a worktree branch and let GitHub Actions run the
workspace/coverage gates — see [`AGENTS.md`](./AGENTS.md).

Operator binary: always the static install under `./target/release/` (or
`./result/bin/`), or the GitHub Release for a `v*.*.*` tag. PR CI smokes
Windows / Darwin store IO; it does not package zips.
Operator knobs: [`OPERATOR.md`](./OPERATOR.md). Experimental mainnet:
[`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

## Crate map

| Crate | Role |
|-------|------|
| `rbitcoin-primitives` | Shared types / newtypes |
| `rbitcoin-store` | Map-free Class A/B/C tables (fd pread/pwrite), scripthash, bulk IO |
| `rbitcoin-query` | Domain API (archive, confirm, reconstruct, Electrum joins) |
| `rbitcoin-consensus` | Validation / confirm; pure-Rust scripts; milestone = scripts only |
| `rbitcoin-net` | P2P + IBD (modular `ibd/`), tip follow, relay |
| `rbitcoin-mempool` | Cluster graph + libre admission |
| `rbitcoin-electrum` | Electrum TCP server |
| `rbitcoin-esplora` | Esplora REST + wallet-scoped WS (opt-in) |
| `rbitcoin-log` | Leveled stderr logger |
| `rbitcoin-rpc` | Documented Core-class JSON-RPC subset (not full Core) |
| `rbitcoin-cli` | CLI client |
| `rbitcoin-node` | Node binary |
| `rbitcoin-bench` | Optional Electrum/Esplora **client** benchmark (`--features cli`; not a default/musl product bin) |
| `rbitcoin-test` | High-level test harness |

## Documentation

Full map (one owner per fact): **[`docs/README.md`](./docs/README.md)**.

| Audience | Start |
|----------|-------|
| Operator | [`OPERATOR.md`](./OPERATOR.md) |
| Product / interop | [`COMPAT.md`](./COMPAT.md) |
| Contributor | [`CONTRIBUTING.md`](./CONTRIBUTING.md) |
| Agent | [`AGENTS.md`](./AGENTS.md) |
| On-disk | [`SCHEMA.md`](./SCHEMA.md) |
| Tests | [`TESTING.md`](./TESTING.md) |

Design uniqueness: [`docs/architecture.md`](./docs/architecture.md).
Security contact: [`SECURITY.md`](./SECURITY.md).

## What this is not

- Production multi-tenant Electrum or “drop-in Core”
- Wallet, mining, GUI, or pruning
- Full Core JSON-RPC surface
- A claim of complete mainnet script validation under the **default** milestone
  (use `--milestone 0` for full scripts)
- A multi-OS port — **Linux is the supported IO target** today

## License

Licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions. See
[`CONTRIBUTING.md`](./CONTRIBUTING.md).
