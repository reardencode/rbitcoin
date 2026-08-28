# rbitcoin

Bitcoin **full node** in Rust aimed at **production server-side** use: multi-peer
IBD, tip follow, block/tx relay (tip mode), optional **Core-class JSON-RPC**, and
in-process **Electrum + optional Esplora REST for wallet clients** (scripthash
index via `--shindex`, default off; not a graphical block-explorer stack) — built
around a **libbitcoin-class relational archive** and a **pure-Rust
consensus/script** path.

> **0.5.1** is the current **named published** 0.x line (GitHub Release:
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
| **Version** | **0.5.1** — [`CHANGELOG.md`](./CHANGELOG.md) |
| **Platform** | **Linux musl** is the operator path. Windows / Darwin are published snapshots (no IoRing; Darwin not notarized) |
| **Security** | [`SECURITY.md`](./SECURITY.md) — **0.5.x** supported published line; no LTS until 1.0 |
| **Design** | [`docs/architecture.md`](./docs/architecture.md) — why this node is different |
| **Develop** | rustup 1.95, no Nix — [`CONTRIBUTING.md`](./CONTRIBUTING.md) |

## Why this node is different

Most full nodes center a **UTXO set + block files** (Bitcoin Core). Most Electrum
backends are **external indexers** of another node. rbitcoin does neither:
**no UTXO set** (libbitcoin-class archive), **Electrum + txindex in-process**.

- **~200 GiB** hot pin/annotate set (schema 17); **~700 GiB** with cold `inwit` —
  census in [`SCHEMA.md`](./SCHEMA.md), `--shindex` costs in [`OPERATOR.md`](./OPERATOR.md)
- **Under ~30 h** IBD on a laptop-class host with **`--milestone 0`**
- **Modest RAM** during sync — no multi‑GiB `dbcache` pause
- **Pure-Rust** consensus/scripts (**no** `libbitcoinconsensus`)
- **Reproducible static musl** for ordinary Linux hosts

Core / Fulcrum contrasts: **[`docs/architecture.md`](./docs/architecture.md)**.
Product surface: [`COMPAT.md`](./COMPAT.md). RPC subset: [`docs/rpc.md`](./docs/rpc.md).

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
details in [`SECURITY.md`](./SECURITY.md). Default milestone and script skip:
[`OPERATOR.md`](./OPERATOR.md). Signet lab:
[`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

## Build

### Develop (any OS, Nix optional)

**Nix is not required.** Rust **1.95** via [rustup](https://rustup.rs)
([`rust-toolchain.toml`](./rust-toolchain.toml)). Clone, first build, `--smoke`,
and Windows/macOS notes: **[`CONTRIBUTING.md`](./CONTRIBUTING.md)** (Getting
started).

```bash
git clone https://github.com/reardencode/rbitcoin.git && cd rbitcoin
cargo build -p rbitcoin-node -p rbitcoin-cli
```

Linux-only optional pin (`nix develop` / `nix-shell`, same `flake.lock` as
release). Agents use a worktree branch and let Actions run workspace/coverage
gates — [`AGENTS.md`](./AGENTS.md).

### Portable static release (Linux operator)

Pinned **nixpkgs + Cargo.lock** musl static binaries. Commands and
byte-identity: [`docs/reproducible-builds.md`](./docs/reproducible-builds.md).
Day-to-day flags: [`OPERATOR.md`](./OPERATOR.md). Experimental mainnet:
[`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

Do **not** use `cargo build --release` inside `nix-shell` / `nix develop` as the
operator binary — that links against the Nix store glibc and fails outside the
store.

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
| Contributor | [`CONTRIBUTING.md`](./CONTRIBUTING.md) (getting started: rustup, Linux / macOS / Windows) |
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
