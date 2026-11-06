# rbitcoin

[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/rbitcoin-org/rbitcoin/badges/coverage.json)](TESTING.md)

Bitcoin **full node** in Rust aimed at **production server-side** use: multi-peer
IBD, tip follow, block/tx relay (tip mode), optional **Core-class JSON-RPC**, and
in-process **Electrum + optional Esplora REST** (scripthash index via
`--sh-index`, default off; **0.8** Core+electrs drop-in:
[`COMPAT.md`](./COMPAT.md)) — built
around a **relational archive (Class A/B/C)** and a **pure-Rust
consensus/script** path.

> **0.9.99** is the in-tree version (pre-**0.10.0**). The published
> GitHub Release is **0.9.0**. The patch line is **`v0.9.x`**.
> Mainnet is the network to run. A consensus split is vanishingly
> unlikely. **1.0** is where further hardening, a support window, and
> signed release binaries are planned. This release is not signed.
>
> The default mainnet milestone is block **966143**
> (`00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3`),
> Bitcoin Core 32.1’s `defaultAssumeValid` block.
> Script and signature checks skip only when that hash and the block being
> connected are the header-path occupants at their heights. Stored minimum
> chain work is not that gate. `--milestone 0` checks every script. An
> explicit height skips by height alone. Signet and testnet4 check every
> script by default.
>
> Occupied **0.6.x** stores refuse: wipe the datadir and sync again.
> Schema **24 and 25** open in place and rewrite to **26**. A published
> **0.8** directory is already schema 26. Electrum and Esplora need
> **`--sh-index`** (default off) for address history. Report security
> issues privately: [`SECURITY.md`](./SECURITY.md). Runbook:
> [`docs/operator/mainnet.md`](./docs/operator/mainnet.md).

| | |
|--|--|
| **License** | MIT OR Apache-2.0 ([`LICENSE-MIT`](./LICENSE-MIT), [`LICENSE-APACHE`](./LICENSE-APACHE)) |
| **Version** | **0.9.99** (pre-0.10.0) — [`CHANGELOG.md`](./CHANGELOG.md). Published release **0.9.0**, patch line **`v0.9.x`**. |
| **Platform** | **Linux musl** (x86_64 and aarch64) is the operator path. The container image is `ghcr.io/rbitcoin-org/rbitcoin`. Windows / Darwin are published snapshots (no IoRing; Darwin not notarized) |
| **Security** | [`SECURITY.md`](./SECURITY.md) — **0.9.x** is the published line; support window and signed binaries are 1.0 |
| **Design** | [`docs/architecture.md`](./docs/architecture.md) — why this node is different |
| **Develop** | rustup 1.95, no Nix — [`CONTRIBUTING.md`](./CONTRIBUTING.md) |
| **Coverage** | Live production-file LCOV (badge; last green `master` `coverage` job). Every PR **must not drop** that ratio. Highest published line coverage among bitcoin full nodes — [`TESTING.md`](./TESTING.md) |

## Why this node is different

Most full nodes center a **UTXO set + block files** (Bitcoin Core). Most Electrum
backends are **external indexers** of another node. rbitcoin does neither:
**no UTXO set** (relational archive), **Electrum + txindex in-process**.

- **~200 GiB** hot pin/annotate set (schema 17); **~730 GiB** with the cold append-only files (`seqsigwit` ~486, `txstat` ~11, `input` ~29) —
  census in [`SCHEMA.md`](./SCHEMA.md), `--sh-index` costs in [`OPERATOR.md`](./OPERATOR.md)
- **Under ~30 h** IBD on a laptop-class host with **`--milestone 0`**
- **Modest RAM** during sync — no multi‑GiB `dbcache` pause
- **Pure-Rust** consensus/scripts (**no** `libbitcoinconsensus`)
- **Highest published line coverage** among bitcoin full nodes (live production-file LCOV on the badge; every PR **must not drop** that ratio) — [`TESTING.md`](./TESTING.md)
- **Reproducible static musl** for ordinary Linux hosts

Core / Fulcrum contrasts: **[`docs/architecture.md`](./docs/architecture.md)**.
Product surface: [`COMPAT.md`](./COMPAT.md). RPC subset: [`docs/rpc.md`](./docs/rpc.md).

## Status

Core pipelines exist (store, consensus, P2P IBD, tip follow, scripthash,
Electrum, Esplora REST, libre mempool) for the **server-side / wallet-client
backend** role. Mainnet is that job. It is not a full Core RPC clone and
not Fulcrum. First hour on regtest (mine → Electrum → Esplora):
[`docs/operator/operations.md`](./docs/operator/operations.md#first-hour-regtest).
The mainnet runbook is [`docs/operator/mainnet.md`](./docs/operator/mainnet.md).
Ongoing test growth is [`docs/quality.md`](./docs/quality.md). A 1.0 tag
is the support window and signed binaries in [`SECURITY.md`](./SECURITY.md).

**0.8:** drop-in for **mempool/electrs or Blockstream electrs HTTP** (not
address-prefix, not their `/api/v1/` Node process). Core RPC for that stack
is TCP plus an opt-in Core cookie (`--rpc-cookie-file`), so stock mempool
`CORE_RPC` works unpatched; a unix-socket patch stays optional. Product
surface: [`COMPAT.md`](./COMPAT.md).

**Authorship:** first-party code is **AI-written** (Grok / xAI) under
**Brandon Black** ([@reardencode](https://github.com/reardencode)) prompting —
details in [`SECURITY.md`](./SECURITY.md). Default milestone and script skip:
[`docs/operator/mainnet.md`](./docs/operator/mainnet.md). Signet and a
constrained host: [`docs/operator/field-notes.md`](./docs/operator/field-notes.md).

## Build

### Develop (any OS, Nix optional)

**Nix is not required.** Rust **1.95** via [rustup](https://rustup.rs)
([`rust-toolchain.toml`](./rust-toolchain.toml)). Clone, first build, `--smoke`,
and Windows/macOS notes: **[`CONTRIBUTING.md`](./CONTRIBUTING.md)** (Getting
started).

```bash
git clone https://github.com/rbitcoin-org/rbitcoin.git && cd rbitcoin
cargo build -p rbitcoin-node -p rbitcoin-cli
```

Linux-only optional pin (`nix develop` / `nix-shell`, same `flake.lock` as
release). Agents use one worktree per session (topic branch per PR) and let
Actions run workspace/coverage gates — [`AGENTS.md`](./AGENTS.md).

### Portable static release (Linux operator)

Pinned **nixpkgs + Cargo.lock** musl static binaries. Commands and
byte-identity: [`docs/reproducible-builds.md`](./docs/reproducible-builds.md).
Day-to-day flags: [`OPERATOR.md`](./OPERATOR.md). Mainnet:
[`docs/operator/mainnet.md`](./docs/operator/mainnet.md).

Do **not** use `cargo build --release` inside `nix-shell` / `nix develop` as the
operator binary — that links against the Nix store glibc and fails outside the
store.

## Crates

Workspace crate ownership and dependency orientation:
[`docs/CRATES.md`](./docs/CRATES.md).

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

Seqsigwit-window prune (`--prune-seqsigwit`), BIP158 filters, silent-payment
tweaks, GBT, and the SV2 template provider are product.

## What this is not

- Production multi-tenant Electrum or “drop-in Core”
- A wallet, a GUI, Core `-prune` of `blk` files, or a full Core RPC clone
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
