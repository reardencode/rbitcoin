# Reproducible builds

Contributors with **Nix** (not necessarily NixOS) can produce **byte-for-byte
identical**, **fully static (musl)** release binaries of `rbitcoin-node` and
`rbitcoin-cli` for a given git revision and target triple. These run on ordinary
Linux hosts without a Nix store or matching glibc.

Host-installed `rustc`, floating `import <nixpkgs> {}`, and
`cargo build --release` inside `nix-shell` / `nix develop` are **not** the
release path. The latter links against the Nix-store glibc interpreter and fails
with `No such file or directory` when run outside that environment. Use the
pinned flake (or `default.nix` + `flake.lock`) musl package.

## What is pinned

| Input | Mechanism |
|-------|-----------|
| nixpkgs (rustc, cargo, musl, linker, …) | `flake.lock` → `nixpkgs` rev + `narHash` |
| crane (layered cargo builder) | `flake.lock` → `crane` rev + `narHash` |
| Rust crate graph | `Cargo.lock` (crates.io checksums) |
| Source tree | Flake `self` filtered via cargo-aware `cleanSourceWith` in `nix/rbitcoin.nix` |

### Pin policy (nixpkgs channel)

| Policy | Detail |
|--------|--------|
| Channel | NixOS **stable/large** branch (`nixos-YY.MM`) — currently **`nixos-26.05`** |
| Why not unstable | Hydra-tested channel + official binary cache; less churn for release digests |
| Lock | Exact commit via `flake.lock`; `shell.nix` / `default.nix` read the same lock |
| Update cadence | Deliberate (`nix flake update`), ~each stable release or near EOL — not daily |
| Co-bumps | **crane**, GHA `dtolnay/rust-toolchain@…`, root `rust-toolchain.toml`, shell `llvmPackages`, AGENTS toolchain strings |
| Verify after bump | `nix develop` → fmt/clippy/test; `nix build .#rbitcoin-musl` static install |
| Dependabot | [`.github/dependabot.yml`](../.github/dependabot.yml) opens **monthly** Nix PRs (plus weekly Cargo / Actions). Treat flake PRs as proposals — still co-bump and verify as above before merge |

### Dependabot take / skip

| Update | Take? | How |
|--------|-------|-----|
| Cargo **patch** / safe **minor** | Yes if CI green | Dependabot PR or hand `cargo update` |
| Cargo **major** with API or dual-graph risk | Human PR only | Full suite; prefer one stack (e.g. axum + tower-http + tungstenite) |
| **`bitcoin_hashes`** | **Ignore in Dependabot** | Co-bump with **`bitcoin` / bip324 / rust-bitcoin** only (must match `bitcoin`’s hashes major) |
| **`dtolnay/rust-toolchain`** | **Ignore in Dependabot** | Tag **is** rustc; co-bump with **nixpkgs / crane / shell llvm** only |
| Other Actions (`checkout`, `codeql-action`, `rust-cache`) | Yes after CI smoke | Prefer full semver or commit SHA; never rewrite the rustc pin in the same PR without a flake bump |
| **nixpkgs / crane** | Deliberate only | Monthly Dependabot is a proposal; co-bump CI rustc + docs |

Channel branches advance only after Hydra succeeds ([channel branches](https://wiki.nixos.org/wiki/Channel_branches); status at [status.nixos.org](https://status.nixos.org/)). That is the “tested snapshot” — not a floating `master` commit.

Release builds set remapped path prefixes and strip symbols so digests do not
depend on the builder’s checkout path or username.

### Heap allocator

Product binaries (`rbitcoin-node`, `rbitcoin-cli`) use
**mimalloc** as the process-wide `#[global_allocator]` on both targets:

| Package | Link | Allocator |
|---------|------|-----------|
| `rbitcoin-musl` | fully static musl | mimalloc (compiled into the binary) |
| `rbitcoin-glibc` | dynamic glibc | mimalloc (static into binary; libc is still glibc) |

Library unit tests keep the platform default allocator. Mimalloc is not selected
via `LD_PRELOAD` — static musl cannot use preload, and the Rust global allocator
path is the same for both packages.

### Crane layers (build speed)

`nix/rbitcoin.nix` uses **crane**:

1. **`buildDepsOnly` → `cargoArtifacts`** — registry/git deps (and build scripts).
   Invalidates when the **lock/graph** changes, not on every `.rs` edit.
2. **`buildPackage`** — workspace crates (`rbitcoin-node`, `rbitcoin-cli`,
   `rbitcoin-store`) linked against that artifact set.

Day-to-day: one `nix build .#rbitcoin-musl` (or `./scripts/repro-build.sh`).
After the deps layer is in the store, app-only changes rebuild far less.

**GitHub Actions:** [`.github/workflows/release.yml`](../.github/workflows/release.yml)
runs that same one-build path on `v*.*.*` tags (and `workflow_dispatch`
without publishing). It stages with `scripts/stage-musl-artifacts.sh`
(`file(1)` must say statically linked). PR `ci` does **not** build musl.
Not `repro-check.sh`.

### Windows / Darwin snapshots (not Nix)

Fully static musl is **Linux-only**. Nix cannot ship a portable Darwin or
Windows operator binary the same way:

| OS | Why not Nix `pkgsStatic` | What ships / what PR CI runs |
|----|--------------------------|----------------|
| **Windows** | No musl-style fully static PE from this flake; mingw cross is a different CRT than operators run | **Release:** `windows-2022` + rustc **1.95** + `-C target-feature=+crt-static`. Stage script refuses VC++ / MinGW runtime DLLs. **PR `ci`:** store platform tests + `--smoke` |
| **Darwin** | Apple forbids a static `libSystem` link. `nix build` on a Mac is store-rpath (not portable) | **Release:** `macos-14` + rustc **1.95**. Stage script allows only `/usr/lib` and `/System/Library` dylibs. Ad-hoc `codesign -s -` (not notarized). **aarch64 only**. **PR `ci`:** store platform tests + `--smoke` |

Staging for Releases: `scripts/stage-native-artifacts.sh`. Not byte-identical
with the musl package. Windows IoRing is not supported.

### GitHub Release (`v*.*.*` tags)

Cut, merge, tag, `vX.Y.x`, and the `.99` bump:
[`releases.md`](./releases.md). After the ship SHA is on the branch:

```bash
./scripts/release-post.sh      # tag + vX.Y.x when this is X.Y.0
./scripts/release.sh --dry-run
```

[`.github/workflows/release.yml`](../.github/workflows/release.yml) builds the
same three snapshots on that tag and attaches them to a GitHub Release:

| File | Notes |
|------|--------|
| `rbitcoin-node-x86_64-linux` / `rbitcoin-cli-x86_64-linux` | Static musl; **operator** binary |
| `SHA256SUMS.linux-musl` + `rbitcoin.cdx.json` | Checksums + CycloneDX from `scripts/sbom.sh` |
| `rbitcoin-*-x86_64-windows.exe` + `SHA256SUMS.windows` | CRT-static PE |
| `rbitcoin-*-aarch64-darwin` + `SHA256SUMS.darwin` | Ad-hoc codesign; not notarized |

`workflow_dispatch` on that workflow builds artifacts only (no Release).

**Byte-identity gate** (`./scripts/repro-check.sh`) still forces two clean
`--rebuild`s — use it for release verification, not every commit.

### Host cargo vs musl (artifact silos)

Do not expect host `cargo test` / coverage to warm the musl release (or the reverse).

| Silo | Location | Command |
|------|----------|---------|
| Dev (gnu debug) | `target/dev` | `nix-shell` → fmt / clippy / `cargo test` |
| Coverage (gnu + llvm-cov) | `target/cov` | `./scripts/coverage.sh` |
| Musl release | Nix store + install to `target/release/` | `nix build .#rbitcoin-musl` |

`target/dev` and `target/cov` are split so instrumented and uninstrumented
fingerprints never thrash each other.

## Requirements

- [Nix](https://nixos.org/download/) 2.18+ with flakes enabled  
  (`experimental-features = nix-command flakes` in `nix.conf`)
- Network access the first time a pin is fetched into the store
- Linux (packages are Linux-only; primary CI/agent is `x86_64-linux`)

## Build (primary / portable static)

From the repository root:

```bash
# Preferred — fully static musl (also the flake default package)
nix build .#rbitcoin-musl
# Binaries:
#   ./result/bin/rbitcoin-node
#   ./result/bin/rbitcoin-cli

# Install where operators typically look:
mkdir -p target/release
install -m 755 result/bin/rbitcoin-node result/bin/rbitcoin-cli target/release/

# CycloneDX 1.5 from Cargo.lock (not a crane output — lockfile only):
./scripts/sbom.sh                    # writes ./rbitcoin.cdx.json
# or: python3 scripts/sbom.py --out rbitcoin.cdx.json


# Helper (same attr; default target is musl)
./scripts/repro-build.sh
# or: ./scripts/repro-build.sh musl
```

Non-flake equivalent (still uses **`flake.lock`**, not `<nixpkgs>`):

```bash
nix-build -A rbitcoin-musl
```

Target triple is host-CPU musl (`x86_64-unknown-linux-musl` on x86_64 hosts,
`aarch64-unknown-linux-musl` on aarch64 hosts) via `pkgsStatic`.

Dev shell with the **same** pin (for tests/clippy — **not** for operator release
binaries):

```bash
nix develop
# or: nix-shell   # shell.nix reads flake.lock
cargo test --workspace
```

## Optional: glibc dynamic (Nix-store linked)

Only needed if you intentionally want a dynamic glibc link for store-native
Nix environments. **Not** portable off the Nix store; not the operator default.

```bash
nix build .#rbitcoin
./scripts/repro-build.sh glibc
# or: nix-build -A rbitcoin
```

**Bit-identity with the musl build is not expected**; only same-target digests
must match across two clean builds of the same package.

### Optional: aarch64-linux cross (x86_64 host)

```bash
nix build .#rbitcoin-aarch64
./scripts/repro-build.sh aarch64
```

Pulls a full cross toolchain (large). Prefer musl for routine multi-target
checks when disk or cache is limited.

## Verify byte-identity (same platform)

Two independent clean rebuilds must yield the same SHA-256 for each binary:

```bash
./scripts/repro-check.sh          # musl static (primary)
./scripts/repro-check.sh both     # musl + optional glibc
./scripts/repro-check.sh glibc    # glibc only
```

What the script does:

1. Realize the package once (`nix build`) so a prior store path exists
2. Run **`nix build --rebuild` twice** (re-executes the builder; logs must
   contain `checking outputs of '….drv'…` — plain cache hits fail the check)
3. SHA-256 `rbitcoin-node` / `rbitcoin-cli` after each rebuild and `diff`
4. Never falls back to a plain `nix build` for the second pass (that would false-pass)

You can also compare by hand:

```bash
nix build .#rbitcoin-musl --out-link /tmp/rbitcoin-a --rebuild
nix build .#rbitcoin-musl --out-link /tmp/rbitcoin-b --rebuild
sha256sum /tmp/rbitcoin-a/bin/* /tmp/rbitcoin-b/bin/*
```

Identical store paths after two pure builds are also fine; always hash the
**file contents** of the bins when reporting digests.

## Layout

| Path | Role |
|------|------|
| `flake.nix` / `flake.lock` | Pinned inputs (nixpkgs + crane) + package outputs (`default` = musl) |
| `nix/rbitcoin.nix` | Crane `buildDepsOnly` + `buildPackage` for node + CLI (+ store utils) |
| `default.nix` | Non-flake attrset using the same pins |
| `shell.nix` | Dev shell from the same nixpkgs pin |
| `scripts/repro-build.sh` | **Day-to-day** one-shot musl build + digests |
| `scripts/repro-check.sh` | **Release-only** double clean rebuild gate |

## Non-goals

- Matching digests across different target triples or OS/libc combinations
- Reproducibility with an arbitrary host Rust toolchain outside Nix
- Guix-style bootstrap of the compiler itself
- Shipping nix-shell `cargo build --release` binaries as the operator product
