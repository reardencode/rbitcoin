# Contributing

## Getting started

**Nix is not required** to clone, compile, run `--smoke`, or send a PR.
CI pins **rustc 1.95.0**; [`rust-toolchain.toml`](./rust-toolchain.toml) makes
[rustup](https://rustup.rs) install that channel (plus `rustfmt` and `clippy`)
the first time you run `cargo` in this tree.

Operator Linux binaries stay the musl path in [`README.md`](./README.md) /
[`OPERATOR.md`](./OPERATOR.md). This section is **developing the tree**.

### Prerequisites

| Need | Why | Typical install |
|------|-----|-----------------|
| **Git** | Clone this repo. Do **not** `git clone --recurse-submodules` — that would pull all of Bitcoin Core. Consensus tests sparse-clone ~16 MiB via [`scripts/core-functional/init-submodule.sh`](./scripts/core-functional/init-submodule.sh). | [git-scm.com](https://git-scm.com) (Windows: Git for Windows, includes Git Bash) |
| **Rust 1.95** via rustup | Workspace `rust-version` / CI. Distro `apt install rustc` / Homebrew `rust` will **not** honor `rust-toolchain.toml`. | [rustup.rs](https://rustup.rs) — then `cd` into the clone; `rustc --version` should print `1.95.0` |
| **C compiler** | `rbitcoin-node` / `rbitcoin-cli` link **mimalloc** (`cc` crate). rust-bitcoin's secp256k1 also compiles C. | Linux: `gcc` or `clang` (`build-essential` on Debian/Ubuntu). macOS: `xcode-select --install`. Windows: MSVC **Build Tools** ("Desktop development with C++"); rustup's default host is `x86_64-pc-windows-msvc` |
| **Bash** | Helper `scripts/*.sh` and the Windows/macOS CI smoke. | Linux/macOS: `/bin/bash`. Windows: **Git Bash** (same shell CI uses). PowerShell can `cargo build` but not those scripts |

First `cargo` also fetches crates.io deps. Keep several **GiB** free for `target/`.

### Clone and first build

```bash
git clone https://github.com/reardencode/rbitcoin.git
cd rbitcoin
# rustup reads rust-toolchain.toml (1.95.0 + rustfmt + clippy)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/dev}"   # matches CI; optional
rustc --version   # expect 1.95.0
cargo build -p rbitcoin-node -p rbitcoin-cli
```

Windows **cmd**: `set CARGO_TARGET_DIR=target\dev` then the same `cargo build`.
PowerShell: `$env:CARGO_TARGET_DIR = "target/dev"`. Git Bash: same `export` as above.

Binaries land at `$CARGO_TARGET_DIR/debug/rbitcoin-node` (`.exe` on Windows).
Without `CARGO_TARGET_DIR`, cargo uses `target/debug/`.

### Smoke (create a tiny store, exit)

Same flag the required `windows` / `macos` CI jobs run:

```bash
# Unix — datadir is disposable
./target/dev/debug/rbitcoin-node --smoke --network regtest \
  --datadir /tmp/rb-smoke --no-seeds --log-level error
```

```bat
REM Windows cmd (adjust path if you did not set CARGO_TARGET_DIR)
target\dev\debug\rbitcoin-node.exe --smoke --network regtest --datadir %TEMP%\rb-smoke --no-seeds --log-level error
```

Do **not** point `--datadir` at a mainnet tree for this. Next: first-hour
regtest (mine → Electrum → Esplora) in [`OPERATOR.md`](./OPERATOR.md#first-hour-regtest)
using this cargo binary (not the musl `target/release/` install).

### What works on each OS

Linux is the **supported operator IO** target (`io_uring` when the ring opens).
Darwin defaults to the **pool** session; Windows to **IOCP** (no IoRing). Matrix:
[`docs/io-modality.md`](./docs/io-modality.md). PR CI still smokes native store
IO on Windows and Darwin.

| You want | Linux | macOS | Windows |
|----------|-------|-------|---------|
| `cargo build -p rbitcoin-node -p rbitcoin-cli` | yes | yes | yes |
| `rbitcoin-node --smoke` | yes | yes | yes |
| `./scripts/ci-os-smoke.sh` (store platform tests + `--smoke`) | yes | yes — this **is** the required `macos` job | **Git Bash** — this **is** the required `windows` job |
| `cargo fmt --all` / `cargo clippy --workspace --all-targets -- -D warnings` | yes | yes | yes |
| `cargo test --workspace` (required `test` job) | yes | usually (see `flock` below) | use **WSL2** (Ubuntu + rustup inside the distro). Native CI does **not** run the full workspace suite |
| `./scripts/coverage.sh` / `cargo deny` / `./scripts/ast-grep.sh` | yes (install extras below, or Nix) | possible; not the CI host | not the supported path |
| `nix develop` / `nix-shell` | optional pin (below) | flake `devShells` are **Linux-only** (`x86_64-linux`, `aarch64-linux`) | no |

**macOS Intel vs Apple Silicon:** rustup installs a native toolchain. CI `macos` is
`macos-14` (aarch64). You can develop on either; Release Darwin zips are **aarch64
only** and ad-hoc signed ([`OPERATOR.md`](./OPERATOR.md)).

**WSL2:** treat it as Linux. Install rustup *inside* the distro (not the Windows
one), clone on the Linux filesystem (`~/…`, not `/mnt/c/…`) so IO and line
endings stay sane. If Git Bash `.sh` scripts fail with `$'\r'` / "bad
interpreter", the clone used CRLF — `git config core.autocrlf input` and
re-checkout.

An editor with **rust-analyzer** at the repo root picks up `rust-toolchain.toml`.

### Core JSON (consensus tests)

`cargo test` for consensus Core vectors stages Bitcoin Core **v31.1**
`src/test/data/*.json` from `third_party/bitcoin`. If that tree is missing,
tests run [`scripts/core-functional/init-submodule.sh`](./scripts/core-functional/init-submodule.sh)
(sparse clone, ~16 MiB). The script needs **git**, **bash**, and **`flock`**:

- Linux: `flock` is from util-linux (usual distro default).
- macOS: not always present — `brew install flock` (or run the script after
  that package is on `PATH`).
- Windows: Git Bash often has **no** `flock`; native `Command::new` on a `.sh`
  also fails. Populate the sparse checkout from WSL or skip to store/node smoke.
  Do not `git submodule update --init` (full Core clone).

You can also run the script yourself before the first consensus test:

```bash
./scripts/core-functional/init-submodule.sh
```

### Day-to-day commands

```bash
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/dev}"
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p rbitcoin-primitives --lib          # fast sanity
cargo test -p rbitcoin-store --lib               # store (set RBITCOIN_HEAD_SCALE=tiny if you want CI-like heads)
cargo test --workspace                           # default suite — Linux / macOS; see table
./scripts/ci-os-smoke.sh                         # Windows/macOS PR surface
```

Suite tiers, budgets, coverage: [`TESTING.md`](./TESTING.md). Design:
[`docs/architecture.md`](./docs/architecture.md). Map: [`docs/README.md`](./docs/README.md).

### Optional tools (CI extras)

Not needed to compile or `--smoke`. CI installs prebuilts; locally:

| Tool | Local | Job |
|------|-------|-----|
| **cargo-deny** | `cargo install cargo-deny --locked` then `cargo deny check` | `deny` |
| **ast-grep** | [ast-grep.github.io](https://ast-grep.github.io) (or Nix) then `./scripts/ast-grep.sh` | `ast-grep` |
| **cargo-llvm-cov** | `cargo install cargo-llvm-cov --locked` + `rustup component add llvm-tools-preview` then `./scripts/coverage.sh` | `coverage` |

### Optional Nix (Linux)

[`flake.nix`](./flake.nix) `devShells` exist only for **Linux**. They pin rustc
to the same `flake.lock` as musl release builds and set `CARGO_TARGET_DIR=target/dev`
plus `RUSTFLAGS=-Dwarnings`:

```bash
nix develop   # or nix-shell — both read flake.lock, not floating <nixpkgs>
```

That is **not** the operator binary (`nix build .#rbitcoin-musl`). Details:
[`docs/reproducible-builds.md`](./docs/reproducible-builds.md).

## Principles

1. **One owner per fact.** The map is [`docs/README.md`](./docs/README.md).
   Update the owner file; do not add a parallel spec. Prefer
   [`docs/architecture.md`](./docs/architecture.md), [`SCHEMA.md`](./SCHEMA.md),
   and [`docs/crash-recovery.md`](./docs/crash-recovery.md) over inventing
   new design notes.
2. Prefer **high-level functional/integration tests** over unit tests
   ([`TESTING.md`](./TESTING.md)).
3. Every PR must keep **≥90% line** coverage on first-party code (and ≥90%
   branch when measured on nightly) via `./scripts/coverage.sh` — same bar as CI.
4. Target is **production server-side** node software (wallet backends, etc.).
   Tip-mode mempool + tx relay are **in scope**; no pruning/GUI/end-user wallet/
   mining without an explicit plan change.
5. Store durability / tip commit: [`docs/crash-recovery.md`](./docs/crash-recovery.md)
   and [`docs/concurrency.md`](./docs/concurrency.md).
6. Security-sensitive reports go through [`SECURITY.md`](./SECURITY.md), not
   public issues.
7. **Source-code comments are a smell.** A comment that restates *what* the
   next statements do means the code itself is not clear — prefer names,
   types, and structure that read as the algorithm. A comment that restates
   *why* those statements exist means the function name or signature is not
   carrying the contract — prefer a name and type that make the reason
   obvious at the call site. A comment that explains a *weird* approach
   usually means the language, library, or framework is a poor fit — prefer
   changing the approach or isolating the quirk at a named boundary. Most
   comments should not exist. Keep a comment only when a specific remaining
   clarity problem (an invariant, protocol rule, or `SAFETY` requirement
   the types cannot state) or a specific quirk of why this code exists (a
   library or workaround constraint that would otherwise look like a bug)
   still requires it. Crate and public-item rustdoc (`//!` / `///`) that
   documents a surface, not a walkthrough of the next line, is not this
   rule.
8. **Tests assert behavior, not the repo.** Default-suite tests drive a
   **shipped** function or scenario and assert an **observable** result
   (return, store after reopen, peer/RPC/log line). Do not `include_str!`
   production sources or markdown and `contains` identifiers, comments, or
   call graphs. Fixture JSON/hex and tests that read **datadir** bytes are
   not this rule.
9. **RAM and CPU are design inputs.** This node indexes chain-scale
   structures (tens of millions of keys, hundred-MiB arrays, GiB-class
   heads). Iterating those structures is expensive. Every algorithm should
   avoid wasting RAM and avoid wasting CPU. Spending one to save the other
   is allowed only as a **named trade** — owner doc or rustdoc on the
   surface, not an accident of the first version that compiled. FdOnly
   packed `g` (`mphf_g=0`) versus fuse8 in RAM is that kind of choice.

   Write as if the structure is huge, because in IBD it is. **Address** it
   (hash, slot, page, bit offset, subscript). Do not walk everything resident
   to recover the few fields this call needs. Nested loops over a loaded
   collection are guilty until the inner work is O(what this call needs),
   not O(what exists). Tiny fixtures prove correctness, not cost
   ([`TESTING.md`](./TESTING.md)).

## Workflow

Matches [`.github/workflows/ci.yml`](./.github/workflows/ci.yml). Required
checks are **separate jobs** on every push/PR (`fmt`, `deny`, `clippy`,
`ast-grep`, `test`, `multinode`, `coverage`) so a red run shows which gate
failed without digging into a monolithic job log.

**Agents** implement on a **git worktree** topic branch, commit per plan step,
and open **one PR** per plan. They do **not** run the full workspace suite or
coverage locally by default — they poll these Actions jobs to green. After
merge they remove the worktree and delete the local **and** remote topic
branch. See [`AGENTS.md`](./AGENTS.md) (worktree + PR, after-merge cleanup)
and [`docs/how-we-plan.md`](./docs/how-we-plan.md).

Humans who want the same gates offline (Nix optional; rustup 1.95 is enough):

```bash
# nix develop   # Linux only — pin via flake.lock; or rustup + rust-toolchain.toml
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/dev}"
cargo fmt --all -- --check
# rustc warnings are denied via workspace.lints (+ RUSTFLAGS=-Dwarnings in the Nix shell)
cargo build --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check                 # advisories + licenses (deny.toml)
cargo build -p rbitcoin-node -p rbitcoin-cli
cargo test --workspace
./scripts/coverage.sh
```

Windows/macOS contributors matching PR CI: `./scripts/ci-os-smoke.sh` (Git Bash
on Windows) rather than the full workspace suite.

### Release binaries (portable static, byte-identical)

Do **not** treat host or nix-shell `cargo build --release` as the operator
binary. Musl pin, `repro-build.sh` / `repro-check.sh`, and `scripts/release.sh`:
[`docs/reproducible-builds.md`](./docs/reproducible-builds.md). Operator install:
[`OPERATOR.md`](./OPERATOR.md). PR `windows` / `macos` jobs smoke native store
IO; they do not package zips. GitHub Releases:
[`.github/workflows/release.yml`](./.github/workflows/release.yml).

## Commits

- Small, reviewable commits with complete sentences in the message body.
- Production code and its covering scenarios land together.
- Do **not** commit live `datadir-*/`, operator `*.log` dumps, secrets, or keys
  (see `.gitignore`).

## Code review checklist

- [ ] Behavior covered by a high-level scenario (or justified narrow test)
- [ ] No new silent dead branches
- [ ] Public API preferred over `#[cfg(test)]` white-box access
- [ ] Store changes respect Class A/B/C and allocate-then-publish
- [ ] Experimental / milestone honesty preserved in user-facing docs when relevant
- [ ] No restating `//` comments. Remaining line comments name an invariant,
      protocol, `SAFETY` requirement, or library quirk the types cannot state.
- [ ] Tests assert shipped behavior, not source/docs text (`include_str!` of
      production `.rs` or markdown is not a pin).
- [ ] Hot-path algorithm is O(need) at chain scale, or the RAM/CPU trade is
      named (principle 9).
