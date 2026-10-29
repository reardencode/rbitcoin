# Contributing

## Getting started

**Nix is not required** to clone, compile, run `--smoke`, or send a PR.
CI pins **rustc 1.95.0**; [`rust-toolchain.toml`](./rust-toolchain.toml) makes
[rustup](https://rustup.rs) install that channel (plus `rustfmt` and `clippy`)
the first time you run `cargo` in this tree. [`rust-forward.toml`](./rust-forward.toml)
is the newer compiler the `rust-forward` job checks. It is not the compiler
you develop with. Later pulls move that channel forward.

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
regtest (mine → Electrum → Esplora) in [`docs/operator/operations.md`](./docs/operator/operations.md#first-hour-regtest)
using this cargo binary (not the musl `target/release/` install).

### What works on each OS

Linux is the **supported operator IO** target (`io_uring` when the ring opens).
Darwin defaults to libc **pread** (`RBITCOIN_IO=pool` opts into the pool session); Windows to **IOCP** (no IoRing). Matrix:
[`docs/io-modality.md`](./docs/io-modality.md). PR CI still smokes native store
IO on Windows and Darwin.

| You want | Linux | macOS | Windows |
|----------|-------|-------|---------|
| `cargo build -p rbitcoin-node -p rbitcoin-cli` | yes | yes | yes |
| `rbitcoin-node --smoke` | yes | yes | yes |
| `./scripts/ci-os-smoke.sh` (store platform + mmap fuse + query confirm + `--smoke`) | yes | yes — this **is** the required `macos` job | **Git Bash** — this **is** the required `windows` job |
| `cargo fmt --all` / `cargo clippy --workspace --all-targets -- -D warnings` | yes | yes | yes |
| `cargo test --workspace` (required `test` job) | yes | usually (see `flock` below) | use **WSL2** (Ubuntu + rustup inside the distro). Native CI does **not** run the full workspace suite |
| `./scripts/coverage.sh` / `cargo deny` / `./scripts/ast-grep.sh` | yes (install extras below, or Nix) | possible; not the CI host | not the supported path |
| `nix develop` / `nix-shell` | optional pin (below) | optional pin (below) — `aarch64-darwin` | no |

**macOS Intel vs Apple Silicon:** rustup installs a native toolchain. CI `macos` is
`macos-26` (aarch64). You can develop on either; Release Darwin zips are **aarch64
only** and ad-hoc signed ([`OPERATOR.md`](./OPERATOR.md)).

**WSL2:** treat it as Linux. Install rustup *inside* the distro (not the Windows
one), clone on the Linux filesystem (`~/…`, not `/mnt/c/…`) so IO and line
endings stay sane. If Git Bash `.sh` scripts fail with `$'\r'` / "bad
interpreter", the clone used CRLF — `git config core.autocrlf input` and
re-checkout.

An editor with **rust-analyzer** at the repo root picks up `rust-toolchain.toml`.

### Core JSON (consensus tests)

`cargo test` for consensus Core vectors stages Bitcoin Core **v32.1**
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
cargo fmt --all                            # includes nested fuzz/ crate
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p rbitcoin-primitives --test suite  # fast sanity
cargo test -p rbitcoin-store --test suite        # store (tests pass Tiny at open; production default is Mainnet)
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

### Optional Nix (Linux / macOS)

[`flake.nix`](./flake.nix) `devShells` cover `x86_64-linux`, `aarch64-linux`, and
`aarch64-darwin`. They pin rustc to the same `flake.lock` as musl release builds
and set `CARGO_TARGET_DIR=target/dev` plus `RUSTFLAGS=-Dwarnings`:

```bash
nix develop   # or nix-shell — both read flake.lock, not floating <nixpkgs>
```

That is **not** the operator binary (`nix build .#rbitcoin-musl`). Details:
[`docs/reproducible-builds.md`](./docs/reproducible-builds.md).

**Release `packages` stay Linux-only** (`nix build` has no `aarch64-darwin`
attribute). The dev shell pins tool versions and builds nothing that ships, so
the static-musl constraint that excludes Darwin from `packages` does not apply
to it. Darwin operator binaries come from the `macos-26` release job, not Nix.

## Principles

Write clear, concrete technical English. Keep Core-aligned terms where we
match Bitcoin Core. Do not inject moralizing or political framing, or soften
consensus and security language. Keep a name unless a new one is clearer
engineering.

1. **One owner per fact.** The map is [`docs/README.md`](./docs/README.md).
   Update the owner file; do not add a parallel spec. Prefer
   [`docs/architecture.md`](./docs/architecture.md), [`SCHEMA.md`](./SCHEMA.md),
   and [`docs/crash-recovery.md`](./docs/crash-recovery.md) over inventing
   new design notes.
2. Prefer **high-level functional/integration tests** over unit tests
   ([`TESTING.md`](./TESTING.md)). A branch no peer, client, or operator can
   trigger is removed rather than covered by a unit.
3. Every PR must keep production line coverage **≥ 91%** (`LH*100 >= LF*91`).
   Nightly branch coverage stays ≥90% when measured. Same bar as CI via
   `./scripts/coverage.sh`. CRAP `--fail-above 30` with the allowlist in
   `.cargo-crap.toml`. Hold the floor by covering from the surface journey
   or by deleting unreachable lines, not by adding a private-helper test.
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
   not this rule. Prefer **one** [true journey](./TESTING.md#true-journeys)
   over a twin unit for the same reject. A `#[test]` that only calls other
   tests is not a journey. A small unit is only for a consensus or schema
   result a real peer, client, or operator session cannot reach without an
   absurd chain. Any other behavior no session can trigger is deleted, not
   unit-tested. Core functional is nightly, not a substitute for that journey.
9. **RAM and CPU are design inputs.** This node indexes chain-scale
   structures (tens of millions of keys, hundred-MiB arrays, GiB-class
   heads). Iterating those structures is expensive. Every algorithm should
   avoid wasting RAM and avoid wasting CPU. Spending one to save the other
   is allowed only as a **named trade** — owner doc or rustdoc on the
   surface, not an accident of the first version that compiled. FdOnly
   packed `g` (`mphf_g=0`) versus mmap sealed `.fuse8` (`fuse8=0` heap)
   and SH BDZ3 occupancy (`mphf_occ=` supers only; occ bits are `file=`)
   is that kind of choice. Reclaim of mapped fuse/occ is drop of file pages,
   not swap. `strong_tx` stays a process-resident bit image and mempool stays a
   process `Vec` (Class C tip-last write-behind / live graph); do not mmap those
   because fuse mapping looked good.

   Write as if the structure is huge, because in IBD it is. **Address** it
   (hash, slot, page, bit offset, subscript). Do not walk everything resident
   to recover the few fields this call needs. Nested loops over a loaded
   collection are guilty until the inner work is O(what this call needs),
   not O(what exists). Tiny fixtures prove correctness, not cost
   ([`TESTING.md`](./TESTING.md)).
10. **Control flow is a type problem.** Early return; session state is a
    struct, not a dozen `mut` parameters; dispatch is a catalog of named
    handlers; boolean products become enums or methods; compose (has-a)
    instead of a 30-field god struct; one owner per algorithm. A replacement
    deletes the old branch in the same change (code-shape rule 9). Do not split
    Core-faithful opcode loops or io_uring machines to beat a line count.
    Full rules, extract policy, and clippy allows:
    [`docs/code-shape.md`](./docs/code-shape.md). Named 0.6.0 extracts
    (**Q-61**) are Completed; residual peels:
    [`docs/quality.md`](./docs/quality.md) **R-10**.
11. **Crate visibility is the production graph; the suite reads it through
    `#[doc(hidden)]`.** Library tests live in `tests/suite` and link the
    normal rlib, so an item a test reaches is `pub` with `#[doc(hidden)]`.
    Plain `pub` (no hidden) and crate-root `pub use` exist only for names
    another crate actually imports, or for a **documented** public library
    API (we do not have one). If we ever ship an out-of-tree library
    surface, write the allowlist in the owner crate rustdoc and then unused
    `pub` on **that** surface is intentional. rustc does not report a dead
    hidden item, so a change that removes the last caller removes the
    callee in the same change (code-shape rule 9); `#[allow(dead_code)]`
    is not a fix, in `src/` or in a suite root. Test hooks in production
    files are `#[cfg(debug_assertions)]`, and every debug node runs that
    code, so a hook is either a bounded counter (`Cell` / atomic increment)
    or **opt-in**: off until the test arms it on its thread. Nothing
    accumulates unarmed (`spindle_mark` is the pattern). A
    `cfg(debug_assertions)` gate never covers an import or re-export that
    production code uses, and it never changes a production constant or
    code path. The node redials, retries SAM, and defers an SV2 budget on
    one interval each; a test that waits on that sleep passes the short
    duration in. How CI compiles the release profile is in
    [`TESTING.md`](TESTING.md#coverage). Tests drive the shipped function
    (principle 8), not a second test-only wrapper or `*_for_test` backdoor.
    IO-shape pins prefer session/table instance stats or on-disk file state
    over a thread-local probe. Fuzz-only `pub` is the same smell — prefer the
    in-crate graph or the published **binary** surface (`rbitcoin-node` /
    CLI) even if the harness pays a little extra setup, rather than
    exporting helpers solely for `fuzz/`.

## Workflow

Unreleased notes are one file per pull in [`changelog.d/`](./changelog.d/).
Do not edit [`CHANGELOG.md`](./CHANGELOG.md) on a feature branch. The release
cut folds those files in. Owner: [`docs/releases.md`](./docs/releases.md).

Required **jobs** match [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)
(`qc`, `test`, `windows`, `macos`, `coverage`, `pread`, `rust-forward`). `qc` is fmt, ast-grep, unwrap-ratchet, hex-ratchet, deny, the script self-tests,
clippy, then nixos-module-eval, in that order on one runner. `pread` is the
Linux libc backend for `rbitcoin-store` and `rbitcoin-query`
(`RBITCOIN_IO=pread`). `rust-forward` is `cargo check --workspace --all-targets`
on the channel in [`rust-forward.toml`](./rust-forward.toml). Both start with
`coverage`, after `qc` and `test`. The `test` job does not set `RBITCOIN_IO`
and stays on 1.95.
Label **`nixos-module-runtime`** to run the NixOS module qemu test (not
eval). That job is not required.

**Agents** open [`docs/ORIENT.md`](./docs/ORIENT.md) when the area is
unclear, follow the agent contract in
[`docs/how-we-plan.md`](./docs/how-we-plan.md#agent-contract), and use
[`.agents/skills/ship-pr/SKILL.md`](./.agents/skills/ship-pr/SKILL.md) to
open or update a pull request. Humans use ordinary git. The bot host file
does not apply to them.

Humans who want the same gates offline (Nix optional; rustup 1.95 is enough):

```bash
# nix develop   # Linux and aarch64-darwin — pin via flake.lock; or rustup + rust-toolchain.toml
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/dev}"
cargo fmt --all -- --check                 # includes nested fuzz/ crate
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
binary. Musl pin, `repro-build.sh` / `repro-check.sh`, and the tag/branch
scripts: [`docs/reproducible-builds.md`](./docs/reproducible-builds.md),
[`docs/releases.md`](./docs/releases.md). Operator install:
[`OPERATOR.md`](./OPERATOR.md). PR `windows` / `macos` jobs smoke native store
IO; they do not package zips. GitHub Releases:
[`.github/workflows/release.yml`](./.github/workflows/release.yml).

## Commits

- Small, reviewable commits with complete sentences in the message body.
- Production code and its covering scenarios land together.
- Do **not** commit live `datadir-*/`, operator `*.log` dumps, secrets, or keys
  (see `.gitignore`).

## Issues and reviews

Read the issue or the review thread before writing. Post a fact that is not
already there. When a person or a bot already reported the finding, skip it,
or agree with a short reply on that comment.

A finding names the wrong result and the reason in a few plain sentences,
including the function and the line. Stop when a reader can check it. A
heading is fine when the text under it is new.

Leave these out of a finding:

- A recap of the diff, the pull request, or the code around the line.
- The same finding in the review body and again on the line. The inline
  comment is the finding. The review body is the count line
  (`0 bugs, 1 suggestion, 0 nits`) plus a finding that has no line.
- Padding around the point: praise, a tour of the author's intent, "this is
  important because", "it is worth noting", and a sentence that restates
  the one above it.

A finding to rewrite:

> Looking at `reject_refill_miss`, this function currently returns false when
> the refill is short and only continues the stored tip. This is significant
> because it means the batch occupies the gap, and a later batch from the
> proved anchor will not replace it. It would be worth considering whether
> the next locator should start at the anchor instead of the walk tip, since
> that would avoid the stall described above.

The comment to post:

> `reject_refill_miss` returns false for a short refill that only continues
> the stored tip, so that batch occupies the gap. A later batch from the
> proved anchor never replaces it, and the next locator starts at the walk
> tip.

## Code review checklist

- [ ] Behavior covered by a true journey (or a justified unit whose result
      is consensus or schema math a real session cannot reach). A behavior
      no session can trigger is deleted. No caller-of-tests, no twin
      for the same reject. Core functional is not the PR pin
      ([`TESTING.md`](./TESTING.md#true-journeys)).
- [ ] Core-facing RPC / P2P / Electrum / Esplora: [`COMPAT.md`](./COMPAT.md)
- [ ] No new silent dead branches
- [ ] No unused crate-root `pub` / `pub use`; suite-only items are
      `#[doc(hidden)]`; a removed caller removes its callee (principle 11).
      Tests drive shipped functions, not `*_for_test` backdoors. A
      `cfg(debug_assertions)` hook is a bounded counter or opt-in, and
      gates no production import, constant, or code path. A test that
      waits on redial, SAM retry, or the SV2 cooldown passes that duration
      in. Fuzz does not
      grow `pub` without considering the binary
      surface.
- [ ] Store changes respect Class A/B/C and allocate-then-publish
- [ ] Experimental / milestone honesty preserved in user-facing docs when relevant
- [ ] No restating `//` comments. Remaining line comments name an invariant,
      protocol, `SAFETY` requirement, or library quirk the types cannot state.
- [ ] Tests assert shipped behavior, not source/docs text (`include_str!` of
      production `.rs` or markdown is not a pin).
- [ ] Hot-path algorithm is O(need) at chain scale, or the RAM/CPU trade is
      named (principle 9).
- [ ] New control flow follows principle 10 / [`docs/code-shape.md`](./docs/code-shape.md):
      early return, session structs, named dispatch, no extra boolean flags.
