# Code shape

How production Rust in this tree should read. Principles 7–9
([`CONTRIBUTING.md`](../CONTRIBUTING.md)) still own comments, tests, and
RAM/CPU. This file owns **control flow, types, naming, and composition**.

Named extracts that applied these rules: [`quality.md`](./quality.md) **Q-61**
(Completed). Residual god-file peels: **R-10**.

Confirm stage IO, leftover union, and store roles stay in
[`invariants.md`](./invariants.md) / [`concurrency.md`](./concurrency.md) —
do not restate them here.

---

## Rules

1. **Early return.** Reject, `continue`, and `?` first. Do not nest four
   levels of `if` / `match` / `for` to reach the work.

2. **Session state is a type.** More than a handful of related `mut`
   parameters is a struct (`PeerFollowState`, `ElectrumConn`). Do not thread
   twelve booleans and maps through a dispatch function.

3. **Dispatch is a table.** `match method` / `match NetworkMessage` arms
   call named handlers. Help text, method lists, and dispatch share **one**
   catalog so they cannot drift.

4. **Boolean products become enums or methods.** `IndexMode` methods, not
   five independent flags at every call site. `PendingSendCmpct::{None, Lb, Hb}`,
   not `AtomicU8` 0/1/2. Four `bool`s in one orchestrator is an enum.

5. **Composition, not a 30-field god struct.** `ChainHub` *has* held bodies
   and mining knobs; `Query` *has* SH write-behind. Keep façade methods on
   the outer type so callers do not churn.

6. **One owner per algorithm.** Display-order 32-byte hex lives in
   `rbitcoin-primitives`. A mempool admit walk used by accept and
   test-accept is one helper. Do not copy reverse-then-hex or pin-view
   forks into each crate.

7. **Names say the pick rule.** `resolve_txid_tip` versus
   `resolve_txid_tip_then_any`. In one crate, `hub` is not both `ChainHub`
   and `PeerHub` without a qualifier (`chain` / `peers`).

8. **Do not split to beat `wc -l`.** Bitcoin script's opcode `match`,
   io_uring machines, and MPHF construction stay dense on purpose. A peel
   needs a **named seam** (two stages, two protocols, two roles) — see
   **R-10**.

9. **One path.** A change that replaces a behavior deletes the old branch
   in the same change. Do not leave the old way behind a flag, a
   thread-local, a test-only wrapper, or a second function that does the
   same job. Confirm-stage IO has the same rule in
   [`invariants.md`](./invariants.md).

10. **First cause.** A wrong result is fixed in the type that already owns
    the fact. Do not add a downstream parser of that type's `Display`, or
    of any other rendered text, to recover a distinction the type already
    made. `ConsensusError` owns a header failure. `block_reject_reason` is
    the BIP22 text. A caller that needs the reason matches the error. A
    change that replaces a text parser deletes that parser in the same
    change (rule 9).

---

## Extract under tests

Behavior-preserving moves still follow Red → Green → Refactor
([`how-we-plan.md`](./how-we-plan.md)). This is a **move**, not a second
implementation:

1. Find the existing production implementations and every caller.
2. Choose the crate that owns the concept (rule 6).
3. If an arm has no observable assert, add one **before** moving the code.
4. Green is the extract only — no new branches. Wrap the old API, switch one
   caller at a time, keep `cargo check -p <crate>` compiling.
5. Delete the old path, the unused flag, and restating comments.

Do not invent a failing test for a pure move that is already pinned.
Do not copy the helper into a test-friendly crate and leave the original
(Miri peels included).

---

## Lint

CI is `cargo clippy --workspace --all-targets -- -D warnings`.

`rbitcoin-log`, `rbitcoin-mempool`, `rbitcoin-rpc`, `rbitcoin-electrum`,
`rbitcoin-esplora`, and `rbitcoin-cli` are `#![forbid(unsafe_code)]` on
each crate root (`lib.rs`, and `rbitcoin-cli`'s `main.rs`). A new `unsafe`
block in those libraries fails the build. Integration tests are separate
crates and are not covered. Store, net, consensus, primitives, node, query,
ibd, and sv2 stay open: they call FFI.

`unsafe_op_in_unsafe_fn` is workspace deny. An `unsafe fn` wraps each
unsafe operation in its own block. The four `loc_simd` helpers are a
site allow: the body is one target-feature intrinsic sequence, and the
contract is the function's `# Safety` section.

`undocumented_unsafe_blocks` is workspace deny. Each `unsafe` block and
`unsafe impl` has a `// SAFETY:` comment on the preceding line. A wrong
positive is a site `#[allow(clippy::undocumented_unsafe_blocks)]` with a
one-line reason. Do not allow it crate-wide.

Bare production `.unwrap()` / `.unwrap_err()` are frozen per file in
[`lint/unwrap-baseline.txt`](../lint/unwrap-baseline.txt).
`./scripts/unwrap-ratchet.sh` fails when a file grows, when a new file
gains one, and when a cleanup leaves the old count in place. Each call
counts as one. The count skips `#[cfg(test)]` items, `tests/`,
`rbitcoin-test`, and `rbitcoin-bench`. A `.lock()` / `.read()` /
`.write()` / `try_into()` receiver is skipped, including a turbofish
and a call broken onto the previous line. A later method on that value
still counts. `.expect(reason)` is not counted.

Production `0x` integer literals are frozen the same way in
[`lint/hex-baseline.txt`](../lint/hex-baseline.txt).
`./scripts/hex-ratchet.sh` fails when a file grows, when a new file
gains one, and when a cleanup leaves the old count in place. Each
literal counts as one, including `0x207f_ffff`. Comments, strings, and
char literals do not count. The skip list matches the unwrap ratchet.
A new opcode byte belongs in `script_opcode.rs`; that file's line moves
with the constant. Any other new literal is a baseline edit in the
same commit.

**Goal:** no `[workspace.lints.clippy]` `= "allow"`. A lint that is wrong
for one item is `#[allow(clippy::lint)]` on **that item**, with a one-line
reason (Core-faithful opcode loop, wire layout, dispatch bag,
`result_large_err` on a public error enum, …). Do not add a new workspace
or crate-wide allow. Do not peel **R-10**, flatten an io_uring machine, or
split `interpreter.rs` to silence a lint.

Complexity still drops because the types got better, not because clippy
denied a Core-faithful loop. That is a **site** allow on that function, not
a standing workspace `cognitive_complexity` allow.

Suite roots (`tests/suite.rs`) carry no `#![allow(...)]` either: the test
tree is linted like `src/`. Suite visibility and test-hook gating:
[`CONTRIBUTING.md`](../CONTRIBUTING.md) principle 11.

The workspace allow list is empty. `cognitive_complexity` is workspace
`warn` (nursery opt-in). A leftover Core-faithful loop or dense surface
test is a **site** allow — do not peel **R-10**, flatten io_uring, or
split `interpreter.rs` to silence it. Do not turn ast-grep into a second
clippy ([`quality.md`](./quality.md) Won't-fix).

---

## What this file is not

- Not a second quality backlog (that is [`quality.md`](./quality.md); **Q-61** is Completed).
- Not confirm stage IO (that is [`invariants.md`](./invariants.md)).
- Not a license to flatten uring, `idx_body_pipeline`, or the IBD confirm
  OS pipeline.
