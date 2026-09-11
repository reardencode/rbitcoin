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

---

## Extract under tests

Behavior-preserving moves still follow Red → Green → Refactor
([`how-we-plan.md`](./how-we-plan.md)):

- Existing tests that drive the shipped function are the pin.
- If an arm has no observable assert, add one **before** moving the code.
- Green is the extract only — no new branches.
- Refactor deletes the dual path, the unused flag, and restating comments
  in the touched function.

Do not invent a failing test for a pure move that is already pinned.

---

## Lint

CI is `cargo clippy --workspace --all-targets -- -D warnings`.

**Goal:** no `[workspace.lints.clippy]` `= "allow"`. A lint that is wrong
for one item is `#[allow(clippy::lint)]` on **that item**, with a one-line
reason (Core-faithful opcode loop, wire layout, dispatch bag,
`result_large_err` on a public error enum, …). Do not add a new workspace
or crate-wide allow. Do not peel **R-10**, flatten an io_uring machine, or
split `interpreter.rs` to silence a lint.

Complexity still drops because the types got better, not because clippy
denied a Core-faithful loop. That is a **site** allow on that function, not
a standing workspace `cognitive_complexity` allow.

Today’s workspace list is debt. Re-enable in batches (style first:
`collapsible_if`, `needless_return`, `redundant_*`, `manual_*`). Do not
turn ast-grep into a second clippy ([`quality.md`](./quality.md) Won't-fix).

---

## What this file is not

- Not a second quality backlog (that is [`quality.md`](./quality.md); **Q-61** is Completed).
- Not confirm stage IO (that is [`invariants.md`](./invariants.md)).
- Not a license to flatten uring, `idx_body_pipeline`, or the IBD confirm
  OS pipeline.
