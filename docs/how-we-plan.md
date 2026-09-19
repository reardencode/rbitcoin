# How we plan (agile / XP-style)

Work lands as **small vertical slices**. Each slice is one
**Red → Green → Refactor** turn, committed before the next slice starts.
This file owns that cycle. Hard-rule pointer: [`AGENTS.md`](../AGENTS.md).
Commands: [`.agents/skills/ship-pr/SKILL.md`](../.agents/skills/ship-pr/SKILL.md).

Plans have more steps than a typical “phase 1 / phase 2” design. Each step
should leave the production path simpler and the suite a sharper pin.

Influences: Extreme Programming (stories, planning game, small releases,
TDD, continuous refactoring), INVEST stories, vertical slicing, YAGNI /
simple design. Adapted for a consensus + IBD codebase and agent-driven
execution.

---

## Why plan this way

| Problem we had | Planning fix |
|----------------|--------------|
| Multi-day “implement the whole design” steps | One step = one testable contract |
| Coding to logs, thrashing heal/soft-path | Red test names the contract before code |
| One-off patches left after green | Explicit **Refactor** under a green suite |
| Slow suite from giant dual tests | Slice size + test budget per step |
| Horizontal “do all store then all net” | Vertical slice through the real entry |
| Plan-end CI churn (fmt, clippy, deny, cross-crate) | Each slice runs local CI except coverage, then commits |

Quality compounds: every step adds a pin; refactor keeps design coherent;
small slices reduce the risk of half-landed protocol changes.

---

## Units of work

### Stories (what “done” means)

A **story** is a short, customer/operator-meaningful change in system
behavior — not a layer of the architecture.

| Attribute (INVEST) | In this repo |
|--------------------|--------------|
| **I**ndependent | Can prioritize without a forced earlier horizontal layer (or the dependency is an earlier vertical slice already green) |
| **N**egotiable | Helper shape is for Red/Green/Refactor; the acceptance contract is fixed |
| **V**aluable | Operator, peer, RPC, IBD, or invariant improvement — not “add struct field” alone |
| **E**stimable | Agent/human can name the entry point and a test strategy in one sitting |
| **S**mall | Fits **one** (or a few tightly related) Red→Green→Refactor cycles |
| **T**estable | Observable fail/pass without a full mainnet open when possible |

Write stories as behavior, e.g.:

- “Mid-batch retarget bits succeed when period-start is only on header plan.”
- “Class A append refuses double-append of starts into published body.”
- “Confirm reject of store invariant permanent-blacklists; wire BadPrev soft-regets.”

Not: “Refactor confirm_run,” “Add cache,” “Clean up store.”

### Plan steps (how we execute)

A **plan step** is one focused pass: one turn of
[the cycle](#the-cycle-red--green--refactor).

| Step is the right size when… | Step is too big when… |
|------------------------------|------------------------|
| You can name the **exact** tests to write first | “Implement Phase 2 of design” with no acceptance pin |
| Green is hours-scale or less for one agent turn | Touches store + net + consensus + docs without intermediate green |
| Refactor target is clear (shared helper, right stage) | Mixes unrelated bugs “while we’re here” |
| Test cost is budgeted (unit vs slim scenario) | Implies a new multi-minute full-store suite by default |

**Vertical slice:** one step may touch several crates if that is what the
*behavior* needs. Prefer that over three horizontal steps (all store, then
all consensus, then all wiring) that cannot be verified until the end.

**Horizontal split is a smell:** “schema only,” “API only,” “callers later”
unless the story *is* an internal contract with its own tests (e.g.
`append_starts` guard) and a later step wires it.

### Spikes (when we do not know yet)

If the path is unclear (perf mystery, unclear ownership, “where does
tip-ahead stamp live?”):

1. Plan a **time-boxed spike**: read-only or throwaway probe, **no**
   production “maybe fix.”
2. Spike output: a written finding plus a named story/step with a testable
   contract.
3. Then the normal cycle.

Do not bury discovery inside a large implementation step.

---

## Anatomy of a good plan

```text
Goal (one paragraph: operator/system outcome)
Constraints (invariants, no live heal, IO split, musl, …)
Out of scope
Steps (ordered; each step is a vertical slice)
  Step N: <behavior title>
    Contract: <one sentence; error string / observable>
    Red / Green / Refactor: <tests, shipped path, what to fold>
    Verify: <targeted cargo test -p …>
Test budget: keep new tests fast; prefer unit when scenario cost >> value
Risks / follow-ups
```

### Step template

```markdown
### Step N — <short behavior title>

- **Contract:** …
- **Red:** `cargo test -p <crate> <filter>` — assert …
- **Green:** touch … (smallest path)
- **Refactor:** extract … / move to … / delete …
- **Verify:** `cargo test -p <crate> <filter>`
- **Done when:** the [cycle](#the-cycle-red--green--refactor) closed and the slice is committed
```

### Ordering steps

| Prefer | Avoid |
|--------|--------|
| Highest risk / most uncertain contract first (or spike first) | Saving “the hard part” for a megastep at the end |
| Dependencies as **prior green slices** | Blocking on unmerged horizontal layers |
| Failed acceptance / prod regressions as explicit early steps | “Also fix if we notice” |
| Thin happy path, then edge cases as separate steps | One step: “all edge cases and perf and docs” |

The operator / design owner orders by value. Developers (and agents) own
estimates and task shape.

---

## Planning game (lightweight)

When drafting or reviewing a plan:

1. **List candidate stories** as behavior sentences (not modules).
2. **Split** anything that cannot name Red tests in one breath.
3. **Order** by value and risk; insert spikes where estimability fails.
4. **Budget tests** per step (see below).
5. **Refuse** steps that only “lay pipe” with no observable green.
6. Re-plan when a step reveals the map was wrong — small steps make that cheap.

Release / multi-day work = ordered stories. One agent turn ≈ one step
(sometimes two tiny ones). Do not stuff a full design into a single turn.

---

## Test strategy inside the plan

| Prefer for Red | When |
|----------------|------|
| Extend an existing default [catalog](../TESTING.md#scenario-catalog) journey | Operator/peer-visible RPC, Electrum, Esplora, BIP324 P2P |
| Focused unit next to shipped fn | Pure helper, fast loop, expensive full path |
| Slim scenario / integration | Stage boundaries, IBD/confirm wiring, store publish order |
| One pin per contract | Not unit + twin integration for the same lines |

Core functional `run` scripts are a nightly oracle. They are **not** the Red
test for a default-CI story and **not** a reason to skip an in-tree journey.
When the labeled `core-functional` job is red, run the failing script locally
until it passes — do not use that CI job as the inner loop
([`core-functional.md`](./core-functional.md)).

| Plan-time rules | |
|-----------------|--|
| Each step declares Red tests **before** Green work | |
| New scenarios must justify cost (what unit cannot catch) | |
| No step that “adds coverage later” | |
| Prefer synthetic `/tmp` fixtures; no agent-VM mainnet open | |
| Hot-path Contract includes the cost model | [`CONTRIBUTING.md`](../CONTRIBUTING.md) principle 9 |
| After Refactor, same tests still pass; only drop **duplicate** tests | |
| Core-facing RPC / P2P / Electrum / Esplora | [`COMPAT.md`](../COMPAT.md) |

Suite speed and fixture size: [`TESTING.md`](../TESTING.md). Worktree, push,
and poll: [ship-pr](../.agents/skills/ship-pr/SKILL.md). A conflicted or
behind PR does not run test CI — rebase first. Do not call the plan done on
a red PR. A plan that multiplies multi-second full-store opens is a bad plan
even if the slices are “vertical.”

---

## The cycle: Red → Green → Refactor

One step is one turn of the loop, **committed before the next step starts**.
Red pins behavior, so Green is safe to be crude. The pin makes Refactor
safe. Refactor leaves the production path simpler and the suite sharper, so
the next Red is easier to name. Skip a phase and the loop degrades: no Red
is coding to logs; no Refactor is one-offs that accrete; no **test**
refactor is a slow suite full of brittle twins. Landing several slices and
then fighting CI is the same skip — the gates never ran under a small diff.

```text
for each plan step:
  1. Red      new test; targeted run; see red. No production edit yet.
  2. Green    smallest production change; targeted run; see green.
  3. Suite    cargo test --workspace; confirm green.
  4. Refactor fold one-offs; production and tests; still green.
  5. Gates    local CI except coverage (commands in ship-pr).
  6. Commit   then the next step.

after the last step (optional):
  holistic refactor → local CI except coverage → commit
  then push and poll GitHub
```

Edits inside Red and Green stay targeted: `cargo test -p <crate> …` and
`cargo check -p <crate> --lib`. Do not `cargo check --tests` after every
edit. The workspace suite is step 3 (and again in step 5 if Refactor
changed code).

**Agent RAM:** do not load full `cargo test`, clippy, deny, or rustc stdout
into the session. Redirect to a file under `/tmp`, then read only the exit
code, the failure names (`test … FAILED`, lint ids, first rustc error), and
at most ~80 lines of tail. `--quiet` is enough to confirm green. Workspace
suite logs in particular will OOM an agent turn.

Pure docs, comments, or formatting skip Red, Green, and the workspace suite.
Still run `cargo fmt --all` if rustfmt would touch the tree, and the other
gates if the slice also changed Rust, scripts, or lint.

If Refactor is empty, do not run the workspace suite twice: step 3 plus
fmt / deny / clippy / ast-grep / `ci-os-smoke.sh` is enough.

Coverage (`./scripts/coverage.sh`) and a host IBD are never local. Native
`windows` / `macos` still run on GitHub Actions; `./scripts/ci-os-smoke.sh`
is the local stand-in. `nixos-module-eval` only when the slice changed
`flake.nix`, `nix/`, or the NixOS module. The qemu VM test
(`nixos-module-runtime`) is GitHub Actions on label **`nixos-module-runtime`**
and on Release tags — not local, not a required PR check. Push may wait until
several slices are committed; each commit must already have passed those
gates.

A step is not done because it compiles, because the one-off is still there,
or because “CI at the end will catch it.”

### Red: name the contract

- One to a few failing tests. No production edit yet.
- The test drives the **shipped** entry point and asserts an observable
  (return value, store after reopen, peer / RPC / log line). It fails with
  the same class of error the bug would produce, not a compile error.
- Prefer extending a default [catalog](../TESTING.md#scenario-catalog)
  journey. A unit belongs next to a pure helper. One pin per contract.
- Watch it fail once. A test that never failed proves nothing.

### Green: smallest change that passes

- Surgical. Crude is allowed: a duplicated line, a hardcoded value, a
  one-off branch. Reach green fast so Refactor happens under a passing suite.
- Do not design ahead. YAGNI: if a later step needs the abstraction, that
  step’s Red will force it, under green tests from this one.
- Keep `--lib` compiling: wrap the old API, switch one caller
  ([Keep the tree compiling](#keep-the-tree-compiling)). Do not commit yet.

### Refactor: production **and** tests, under green

Refactor changes structure, not behavior: the same tests pass before and
after, minus duplicates you deleted. If you need a new assert to feel safe,
that is the next step’s Red, not a silent change now.

Target is XP simple design (Beck), in this order:

1. Passes all tests
2. Reveals intention (names, stage structs, named dispatch;
   [`code-shape.md`](./code-shape.md))
3. No duplication (one owner per concept; one production path)
4. Fewest elements (drop the flag, parameter, or branch the tests now prove
   unnecessary)

Production moves: fold the one-off into the real shape; delete the dual
path; move the helper to the crate that owns the concept; drop a `pub`
nobody imports.

Test moves ([`TESTING.md`](../TESTING.md) owns the budget):

- Lift guts asserts up to the journey once the journey hits the same shipped
  path, then delete the twin unit.
- Delete tests that pin implementation shape rather than behavior.
- Replace a `*_for_test` hook or hot-path probe with an instance stat or an
  on-disk assert, then delete the hook.
- Fold duplicate fixtures into the shared `testutil`; shrink N to the
  smallest that still hits the branch.
- Sharpen asserts (exact error string, state after reopen) so the pin is
  stronger with fewer tests.

| After Green | Refactor move |
|-------------|---------------|
| A unit drove a private helper; the journey now covers that path | Move the assert to the journey, delete the unit, inline or `pub(crate)` the helper |
| Green added a second branch beside the old one | Collapse to one path and delete the old; the same test still passes |
| Green needed a test-only hook on production | Assert the session/table stat or file state instead; delete the hook |
| A new scenario re-mines a pad the journey already has | Reuse that journey’s pad; one open per binary |
| Refactor exposed a missing pin | Name it as the next step’s Red |

After the last slice, a **holistic** refactor is optional: cross-slice
cleanup that would have been YAGNI mid-plan. Same gates, then its own
commit. Then push and poll GitHub. Coverage is the remaining required job
that is not run locally.

---

## Examples (this codebase)

### Good step

**Contract:** `expected_bits_extending` at retarget height succeeds when
period-start is only on ConfirmParentCache (not confirmed).

- **Red:** unit in `confirm_run` driving `expected_bits_extending` with
  plan-only first@2016.
- **Green:** confirmed-or-plan timestamp in that fn.
- **Refactor:** shared header-at-height-for-pow helper if a second caller
  needs it (optional same step if small).
- **Verify:** `cargo test -p rbitcoin-consensus expected_bits_extending`.

### Bad step

“Fix IBD tip stall around retargets: heal, soft-requeue, walk seed, rebuild
head, and document.” — many contracts, thrash-prone, no single Red.

### Split of a large feature

Feature: “lookup stamps body_range for load denserels.”

| Step | Contract |
|------|----------|
| 1 | Plan/archive stamp fills `external_parents` body for creates-only in_flight parent |
| 2 | Load pin hard-fails if range missing (no cold idx denserels) |
| 3 | plan=None path stamps parent pin from archived Class A |
| 4 | Soft-requeue policy: store invariants permanent (tests only on reject map) |

Each step is independently green, gated, committed, and shippable.

---

## Anti-patterns

| Anti-pattern | Instead |
|--------------|---------|
| Waterfall plan: design all → code all → test all | Story steps each with Red first |
| Horizontal layers as steps | Vertical behavior slices |
| “Mega-PR” step list | More steps, smaller greens |
| Spike disguised as implement | Named spike + follow-on story |
| Green without refactor forever | Refactor phase required in the step template |
| Refactor touches production only | Fold twin tests into the journey, delete hooks, share fixtures in the same phase |
| Plan ignores test runtime | Explicit unit vs scenario choice per step |
| Core functional as the default-CI Red | In-tree catalog journey; Core stays nightly |
| Several slices uncommitted; first GitHub run is the fmt/clippy/suite gate | Each slice commits only after those gates |
| Delete a large type/module then `cargo check --tests` until the workspace builds | Keep-compiling facade (below) |
| Inner loop = `cargo check --tests` after every edit | `--lib` until that crate’s lib is green |

### Keep the tree compiling

Schema/API rewires stall when a session deletes the old type (`TxIdx`, a
body meta field, …) and then spends the rest of the turn on `unresolved` /
`dead_code` across store tests, query, consensus, and net. That is not TDD;
it is a compile-doom loop. `rbitcoin-store --tests` is a fat rustc unit —
do not use it as the edit cycle.

| Do | Do not |
|----|--------|
| New type + its unit tests green, **then** a thin wrap on the old API | Delete the old module in the same dirty tree as all callers |
| Switch **one** caller crate per step; `--lib` stays green | One uncommitted tree spanning store + confirm + query + net + docs |
| Keep `--lib` compiling throughout; commit after local CI except coverage | Hours of un-gated WIP, or a slice commit that has not passed those gates |
| `cargo check -p <crate> --lib` (or `cargo test -p <crate> --lib <filter>`) | `cargo check -p rbitcoin-store --tests` or six-crate `--tests` after each edit |

`--tests` / multi-crate check belongs after Green and in Gates, not in the
inner loop. Commands:
[`.agents/skills/ship-pr/SKILL.md`](../.agents/skills/ship-pr/SKILL.md).

---

## Checklist for authors (and agents)

Before accepting a plan:

- [ ] Goal is one operator/system outcome
- [ ] Every step has **Contract + Red + Green + Refactor + Verify**
- [ ] No step larger than one Red→Green→Refactor without a spike
- [ ] Vertical slices; horizontal deps called out as prior steps
- [ ] Test budget: suite stays fast; no unjustified full-store twins; Red is in-tree (catalog journey or unit), not Core functional
- [ ] No production-scale default fixtures when tiny N still hits the branch (see TESTING.md)
- [ ] Constraints cite project invariants (concurrency, IO split, no live heal, …)
- [ ] Out of scope is explicit

Before closing a step: the [cycle](#the-cycle-red--green--refactor) ran
(Red seen failing, Green, workspace suite, Refactor of production **and**
tests, local CI except coverage) and the slice is committed. No known red
left for “later in the plan.”

Before closing a **plan**:

- [ ] Optional holistic refactor gated and committed
- [ ] Work landed on a session-worktree topic branch (not local `master`)
- [ ] One PR contains the plan’s commits
- [ ] Required GitHub Actions checks on that PR are green (including coverage)
- [ ] After merge: topic branch deleted locally and on `origin`; session worktree kept until the session ends

---

## References (ideas, not process religion)

- Extreme Programming: planning game, stories, small releases, TDD, refactoring
- Bill Wake — **INVEST** user stories
- Vertical story slicing (value through the stack, not layer-by-layer)
- Project: [AGENTS.md](../AGENTS.md) (change discipline) and
  [`.agents/skills/ship-pr/SKILL.md`](../.agents/skills/ship-pr/SKILL.md)
  (worktree + PR)
