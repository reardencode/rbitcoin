# How we plan (agile / XP-style)

This project plans and executes work as a sequence of **small vertical slices**,
each sized for one **Red → Green → Refactor** cycle (see [AGENTS.md](../AGENTS.md)
TDD section). Plans have **more steps** than a typical “phase 1 / phase 2”
design doc; each step should leave the tree greener and the suite a little
stronger.

Influences: Extreme Programming (stories, planning game, small releases,
TDD, continuous refactoring), INVEST stories, vertical slicing, YAGNI / simple
design. Adapted for a consensus + IBD codebase and agent-driven execution.

---

## Why plan this way

| Problem we had | Planning fix |
|----------------|--------------|
| Multi-day “implement the whole design” steps | One step = one testable contract |
| Coding to logs, thrashing heal/soft-path | Red test names the contract before code |
| One-off patches left after green | Explicit **Refactor** phase under green suite |
| Slow suite from giant dual tests | Slice size + test budget per step |
| Horizontal “do all store then all net” | Vertical slice through the real entry |

Quality compounds: every step adds a pin; refactor keeps design coherent;
small slices reduce risk of half-landed protocol changes.

---

## Units of work

### Stories (what “done” means)

A **story** is a short, customer/operator-meaningful change in system behavior
— not a layer of the architecture.

| Attribute (INVEST) | In this repo |
|--------------------|--------------|
| **I**ndependent | Can prioritize without a forced earlier horizontal layer (or the dependency is an earlier vertical slice already green) |
| **N**egotiable | Details of helper shape are for Red/Green/Refactor; the acceptance contract is fixed |
| **V**aluable | Operator, peer, RPC, IBD, or invariant improvement — not “add struct field” alone |
| **E**stimable | Agent/human can name the entry point and a test strategy in one sitting |
| **S**mall | Fits **one** (or few tightly related) Red→Green→Refactor cycles |
| **T**estable | Observable fail/pass without full mainnet open when possible |

Write stories as behavior, e.g.:

- “Mid-batch retarget bits succeed when period-start is only on header plan.”
- “Class A append refuses double-append of starts into published body.”
- “Confirm reject of store invariant permanent-blacklists; wire BadPrev soft-regets.”

Not: “Refactor confirm_run,” “Add cache,” “Clean up store.”

### Tasks / plan steps (how we execute)

A **plan step** is the unit an agent (or human) executes in one focused pass:

```text
Red (1–few failing tests) → Green (surgical code) → Refactor (integrate, still green)
```

| Step is the right size when… | Step is too big when… |
|------------------------------|------------------------|
| You can name the **exact** tests to write first | “Implement Phase 2 of design” with no acceptance pin |
| Green is hours-scale or less for one agent turn | Touches store + net + consensus + docs without intermediate green |
| Refactor target is clear (shared helper, right stage) | Mixes unrelated bugs “while we’re here” |
| Test cost is budgeted (unit vs slim scenario) | Implies new multi-minute full-store suite by default |

**Vertical slice:** one step may touch multiple crates (query + consensus +
net) if that is what the *behavior* needs. Prefer that over three horizontal
steps (all store, then all consensus, then all wiring) that cannot be verified
until the end.

**Horizontal split is a smell:** “schema only,” “API only,” “callers later”
unless the story *is* an internal contract with its own tests (e.g. `append_starts`
guard) and a later step wires it.

### Spikes (when we do not know yet)

If the path is unclear (perf mystery, unclear ownership, “where does tip-ahead
stamp live?”):

1. Plan a **time-boxed spike** step: read-only or throwaway probe, **no**
   production “maybe fix.”
2. Spike output: written finding + named story/step with a testable contract.
3. Then normal Red→Green→Refactor.

Do not bury discovery inside a large implementation step.

---

## Anatomy of a good plan

### Shape

```text
Goal (one paragraph: operator/system outcome)
Constraints (invariants, no live heal, IO split, musl, …)
Out of scope
Steps (ordered; each step is a vertical slice)
  Step N: <behavior title>
    Contract: <one sentence; error string / observable>
    Red: <tests to add/extend; crate; unit vs scenario>
    Green: <shipped entry points / modules expected>
    Refactor: <how to fold; what one-offs to delete>
    Verify: <cargo test -p … filters>
    Done when: <checklist>
Test budget: keep new tests fast; prefer unit when scenario cost >> value
Risks / follow-ups
```

### Step template (copy into plan docs / PR plans)

```markdown
### Step N — <short behavior title>

- **Contract:** …
- **Red:** `cargo test -p <crate> <filter>` — assert …
- **Green:** touch … (smallest path)
- **Refactor:** extract … / move to … / delete …
- **Verify:** …
- **Done when:** [ ] red seen  [ ] green  [ ] refactor green  [ ] related tests pass
```

### Ordering steps

| Prefer | Avoid |
|--------|--------|
| Highest risk / most uncertain contract first (or spike first) | Saving “the hard part” for a megastep at the end |
| Dependencies as **prior green slices** | Blocking on unmerged horizontal layers |
| Failed acceptance / prod regressions as explicit early steps | “Also fix if we notice” |
| Thin happy path then edge cases as separate steps | One step: “all edge cases and perf and docs” |

XP-style: customer (here: operator / design owner) orders by value; developers
own estimates and task shape. For agents: **user orders value; plan steps own
size and test strategy.**

---

## Planning game (lightweight)

When drafting or reviewing a plan (human or agent):

1. **List candidate stories** as behavior sentences (not modules).
2. **Split** anything that cannot name Red tests in one breath.
3. **Order** by value and risk; insert spikes where estimability fails.
4. **Budget tests** per step (see below).
5. **Refuse** steps that only “lay pipe” with no observable green.
6. Re-plan when a step reveals the map was wrong — small steps make that cheap.

Release / multi-day work = ordered stories. One agent turn ≈ one step (sometimes
two tiny ones). Do not stuff a full design into a single turn.

---

## Test strategy inside the plan

Aligned with AGENTS.md TDD + suite speed:

| Prefer for Red | When |
|----------------|------|
| Focused unit next to shipped fn | Pure helper, fast loop, expensive full path |
| Slim scenario / integration | Stage boundaries, IBD/confirm wiring, store publish order |
| One pin per contract | Not unit + twin integration for the same lines |

| Plan-time rules | |
|-----------------|--|
| Each step declares Red tests **before** Green work | |
| New scenarios must justify cost (what unit cannot catch) | |
| No step that “adds coverage later” | |
| Prefer synthetic `/tmp` fixtures; no agent-VM mainnet open | |
| Hot-path Contract includes the cost model | [`CONTRIBUTING.md`](../CONTRIBUTING.md) principle 9 |
| After Refactor, same tests still pass; only drop **duplicate** tests | |

### Mid-plan gates vs plan-end gates

Worktree, local tests, push URL, poll CI, musl-after-merge, after-merge
cleanup: [`AGENTS.md`](../AGENTS.md). Suite speed and fixture size:
[`TESTING.md`](../TESTING.md).

Do not call the plan done on a red PR. A plan that multiplies multi-second
full-store opens is a bad plan even if slices are “vertical.”

---

## Simple design under continuous refactor

After Green, Refactor toward XP simple design (Beck):

1. Passes all tests  
2. Reveals intention (names, stages, roles)  
3. No duplication (one owner for the concept)  
4. Fewest elements  

YAGNI: do not add abstraction for a story two steps ahead. If the next step
needs it, that step’s Red will force it — under green tests from prior steps.

---

## Examples (this codebase)

### Good step

**Contract:** `expected_bits_extending` at retarget height succeeds when
period-start is only on ConfirmParentCache (not confirmed).

- **Red:** unit in `confirm_run` driving `expected_bits_extending` with plan-only first@2016.  
- **Green:** confirmed-or-plan timestamp in that fn.  
- **Refactor:** shared header-at-height-for-pow helper if a second caller needs it (optional same step if small).  
- **Verify:** `cargo test -p rbitcoin-consensus expected_bits_extending`.

### Bad step

“Fix IBD tip stall around retargets: heal, soft-requeue, walk seed, rebuild head,
and document.” — many contracts, thrash-prone, no single Red.

### Split of a large feature

Feature: “lookup stamps body_range for load denserels.”

| Step | Contract |
|------|----------|
| 1 | Plan/archive stamp fills `external_parents` body for creates-only in_flight parent |
| 2 | Load pin hard-fails if range missing (no cold idx denserels) |
| 3 | plan=None path stamps parent pin from archived Class A |
| 4 | Soft-requeue policy: store invariants permanent (tests only on reject map) |

Each step is independently green and shippable.

---

## Anti-patterns

| Anti-pattern | Instead |
|--------------|---------|
| Waterfall plan: design all → code all → test all | Story steps each with Red first |
| Horizontal layers as steps | Vertical behavior slices |
| “Mega-PR” step list | More steps, smaller greens |
| Spike disguised as implement | Named spike + follow-on story |
| Green without refactor forever | Refactor phase required in the step template |
| Plan ignores test runtime | Explicit unit vs scenario choice per step |
| Step done = “code compiles” | Step done = Red→Green→Refactor verify checklist |

---

## Checklist for authors (and agents)

Before accepting a plan:

- [ ] Goal is one operator/system outcome  
- [ ] Every step has **Contract + Red + Green + Refactor + Verify**  
- [ ] No step larger than one Red→Green→Refactor without a spike  
- [ ] Vertical slices; horizontal deps called out as prior steps  
- [ ] Test budget: suite stays fast; no unjustified full-store twins  
- [ ] No production-scale default fixtures when tiny N still hits the branch (see TESTING.md)  

- [ ] Constraints cite project invariants (concurrency, IO split, no live heal, …)  
- [ ] Out of scope is explicit  

Before closing a step:

- [ ] Red was observed failing once  
- [ ] Green makes that test pass  
- [ ] Refactor left all related tests green  
- [ ] No known red left for “later in the plan”  

Before closing a **plan**:

- [ ] Work landed on a worktree topic branch (not local `master`)  
- [ ] One PR contains the plan’s commits  
- [ ] Required GitHub Actions checks on that PR are green  
- [ ] After merge: worktree removed; local and remote topic branches deleted 


---

## References (ideas, not process religion)

- Extreme Programming: planning game, stories, small releases, TDD, refactoring  
- Bill Wake — **INVEST** user stories  
- Vertical story slicing (value through the stack, not layer-by-layer)  
- Project: [AGENTS.md](../AGENTS.md) (TDD, worktree + PR, musl after merge)
