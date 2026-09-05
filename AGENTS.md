# Agent notes

Documentation map (one owner per fact): [`docs/README.md`](docs/README.md).
This file is the harness-injected **hard-rule** contract. Design lives in
the owner docs; do not grow a second design book here.

## Plain technical language

Write **clear, concrete technical English** in code, comments, docs, commits,
and PR text. Do **not** inject moralizing, political framing, or performative
“sensitivity” language.

- **OK:** precise domain terms, plain failures (“reject”, “invalid”,
  “permanent blacklist”), Core-aligned vocabulary where we match Bitcoin Core.
- **Also OK when clearer:** `allowlist` / `denylist` for permitted or blocked
  names — for clarity, not as a ritual rename.
- **Not OK:** fashion rewrites, equity disclaimers, or softening
  consensus/security language.

If unsure whether a wording change is engineering clarity or cultural noise,
keep the existing technical term (especially if it matches Core or our logs).

## Comments are a smell

Do not restate *what* / *why* / *weird*. Prefer names, types, and structure.
Keep `//` only for an invariant, protocol rule, `SAFETY`, or library quirk.
Crate/public rustdoc (`//!` / `///`) that documents a surface is not this rule.

Full text and review checklist: [`CONTRIBUTING.md`](CONTRIBUTING.md) principle 7.

## Composition and immutability

Prefer composition (has-a) over inheritance (is-a); avoid tall trees. Prefer
immutable structures built once, then composed. If a hashmap needs extra
fields, wrap it on read rather than mutating members in place.

## Store

**No locks on the store hot path.** Roles, publish order, grow, pins:
[`docs/concurrency.md`](docs/concurrency.md). Heads: [`docs/heads.md`](docs/heads.md).
Class B insert geometry: [`SCHEMA.md`](SCHEMA.md) (Class B). Stage IO (the
only Allowed/Forbidden table): [`docs/invariants.md`](docs/invariants.md).

Do **not** reintroduce CreateResidency, OutFifo, ContigPark, archive sticky,
process pin FIFO, or map epochs.

On-disk format change: [`SCHEMA.md`](SCHEMA.md) (soft migrate / `SCHEMA_VERSION`
bump / explicit refuse). Same commit as the format code. Do not surprise an
operator with a silent wipe.

io_uring machines: [`docs/io-modality.md`](docs/io-modality.md). Do **not**
flatten a purpose-built machine to batched `pread`/`pwrite` without asking.

Pin material is plan/batch only. IBD intake is body queue → lookup → load.
In-flight prune and leftover identity: [`docs/invariants.md`](docs/invariants.md).

Anything on lookup / load / scripts / write (or a sidecar the write thread
joins) gets a **named** `ibd: perf` timer **in the same commit**. Inventory:
`crates/rbitcoin-net/src/ibd/perf_log.rs`.

Process RAM vs page cache, body-queue soft assign, production evict APIs:
[`docs/ibd-memory.md`](docs/ibd-memory.md).

## Ship via worktree + pull request

```text
worktree branch → many small commits → one PR → poll GitHub Actions → green PR
```

A plan is **not complete** until that PR’s **required** checks are green.

```bash
git fetch origin
git worktree add -b <area>/<short-name> /tmp/rbtc-<short> origin/master
export CARGO_TARGET_DIR=/tmp/rbtc-<short>/target/dev
```

| Rule | Detail |
|------|--------|
| Base | Current `origin/master` (or `main`) |
| Branch | Topic name — **never** commit the plan onto `master` |
| `CARGO_TARGET_DIR` | Inside the worktree (`…/target/dev`) |
| Identity | Worktree-only `git config --worktree user.name` / `user.email` for bot commits |
| Remotes | Worktrees **share** `origin`. Fetch/pull is HTTPS; `pushurl` is SSH. Never `git remote set-url origin` (collapses the split). |

### After merge cleanup

Once the PR is **merged** (not while open):

```bash
git worktree remove /tmp/rbtc-<short>
git branch -d <area>/<short-name>
git push https://github.com/reardencode/rbitcoin.git --delete <area>/<short-name>
git fetch origin --prune
```

Keep `master` / `main`, the primary checkout, and any **open-PR** worktree.
Do **not** delete a branch that still has an open PR. Do **not**
`git push --delete master`.

### Local tests (thin on purpose)

From `nix-shell` (CI pins **rustc 1.95.0**). Shell `CARGO_TARGET_DIR=target/dev`.
Suite, budgets, coverage: [`TESTING.md`](TESTING.md).

| When | Run |
|------|-----|
| **Each plan step / single-shot** | Targeted `cargo test -p <crate> …` (or slim scenario). `cargo fmt --all` if dirty. |
| **Not by default** | `cargo test --workspace`, `./scripts/coverage.sh`, workspace clippy, `nix build .#rbitcoin-musl` |
| **Exception** | User asked for a local full suite, or you cannot push and must prove gates offline |

Do **not** wait out a host IBD or a 90% coverage run in the agent VM. GitHub
Actions is the workspace/coverage/clippy gate.

### Push, PR, poll CI

Required jobs: **`fmt`**, **`deny`**, **`clippy`**, **`ast-grep`**, **`test`**,
**`windows`**, **`macos`**, **`multinode`**, **`coverage`**. Structural scan is
`./scripts/ast-grep.sh` (rules live in `lint/ast-grep/`; do not copy them here).
`windows` / `macos` are native
store + `--smoke` (not operator zips). Operator binaries are GitHub Releases
(`release.yml`). Label **`core-functional`** when the PR touches the Core
functional harness.

`origin` fetch/pull is HTTPS; `pushurl` is SSH (operator). This VM has **no**
GitHub App SSH key. The App token from `~/.config/rbitcoin-grok/gh-login.sh`
(~1h) is HTTPS-only.

`gh pr create` / `gh pr checks` talk to the API. `git fetch origin` works
here. Bot **push** must use an **explicit HTTPS URL**. Do **not**
`git remote set-url origin`. Do **not** `git push origin` as the bot.

The App token **cannot** create or update `.github/workflows/*` (GitHub
`workflows` permission). If the commit set touches workflow YAML, **stop
and ask the operator to push** that branch. Do not strip the workflow
diff to sneak a push. Non-workflow commits on an already-pushed branch
are fine.

```bash
~/.config/rbitcoin-grok/gh-login.sh
git fetch origin
git push https://github.com/reardencode/rbitcoin.git HEAD:<area>/<short-name>
gh pr create --repo reardencode/rbitcoin --head <area>/<short-name> --title "…" --body "…"
gh pr checks --watch
```

No `-u` on push (that would retarget the branch remote away from `origin`).

| Rule | Detail |
|------|--------|
| **One PR per plan** | Push more commits to the same branch. |
| **Poll until green** | Do not walk away and call the plan done. |
| **Done** | Required checks green **and** the PR is up for review. Do not merge unless asked. |
| **No post-green PR-cite** | After required checks are green, do **not** push a docs-only follow-up whose only change is inserting this PR's number into CHANGELOG / quality.md / similar. That wastes a full CI run. Cite in the **PR body**. Owner docs can omit the GitHub number, or pick it up later in a docs change that was already needed. |
| **Do not** | Force-push `master`, merge a red PR, collapse `origin` to a single URL, skip polling because “tests passed locally,” or invent **empty commits** to poke Actions. |
| **Workflow YAML** | App cannot push `.github/workflows/*`. Ask the operator to `git push`. |
| **CodeQL in tests** | Alert that only fires in `#[cfg(test)]` / test modules: **stop**. Do **not** rename tests or shuffle literals to silence it. Ask the operator to **dismiss** the alert (App token cannot). Production / library CodeQL is a real finding — fix it. |

#### Retrigger CI (no empty commits)

When required checks are green locally and CI only needs a re-run (flake,
stale run, App cannot `gh run rerun`):

| OK | Not OK |
|----|--------|
| GitHub Actions UI **Re-run failed jobs** / **Re-run all jobs** | Empty commit whose only purpose is to wake Actions |
| `gh run rerun <id> [--failed]` when the token allows it | Noise commits (“ci: bump”, “trigger”) with no product/test change; docs-only follow-up whose only change is this PR's `#N` after checks are already green |
| Amend the tip commit (or rebase) and **force-push the topic branch** with `--force-with-lease` over HTTPS | Force-push `master` / `main` |

```bash
# Prefer API when the App/token can write Actions:
gh run rerun <run-id> --failed

# Else: amend tip (no empty commit) and lease-force the topic branch only:
git commit --amend --no-edit   # or fold a real fix into the tip
git push --force-with-lease https://github.com/reardencode/rbitcoin.git HEAD:<area>/<short-name>
```

Coverage (≥90% LCOV `LH`/`LF`) is a required CI job — see
[`TESTING.md`](TESTING.md). If CI `coverage` fails, add a pin and push.

Plans: [`docs/how-we-plan.md`](docs/how-we-plan.md). Each step names
**Contract, Red, Green, Refactor, Verify**. Many small vertical slices.

## Commit hygiene

This tree is **public**.

| Rule | Detail |
|------|--------|
| **One logical change** | One concern per commit. |
| **Small** | Sequence of small commits; checkpoint before risky follow-ons. |
| **Clear message** | Subject + body: **what** and **why**. No chat context assumed. |
| **Not** | “WIP”, “misc”, drive-by renames mixed with behavior. |

Green-then-refactor is fine as **two** commits when each stands alone.

1. Pass targeted tests for what you touched.
2. Commit. A plan is **many commits, one PR**.
3. Push the worktree branch and open or update the plan PR. Poll to green.
4. **Musl install only after merge onto `master`/`main`**, tree clean, and the
   node/cli binary changed. Commands: [`docs/reproducible-builds.md`](docs/reproducible-builds.md)
   / [`OPERATOR.md`](OPERATOR.md). Do **not** `nix build .#rbitcoin-musl` on a
   feature branch or with uncommitted edits. Do **not** run
   `./scripts/repro-check.sh` as the day-to-day install (release / digest gate
   only). Do **not** ship `nix-shell` / host `cargo build --release` as the
   operator binary (Nix/host glibc; dies off-store).

## Test-driven development

**No production code change without a test that fails first.** Pure
docs/comments/formatting need no tests. Do **not** open a mainnet datadir in
the agent VM. Perf A/B is operator-host only.

| Phase | Goal | Rules |
|-------|------|--------|
| **Red** | Encode the contract | Failing test only. No production edit yet. |
| **Green** | Make it pass | **Smallest surgical** change. One-offs OK *temporarily*. |
| **Refactor** | Remove the one-off | Still green: fold into the real shape; delete dual paths. |

Planning anatomy, INVEST, step template: [`docs/how-we-plan.md`](docs/how-we-plan.md).
Fixture size, one-entry-per-path, coverage bar: [`TESTING.md`](TESTING.md).

The test must assert the **exact** contract, drive the **shipped** function,
fail with the **same class of error**, and use tiny `/tmp` fixtures.

## Lean-code rules

One production implementation at the **lowest crate** that owns the concept.
Missing promised fact → `StoreError::Corrupt("invariant: …")` — no silent
fallback. Spentness / same-block / pin identity:
[`docs/invariants.md`](docs/invariants.md). Tests assert shipped behavior, not
repo text ([`CONTRIBUTING.md`](CONTRIBUTING.md) principle 8);
[`TESTING.md`](TESTING.md) owns budgets, no `*_for_test` backdoors, and no
production-scale default fixtures. Do not waste RAM or CPU; a spend of one
to save the other is a named trade ([`CONTRIBUTING.md`](CONTRIBUTING.md)
principle 9).

Do not leave dead code. Do not silence dead-code / `#[cfg(test)]` warnings
without a bulletproof justification — delete the code.
