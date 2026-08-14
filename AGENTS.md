# Agent notes

## Plain technical language

This is an engineering project. Write **clear, concrete technical English** in
code, comments, docs, commits, and PR text. Do **not** inject moralizing,
political framing, or performative “sensitivity” language. Prefer words that
describe the mechanism or policy accurately.

- **OK:** precise domain terms, plain failures (“reject”, “invalid”, “permanent
  blacklist” for a hash we never re-request, Core-aligned vocabulary where we
  are matching Bitcoin Core).
- **Also OK when clearer:** `allowlist` / `denylist` for sets of permitted or
  blocked names — they read better than color metaphors. Use them for clarity,
  not as a ritual rename of everything.
- **Not OK:** rewriting technical prose to satisfy fashion, adding equity
  disclaimers, or soft-pedaling consensus/security language so it sounds
  “inclusive.” Correctness and operator honesty first.

If you are unsure whether a wording change is engineering clarity or cultural
noise, keep the existing technical term (especially if it matches Core or our
logs) and move on.

## Prefer composition over inheritance in data models

Composition (has-a) is typically more clear and less error prone than
inheritance (is-a), although rust traits can make that blurry. Avoid tall
inheritance trees.

## Prefer immutable data structures

Immutable data structures built once then composed with other immutable
structures typically perform better than data structures mutated over time.

For example, prefer an immutable map that is built from the streamed results
of some work over a mutable hashmap. Even if the data structure itself is
mutable, in rust not having to make it mutable makes life better.

If we needed to add additional data to the members of a hashmap, we could
create an outer map that contains the additional info and annotates the
members of the inner map on read, converting them to the data type with the
additional fields (which will also have the inner object).

In short, prefer composition over mutation as well as composition over
inheritance.

## Scripthash (Class B) insert rules

| Rule | Detail |
|------|--------|
| Creates only | Index is thin `create_tx_fk` per Electrum scripthash (outputs); spends join Class A + annotations |
| Sorted FKs | Durable create_tx_fks per key are **strictly increasing** (within pages and across pages) |
| Insert | Max FK from **last page only** (or inline); **skip `fk ≤ max`** (re-queue OK); append higher only — **no full chain walk** on insert |
| Batch order | Callers must apply SH create batches in **non-decreasing block/batch time order** so skip-lower never leaves holes |
| Cold megakey | Pack each 4 KiB page in RAM with `next` predicted; **one write per page** (no previous-page RMW) |

See `SCHEMA.md` Class B and `scripthash_pages.rs`.

## Store concurrency: lock-free by default

**Default: no locks on the store hot path.** Concurrency is **roles + publish
order + HWM**, not map mutexes (maps removed — phase 6).

| Rule | Detail |
|------|--------|
| Roles | At most **one Class A appender** and **one spend annotator** per process; **N readers** of published ranges always free |
| Publish | body → idx → count/HWM (Release); then head / `header_txs` as visibility requires |
| Capacity grow | fallocate/`set_len` only (no map epochs); readers use published HWM |
| Layout grow (`tx.head`) | **segment roll**: seal open head (fuse8) + create new fixed 25-bit head — no mono-file bits-widen |
| Class C tip | L2 write-behind; `flush_class_c_tip` **before** body-queue dequeue |
| Not OK | Long-held store locks on IBD/read path, “pause all queries during confirm”, multi appenders |

If a change introduces a new long-held store lock on the IBD/read path, it is the
wrong design — fix the protocol. Roles: [`docs/concurrency.md`](docs/concurrency.md).
Which head file: [`docs/heads.md`](docs/heads.md).

## On-disk format changes: warn, schema, or migrate

Changing any durable store bytes (table layout, side files like fuse8,
envelope version, encode of sealed products) must not surprise an operator with
a silent wipe / full head rebuild. Pick at least one:

| Option | When |
|--------|------|
| **Soft migrate** | Payload-only change (e.g. fuse8 v1→v2): open legacy, log a clear `warn!`, always-probe or dual-read, rewrite on open or next seal — **do not** treat decode failure as “recreate whole table” |
| **`SCHEMA_VERSION` bump** | Class A / OA / body layout change, or anything that cannot soft-open prior files |
| **Explicit refuse** | Incompatible durable state: hard error with a one-line wipe/reindex message (which files), not a cryptic `Corrupt` that cascades into head recreate |

Also document the change in `SCHEMA.md` / `SCHEMA_HISTORY.md` in the same
commit as the format code. Side-format version fields (e.g. BF8R version) are
not a substitute for operator-visible logs when migration runs. See fuse8 v1→v2
notes in `SCHEMA_HISTORY.md` (side format under schema 14).

## io_uring: do not flatten custom machines

**Under no circumstances** replace a purpose-built / multi-stage **io_uring
machine** (fused resolve, spend-annotate RMW, pipeline stages, depth-round
machines, etc.) with “simple” batched `pread`/`pwrite` / one-shot
`pread_batch`/`pwrite_batch` submission **without explicit permission from the
user**.

| OK | Not OK without permission |
|----|---------------------------|
| Fix bugs inside the existing machine | Delete/retire a custom machine and call bulk batch helpers instead |
| Thread new flags (e.g. DONTCACHE) through the same SQE path | “Simplify” to serial pread + one big submit for a path that had a staged machine |
| Fall back to pread when uring is unavailable (existing policy) | Rewrite a machine away “because batch is enough” |

If a change seems to require collapsing a machine, **stop and ask** — do not
land the simplification as a drive-by cleanup.

## Create pins: pipeline-local only (no process FIFO)

| Rule | Detail |
|------|--------|
| Pin material | **Plan / batch only** — `batch_pin`, `BatchParents`, plan-local **sparse** `external_parent_outs` (`SparseExternalPin`). SharedParentPin = immutable body compose. No process create pin FIFO |
| IBD confirm intake | **body queue wire only** → lookup → load (no hash-only / Class-A-only confirm) |
| Ancient parents | Cold Class A **`txout` outs** into plan-local / BatchParents only |
| Header plans | **ConfirmParentCache** always on (MTP / tip-ahead headers) |
| Removed | **CreateResidency**, **OutFifo**, **archive sticky**, half-row / out-slim, **`RBITCOIN_CONFIRM_CACHE`**, **`RBITCOIN_RESIDENCY_BYTES`** |
| IBD sizes | **`conf_plans=`** + body-queue / pipeline meters (no `residency creates=`) |


## Confirm pipeline timers (required visibility)

Anything that runs on the confirm pipeline — **lookup, load, scripts, write**,
or a sidecar the write thread **joins** — must have a **named** timer on
`ibd: perf` / `ibd: perf_dbg` **in the same commit** as the work. Write-thread
`Instant` regions also go on [`LastWritePhases`](crates/rbitcoin-consensus/src/lib.rs)
and the `confirm write slow` line. See [`crates/rbitcoin-net/src/ibd/perf_log.rs`](crates/rbitcoin-net/src/ibd/perf_log.rs)
(`write_stage_ms`, `format_info`, `format_debug`).

**Why:** signet IBD 17:47–18:16 (tip 0→263k, `--sptweaks`, no `tweaks=` yet)
was write-bound from ~180k. `confirm write slow` named phases
(`class_a+ensure+struct+class_c+spend_ann+tip_gc`) covered only **~35–44%**
of wall (median hole **~3.2 s**, up to **6.9 s**, **~56–66%** of a 5–10 s
batch). That work was `index_sp_tweaks_batch` on the only thread that can
advance tip. After `tweaks=`, the 18:43 run’s window **`write=` equals**
`class_a+ensure+struct+class_c+sh+spend+tweaks+tip_gc` (delta 0); **tweaks
were 60–80%** of write in the first fat windows. A silent path is how we
lose the bottleneck.

| Rule | Detail |
|------|--------|
| New confirm-path work | Same commit: atomic ns + `ibd: perf` token. Write-thread wall also on `LastWritePhases` + `confirm write slow`. |
| Completeness | Window `write=` **must** equal the sum of write tokens (`write_stage_ms`). A new large `confirm write slow` named/wall gap is a **missing timer** — add it before more perf work. |
| Tests | Pin the new token on `format_info` / `write_stage_ms` (or `last_write_phases`) the way `tweaks=` is pinned. |
| Not OK | Silent index, flush, secp, body walk, memtable lock, or sidecar join on lookup/load/scripts/write. “Meter it later.” |

Stages overlap on OS threads. Rank by `lookup_thr busy=` / `thr load/script/write busy/wait=` + `loadq_hwm` / `scriptq_hwm` / `writeq_hwm`, not work-sum alone.

### Current inventory (keep this list honest)

| Stage | Tokens | What must stay visible |
|-------|--------|------------------------|
| **Lookup** | `lookup=` / `lookup_thr` / `head_rd` | BQ-ahead TipOnly `head_fk` (`head_n` / blocks-per-wave). `lookup_thr resolve=` is BQ decode in the wave. Does **not** claim. |
| **Load** | `load=` / `load_budget` / `pin(` / `assemble=` / stamp_sub | claim resolve-complete + structure/stamp from BQ hits (no external `head_fk`) + pin + assemble |
| **Scripts** | `script=` (`SCRIPT_NS`) | `rbtc-scripts-*` steal verify. Milestone skip is still this stage (near-zero when `check_scripts` is false). |
| **Write** | `write=` = `write_stage_ms` | table below |
| **Occupancy** | `loadq` / `scriptq` / `writeq` + `*_hwm`, `thr … busy/wait` | who is the serial pole |

**Write tokens** (must sum to `write=`):

| Token | Work |
|-------|------|
| `class_a=` | `archive_commit_plan` (`class_a_sub` body/head/htxs/reserve) |
| `ensure=` | fill planned layout + ensure spend abs (`pin=` / `cold=`) |
| `struct=` | spentness / create-height / BIP68 (`spent_sub`) |
| `class_c=` | strong + tip tables + `flush_class_c_tip` (**not** the SH join wait) |
| `sh=` | SH filter+collect (Direct enqueue / tip durable append). Parallel with strong. |
| `spend=` | spend annotate (`ann=` / `pread_skip`) |
| `tweaks=` | Tip write-through `index_sp_tweaks_batch` only (`--sptweaks`; **0 in Direct** — backfill after IBD) |
| `tip_gc=` | `advance_parent_cache_tip` |

Known leftover on `confirm write slow` **Instant** vs named (18:43 run, after `tweaks=`): **~100–300 ms/batch** (~5% of wall). That is SH enqueue / `thread::scope` join, **not** another multi-second silent index. Do not treat it as the 17:47 hole. If a future change makes that leftover large, meter SH enqueue/join explicitly.

Do not add confirm-path work that does not appear in this inventory without extending the table **and** the logs in the same commit.


## Ship via worktree + pull request (default)

Agent work is **not** committed onto local `master` and is **not** proven by a
full local workspace suite. Default delivery:

```text
worktree branch → many small commits → one PR → poll GitHub Actions → green PR
```

A plan is **not complete** until that PR’s **required** checks are green.
Typical shape: **many commits, one PR**.

### Worktrees

Implement on a **linked worktree**, not the primary checkout (that tree may be
another agent’s dirty branch, and sharing `target/` fights cargo locks).

```bash
# Fetch without rewriting origin (origin stays SSH — see Push below).
git fetch https://github.com/reardencode/rbitcoin.git master:refs/remotes/origin/master
git worktree add -b <area>/<short-name> /tmp/rbtc-<short> origin/master
export CARGO_TARGET_DIR=/tmp/rbtc-<short>/target/dev
```

| Rule | Detail |
|------|--------|
| Base | Current `origin/master` (or `main`) |
| Branch | Topic name (`store/…`, `perf/…`, `docs/…`) — **never** commit the plan onto `master` |
| `CARGO_TARGET_DIR` | Inside the worktree (`…/target/dev`) so objects stay off the other agent’s tree |
| Identity | Worktree-only `git config --worktree user.name` / `user.email` when committing as a bot; do not change the primary checkout’s `user.*` |
| Remotes | Worktrees **share** `origin` with the primary checkout. Never `git remote set-url origin`. |
| After merge | `git worktree remove` the dir; delete the local branch |

### Local tests (thin on purpose)

From `nix-shell` (CI pins **rustc 1.95.0**, same class as `nixos-26.05` in
`flake.lock`). The shell’s `CARGO_TARGET_DIR=target/dev` keeps host objects
out of `target/cov`.

| When | Run |
|------|-----|
| **Each plan step / single-shot** | Targeted `cargo test -p <crate> …` (or slim scenario) for what you touched. `cargo fmt --all` if rustfmt is dirty. |
| **Not by default** | `cargo test --workspace`, `./scripts/coverage.sh`, workspace `clippy … -D warnings`, `nix build .#rbitcoin-musl` |
| **Exception** | User asked for a local full suite, or you cannot push and must prove gates offline |

Do **not** wait out a host IBD or a 90% coverage run in the agent VM. GitHub
Actions is the workspace/coverage/clippy gate.

Targeted tests still follow TDD (Red → Green → Refactor). A step that would
fail its **own** new test is not ready to commit.

### Push, PR, poll CI

Required PR/push jobs (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)):
**`fmt`**, **`deny`**, **`clippy`**, **`test`**, **`multinode`**, **`coverage`**.
The UI shows which gate failed. **`musl.yml`** is **not** required (runs after
green `master` `ci` and uploads node/cli + `SHA256SUMS`).

`origin` stays **SSH** (`git@github.com:reardencode/rbitcoin.git`). The operator
auths over SSH only. This VM has **no** GitHub App SSH key (`Permission denied
(publickey)`). The App token from `~/.config/rbitcoin-grok/gh-login.sh` (~1h)
is HTTPS-only (`gh auth setup-git`).

`gh pr create` / `gh pr checks` talk to the API — they do not use `origin`.
`git fetch` / `git push` as the bot must use an **explicit HTTPS URL**. Do
**not** `git remote set-url origin https://…` (breaks the operator). Do **not**
`git push origin` as the bot (SSH will fail here).

```bash
~/.config/rbitcoin-grok/gh-login.sh   # if the hour-token expired
git fetch https://github.com/reardencode/rbitcoin.git master:refs/remotes/origin/master
git push -u https://github.com/reardencode/rbitcoin.git HEAD:<area>/<short-name>
gh pr create --title "…" --body "…"
gh pr checks --watch          # or: gh run watch
# later commits on the same branch:
git push https://github.com/reardencode/rbitcoin.git HEAD
```

| Rule | Detail |
|------|--------|
| **Leave `origin` on SSH** | Shared with the primary checkout. Push/fetch via the HTTPS URL above. |
| **One PR per plan** | Do not open a PR per step. Push more commits to the same branch. |
| **Poll until green** | After opening (and after each fixup push), watch required checks. Do not walk away and call the plan done. |
| **Red PR** | Fix on the worktree, commit, push, poll again. Same TDD: targeted test first when the fail is behavioral. |
| **Done** | Required checks green **and** the PR is up for review. Do not merge unless the user asked. |
| **Do not** | Force-push `master`, merge a red PR, rewrite `origin` to HTTPS, or skip polling because “tests passed locally.” |

A red required check on the PR is incomplete work. A red `ci` on **`master`**
after merge is also incomplete — fix forward or revert.

**Toolchain:** do not rely on host “latest stable” alone. Expand clippy allows
only for real noise after a toolchain bump — prefer fixing the code.

### Coverage job (CI, not local default)

`./scripts/coverage.sh` enforces **≥90% first-party line coverage** (LCOV
`LH`/`LF`; see `COVERAGE.md`). It is a **required** CI job (slow). Prefer not
to grow uncovered production regions; the 90% bar applies to new and existing
code. If CI `coverage` fails, add a pin and push — do not start a local
coverage run unless you cannot use Actions.

### Multi-step plan execution

When executing an **approved multi-step plan** (see [`docs/how-we-plan.md`](docs/how-we-plan.md)):

| Phase | Expectation |
|-------|-------------|
| **Each intermediate step** | Red → green targeted tests; **one logical commit**. No workspace suite, coverage, or musl. |
| **Plan coded** | Push the branch and open **one** PR. |
| **Plan complete** | Required GitHub Actions checks on that PR are **green**. |
| **After merge to master** | Musl install on the operator host if the node/cli binary changed (recipe below). |

Single-shot turns (one bugfix, one docs rule) use the same path: worktree
branch, targeted tests, one or few commits, one PR, poll to green.

## Commit + static musl release after code changes

### Public commit hygiene (required)

This tree is **public**. Every commit must:

| Rule | Detail |
|------|--------|
| **One logical change** | One concern per commit (one bug fix, one feature slice, one docs rule, one refactor). Do not bundle unrelated edits. |
| **Small** | Prefer a sequence of small commits over one mega-commit. Checkpoint before risky follow-ons so rollback is easy. |
| **Clear message** | Subject + body state **what** changed and **why** in complete sentences. Assume readers have no chat context. |
| **Not** | “WIP”, “misc”, “fix stuff”, drive-by renames mixed with behavior, or multi-hour experiments left as one opaque blob. |

Green-then-refactor is fine as **two** commits when each stands alone (tests still pass at each).

Whenever a turn **changes code** (or you finish a multi-step coding task in that turn):

1. **Pass targeted tests** for what you touched (`cargo test -p <crate> …`).
   Do **not** run the workspace suite or coverage unless the user asked.
2. **Commit** following the public hygiene table above. Prefer one commit per
   logical checkpoint — especially before starting a risky follow-on experiment,
   so we can roll back. Do **not** leave multi-hour IBD perf/refactor work
   uncommitted. A plan is **many commits, one PR**.
3. **Push the worktree branch and open or update the plan PR.** Poll required
   GitHub Actions checks to green before calling the work done.
4. **Musl install (strict):** only after the change is **on `master`/`main`**
   (merged PR) and the tree is clean. Never on a plan branch, never from
   uncommitted work.

   | Situation | Musl? |
   |-----------|--------|
   | Plan / PR branch | **No** |
   | On `master`, after merge of code that ships in the node/cli | **Yes** — one `nix build .#rbitcoin-musl` + install (recipe below) |
   | Uncommitted dirty tree | **No** |
   | Cannot push (hooks, secrets, user said not to) | No musl; say the tree was not pushed |
   | Pure discussion, no compile-affecting edits | Skip commit, PR, and musl |

### Required recipe (only this — single `nix build`; **master + post-commit only**)

```bash
# Preconditions (do not skip):
#   git branch --show-current   # must be master (or main)
#   git status -sb              # clean working tree after the commit
nix build .#rbitcoin-musl --out-link result
mkdir -p target/release
install -m 755 result/bin/rbitcoin-node result/bin/rbitcoin-cli target/release/
file target/release/rbitcoin-node   # must say "statically linked" (musl)
```

Musl builds use **crane** (deps derivation + app derivation). After the first
full deps build, **crate-only edits** recompile workspace crates against a
cached `cargoArtifacts` layer — still one `nix build`, not a host `cargo
build --release`.

### Do **not** run for day-to-day agent turns

| Command | When |
|---------|------|
| `./scripts/repro-check.sh` | **Release / digest gate only** — realize + **two** forced `--rebuild`s. Slow by design. Never as the post-edit install step. |
| `./scripts/repro-check.sh both` | Even heavier (musl + glibc). Release only. |
| `nix build .#rbitcoin-musl` on a feature branch | Agent workflow: **never** — only on master after commit |
| `nix build .#rbitcoin-musl` with uncommitted edits | **Never** — commit first |

On master after commit, portable install = **one** `nix build .#rbitcoin-musl`
(recipe above). Byte-identity claims for a revision = `./scripts/repro-check.sh`
once at release.

### Forbidden for the operator binary

| Do **not** run | Why |
|----------------|-----|
| `nix-shell --run 'cargo build -p rbitcoin-node --release'` | Dynamic **Nix glibc** link; dies off-store with `No such file or directory` |
| `cargo build --release` (host toolchain) | Same class of non-portable binary |
| Leaving `target/release/` as the last **debug** or glibc build | User restarts IBD from that path |

`nix-shell` / `cargo test` for **tests** is fine. Only the **shipped** node/cli
under `target/release/` must come from `nix build .#rbitcoin-musl` (and only
refreshed from master post-commit per the table above).

## How we plan

Multi-step work is planned as **many small vertical slices**, each roughly one
**Red → Green → Refactor** cycle — not a few large “implement phase N” blocks.
Prefer more steps with explicit contracts and test budgets over horizontal
layering (all store, then all consensus, then wire). Full guide:

**[`docs/how-we-plan.md`](docs/how-we-plan.md)** — XP/INVEST-inspired stories,
step template, spikes, suite-speed as a planning constraint, anti-patterns.

When writing or executing a plan/PR plan: every step should name **Contract,
Red, Green, Refactor, Verify** before production code for that step.

## Test-driven development (required for behavioral changes)

**Default: no production code change without a test that fails first and pins
exactly the contract you are fixing or adding.** “When practical” is not an
escape hatch for bugfixes or hot-path behavior. Pure docs/comments/formatting
need no tests. If a full mainnet case cannot run in this VM (see datadir notes),
still encode a synthetic/scenario regression that drives the **shipped** path.

Thrashing (heal → unheal, soft-requeue → permanent, walk-seed → plan-lookup)
comes from coding to logs instead of a failing assertion. A precise failing
test forces a **surgical** green, then a clean **refactor** under green tests
instead of leaving one-off patches everywhere.

### Virtuous cycle: Red → Green → Refactor (agile TDD)

Do not stop at “tests pass.” The suite is the safety net that lets you
**integrate** the fix into the design without re-breaking the contract.

| Phase | Goal | Rules |
|-------|------|--------|
| **Red** | Encode the contract | Failing test only. No production edit yet. Prove the path if non-obvious. |
| **Green** | Make it pass | **Smallest surgical** production change. One-offs and local branches are OK *temporarily* to get green. Do not refactor and invent design in the same breath as the first fix. |
| **Refactor** | Remove the one-off | With **all** relevant tests still green, fold the fix into the real shape: shared helper, right stage (lookup vs load), one policy site, delete dead dual paths. Re-run tests after each refactor step. |

| Anti-pattern | Prefer |
|--------------|--------|
| Ship the first green hunk forever (copy-paste guards, “if mainnet retarget…” special cases next to every caller) | One production implementation at the **lowest owner** of the concept; callers stay dumb |
| Big redesign before any green test | Green first, then refactor under the suite |
| “Refactor” that weakens or deletes the red test | Keep the contract pin; only collapse **duplicate** tests of the same entry (lean-code rules) |
| New soft path / heal beside the real path so tests pass | Fix the protocol; invariants over silent fallbacks |

Commit after green when the checkpoint is useful (especially before a risky
refactor). Prefer the refactored form in the final commit of the change when
it stays small; otherwise green commit then refactor commit — both must stay green.

### Order of work (bugs and features)

| Step | Required |
|------|----------|
| 1. Reproduce | Name the failing contract in one sentence (error string, invariant, observable outcome). Prefer static proof of the code path from production entry → bug when the failure is non-obvious. |
| 2. Red | Add or extend a test that **fails without the change** and would pass only if that contract holds. Run it; capture the fail. |
| 3. Green | Implement the **smallest** production change that makes that test pass. Do not expand scope mid-fix. |
| 4. Refactor | Still green: integrate the fix into shared structure / the correct stage; delete one-offs and dual paths introduced only to get green. Re-run the new and related tests. |
| 5. Before commit | `cargo test -p <crate> …` (or scenario) for everything touched; do not land known red. Workspace suite / coverage wait for GitHub Actions on the PR. |

For **performance**, prefer a before/after benchmark or metered scenario that
shows the win; do not land “perf” rewrites with only correctness tests. Same
cycle: red (or baseline bench) → green (measured win) → refactor without
losing the win.

### What the test must assert

| Do | Do not |
|----|--------|
| Assert the **exact** bug/feature contract (e.g. `expected_bits` with period-start **only** on header plan; pin identity mismatch → invariant, not soft spentness) | Vague “does not panic” / “returns Ok” without encoding the failure mode |
| Drive the **shipped** function or pipeline stage under test | Local helpers that re-implement production and then assert the helper |
| Fail with the **same class of error** (or wrong result) seen in prod when the bug is present | Comment-only or log-narrative “tests” with no executable pin |
| Keep fixtures minimal and synthetic (`/tmp`, tiny head scale) | Require full mainnet datadir open in the agent VM |

### Scenario vs unit — prefer scenarios, balance cost

**Prefer scenario / integration tests** (`rbitcoin-test`, multi-stage confirm
scenarios, store open→append→read) when they exercise the real entry point
cheaply enough. They catch IO-split, tip-ahead, and stage-boundary bugs unit
tests miss.

**Also keep focused unit tests** next to the code (`#[cfg(test)]` in the same
crate) when:

- the scenario would be **slow**, multi-GB, or hard to set up for one branch;
- the bug lives in a **pure helper** on the hot path (bits, range decode, append guards);
- you need a **fast red/green loop** while iterating the fix.

| Goal | How |
|------|-----|
| Quick CI / agent loop | Unit or slim scenario; avoid full-store opens and duplicate suites for the same lines |
| Good practical coverage | One scenario at the entry that mattered in prod **or** one unit on the exact shipped fn — not both for the same lines unless the scenario cannot reach the branch |
| Cheap later refactors | Assert **behavior/contracts**, not private layout trivia; collapse twin unit+integration for the same entry (see lean-code rules) |

Do **not** grow a second full-store suite “for completeness” when a tighter test
already pins the fix. Do **not** skip the failing test because “we’ll add
coverage later.”

## Simplification / lean-code rules (apply while editing)

| Rule | Detail |
|------|--------|
| **Shared helpers** | Prefer one production implementation (composition or shared fn) over copy-paste probe/hash/layout math across modules. Put the helper in the **lowest crate that owns the concept** (`open_address` for FNV/open-hash, etc.). |
| **Invariants > silent fallbacks** | On confirm/store hot path, if load or body load promised a fact (range present, `txout` decode, outs for need_vouts, **spent_range abs**, **parent create identity for a pin**), missing fact → `StoreError::Corrupt("invariant: …")` (or consensus wrap). Do **not** soft-continue to a colder path that hides bugs. Env/protocol multi-path (io_uring off, multi-spender list, RPC reconstruct) stays non-invariant. |
| **No spentness fallbacks for load bugs** | Tip-follow and IBD confirm **must not** recover from wrong/missing pin `create_fk` identity or missing `spent_range` abs by soft spentness paths (thin-as-hint, unpinned wire-corrected idx spentness, reject-only wire re-checks). Fix load/stamp so parent identity matches wire `prev_txid` **before** structural (plan RAM reverse map, else `txid.body`; spent-range ensure when a Class A plan exists). False `PrevoutSpent` from zero-identity pins is a **load bug**, not a spentness oracle problem. |
| **Same-block / corrupt spender meta** | Same-block spends (`create_fk` null) use **pending only** — never durable store-by-txid (Class A rehydrate already holds those creates). Sole `spent` slots whose confirmed-strong spender height **predates** the create height are **impossible** (annotate corruption) — ignore as unspent, do not surface as consensus `PrevoutSpent`. |
| **No test-only production APIs** | Do not add `*_for_test` / budget overrides / backdoors on production types when tests can use real clamps (large payloads, env, or public constructors). Prefer demoting or deleting over growing `cfg(test)` surface that does not exist for dependent crates. |
| **No re-implemented oracles in tests** | A test must drive the **shipped** function. Local helpers that re-code the unit under test and then “assert” that helper are test theater — delete them. |
| **Collapse same-entry duplicates** | Prefer one unit test next to the shipped path over twin unit+integration suites covering the same lines. Keep the closer entry-point test; drop the other only when coverage remains. |
| **Compile/test lean** | Prefer fewer full-store opens, less fixture copy-paste, and no giant dual test modules for the same slim/filter helper. Measure before claiming wall-time wins. |
| **No production-scale fixtures in default unit tests** | Do **not** pin production constants as test IO size when a smaller N still hits the branch: e.g. `FANIN_TARGET_STREAM_RUNS` (4096) run files, multi‑GiB / mainnet heads under `cargo test`, or remine 100-block maturity pads with `confirm_wire_run`. Use tiny stream targets / `RBITCOIN_HEAD_SCALE=tiny` / `pad_empty_from`. Pure math may still assert production geometry. See [`TESTING.md`](TESTING.md) suite-speed budgets; new default tests **&gt;2 s** wall need PR justification. |

## Datadir / store on this workspace (do not open in the agent VM)

The workspace is mounted into the agent VM as **9p** (`workspace` on `/home/agent/workspace`, `trans=virtio`). On this mount:

- Store/mempool tables are **map-free** (pread/pwrite only) — open should work without `MAP_SHARED`.
- Prefer `/tmp` fixtures for agent correctness tests (synthetic stores).

**Perf A/B** is **operator-host only**, with the musl static binary — never agent-VM timings. See [`docs/io-modality.md`](docs/io-modality.md).

### What works instead

- Read **logs** the user leaves in-tree (`signet-ibd.log`, etc.).
- Inspect store files with **pread**/Python struct parsing of HWMs, headers when useful for offline forensics.
- Reproduce with **synthetic fixtures** and `rbitcoin-test` scenarios under `/tmp`.
- Ask the user to run the node / confirm diagnostics / **host musl benches** on their host (normal local FS).

## No dead code warnings silenced unless there is an absolutely bulletproof justification.

Do not leave dead code around. Delete it. Don't silence warnings unless there
is bulletproof justification

Same goes for #[cfg(test)].

## IBD / process memory leak prevention

**Full rules:** `docs/ibd-memory.md`. Summary for agents:

1. **Distinguish** process-owned heap (Rust structures, confirm pipeline wire,
   in-RAM body queue) from **kernel page cache** under FdOnly table files (`RssFile`).
   Do not “fix” RSS by gutting intentional caches (body queue, ConfirmParentCache header plans).
2. **Unified path only:** peer → in-RAM **body queue** → confirm lookup/load/
   scripts/commit (sole Class A). **No** dual-track `ArchiveJob` / ContigPark.
   Unknown-height `BlockFramed` → `mark_missing` and re-getdata after height.
   Body queue is **RAM-only** (redownload on restart) to avoid double disk write
   of every block; soft densify assign uses two limits (no hysteresis): under
   ~100 MiB free densify ahead; over ~100 MiB only heights confirm will consume
   in the next ~1 min at tip rate.
3. **Soft budgets are request-limited only.** Always accept already-requested
   block bytes into the body queue (`block_queue_offer` ignores soft assign
   limits), even if that overshoots soft depth. Bound memory by limiting new
   densify **getdata assign** — never by stalling TCP reads or Full-dropping
   bodies already on the wire.
4. **Tests** must tear down intentional caches with **production** APIs (table
   below) — not a secret free-all that masks production leaks.
5. **Regression filters:** body-queue soft depth / presence lifecycle / confirm
   reject paths as listed in `docs/ibd-memory.md`.

### Production clear / evict APIs (tests must call these)

| Structure | Production API |
|-----------|----------------|
| Soft densify depth | Bound **only** via body-queue soft assign (100 MiB free / 1 min confirm window) — never receive-side Full-drop |
| Confirm plans/headers | **`ConfirmParentCache::advance_tip`** (write `post_commit`) |
| Pipeline pins | Drop with plan/batch; **no** process pin FIFO. Tests tear down via production plan drop / batch drop |
| Ordered maps | **`IbdWorkState::hygiene`** |
| Body presence | **`BodyPresence::hygiene_retain`** (rejected retained by design) |
