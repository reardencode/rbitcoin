---
name: ship-pr
description: >-
  Open, update, push, or poll a pull request. Use for session worktrees,
  topic branches, HTTPS bot push, fail-fast CI, rebase when unmergeable,
  and retriggering a flake without an empty commit.
---

# Ship a pull request

One session worktree, one topic branch per plan, many small commits (each
already passed local CI except coverage), required checks green. A plan is
not done until those checks are green. Do not merge unless asked.

When to run which command:
[`docs/how-we-plan.md`](../../../docs/how-we-plan.md#agent-contract).
Suite and budgets: [`TESTING.md`](../../../TESTING.md).
Do not copy those facts here.

## Session worktree

One `/tmp/rbtc-<session>` for the session. The next PR is `git switch -C`
from current `origin/master`, not another worktree. Never commit the plan
onto `master`. Worktrees share `origin`. Never `git remote set-url origin`.

`rearden-grok[bot]`: per-session cargo target, identity, HTTPS
`HEAD:<branch>` push, and session end are
[`rearden-vm-HOST.md`](../../../rearden-vm-HOST.md). If you are not that
identity, ignore that file. Use `$PWD/target/dev` and push the topic branch
with ordinary `git push`.

After merge, delete the topic branch only. Keep the session worktree until
the session ends. Do not delete a branch that still has an open PR. Do not
`git push --delete master`.

## Local tests

From `nix-shell` (CI pins rustc 1.95.0). `CARGO_TARGET_DIR` as in Session
worktree. Same **commands** as the required jobs, not the GitHub Actions
`env:` (leave `CARGO_INCREMENTAL` unset; that is
[`ci.yml`](../../../.github/workflows/ci.yml) only).

| When | Run |
|------|-----|
| Inner loop (Red / Green) | Targeted `cargo test -p <crate> --test suite … -- --quiet`. `cargo check -p <crate>`. Not a workspace `--tests` after every edit |
| After Green | `cargo test --workspace --quiet` |
| After Refactor, before commit | Local CI except coverage (below) |
| Docs, comments, formatting only | Skip the suite. `cargo fmt` if rustfmt would touch the tree |
| Core functional CI red | [core-functional skill](../core-functional/SKILL.md) |
| Overlay functional CI red | [overlay-functional skill](../overlay-functional/SKILL.md) |
| Never local | `./scripts/coverage.sh`, `nix build .#rbitcoin-musl`, host IBD |

Redirect every cargo, clippy, deny, and rustc command (stdout and stderr
to `/tmp`, print `EXIT`, search then tail on failure). Recipe:
[`docs/how-we-plan.md`](../../../docs/how-we-plan.md#agent-ram).

Local CI except coverage:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
./scripts/ast-grep.sh
cargo test --workspace --quiet
./scripts/ci-os-smoke.sh
```

If the slice changed `flake.nix`, `nix/`, or the NixOS module, also
`nix build .#checks.x86_64-linux.nixos-module-eval --no-link`. Label the PR
`nixos-module-runtime` when systemd deps, users/groups, firewall, or the VM
start argv changed. Do not wait out the VM test locally.

Coverage and native `windows` / `macos` stay GitHub Actions;
`ci-os-smoke.sh` is the local stand-in.

## Push and poll

Required jobs: `qc`, `test`, `windows`, `macos`, `coverage`, `pread`, and
`rust-forward`. `qc` is fmt, ast-grep, deny, the script self-tests, clippy,
then nixos-module-eval on one runner. `pread` is GitHub Actions only:
`RBITCOIN_IO=pread cargo test -p rbitcoin-store -p rbitcoin-query` after
`qc` and `test`, in parallel with `coverage`. `rust-forward` is the same
wait: `cargo check --workspace --all-targets` on the channel in
`rust-forward.toml`. Do not run either in the local gate list. The `test`
job leaves `RBITCOIN_IO` unset and stays on rustc 1.95. Mutants run nightly
with workspace tests (`mutants.yml`); they are not a required check.
Structural scan is `./scripts/ast-grep.sh`. `windows` / `macos` are native
store plus `--smoke`, not operator zips.

Label `core-functional` when the PR touches that harness, and on every ship
version-bump PR. Do not label ordinary net or RPC PRs.
Label `overlay-functional` when the PR touches that harness, and on every
ship version-bump PR. Poll with `--interest overlay-functional`. It is not
a required check.
Label `warnet` to run the two-tank Docker example
([`docs/core-functional.md`](../../../docs/core-functional.md)). Not a
required check. Do not label ordinary PRs.
Label `nixos-module-runtime` when the NixOS module VM test should run (not
eval). Poll with `--interest nixos-module-runtime`. It is not a required
check.

Bot fetch and push: [`rearden-vm-HOST.md`](../../../rearden-vm-HOST.md).

Pull-request and review text follows
[`CONTRIBUTING.md`](../../../CONTRIBUTING.md#issues-and-reviews).
Read the thread before a review or a reply. Do not copy that section here.

```bash
gh pr create --repo rbitcoin-org/rbitcoin --head <area>/<short-name> --title "…" --body "…"
gh pr view --repo rbitcoin-org/rbitcoin --json mergeable,mergeStateStatus
./scripts/pr-checks-watch.sh --repo rbitcoin-org/rbitcoin --pr <n> \
  --interest windows
```

Installation write: `contents`, `pull_requests`, `issues`, `workflows`,
`actions`. Push `.github/workflows/*` with the topic branch. Do not strip a
workflow diff to sneak a push. `gh run rerun` is in-band. Dismissing a
zizmor code-scanning alert stays operator (`security_events` is read).
A workflow finding is a real finding — fix it. The zizmor job stays green
when it reports alerts; the Protected ruleset is what blocks on them.

**Fail-fast poll.** `./scripts/pr-checks-watch.sh` exits 1 as soon as any
required job fails, and as soon as a `--interest` job fails. On exit 1:
stop polling, fetch that job’s log, and start the fix. `gh pr checks --watch`
waits out `coverage` and zizmor after a job this change already failed.

```bash
gh api --allow-escape-sequences repos/rbitcoin-org/rbitcoin/actions/jobs/<job-id>/logs
gh run view <run-id> --repo rbitcoin-org/rbitcoin --job <job-id> --log-failed
```

**Unmergeable means tests do not run.** If `mergeable` is `CONFLICTING` or
`mergeStateStatus` is `DIRTY` (or `BEHIND` when the branch is not on current
`origin/master`), required `test` CI does not start. Rebase onto
`origin/master`, lease-force the topic branch, then poll. Do not `gh run rerun`
to wake jobs that never queued. Bot lease-force:
[`rearden-vm-HOST.md`](../../../rearden-vm-HOST.md).

| Rule | Detail |
|------|--------|
| One PR per plan | Push more commits to the same branch |
| Mergeable first | Conflicted or behind PRs skip test CI. Rebase, then poll |
| Poll until green | `--interest` the job this change exercises. On fail, fetch the log and fix |
| Done | Required checks green and the PR is up for review. Do not merge unless asked |
| No post-green PR-cite | Do not push a docs-only commit whose only change is this PR's number. Cite it in the PR body |
| Do not | Force-push `master`, merge a red PR, collapse `origin` to one URL, skip polling, or invent empty commits to poke Actions |

### Retrigger CI

When required checks are green locally and CI only needs a re-run:

| OK | Not OK |
|----|--------|
| `gh run rerun <id> [--failed]` | Empty commit whose only purpose is to wake Actions |
| GitHub Actions re-run failed or all jobs | Noise commits (`ci: bump`, `trigger`) |
| Amend the tip and `--force-with-lease` the topic branch | Force-push `master` / `main` |

```bash
gh run rerun <run-id> --failed
```

If the API rejects, amend the tip (no empty commit) and lease-force the
topic branch only. Bot lease-force is
[`rearden-vm-HOST.md`](../../../rearden-vm-HOST.md).

If CI `coverage` fails, add a pin and push. Floor: [`TESTING.md`](../../../TESTING.md).

Operator musl binaries are [`docs/releases.md`](../../../docs/releases.md).
Do not `nix build .#rbitcoin-musl` on a feature branch.
