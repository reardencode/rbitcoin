# rearden-grok operator VM

**Ignore this file unless you are acting as `rearden-grok[bot]`.**

This is one operator Cursor VM (ephemeral disk, no App SSH key). It is not
contributor setup, CI, a fork, or any other agent identity. Humans and
other agents use [`TESTING.md`](TESTING.md) Artifact silos and
[`CONTRIBUTING.md`](CONTRIBUTING.md) (`$PWD/target/dev`).

Owner of these host facts. Do not copy the tables into `AGENTS.md`,
`TESTING.md`, or the skills.

## Identity

Worktree-only (do not change the Cursor checkout `user.name`):

```bash
~/.config/rbitcoin-grok/configure-worktree.sh .
# rearden-grok[bot] <317016512+rearden-grok[bot]@users.noreply.github.com>
```

Re-auth (~1 h token): `~/.config/rbitcoin-grok/gh-login.sh`.

## Disk and cargo

Root is ~40 G. Git worktrees already share `.git` objects. Each session
has its own worktree and its own `target/dev` (~9 G once warm). Several
sessions build and test at the same time. Abandoned worktrees, a target
that keeps bins from a previous branch, and cargo in the editor tree are
what fill the disk.

| Rule | How |
|------|-----|
| One worktree per session | `/tmp/rbtc-<session>`. Another agent uses another directory. The next PR in this session is `git switch -C` in this worktree. |
| One target per session | Leave `CARGO_TARGET_DIR` unset. The nix hook sets `$PWD/target/dev` inside that worktree. Each target has its own lock and its own bins, so concurrent cargos stay apart. Leave `CARGO_HOME` at the default: `~/.cargo` is the shared registry and git-dep cache. |
| Editor tree | `/home/agent/workspace/rearden-bitcoin` is the Cursor checkout. Do not cargo there. The session branch lives in its `/tmp/rbtc-<session>` worktree. |
| Clean this target | On one branch, dep rlibs and incremental are the warm cache. On each `git switch -C`, `rm -rf target/dev/debug/incremental`. Do that mid-branch too when `debug/incremental` is multiple GiB: those files grow with every edit, and the old CGUs are not reused. `cargo clean` this session's target when the dep graph or `RUSTFLAGS` changed, or when `debug/deps` still holds hashed bins from the previous branch. That clean hits only this worktree. |
| Other sessions | Do not `cargo clean` or delete another session's `target/`. A live session is a `/tmp/rbtc-*` worktree with a cargo or rustc whose cwd is that tree, or a held `target/.cargo-lock`. |
| ENOSPC | Before the first cargo of a session, `df /`. Clean this session's incremental and stale dep bins first. Skip production-scale body tests (`sp_tweaks` and similar multi‑GiB `/tmp` files). Skip `cargo test --workspace` when free space is a few GiB. Never `./scripts/coverage.sh` here (`target/cov` is another silo). Targeted `-p` tests plus clippy are enough to push. |
| No `cargo mutants` | Never run `cargo mutants` on this VM. A copy of the workspace build fills the root disk. How to check a miss: [`TESTING.md`](TESTING.md). |
| Session end | `git worktree remove` this session's `/tmp/rbtc-<session>` (that removes its `target/dev`). `rm -rf` the `/tmp/rbitcoin-*` test dirs this session created. |

Do not change `shell.nix` / `flake.nix` defaults. Those stay
`$PWD/target/dev` for humans, CI, and this VM.

## Session worktree

```bash
# once per session
git fetch origin
git worktree add /tmp/rbtc-<session> origin/master
cd /tmp/rbtc-<session>
git switch -c <area>/<short-name>
# CARGO_TARGET_DIR stays unset; nix-shell sets $PWD/target/dev
~/.config/rbitcoin-grok/configure-worktree.sh .

# next PR in the same session (same worktree, same target path)
git fetch origin
rm -rf target/dev/debug/incremental
# cargo clean   # when the dep graph, RUSTFLAGS, or hashed dep bins changed
git switch -C <area>/<next-short> origin/master
```

```bash
# session end
git worktree remove /tmp/rbtc-<session>
rm -rf /tmp/rbitcoin-*
git fetch origin --prune
```

Commands after that: [`.agents/skills/ship-pr/SKILL.md`](.agents/skills/ship-pr/SKILL.md).
Cargo/clippy/deny/rustc stdout: [`docs/how-we-plan.md`](docs/how-we-plan.md)
(Agent RAM).

## Fetch and push

`origin` stays SSH (`git@github.com:rbitcoin-org/rbitcoin.git`) with HTTPS
fetch. This VM has no App SSH key (`ssh -T git@github.com` → Permission
denied). Never `git remote set-url origin` (worktrees share remotes).

Bot `git fetch` / `git push` use an explicit HTTPS URL. Do not
`git push origin`. No `-u` (that retargets the branch remote away from
`origin`).

```bash
~/.config/rbitcoin-grok/gh-login.sh
git fetch origin
git push https://github.com/rbitcoin-org/rbitcoin.git HEAD:<area>/<short-name>
gh pr create --repo rbitcoin-org/rbitcoin --head <area>/<short-name> --title "…" --body "…"

# rebase then update the topic branch
git rebase origin/master
git push --force-with-lease https://github.com/rbitcoin-org/rbitcoin.git HEAD:<area>/<short-name>

# after merge, delete the topic branch only
git push https://github.com/rbitcoin-org/rbitcoin.git --delete <area>/<merged-short>
```
