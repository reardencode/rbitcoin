# Releases

How we cut, tag, and publish `vX.Y.Z`. Operator snapshots (musl / Windows /
Darwin) are [`.github/workflows/release.yml`](../.github/workflows/release.yml)
on the tag. Byte-identity of those binaries:
[`reproducible-builds.md`](./reproducible-builds.md). This file owns the
**git / PR / branch** process and is the agent playbook (linked from
[`AGENTS.md`](../AGENTS.md)). Do not keep a second copy under a harness
skill directory.

---

## Version model

| Tree | `workspace.package.version` | Meaning |
|------|-----------------------------|---------|
| `master` / `main` | **X.Y.99** | In-tree toward **X.(Y+1).0**. Never tagged. |
| Ship commit | **X.Y.0** (minor/major) or **X.Y.Z** (patch, Z≠99) | Tagged `vX.Y.Z`. GitHub Release. |
| Patch line | **`vX.Y.x`** branch | X.Y.1, X.Y.2, … after that minor/major. |

Patch **99** is the in-tree sentinel, not a published patch. `./scripts/release.sh`
refuses to tag it. `--patch` refuses to create it (`Z` stays `< 99`).

Homes that must match on a ship commit: `Cargo.toml`
`[workspace.package].version`, `nix/rbitcoin.nix` `version`, `CHANGELOG.md`
`## [X.Y.Z]` with a **`### Highlights`** subsection (1–10 bullets,
operator-facing). `./scripts/release-gate.sh` checks that. Narrative banners
(README, SECURITY, `docs/road-to-1.0.md`, `docs/experimental-mainnet.md`)
are edited on the same bump PR; the scripts do not rewrite them.

`./scripts/release-cut.sh` moves `## [Unreleased]` into `## [X.Y.Z] — date`
and inserts an empty `### Highlights`. The ship PR **writes those bullets**
(brief: what an operator should know, not the full Keep a Changelog body).
`./scripts/release-notes.sh` is the GitHub Release / annotated-tag text:
platform blurb + Highlights + a pointer at CHANGELOG. `release.yml` calls
that script. Do not dump Unreleased into the GitHub Release.

Existing line: **`v0.6.x`** (tag `v0.6.0`). Next minor from
today’s `0.6.99` is **0.7.0**, then **`v0.7.x`**, then master **0.7.99**.

---

## Atomicity (as close as git+GitHub allow)

GitHub merge creates the ship SHA. The tag must point at **that** SHA, not
the topic-branch tip (squash/rebase would move it). Closest sequence:

1. Version-bump PR reaches required checks **plus** `core-functional` /
   `release-extra` (below).
2. Merge (`gh pr merge --merge` — merge commit, not squash).
3. **Immediately** tag `vX.Y.Z` on `mergeCommit.oid` and push **only the
   tag** (`./scripts/release.sh --tag-only` or `./scripts/release-post.sh`).
   That push is what starts `release.yml`.
4. If this was **X.Y.0**: create **`vX.Y.x`** at the same SHA (if missing)
   and open the **X.Y.99** PR onto `master`.

Do not wait for the `.99` PR before tagging. Do not tag `.99`. Do not leave
a ship version sitting on `master` untagged.

`GITHUB_TOKEN` tag pushes **do not** start `release.yml` (GitHub recursive
workflow rule). Tag from the App token / operator remote so the Release
workflow actually runs.

---

## Scripts

All hermetic pins: `./scripts/release.test.sh` (includes
`release-flow.test.sh`). `--root` / `--dry-run` / `--no-push` as elsewhere.

| Command | Does |
|---------|------|
| `./scripts/release-cut.sh --minor` | `X.Y.99` → `X.(Y+1).0`; cuts CHANGELOG |
| `./scripts/release-cut.sh --major` | `X.Y.99` → `(X+1).0.0` |
| `./scripts/release-cut.sh --patch` | `X.Y.Z` → `X.Y.(Z+1)` on `vX.Y.x` |
| `./scripts/release-cut.sh --dev-next` | just-shipped `X.Y.0` → `X.Y.99` |
| `./scripts/release-cut.sh --print-plan …` | prints `ship=` / `maint=` / `dev_next=` |
| `./scripts/release-cut.sh --latest-maint` | highest `vX.Y.x` ref |
| `./scripts/release-gate.sh` | cargo/nix/changelog; ship needs Highlights; `--kind` → `ship`\|`dev` |
| `./scripts/release-notes.sh` | GitHub Release / tag text (blurb + Highlights) |
| `./scripts/release.sh` | annotated tag on a **ship** version |
| `./scripts/release.sh --tag-only` | push the tag, not the branch |
| `./scripts/release-post.sh` | tag + for `X.Y.0` create `vX.Y.x` |

`--minor` / `--major` require a `.99` tree. `--patch` is refused on `.99`.
`--dev-next` requires patch `0`.

This VM’s App token is HTTPS-only. Prefer `--no-push` then:

```bash
git push https://github.com/reardencode/rbitcoin.git refs/tags/vX.Y.Z
git push https://github.com/reardencode/rbitcoin.git refs/heads/vX.Y.x   # X.Y.0 only
```

An operator with SSH `pushurl` may omit `--no-push`.

---

## CI gates on a ship PR

A **ship PR** is one whose tree version is not `.99` (detect job reads
Cargo.toml). Those PRs run Core functional even without a label.

| Check | Who |
|-------|-----|
| `fmt` `deny` `clippy` `ast-grep` `test` `windows` `macos` `multinode` `coverage` | Every PR (`ci.yml`) |
| `core-functional` | Nightly, `workflow_dispatch`, label **`core-functional`**, label **`release`**, **or** ship version |
| `release-extra` | Every PR. **Fails** if the PR is ship and `core-functional` is not success |

Label ship PRs **`release`** and **`core-functional`**. The detect job is
the backstop if a label is missing.

Ask the operator to add **`release-extra`** as a **required** status check
on `master` / `main` / `v*.*.x` (ruleset). Until then, agents still wait
for it before merge.

Unlabeled non-ship PRs keep cargo gates only (detect=`dev`,
`core-functional` skipped, `release-extra` green).

---

## Playbooks

Worktree + HTTPS push + poll: [`AGENTS.md`](../AGENTS.md). Do not commit
the bump on `master`. Do not merge a red PR.

### Minor (`do a minor release`)

From current `origin/master` at `X.Y.99`:

1. Worktree `release/X.(Y+1).0`. `./scripts/release-cut.sh --minor`.
2. Write **`### Highlights`** (brief, operator-facing). Edit narrative
   banners to the new **X.(Y+1).0** (and that `vX.(Y+1).x` will be the
   patch line). Keep the detailed Unreleased body under the new heading.
3. `./scripts/release-gate.sh` and `./scripts/release-notes.sh` must
   succeed (preview the GitHub Release text).
4. PR → `master`. Labels `release` + `core-functional`. Poll **required +
   `core-functional` + `release-extra`**.
5. `gh pr merge --merge`. Fetch. Create a throwaway branch at
   `origin/master` (or `origin/vX.Y.x`) — do not steal `master` from
   another worktree (`git switch -C tag/vX.Y.Z origin/master`).
6. `./scripts/release-post.sh --no-push --allow-branch tag/vX.Y.Z` then
   HTTPS-push the tag and `vX.(Y+1).x`. Confirm `release.yml` started.
7. New worktree from that master: `./scripts/release-cut.sh --dev-next`.
   Narrative banners → **X.(Y+1).99**. PR → `master` (no ship labels).
   Merge when required checks are green.

### Patch (`do a patch release with <change>`)

1. `./scripts/release-cut.sh --latest-maint` (override if the user named
   an older line, e.g. `v0.5.x` after 0.6 is out).
2. Worktree from `origin/vX.Y.x`. Cherry-pick the change (must apply). If
   master also needs it and does not have it, say so — do not silently
   skip master.
3. `./scripts/release-cut.sh --patch`. Write **`### Highlights`**. Narrative
   as needed.
4. PR → **`vX.Y.x`** (not `master`). Same ship labels and gates.
5. Merge, fetch, checkout `origin/vX.Y.x`, `./scripts/release-post.sh`
   (tags; does **not** create a new maint branch or a `.99` bump).

### Major (`do a major release`)

Same as minor with `--major`, **after** reading
[`road-to-1.0.md`](./road-to-1.0.md). If any 1.0 promise is still open,
**stop** and report; do not tag `v1.0.0` as a dry run. 1.0 also updates
SECURITY support window and schema-freeze language.

---

## Operator follow-ups (not agent-mergeable)

- Required check **`release-extra`** on protected branches.
- Retry artifacts only: Actions → **release** → Run workflow (no tag).
