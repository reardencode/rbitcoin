# Releases

How we cut, tag, and publish `vX.Y.Z`. Operator snapshots (musl x86_64 and
aarch64 / Windows / Darwin) and the container image are
[`.github/workflows/release.yml`](../.github/workflows/release.yml) on the tag
([Release workflow](#release-workflow)). Byte-identity of those binaries:
[`reproducible-builds.md`](./reproducible-builds.md). This file owns the
**git / PR / branch** process and is the only release playbook.
[`.agents/skills/release/SKILL.md`](../.agents/skills/release/SKILL.md) points
here. Do not copy this playbook into that skill.

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
operator-facing, then the thanks paragraph when this release has one).
`./scripts/release-gate.sh` checks the bullets. Narrative banners
(README, SECURITY, `docs/experimental-mainnet.md`)
are edited on the same bump PR; the scripts do not rewrite them.

`./scripts/release-cut.sh` folds [`changelog.d/`](../changelog.d/) into
`## [Unreleased]`, moves that section into `## [X.Y.Z] — date`, and inserts
an empty `### Highlights`. The ship PR **writes those bullets**
(brief: what an operator should know, not the full Keep a Changelog body).
`./scripts/release-notes.sh` is the GitHub Release / annotated-tag text:
platform blurb + Highlights + a pointer at CHANGELOG. Thanks are part of
Highlights. `release.yml` calls that script. Do not dump Unreleased into
the GitHub Release.

Existing line: **`v0.8.x`** (tag `v0.8.0`). Next minor from
today’s `0.8.99` is **0.9.0**, then **`v0.9.x`**, then master **0.9.99**.

---

## Changelog

Feature pulls do not edit [`CHANGELOG.md`](../CHANGELOG.md). That file is the
published release notes. Unreleased notes are one file per pull under
[`changelog.d/`](../changelog.d/), so two open branches never insert at the
same line.

`changelog.d/<topic>.md` (not `README.md` or `thanks.md`):

```markdown
Fixed

- **CI quick checks share one runner.** `qc` runs fmt, then ast-grep.
```

The first non-empty line is the category: `Added`, `Changed`, `Deprecated`,
`Removed`, `Fixed`, or `Security`. The rest is the Keep a Changelog bullets.
One fragment per pull. A stack adds one file on each branch.
`thanks.md` is not a category fragment. It is one release's thanks
paragraph. The cut places it under `### Highlights` and deletes it.
Write it as prose, not a `- ` bullet, so it does not count toward the
ten. There is no `### Thanks` section.

`./scripts/release-cut.sh --minor`, `--major`, and `--patch` fold every
fragment into `## [Unreleased]` under the matching `###` heading, delete
those files, then move that section under `## [X.Y.Z] — date`. Notes already
sitting in `## [Unreleased]` stay and are cut with the fragments.
`--dev-next` does not consume `changelog.d/`.

---

## Atomicity (as close as git+GitHub allow)

GitHub merge creates the ship SHA. The tag must point at **that** SHA, not
the topic-branch tip (squash/rebase would move it). Closest sequence:

1. Version-bump PR reaches required checks **plus** `release-extra`
   (below).
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
| `./scripts/release-cut.sh --minor` | `X.Y.99` → `X.(Y+1).0`; folds `changelog.d/` into CHANGELOG, then cuts |
| `./scripts/release-cut.sh --major` | `X.Y.99` → `(X+1).0.0`; same changelog fold as `--minor` |
| `./scripts/release-cut.sh --patch` | `X.Y.Z` → `X.Y.(Z+1)` on `vX.Y.x`; same changelog fold |
| `./scripts/release-cut.sh --dev-next` | just-shipped `X.Y.0` → `X.Y.99` |
| `./scripts/release-cut.sh --print-plan …` | prints `ship=` / `maint=` / `dev_next=` |
| `./scripts/release-cut.sh --latest-maint` | highest `vX.Y.x` ref |
| `./scripts/release-gate.sh` | cargo/nix/changelog; ship needs Highlights; `--kind` → `ship`\|`dev` |
| `./scripts/release-notes.sh` | GitHub Release / tag text (blurb + Highlights) |
| `./scripts/release.sh` | annotated tag on a **ship** version |
| `./scripts/release.sh --tag-only` | push the tag, not the branch |
| `./scripts/release-post.sh` | tag + for `X.Y.0` create `vX.Y.x` |
| `./scripts/docker-tags.sh vX.Y.Z` | image tags: `X.Y.Z`; `X.Y` when newest on its line; `latest` when newest overall |
| `./scripts/docker-smoke.sh IMAGE SUMS` | image run contract (hashes, version, regtest boot, cli, SIGTERM) |

`--minor` / `--major` require a `.99` tree. `--patch` is refused on `.99`.
`--dev-next` requires patch `0`.

This VM’s App token is HTTPS-only. Prefer `--no-push` then:

```bash
git push https://github.com/reardencode/rbitcoin.git refs/tags/vX.Y.Z
git push https://github.com/reardencode/rbitcoin.git refs/heads/vX.Y.x   # X.Y.0 only
```

An operator with SSH `pushurl` may omit `--no-push`.

---

## Release workflow

`release.yml` on a pushed `vX.Y.Z` tag:

| Job | Does |
|-----|------|
| `musl-x86_64`, `musl-aarch64` | `.#rbitcoin-musl` natively on `ubuntu-latest` / `ubuntu-24.04-arm` |
| `docker-amd64`, `docker-arm64` | Image from that arch's binaries on a native runner, then `docker-smoke.sh`. No push |
| `windows`, `macos`, `nixos-module-runtime` | Native snapshots; NixOS VM test |
| `github-release` | Needs all of the above. Creates the Release with every asset |
| `docker-publish` | After the Release. One multi-arch manifest (`linux/amd64`, `linux/arm64`) to GHCR, and to Docker Hub when `vars.DOCKERHUB_REPOSITORY` is set. Tags from `docker-tags.sh` |

The `docker` legs gate the Release because they are the only boot of the
aarch64 binary before it ships. `docker-publish` rebuilds the image in one
call from the same staged binaries (the Dockerfile has no `RUN`, so no
emulation) and `sha256sum -c`s them first.

`workflow_dispatch` runs both builds and both smoke legs and never
publishes. If `docker-publish` fails after a good Release, rerun that job:
the same tag gives the same platform manifests.

`docker-publish` runs one tag at a time across the repo (its own
concurrency group), and each run reads the tag list at its start. Two tags
cut together, such as `X.Y.0` and a patch on `vX.(Y-1).x`, cannot move
`latest` or `X.Y` backwards. The group sets `queue: max`, so a third tag
waits its turn instead of cancelling the one already pending.

---

## CI gates on a ship PR

A **ship PR** is one whose tree version is not `.99` (detect job reads
Cargo.toml). Those PRs run Core functional, overlay functional, and the
Warnet example even without a label. [`release-gate.yml`](../.github/workflows/release-gate.yml)
owns ship detection. On a ship PR or label **`release`** it calls
`core-functional.yml`, `overlay-functional.yml`, and `warnet-example.yml`
(`workflow_call`) so `release-extra` can `needs:` all three. Those checks
show as `core-functional / core-functional` and so on.

| Check | Who |
|-------|-----|
| `qc` `test` `windows` `macos` `coverage` `pread` `rust-forward` | Every PR (`ci.yml`). `qc` runs fmt, ast-grep, unwrap-ratchet, hex-ratchet, deny, script self-tests, clippy, then nixos-module-eval. `pread` is `RBITCOIN_IO=pread cargo test -p rbitcoin-store -p rbitcoin-query` on Ubuntu. `rust-forward` is `cargo check --workspace --all-targets` on the channel in `rust-forward.toml`. Both `need` `qc` and `test`, so they start with `coverage`. The `test` job leaves `RBITCOIN_IO` unset (io_uring) and uses rustc 1.95. |
| `mutants` | Nightly `47 0 * * *` (17:47 Pacific during PDT) and `workflow_dispatch` (`mutants.yml`). Workspace tests. New mutants until half of the first job's budget, then the backlog; the second job does not open another new window. 8 hour budget in two jobs. Not required. Cursor and `MISSED` lines are on the `mutants-state` branch. |
| `core-functional` | Nightly, `workflow_dispatch`, label **`core-functional`**; via `release-gate.yml` on label **`release`** **or** ship version |
| `overlay-functional` | Nightly (`42 6`), `workflow_dispatch`, label **`overlay-functional`**; via `release-gate.yml` on label **`release`** **or** ship version |
| `warnet-example` | Label **`warnet`**, `workflow_dispatch`; via `release-gate.yml` on label **`release`** **or** ship version. Two-tank Docker lab. |
| `nixos-module-runtime` | Label **`nixos-module-runtime`**, `workflow_dispatch`, **or** GitHub Release tags (`release.yml`). Not required. |
| `release-extra` | Every PR (`release-gate.yml`). **Fails** if the PR is ship and any of `core-functional`, `overlay-functional`, `warnet-example` is not success |
| `zizmor` | Every PR, push to `master` / `main`, and Monday 05:23 UTC (`zizmor.yml`). Audits Actions workflows. The job stays green when it finds issues. Merge blocking is the Protected ruleset code-scanning tool, which must be `zizmor` (security alerts high or higher, other alerts errors). Not a required status check. `v*.*.x` is in that same ruleset, so those branches need `zizmor.yml` before the tool name changes |

Label ship PRs **`release`**. The detect job is the backstop if the label
is missing.

Ask the operator to add **`release-extra`** as a **required** status check
on `master` / `main` / `v*.*.x` (ruleset). Until then, agents still wait
for it before merge.

Unlabeled non-ship PRs keep cargo gates only (detect=`dev`, the three
functional suites skipped, `release-extra` green).

---

## Playbooks

Worktree + HTTPS push + poll:
[`.agents/skills/ship-pr/SKILL.md`](../.agents/skills/ship-pr/SKILL.md).
Do not commit the bump on `master`. Do not merge a red PR.

### Minor (`do a minor release`)

From current `origin/master` at `X.Y.99`:

1. Worktree `release/X.(Y+1).0`. `./scripts/release-cut.sh --minor`.
2. Write **`### Highlights`** (brief, operator-facing; at most ten bullets).
   Leave the thanks paragraph from `changelog.d/thanks.md` at the end of
   that section. `release-notes.sh` keeps thanks in Highlights. When a
   commit since the previous tag is by someone other than `reardencode`
   and `rearden-grok[bot]`, and that login is not already named there, the
   notes add `Thanks to @login for changes in this release.` in the same
   block. A login counts when its commit email is a GitHub noreply address,
   or when a merge commit says `from login/`. The maintainer, the bot, and
   dependabot stay out. Edit narrative
   banners to the new **X.(Y+1).0** (and that `vX.(Y+1).x` will be the
   patch line). Keep the detailed Unreleased body under the new heading.
3. `./scripts/release-gate.sh` and `./scripts/release-notes.sh` must
   succeed (preview the GitHub Release text).
4. PR → `master`. Label `release`. Poll **required +
   `core-functional` + `overlay-functional` + `warnet-example` +
   `release-extra`**.
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
3. `./scripts/release-cut.sh --patch`. Write **`### Highlights`**
   (bullets, then the thanks paragraph, same as a minor). Narrative
   as needed.
4. PR → **`vX.Y.x`** (not `master`). Same ship labels and gates.
5. Merge, fetch, checkout `origin/vX.Y.x`, `./scripts/release-post.sh`
   (tags; does **not** create a new maint branch or a `.99` bump).

### Major (`do a major release`)

Same as minor with `--major`. Do not tag `v1.0.0` until
[`SECURITY.md`](../SECURITY.md) names a 1.0.x support window. The same
bump updates that window and the schema-freeze language.

---

## Operator follow-ups (not agent-mergeable)

- Required check **`release-extra`** on protected branches.
- Retry artifacts only: Actions → **release** → Run workflow (no tag).
- Docker Hub: create `reardencode/rbitcoin` and an access token with Read &
  Write on that repository only. Set repo variables `DOCKERHUB_REPOSITORY`
  (`reardencode/rbitcoin`) and `DOCKERHUB_USERNAME`, and secret
  `DOCKERHUB_TOKEN`. With the variable unset, `docker-publish` pushes GHCR
  only.
- GHCR: after the first `docker-publish`, check that package `rbitcoin` is
  Public and linked to this repository.
- The BuildKit image pin in `docker-publish` is bumped by hand. Dependabot
  does not track it.
