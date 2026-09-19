# Agent notes

Documentation map (one owner per fact): [`docs/README.md`](docs/README.md).
Before exploring, read [`docs/ORIENT.md`](docs/ORIENT.md).
This file is the harness-injected hard-rule contract. Design lives in the
owner docs; do not grow a second design book here.

Process playbooks are Agent Skills under [`.agents/skills/`](.agents/skills/).
Read the matching `SKILL.md` when the task needs it. Do not paste those
playbooks back into this file.

## Language, comments, composition

Write clear, concrete technical English. Keep Core-aligned terms where we
match Bitcoin Core. Do not inject moralizing or political framing, or soften
consensus and security language. If a rename is not clearer engineering, keep
the existing term.

Comments that restate what, why, or weird are a smell. Prefer names, types,
and structure. Keep `//` only for an invariant, protocol rule, `SAFETY`, or
library quirk. Crate and public rustdoc (`//!` / `///`) is not this rule.
Full text: [`CONTRIBUTING.md`](CONTRIBUTING.md) principle 7.

Prefer composition (has-a) over inheritance; avoid tall trees. Build
immutable structures once, then compose them. If a map needs extra fields,
wrap it on read rather than mutating members in place.
Control flow: principle 10 and [`docs/code-shape.md`](docs/code-shape.md).

## Store and IBD

**No locks on the store hot path.** Roles, publish order, grow, pins:
[`docs/concurrency.md`](docs/concurrency.md). Heads: [`docs/heads.md`](docs/heads.md).
Class B insert geometry: [`SCHEMA.md`](SCHEMA.md). Stage IO (the only
Allowed/Forbidden table): [`docs/invariants.md`](docs/invariants.md).

- No large process-resident body, pin, or archive caches with FIFO, LRU, or
  sticky residency. Pins are plan/batch only. IBD intake is body queue →
  lookup → load. [`docs/ibd-memory.md`](docs/ibd-memory.md).
- Grow capacity with fallocate / `set_len` and a published high-water mark.
  Do not introduce remap-epoch schemes. [`docs/concurrency.md`](docs/concurrency.md).
- Do not replace a purpose-built IO machine with generic batched `pread` /
  `pwrite` without asking. [`docs/io-modality.md`](docs/io-modality.md).
- Missing promised fact → `StoreError::Corrupt("invariant: …")`. No silent
  fallback. On-disk change: soft migrate, `SCHEMA_VERSION` bump, or explicit
  refuse, in the same commit as the format code. Never a silent wipe.
  [`SCHEMA.md`](SCHEMA.md).
- Test-only adapters stay in `*_testutil`. Do not grow production APIs around
  fixture shapes.
- Anything on lookup, load, scripts, or write (or a sidecar the write thread
  joins) gets a named `ibd: perf` timer in the same commit. Inventory:
  `crates/rbitcoin-net/src/ibd/perf_log.rs`.

## Change discipline

No production code change without a test that fails first. Docs, comments,
and formatting need no tests. Do not open a mainnet datadir in the agent VM.
Perf A/B is operator-host only.

One plan step is one Red → Green → Refactor turn, committed before the next
step. Keep `--lib` compiling (wrap the old API, switch one caller). Owner:
[`docs/how-we-plan.md`](docs/how-we-plan.md). Commands:
[`.agents/skills/ship-pr/SKILL.md`](.agents/skills/ship-pr/SKILL.md).

One production implementation at the lowest crate that owns the concept.
Extract is a move: [`docs/code-shape.md`](docs/code-shape.md). Core-facing
RPC / P2P / Electrum / Esplora: [`COMPAT.md`](COMPAT.md).

Tests assert shipped behavior, not repo text
([`CONTRIBUTING.md`](CONTRIBUTING.md) principle 8). Budgets, no `*_for_test`
backdoors, no production-scale default fixtures: [`TESTING.md`](TESTING.md).
Tests use session or table instance stats or on-disk state, not thread-local
hot-path IO probes.

Crate `pub` is the cross-crate graph only. Unused `pub` is forbidden.
`#[cfg(test)]` on production items is a smell, including fuzz-only exports.
Do not leave dead code or silence `dead_code`. A RAM or CPU trade is named
([`CONTRIBUTING.md`](CONTRIBUTING.md) principle 9).

One logical change per commit. The message says what and why. Not WIP, misc,
or a drive-by rename mixed with behavior.

Before the first edit under `crates/<name>/`, read `crates/<name>/AGENTS.md`
when it exists.

## Ship, release, Core functional

One session worktree, one topic branch per PR, required checks green before
the plan is done. Do not merge unless asked.

- Opening, updating, pushing, or polling a PR:
  [`.agents/skills/ship-pr/SKILL.md`](.agents/skills/ship-pr/SKILL.md).
- A minor, patch, or major release:
  [`.agents/skills/release/SKILL.md`](.agents/skills/release/SKILL.md).
  Owner playbook: [`docs/releases.md`](docs/releases.md).
- Core functional harness:
  [`.agents/skills/core-functional/SKILL.md`](.agents/skills/core-functional/SKILL.md).
