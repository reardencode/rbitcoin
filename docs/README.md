# Documentation map

**One audience, one start file. One fact, one owner. Everyone else links.**

This is the only index. Do not add a second table of contents in `README.md`,
`AGENTS.md`, or a new `docs/INDEX.md`. When a fact already has an owner,
update that file — do not paste a parallel spec.

| Audience | Start | Owns |
|----------|-------|------|
| Operator / new human | [`README.md`](../README.md) → [`OPERATOR.md`](../OPERATOR.md) | Task routes into setup, operations, storage/indexes, client interfaces, and field notes |
| Product / interop | [`COMPAT.md`](../COMPAT.md) | Intentional differences, Electrum/RPC surface |
| Contributor (human) | [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Getting started (any OS, no Nix), principles, review checklist, comments-as-smell, CI commands |
| Agent | [`AGENTS.md`](../AGENTS.md) | Short hard rules + pointers (not a second design book) |
| On-disk | [`SCHEMA.md`](../SCHEMA.md) | Current bytes; soft migrate / bump / refuse; history in [`SCHEMA_HISTORY.md`](../SCHEMA_HISTORY.md) |
| Confirm / store implementer | [`invariants.md`](./invariants.md) + [`concurrency.md`](./concurrency.md) | Stage IO, leftover union, roles, tip commit |
| Tests | [`TESTING.md`](../TESTING.md) | How to run, budgets, coverage, default-CI pin vs nightly Core |
| Peer full nodes | [`peer-clients.md`](./peer-clients.md) | Hornet / satd comparison; later-consideration tests and ideas |

Planning a multi-step change: [`how-we-plan.md`](./how-we-plan.md).
Workspace crate roles and dependency orientation: [`CRATES.md`](./CRATES.md).
Home-node overlays and seqsigwit-window prune: [`operator/operations.md`](./operator/operations.md).
Releases (tag / `vX.Y.x` / `.99`): [`releases.md`](./releases.md).
1.0 product gates: [`road-to-1.0.md`](./road-to-1.0.md) (not the living
quality backlog).

Agent task router (not a second fact index): [`ORIENT.md`](./ORIENT.md).
Process playbooks: [`.agents/skills/`](../.agents/skills/). Do not copy them
into `AGENTS.md`.

---

## `docs/` (this directory)

| Doc | Owns |
|-----|------|
| [`ORIENT.md`](./ORIENT.md) | Agent task router and read-first links. Open one matching row. Not a second index of facts. |
| [`CRATES.md`](./CRATES.md) | Workspace crate roles and dependency orientation. |
| [`operator/`](./operator/) | Task guides linked from `OPERATOR.md`: setup, node operations, storage/indexes, client interfaces, and field notes. |
| [`architecture.md`](./architecture.md) | Why this node is different (Core / Fulcrum contrasts). No stage-IO table copy. |
| [`concurrency.md`](./concurrency.md) | Writer roles, publish order, body-queue, pins. Links invariants for leftover union. |
| [`invariants.md`](./invariants.md) | Confirm stage IO (the **only** copy), leftover union, store start states S0–S4, no silent fallbacks. |
| [`crash-recovery.md`](./crash-recovery.md) | Tip-as-commit write order, kill-9, open repair, mempool sidecar 5 s lag. |
| [`ibd-memory.md`](./ibd-memory.md) | Process RAM vs page cache; body-queue soft assign; production evict APIs. |
| [`io-modality.md`](./io-modality.md) | `RBITCOIN_IO`, fd vs uring, TLS harvest, do-not-flatten machines, host A/B. |
| [`heads.md`](./heads.md) | Which head file / module (tx / header / SH). |
| [`env-knobs.md`](./env-knobs.md) | Residual `RBITCOIN_*` inventory. |
| [`experimental-mainnet.md`](./experimental-mainnet.md) | 0.x mainnet runbook (early production / high-scrutiny). |
| [`rpc.md`](./rpc.md) | Core-class JSON-RPC subset. |
| [`consensus-tests.md`](./consensus-tests.md) | Rules we own vs Core corpora. |
| [`core-functional.md`](./core-functional.md) | Core v31.1 functional harness. |
| [`overlay-functional.md`](./overlay-functional.md) | Private Tor / i2pd / cjdns mesh harness (labeled / nightly). |
| [`how-we-plan.md`](./how-we-plan.md) | Agent contract (cycle, Agent RAM, keep-compiling), then human rationale. |
| [`sv2-template-provider.md`](./sv2-template-provider.md) | SV2 Template Distribution Protocol server roadmap (**Q-64**): Step 0 finding and plans A–D. Live flags/COMPAT rows land in OPERATOR/COMPAT with the plan that ships them. |
| [`sv2-job-validation.md`](./sv2-job-validation.md) | Proposed TDP messages for JDS job validation (`ProposeTemplate`, sv2-spec discussion #239); owner of the wire contract until it lands upstream. Plan D in `sv2-template-provider.md` is the implementation. |
| [`releases.md`](./releases.md) | Tag `vX.Y.Z`, `vX.Y.x` patch line, `.99` bump, Highlights / GitHub notes. |
| [`code-shape.md`](./code-shape.md) | Control flow, types, naming, composition (CONTRIBUTING principle 10). Named extracts: quality.md **Q-61** (Completed). Clippy: no workspace `allow` list; leftover lints are site-local with a reason. |
| [`quality.md`](./quality.md) | Living quality roadmap (Open + Won't-fix + Parked + Protect). |
| [`road-to-1.0.md`](./road-to-1.0.md) | 1.0 product gates and milestone sequence. |
| [`reproducible-builds.md`](./reproducible-builds.md) | Pinned Nix / musl byte-identity. |
| [`rust-bitcoin-limitations.md`](./rust-bitcoin-limitations.md) | rust-bitcoin workarounds, and the upstream issue queue (user-facing bugs, node-only gaps, performance). |
| [`mempool-fee-estimation.md`](./mempool-fee-estimation.md) | Fee estimator notes. |
| [`errata.md`](./errata.md) | Known one-off store/confirm quirks. Retired confirm dual-path names. |
| [`peer-clients.md`](./peer-clients.md) | Hornet Node and satd: what to steal (tests/ideas) and what not to copy. Ranked items stay here; do not copy into quality.md. |
| [`lightning.md`](./lightning.md) | CLN, ldk-node, and LND as Bitcoin backends: `bcli` calls, Esplora/Electrum chain sync, LND `rpcpolling`, `--sh-index` API matrix. | 
| [`wallets.md`](./wallets.md) | Which on-chain wallets connect, and the server string or RPC cookie for each. Lightning stays in `lightning.md`. |
| [`external_findings/`](./external_findings/) | Numbered audit reports + regression pointers. Do not flatten into CHANGELOG. |

## Root (stay at root)

| Doc | Owns |
|-----|------|
| [`README.md`](../README.md) | Product pitch + short pointer table (this map is the rest). |
| [`OPERATOR.md`](../OPERATOR.md) | Day-to-day ops, flags. |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Getting started (rustup; Linux / macOS / Windows) + human+agent principles + checklist. |
| [`AGENTS.md`](../AGENTS.md) | Harness-injected agent contract (hard rules + pointers; not a second design book). |
| [`rearden-vm-HOST.md`](../rearden-vm-HOST.md) | `rearden-grok[bot]` operator VM (per-session worktree and cargo target, bot push). Other identities ignore it. |
| `crates/*/AGENTS.md` | Crate index: neighbors, read-first owners, verify command. Owns no facts. |
| [`COMPAT.md`](../COMPAT.md) | Product surface. |
| [`SECURITY.md`](../SECURITY.md) | Vulnerability reporting. |
| [`CHANGELOG.md`](../CHANGELOG.md) | Published release notes. Unreleased fragments: [`changelog.d/`](../changelog.d/). Process: [`releases.md`](./releases.md). |
| [`SCHEMA.md`](../SCHEMA.md) | Current on-disk schema (`SCHEMA_VERSION` home). Soft migrate / bump / refuse. |
| [`SCHEMA_HISTORY.md`](../SCHEMA_HISTORY.md) | Prior versions and migrations. |
| [`TESTING.md`](../TESTING.md) | Suite, budgets, coverage policy, default-CI pin vs nightly Core. |

## Confirm stage IO (one table)

**Owner:** [`invariants.md`](./invariants.md) (“Direct IBD stage table”).

`concurrency.md`, `heads.md`, `architecture.md`, and `ORIENT.md` **link** that
table. Do not paste a second Allowed/Forbidden IO copy, including into
`AGENTS.md`.

`crash-recovery.md` owns write-order / tip-as-commit (different fact).
`ibd-memory.md` owns RAM caps (different fact).

## Adding or changing a doc

1. Find the owner in the tables above. Edit that file.
2. If the fact has no owner, add a row here in the same commit as the new file.
3. Do not resurrect `docs/future-features/`, `docs/store-format.md`,
   `docs/startup-states.md`, `docs/design-ibd-most-work-reorg.md`,
   `docs/algo-review.md`, or `COVERAGE.md`. Their content lives in SCHEMA /
   invariants / architecture / TESTING / quality.md.
