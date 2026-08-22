# Documentation map

**One audience, one start file. One fact, one owner. Everyone else links.**

This is the only index. Do not add a second table of contents in `README.md`,
`AGENTS.md`, or a new `docs/INDEX.md`. When a fact already has an owner,
update that file — do not paste a parallel spec.

| Audience | Start | Owns |
|----------|-------|------|
| Operator / new human | [`README.md`](../README.md) → [`OPERATOR.md`](../OPERATOR.md) | How to run, flags |
| Product / interop | [`COMPAT.md`](../COMPAT.md) | Intentional differences, Electrum/RPC surface |
| Contributor (human) | [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Principles, review checklist, comments-as-smell, CI commands |
| Agent | [`AGENTS.md`](../AGENTS.md) | Short hard rules + pointers (not a second design book) |
| On-disk | [`SCHEMA.md`](../SCHEMA.md) | Current bytes; history in [`SCHEMA_HISTORY.md`](../SCHEMA_HISTORY.md) |
| Confirm / store implementer | [`invariants.md`](./invariants.md) + [`concurrency.md`](./concurrency.md) | Stage IO, leftover union, roles, tip commit |
| Tests | [`TESTING.md`](../TESTING.md) | How to run, budgets, coverage |

Planning a multi-step change: [`how-we-plan.md`](./how-we-plan.md).

---

## `docs/` (this directory)

| Doc | Owns |
|-----|------|
| [`architecture.md`](./architecture.md) | Why this node is different (Core / Fulcrum contrasts). No stage-IO table copy. |
| [`concurrency.md`](./concurrency.md) | Writer roles, publish order, body-queue, pins. Links invariants for leftover union. |
| [`invariants.md`](./invariants.md) | Confirm stage IO (the **only** copy), leftover union, store start states S0–S4, no silent fallbacks. |
| [`crash-recovery.md`](./crash-recovery.md) | Tip-as-commit write order, kill-9, open repair. |
| [`ibd-memory.md`](./ibd-memory.md) | Process RAM vs page cache; body-queue soft assign; production evict APIs. |
| [`io-modality.md`](./io-modality.md) | `RBITCOIN_IO`, fd vs uring, host A/B. |
| [`heads.md`](./heads.md) | Which head file / module (tx / header / SH). |
| [`env-knobs.md`](./env-knobs.md) | Residual `RBITCOIN_*` inventory. |
| [`experimental-mainnet.md`](./experimental-mainnet.md) | 0.5 mainnet runbook (early production / high-scrutiny). |
| [`rpc.md`](./rpc.md) | Core-class JSON-RPC subset. |
| [`consensus-tests.md`](./consensus-tests.md) | Rules we own vs Core corpora. |
| [`core-functional.md`](./core-functional.md) | Core v31.1 functional harness. |
| [`how-we-plan.md`](./how-we-plan.md) | Red → Green → Refactor planning contract. |
| [`quality.md`](./quality.md) | Living quality roadmap (Open + Won't fix + short Completed). |
| [`reproducible-builds.md`](./reproducible-builds.md) | Pinned Nix / musl byte-identity. |
| [`rust-bitcoin-limitations.md`](./rust-bitcoin-limitations.md) | Workarounds where rust-bitcoin is not Core-faithful. |
| [`mempool-fee-estimation.md`](./mempool-fee-estimation.md) | Fee estimator notes. |
| [`errata.md`](./errata.md) | Known one-off store/confirm quirks. |
| [`external_findings/`](./external_findings/) | Numbered audit reports + regression pointers. Do not flatten into CHANGELOG. |

## Root (stay at root)

| Doc | Owns |
|-----|------|
| [`README.md`](../README.md) | Product pitch + short pointer table (this map is the rest). |
| [`OPERATOR.md`](../OPERATOR.md) | Day-to-day ops, flags. |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Human+agent principles + checklist. |
| [`AGENTS.md`](../AGENTS.md) | Harness-injected agent contract. |
| [`COMPAT.md`](../COMPAT.md) | Product surface. |
| [`SECURITY.md`](../SECURITY.md) | Vulnerability reporting. |
| [`CHANGELOG.md`](../CHANGELOG.md) | Release notes. |
| [`SCHEMA.md`](../SCHEMA.md) | Current on-disk schema (`SCHEMA_VERSION` home). |
| [`SCHEMA_HISTORY.md`](../SCHEMA_HISTORY.md) | Prior versions and migrations. |
| [`TESTING.md`](../TESTING.md) | Suite, budgets, coverage policy. |

## Confirm stage IO (one table)

**Owner:** [`invariants.md`](./invariants.md) (“Direct IBD stage table”).

`concurrency.md`, `heads.md`, `architecture.md`, and `AGENTS.md` **link** that
table. Do not paste a second Allowed/Forbidden IO copy.

`crash-recovery.md` owns write-order / tip-as-commit (different fact).
`ibd-memory.md` owns RAM caps (different fact).

## Adding or changing a doc

1. Find the owner in the tables above. Edit that file.
2. If the fact has no owner, add a row here in the same commit as the new file.
3. Do not resurrect `docs/future-features/`, `docs/store-format.md`,
   `docs/startup-states.md`, `docs/design-ibd-most-work-reorg.md`, or
   `COVERAGE.md`. Their content lives in SCHEMA / invariants / architecture /
   TESTING.
