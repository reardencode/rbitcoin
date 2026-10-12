# Test Size as Resource Contract

Owner: this file. TESTING.md points here; CONTRIBUTING.md routes via TESTING.md.

Test size is determined by what a test is allowed and required to do,
not by the resources it happened to consume in one run, and not by
which helper name implements it.

A function that only hashes a header through `tiny_query` plumbing can
still be Small. A test using `tiny_query` isn't automatically Small,
and a test using a larger helper isn't automatically Large. A journey
that only opens a repository-local store is Medium even if its name
doesn't contain `tiny_store`.

## Definitions

**Small**: pure/in-process, no external resources, no sleep, no filesystem/network, very fast.
Example: `rbitcoin-primitives/src/scriptnum.rs::miri_scriptnum_range_width5_nonminimal`

**Medium**: repository-local integration that uses bounded filesystem state (`TempDir`/`TestDatadir`) or localhost networking with ephemeral ports (`:0`), with bounded setup/teardown.
Examples: `tiny_store` / `tiny_query` / `tiny_regtest_hub` / `TestDatadir`
Example: `rbitcoin-test/tests/scenarios.rs::pin_conf_unknown_key_and_peertimeout` — one TestDatadir, writes conf, asserts exit code.

**Large**: tests requiring external processes, external networks/overlays, or Core differential execution; normally scheduled outside the fast default feedback loop (`core-functional` label, `overlay-functional` live Tor/i2pd, nightly Core, differential outside default `cargo test`).
Example: `core-functional` label, `overlay-functional` live Tor/i2pd

## Policy

- Time is SLO at suite/package level (`cargo test --workspace` ≤3min warm, budgets in `TESTING.md`), not per-test fail line
- No 80/15/5 distribution target
- No per-test timing gates
- Large stays outside default `cargo test` — Core and overlay differential remain nightly/ship/`core-functional` oracle, not default
- Resource budgets and execution limits are owned by the test harness and CI configuration, not by this document. They may change independently of Small/Medium/Large.
- When designing a test, account for applicable resource and isolation constraints, including filesystem, memory, time, process, network, and other harness-enforced requirements. Examples are non-exhaustive.
- Prefer existing shared fixtures when they avoid redundant setup, while preserving the isolation required by the test.
- Use ephemeral ports rather than fixed ports where networking is required.
- Coverage is governed separately by TESTING.md and the CI coverage configuration, not by test-size classification.
- Forbidden-resource detection (sleep in Small/Medium, fixed port bind not `:0`, unlocked `set_var`) remains future lint-only work, not in this contract
