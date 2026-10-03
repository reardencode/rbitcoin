# Test Size as Resource Contract

Owner: this file. TESTING.md points here; CONTRIBUTING.md routes via TESTING.md.

Size is what the test **does**, not which helper it calls. A function that only hashes a header through `tiny_query` plumbing can still be Small. A journey that opens a store is Medium even if name doesn't contain `tiny_store`.

## Definitions

**Small**: pure/in-process, no external resources, no sleep, no filesystem/network, very fast.
Example: `rbitcoin-primitives/src/scriptnum.rs::miri_scriptnum_range_width5_nonminimal`

**Medium**: repository-local integration that touches filesystem (`TempDir`/`TestDatadir` with bounded teardown) or localhost `:0` only, bounded setup/teardown.
Examples: `tiny_store` / `tiny_query` / `tiny_regtest_hub` / `TestDatadir`
Example: `rbitcoin-test/tests/scenarios.rs::pin_conf_unknown_key_and_peertimeout` — one TestDatadir, writes conf, asserts exit code.

**Large**: tests requiring external processes, external networks/overlays, or Core differential execution; normally scheduled outside the fast default feedback loop (`core-functional` label, `overlay-functional` live Tor/i2pd, nightly Core, differential outside default `cargo test`).
Example: `core-functional` label, `overlay-functional` live Tor/i2pd

## Policy

- Time is SLO at suite/package level (`cargo test --workspace` ≤3min warm, budgets in `TESTING.md`), not per-test fail line
- No 80/15/5 distribution target
- No per-test timing gates
- Large stays outside default `cargo test` — Core and overlay differential remain nightly/ship/`core-functional` oracle, not default
- Forbidden-resource detection (sleep in Small/Medium, fixed port bind not `:0`, unlocked `set_var`) remains future lint-only work, not in this contract

