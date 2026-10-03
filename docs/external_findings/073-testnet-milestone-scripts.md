# 073 — Omitted testnet milestone checks every script

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M6)

An omitted milestone on testnet was height-only, so script checks were skipped below that height. The default testnet height is 0, so every script is checked. An explicit `--milestone HEIGHT` stays height-only. Omitted mainnet stays anchored to the milestone hash and minimum chain work. NixOS `services.rbitcoin.milestone` is unset by default and passes `--milestone` only when set.

**Regression:** `rbitcoin-node` `p3_default_milestone_heights`, `operator_conf_and_argv`.
