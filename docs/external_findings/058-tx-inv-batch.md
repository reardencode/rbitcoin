# 058 — Mempool announcements batch into one inv

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M7)

Each mempool transaction was its own inv. Announcements are batched up to 1000 per message and still charged against the per-peer send budget.

**Regression:** `rbitcoin-net` `tx_inv_over_one_thousand_is_two_messages`.
