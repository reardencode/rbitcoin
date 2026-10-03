# 083 — Mempool expiry runs without a new admission

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L14)

Mempool expiry ran only when a transaction was admitted, and a full walk held the pool. Expiry also runs from the headers poll, scanning at most 256 entries from a cursor, so a quiet pool still drops stale transactions. A young pool does not take a full scan.

**Regression:** `rbitcoin-net` `expire_stale_drops_old_tx_without_a_new_accept`, `hub_live_journey`.
