# 082 — Invalid-hash set stops at 4096

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L12)

The invalid-hash set grew without a cap, clearing entries to make room. It stops at 4096 and does not clear.

**Regression:** `rbitcoin-net` `invalid_hash_set_stops_at_the_cap`.
