# 074 — Tip-follow bodies and one peer's orphans are bounded

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M8)

Pending blocks and orphans were capped by count only. A tip-follow pending block or held body larger than 4,000,000 bytes is not parked, and the byte ceiling is the count cap times that size. The IBD body queue is not byte-capped. One peer's orphans stay within that peer's weight reserve.

**Regression:** `rbitcoin-net` `pending_block_over_four_megabytes_is_not_parked`, `one_peer_cannot_fill_the_orphanage`.
