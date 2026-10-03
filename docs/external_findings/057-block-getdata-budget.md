# 057 — Block serving stops when the send budget is over

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M1)

Block getdata could queue more data after the per-peer send budget was already over. Serving stops once that budget is over.

**Regression:** `rbitcoin-net` `getdata_stops_when_send_budget_is_already_over`.
