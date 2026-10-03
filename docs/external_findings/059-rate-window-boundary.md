# 059 — Rate window keeps the previous second

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L13)

At a one-second boundary the rate window dropped the previous second and granted a second full budget. It keeps that second. The window does not allocate per message.

**Regression:** `rbitcoin-net` `rate_limiter_boundary_does_not_grant_a_second_budget`.
