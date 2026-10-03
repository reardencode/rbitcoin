# 079 — Recent-reject set stops at 4096

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L6)

The recent-reject set cleared itself when it reached the cap, so it could keep growing. It stops at 4096 entries and does not clear.

**Regression:** `rbitcoin-net` `recent_reject_at_the_cap_does_not_clear`.
