# 061 — Misbehavior disconnect is remembered in memory

**Severity:** high
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (H2-ban)

A misbehavior disconnect was forgotten, so the same address could reconnect immediately. The address is refused from a capped in-memory set. There is no ban file and no new ban-time flag. A netgroup that just lost an inbound slot waits ten minutes.

**Regression:** `rbitcoin-net` `misbehavior_disconnect_refuses_the_same_address`.
