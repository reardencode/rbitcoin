# 060 — Evict the newest inbound in the largest netgroup

**Severity:** high
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (H2)

Inbound eviction disconnected the oldest unprotected peer. It protects a share of the longest-connected peers, then disconnects the newest peer in the largest netgroup. The netgroup key is fixed when the peer is accepted. Asmap stays outbound-only.

**Regression:** `rbitcoin-net` `eviction_drops_the_newest_in_the_largest_netgroup`.
