# 055 — Decoy packets count toward the rate window

**Severity:** high
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (H1)

Decoy and invalid-type packets skipped the per-peer rate window and were logged at info. They are handed to the rate hook on tip-follow and during initial download. A full window disconnects. The window does not allocate per message.

**Regression:** `rbitcoin-net` `decoy_packet_is_handed_to_the_rate_hook`.
