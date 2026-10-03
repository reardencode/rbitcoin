# 076 — Height 0 is a genesis coin for BIP68

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L1)

A height-0 BIP68 time lock was treated as an unresolved coin and used median time 0. Height 0 is the genesis coin. The structural check looks up that block's median. A missing create height is still `bad-txns-nonfinal`. An empty median is not substituted.

**Regression:** `rbitcoin-consensus` `bip68_height_zero_time_lock_uses_the_median`.
