# 067 — fuse8 segment length must be a power of two

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M4)

A fuse8 filter whose segment length is not a power of two could index past the fingerprint array and panic the thread. Loading that geometry returns corrupt. A filter this node writes still loads.

**Regression:** `rbitcoin-store` `fuse8_segment_length_must_be_power_of_two`.
