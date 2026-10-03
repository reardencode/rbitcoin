# 068 — Body reads compare the caller's published end

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M5)

A class A bulk read and a create.loc window pread could decode bytes past the published end left by a reorg. The read compares the end the caller already paired with the count and returns corrupt when the span is past that integer. It does not take the publish seqlock again on that read. A read inside the snapshot still succeeds after a later shrink.

**Regression:** `rbitcoin-store` `body_read_past_published_end_is_corrupt`, `create_loc_read_past_published_end_is_corrupt`, `body_read_uses_the_caller_published_end`, `create_loc_window_read_uses_the_planned_published_end`.
