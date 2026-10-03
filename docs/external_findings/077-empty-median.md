# 077 — Empty median time is an error

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L4)

An empty median-time input panicked. It returns an error. Callers map that to a bad header, a corrupt store, or a failed header walk.

**Regression:** `rbitcoin-primitives` `empty_median_time_is_an_error`.
