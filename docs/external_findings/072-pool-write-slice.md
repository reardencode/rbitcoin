# 072 — Pool write jobs use a shared slice

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L15)

The background IO worker formed a mutable slice for every job, including writes that only read the caller buffer. A write uses a shared slice. A read still uses a mutable slice.

**Regression:** `rbitcoin-store` pool write arm uses a shared slice.
