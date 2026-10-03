# 069 — io_uring drop does not free a buffer still in the kernel

**Severity:** high
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M9)

Dropping an io_uring session that had stopped completing freed buffers the kernel could still write. Drop uses the same drain hard cap as the fail-closed path and does not shorten that cap. Outside tests, a drain that hits the cap aborts. In tests, the pending buffers are leaked and the error is surfaced.

**Regression:** `rbitcoin-store` `drain_guard_drop_with_leftover_pending_does_not_abort`.
