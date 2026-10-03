# 066 — RPC accept times out and long-polls release the permit

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M3)

The RPC listener had no accept timeout, and a long-poll held a work-queue permit for the whole wait. Accepts time out at two minutes, the listener caps connections, and the long-poll takes a permit only after the wait.

**Regression:** `rbitcoin-rpc` `long_poll_does_not_hold_the_work_queue`, `wait_timeout_ms_caps_at_two_minutes`.
