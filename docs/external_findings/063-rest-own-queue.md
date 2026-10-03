# 063 — REST is off unless --rest is set

**Severity:** high
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (H3)

REST on the RPC listener was always on, shared the RPC work queue, and took a permit before the body was read. REST is off unless `--rest` or `rest=` is set, uses its own queue of the same depth, and reads the body before taking a permit. A full REST queue is HTTP 503. NixOS `services.rbitcoin.rpc.rest` defaults to false and passes `--rest` only when RPC and that option are on.

**Regression:** `rbitcoin-rpc` `rest_is_404_without_the_flag`.
