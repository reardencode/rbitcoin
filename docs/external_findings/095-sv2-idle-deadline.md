# 095 — SV2 session has no idle deadline after setup

**Severity:** high
**Status:** fixed (now opt-in)
**Found by:** bobberb and muse, 2026-10-18

The setup deadline covered the handshake and the first `CoinbaseOutputConstraints`. After that frame, `frames.recv` waited with no deadline, so a client that went silent held one of eight session slots. An idle deadline now drops such a client. It moves only when a frame is handled. Tip and fee-check wakes do not refresh it.

The deadline is opt-in (`--sv2-tp-idle-timeout SECS`, default off). SRI pools and JDCs are legitimately silent between shares and solutions, and the SRI pool shuts down when its TP drops it, so the 10 s default dropped working clients. Operators who face untrusted clients can set it; the regression test enables it.

**Regression:** `rbitcoin-sv2` `session_silent_after_constraints_is_dropped_at_the_idle_deadline`.
