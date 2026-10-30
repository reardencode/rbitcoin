Fixed

- **The SV2 Template Provider no longer drops a client that is quiet after setup.** A session that sent nothing for 10 s after its first `CoinbaseOutputConstraints` was closed, but Stratum v2 reference pools and job declarators send nothing between shares, so a pool connected, got its first template and was disconnected 10 s later (and shut down). There is now no idle deadline by default. `--sv2-tp-idle-timeout SECS` (conf `sv2_tp_idle_timeout`, 0 to 86400, `0` = off) restores one for operators who want it. The setup deadline is unchanged.
