# 065 — Silent-payment scan stays inside 256 blocks

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M2)

A silent-payment scan whose start height was not zero walked from there to the tip and kept running after the client disconnected. Every scan is at most the existing 256-height window at the tip, including a nonzero start, and it stops when the connection ends. The scan uses the tweak index. It does not require `--sh-index`.

**Regression:** `rbitcoin-electrum` `parse_sub_labels_start_and_networks`, `sp_scan_stops_when_the_client_hangs_up`.
