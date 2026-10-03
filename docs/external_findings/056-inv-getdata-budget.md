# 056 — Inv getdata charges the send budget

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (N1)

Getdata driven by an inv was not charged against the per-peer send budget. Those bytes are charged.

**Regression:** `rbitcoin-net` `inv_getdata_charges_send_budget`.
