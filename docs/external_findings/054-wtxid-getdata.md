# 054 — Wtxid follow-up is a wtxid getdata

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (N2)

A wtxid announcement was re-requested as a txid. The follow-up getdata uses a wtxid.

**Regression:** `rbitcoin-net` `wtxid_followup_is_requested_as_wtx`.
