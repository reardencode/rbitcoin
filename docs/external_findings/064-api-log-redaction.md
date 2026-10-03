# 064 — API logs redact scan secrets and extended keys

**Severity:** medium
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (H4)

Silent-payment unsubscribe and generic RPC `api_call` wrote the scan secret and extended private keys to the API log. Those values are redacted before the line is written. The method name stays.

**Regression:** `rbitcoin-rpc` `api_call_redacts_scan_secrets_and_ext_privkeys`.
