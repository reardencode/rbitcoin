# 078 — Version nonce comes from the CSPRNG

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L5)

The version nonce was not drawn from a CSPRNG. Each handshake fills it from the system CSPRNG.

**Regression:** `rbitcoin-net` `rand_nonce_changes`.
