# 075 — Secret debug output is redacted

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (M10)

Secret types derived Debug, so the bytes appeared in format output, and secret files were created with the umask and then chmod'd. Debug output is redacted. `store.secret` and the API log are created mode 0600.

**Regression:** `rbitcoin-store` `debug_does_not_print_secret_bytes`, `debug_does_not_print_the_token`.
