# 080 — Tor control password rejects a line break

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L9)

A Tor control password containing CR, LF, or NUL was accepted, and passing the key on the command line was silent. Those bytes are refused. An argv password warns once.

**Regression:** `rbitcoin-node` `tor_control_password_rejects_a_line_break`.
