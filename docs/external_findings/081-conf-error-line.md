# 081 — Conf errors name the file and line

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L11)

A conf parse error interpolated the raw line, which could echo a secret. The error names the file and line and expects `key=value`. The raw line is not included.

**Regression:** `rbitcoin-node` `conf_error_names_the_file_and_line`.
