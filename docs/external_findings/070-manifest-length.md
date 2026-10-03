# 070 — Manifest and txstat lengths must fit the file

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L8)

A sorted-run manifest and a txstat blob trusted a length and allocated it before noticing the file was shorter. A length past the remaining file or the fixed ceiling is corrupt and is not allocated.

**Regression:** `rbitcoin-store` `manifest_length_past_the_file_is_corrupt`, `txstat_blob_longer_than_the_file_is_corrupt`.
