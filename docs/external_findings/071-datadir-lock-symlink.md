# 071 — Datadir lock does not follow a symlink

**Severity:** low
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (L10)

The datadir lock was created with ordinary open, so a symlink in the datadir made the lock land somewhere else, and the mode followed the umask. The open does not follow a symlink, and the file is created mode 0600.

**Regression:** `rbitcoin-node` `lock_file_does_not_follow_a_symlink`.
