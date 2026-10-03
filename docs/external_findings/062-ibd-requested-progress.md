# 062 — Only a requested block moves the IBD stall clock

**Severity:** high
**Status:** fixed
**Found by:** Stephan Livera, 2026-10-02 (H5)

During initial download, unsolicited blocks and decoys refreshed the stall clock, and unsolicited blocks were queued. Only a block this node requested moves the clock or is queued. Requested bodies are still accepted past 16 MB/s. The requested-body channel stays unbounded, and the reader does not wait on a decode permit.

**Regression:** `rbitcoin-net` `unsolicited_block_does_not_refresh_progress`.
