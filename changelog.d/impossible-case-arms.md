Changed

- **A missing fact is no longer treated as success, or as the peer's fault.** Output amounts stay unsigned after they are decoded. A confirm or index step that was promised a row and does not have it fails that step. It does not skip the row, zero it, or blame the peer.
