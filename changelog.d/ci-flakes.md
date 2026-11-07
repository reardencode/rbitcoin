Fixed

- **`disconnectnode` no longer finds a peer that is already leaving.**
  `getpeerinfo` hides that peer while its session finishes. A second
  `disconnectnode` for the same id or address now returns -29 (not
  connected). Before, it returned success until the session ended.
- **Electrum's port is closed when the node stops.** A failed start or a
  stop now waits for the Electrum listener to close, so the port can be
  bound again at once.
