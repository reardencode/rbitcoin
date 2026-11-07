Fixed

- **`disconnectnode` no longer finds a peer that is already leaving.**
  `getpeerinfo` hides that peer while its session finishes. A second
  `disconnectnode` for the same id or address now returns -29 (not
  connected). Before, it returned success until the session ended.
