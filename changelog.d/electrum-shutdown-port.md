Fixed

- **Electrum's port is closed when the node stops.** A failed start or a
  stop now waits for the Electrum listener to close, so the port can be
  bound again at once.
