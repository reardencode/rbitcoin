Fixed

- **A peer learns blocks mined during its handshake.** The outbound session
  subscribed to new tips only after the handshake returned, so those blocks
  waited for the two-minute headers poll. A tip already in place when the
  handshake started is not pushed.
