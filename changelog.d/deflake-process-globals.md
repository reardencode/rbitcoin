Fixed

- **A peer learns blocks mined during its handshake.** The outbound session
  subscribed to new tips only after the handshake returned, so those blocks
  waited for the two-minute headers poll. The session announces the tip it
  already has once the connection is up.
