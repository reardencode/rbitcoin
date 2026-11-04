Fixed

- **A block still inside the download window is not forgotten at 10 seconds.**
  The getdata stall no longer drops a hash that window still lists, so the
  ping suspend holds and the peer stays until the block-interval timeout.
  A request the window has already given up still expires at 10 seconds.
