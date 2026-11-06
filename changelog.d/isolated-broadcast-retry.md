Changed

- **A private broadcast is sent again if it doesn't come back.** If no
  normal peer sends your tx back, the node sends it privately again in
  another round to two peers, 2 to 3.5 minutes after the last round, up
  to 1,000 rounds. A tx already in a block is not sent again. Before, a
  tx whose private sends were lost was never sent again.
