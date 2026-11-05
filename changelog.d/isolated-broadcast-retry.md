Changed

- **A private broadcast is sent again if it doesn't come back.** If no
  normal peer sends your tx back within 2 to 3 minutes, the node sends it
  privately again to fresh peers, up to 1,000 times, like Bitcoin Core.
  Before, a tx whose private sends were lost was never sent again.
