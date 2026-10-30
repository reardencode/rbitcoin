Fixed

- **`reconsiderblock` clears `invalidateblock` on a side block.** The body
  stays parked. A resubmit of that block is `duplicate`, and a heavier
  child of it becomes the tip.
