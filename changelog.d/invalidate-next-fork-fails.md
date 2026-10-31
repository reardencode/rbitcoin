Fixed

- **`invalidateblock` succeeds when a block of the next fork fails.** It
  returned that block's error (`bad-cb-amount`) after the tip had already
  moved. As in Core, the block is marked invalid, the next fork is tried,
  and the call returns null. A store fault is still an error.
  In `getchaintips` a tip at or above an invalidated or failed block is
  `invalid`, and that block is not listed when a tip builds on it (#1258).
