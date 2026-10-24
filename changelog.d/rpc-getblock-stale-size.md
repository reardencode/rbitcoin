Fixed

- **`getblock` verbosity 1 sends `size`, `strippedsize` and `weight` for a
  stale block**, as Core does. They were only present at verbosity 2 off the
  active chain, and BDK's reorg walk failed on the missing field.
