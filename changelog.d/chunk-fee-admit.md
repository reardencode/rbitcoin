Fixed

- **A CPFP package is metered once, at the chunk feerate.** Fee
  estimates used to bucket each member at its own feerate, so a cheap
  parent with a paying child moved the low bucket and missed the rate
  the template mines. The package moves that chunk's bucket once,
  including a parent and child admitted together, and that sample is
  taken before orphan promotion. A child that joins a parent already
  in the pool adds only its own weight at that same chunk rate.
