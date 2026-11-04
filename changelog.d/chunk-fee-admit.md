Fixed

- **A CPFP package is metered once, at the chunk feerate.** Fee
  estimates used to bucket each member at its own feerate, so a cheap
  parent with a paying child moved the low bucket and missed the rate
  the template mines. The parent and child now move that chunk's
  bucket once.
