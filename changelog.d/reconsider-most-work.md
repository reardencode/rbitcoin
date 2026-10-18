Fixed

- **`reconsiderblock` connects restored paths that continue one another as
  one branch**, as in Core. Each path used to be re-applied on its own, so a
  chain that only outweighed the tip as a whole stayed inactive. A restored
  block that loses stays a valid fork, so a later `invalidateblock` can fall
  back to it.
