Fixed

- **Initial download no longer scans the whole header chain every second.**
  That scan ran on the main loop and held its lock. At a mainnet tip it
  took most of the second, so block requests went out in one burst per
  second. The once-a-second pass now only compacts the live download.
