Fixed

- **IBD teardown no longer waits out a whole confirm lookup wave.** A wave
  resolves up to 64k parent txids in one batch, which on a busy HDD datadir
  took most of an hour, and stop, SIGTERM and a catch-up give-up all waited
  for it (`still waiting for confirm engine` for 58 minutes in the field).
  The batch now runs in pieces of 4,096 under one fence snapshot and checks
  the confirm cancel before each piece; a cancelled wave ends the lookup
  thread instead of counting as a lookup fault.
