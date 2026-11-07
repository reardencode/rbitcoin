Fixed

- **The `rbitcoin-ibd` test suite builds on macOS again.** Its header-thread
  name test reads `/proc`, so it now compiles on Linux only, together with its
  imports.
