Fixed

- **A failed store-read drain no longer returns while reads are still in flight.** The process aborts instead of freeing buffers the kernel or a pool worker still owns.
