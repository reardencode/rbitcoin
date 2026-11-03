Fixed

- **A store read no longer completes into memory that was already freed.** Leaving a batch, growing it, or dropping the session aborts if a read is still in flight. Only the code that still owns the buffers waits for those reads.
