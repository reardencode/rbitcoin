Fixed

- **A panic during a store read no longer leaves the next read writing into freed memory.** Dropping the session while reads are in flight aborts. An index build finishes or aborts those reads before it returns its error, and the buffers are still live. The original build error is kept.
