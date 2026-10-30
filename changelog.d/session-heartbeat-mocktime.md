Fixed

- **`setmocktime` wakes live sessions.** Ping and timeout checks on those
  sessions run on that call, instead of waiting for the next 50 ms tick.
