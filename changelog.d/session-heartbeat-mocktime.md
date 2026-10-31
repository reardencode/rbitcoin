Fixed

- **`setmocktime` wakes live sessions.** Ping and timeout checks on those
  sessions run on that call, instead of waiting for the next 50 ms tick.
- **`waitforblock` and `waitforblockheight` return a tip-read error on the
  poll that sees it.** A missing tip or a failed header read no longer
  holds the call until the timeout.
- **`invalidateblock` wakes `waitforblock`, `waitforblockheight`, and
  `waitfornewblock`.** The tip left after that call, including a replacement
  fork, is published even when that RPC context has no mempool.
