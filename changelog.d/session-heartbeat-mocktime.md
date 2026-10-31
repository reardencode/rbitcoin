Fixed

- **`setmocktime` wakes live sessions.** Ping and timeout checks on those
  sessions run on that call, instead of waiting for the next 50 ms tick.
- **`waitforblock` and `waitforblockheight` return a tip-read error on the
  poll that sees it.** A missing tip or a failed header read no longer
  holds the call until the timeout.
- **`invalidateblock` wakes `waitforblock`, `waitforblockheight`,
  `waitfornewblock`, and a `getblocktemplate` longpoll.** The tip that call
  leaves, including a replacement fork, is what those waits see. The stump
  is published only when no fork replaces it.
