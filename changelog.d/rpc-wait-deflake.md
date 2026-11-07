Fixed

- **Two RPC long-poll tests no longer race the clock.** The batch queue test
  waits for the long-poll to show in `getrpcinfo` instead of sleeping
  80 ms, and the HTTP `waitfornewblock` wake test checks that the tip, not
  the deadline, ended the wait instead of timing the round trip to 40 ms.
