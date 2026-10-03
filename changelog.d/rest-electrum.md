Security

- `/rest/` on the RPC listener is off unless `--rest` or `rest=` is set.
  It uses its own queue, and the body is read before that permit is taken.
- A silent-payment subscribe scans at most the recent 256-block window,
  including when the client passes a start height. The scan stops when
  the client hangs up.
