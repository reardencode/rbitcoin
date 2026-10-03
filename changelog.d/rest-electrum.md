Security

- `/rest/` on the RPC listener is off unless `--rest` or `rest=` is set.
  It uses its own queue, and the body is read before that permit is taken.
