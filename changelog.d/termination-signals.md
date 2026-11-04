Fixed

- **SIGHUP, SIGUSR1, and SIGUSR2 shut the node down.** They take the same
  path as SIGTERM and SIGINT, including the spend-durable flush. Closing a
  terminal, a logrotate `postrotate`, or `systemctl reload` no longer skips
  that flush.
