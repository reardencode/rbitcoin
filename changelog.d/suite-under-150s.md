Changed

- **Shutdown wakes dial, accept, and connect-retry.** Those tasks were blocked on a channel or a timer, so every shutdown waited out the full 750 ms grace and then aborted them. The grace remains for a session that is still unwinding.
- **`--max-run-secs` exits when the deadline is reached.** The tip loop used to notice it only on the 5 second progress tick.
