Fixed

- **Initial download can refill its queue from headers it already stored.** Cleanup keeps the height and parent of those headers.
- **A new batch of headers ahead of the tip does not skip stored headers waiting for queue space.** Those slots stay for the next headers in order.
- **Only a reconnect round with no live download peer spends the reconnect budget.** A replacement connection that already started is allowed to finish. A spent budget still stops initial download without entering tip mode.
- **A tip-follow peer that goes over the message or byte rate is disconnected on that message.** Its unanswered block requests are released however the session ends, including `disconnectnode` and eviction, so another peer can be asked right away. A second rate-limit disconnect from the same address within an hour refuses that address for a day. Noban, manual, and local peers leave no strike.
