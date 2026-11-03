Fixed

- **Accepting a block during initial download no longer scans the body queue under the lock lookup uses.** Whether a hash is queued is a map lookup. Lookup's decoded blocks have their own lock, so that check cannot stall confirm.
