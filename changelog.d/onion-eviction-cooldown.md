Fixed

- **Initial-download eviction strikes follow the peer, not the TCP port.** Onion peers that share a port no longer share a strike count, and a cooldown no longer hides other onion addresses. A strike is dropped after the address leaves the address book and the cooldown has ended.
