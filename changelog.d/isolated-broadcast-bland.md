Changed

- **Isolated broadcast picks fresh peers for each transaction.** It used
  to send every one of your transactions to the same first two addrman
  peers, which tied them together. Each transaction now draws a network
  and then a peer in it at random, as Core's private broadcast does.
  Only networks reachable through the proxy are drawn.
- **Isolated broadcast sends a VERSION that does not identify the node.**
  It used to send this node's user agent, clock, service bits, and
  relay flag, then `wtxidrelay` and `sendaddrv2`. It now sends Bitcoin
  Core's private-broadcast VERSION (no services, time 0, no addresses,
  `/pynode:0.0.1/`, height 0, relay off) and nothing else before
  `verack`. A peer whose own VERSION turns relay off is skipped, as Core
  does. Ordinary peers see the same handshake as before.
