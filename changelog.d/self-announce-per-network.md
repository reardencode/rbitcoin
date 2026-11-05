Security

- **Self-announce stays on the link's network.** The daily `addrv2`
  self-announce put the onion, the I2P destination and `--external-ip` in
  one message to every peer, so a clearnet peer could tie the onion to the
  node's IP and an onion peer learned that IP. Each link now carries only
  the address of its own network: the onion over Tor (`.onion` peers,
  dials through `--proxy`, the onion listener), the I2P destination over
  I2P, a public `--external-ip` to direct clearnet peers, and an
  `fc00::/8` address only to CJDNS peers. Neither a `getaddr` reply nor
  `addrv2` relay passes on the node's own addresses after a peer gossips
  them back.
