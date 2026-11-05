Changed

- **A private broadcast ends when the transaction comes back.** The node
  used to stay silent toward ordinary peers after the network already had
  the transaction, so it stood out. When a normal peer sends that
  transaction back, the private broadcast ends and the transaction is
  announced on the normal timer. A txid announcement from a wtxid-relay
  peer is ignored for every transaction, whether or not this node already
  has it. If the first peer does not send the transaction, the next
  standing peer who announced it is asked. Inbound peers wait 30 seconds
  from that echo, not from submit.
