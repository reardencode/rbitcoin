Changed

- **A private broadcast ends when the tx comes back.** Your node never
  mentioned its own tx to its normal peers, even after the network had
  it, so it stood out. Now, when a normal peer sends that tx back to you,
  the private broadcast is done and the tx is announced the normal way.
  A txid announcement from a wtxid-relay peer is ignored for every
  transaction, so this node answers the same way whether or not it
  already has the tx.
