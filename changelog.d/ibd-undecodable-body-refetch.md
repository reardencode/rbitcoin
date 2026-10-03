Fixed

- **IBD no longer stalls on an undecodable block body.** A peer that
  answered `getdata` with the real header and transactions that do not
  parse left the body queued forever, so the honest copy was dropped and
  confirm stopped at that height until restart. Intake now refuses such a
  body and disconnects the sender, and lookup drops any queued row that
  does not decode. The hash is requested again and is never marked
  invalid.
- **A block with Core's 10-byte empty transaction is invalid, not
  undecodable.** Core reads an empty input list followed by segwit flag 0
  as a transaction with no inputs and no outputs and rejects the block.
  rbitcoin now decodes that encoding the same way and marks the block
  invalid, instead of refetching it and dropping every peer that serves
  it.
